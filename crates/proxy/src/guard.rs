use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use base64::Engine;
use rand::RngCore;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

pub const PAGE: &str = include_str!("login.html");
pub const PASSWORD_ENV: &str = "SHAHRAH_METRICS_PASSWORD";
pub const OPEN_ENV: &str = "SHAHRAH_METRICS_OPEN";
pub const COOKIE: &str = "shahrah_operator";
pub const SESSION_LIFE: Duration = Duration::from_secs(12 * 3600);

const LOGIN_TRIES: u32 = 5;
const LOGIN_WINDOW: Duration = Duration::from_secs(60);
const LOCKOUT_FIRST: Duration = Duration::from_secs(30);
const LOCKOUT_CEILING: Duration = Duration::from_secs(900);
const REFUSAL_DELAY: Duration = Duration::from_millis(250);
const REQUESTS_PER_MINUTE: u32 = 600;
const REQUEST_WINDOW: Duration = Duration::from_secs(60);
const TRACKED_CALLERS: usize = 4096;
const LIVE_SESSIONS: usize = 512;

#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    Allowed,
    NeedsLogin,
    TooManyRequests { after: u64 },
    LockedOut { after: u64 },
}

struct Caller {
    failures: u32,
    counting_from: Instant,
    locked_until: Option<Instant>,
    lockout: Duration,
    requests: u32,
    requests_from: Instant,
    seen: Instant,
}

impl Caller {
    fn fresh(at: Instant) -> Self {
        Self {
            failures: 0,
            counting_from: at,
            locked_until: None,
            lockout: LOCKOUT_FIRST,
            requests: 0,
            requests_from: at,
            seen: at,
        }
    }
}

pub struct Gate {
    secret: Option<[u8; 32]>,
    callers: Mutex<HashMap<IpAddr, Caller>>,
    sessions: Mutex<HashMap<[u8; 32], Instant>>,
}

impl Default for Gate {
    fn default() -> Self {
        Self {
            secret: None,
            callers: Mutex::new(HashMap::new()),
            sessions: Mutex::new(HashMap::new()),
        }
    }
}

impl Gate {
    #[must_use]
    pub fn from_env() -> Self {
        let secret = std::env::var(PASSWORD_ENV).ok().and_then(|given| {
            let trimmed = given.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(digest(trimmed.as_bytes()))
            }
        });
        Self {
            secret,
            callers: Mutex::new(HashMap::new()),
            sessions: Mutex::new(HashMap::new()),
        }
    }

    #[must_use]
    pub fn guarded(&self) -> bool {
        self.secret.is_some()
    }

    pub fn admits(&self, caller: IpAddr, cookie: Option<&str>, offered: Option<&str>) -> Verdict {
        let now = Instant::now();
        if let Some(after) = self.over_the_rate(caller, now) {
            return Verdict::TooManyRequests { after };
        }
        let Some(secret) = self.secret.as_ref() else {
            return Verdict::Allowed;
        };
        if cookie.is_some_and(|token| self.knows(token, now)) {
            return Verdict::Allowed;
        }
        if let Some(after) = self.locked_for(caller, now) {
            return Verdict::LockedOut { after };
        }
        let Some(given) = offered else {
            return Verdict::NeedsLogin;
        };
        if digest(given.as_bytes()).ct_eq(secret).into() {
            self.forgive(caller);
            return Verdict::Allowed;
        }
        self.remember_failure(caller, now);
        match self.locked_for(caller, now) {
            Some(after) => Verdict::LockedOut { after },
            None => Verdict::NeedsLogin,
        }
    }

    pub fn try_login(&self, caller: IpAddr, given: &str) -> Result<String, Verdict> {
        let now = Instant::now();
        if let Some(after) = self.locked_for(caller, now) {
            return Err(Verdict::LockedOut { after });
        }
        let Some(secret) = self.secret.as_ref() else {
            return Ok(String::new());
        };
        let matches: bool = digest(given.as_bytes()).ct_eq(secret).into();
        if !matches {
            self.remember_failure(caller, now);
            return Err(Verdict::NeedsLogin);
        }
        self.forgive(caller);
        Ok(self.open_session(now))
    }

    #[must_use]
    pub const fn slow_down_after_a_refusal() -> Duration {
        REFUSAL_DELAY
    }

    pub fn forget_session(&self, token: &str) {
        let Some(raw) = decode_token(token) else {
            return;
        };
        let _gone = self
            .sessions
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&raw);
    }

    fn open_session(&self, now: Instant) -> String {
        let mut raw = [0u8; 32];
        rand::rng().fill_bytes(&mut raw);
        let mut sessions = self.sessions.lock().unwrap_or_else(PoisonError::into_inner);
        sessions.retain(|_token, until| *until > now);
        if sessions.len() >= LIVE_SESSIONS {
            let oldest = sessions
                .iter()
                .min_by_key(|(_token, until)| **until)
                .map(|(token, _until)| *token);
            if let Some(oldest) = oldest {
                let _gone = sessions.remove(&oldest);
            }
        }
        let _placed = sessions.insert(raw, now.checked_add(SESSION_LIFE).unwrap_or(now));
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw)
    }

    fn knows(&self, token: &str, now: Instant) -> bool {
        let Some(raw) = decode_token(token) else {
            return false;
        };
        let mut sessions = self.sessions.lock().unwrap_or_else(PoisonError::into_inner);
        match sessions.get(&raw) {
            Some(until) if *until > now => true,
            Some(_stale) => {
                let _gone = sessions.remove(&raw);
                false
            }
            None => false,
        }
    }

    fn over_the_rate(&self, caller: IpAddr, now: Instant) -> Option<u64> {
        let mut callers = self.callers.lock().unwrap_or_else(PoisonError::into_inner);
        make_room(&mut callers, now);
        let entry = callers.entry(caller).or_insert_with(|| Caller::fresh(now));
        entry.seen = now;
        if now.duration_since(entry.requests_from) > REQUEST_WINDOW {
            entry.requests = 0;
            entry.requests_from = now;
        }
        entry.requests = entry.requests.saturating_add(1);
        if entry.requests > REQUESTS_PER_MINUTE {
            let left = REQUEST_WINDOW.saturating_sub(now.duration_since(entry.requests_from));
            return Some(left.as_secs().saturating_add(1));
        }
        None
    }

    fn locked_for(&self, caller: IpAddr, now: Instant) -> Option<u64> {
        let callers = self.callers.lock().unwrap_or_else(PoisonError::into_inner);
        let entry = callers.get(&caller)?;
        let until = entry.locked_until?;
        if until <= now {
            return None;
        }
        Some(until.duration_since(now).as_secs().saturating_add(1))
    }

    fn remember_failure(&self, caller: IpAddr, now: Instant) {
        let mut callers = self.callers.lock().unwrap_or_else(PoisonError::into_inner);
        make_room(&mut callers, now);
        let entry = callers.entry(caller).or_insert_with(|| Caller::fresh(now));
        entry.seen = now;
        if now.duration_since(entry.counting_from) > LOGIN_WINDOW {
            entry.failures = 0;
            entry.counting_from = now;
        }
        entry.failures = entry.failures.saturating_add(1);
        if entry.failures >= LOGIN_TRIES {
            entry.locked_until = now.checked_add(entry.lockout);
            entry.lockout = entry.lockout.saturating_mul(2).min(LOCKOUT_CEILING);
            entry.failures = 0;
            entry.counting_from = now;
        }
    }

    fn forgive(&self, caller: IpAddr) {
        let mut callers = self.callers.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(entry) = callers.get_mut(&caller) {
            entry.failures = 0;
            entry.locked_until = None;
            entry.lockout = LOCKOUT_FIRST;
        }
    }
}

fn make_room(callers: &mut HashMap<IpAddr, Caller>, now: Instant) {
    if callers.len() < TRACKED_CALLERS {
        return;
    }
    callers.retain(|_who, entry| {
        entry.locked_until.is_some_and(|until| until > now)
            || now.duration_since(entry.seen) < REQUEST_WINDOW
    });
    while callers.len() >= TRACKED_CALLERS {
        let Some(victim) = the_one_worth_least(callers) else {
            break;
        };
        let _gone = callers.remove(&victim);
    }
}

fn the_one_worth_least(callers: &HashMap<IpAddr, Caller>) -> Option<IpAddr> {
    callers
        .iter()
        .filter(|(_who, entry)| entry.locked_until.is_none())
        .min_by_key(|(_who, entry)| entry.seen)
        .map(|(who, _entry)| *who)
        .or_else(|| {
            callers
                .iter()
                .min_by_key(|(_who, entry)| entry.locked_until)
                .map(|(who, _entry)| *who)
        })
}

fn digest(value: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(value);
    hasher.finalize().into()
}

fn decode_token(token: &str) -> Option<[u8; 32]> {
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(token.trim())
        .ok()?;
    <[u8; 32]>::try_from(raw.as_slice()).ok()
}

#[must_use]
pub fn login_page(trouble: Option<&str>) -> String {
    match trouble {
        Some(words) => PAGE.replace(
            "<!--TROUBLE-->",
            &format!("<p class=\"bad\">{}</p>", crate::metrics::html_escape(words)),
        ),
        None => PAGE.replace("<!--TROUBLE-->", ""),
    }
}

#[must_use]
pub fn form_value(body: &str, wanted: &str) -> Option<String> {
    body.split('&').find_map(|pair| {
        let (name, value) = pair.split_once('=')?;
        (name == wanted).then(|| crate::metrics::decoded(value))
    })
}

#[must_use]
pub fn cookie_from(header: Option<&str>) -> Option<String> {
    let header = header?;
    header.split(';').find_map(|pair| {
        let (name, value) = pair.split_once('=')?;
        (name.trim() == COOKIE).then(|| value.trim().to_owned())
    })
}

#[must_use]
pub fn password_from(header: Option<&str>) -> Option<String> {
    let header = header?.trim();
    if let Some(token) = header.strip_prefix("Bearer ") {
        return Some(token.trim().to_owned());
    }
    let encoded = header.strip_prefix("Basic ")?;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(encoded.trim())
        .ok()?;
    let text = String::from_utf8(raw).ok()?;
    let (_user, password) = text.split_once(':')?;
    Some(password.to_owned())
}


#[cfg(test)]
mod tests {
    use super::*;

    fn gate_with(secret: &str) -> Gate {
        Gate {
            secret: Some(digest(secret.as_bytes())),
            callers: Mutex::new(HashMap::new()),
            sessions: Mutex::new(HashMap::new()),
        }
    }

    fn caller(last: u8) -> IpAddr {
        IpAddr::from([203, 0, 113, last])
    }

    #[test]
    fn a_gate_with_no_password_admits_everyone() {
        let open = Gate::default();
        assert!(!open.guarded());
        assert_eq!(open.admits(caller(1), None, None), Verdict::Allowed);
    }

    #[test]
    fn a_guarded_gate_refuses_until_the_password_is_right() {
        let gate = gate_with("correct horse");
        assert_eq!(gate.admits(caller(2), None, None), Verdict::NeedsLogin);
        assert_eq!(
            gate.admits(caller(2), None, Some("wrong")),
            Verdict::NeedsLogin
        );
        assert_eq!(
            gate.admits(caller(2), None, Some("correct horse")),
            Verdict::Allowed
        );
    }

    #[test]
    fn guessing_through_the_authorization_header_locks_out_the_same_way() {
        let gate = gate_with("correct horse");
        let who = caller(10);
        for _ in 0..LOGIN_TRIES {
            let _wrong = gate.admits(who, None, Some("guess"));
        }
        assert!(
            matches!(gate.admits(who, None, Some("guess")), Verdict::LockedOut { .. }),
            "a header is a guess like any other and must not be a way around the lock"
        );
        assert!(
            matches!(
                gate.admits(who, None, Some("correct horse")),
                Verdict::LockedOut { .. }
            ),
            "the lock holds while it holds, however the password arrives"
        );
    }

    #[test]
    fn a_session_still_works_while_the_address_is_locked_out() {
        let gate = gate_with("s3cret");
        let who = caller(11);
        let Ok(token) = gate.try_login(who, "s3cret") else {
            panic!("the right password should open a session");
        };
        for _ in 0..(LOGIN_TRIES + 2) {
            let _wrong = gate.admits(who, None, Some("guess"));
        }
        assert_eq!(
            gate.admits(who, Some(&token), None),
            Verdict::Allowed,
            "an operator already signed in is not thrown out by someone else guessing"
        );
    }

    #[test]
    fn a_session_opened_by_logging_in_is_admitted_afterwards() {
        let gate = gate_with("s3cret");
        let Ok(token) = gate.try_login(caller(3), "s3cret") else {
            panic!("the right password should open a session");
        };
        assert_eq!(gate.admits(caller(3), Some(&token), None), Verdict::Allowed);
        gate.forget_session(&token);
        assert_eq!(
            gate.admits(caller(3), Some(&token), None),
            Verdict::NeedsLogin,
            "a session that logged out is not a session any more"
        );
    }

    #[test]
    fn a_token_from_nowhere_is_not_a_session() {
        let gate = gate_with("s3cret");
        for pretend in ["", "not-base64!!", "AAAA", &"A".repeat(43)] {
            assert_eq!(
                gate.admits(caller(4), Some(pretend), None),
                Verdict::NeedsLogin,
                "{pretend} should not pass"
            );
        }
    }

    #[test]
    fn five_wrong_guesses_lock_the_caller_out() {
        let gate = gate_with("s3cret");
        let who = caller(5);
        for _ in 0..LOGIN_TRIES {
            assert!(gate.try_login(who, "guess").is_err());
        }
        match gate.try_login(who, "s3cret") {
            Err(Verdict::LockedOut { after }) => assert!(after > 0),
            _other => panic!("the right password must not open the lock early"),
        }
        assert!(
            matches!(gate.admits(who, None, None), Verdict::LockedOut { .. }),
            "a locked caller is told so rather than shown the form again"
        );
    }

    #[test]
    fn a_lockout_lands_on_one_caller_and_not_the_next() {
        let gate = gate_with("s3cret");
        for _ in 0..LOGIN_TRIES {
            let _wrong = gate.try_login(caller(6), "guess");
        }
        assert!(matches!(
            gate.admits(caller(6), None, None),
            Verdict::LockedOut { .. }
        ));
        assert_eq!(
            gate.admits(caller(7), None, None),
            Verdict::NeedsLogin,
            "one caller guessing must not lock the operators out"
        );
    }

    #[test]
    fn a_flood_from_one_caller_is_refused_by_rate_rather_than_served() {
        let gate = gate_with("s3cret");
        let who = caller(8);
        let mut refused = false;
        for _ in 0..=REQUESTS_PER_MINUTE {
            if matches!(gate.admits(who, None, None), Verdict::TooManyRequests { .. }) {
                refused = true;
                break;
            }
        }
        assert!(refused, "a caller past the rate is told to come back later");
        assert_eq!(
            gate.admits(caller(9), None, None),
            Verdict::NeedsLogin,
            "the flood does not spill onto another caller"
        );
    }

    #[test]
    fn a_table_of_locked_out_addresses_is_bounded_too() {
        let gate = gate_with("a generated secret");
        let mut who = 0u32;
        while who < 6000 {
            let caller = IpAddr::V4(std::net::Ipv4Addr::from(who.to_be_bytes()));
            for _try in 0..LOGIN_TRIES {
                let _refused = gate.try_login(caller, "wrong");
            }
            who = who.saturating_add(1);
        }
        let held = gate
            .callers
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len();
        assert!(
            held <= TRACKED_CALLERS,
            "an attacker with more addresses than the table holds still cannot grow it: {held}"
        );
    }

    #[test]
    fn the_caller_table_cannot_be_grown_without_bound() {
        let gate = gate_with("s3cret");
        for n in 0..(TRACKED_CALLERS + 500) {
            let octets = u32::try_from(n).unwrap_or(0).to_be_bytes();
            let _seen = gate.admits(IpAddr::from(octets), None, None);
        }
        let held = gate
            .callers
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len();
        assert!(
            held <= TRACKED_CALLERS,
            "tracking callers must not become the denial of service: held {held}"
        );
    }

    #[test]
    fn a_bearer_or_basic_header_carries_the_password() {
        assert_eq!(password_from(Some("Bearer hunter2")).as_deref(), Some("hunter2"));
        assert_eq!(
            password_from(Some("Basic b3BlcmF0b3I6aHVudGVyMg==")).as_deref(),
            Some("hunter2")
        );
        assert_eq!(password_from(Some("Digest whatever")), None);
        assert_eq!(password_from(None), None);
    }

    #[test]
    fn the_cookie_is_picked_out_of_whatever_else_the_browser_sends() {
        assert_eq!(
            cookie_from(Some("theme=dark; shahrah_operator=abc123; other=1")).as_deref(),
            Some("abc123")
        );
        assert_eq!(cookie_from(Some("theme=dark")), None);
        assert_eq!(cookie_from(None), None);
    }

    #[test]
    fn an_address_that_is_not_loopback_is_treated_as_reachable() {
        assert!(!crate::address::reaches_the_world("127.0.0.1:9187"));
        assert!(!crate::address::reaches_the_world("[::1]:9187"));
        assert!(crate::address::reaches_the_world("0.0.0.0:9187"));
        assert!(crate::address::reaches_the_world("10.0.0.4:9187"));
        assert!(crate::address::reaches_the_world("metrics.internal:9187"));
    }
}
