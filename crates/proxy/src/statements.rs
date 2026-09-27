use std::collections::hash_map::DefaultHasher;
use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};

use shahrah_protocol::messages::{
    TAG_BIND, TAG_CLOSE, TAG_DESCRIBE_STATEMENT, TAG_PARSE, TAG_PARSE_COMPLETE, TAG_QUERY,
};
use shahrah_protocol::reader::Reader;
use shahrah_protocol::writer::Writer;

use crate::error::SessionError;

const OPENING_TRIGGERS: &[&str] = &[
    "SET ",
    "LISTEN ",
    "UNLISTEN ",
    "PREPARE ",
    "CREATE TEMP ",
    "CREATE TEMPORARY ",
    "CREATE LOCAL TEMP ",
];

const ANYWHERE_TRIGGERS: &[&str] = &[
    "PG_ADVISORY_LOCK",
    "PG_TRY_ADVISORY_LOCK",
    "PG_ADVISORY_UNLOCK",
    "SET_CONFIG(",
    "SET_CONFIG (",
    "WITH HOLD",
];

const NOT_PINNED: &[&str] = &["SET LOCAL ", "SET TRANSACTION ", "SET CONSTRAINTS "];

#[derive(Debug, Default)]
pub struct Action {
    pub replacement: Option<Vec<u8>>,
    pub skip: bool,
    pub synthesise_parse_complete: bool,
    pub pins: bool,
    pub prepared: Option<String>,
    pub closed: Option<String>,
}

#[derive(Debug, Clone)]
struct Prepared {
    global: String,
    parse: Vec<u8>,
}

#[derive(Debug, Default)]
pub struct Statements {
    by_client_name: HashMap<Vec<u8>, Prepared>,
    in_flight: HashSet<String>,
    swallow_parse_complete: usize,
    unnamed_parse: Option<Vec<u8>>,
    unnamed_present: bool,
}

impl Statements {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn commit_in_flight(&mut self) {
        self.in_flight.clear();
    }

    pub fn clear_in_flight(&mut self) {
        self.in_flight.clear();
        self.unnamed_present = false;
    }

    fn already_there(&self, global: &str, on_backend: &dyn Fn(&str) -> bool) -> bool {
        self.in_flight.contains(global) || on_backend(global)
    }

    pub fn inspect(
        &mut self,
        tag: u8,
        raw: &[u8],
        body: &[u8],
        on_backend: &dyn Fn(&str) -> bool,
    ) -> Result<Action, SessionError> {
        match tag {
            TAG_QUERY => {
                let mut reader = Reader::new(body);
                let sql = reader.cstring()?;
                Ok(Action {
                    pins: pins(sql),
                    ..Action::default()
                })
            }
            TAG_PARSE => self.on_parse(raw, body, on_backend),
            TAG_BIND => self.on_bind(raw, body, on_backend),
            TAG_DESCRIBE_STATEMENT | TAG_CLOSE => self.rewrite_kinded_name(tag, raw, body),
            _ => Ok(Action::default()),
        }
    }

    fn on_parse(
        &mut self,
        raw: &[u8],
        body: &[u8],
        on_backend: &dyn Fn(&str) -> bool,
    ) -> Result<Action, SessionError> {
        let mut reader = Reader::new(body);
        let name = reader.cstring()?.to_vec();
        let sql = reader.cstring()?;
        let pinning = pins(sql);
        let types = reader.remaining();

        if name.is_empty() {
            self.unnamed_parse = Some(raw.to_vec());
            self.unnamed_present = true;
            return Ok(Action {
                pins: pinning,
                ..Action::default()
            });
        }

        let global = global_name(sql, types);
        let mut writer = Writer::with_capacity(body.len().saturating_add(32));
        writer.begin(TAG_PARSE)?;
        writer.cstring(global.as_bytes());
        writer.cstring(sql);
        writer.bytes(types);
        writer.end()?;
        let parse = writer.as_bytes().to_vec();
        self.by_client_name.insert(
            name,
            Prepared {
                global: global.clone(),
                parse: parse.clone(),
            },
        );

        if self.already_there(&global, on_backend) {
            return Ok(Action {
                skip: true,
                synthesise_parse_complete: true,
                pins: pinning,
                ..Action::default()
            });
        }

        self.in_flight.insert(global.clone());
        Ok(Action {
            replacement: Some(parse),
            pins: pinning,
            prepared: Some(global),
            ..Action::default()
        })
    }

    fn on_bind(
        &mut self,
        raw: &[u8],
        body: &[u8],
        on_backend: &dyn Fn(&str) -> bool,
    ) -> Result<Action, SessionError> {
        let mut reader = Reader::new(body);
        let portal = reader.cstring()?;
        let name = reader.cstring()?;
        let rest = reader.remaining();
        let Some(prepared) = self.by_client_name.get(name) else {
            if name.is_empty()
                && !self.unnamed_present
                && let Some(parse) = self.unnamed_parse.clone()
            {
                self.unnamed_present = true;
                self.swallow_parse_complete = self.swallow_parse_complete.saturating_add(1);
                let mut combined = parse;
                combined.extend_from_slice(raw);
                return Ok(Action {
                    replacement: Some(combined),
                    ..Action::default()
                });
            }
            return Ok(Action::default());
        };

        let mut writer = Writer::with_capacity(body.len().saturating_add(32));
        writer.begin(TAG_BIND)?;
        writer.cstring(portal);
        writer.cstring(prepared.global.as_bytes());
        writer.bytes(rest);
        writer.end()?;

        if self.already_there(&prepared.global, on_backend) {
            return Ok(Action {
                replacement: Some(writer.as_bytes().to_vec()),
                ..Action::default()
            });
        }

        let global = prepared.global.clone();
        let mut combined = prepared.parse.clone();
        self.in_flight.insert(global.clone());
        combined.extend_from_slice(writer.as_bytes());
        self.swallow_parse_complete = self.swallow_parse_complete.saturating_add(1);
        Ok(Action {
            replacement: Some(combined),
            prepared: Some(global),
            ..Action::default()
        })
    }

    fn rewrite_kinded_name(
        &mut self,
        tag: u8,
        raw: &[u8],
        body: &[u8],
    ) -> Result<Action, SessionError> {
        let _original = raw;
        let mut reader = Reader::new(body);
        let kind = reader.u8()?;
        let name = reader.cstring()?;
        if kind != b'S' || name.is_empty() {
            return Ok(Action::default());
        }
        let Some(prepared) = self.by_client_name.get(name) else {
            if name.is_empty()
                && !self.unnamed_present
                && let Some(parse) = self.unnamed_parse.clone()
            {
                self.unnamed_present = true;
                self.swallow_parse_complete = self.swallow_parse_complete.saturating_add(1);
                let mut combined = parse;
                combined.extend_from_slice(raw);
                return Ok(Action {
                    replacement: Some(combined),
                    ..Action::default()
                });
            }
            return Ok(Action::default());
        };
        let global = prepared.global.clone();

        let mut writer = Writer::with_capacity(body.len().saturating_add(32));
        writer.begin(tag)?;
        writer.u8(kind);
        writer.cstring(global.as_bytes());
        writer.end()?;

        let closed = if tag == TAG_CLOSE {
            self.by_client_name.remove(name);
            self.in_flight.remove(&global);
            Some(global)
        } else {
            None
        };

        Ok(Action {
            replacement: Some(writer.as_bytes().to_vec()),
            closed,
            ..Action::default()
        })
    }

    pub fn swallow(&mut self, tag: u8) -> bool {
        if tag == TAG_PARSE_COMPLETE && self.swallow_parse_complete > 0 {
            self.swallow_parse_complete = self.swallow_parse_complete.saturating_sub(1);
            return true;
        }
        false
    }
}

fn global_name(sql: &[u8], types: &[u8]) -> String {
    let mut hasher = DefaultHasher::new();
    sql.hash(&mut hasher);
    types.hash(&mut hasher);
    format!("shahrah_{:016x}", hasher.finish())
}

fn head_of(sql: &[u8]) -> &[u8] {
    let mut at = 0usize;
    loop {
        let Some(byte) = sql.get(at) else {
            return &[];
        };
        if byte.is_ascii_whitespace() {
            at = at.saturating_add(1);
        } else if *byte == b'-' && sql.get(at.saturating_add(1)) == Some(&b'-') {
            at = past_line_comment(sql, at);
        } else if *byte == b'/' && sql.get(at.saturating_add(1)) == Some(&b'*') {
            at = past_block_comment(sql, at);
        } else {
            return sql.get(at..).unwrap_or(&[]);
        }
    }
}

fn opens_with(haystack: &[u8], needle: &str) -> bool {
    haystack
        .get(..needle.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(needle.as_bytes()))
}

fn holds(haystack: &[u8], needle: &str) -> bool {
    let needle = needle.as_bytes();
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    haystack
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle))
}

fn statements_in(sql: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let mut from = 0usize;
    let mut at = 0usize;
    while let Some(byte) = sql.get(at) {
        match byte {
            b'\'' => at = past_string(sql, at),
            b'"' => at = past_quoted_name(sql, at),
            b'$' => at = past_dollar_quote(sql, at),
            b'-' if sql.get(at.saturating_add(1)) == Some(&b'-') => {
                at = past_line_comment(sql, at);
            }
            b'/' if sql.get(at.saturating_add(1)) == Some(&b'*') => {
                at = past_block_comment(sql, at);
            }
            b';' => {
                if let Some(piece) = sql.get(from..at) {
                    out.push(piece);
                }
                at = at.saturating_add(1);
                from = at;
            }
            _ => at = at.saturating_add(1),
        }
    }
    if let Some(piece) = sql.get(from..) {
        out.push(piece);
    }
    out
}

fn escapes_backslashes(sql: &[u8], opener: usize) -> bool {
    let Some(before) = opener.checked_sub(1).and_then(|at| sql.get(at)) else {
        return false;
    };
    if !matches!(before, b'e' | b'E') {
        return false;
    }
    match opener.checked_sub(2).and_then(|at| sql.get(at)) {
        Some(earlier) => !(earlier.is_ascii_alphanumeric() || *earlier == b'_'),
        None => true,
    }
}

fn past_string(sql: &[u8], opener: usize) -> usize {
    let escaping = escapes_backslashes(sql, opener);
    let mut at = opener.saturating_add(1);
    while let Some(byte) = sql.get(at) {
        match byte {
            b'\\' if escaping => at = at.saturating_add(2),
            b'\'' if sql.get(at.saturating_add(1)) == Some(&b'\'') => at = at.saturating_add(2),
            b'\'' => return at.saturating_add(1),
            _ => at = at.saturating_add(1),
        }
    }
    at
}

fn past_quoted_name(sql: &[u8], opener: usize) -> usize {
    let mut at = opener.saturating_add(1);
    while let Some(byte) = sql.get(at) {
        match byte {
            b'"' if sql.get(at.saturating_add(1)) == Some(&b'"') => at = at.saturating_add(2),
            b'"' => return at.saturating_add(1),
            _ => at = at.saturating_add(1),
        }
    }
    at
}

fn past_dollar_quote(sql: &[u8], opener: usize) -> usize {
    let Some(tag_end) = dollar_tag_end(sql, opener) else {
        return opener.saturating_add(1);
    };
    let Some(tag) = sql.get(opener..tag_end) else {
        return opener.saturating_add(1);
    };
    let mut at = tag_end;
    while at < sql.len() {
        if sql.get(at..at.saturating_add(tag.len())) == Some(tag) {
            return at.saturating_add(tag.len());
        }
        at = at.saturating_add(1);
    }
    sql.len()
}

fn dollar_tag_end(sql: &[u8], opener: usize) -> Option<usize> {
    let mut at = opener.saturating_add(1);
    let mut first = true;
    loop {
        let byte = sql.get(at)?;
        if *byte == b'$' {
            return Some(at.saturating_add(1));
        }
        let fits = if first {
            byte.is_ascii_alphabetic() || *byte == b'_'
        } else {
            byte.is_ascii_alphanumeric() || *byte == b'_'
        };
        if !fits {
            return None;
        }
        first = false;
        at = at.saturating_add(1);
    }
}

fn past_line_comment(sql: &[u8], opener: usize) -> usize {
    let mut at = opener.saturating_add(2);
    while let Some(byte) = sql.get(at) {
        if *byte == b'\n' {
            return at.saturating_add(1);
        }
        at = at.saturating_add(1);
    }
    at
}

fn past_block_comment(sql: &[u8], opener: usize) -> usize {
    let mut at = opener.saturating_add(2);
    let mut depth = 1usize;
    while at < sql.len() {
        let here = sql.get(at);
        let next = sql.get(at.saturating_add(1));
        if here == Some(&b'/') && next == Some(&b'*') {
            depth = depth.saturating_add(1);
            at = at.saturating_add(2);
        } else if here == Some(&b'*') && next == Some(&b'/') {
            depth = depth.saturating_sub(1);
            at = at.saturating_add(2);
            if depth == 0 {
                return at;
            }
        } else {
            at = at.saturating_add(1);
        }
    }
    sql.len()
}

fn pins(sql: &[u8]) -> bool {
    if ANYWHERE_TRIGGERS.iter().any(|trigger| holds(sql, trigger)) {
        return true;
    }
    statements_in(sql).into_iter().any(|piece| {
        let head = head_of(piece);
        !NOT_PINNED.iter().any(|safe| opens_with(head, safe))
            && OPENING_TRIGGERS
                .iter()
                .any(|trigger| opens_with(head, trigger))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn framed(tag: u8, body: &[u8]) -> Vec<u8> {
        let mut raw = vec![tag];
        let length = u32::try_from(body.len().saturating_add(4)).unwrap_or(u32::MAX);
        raw.extend_from_slice(&length.to_be_bytes());
        raw.extend_from_slice(body);
        raw
    }

    fn parse_body(name: &str, sql: &str) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(name.as_bytes());
        body.push(0);
        body.extend_from_slice(sql.as_bytes());
        body.push(0);
        body.extend_from_slice(&[0, 0]);
        body
    }

    fn bind_body(portal: &str, name: &str) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(portal.as_bytes());
        body.push(0);
        body.extend_from_slice(name.as_bytes());
        body.push(0);
        body.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
        body
    }

    fn prepare(statements: &mut Statements, name: &str, sql: &str) -> String {
        let body = parse_body(name, sql);
        let raw = framed(TAG_PARSE, &body);
        let nowhere = |_: &str| false;
        let action = match statements.inspect(TAG_PARSE, &raw, &body, &nowhere) {
            Ok(action) => action,
            Err(error) => panic!("a parse did not inspect: {error}"),
        };
        match action.prepared {
            Some(global) => global,
            None => panic!("a named parse names the statement it prepared"),
        }
    }

    fn bind(statements: &mut Statements, name: &str, on_backend: &dyn Fn(&str) -> bool) -> Vec<u8> {
        let body = bind_body("", name);
        let raw = framed(TAG_BIND, &body);
        let action = match statements.inspect(TAG_BIND, &raw, &body, on_backend) {
            Ok(action) => action,
            Err(error) => panic!("a bind did not inspect: {error}"),
        };
        match action.replacement {
            Some(replacement) => replacement,
            None => panic!("a bind naming a translated statement is always rewritten"),
        }
    }

    #[test]
    fn a_bind_the_backend_can_already_answer_carries_only_the_bind() {
        let mut statements = Statements::new();
        let global = prepare(&mut statements, "s1", "select $1::int");
        statements.commit_in_flight();

        let held = |name: &str| name == global;
        let sent = bind(&mut statements, "s1", &held);
        assert_eq!(
            sent.first(),
            Some(&TAG_BIND),
            "the backend holds the statement, so the parse must not be sent again"
        );
    }

    #[test]
    fn a_bind_the_backend_has_never_seen_carries_the_parse_in_front_of_it() {
        let mut statements = Statements::new();
        let _global = prepare(&mut statements, "s1", "select $1::int");
        statements.commit_in_flight();

        let nowhere = |_: &str| false;
        let sent = bind(&mut statements, "s1", &nowhere);
        assert_eq!(
            sent.first(),
            Some(&TAG_PARSE),
            "the backend has never seen it, so the parse has to go in front of the bind"
        );
    }

    #[test]
    fn the_rewritten_bind_names_the_translated_statement_and_keeps_the_portal() {
        let mut statements = Statements::new();
        let global = prepare(&mut statements, "s1", "select $1::int");
        statements.commit_in_flight();

        let held = |name: &str| name == global;
        let sent = bind(&mut statements, "s1", &held);
        let body = match sent.get(5..) {
            Some(body) => body,
            None => panic!("a bind frame has a header"),
        };
        let mut reader = Reader::new(body);
        let portal = match reader.cstring() {
            Ok(portal) => portal,
            Err(error) => panic!("the rewritten bind has no portal: {error}"),
        };
        let named = match reader.cstring() {
            Ok(named) => named,
            Err(error) => panic!("the rewritten bind names nothing: {error}"),
        };
        assert_eq!(portal, b"", "the portal the client asked for is kept");
        assert_eq!(named, global.as_bytes(), "the client's name is translated away");
    }

    #[test]
    fn a_statement_that_outlives_its_transaction_pins_the_session() {
        assert!(pins(b"SET search_path TO app"));
        assert!(pins(b"set search_path to app"), "keywords are not case-sensitive");
        assert!(pins(b"  \n\t set time zone 'utc'"), "leading blanks do not hide it");
        assert!(pins(b"select pg_advisory_lock(1)"), "a trigger anywhere pins");
        assert!(pins(b"DECLARE c CURSOR WITH HOLD FOR select 1"));
    }

    #[test]
    fn a_statement_the_transaction_takes_with_it_does_not_pin() {
        assert!(!pins(b"SET LOCAL work_mem = '1MB'"));
        assert!(!pins(b"set local work_mem = '1MB'"));
        assert!(!pins(b"SET TRANSACTION ISOLATION LEVEL SERIALIZABLE"));
        assert!(!pins(b"SET CONSTRAINTS ALL DEFERRED"));
        assert!(!pins(b"select 1"));
        assert!(!pins(b""));
    }

    #[test]
    fn an_ordinary_write_does_not_pin_the_session_to_its_backend() {
        assert!(!pins(b"update users set name = 'x' where id = 1"));
        assert!(!pins(b"UPDATE users SET name = 'x' WHERE id = 1"));
        assert!(!pins(
            b"insert into t values (1) on conflict (id) do update set n = 2"
        ));
        assert!(
            !pins(b"select 'set search_path to evil'"),
            "a trigger inside a string literal is text, not a statement"
        );
    }

    #[test]
    fn a_session_level_advisory_lock_pins_however_it_is_taken() {
        assert!(pins(b"select pg_advisory_lock(1)"));
        assert!(pins(b"select pg_try_advisory_lock(1)"));
        assert!(pins(b"select pg_advisory_lock_shared(1)"));
        assert!(pins(b"select pg_try_advisory_lock_shared(1)"));
        assert!(pins(b"select pg_advisory_unlock(1)"));
        assert!(pins(b"select pg_advisory_unlock_all()"));
    }

    #[test]
    fn a_lock_the_transaction_releases_does_not_pin() {
        assert!(!pins(b"select pg_advisory_xact_lock(1)"));
        assert!(!pins(b"select pg_try_advisory_xact_lock(1)"));
        assert!(!pins(b"select pg_advisory_xact_lock_shared(1)"));
    }

    #[test]
    fn a_quote_inside_another_quoting_does_not_hide_a_later_trigger() {
        assert!(
            pins(b"select $$'$$; set search_path to evil"),
            "an apostrophe inside a dollar quote is text, not an opening quote"
        );
        assert!(
            pins(b"select e'\\'' ; set search_path to evil"),
            "a backslash-escaped quote does not end an E string"
        );
        assert!(
            pins(b"select \"it's\"; set search_path to evil"),
            "an apostrophe inside a quoted name is part of the name"
        );
    }

    #[test]
    fn a_statement_that_opens_with_a_comment_still_pins() {
        assert!(pins(b"/* shahrah: key=7 */ set search_path to app"));
        assert!(pins(b"-- why\nset search_path to app"));
        assert!(pins(b"select 1; /* then */ set search_path to app"));
    }

    #[test]
    fn a_semicolon_that_is_not_a_statement_boundary_does_not_pin() {
        assert!(!pins(b"select 'a; set search_path to evil'"));
        assert!(!pins(b"select 1 /* ; set search_path to evil */"));
        assert!(!pins(b"select 1 -- ; set search_path to evil"));
        assert!(!pins(
            b"create function f() returns int as $$ begin set x = 1; return 1; end $$ language plpgsql"
        ));
    }

    #[test]
    fn a_trigger_after_a_semicolon_still_pins() {
        assert!(pins(b"select 1; set search_path to app"));
        assert!(pins(b"update t set n = 1; set search_path to app"));
        assert!(
            !pins(b"update t set n = 1; select 2"),
            "two writes in one frame are still two writes"
        );
        assert!(
            pins(b"set local a = 1; set b = 2"),
            "the second statement pins even though the first would not"
        );
    }
}
