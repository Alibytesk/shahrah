use std::time::Duration;

pub fn flag(name: &str) -> Result<bool, String> {
    read_flag(name, std::env::var(name).ok().as_deref())
}

pub fn count(name: &str, fallback: usize) -> Result<usize, String> {
    read_count(name, std::env::var(name).ok().as_deref(), fallback)
}

pub fn seconds(name: &str, fallback: Option<Duration>) -> Result<Option<Duration>, String> {
    read_span(
        name,
        std::env::var(name).ok().as_deref(),
        fallback,
        Span::Seconds,
    )
}

pub fn millis(name: &str, fallback: Option<Duration>) -> Result<Option<Duration>, String> {
    read_span(
        name,
        std::env::var(name).ok().as_deref(),
        fallback,
        Span::Millis,
    )
}

#[derive(Clone, Copy)]
enum Span {
    Seconds,
    Millis,
}

impl Span {
    const fn named(self) -> &'static str {
        match self {
            Self::Seconds => "seconds",
            Self::Millis => "milliseconds",
        }
    }

    const fn of(self, asked: u64) -> Duration {
        match self {
            Self::Seconds => Duration::from_secs(asked),
            Self::Millis => Duration::from_millis(asked),
        }
    }
}

fn read_flag(name: &str, given: Option<&str>) -> Result<bool, String> {
    let Some(trimmed) = given.map(str::trim).filter(|given| !given.is_empty()) else {
        return Ok(false);
    };
    if ["yes", "true", "on", "1"]
        .iter()
        .any(|word| trimmed.eq_ignore_ascii_case(word))
    {
        return Ok(true);
    }
    if ["no", "false", "off", "0"]
        .iter()
        .any(|word| trimmed.eq_ignore_ascii_case(word))
    {
        return Ok(false);
    }
    Err(format!(
        "{name} is set to \"{trimmed}\", which is neither yes nor no. shahrah will not start \
         rather than guess at a setting that decides what it is safe to do"
    ))
}

fn read_count(name: &str, given: Option<&str>, fallback: usize) -> Result<usize, String> {
    let Some(trimmed) = given.map(str::trim).filter(|given| !given.is_empty()) else {
        return Ok(fallback);
    };
    trimmed.parse::<usize>().map_err(|_not_a_number| {
        format!(
            "{name} is set to \"{trimmed}\", which is not a whole number. shahrah will not start \
             rather than fall back to {fallback} and let a typo size it"
        )
    })
}

fn read_span(
    name: &str,
    given: Option<&str>,
    fallback: Option<Duration>,
    span: Span,
) -> Result<Option<Duration>, String> {
    let Some(trimmed) = given.map(str::trim).filter(|given| !given.is_empty()) else {
        return Ok(fallback);
    };
    let asked = trimmed.parse::<u64>().map_err(|_not_a_number| {
        format!(
            "{name} is set to \"{trimmed}\", which is not a whole number of {}. shahrah will not \
             start rather than let a typo turn a bound off",
            span.named()
        )
    })?;
    if asked == 0 {
        return Ok(None);
    }
    Ok(Some(span.of(asked)))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{read_count, read_flag, read_span, Span};

    const NAME: &str = "SHAHRAH_A_SETTING";

    #[test]
    fn a_flag_reads_the_words_people_write_for_yes_and_no() {
        for yes in ["yes", "YES", "true", "on", "1", " yes "] {
            assert_eq!(read_flag(NAME, Some(yes)), Ok(true), "{yes} means yes");
        }
        for no in ["no", "NO", "false", "off", "0", "", "  "] {
            assert_eq!(read_flag(NAME, Some(no)), Ok(false), "{no:?} means no");
        }
        assert_eq!(read_flag(NAME, None), Ok(false), "unset means no");
    }

    #[test]
    fn a_flag_that_says_something_else_refuses_rather_than_guesses() {
        assert!(
            read_flag(NAME, Some("disable")).is_err(),
            "a word shahrah does not know is not a no"
        );
        assert!(read_flag(NAME, Some("maybe")).is_err());
        assert!(read_flag(NAME, Some("2")).is_err());
    }

    #[test]
    fn a_number_that_will_not_parse_refuses_rather_than_falls_back() {
        assert_eq!(read_count(NAME, Some("40"), 20), Ok(40));
        assert_eq!(read_count(NAME, None, 20), Ok(20));
        assert_eq!(read_count(NAME, Some(""), 20), Ok(20));
        assert!(
            read_count(NAME, Some("2O"), 20).is_err(),
            "a letter O is not a zero"
        );
        assert!(read_count(NAME, Some("-1"), 20).is_err());
    }

    #[test]
    fn a_bound_of_zero_turns_the_bound_off() {
        let nine = Some(Duration::from_secs(9));
        assert_eq!(read_span(NAME, Some("0"), nine, Span::Seconds), Ok(None));
        assert_eq!(read_span(NAME, Some("0"), nine, Span::Millis), Ok(None));
    }

    #[test]
    fn a_bound_is_read_in_the_unit_it_is_named_in() {
        assert_eq!(
            read_span(NAME, Some("30"), None, Span::Seconds),
            Ok(Some(Duration::from_secs(30)))
        );
        assert_eq!(
            read_span(NAME, Some("30"), None, Span::Millis),
            Ok(Some(Duration::from_millis(30)))
        );
        assert_eq!(read_span(NAME, None, nine(), Span::Seconds), Ok(nine()));
        assert!(read_span(NAME, Some("half a minute"), None, Span::Seconds).is_err());
    }

    fn nine() -> Option<Duration> {
        Some(Duration::from_secs(9))
    }
}
