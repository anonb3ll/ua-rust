//! Timestamps.
//!
//! Stored timestamps are RFC 3339 UTC strings with second precision and an
//! explicit `+00:00` offset, the same text form the original hub writes, so
//! values sort lexically and imported rows compare correctly.

use jiff::Timestamp;

/// The current time as stored in the database, e.g. `2026-11-19T10:04:05+00:00`.
pub fn now() -> String {
    format_ts(Timestamp::now())
}

/// Format a timestamp in the storage form.
pub fn format_ts(ts: Timestamp) -> String {
    ts.strftime("%Y-%m-%dT%H:%M:%S+00:00").to_string()
}

/// Parse any RFC 3339 timestamp (with `Z` or an offset).
pub fn parse_ts(s: &str) -> Option<Timestamp> {
    s.parse::<Timestamp>().ok()
}

/// Current Unix time in milliseconds.
pub fn now_ms() -> i64 {
    Timestamp::now().as_millisecond()
}

/// An injectable clock. [`Clock::System`] reads the wall clock; a
/// [`Clock::Fixed`] clock always answers the same instant, so a test or the
/// memory retrieval bench gives the same result on every day it runs.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Clock {
    /// The wall clock.
    #[default]
    System,
    /// Always this instant.
    Fixed(Timestamp),
}

impl Clock {
    /// A fixed clock at an RFC 3339 instant; `None` if `ts` does not parse.
    pub fn fixed(ts: &str) -> Option<Self> {
        parse_ts(ts).map(Self::Fixed)
    }

    /// The current instant on this clock.
    pub fn timestamp(&self) -> Timestamp {
        match self {
            Self::System => Timestamp::now(),
            Self::Fixed(ts) => *ts,
        }
    }

    /// [`now`] on this clock.
    pub fn now(&self) -> String {
        format_ts(self.timestamp())
    }

    /// [`now_ms`] on this clock.
    pub fn now_ms(&self) -> i64 {
        self.timestamp().as_millisecond()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn storage_form_round_trips() {
        let s = now();
        assert!(s.ends_with("+00:00"), "{s}");
        assert_eq!(s.len(), 25);
        let parsed = parse_ts(&s).unwrap();
        assert_eq!(format_ts(parsed), s);
    }

    #[test]
    fn a_fixed_clock_does_not_move() {
        let clock = Clock::fixed("2026-03-01T00:00:00Z").unwrap();
        assert_eq!(clock.now(), "2026-03-01T00:00:00+00:00");
        assert_eq!(clock.now(), clock.now());
        assert_eq!(clock.now_ms(), 1_772_323_200_000);
        assert!(Clock::fixed("not a time").is_none());
        assert_eq!(Clock::default(), Clock::System);
    }
}
