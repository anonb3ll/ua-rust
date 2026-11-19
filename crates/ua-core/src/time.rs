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
}
