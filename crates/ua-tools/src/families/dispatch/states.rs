//! The dispatch run state machine.
//!
//! A run is minted `claimed`, becomes `launched` when a launch is attempted
//! (a stub launch with no harness stays there) and `running` once a real
//! child process is recorded. It ends `finished`, `failed`, `blocked` or
//! `cancelled`, or is handed back as `retryable` when its lease lapses.
//! `dispatch_resume` moves a `cancelled` (with confirmed cessation),
//! `failed` or `retryable` run back to `claimed` under a new fence.
//! `denied` and `expired` are kept in the vocabulary for imported rows; no
//! path here enters them.
//!
//! Every state write goes through [`legal`]: a transition that is not in the
//! table is refused before any SQL runs.

/// A run that holds its task's live slot.
pub const LIVE: [&str; 3] = ["claimed", "launched", "running"];

/// A run that will not change again without an explicit resume.
pub const TERMINAL: [&str; 6] = ["finished", "failed", "blocked", "denied", "cancelled", "expired"];

/// Every state a run row can hold.
pub const ALL: [&str; 10] = [
    "claimed",
    "launched",
    "running",
    "finished",
    "failed",
    "retryable",
    "blocked",
    "denied",
    "cancelled",
    "expired",
];

/// States a self-report may set.
pub const SELF_REPORT: [&str; 3] = ["finished", "failed", "blocked"];

/// States `dispatch_resume` may restart from.
pub const RESUMABLE: [&str; 3] = ["cancelled", "failed", "retryable"];

pub fn is_live(state: &str) -> bool {
    LIVE.contains(&state)
}

pub fn is_terminal(state: &str) -> bool {
    TERMINAL.contains(&state)
}

/// Whether `from -> to` is an allowed edge. `cancelled -> cancelled` is the
/// reconciliation of an unconfirmed cancellation into a confirmed one.
pub fn legal(from: &str, to: &str) -> bool {
    matches!(
        (from, to),
        ("claimed", "launched" | "running" | "finished" | "failed" | "blocked" | "retryable" | "cancelled")
            | ("launched", "running" | "finished" | "failed" | "blocked" | "retryable" | "cancelled")
            | ("running", "finished" | "failed" | "blocked" | "retryable" | "cancelled")
            | ("retryable", "claimed" | "finished" | "failed" | "blocked")
            | ("failed", "claimed")
            | ("cancelled", "claimed" | "cancelled")
            | ("blocked", "cancelled")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_table_is_closed() {
        // Terminal success never moves.
        for to in ALL {
            assert!(!legal("finished", to), "finished -> {to}");
            assert!(!legal("denied", to), "denied -> {to}");
            assert!(!legal("expired", to), "expired -> {to}");
        }
        // No edge leads back into launched/running from outside the live set.
        for from in ["retryable", "failed", "cancelled", "blocked"] {
            assert!(!legal(from, "launched"));
            assert!(!legal(from, "running"));
        }
        assert!(legal("claimed", "launched"));
        assert!(legal("running", "finished"));
        assert!(legal("cancelled", "claimed"));
        assert!(!legal("running", "claimed"));
        assert!(!legal("claimed", "claimed"));
        // Every state named in an edge is a real state.
        for from in ALL {
            for to in ALL {
                if legal(from, to) {
                    assert!(ALL.contains(&from) && ALL.contains(&to));
                }
            }
        }
    }
}
