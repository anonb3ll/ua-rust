//! The lease reaper.
//!
//! One sweep:
//! 1. finishes cancellations whose intent was recorded but never finalized
//!    (a crash between the intent write and the stop attempt), so the lease
//!    path below never turns such a run into a plain `retryable` one;
//! 2. for every live run whose lease has passed: renews it when this process
//!    still supervises the child at the same fence; kills the group of a
//!    recorded child proven to be an orphan (see
//!    [`executor::orphan_proof`]) and hands the run back as `retryable`
//!    (`lease_expired_orphan_killed`); fails it with
//!    `lease_expired_outcome_unknown` when a recorded pid that cannot be
//!    proven ours is still alive (a resume would overlap it); otherwise hands
//!    it back as `retryable` (`lease_expired`) for `dispatch_resume`.
//!
//! `ua serve` runs one sweep at startup, so runs a previous hub process left
//! behind are reconciled before new work arrives, then [`spawn_reaper`] runs
//! it every `Config::dispatch_reaper_interval()` seconds (a third of the
//! lease by default). [`reap_expired_leases`] is also callable directly.

use std::time::Duration;

use serde_json::{Value, json};
use ua_core::UaResult;

use super::{Outcome, after_seconds, classify_termination, executor, finalize_cancellation, now, runs_where};
use crate::hub::Hub;

const ACTOR: &str = "lease-reaper";

/// Run one reaper sweep. Blocking: call it off the async runtime.
pub fn reap_expired_leases(hub: &Hub) -> UaResult<Value> {
    let db = hub.db();

    // 1. Unfinished cancellations.
    let pending = db.read(|c| runs_where(c, "termination_outcome = 'requested'"))?;
    let mut reconciled = Vec::new();
    for run in pending {
        let termination = executor::terminate(&run);
        let cessation = classify_termination(termination);
        let res = db.write(|tx| {
            finalize_cancellation(
                tx,
                &run.run_id,
                ACTOR,
                "reaper",
                "reconciled_cancellation",
                termination,
                cessation,
            )
        })?;
        reconciled.push(json!({ "run_id": run.run_id, "termination": termination, "cessation": cessation, "result": res }));
    }

    // 2. Expired leases.
    let live = db.read(|c| {
        runs_where(
            c,
            "state IN ('claimed','launched','running') AND lease_expires_at IS NOT NULL \
             AND termination_outcome IS NULL",
        )
    })?;
    let now_ts = jiff::Timestamp::now();
    let lease = hub.cfg().dispatch_lease_seconds.max(1);
    let (mut reclaimed, mut renewed, mut failed) = (Vec::new(), Vec::new(), Vec::new());
    for run in live {
        let expired =
            run.lease_expires_at.as_deref().and_then(ua_core::time::parse_ts).is_none_or(|exp| exp <= now_ts);
        if !expired {
            continue;
        }
        if executor::supervises(&run.run_id, run.fence) {
            let (rid, fence) = (run.run_id.clone(), run.fence);
            db.write(|tx| {
                tx.execute(
                    "UPDATE dispatch_runs SET lease_expires_at = ?3, updated_at = ?4 \
                     WHERE run_id = ?1 AND fence = ?2 AND termination_outcome IS NULL",
                    rusqlite::params![rid, fence, after_seconds(lease), now()],
                )?;
                Ok(())
            })?;
            renewed.push(json!({ "run_id": run.run_id }));
            continue;
        }
        let termination = executor::terminate(&run);
        let (state, reason) = match termination {
            "already_gone" => ("retryable", "lease_expired"),
            "killed" | "killed_orphan" => ("retryable", "lease_expired_orphan_killed"),
            _ => ("failed", "lease_expired_outcome_unknown"),
        };
        let orphan_alive = state == "failed";
        let res = db.write(|tx| {
            super::record_outcome(
                tx,
                Outcome {
                    run_id: &run.run_id,
                    fence: Some(run.fence),
                    state,
                    actor: ACTOR,
                    source: "reaper",
                    evidence: None,
                    failure_reason: Some(reason.into()),
                    failure_class: Some("lease".into()),
                    usage: None,
                },
            )
        })?;
        if res["ok"] == json!(true) {
            let row = json!({
                "run_id": run.run_id, "task_id": run.task_id, "state": state, "failure_reason": reason,
                "termination": termination,
            });
            if orphan_alive { failed.push(row) } else { reclaimed.push(row) }
        }
    }
    Ok(json!({
        "reconciled": reconciled,
        "renewed": renewed,
        "reclaimed": reclaimed,
        "failed": failed,
    }))
}

/// Run one sweep off the async runtime, logging what it did. `ua serve`
/// calls it once before it starts serving.
pub async fn startup_sweep(hub: &Hub) {
    let h = hub.clone();
    match tokio::task::spawn_blocking(move || reap_expired_leases(&h)).await {
        Ok(Ok(v)) => {
            let n = |k: &str| v[k].as_array().map_or(0, Vec::len);
            tracing::info!(
                reconciled = n("reconciled"),
                reclaimed = n("reclaimed"),
                failed = n("failed"),
                "dispatch startup sweep"
            );
        }
        Ok(Err(e)) => tracing::warn!(error = %e, "dispatch startup sweep failed"),
        Err(e) => tracing::warn!(error = %e, "dispatch startup sweep task failed"),
    }
}

/// Start the background reaper unless `dispatch_reaper_interval_s` is 0.
pub fn spawn_reaper(hub: &Hub) -> Option<tokio::task::JoinHandle<()>> {
    let secs = hub.cfg().dispatch_reaper_interval();
    if secs == 0 {
        return None;
    }
    let hub = hub.clone();
    Some(tokio::spawn(async move {
        // The first sweep is one period out: `ua serve` sweeps once itself
        // at startup ([`startup_sweep`]).
        let period = Duration::from_secs(secs);
        let mut tick = tokio::time::interval_at(tokio::time::Instant::now() + period, period);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            let h = hub.clone();
            match tokio::task::spawn_blocking(move || reap_expired_leases(&h)).await {
                Ok(Ok(_)) => {}
                Ok(Err(e)) => tracing::warn!(error = %e, "dispatch lease reaper sweep failed"),
                Err(e) => tracing::warn!(error = %e, "dispatch lease reaper task failed"),
            }
        }
    }))
}
