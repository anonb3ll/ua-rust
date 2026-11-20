//! `ua serve` stops its background loops with one cancellation token: each
//! loop returns promptly once the token is cancelled, whether it was
//! cancelled before the loop started or while it waits for its next tick.

use std::time::Duration;

use tokio_util::sync::CancellationToken;
use ua_core::Config;
use ua_tools::Hub;
use ua_tools::families::{dispatch, github, node_queue, routines};

fn hub() -> Hub {
    let mut cfg = Config::for_home(std::env::temp_dir());
    cfg.node_wait_sweep_s = 3600;
    cfg.dispatch_reaper_interval_s = Some(3600);
    cfg.github_poll_interval_s = 3600;
    Hub::in_memory(cfg).unwrap()
}

fn spawn_all(hub: &Hub, ct: &CancellationToken) -> Vec<tokio::task::JoinHandle<()>> {
    let mut tasks = vec![tokio::spawn(routines::run_ticker(hub.clone(), ct.clone()))];
    tasks.extend(dispatch::spawn_reaper(hub, ct.clone()));
    tasks.extend(node_queue::spawn_sweeper(hub, ct.clone()));
    tasks.extend(github::spawn_poller(hub, ct.clone()));
    assert_eq!(tasks.len(), 4, "every loop is enabled in this config");
    tasks
}

async fn all_stop(tasks: Vec<tokio::task::JoinHandle<()>>) {
    for t in tasks {
        tokio::time::timeout(Duration::from_secs(5), t)
            .await
            .expect("a background loop kept running after cancellation")
            .unwrap();
    }
}

#[tokio::test]
async fn background_loops_stop_when_cancelled_while_waiting() {
    let hub = hub();
    let ct = CancellationToken::new();
    let tasks = spawn_all(&hub, &ct);
    // Let each loop run its first (immediate) tick and park on the next.
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(tasks.iter().all(|t| !t.is_finished()), "loops run until cancelled");
    ct.cancel();
    all_stop(tasks).await;
}

#[tokio::test]
async fn background_loops_started_after_cancellation_do_no_work() {
    let hub = hub();
    let ct = CancellationToken::new();
    ct.cancel();
    all_stop(spawn_all(&hub, &ct)).await;
}
