//! One `ua serve` per database: a second one on the same database is refused
//! before it opens the database or binds a port; other commands run beside
//! it; the lock goes with the process (a crash included); and two databases
//! do not block each other.

#![cfg(unix)]

use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::{Child, Command, Output, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

fn ua(home: &Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_ua"));
    cmd.env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", home)
        .env("UA_HOME", home)
        .env("UA_ENFORCE_AUTH", "false")
        .env("UA_LOG", "info")
        .env("NO_COLOR", "1");
    cmd
}

/// Start `ua serve` on port 0 (nothing here connects to it, so no port is
/// picked in advance and none can be taken in between) and wait for "hub
/// listening".
fn spawn_serve(home: &Path) -> Child {
    let mut child = ua(home)
        .arg("serve")
        .env("UA_BIND", "127.0.0.1:0")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let (tx, rx) = mpsc::channel::<()>();
    let stderr = child.stderr.take().unwrap();
    let reader = std::thread::spawn(move || {
        let mut log = String::new();
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            if line.contains("hub listening") {
                let _ = tx.send(());
            }
            log.push_str(&line);
            log.push('\n');
        }
        log
    });
    if rx.recv_timeout(Duration::from_secs(60)).is_ok() {
        return child;
    }
    let _ = child.kill();
    let _ = child.wait();
    panic!("the hub did not start:\n{}", reader.join().unwrap());
}

/// Run a second `ua serve` to completion (it must exit by itself). It is
/// asked for port 0, so it could bind if it got that far: whether it did is
/// read from its log, not guessed from a port.
fn second_serve(home: &Path) -> Output {
    let mut child = ua(home)
        .arg("serve")
        .env("UA_BIND", "127.0.0.1:0")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if child.try_wait().unwrap().is_some() {
            return child.wait_with_output().unwrap();
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let out = child.wait_with_output().unwrap();
            panic!("the second ua serve did not exit:\n{}", String::from_utf8_lossy(&out.stderr));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// A Slack command admitted by "the running serve" and not finished: the
/// startup sweep of any serve that got as far as serving would abandon it.
fn plant_in_flight_slack_command(db: &Path) {
    let conn = rusqlite::Connection::open(db).unwrap();
    conn.busy_timeout(Duration::from_secs(10)).unwrap();
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
    conn.execute(
        "INSERT INTO inbound_deliveries \
         (org_id, source, kind, delivery_key, state, received_at, updated_at, expires_at, claim, identity) \
         VALUES ('default', 'slack', 'trigger', 'in-flight-1', 'accepted', ?1, ?1, ?2, 'claim-of-the-first', 'op')",
        rusqlite::params![now, now + 86_400],
    )
    .unwrap();
}

/// The planted row's state, the parts recorded and the abandonments ledgered.
fn snapshot(db: &Path) -> (String, i64, i64) {
    let conn = rusqlite::Connection::open(db).unwrap();
    conn.busy_timeout(Duration::from_secs(10)).unwrap();
    let state = conn
        .query_row("SELECT state FROM inbound_deliveries WHERE delivery_key = 'in-flight-1'", [], |r| {
            r.get(0)
        })
        .unwrap();
    let parts = conn.query_row("SELECT count(*) FROM schema_parts", [], |r| r.get(0)).unwrap();
    let abandoned = conn
        .query_row(
            "SELECT count(*) FROM event_log WHERE channel = 'agent.slack.request.abandoned'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    (state, parts, abandoned)
}

#[test]
fn a_second_serve_on_the_same_database_is_refused_until_the_first_exits() {
    let home = tempfile::tempdir().unwrap();
    let mut first = spawn_serve(home.path());

    let db = std::fs::canonicalize(home.path()).unwrap().join("ua.db");
    plant_in_flight_slack_command(&db);
    let before = snapshot(&db);
    let out = second_serve(home.path());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "{err}");
    assert!(err.contains("another `ua serve` holds the database"), "{err}");
    assert!(err.contains(&db.display().to_string()), "names the database: {err}");
    // Refused before it opened the hub or bound a port, so it swept nothing:
    // the first serve's in-flight command is still in flight.
    assert!(!err.contains("hub listening") && !err.contains("abandoned"), "{err}");
    let after = snapshot(&db);
    assert_eq!(after.0, "accepted", "the in-flight Slack command was not abandoned");
    assert_eq!((after.1, after.2), (before.1, before.2), "no part applied, no abandonment ledgered");

    // A non-serve command still runs beside the serving process.
    let tools = ua(home.path()).args(["tools", "--names"]).output().unwrap();
    assert!(tools.status.success(), "{}", String::from_utf8_lossy(&tools.stderr));
    assert!(String::from_utf8_lossy(&tools.stdout).lines().count() > 10);
    let call = ua(home.path()).args(["call", "task_list", "{}"]).output().unwrap();
    assert!(call.status.success(), "{}", String::from_utf8_lossy(&call.stderr));

    // The first one dies without a clean shutdown: the OS releases the lock,
    // and nothing stale is left behind to clean up.
    first.kill().unwrap();
    first.wait().unwrap();
    let mut again = spawn_serve(home.path());
    again.kill().unwrap();
    again.wait().unwrap();
}

#[test]
fn two_databases_do_not_block_each_other() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let mut first = spawn_serve(a.path());
    let mut second = spawn_serve(b.path());
    for child in [&mut first, &mut second] {
        child.kill().unwrap();
        child.wait().unwrap();
    }
}

/// Make the database look one part older than this build: `code.v1`'s SQL
/// is idempotent, so re-applying it is a real (if small) migration.
fn forget_a_part(db: &Path) {
    let conn = rusqlite::Connection::open(db).unwrap();
    conn.busy_timeout(Duration::from_secs(10)).unwrap();
    assert_eq!(conn.execute("DELETE FROM schema_parts WHERE name = 'code.v1'", []).unwrap(), 1);
}

fn records_code_part(db: &Path) -> bool {
    let conn = rusqlite::Connection::open(db).unwrap();
    conn.query_row("SELECT count(*) FROM schema_parts WHERE name = 'code.v1'", [], |r| r.get::<_, i64>(0))
        .unwrap()
        == 1
}

#[test]
fn a_migration_beside_a_running_serve_is_refused_and_serve_migrates_itself() {
    let home = tempfile::tempdir().unwrap();
    let db = std::fs::canonicalize(home.path()).unwrap().join("ua.db");
    let mut serve = spawn_serve(home.path());

    // A no-op open beside the serve (same build, nothing to apply) works.
    let tools = ua(home.path()).args(["tools", "--names"]).output().unwrap();
    assert!(tools.status.success(), "{}", String::from_utf8_lossy(&tools.stderr));

    // The serve is now "older": this build would apply a part under it.
    forget_a_part(&db);
    for override_on in [false, true] {
        let mut cmd = ua(home.path());
        if override_on {
            cmd.arg("--allow-newer-schema");
        }
        let out = cmd.args(["call", "task_list", "{}"]).output().unwrap();
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(!out.status.success(), "{err}");
        assert!(err.contains("a running `ua serve` holds the database"), "{err}");
        assert!(err.contains(&db.display().to_string()) && err.contains("[code.v1]"), "{err}");
        assert!(err.contains("Stop the running `ua serve`"), "{err}");
    }
    assert!(!records_code_part(&db), "nothing was applied");

    // With no serve running the same migration goes ahead.
    serve.kill().unwrap();
    serve.wait().unwrap();
    let call = ua(home.path()).args(["call", "task_list", "{}"]).output().unwrap();
    assert!(call.status.success(), "{}", String::from_utf8_lossy(&call.stderr));
    assert!(records_code_part(&db));

    // `ua serve` migrates at startup under its own lock.
    forget_a_part(&db);
    let mut serve = spawn_serve(home.path());
    assert!(records_code_part(&db));
    serve.kill().unwrap();
    serve.wait().unwrap();
}
