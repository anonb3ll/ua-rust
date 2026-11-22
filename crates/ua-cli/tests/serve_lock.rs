//! One `ua serve` per database: a second one on the same database is refused
//! before it opens the database or binds a port; other commands run beside
//! it; the lock goes with the process (a crash included); and two databases
//! do not block each other.

#![cfg(unix)]

use std::io::{BufRead, BufReader};
use std::net::TcpListener;
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

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

/// Start `ua serve` and wait for "hub listening" (retrying a port clash).
fn spawn_serve(home: &Path) -> (Child, u16) {
    for attempt in 1..=5 {
        let port = free_port();
        let mut child = ua(home)
            .arg("serve")
            .env("UA_BIND", format!("127.0.0.1:{port}"))
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
            return (child, port);
        }
        let _ = child.kill();
        let _ = child.wait();
        let log = reader.join().unwrap();
        if attempt < 5 && log.contains("Address already in use") {
            continue;
        }
        panic!("the hub did not start:\n{log}");
    }
    unreachable!()
}

/// Run a second `ua serve` to completion (it must exit by itself).
fn second_serve(home: &Path, port: u16) -> Output {
    let mut child = ua(home)
        .arg("serve")
        .env("UA_BIND", format!("127.0.0.1:{port}"))
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

#[test]
fn a_second_serve_on_the_same_database_is_refused_until_the_first_exits() {
    let home = tempfile::tempdir().unwrap();
    let (mut first, _) = spawn_serve(home.path());

    let port = free_port();
    let out = second_serve(home.path(), port);
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "{err}");
    assert!(err.contains("another `ua serve` holds the database"), "{err}");
    let db = std::fs::canonicalize(home.path()).unwrap().join("ua.db");
    assert!(err.contains(&db.display().to_string()), "names the database: {err}");
    // Refused before it bound a port or opened the hub.
    assert!(!err.contains("hub listening"), "{err}");
    assert!(TcpListener::bind(("127.0.0.1", port)).is_ok(), "the second serve left its port free");

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
    let (mut again, _) = spawn_serve(home.path());
    again.kill().unwrap();
    again.wait().unwrap();
}

#[test]
fn two_databases_do_not_block_each_other() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let (mut first, _) = spawn_serve(a.path());
    let (mut second, _) = spawn_serve(b.path());
    for child in [&mut first, &mut second] {
        child.kill().unwrap();
        child.wait().unwrap();
    }
}
