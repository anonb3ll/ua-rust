//! `ua serve` stops gracefully on SIGTERM: it exits 0 well inside its grace
//! period even with an event stream open (the stream ends on shutdown), and
//! leaves the WAL checkpointed and truncated.

#![cfg(unix)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

#[test]
fn sigterm_drains_and_checkpoints_the_wal() {
    let home = tempfile::tempdir().unwrap();
    let port = free_port();
    let mut child = Command::new(env!("CARGO_BIN_EXE_ua"))
        .arg("serve")
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", home.path())
        .env("UA_HOME", home.path())
        .env("UA_BIND", format!("127.0.0.1:{port}"))
        .env("UA_ENFORCE_AUTH", "false")
        .env("UA_ROUTINES_ENABLED", "true")
        .env("UA_LOG", "info")
        .env("NO_COLOR", "1")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    // Collect the log on a thread; signal when the hub is listening.
    let (tx, rx) = mpsc::channel::<String>();
    let stderr = child.stderr.take().unwrap();
    let reader = std::thread::spawn(move || {
        let mut log = String::new();
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            if line.contains("hub listening") {
                let _ = tx.send(line.clone());
            }
            log.push_str(&line);
            log.push('\n');
        }
        log
    });
    if rx.recv_timeout(Duration::from_secs(60)).is_err() {
        let _ = child.kill();
        panic!("the hub did not start:\n{}", reader.join().unwrap());
    }

    // Hold an event stream open across the shutdown.
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    write!(
        stream,
        "GET /api/events/stream HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nAccept: text/event-stream\r\n\r\n"
    )
    .unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut head = [0u8; 12];
    stream.read_exact(&mut head).unwrap();
    assert_eq!(&head, b"HTTP/1.1 200", "the event stream opened");

    let wal = home.path().join("ua.db-wal");
    assert!(std::fs::metadata(&wal).map(|m| m.len()).unwrap_or(0) > 0, "the running hub has a WAL");

    let started = Instant::now();
    let status = Command::new("kill").args(["-TERM", &child.id().to_string()]).status().unwrap();
    assert!(status.success());
    let exit = loop {
        if let Some(s) = child.try_wait().unwrap() {
            break s;
        }
        if started.elapsed() > Duration::from_secs(20) {
            let _ = child.kill();
            panic!("the hub did not exit after SIGTERM:\n{}", reader.join().unwrap());
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let took = started.elapsed();
    let log = reader.join().unwrap();
    assert!(exit.success(), "exit {exit:?}\n{log}");
    // The open stream ended with the shutdown instead of holding it for the
    // whole 10 s grace period.
    assert!(took < Duration::from_secs(8), "shutdown took {took:?}\n{log}");
    assert!(log.contains("signal=\"SIGTERM\"") || log.contains("signal=SIGTERM"), "{log}");
    assert!(log.contains("WAL checkpointed and truncated"), "{log}");
    assert!(log.contains("hub stopped"), "{log}");
    assert_eq!(std::fs::metadata(&wal).map(|m| m.len()).unwrap_or(0), 0, "the WAL was truncated\n{log}");
}
