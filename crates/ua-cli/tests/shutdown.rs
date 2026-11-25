//! `ua serve` stops gracefully on SIGTERM: it exits 0 well inside its grace
//! period even with an event stream open (the stream ends on shutdown), and
//! leaves the WAL checkpointed and truncated. A dispatch run in flight ends
//! with a `hub_shutdown` receipt and leaves no grandchild behind, and a
//! second signal exits at once.

#![cfg(unix)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// Start `ua serve` on a port picked just before the spawn. The binary logs
/// the configured address rather than the bound one, so it cannot be asked for
/// port 0 and read back; instead a bind clash (another process took the port
/// between the pick and the bind: the server exits with "Address already in
/// use") is retried with a new port, up to five times. Returns the child, its
/// port, the log thread and the channel that signals "hub listening".
fn spawn_serve(
    home: &std::path::Path,
    extra: &[(&str, &str)],
) -> (std::process::Child, u16, std::thread::JoinHandle<String>, mpsc::Receiver<()>) {
    for attempt in 1..=5 {
        let port = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_ua"));
        cmd.arg("serve")
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("HOME", home)
            .env("UA_HOME", home)
            .env("UA_BIND", format!("127.0.0.1:{port}"))
            .env("NO_COLOR", "1");
        for (k, v) in extra {
            cmd.env(k, v);
        }
        let mut child = cmd.stdout(Stdio::null()).stderr(Stdio::piped()).spawn().unwrap();
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
        match rx.recv_timeout(Duration::from_secs(60)) {
            Ok(()) => return (child, port, reader, rx),
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                let log = reader.join().unwrap();
                if attempt < 5 && log.contains("Address already in use") {
                    continue;
                }
                panic!("the hub did not start:\n{log}");
            }
        }
    }
    unreachable!()
}

#[test]
fn sigterm_drains_and_checkpoints_the_wal() {
    let home = tempfile::tempdir().unwrap();
    let (mut child, port, reader, _listening) = spawn_serve(
        home.path(),
        &[("UA_ENFORCE_AUTH", "false"), ("UA_ROUTINES_ENABLED", "true"), ("UA_LOG", "info")],
    );

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
    // A build without the mcp-server feature says at startup that it serves
    // no MCP.
    let warned = log.contains("built without the mcp-server feature");
    assert_eq!(warned, !cfg!(feature = "mcp-server"), "{log}");
    assert_eq!(std::fs::metadata(&wal).map(|m| m.len()).unwrap_or(0), 0, "the WAL was truncated\n{log}");
}

const AGENT: &str = "agent-test-token-0001";
const OPERATOR: &str = "operator-test-token-0002";

/// A running `ua serve` with an agent and a human token and one harness
/// (`hang`) whose child backgrounds a grandchild in `work`.
struct Hub {
    child: std::process::Child,
    port: u16,
    home: tempfile::TempDir,
    work: tempfile::TempDir,
    log: Option<std::thread::JoinHandle<String>>,
}

/// A failing test must not leave a hub (or its runs) behind.
impl Drop for Hub {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

fn start_hub() -> Hub {
    let (home, work) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let config = format!(
        "human_identities = [\"operator\"]\nagent_tokens = \"agent-1:{AGENT},operator:{OPERATOR}\"\n\n\
         [profiles]\noperator = \"operator\"\n\n\
         [harnesses.hang]\nargv = [\"/bin/sh\", \"-c\", \"sleep 300 & echo $! > grandchild.pid; wait\"]\n\
         timeout_s = 600\nworkdir = \"{}\"\n",
        work.path().display()
    );
    std::fs::write(home.path().join("config.toml"), config).unwrap();
    let (child, port, log, _listening) = spawn_serve(home.path(), &[("UA_LOG", "info")]);
    Hub { child, port, home, work, log: Some(log) }
}

impl Hub {
    /// `POST /api/tools/{tool}` with a bearer token: (status, body).
    fn call(&self, token: &str, tool: &str, args: serde_json::Value) -> (u16, serde_json::Value) {
        let body = args.to_string();
        let mut s = TcpStream::connect(("127.0.0.1", self.port)).unwrap();
        write!(
            s,
            "POST /api/tools/{tool} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nAuthorization: Bearer {token}\r\n\
             Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            self.port,
            body.len()
        )
        .unwrap();
        let mut out = String::new();
        s.read_to_string(&mut out).unwrap();
        let status: u16 = out[9..12].parse().unwrap();
        let json = out.split_once("\r\n\r\n").map(|(_, b)| b).unwrap_or("");
        (status, serde_json::from_str(json).unwrap_or(serde_json::Value::Null))
    }

    /// Dispatch the `hang` harness for a new task; returns the run id and
    /// the grandchild's pid.
    fn dispatch(&self) -> (String, i32) {
        let (st, task) = self.call(AGENT, "task_add", serde_json::json!({ "title": "Long run" }));
        assert_eq!(st, 200, "{task}");
        let args = serde_json::json!({ "task_id": task["id"], "agent": "agent-1", "harness": "hang" });
        let (st, parked) = self.call(AGENT, "dispatch_task", args.clone());
        assert_eq!(st, 202, "{parked}");
        let approval = parked["approval_id"].as_i64().unwrap_or_else(|| panic!("{parked}"));
        let (st, v) = self.call(
            OPERATOR,
            "approval_resolve",
            serde_json::json!({ "id": approval, "decision": "approve" }),
        );
        assert_eq!(st, 200, "{v}");
        let (st, run) = self.call(AGENT, "dispatch_task", args);
        assert_eq!((st, run["state"].as_str()), (200, Some("running")), "{run}");
        let pidfile = self.work.path().join("grandchild.pid");
        for _ in 0..100 {
            if let Some(pid) = std::fs::read_to_string(&pidfile).ok().and_then(|s| s.trim().parse().ok()) {
                return (run["run_id"].as_str().unwrap().to_string(), pid);
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!("the harness wrote no grandchild pid");
    }

    fn signal(&self, sig: &str) {
        assert!(Command::new("kill").args([sig, &self.child.id().to_string()]).status().unwrap().success());
    }

    /// Wait for the process to exit: (status, time taken, log).
    fn wait(&mut self, started: Instant, limit: Duration) -> (std::process::ExitStatus, Duration, String) {
        let exit = loop {
            if let Some(s) = self.child.try_wait().unwrap() {
                break s;
            }
            if started.elapsed() > limit {
                let _ = self.child.kill();
                let _ = self.child.wait();
                panic!("the hub did not exit:\n{}", self.log.take().unwrap().join().unwrap());
            }
            std::thread::sleep(Duration::from_millis(50));
        };
        (exit, started.elapsed(), self.log.take().unwrap().join().unwrap())
    }
}

fn alive(pid: i32) -> bool {
    std::path::Path::new(&format!("/proc/{pid}")).exists()
        || Command::new("kill")
            .args(["-0", &pid.to_string()])
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .success()
}

fn gone_soon(pid: i32) -> bool {
    for _ in 0..40 {
        if !alive(pid) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

#[test]
fn a_dispatch_run_in_flight_at_sigterm_ends_with_a_hub_shutdown_receipt() {
    let mut hub = start_hub();
    let (run_id, grandchild) = hub.dispatch();
    assert!(alive(grandchild));
    let started = Instant::now();
    hub.signal("-TERM");
    let (exit, took, log) = hub.wait(started, Duration::from_secs(20));
    assert!(exit.success(), "exit {exit:?}\n{log}");
    // Runs may finish until 3 s before the 10 s grace ends, then stop.
    assert!(took < Duration::from_secs(10), "{took:?}\n{log}");
    assert!(log.contains("dispatch runs stopped for the shutdown"), "{log}");
    assert!(gone_soon(grandchild), "grandchild {grandchild} outlived the hub\n{log}");
    let db = rusqlite::Connection::open(hub.home.path().join("ua.db")).unwrap();
    let (state, reason): (String, String) = db
        .query_row("SELECT state, failure_reason FROM dispatch_runs WHERE run_id = ?1", [&run_id], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .unwrap();
    assert_eq!((state.as_str(), reason.as_str()), ("retryable", "hub_shutdown"));
    let (source, rstate): (String, String) = db
        .query_row(
            "SELECT source, state FROM dispatch_receipts WHERE run_id = ?1 ORDER BY id DESC LIMIT 1",
            [&run_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!((source.as_str(), rstate.as_str()), ("hub_shutdown", "retryable"));
}

#[test]
fn a_second_signal_exits_at_once_and_kills_run_groups() {
    let mut hub = start_hub();
    let (_, grandchild) = hub.dispatch();
    hub.signal("-TERM");
    std::thread::sleep(Duration::from_millis(500));
    let started = Instant::now();
    hub.signal("-TERM");
    let (exit, took, log) = hub.wait(started, Duration::from_secs(5));
    assert_eq!(exit.code(), Some(143), "{log}");
    assert!(took < Duration::from_secs(2), "{took:?}\n{log}");
    assert!(log.contains("second signal: exiting now"), "{log}");
    assert!(gone_soon(grandchild), "grandchild {grandchild} outlived the forced exit\n{log}");
}
