//! The unknown-part fence from the command line: a database that records a
//! schema part this build does not know (one a newer build applied) is
//! refused by `ua serve` and the writing commands, with the part named;
//! `ua doctor` and `ua backup` still run on it; the override opens it and
//! says so loudly; and restoring a backup taken before the upgrade recovers.

use std::path::Path;
use std::process::{Command, Output};

use serde_json::Value;

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

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

/// A home whose database a "newer build" upgraded: it records `future.v9`
/// and the table that part created. Returns the backup taken before.
fn upgraded_home(root: &Path) -> (std::path::PathBuf, std::path::PathBuf) {
    let home = root.join("hub-home");
    let init = ua(&home).args(["init", "--home", home.to_str().unwrap(), "--json"]).output().unwrap();
    assert!(init.status.success(), "{}", text(&init.stderr));
    // The current build creates the database.
    let made = ua(&home).args(["tools", "--names"]).output().unwrap();
    assert!(made.status.success(), "{}", text(&made.stderr));
    let before = root.join("before-upgrade.db");
    let bak = ua(&home).args(["backup", "--to", before.to_str().unwrap()]).output().unwrap();
    assert!(bak.status.success(), "{}", text(&bak.stderr));
    let conn = rusqlite::Connection::open(home.join("ua.db")).unwrap();
    conn.execute_batch(
        "CREATE TABLE future_things (id INTEGER PRIMARY KEY);
         INSERT INTO schema_parts (name, checksum, applied_at) VALUES ('future.v9', 'x', '2026-11-21T00:00:00Z');",
    )
    .unwrap();
    (home, before)
}

fn assert_refused(out: &Output, what: &str) {
    let err = text(&out.stderr);
    assert!(!out.status.success(), "{what} must refuse: {err}");
    assert!(err.contains("written by a newer build"), "{what}: {err}");
    assert!(err.contains("[future.v9]"), "{what} names the unknown part: {err}");
    assert!(err.contains("restore a backup taken before the upgrade"), "{what}: {err}");
    assert!(err.contains("UA_ALLOW_NEWER_SCHEMA=1"), "{what}: {err}");
}

#[test]
fn a_database_from_a_newer_build_is_refused_for_serving_and_writing() {
    let root = tempfile::tempdir().unwrap();
    let (home, _) = upgraded_home(root.path());

    // Serving: refused before the port is bound.
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let serve = ua(&home).arg("serve").env("UA_BIND", format!("127.0.0.1:{port}")).output().unwrap();
    assert_refused(&serve, "ua serve");
    assert!(!text(&serve.stderr).contains("hub listening"));
    // Writing (and every other command that opens the hub).
    let call = ua(&home).args(["call", "task_add", r#"{"title":"after a downgrade"}"#]).output().unwrap();
    assert_refused(&call, "ua call");
    assert_refused(&ua(&home).args(["token", "issue", "agent-1"]).output().unwrap(), "ua token issue");
    assert_refused(&ua(&home).args(["tools", "--names"]).output().unwrap(), "ua tools");

    // Diagnosis still runs, and says what is wrong.
    let doctor = ua(&home).args(["doctor", "--json"]).output().unwrap();
    let rep: Value =
        serde_json::from_slice(&doctor.stdout).unwrap_or_else(|e| panic!("{e}: {}", text(&doctor.stdout)));
    let schema = rep["checks"].as_array().unwrap().iter().find(|c| c["name"] == "schema").unwrap().clone();
    assert_eq!(schema["status"], "fail", "{schema}");
    let detail = schema["detail"].as_str().unwrap();
    assert!(detail.contains("written by a newer build") && detail.contains("future.v9"), "{schema}");
    // So does a backup: a read-only snapshot.
    let snap = root.path().join("fenced.db");
    let bak = ua(&home).args(["backup", "--to", snap.to_str().unwrap()]).output().unwrap();
    assert!(bak.status.success(), "{}", text(&bak.stderr));
}

#[test]
fn the_override_opens_it_and_logs_and_a_bad_value_is_refused() {
    let root = tempfile::tempdir().unwrap();
    let (home, _) = upgraded_home(root.path());

    for (env, flag) in [(Some("1"), false), (None, true)] {
        let mut cmd = ua(&home);
        if let Some(v) = env {
            cmd.env("UA_ALLOW_NEWER_SCHEMA", v);
        }
        if flag {
            cmd.arg("--allow-newer-schema");
        }
        let out = cmd.args(["call", "task_list", "{}"]).output().unwrap();
        let err = text(&out.stderr);
        assert!(out.status.success(), "env={env:?} flag={flag}: {err}");
        assert!(err.contains("OPENING A DATABASE WRITTEN BY A NEWER BUILD"), "{err}");
        assert!(err.contains("future.v9"), "{err}");
        assert!(err.contains("replay window"), "{err}");
    }
    // Off unless explicitly on; anything unclear is refused, not guessed.
    assert_refused(&ua(&home).env("UA_ALLOW_NEWER_SCHEMA", "0").args(["tools"]).output().unwrap(), "=0");
    let bad = ua(&home).env("UA_ALLOW_NEWER_SCHEMA", "maybe").args(["tools"]).output().unwrap();
    assert!(!bad.status.success());
    assert!(text(&bad.stderr).contains("UA_ALLOW_NEWER_SCHEMA must be 1"), "{}", text(&bad.stderr));
}

#[test]
fn restoring_a_backup_from_before_the_upgrade_recovers() {
    let root = tempfile::tempdir().unwrap();
    let (home, before) = upgraded_home(root.path());
    let restore = ua(&home)
        .args(["restore", "--from", before.to_str().unwrap(), "--force", "--allow-unpinned"])
        .output()
        .unwrap();
    assert!(restore.status.success(), "{}", text(&restore.stderr));
    let call = ua(&home).args(["call", "task_list", "{}"]).output().unwrap();
    assert!(call.status.success(), "{}", text(&call.stderr));
    assert!(!text(&call.stderr).contains("NEWER BUILD"));
}
