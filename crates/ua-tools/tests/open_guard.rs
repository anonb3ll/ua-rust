//! The migration guard is the default open: a program that embeds the hub
//! and calls `Hub::open` gets it without asking. A migration (an open that
//! would apply a part the database does not record yet) is refused while
//! another process holds the database's serve lock; the serving process
//! migrates by showing its own held lock (`Hub::open_serving`).
//!
//! `flock` locks belong to the open file, so a `ServeLock` taken in this test
//! stands for another process holding it.

#![cfg(unix)]

use ua_core::Config;
use ua_store::ServeLock;
use ua_tools::Hub;

/// Make the database one part older than this build (`code.v1` is
/// idempotent SQL, so re-applying it is a real, small migration).
fn forget_a_part(cfg: &Config) {
    let conn = rusqlite::Connection::open(cfg.db_path()).unwrap();
    assert_eq!(conn.execute("DELETE FROM schema_parts WHERE name = 'code.v1'", []).unwrap(), 1);
}

fn records_code_part(cfg: &Config) -> bool {
    let conn = rusqlite::Connection::open(cfg.db_path()).unwrap();
    conn.query_row("SELECT count(*) FROM schema_parts WHERE name = 'code.v1'", [], |r| r.get::<_, i64>(0))
        .unwrap()
        == 1
}

#[test]
fn a_plain_open_refuses_to_migrate_underneath_a_serve_and_migrates_without_one() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = Config::for_home(dir.path().join("home"));
    // No serve: a plain open creates and migrates the database.
    drop(Hub::open(cfg.clone()).unwrap());

    let serve = ServeLock::acquire(&cfg.db_path()).unwrap();
    // Nothing to apply: a plain open beside the serve works.
    drop(Hub::open(cfg.clone()).unwrap());
    // A migration is refused, with or without the recovery override.
    forget_a_part(&cfg);
    for err in [Hub::open(cfg.clone()).err(), Hub::open_with(cfg.clone(), true).err()] {
        let err = err.expect("refused").to_string();
        assert!(err.contains("a running `ua serve` holds the database"), "{err}");
        assert!(err.contains("[code.v1]"), "{err}");
    }
    assert!(!records_code_part(&cfg), "nothing applied");

    // The serve goes away: the plain open migrates.
    drop(serve);
    drop(Hub::open(cfg.clone()).unwrap());
    assert!(records_code_part(&cfg));
}

#[test]
fn the_serving_process_migrates_with_its_own_lock_and_only_that_lock() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = Config::for_home(dir.path().join("home"));
    drop(Hub::open(cfg.clone()).unwrap());
    forget_a_part(&cfg);

    let serve = ServeLock::acquire(&cfg.db_path()).unwrap();
    // A serve lock for another database proves nothing about this one.
    let other = ServeLock::acquire(&dir.path().join("other").join("ua.db")).unwrap();
    let err = Hub::open_serving(cfg.clone(), &other).err().expect("refused").to_string();
    assert!(err.contains("a running `ua serve` holds the database"), "{err}");
    assert!(!records_code_part(&cfg));
    // Its own lock does.
    drop(Hub::open_serving(cfg.clone(), &serve).unwrap());
    assert!(records_code_part(&cfg));
}

#[test]
fn an_in_memory_hub_has_no_file_and_no_guard() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = Config::for_home(dir.path().join("home"));
    let _serve = ServeLock::acquire(&cfg.db_path()).unwrap();
    drop(Hub::in_memory(cfg).unwrap());
}
