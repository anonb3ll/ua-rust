//! The inbound-delivery table and its API, on an in-memory store.

use ua_store::Db;

use super::*;

const T0: i64 = 1_800_000_000;
const RULES: Rules = Rules { ttl_s: 3600, in_flight_s: 600, stale: Stale::Redeliver };

fn db() -> Db {
    let mut parts: Vec<Part> = vec![ua_store::ledger::SCHEMA.into(), ua_store::org::STORE_PART.into()];
    parts.extend(schema_parts());
    let db = Db::open_in_memory(&parts).unwrap();
    db.write(|tx| {
        tx.execute(
            "INSERT INTO orgs (id, slug, display_name, allowed_profiles, created_at) \
             VALUES ('acme', 'acme', 'Acme', '[]', '2026-01-01T00:00:00+00:00')",
            [],
        )?;
        Ok(())
    })
    .unwrap();
    db
}

fn d<'a>(key: &'a str) -> Delivery<'a> {
    Delivery { org_id: ua_core::DEFAULT_ORG, source: "demo", kind: "id", key }
}

fn state(db: &Db, dl: Delivery<'_>) -> Option<String> {
    let (o, s, k, key) =
        (dl.org_id.to_string(), dl.source.to_string(), dl.kind.to_string(), dl.key.to_string());
    db.read(move |c| {
        Ok(c.query_row(
            "SELECT state FROM inbound_deliveries WHERE org_id = ?1 AND source = ?2 AND kind = ?3 \
             AND delivery_key = ?4",
            params![o, s, k, key],
            |r| r.get(0),
        )
        .optional()?)
    })
    .unwrap()
}

/// Make a row look as a stopped process left it.
fn orphan(db: &Db, key: &str) {
    let key = key.to_string();
    db.write(move |tx| {
        tx.execute(
            "UPDATE inbound_deliveries SET claim = 'a-stopped-process' WHERE delivery_key = ?1",
            [key],
        )?;
        Ok(())
    })
    .unwrap();
}

#[test]
fn first_sight_then_duplicate() {
    let db = db();
    let first = db.write(|tx| record(tx, d("a"), T0, RULES, Some("push"))).unwrap();
    assert_eq!(first, Sight::First);
    assert_eq!(state(&db, d("a")).as_deref(), Some("seen"));
    let again = db.write(|tx| record(tx, d("a"), T0 + 1, RULES, None)).unwrap();
    assert_eq!(again, Sight::Duplicate { state: State::Seen });
}

#[test]
fn a_live_accepted_delivery_is_a_duplicate_and_a_finished_one_stays_one() {
    let db = db();
    db.write(|tx| {
        record(tx, d("a"), T0, RULES, None)?;
        assert!(accept(tx, d("a"), T0, Some("operator"))?);
        Ok(())
    })
    .unwrap();
    // In flight under this process's claim: another copy is a duplicate.
    let again = db.write(|tx| record(tx, d("a"), T0 + 5, RULES, None)).unwrap();
    assert_eq!(again, Sight::Duplicate { state: State::Accepted });
    assert!(db.write(|tx| finish(tx, d("a"), T0 + 6)).unwrap());
    // Finished is a duplicate whatever the stale rule says.
    let after = db.write(|tx| record(tx, d("a"), T0 + 7, RULES, None)).unwrap();
    assert_eq!(after, Sight::Duplicate { state: State::Finished });
    assert!(!db.write(|tx| accept(tx, d("a"), T0 + 8, None)).unwrap(), "only a seen row is accepted");
}

#[test]
fn an_accepted_delivery_of_a_stopped_process_is_redelivered_or_refused_by_rule() {
    let db = db();
    db.write(|tx| {
        record(tx, d("a"), T0, RULES, None)?;
        accept(tx, d("a"), T0, None)
    })
    .unwrap();
    orphan(&db, "a");
    let refused = db.write(|tx| record(tx, d("a"), T0 + 1, Rules { stale: Stale::Duplicate, ..RULES }, None));
    assert_eq!(refused.unwrap(), Sight::Duplicate { state: State::Accepted });
    let again = db.write(|tx| record(tx, d("a"), T0 + 2, RULES, None)).unwrap();
    assert_eq!(again, Sight::Redelivered { was: State::Accepted });
    assert_eq!(state(&db, d("a")).as_deref(), Some("seen"), "taken on again from the start");
    // Now it is this process's again: a further copy is a duplicate.
    db.write(|tx| accept(tx, d("a"), T0 + 2, None)).unwrap();
    let dup = db.write(|tx| record(tx, d("a"), T0 + 3, RULES, None)).unwrap();
    assert_eq!(dup, Sight::Duplicate { state: State::Accepted });
}

#[test]
fn an_accepted_delivery_past_the_in_flight_bound_is_stale_even_for_this_process() {
    let db = db();
    db.write(|tx| {
        record(tx, d("a"), T0, RULES, None)?;
        accept(tx, d("a"), T0, None)
    })
    .unwrap();
    let inside = db.write(|tx| record(tx, d("a"), T0 + 600, RULES, None)).unwrap();
    assert_eq!(inside, Sight::Duplicate { state: State::Accepted });
    let past = db.write(|tx| record(tx, d("a"), T0 + 601, RULES, None)).unwrap();
    assert_eq!(past, Sight::Redelivered { was: State::Accepted });
}

#[test]
fn release_makes_a_delivery_deliverable_again() {
    let db = db();
    db.write(|tx| {
        record(tx, d("a"), T0, RULES, None)?;
        accept(tx, d("a"), T0, None)
    })
    .unwrap();
    assert!(db.write(|tx| release(tx, d("a"))).unwrap());
    assert_eq!(state(&db, d("a")), None);
    assert_eq!(db.write(|tx| record(tx, d("a"), T0 + 1, RULES, None)).unwrap(), Sight::First);
    assert!(!db.write(|tx| release(tx, d("missing"))).unwrap());
}

#[test]
fn sweep_expires_rows_but_never_an_accepted_one() {
    let db = db();
    db.write(|tx| {
        record(tx, d("old-seen"), T0, RULES, None)?;
        record(tx, d("old-done"), T0, RULES, None)?;
        finish(tx, d("old-done"), T0)?;
        record(tx, d("old-running"), T0, RULES, None)?;
        accept(tx, d("old-running"), T0, None)?;
        record(tx, d("young"), T0 + 3000, RULES, None)?;
        Ok(())
    })
    .unwrap();
    let rules = SweepRules { max_per_kind: None, abandon_after_s: None };
    let swept = db.write(|tx| sweep(tx, "demo", T0 + 3600, rules)).unwrap();
    assert_eq!(swept.expired, 2);
    assert_eq!(state(&db, d("old-seen")), None);
    assert_eq!(state(&db, d("old-done")), None);
    assert_eq!(state(&db, d("old-running")).as_deref(), Some("accepted"), "waits for the abandon step");
    assert_eq!(state(&db, d("young")).as_deref(), Some("seen"));
    // Another source's rows are untouched.
    let other = Delivery { source: "other", ..d("x") };
    db.write(|tx| record(tx, other, T0, RULES, None)).unwrap();
    db.write(|tx| sweep(tx, "demo", T0 + 99_999, rules)).unwrap();
    assert_eq!(state(&db, other).as_deref(), Some("seen"));
}

#[test]
fn sweep_abandons_stuck_rows_and_reports_them() {
    let db = db();
    db.write(|tx| {
        for k in ["stopped", "hung", "live"] {
            record(tx, d(k), T0, RULES, None)?;
            accept(tx, d(k), T0, Some("operator"))?;
        }
        tx.execute("UPDATE inbound_deliveries SET updated_at = ?1 WHERE delivery_key = 'live'", [T0 + 500])?;
        Ok(())
    })
    .unwrap();
    orphan(&db, "stopped");
    let rules = SweepRules { max_per_kind: None, abandon_after_s: Some(600) };
    let swept = db.write(|tx| sweep(tx, "demo", T0 + 700, rules)).unwrap();
    let keys: Vec<&str> = swept.abandoned.iter().map(|a| a.key.as_str()).collect();
    assert_eq!(keys, ["hung", "stopped"]);
    assert_eq!(swept.abandoned[0].identity.as_deref(), Some("operator"));
    assert_eq!(state(&db, d("hung")).as_deref(), Some("abandoned"));
    assert_eq!(state(&db, d("live")).as_deref(), Some("accepted"));
    // An abandoned delivery is redelivered or refused by the caller's rule.
    let dup =
        db.write(|tx| record(tx, d("hung"), T0 + 701, Rules { stale: Stale::Duplicate, ..RULES }, None));
    assert_eq!(dup.unwrap(), Sight::Duplicate { state: State::Abandoned });
    let again = db.write(|tx| record(tx, d("hung"), T0 + 702, RULES, None)).unwrap();
    assert_eq!(again, Sight::Redelivered { was: State::Abandoned });
    // Abandoned rows expire like any other.
    db.write(|tx| sweep(tx, "demo", T0 + 99_999, SweepRules { max_per_kind: None, abandon_after_s: None }))
        .unwrap();
    assert_eq!(state(&db, d("stopped")), None);
}

#[test]
fn sweep_caps_each_kind_keeping_the_newest_and_any_accepted() {
    let db = db();
    db.write(|tx| {
        for i in 0..5 {
            record(tx, d(&format!("k{i}")), T0 + i, RULES, None)?;
        }
        accept(tx, d("k0"), T0, None)?;
        let body = Delivery { kind: "body", ..d("b") };
        record(tx, body, T0, RULES, None)?;
        Ok(())
    })
    .unwrap();
    let swept = db
        .write(|tx| sweep(tx, "demo", T0 + 10, SweepRules { max_per_kind: Some(2), abandon_after_s: None }));
    assert_eq!(swept.unwrap().capped, 2, "k1 and k2 go; k0 is accepted");
    for (k, kept) in [("k0", true), ("k1", false), ("k2", false), ("k3", true), ("k4", true)] {
        assert_eq!(state(&db, d(k)).is_some(), kept, "{k}");
    }
    assert!(state(&db, Delivery { kind: "body", ..d("b") }).is_some(), "the cap is per kind");
}

#[test]
fn two_organizations_do_not_collide() {
    let db = db();
    let acme = Delivery { org_id: "acme", ..d("same") };
    assert_eq!(db.write(|tx| record(tx, d("same"), T0, RULES, None)).unwrap(), Sight::First);
    assert_eq!(db.write(|tx| record(tx, acme, T0, RULES, None)).unwrap(), Sight::First);
    db.write(|tx| finish(tx, acme, T0)).unwrap();
    assert_eq!(state(&db, d("same")).as_deref(), Some("seen"));
    assert_eq!(state(&db, acme).as_deref(), Some("finished"));
    // An organization the hub does not hold is refused by the tenant trigger.
    let ghost = Delivery { org_id: "no-such-org", ..d("x") };
    assert!(db.write(|tx| record(tx, ghost, T0, RULES, None)).is_err());
}

#[test]
fn malformed_fields_are_refused() {
    let db = db();
    let long = "k".repeat(257);
    for bad in [d(""), Delivery { source: "", ..d("a") }, Delivery { kind: "", ..d("a") }, d(&long)] {
        assert!(db.write(|tx| record(tx, bad, T0, RULES, None)).is_err(), "{bad:?}");
    }
}

#[test]
fn the_table_is_tenant_scoped() {
    let db = db();
    let triggers: Vec<String> = db
        .read(|c| {
            let mut stmt = c.prepare(
                "SELECT name FROM sqlite_master WHERE type = 'trigger' AND tbl_name = 'inbound_deliveries' \
                 ORDER BY name",
            )?;
            Ok(stmt.query_map([], |r| r.get(0))?.collect::<Result<_, _>>()?)
        })
        .unwrap();
    assert_eq!(triggers, ["inbound_deliveries_org_exists", "inbound_deliveries_org_immutable"]);
    let notnull: i64 = db
        .read(|c| {
            Ok(c.query_row(
                "SELECT \"notnull\" FROM pragma_table_info('inbound_deliveries') WHERE name = 'org_id'",
                [],
                |r| r.get(0),
            )?)
        })
        .unwrap();
    assert_eq!(notnull, 1);
}
