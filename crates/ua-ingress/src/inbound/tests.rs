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

/// Record and accept `key` at `at`; the claim it was taken on under.
fn take(db: &Db, key: &str, at: i64) -> Claim {
    db.write(|tx| {
        let sight = record(tx, d(key), at, RULES, None)?;
        let claim = sight.claim().cloned().expect("taken on");
        assert!(accept(tx, d(key), &claim, at, Some("operator"))?);
        Ok(claim)
    })
    .unwrap()
}

/// Make a row look as a stopped process left it.
fn orphan(db: &Db, key: &str) {
    let key = key.to_string();
    db.write(move |tx| {
        tx.execute(
            "UPDATE inbound_deliveries SET claim = 'a-stopped-process:0' WHERE delivery_key = ?1",
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
    assert!(matches!(first, Sight::First { .. }), "{first:?}");
    assert!(first.claim().unwrap().as_str().starts_with(process_prefix()));
    assert_eq!(state(&db, d("a")).as_deref(), Some("seen"));
    let again = db.write(|tx| record(tx, d("a"), T0 + 1, RULES, None)).unwrap();
    assert_eq!(again, Sight::Duplicate { state: State::Seen });
    assert_eq!(again.claim(), None);
}

#[test]
fn each_taking_on_gets_its_own_claim() {
    let db = db();
    let a = take(&db, "a", T0);
    let b = take(&db, "b", T0);
    assert_ne!(a, b);
    // Accepting needs the claim the row was recorded under.
    db.write(|tx| record(tx, d("c"), T0, RULES, None)).unwrap();
    assert!(!db.write(|tx| accept(tx, d("c"), &a, T0, None)).unwrap());
}

#[test]
fn a_live_accepted_delivery_is_a_duplicate_and_a_finished_one_stays_one() {
    let db = db();
    let claim = take(&db, "a", T0);
    let again = db.write(|tx| record(tx, d("a"), T0 + 5, RULES, None)).unwrap();
    assert_eq!(again, Sight::Duplicate { state: State::Accepted });
    assert_eq!(db.write(|tx| finish(tx, d("a"), &claim, T0 + 6)).unwrap(), Settle::Settled);
    let after = db.write(|tx| record(tx, d("a"), T0 + 7, RULES, None)).unwrap();
    assert_eq!(after, Sight::Duplicate { state: State::Finished });
    assert!(!db.write(|tx| accept(tx, d("a"), &claim, T0 + 8, None)).unwrap(), "only a seen row is accepted");
}

#[test]
fn an_accepted_delivery_of_a_stopped_process_is_redelivered_or_refused_by_rule() {
    let db = db();
    take(&db, "a", T0);
    orphan(&db, "a");
    let refused = db.write(|tx| record(tx, d("a"), T0 + 1, Rules { stale: Stale::Duplicate, ..RULES }, None));
    assert_eq!(refused.unwrap(), Sight::Duplicate { state: State::Accepted });
    let again = db.write(|tx| record(tx, d("a"), T0 + 2, RULES, None)).unwrap();
    assert!(matches!(again, Sight::Redelivered { was: State::Accepted, .. }), "{again:?}");
    assert_eq!(state(&db, d("a")).as_deref(), Some("seen"), "taken on again from the start");
    let claim = again.claim().cloned().unwrap();
    db.write(|tx| accept(tx, d("a"), &claim, T0 + 2, None)).unwrap();
    let dup = db.write(|tx| record(tx, d("a"), T0 + 3, RULES, None)).unwrap();
    assert_eq!(dup, Sight::Duplicate { state: State::Accepted });
}

#[test]
fn an_accepted_delivery_past_the_in_flight_bound_is_stale_even_for_this_process() {
    let db = db();
    take(&db, "a", T0);
    let inside = db.write(|tx| record(tx, d("a"), T0 + 600, RULES, None)).unwrap();
    assert_eq!(inside, Sight::Duplicate { state: State::Accepted });
    let past = db.write(|tx| record(tx, d("a"), T0 + 601, RULES, None)).unwrap();
    assert!(matches!(past, Sight::Redelivered { was: State::Accepted, .. }), "{past:?}");
}

#[test]
fn release_makes_a_delivery_deliverable_again() {
    let db = db();
    let claim = take(&db, "a", T0);
    assert_eq!(db.write(|tx| release(tx, d("a"), &claim)).unwrap(), Settle::Settled);
    assert_eq!(state(&db, d("a")), None);
    let next = db.write(|tx| record(tx, d("a"), T0 + 1, RULES, None)).unwrap();
    assert!(matches!(next, Sight::First { .. }));
    assert_eq!(
        db.write(|tx| release(tx, d("missing"), &claim)).unwrap(),
        Settle::NotMine { state: None },
        "no row"
    );
}

// --- settling only what is still the caller's -------------------------------------------

#[test]
fn finish_after_the_sweep_abandoned_the_same_claim_marks_it_finished() {
    let db = db();
    let slow = take(&db, "a", T0);
    let rules = SweepRules { max_per_kind: None, abandon_after_s: Some(600) };
    let swept = db.write(|tx| sweep(tx, ua_core::DEFAULT_ORG, "demo", T0 + 700, rules)).unwrap();
    assert_eq!(swept.abandoned.len(), 1);
    // The slow handler finishes: the row is still its own (same claim), so
    // a later copy is a duplicate instead of running again.
    assert_eq!(db.write(|tx| finish(tx, d("a"), &slow, T0 + 701)).unwrap(), Settle::Settled);
    let later = db.write(|tx| record(tx, d("a"), T0 + 702, RULES, None)).unwrap();
    assert_eq!(later, Sight::Duplicate { state: State::Finished });
}

#[test]
fn release_after_the_sweep_abandoned_the_row_leaves_the_report_standing() {
    let db = db();
    let slow = take(&db, "a", T0);
    db.write(|tx| {
        sweep(
            tx,
            ua_core::DEFAULT_ORG,
            "demo",
            T0 + 700,
            SweepRules { max_per_kind: None, abandon_after_s: Some(600) },
        )
    })
    .unwrap();
    let r = db.write(|tx| release(tx, d("a"), &slow)).unwrap();
    assert_eq!(r, Settle::NotMine { state: Some(State::Abandoned) });
    assert_eq!(state(&db, d("a")).as_deref(), Some("abandoned"));
}

#[test]
fn a_slow_original_cannot_settle_a_row_taken_over_since() {
    let db = db();
    let slow = take(&db, "a", T0);
    // Past the bound, a redelivery takes it over under a new claim.
    let over = db.write(|tx| record(tx, d("a"), T0 + 601, RULES, None)).unwrap();
    let newer = over.claim().cloned().unwrap();
    db.write(|tx| accept(tx, d("a"), &newer, T0 + 601, None)).unwrap();
    // Neither finishing nor releasing under the old claim touches it.
    let f = db.write(|tx| finish(tx, d("a"), &slow, T0 + 602)).unwrap();
    assert_eq!(f, Settle::NotMine { state: Some(State::Accepted) });
    let r = db.write(|tx| release(tx, d("a"), &slow)).unwrap();
    assert_eq!(r, Settle::NotMine { state: Some(State::Accepted) });
    assert_eq!(state(&db, d("a")).as_deref(), Some("accepted"));
    // The newer owner settles it.
    assert_eq!(db.write(|tx| finish(tx, d("a"), &newer, T0 + 603)).unwrap(), Settle::Settled);
    // ...and the old claim still cannot undo that.
    let r = db.write(|tx| release(tx, d("a"), &slow)).unwrap();
    assert_eq!(r, Settle::NotMine { state: Some(State::Finished) });
    assert_eq!(state(&db, d("a")).as_deref(), Some("finished"));
}

#[test]
fn release_of_a_finished_row_is_refused_even_for_its_own_claim() {
    let db = db();
    let claim = take(&db, "a", T0);
    db.write(|tx| finish(tx, d("a"), &claim, T0 + 1)).unwrap();
    let r = db.write(|tx| release(tx, d("a"), &claim)).unwrap();
    assert_eq!(r, Settle::NotMine { state: Some(State::Finished) });
    assert_eq!(state(&db, d("a")).as_deref(), Some("finished"));
    // A second finish is not a settlement either.
    let again = db.write(|tx| finish(tx, d("a"), &claim, T0 + 2)).unwrap();
    assert_eq!(again, Settle::NotMine { state: Some(State::Finished) });
}

#[test]
fn a_claim_of_another_process_settles_nothing() {
    let db = db();
    take(&db, "a", T0);
    orphan(&db, "a");
    let stranger = Claim::from_raw(format!("{}999999", process_prefix()));
    assert_eq!(
        db.write(|tx| finish(tx, d("a"), &stranger, T0 + 1)).unwrap(),
        Settle::NotMine { state: Some(State::Accepted) }
    );
    assert_eq!(state(&db, d("a")).as_deref(), Some("accepted"));
}

// --- the sweep ------------------------------------------------------------------------------------

#[test]
fn sweep_expires_rows_but_never_an_accepted_one() {
    let db = db();
    db.write(|tx| {
        record(tx, d("old-seen"), T0, RULES, None)?;
        Ok(())
    })
    .unwrap();
    let done = take(&db, "old-done", T0);
    db.write(|tx| finish(tx, d("old-done"), &done, T0)).unwrap();
    take(&db, "old-running", T0);
    db.write(|tx| record(tx, d("young"), T0 + 3000, RULES, None)).unwrap();
    let rules = SweepRules { max_per_kind: None, abandon_after_s: None };
    let swept = db.write(|tx| sweep(tx, ua_core::DEFAULT_ORG, "demo", T0 + 3600, rules)).unwrap();
    assert_eq!(swept.expired, 2);
    assert_eq!(state(&db, d("old-seen")), None);
    assert_eq!(state(&db, d("old-done")), None);
    assert_eq!(state(&db, d("old-running")).as_deref(), Some("accepted"), "waits for the abandon step");
    assert_eq!(state(&db, d("young")).as_deref(), Some("seen"));
    let other = Delivery { source: "other", ..d("x") };
    db.write(|tx| record(tx, other, T0, RULES, None)).unwrap();
    db.write(|tx| sweep(tx, ua_core::DEFAULT_ORG, "demo", T0 + 99_999, rules)).unwrap();
    assert_eq!(state(&db, other).as_deref(), Some("seen"), "another source is untouched");
}

#[test]
fn sweep_abandons_stuck_rows_and_reports_them() {
    let db = db();
    for k in ["stopped", "hung", "live"] {
        take(&db, k, T0);
    }
    db.write(|tx| {
        tx.execute("UPDATE inbound_deliveries SET updated_at = ?1 WHERE delivery_key = 'live'", [T0 + 500])?;
        Ok(())
    })
    .unwrap();
    orphan(&db, "stopped");
    let rules = SweepRules { max_per_kind: None, abandon_after_s: Some(600) };
    let swept = db.write(|tx| sweep(tx, ua_core::DEFAULT_ORG, "demo", T0 + 700, rules)).unwrap();
    let keys: Vec<&str> = swept.abandoned.iter().map(|a| a.key.as_str()).collect();
    assert_eq!(keys, ["hung", "stopped"]);
    assert_eq!(swept.abandoned[0].identity.as_deref(), Some("operator"));
    assert_eq!(state(&db, d("hung")).as_deref(), Some("abandoned"));
    assert_eq!(state(&db, d("live")).as_deref(), Some("accepted"));
    let dup =
        db.write(|tx| record(tx, d("hung"), T0 + 701, Rules { stale: Stale::Duplicate, ..RULES }, None));
    assert_eq!(dup.unwrap(), Sight::Duplicate { state: State::Abandoned });
    let again = db.write(|tx| record(tx, d("hung"), T0 + 702, RULES, None)).unwrap();
    assert!(matches!(again, Sight::Redelivered { was: State::Abandoned, .. }), "{again:?}");
    db.write(|tx| {
        sweep(
            tx,
            ua_core::DEFAULT_ORG,
            "demo",
            T0 + 99_999,
            SweepRules { max_per_kind: None, abandon_after_s: None },
        )
    })
    .unwrap();
    assert_eq!(state(&db, d("stopped")), None, "abandoned rows expire like any other");
}

#[test]
fn sweep_caps_each_kind_keeping_the_newest_and_any_accepted() {
    let db = db();
    take(&db, "k0", T0);
    db.write(|tx| {
        for i in 1..5 {
            record(tx, d(&format!("k{i}")), T0 + i, RULES, None)?;
        }
        record(tx, Delivery { kind: "body", ..d("b") }, T0, RULES, None)?;
        Ok(())
    })
    .unwrap();
    let swept = db.write(|tx| {
        sweep(
            tx,
            ua_core::DEFAULT_ORG,
            "demo",
            T0 + 10,
            SweepRules { max_per_kind: Some(2), abandon_after_s: None },
        )
    });
    assert_eq!(swept.unwrap().capped, 2, "k1 and k2 go; k0 is accepted");
    for (k, kept) in [("k0", true), ("k1", false), ("k2", false), ("k3", true), ("k4", true)] {
        assert_eq!(state(&db, d(k)).is_some(), kept, "{k}");
    }
    assert!(state(&db, Delivery { kind: "body", ..d("b") }).is_some(), "the cap is per kind");
}

// --- organizations and shape ------------------------------------------------------------------

#[test]
fn two_organizations_do_not_collide() {
    let db = db();
    let acme = Delivery { org_id: "acme", ..d("same") };
    assert!(matches!(db.write(|tx| record(tx, d("same"), T0, RULES, None)).unwrap(), Sight::First { .. }));
    let sight = db.write(|tx| record(tx, acme, T0, RULES, None)).unwrap();
    let claim = sight.claim().cloned().unwrap();
    db.write(|tx| accept(tx, acme, &claim, T0, None)).unwrap();
    db.write(|tx| finish(tx, acme, &claim, T0)).unwrap();
    assert_eq!(state(&db, d("same")).as_deref(), Some("seen"));
    assert_eq!(state(&db, acme).as_deref(), Some("finished"));
    let ghost = Delivery { org_id: "no-such-org", ..d("x") };
    assert!(db.write(|tx| record(tx, ghost, T0, RULES, None)).is_err(), "the tenant trigger refuses it");
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

#[test]
fn a_sweep_touches_only_its_organization() {
    let db = db();
    let acme = Delivery { org_id: "acme", ..d("a") };
    db.write(|tx| record(tx, acme, T0, RULES, None)).unwrap();
    let sight = db.write(|tx| record(tx, Delivery { org_id: "acme", ..d("b") }, T0, RULES, None)).unwrap();
    let claim = sight.claim().cloned().unwrap();
    db.write(|tx| accept(tx, Delivery { org_id: "acme", ..d("b") }, &claim, T0, None)).unwrap();
    let rules = SweepRules { max_per_kind: Some(0), abandon_after_s: Some(0) };
    let swept = db.write(|tx| sweep(tx, ua_core::DEFAULT_ORG, "demo", T0 + 99_999, rules)).unwrap();
    assert_eq!(swept, Swept::default(), "nothing in the default organization");
    assert_eq!(state(&db, acme).as_deref(), Some("seen"));
    assert_eq!(state(&db, Delivery { org_id: "acme", ..d("b") }).as_deref(), Some("accepted"));
    let swept = db.write(|tx| sweep(tx, "acme", "demo", T0 + 99_999, rules)).unwrap();
    assert_eq!(swept.abandoned.len(), 1);
    assert!(swept.abandoned.iter().all(|a| a.org_id == "acme"));
}
