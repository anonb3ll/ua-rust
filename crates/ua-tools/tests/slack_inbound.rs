//! Slack's replay keys and delivery ids on `ua_ingress::inbound`: replay and
//! duplicate refusal for both transports, the outcome-unknown path, a stale
//! delivery that must never run twice, the copy of the old tables, and
//! organizations.

use serde_json::Value;
use ua_core::{Config, UaError};
use ua_store::ledger::{self, EventQuery};
use ua_tools::Hub;
use ua_tools::families::slack::{self, Admission, DeliveryKind, ReplayKey};

const T0: i64 = 1_700_000_000;

fn config(home: &std::path::Path) -> Config {
    let mut cfg = Config::for_home(home);
    cfg.human_identities = vec!["operator".into(), "reviewer-1".into()];
    cfg.slack_identities = vec![
        ua_core::SlackIdentity {
            team_id: "T0TEAM1".into(),
            user_id: "U0HUMAN".into(),
            identity: "operator".into(),
            can_approve: true,
        },
        ua_core::SlackIdentity {
            team_id: "T0TEAM1".into(),
            user_id: "U0DEV".into(),
            identity: "reviewer-1".into(),
            can_approve: false,
        },
    ];
    cfg
}

struct Env {
    hub: Hub,
    _home: tempfile::TempDir,
}

fn env() -> Env {
    let home = tempfile::tempdir().unwrap();
    let hub = Hub::in_memory(config(home.path())).unwrap();
    Env { hub, _home: home }
}

fn delivery(kind: DeliveryKind, user: &str, id: &str) -> slack::Delivery {
    slack::Delivery {
        kind,
        delivery_id: id.into(),
        team_id: "T0TEAM1".into(),
        user_id: user.into(),
        command: Some("task".into()),
        refusal: None,
    }
}

/// How one request was replay-keyed.
enum Key {
    Signed(&'static str, &'static str),
    Envelope(&'static str),
}

async fn admit(hub: &Hub, key: Key, now: i64, d: slack::Delivery) -> Result<Admission, UaError> {
    let db = hub.db().clone();
    let hub = hub.clone();
    db.write_async(move |tx| {
        let k = match &key {
            Key::Signed(ts, body) => ReplayKey::Signed { timestamp: ts, body: body.as_bytes() },
            Key::Envelope(id) => ReplayKey::Envelope { envelope_id: id },
        };
        slack::admit_keyed(tx, hub.cfg(), k, now, &d)
    })
    .await
}

/// Slack's rows in the table: (kind, key, state, identity), ordered.
async fn rows(hub: &Hub) -> Vec<(String, String, String, Option<String>)> {
    hub.db()
        .read_async(|c| {
            let mut stmt = c.prepare(
                "SELECT kind, delivery_key, state, identity FROM inbound_deliveries WHERE source = 'slack' \
                 AND kind != 'request_sha' ORDER BY kind, delivery_key",
            )?;
            Ok(stmt
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?
                .collect::<Result<_, _>>()?)
        })
        .await
        .unwrap()
}

async fn replay_keys(hub: &Hub) -> i64 {
    hub.db()
        .read_async(|c| {
            Ok(c.query_row(
                "SELECT COUNT(*) FROM inbound_deliveries WHERE source = 'slack' AND kind = 'request_sha'",
                [],
                |r| r.get(0),
            )?)
        })
        .await
        .unwrap()
}

async fn channel(hub: &Hub, name: &str) -> Vec<Value> {
    let name = name.to_string();
    hub.db()
        .read_async(move |c| {
            ledger::query(c, &EventQuery { channels: Some(vec![name]), ..Default::default() })
        })
        .await
        .unwrap()
        .into_iter()
        .map(|e| e.payload)
        .collect()
}

fn accepted(identity: &str) -> Admission {
    Admission::Accepted { identity: identity.into() }
}

#[tokio::test]
async fn replays_and_duplicates_are_refused_on_both_transports() {
    let e = env();
    let cmd = |id| delivery(DeliveryKind::Trigger, "U0HUMAN", id);
    let ev = |id| delivery(DeliveryKind::Event, "U0DEV", id);
    // HTTP: the same signed bytes are a replay; new bytes, same trigger, a duplicate.
    assert_eq!(
        admit(&e.hub, Key::Signed("1700000000", "a"), T0, cmd("1.2.a")).await.unwrap(),
        accepted("operator")
    );
    let replay = admit(&e.hub, Key::Signed("1700000000", "a"), T0, cmd("1.2.z")).await.unwrap_err();
    assert_eq!(replay.reason_code(), Some("replayed"));
    let dup = admit(&e.hub, Key::Signed("1700000001", "b"), T0, cmd("1.2.a")).await.unwrap();
    assert_eq!(dup, Admission::Deduped { identity: "operator".into() });
    // Socket Mode: the same envelope is a replay; one event over both
    // transports runs once.
    assert_eq!(admit(&e.hub, Key::Envelope("env-1"), T0, ev("Ev01")).await.unwrap(), accepted("reviewer-1"));
    let replay = admit(&e.hub, Key::Envelope("env-1"), T0, ev("Ev02")).await.unwrap_err();
    assert_eq!(replay.reason_code(), Some("replayed"));
    let dup = admit(&e.hub, Key::Signed("1700000002", "c"), T0, ev("Ev01")).await.unwrap();
    assert_eq!(dup, Admission::Deduped { identity: "reviewer-1".into() });
    assert_eq!(
        rows(&e.hub).await,
        [
            ("event".into(), "Ev01".into(), "accepted".into(), Some("reviewer-1".into())),
            ("trigger".into(), "1.2.a".into(), "accepted".into(), Some("operator".into())),
        ]
    );
    // a, b, env-1, c: every accepted key, the refused replays rolled back.
    assert_eq!(replay_keys(&e.hub).await, 4);
}

#[tokio::test]
async fn a_stale_slack_delivery_is_never_run_a_second_time() {
    let e = env();
    let cmd = || delivery(DeliveryKind::Trigger, "U0HUMAN", "1.2.s");
    assert_eq!(admit(&e.hub, Key::Signed("1700000000", "a"), T0, cmd()).await.unwrap(), accepted("operator"));
    let dup = Admission::Deduped { identity: "operator".into() };
    // As a stopped process left it...
    e.hub
        .db()
        .write(|tx| {
            tx.execute(
                "UPDATE inbound_deliveries SET claim = 'a-stopped-process:0' WHERE delivery_key = '1.2.s'",
                [],
            )?;
            Ok(())
        })
        .unwrap();
    assert_eq!(admit(&e.hub, Key::Signed("1700000001", "b"), T0 + 60, cmd()).await.unwrap(), dup);
    // ...or a day old in this process: still a duplicate.
    assert_eq!(admit(&e.hub, Key::Signed("1700000002", "c"), T0 + 86_000, cmd()).await.unwrap(), dup);
    // Abandoned by the startup sweep: still a duplicate.
    let db = e.hub.db().clone();
    assert_eq!(db.write_async(|tx| slack::sweep_abandoned(tx, T0 + 86_001)).await.unwrap(), 1);
    assert_eq!(admit(&e.hub, Key::Signed("1700000003", "d"), T0 + 86_002, cmd()).await.unwrap(), dup);
    assert_eq!(channel(&e.hub, "agent.slack.request.accepted").await.len(), 1, "run once");
    assert_eq!(channel(&e.hub, "agent.slack.request.deduped").await.len(), 3);
}

#[tokio::test]
async fn the_outcome_unknown_path_is_reported_once_and_kept_visible() {
    let e = env();
    let cmd = || delivery(DeliveryKind::Trigger, "U0HUMAN", "1.2.lost");
    admit(&e.hub, Key::Signed("1700000000", "a"), T0, cmd()).await.unwrap();
    let db = e.hub.db().clone();
    assert_eq!(db.write_async(|tx| slack::sweep_abandoned(tx, T0 + 30)).await.unwrap(), 1);
    assert_eq!(db.write_async(|tx| slack::sweep_abandoned(tx, T0 + 60)).await.unwrap(), 0);
    let abandoned = channel(&e.hub, "agent.slack.request.abandoned").await;
    assert_eq!(abandoned.len(), 1);
    assert_eq!(abandoned[0]["age_s"], 30);
    assert_eq!(abandoned[0]["outcome"], "unknown");
    assert_eq!(
        rows(&e.hub).await,
        [("trigger".into(), "1.2.lost".into(), "abandoned".into(), Some("operator".into()))]
    );
    // If the command's outcome arrives after all (a slow handler), it is
    // ledgered and the row is finished, as before.
    db.write_async(|tx| {
        slack::record_executed(
            tx,
            "operator",
            DeliveryKind::Trigger,
            "1.2.lost",
            "task",
            None,
            &Ok(Value::Null),
        )
    })
    .await
    .unwrap();
    assert_eq!(rows(&e.hub).await[0].2, "finished");
    let dup = admit(&e.hub, Key::Signed("1700000001", "b"), T0 + 61, cmd()).await.unwrap();
    assert_eq!(dup, Admission::Deduped { identity: "operator".into() });
}

#[tokio::test]
async fn two_organizations_do_not_collide() {
    let e = env();
    e.hub
        .db()
        .write(|tx| {
            tx.execute(
                "INSERT INTO orgs (id, slug, display_name, allowed_profiles, created_at) \
                 VALUES ('acme', 'acme', 'Acme', '[]', '2026-01-01T00:00:00+00:00')",
                [],
            )?;
            tx.execute(
                "INSERT INTO inbound_deliveries (org_id, source, kind, delivery_key, state, received_at, \
                 updated_at, expires_at) VALUES ('acme', 'slack', 'trigger', '1.2.x', 'finished', ?1, ?1, ?2)",
                [T0, T0 + 86_400],
            )?;
            Ok(())
        })
        .unwrap();
    let cmd = delivery(DeliveryKind::Trigger, "U0HUMAN", "1.2.x");
    assert_eq!(admit(&e.hub, Key::Signed("1700000000", "a"), T0, cmd).await.unwrap(), accepted("operator"));
    // The startup sweep of the default organization leaves the other alone.
    let db = e.hub.db().clone();
    assert_eq!(db.write_async(|tx| slack::sweep_abandoned(tx, T0 + 1)).await.unwrap(), 1);
    let acme: String = e
        .hub
        .db()
        .read(|c| {
            Ok(c.query_row("SELECT state FROM inbound_deliveries WHERE org_id = 'acme'", [], |r| r.get(0))?)
        })
        .unwrap();
    assert_eq!(acme, "finished");
}

#[test]
fn an_upgraded_hub_keeps_every_state_and_still_refuses_what_it_saw() {
    use ua_store::Part;
    let dir = tempfile::tempdir().unwrap();
    let cfg = config(&dir.path().join("home"));
    let new_parts =
        ["ingress.inbound.v1", "organization.v1.ingress", "github.inbound.v1.copy", "slack.inbound.v1.copy"];
    let old: Vec<Part> =
        ua_tools::schema_parts().into_iter().filter(|p| !new_parts.contains(&p.name)).collect();
    assert_eq!(old.len() + new_parts.len(), ua_tools::schema_parts().len());
    let seen_sha = slack::signed_request_sha("1700000000", b"old");
    {
        // A hub from before this change.
        let db = ua_store::Db::open(&cfg.db_path(), &old).unwrap();
        let sha = seen_sha.clone();
        db.write(move |tx| {
            tx.execute(
                "INSERT INTO slack_seen_signatures (request_sha, seen_at) VALUES (?1, ?2)",
                rusqlite::params![sha, T0],
            )?;
            for (kind, id, state, who) in [
                ("trigger", "t-seen", "seen", None),
                ("trigger", "t-acc", "accepted", Some("operator")),
                ("trigger", "t-fin", "finished", Some("operator")),
                ("event", "e-ab", "abandoned", Some("reviewer-1")),
            ] {
                tx.execute(
                    "INSERT INTO slack_seen_deliveries (kind, delivery_id, seen_at, state, identity) \
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    rusqlite::params![kind, id, T0, state, who],
                )?;
            }
            Ok(())
        })
        .unwrap();
    }
    let hub = Hub::open(cfg).unwrap();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        // Every state carried as it was; nothing turned into `finished`.
        assert_eq!(
            rows(&hub).await,
            [
                ("event".into(), "e-ab".into(), "abandoned".into(), Some("reviewer-1".into())),
                ("trigger".into(), "t-acc".into(), "accepted".into(), Some("operator".into())),
                ("trigger".into(), "t-fin".into(), "finished".into(), Some("operator".into())),
                ("trigger".into(), "t-seen".into(), "seen".into(), None),
            ]
        );
        let expiry: Vec<(String, i64)> = hub
            .db()
            .read(|c| {
                let mut stmt = c.prepare(
                    "SELECT kind, expires_at - received_at FROM inbound_deliveries WHERE source = 'slack' \
                     GROUP BY kind ORDER BY kind",
                )?;
                Ok(stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?.collect::<Result<_, _>>()?)
            })
            .unwrap();
        assert_eq!(
            expiry,
            [
                ("event".into(), slack::DELIVERY_RETENTION_S),
                ("request_sha".into(), slack::SEEN_RETENTION_S),
                ("trigger".into(), slack::DELIVERY_RETENTION_S),
            ]
        );
        // What the old hub saw is still refused: the signed bytes, and every
        // delivery id in any state.
        let now = T0 + 10;
        let err = admit(
            &hub,
            Key::Signed("1700000000", "old"),
            now,
            delivery(DeliveryKind::Trigger, "U0HUMAN", "new"),
        )
        .await
        .unwrap_err();
        assert_eq!(err.reason_code(), Some("replayed"));
        for (i, (kind, id)) in [
            (DeliveryKind::Trigger, "t-seen"),
            (DeliveryKind::Trigger, "t-acc"),
            (DeliveryKind::Trigger, "t-fin"),
            (DeliveryKind::Event, "e-ab"),
        ]
        .into_iter()
        .enumerate()
        {
            let bodies = ["b1", "b2", "b3", "b4"];
            let a =
                admit(&hub, Key::Signed("1700000005", bodies[i]), now, delivery(kind, "U0HUMAN", id)).await;
            assert_eq!(a.unwrap(), Admission::Deduped { identity: "operator".into() }, "{id}");
        }
        // The delivery the old hub had in flight is reported at the next
        // startup, as it would have been.
        let db = hub.db().clone();
        assert_eq!(db.write_async(move |tx| slack::sweep_abandoned(tx, now)).await.unwrap(), 1);
        let abandoned = channel(&hub, "agent.slack.request.abandoned").await;
        assert_eq!(abandoned.len(), 1);
        assert_eq!(abandoned[0]["delivery_id"], "t-acc");
        assert_eq!(abandoned[0]["identity"], "operator");
        assert_eq!(abandoned[0]["age_s"], 10);
        // The copy is idempotent.
        let again = slack::INBOUND_COPY;
        hub.db()
            .write(|tx| (again.run)(tx, again.args).map(|_| ()).map_err(|e| UaError::internal(e.to_string())))
            .unwrap();
        let total: i64 = hub
            .db()
            .read(|c| {
                Ok(c.query_row("SELECT COUNT(*) FROM inbound_deliveries WHERE source = 'slack'", [], |r| {
                    r.get(0)
                })?)
            })
            .unwrap();
        // 1 old key + 4 new keys (the replay was refused and rolled back) + 4 deliveries.
        assert_eq!(total, 1 + 4 + 4);
        // The old tables are left as they were.
        let old_rows: i64 = hub
            .db()
            .read(|c| Ok(c.query_row("SELECT COUNT(*) FROM slack_seen_deliveries", [], |r| r.get(0))?))
            .unwrap();
        assert_eq!(old_rows, 4);
    });
}

#[tokio::test]
async fn a_late_outcome_settles_only_the_row_its_admission_created() {
    let e = env();
    let db = e.hub.db().clone();
    let cfg = e.hub.cfg().clone();
    let d = delivery(DeliveryKind::Trigger, "U0HUMAN", "1.2.late");
    let (d1, cfg1) = (d.clone(), cfg.clone());
    let (first, old_claim) = db
        .write_async(move |tx| {
            let k = ReplayKey::Signed { timestamp: "1700000000", body: b"a" };
            slack::admit_claimed(tx, &cfg1, k, T0, &d1)
        })
        .await
        .unwrap();
    assert_eq!(first, accepted("operator"));
    let old_claim = old_claim.expect("an accepted delivery has a claim");
    // The row goes away (as after its retention) and the same id is admitted
    // again: a newer row, under a newer claim.
    db.write_async(|tx| {
        tx.execute("DELETE FROM inbound_deliveries WHERE delivery_key = '1.2.late'", [])?;
        Ok(())
    })
    .await
    .unwrap();
    let (d2, cfg2) = (d.clone(), cfg.clone());
    let (second, new_claim) = db
        .write_async(move |tx| {
            let k = ReplayKey::Signed { timestamp: "1700000001", body: b"b" };
            slack::admit_claimed(tx, &cfg2, k, T0 + 1, &d2)
        })
        .await
        .unwrap();
    assert_eq!(second, accepted("operator"));
    assert_ne!(new_claim.unwrap(), old_claim);
    // The first admission's outcome arrives very late: it is ledgered, and the
    // newer row stays accepted.
    db.write_async(move |tx| {
        slack::record_executed_under(
            tx,
            Some(&old_claim),
            "operator",
            DeliveryKind::Trigger,
            "1.2.late",
            "task",
            None,
            &Ok(Value::Null),
        )
    })
    .await
    .unwrap();
    assert_eq!(
        rows(&e.hub).await,
        [("trigger".into(), "1.2.late".into(), "accepted".into(), Some("operator".into()))]
    );
    assert_eq!(channel(&e.hub, "agent.slack.request.executed").await.len(), 1);
}
