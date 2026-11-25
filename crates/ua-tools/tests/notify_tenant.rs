//! The notification tables are tenant data (`docs/organization.md`, Scoping
//! per subsystem): `notify_outbox` and `pending_notifications`
//! (`organization.v1.tools.notify`, `notify.v2.org_indexes`) and
//! `zulip_sends` (`organization.v1.tools.zulip`). None of them has a key
//! beyond its AUTOINCREMENT id, so no key rebuild exists; the per-organization
//! keys are the queries' (the digest category count, the Zulip duplicate
//! check), and both are scoped here.
//!
//! A second organization is created at the storage level, as no tool creates
//! one yet, and its callers are built by hand. The notify tools take an
//! organization-B caller directly. The Zulip send path refuses one (the hub's
//! Zulip is the default organization's destination), so organization B's
//! Zulip sends are seeded by SQL.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Form, Json, Router};
use secrecy::SecretString;
use serde_json::{Value, json};
use ua_core::{ActorKind, Caller, Config, DEFAULT_ORG, Profile, UaError, identity::Transport};
use ua_tools::{Hub, Registry, builtin_registry};

const ORG_B: &str = "org-b";
const UNKNOWN: &str = "missing-org";
const PARTS: [&str; 3] =
    ["organization.v1.tools.notify", "notify.v2.org_indexes", "organization.v1.tools.zulip"];
const TABLES: [&str; 3] = ["notify_outbox", "pending_notifications", "zulip_sends"];

fn old_parts() -> Vec<ua_store::Part> {
    ua_tools::schema_parts().into_iter().filter(|p| !PARTS.contains(&p.name)).collect()
}

fn add_org(hub: &Hub, id: &str) {
    hub.db()
        .write(|tx| {
            tx.execute(
                "INSERT INTO orgs (id, slug, display_name, allowed_profiles, created_at)
                 VALUES (?1, ?1, 'Org B', '[\"coordinator\",\"operator\"]', '2026-01-01T00:00:00+00:00')",
                [id],
            )?;
            Ok(())
        })
        .unwrap();
}

fn agent(org: &str) -> Caller {
    Caller {
        label: "speaker-1".into(),
        kind: ActorKind::Agent,
        profile: Profile::Coordinator,
        enforce_profile: true,
        session_key: Some("speaker-1-s".into()),
        transport: Transport::Mcp,
        org_id: org.into(),
    }
}

fn human(org: &str) -> Caller {
    Caller {
        label: "operator".into(),
        kind: ActorKind::Human,
        profile: Profile::Operator,
        enforce_profile: false,
        session_key: Some("operator-s".into()),
        transport: Transport::Mcp,
        org_id: org.into(),
    }
}

fn reason(e: &UaError) -> String {
    match e {
        UaError::ApprovalRequired { .. } => "approval_required".into(),
        e => e.reason_code().map(str::to_string).unwrap_or_else(|| e.code().to_string()),
    }
}

// --- a stub webhook and Zulip ------------------------------------------------------------

#[derive(Default)]
struct Seen {
    /// Webhook bodies.
    hooks: Vec<Value>,
    /// Zulip send forms.
    sends: Vec<HashMap<String, String>>,
    /// Status the next Zulip send answers with.
    zulip_status: u16,
    /// Requests for the bot's own user (the first step of every fetch).
    me_calls: usize,
}

type Shared = Arc<Mutex<Seen>>;

async fn on_hook(State(s): State<Shared>, Json(body): Json<Value>) -> StatusCode {
    s.lock().unwrap().hooks.push(body);
    StatusCode::OK
}

async fn on_send(
    State(s): State<Shared>,
    Form(form): Form<HashMap<String, String>>,
) -> (StatusCode, Json<Value>) {
    let mut seen = s.lock().unwrap();
    seen.sends.push(form);
    match seen.zulip_status {
        200 => (StatusCode::OK, Json(json!({ "result": "success", "id": 7 }))),
        code => (StatusCode::from_u16(code).unwrap(), Json(json!({ "result": "error", "msg": "stub" }))),
    }
}

async fn on_me(State(s): State<Shared>) -> Json<Value> {
    s.lock().unwrap().me_calls += 1;
    Json(json!({ "result": "success", "user_id": 99, "email": "bot@example.com" }))
}

async fn on_fetch() -> Json<Value> {
    Json(json!({ "result": "success", "messages": [] }))
}

struct H {
    hub: Hub,
    reg: Registry,
    seen: Shared,
    _dir: tempfile::TempDir,
}

impl H {
    async fn new() -> Self {
        let seen: Shared = Arc::new(Mutex::new(Seen { zulip_status: 200, ..Seen::default() }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let app = Router::new()
            .route("/hook", post(on_hook))
            .route("/api/v1/messages", post(on_send).get(on_fetch))
            .route("/api/v1/users/me", get(on_me))
            .with_state(seen.clone());
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let dir = tempfile::tempdir().unwrap();
        let mut cfg = Config::for_home(dir.path().join("home"));
        cfg.human_identities = vec!["operator".into()];
        cfg.notify_webhook_url = Some(format!("{base}/hook"));
        cfg.notify_max_attempts = 1;
        cfg.fetch_allow_loopback = true;
        cfg.zulip_site = Some(base);
        cfg.zulip_email = Some("bot@example.com".into());
        cfg.zulip_api_key = Some(SecretString::from("zulip-test-key"));
        cfg.zulip_retired = Some("0".into());
        cfg.zulip_channels = [("requests".to_string(), "Requests".to_string())].into_iter().collect();
        cfg.zulip_send_calls_per_hour = 1000;
        let hub = Hub::in_memory(cfg).unwrap();
        add_org(&hub, ORG_B);
        Self { hub, reg: builtin_registry(), seen, _dir: dir }
    }

    async fn call(&self, who: &Caller, tool: &str, args: Value) -> Result<Value, UaError> {
        self.reg.call(&self.hub, who, tool, args).await
    }

    async fn ok(&self, who: &Caller, tool: &str, args: Value) -> Value {
        match self.call(who, tool, args.clone()).await {
            Ok(v) => v,
            Err(e) => panic!("{}: {tool}({args}) failed: {e:?}", who.org_id),
        }
    }

    fn hook_texts(&self) -> Vec<String> {
        self.seen
            .lock()
            .unwrap()
            .hooks
            .iter()
            .map(|b| b["text"].as_str().unwrap_or_default().to_string())
            .collect()
    }

    fn zulip_sends(&self) -> usize {
        self.seen.lock().unwrap().sends.len()
    }

    fn count(&self, sql: &str) -> i64 {
        let sql = sql.to_string();
        self.hub.db().read(move |c| Ok(c.query_row(&sql, [], |r| r.get(0))?)).unwrap()
    }

    /// `(org_id, kind, category, status, message)` of every outbox row.
    #[allow(clippy::type_complexity)]
    fn outbox(&self) -> Vec<(String, String, Option<String>, String, Option<String>)> {
        self.hub
            .db()
            .read(|c| {
                Ok(c.prepare(
                    "SELECT org_id, kind, category, status, message FROM notify_outbox ORDER BY id",
                )?
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)))?
                .collect::<Result<_, _>>()?)
            })
            .unwrap()
    }

    /// `(org_id, category, message)` of every queued digest entry.
    fn pending(&self) -> Vec<(String, String, String)> {
        self.hub
            .db()
            .read(|c| {
                Ok(c.prepare("SELECT org_id, category, message FROM pending_notifications ORDER BY id")?
                    .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
                    .collect::<Result<_, _>>()?)
            })
            .unwrap()
    }

    /// `(org_id, status)` of a Zulip send.
    fn zulip_row(&self, id: i64) -> (String, String) {
        self.hub
            .db()
            .read(move |c| {
                Ok(c.query_row("SELECT org_id, status FROM zulip_sends WHERE id = ?1", [id], |r| {
                    Ok((r.get(0)?, r.get(1)?))
                })?)
            })
            .unwrap()
    }

    /// A Zulip send of organization `org`, written directly: the send tool
    /// refuses every organization but the default.
    fn seed_zulip(&self, org: &str, content: &str, status: &str) -> i64 {
        let (org, sha, status) = (org.to_string(), sha256(content), status.to_string());
        self.hub
            .db()
            .write(move |tx| {
                tx.execute(
                    "INSERT INTO zulip_sends (org_id, agent_label, channel, stream, topic, content_sha256, chars,
                     bytes, status, created_at, updated_at)
                     VALUES (?1, 'speaker-1', 'requests', 'Requests', 't', ?2, 1, 1, ?3,
                     '2026-01-02T00:00:00+00:00', '2026-01-02T00:00:00+00:00')",
                    [&org, &sha, &status],
                )?;
                Ok(tx.last_insert_rowid())
            })
            .unwrap()
    }

    async fn zulip_send(&self, who: &Caller, content: &str) -> Result<Value, UaError> {
        let args =
            json!({ "agent_label": "speaker-1", "channel": "requests", "topic": "t", "content": content });
        self.call(who, "zulip_send_message", args).await
    }

    /// Park the approval, approve it as the default organization's human, send again.
    async fn approved_zulip_send(&self, content: &str) -> Result<Value, UaError> {
        let id = match self.zulip_send(&agent(DEFAULT_ORG), content).await {
            Err(UaError::ApprovalRequired { approval_id, .. }) => approval_id,
            other => panic!("expected an approval request, got {other:?}"),
        };
        self.ok(&human(DEFAULT_ORG), "approval_resolve", json!({ "id": id, "decision": "approve" })).await;
        self.zulip_send(&agent(DEFAULT_ORG), content).await
    }
}

fn sha256(text: &str) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(text.as_bytes()))
}

fn names(c: &rusqlite::Connection, kind: &str, table: &str) -> Vec<String> {
    c.prepare(
        "SELECT name FROM sqlite_master WHERE type = ?1 AND tbl_name = ?2 AND sql IS NOT NULL ORDER BY name",
    )
    .unwrap()
    .query_map([kind, table], |r| r.get(0))
    .unwrap()
    .collect::<Result<_, _>>()
    .unwrap()
}

// --- schema ------------------------------------------------------------------------------------

#[test]
fn a_legacy_database_upgrades_into_the_default_organization() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = Config::for_home(dir.path());
    {
        let db = ua_store::Db::open(&cfg.db_path(), &old_parts()).unwrap();
        db.write(|tx| {
            tx.execute_batch(
                "INSERT INTO notify_outbox (kind, category, agent, message, chars, status, created_at, updated_at)
                 VALUES ('notify', NULL, 'a', 'old', 3, 'not_configured', '2026-01-02T00:00:00+00:00',
                         '2026-01-02T00:00:00+00:00'),
                        ('digest', 'drift', 'system', NULL, 9, 'delivered', '2026-01-02T00:00:00+00:00',
                         '2026-01-02T00:00:00+00:00');
                 DELETE FROM notify_outbox WHERE kind = 'digest';
                 INSERT INTO pending_notifications (category, message, agent, created_at)
                 VALUES ('drift', 'queued', 'a', '2026-01-02T00:00:00+00:00');
                 INSERT INTO zulip_sends (agent_label, channel, stream, topic, content_sha256, chars, bytes,
                                          status, created_at, updated_at)
                 VALUES ('a', 'requests', 'Requests', 't', 'abc', 1, 1, 'uncertain',
                         '2026-01-02T00:00:00+00:00', '2026-01-02T00:00:00+00:00');",
            )?;
            Ok(())
        })
        .unwrap();
    }

    // Open twice: the upgrade is idempotent across restarts.
    for _ in 0..2 {
        let hub = Hub::open(cfg.clone()).unwrap();
        hub.db()
            .read(|c| {
                for t in TABLES {
                    let orgs: Vec<String> = c
                        .prepare(&format!("SELECT org_id FROM {t} ORDER BY id"))?
                        .query_map([], |r| r.get(0))?
                        .collect::<Result<_, _>>()?;
                    assert_eq!(orgs, vec![DEFAULT_ORG.to_string()], "{t}");
                    let notnull: i64 = c.query_row(
                        "SELECT \"notnull\" FROM pragma_table_info(?1) WHERE name = 'org_id'",
                        [t],
                        |r| r.get(0),
                    )?;
                    assert_eq!(notnull, 1, "{t}");
                    let triggers = names(c, "trigger", t);
                    assert_eq!(triggers, [format!("{t}_org_exists"), format!("{t}_org_immutable")], "{t}");
                }
                // The legacy indexes stay and the organization-led ones exist.
                assert_eq!(
                    names(c, "index", "notify_outbox"),
                    ["idx_notify_outbox_org", "idx_notify_outbox_status"]
                );
                assert_eq!(
                    names(c, "index", "pending_notifications"),
                    ["idx_pending_notifications_cat", "idx_pending_notifications_org_cat"]
                );
                assert_eq!(names(c, "index", "zulip_sends"), ["idx_zulip_sends_content"]);
                let fk: i64 = c.query_row("PRAGMA foreign_keys", [], |r| r.get(0))?;
                assert_eq!(fk, 1, "foreign keys stay on");
                Ok(())
            })
            .unwrap();
    }

    let hub = Hub::open(cfg).unwrap();
    add_org(&hub, ORG_B);
    hub.db()
        .write(|tx| {
            // The AUTOINCREMENT high-water mark survives: the deleted id 2 is never reused.
            tx.execute(
                "INSERT INTO notify_outbox (org_id, kind, chars, status, created_at, updated_at)
                 VALUES ('org-b', 'notify', 1, 'not_configured', 'x', 'x')",
                [],
            )?;
            assert_eq!(tx.last_insert_rowid(), 3);
            for t in TABLES {
                // An unknown organization is refused, and a row never moves.
                let err = tx
                    .execute(&format!("INSERT INTO {t} (org_id) SELECT 'nowhere' FROM {t} LIMIT 1"), [])
                    .unwrap_err()
                    .to_string();
                assert!(err.contains("unknown organization"), "{t}: {err}");
                let err =
                    tx.execute(&format!("UPDATE {t} SET org_id = 'org-b'"), []).unwrap_err().to_string();
                assert!(err.contains("org_id cannot change"), "{t}: {err}");
            }
            Ok(())
        })
        .unwrap();
}

// --- notify ------------------------------------------------------------------------------------

/// The hub's webhook is the default organization's destination: organization
/// B's notification stays in its own outbox, never reaches the webhook, and
/// neither organization's status shows the other's rows.
#[tokio::test]
async fn notifications_are_isolated_in_both_directions() {
    let h = H::new().await;
    let a = h.ok(&agent(DEFAULT_ORG), "notify", json!({ "message": "alpha news" })).await;
    assert_eq!((a["delivered"].as_bool(), a["status"].as_str()), (Some(true), Some("delivered")), "{a}");
    let b = h.ok(&agent(ORG_B), "notify", json!({ "message": "beta secret" })).await;
    assert_eq!(b["status"], "not_configured", "{b}");
    assert_eq!(b["error"], "no notification webhook is configured for this organization");
    assert_eq!(h.hook_texts(), ["alpha news"], "organization B's text never reaches the hub's webhook");

    let (a_id, b_id) = (a["outbox_id"].as_i64().unwrap(), b["outbox_id"].as_i64().unwrap());
    let rows = h.outbox();
    assert_eq!(rows[0].0, DEFAULT_ORG);
    // Organization B has no destination to resend to, so its text is not kept.
    assert_eq!((rows[1].0.as_str(), rows[1].3.as_str(), rows[1].4.as_deref()), (ORG_B, "not_configured", None));
    assert_eq!(h.count(&format!("SELECT chars FROM notify_outbox WHERE id = {b_id}")), 11);

    let ids = |v: &Value| -> Vec<i64> {
        v["deliveries"].as_array().unwrap().iter().map(|d| d["id"].as_i64().unwrap()).collect()
    };
    let sa = h.ok(&agent(DEFAULT_ORG), "notify_delivery_status", json!({})).await;
    assert_eq!((ids(&sa), sa["configured"].as_bool()), (vec![a_id], Some(true)), "{sa}");
    let sb = h.ok(&agent(ORG_B), "notify_delivery_status", json!({})).await;
    assert_eq!((ids(&sb), sb["configured"].as_bool()), (vec![b_id], Some(false)), "{sb}");
    assert_eq!(sb["last_delivery"]["status"], "not_configured");
}

/// One digest category in two organizations: the batch threshold counts each
/// organization's own queue, a flush takes only the caller's organization's
/// entries, and both organizations' digests are produced; only the default
/// organization's goes to the hub's webhook.
#[tokio::test]
async fn an_identical_digest_category_in_two_organizations_flushes_separately() {
    let h = H::new().await;
    let batch = |msgs: &[&str]| json!({ "messages": msgs, "category": "drift", "max_batch_size": 3 });
    for (org, msgs) in [(DEFAULT_ORG, ["a1", "a2"]), (ORG_B, ["b1", "b2"])] {
        let v = h.ok(&agent(org), "batch_notify", batch(&msgs)).await;
        // Four queued in the category hub-wide, but two per organization: no flush.
        assert_eq!(
            (v["flushed"].as_bool(), v["total_pending"].as_i64()),
            (Some(false), Some(2)),
            "{org}: {v}"
        );
    }
    let pending_of = |v: &Value| v["pending_digest"].clone();
    for org in [DEFAULT_ORG, ORG_B] {
        let s = h.ok(&agent(org), "notify_delivery_status", json!({})).await;
        assert_eq!(pending_of(&s), json!({ "drift": 2 }), "{org}: {s}");
    }

    let fb = h.ok(&agent(ORG_B), "flush_digest", json!({ "category": "drift" })).await;
    assert_eq!(
        (fb["flushed_count"].as_i64(), fb["status"].as_str()),
        (Some(2), Some("not_configured")),
        "{fb}"
    );
    let left: Vec<String> = h.pending().into_iter().map(|(o, _, m)| format!("{o}:{m}")).collect();
    assert_eq!(left, ["default:a1", "default:a2"], "organization A's queue is untouched");

    let fa = h.ok(&agent(DEFAULT_ORG), "flush_digest", json!({})).await;
    assert_eq!((fa["flushed_count"].as_i64(), fa["delivered"].as_bool()), (Some(2), Some(true)), "{fa}");
    assert!(h.pending().is_empty());

    let digests: Vec<(String, Option<String>)> =
        h.outbox().into_iter().filter(|r| r.1 == "digest").map(|r| (r.0, r.4)).collect();
    assert_eq!(digests.len(), 2, "{digests:?}");
    // B's digest is recorded without its text (B has no destination).
    assert_eq!(digests.iter().find(|d| d.0 == ORG_B).map(|d| d.1.clone()), Some(None), "{digests:?}");
    let a_text = digests.iter().find(|d| d.0 == DEFAULT_ORG).map(|d| d.1.clone());
    assert_eq!(a_text, Some(None), "a delivered digest's text is cleared: {digests:?}");
    let hooks = h.hook_texts();
    assert_eq!(hooks.len(), 1, "{hooks:?}");
    assert!(hooks[0].contains("a1") && hooks[0].contains("a2"), "{hooks:?}");
    assert!(!hooks[0].contains("b1") && !hooks[0].contains("b2"), "{hooks:?}");
}

/// Organization B's write path: its batch and digest are recorded in its own
/// organization, its flush with nothing queued answers as empty even while
/// the default organization has entries.
#[tokio::test]
async fn organization_b_writes_land_in_organization_b() {
    let h = H::new().await;
    h.ok(&agent(DEFAULT_ORG), "batch_notify", json!({ "messages": ["only default"] })).await;
    let empty = h.ok(&agent(ORG_B), "flush_digest", json!({})).await;
    assert_eq!(empty["flushed_count"], 0, "{empty}");
    h.ok(&agent(ORG_B), "batch_notify", json!({ "messages": ["mine"], "flush_now": true })).await;
    let orgs: Vec<(String, String)> = h.outbox().into_iter().map(|r| (r.0, r.1)).collect();
    assert_eq!(orgs, [(ORG_B.to_string(), "digest".to_string())]);
    let pending: Vec<String> = h.pending().into_iter().map(|(o, _, m)| format!("{o}:{m}")).collect();
    assert_eq!(pending, ["default:only default"]);
}

#[tokio::test]
async fn an_unknown_organization_is_refused_before_any_write() {
    let h = H::new().await;
    h.ok(&agent(DEFAULT_ORG), "batch_notify", json!({ "messages": ["queued"] })).await;
    let before = h.count("SELECT COUNT(*) FROM event_log");
    let who = agent(UNKNOWN);
    for (tool, args) in [
        ("notify", json!({ "message": "x" })),
        ("batch_notify", json!({ "messages": ["x"] })),
        // A write with nothing of its own to delete is still refused.
        ("flush_digest", json!({})),
    ] {
        let e = h.call(&who, tool, args).await.unwrap_err();
        assert!(e.to_string().contains("unknown organization"), "{tool}: {e}");
    }
    assert!(h.outbox().is_empty());
    assert_eq!(h.pending().len(), 1);
    assert_eq!(h.count("SELECT COUNT(*) FROM event_log"), before);
    assert!(h.hook_texts().is_empty());
}

/// Review follow-up: notification events of another organization reach the
/// default ledger with no category (a caller-chosen name) and the neutral
/// originator; the default organization's keep both. No event carries text.
#[tokio::test]
async fn notification_events_of_another_organization_carry_no_names() {
    let h = H::new().await;
    let before = h.count("SELECT COALESCE(MAX(seq), 0) FROM event_log");
    let b_category = "falcon-board-alerts";
    let b_agent = Caller { label: "kestrel-notifier".into(), ..agent(ORG_B) };
    h.ok(&b_agent, "notify", json!({ "message": "beta secret one" })).await;
    h.ok(&b_agent, "batch_notify", json!({ "messages": ["beta secret two"], "category": b_category, "flush_now": true }))
        .await;
    h.ok(&agent(DEFAULT_ORG), "batch_notify", json!({ "messages": ["alpha two"], "category": "drift", "flush_now": true }))
        .await;
    let events: Vec<(String, String, String)> = h
        .hub
        .db()
        .read(move |c| {
            let mut stmt = c.prepare(
                "SELECT channel, COALESCE(originator, ''), payload FROM event_log \
                 WHERE seq > ?1 AND channel LIKE 'agent.notify.%' ORDER BY seq",
            )?;
            let rows = stmt.query_map([before], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
            Ok(rows.collect::<Result<Vec<_>, _>>()?)
        })
        .unwrap();
    let channels: Vec<&str> = events.iter().map(|e| e.0.as_str()).collect();
    assert_eq!(
        channels,
        [
            "agent.notify.queued",
            "agent.notify.batched",
            "agent.notify.queued",
            "agent.notify.batched",
            "agent.notify.queued",
            "agent.notify.delivered",
        ],
        "{events:?}"
    );
    for (i, (channel, originator, payload)) in events.iter().enumerate() {
        for secret in ["beta secret", "alpha two", b_category, "kestrel-notifier"] {
            assert!(!payload.contains(secret), "{channel} carries {secret}: {payload}");
        }
        let p: Value = serde_json::from_str(payload).unwrap();
        if i < 3 {
            assert_eq!(originator, "system", "{channel}: {payload}");
            assert!(p.get("category").is_none_or(Value::is_null), "{channel}: {payload}");
        } else {
            assert_eq!(originator, if channel == "agent.notify.batched" { "speaker-1" } else { "system" });
        }
    }
    let batched: Value = serde_json::from_str(&events[3].2).unwrap();
    assert_eq!(batched["category"], "drift", "the default organization keeps its category");
}

// --- zulip -------------------------------------------------------------------------------------

/// Organization B cannot post through the default organization's Zulip:
/// refused before any check, approval, row or event is recorded. An unknown
/// organization is refused the same way.
#[tokio::test]
async fn zulip_sends_of_another_organization_are_refused_before_anything_is_recorded() {
    let h = H::new().await;
    let before = h.count("SELECT COUNT(*) FROM event_log");
    let e = h.zulip_send(&agent(ORG_B), "from b").await.unwrap_err();
    assert_eq!(reason(&e), "zulip_not_configured", "{e}");
    let e = h.zulip_send(&agent(UNKNOWN), "from nowhere").await.unwrap_err();
    assert!(e.to_string().contains("unknown organization"), "{e}");
    assert_eq!(h.zulip_sends(), 0);
    assert_eq!(h.count("SELECT COUNT(*) FROM zulip_sends"), 0);
    assert_eq!(h.count("SELECT COUNT(*) FROM approvals"), 0);
    assert_eq!(h.count("SELECT COUNT(*) FROM event_log"), before);
}

/// Review follow-up: organization B cannot read the default organization's
/// Zulip either. A fetch is refused before any request, cursor or event; an
/// unknown organization is refused the same way. The default organization
/// still fetches and keeps its cursor.
#[tokio::test]
async fn zulip_fetches_of_another_organization_are_refused_before_anything_is_recorded() {
    let h = H::new().await;
    let before = h.count("SELECT COUNT(*) FROM event_log");
    let args = json!({ "agent_label": "speaker-1", "channel": "requests", "anchor": "newest" });
    let e = h.call(&agent(ORG_B), "zulip_fetch_messages", args.clone()).await.unwrap_err();
    assert_eq!(reason(&e), "zulip_not_configured", "{e}");
    let e = h.call(&agent(UNKNOWN), "zulip_fetch_messages", args.clone()).await.unwrap_err();
    assert!(e.to_string().contains("unknown organization"), "{e}");
    assert_eq!(h.seen.lock().unwrap().me_calls, 0, "no request reached the Zulip site");
    assert_eq!(h.count("SELECT COUNT(*) FROM zulip_fetch_cursors"), 0);
    assert_eq!(h.count("SELECT COUNT(*) FROM event_log"), before);

    let ok = h.ok(&agent(DEFAULT_ORG), "zulip_fetch_messages", args).await;
    assert_eq!(ok["received"], true, "{ok}");
    assert_eq!(h.seen.lock().unwrap().me_calls, 1);
    assert_eq!(h.count("SELECT COUNT(*) FROM event_log WHERE channel = 'agent.zulip.fetched'"), 1);
}

/// The duplicate check is per organization: organization B's open send of
/// the same text to the same topic does not block the default organization's,
/// which is delivered; the default organization's own open send still does.
#[tokio::test]
async fn an_identical_zulip_send_key_in_two_organizations_both_proceed() {
    let h = H::new().await;
    let b_send = h.seed_zulip(ORG_B, "same text", "uncertain");
    let sent = h.approved_zulip_send("same text").await.unwrap();
    assert_eq!(sent["sent"], true, "{sent}");
    assert_eq!(h.zulip_sends(), 1);
    let a_send = sent["send_id"].as_i64().unwrap();
    assert_eq!(h.zulip_row(a_send), (DEFAULT_ORG.into(), "sent".into()));
    assert_eq!(h.zulip_row(b_send), (ORG_B.into(), "uncertain".into()), "organization B's row is untouched");

    // The default organization's own uncertain send still blocks its resend.
    h.seen.lock().unwrap().zulip_status = 503;
    assert_eq!(reason(&h.approved_zulip_send("again").await.unwrap_err()), "zulip_uncertain");
    h.seen.lock().unwrap().zulip_status = 200;
    let dup = h.zulip_send(&agent(DEFAULT_ORG), "again").await.unwrap_err();
    assert_eq!(reason(&dup), "zulip_duplicate", "{dup}");
}

/// `zulip_resolve_send` answers another organization's send exactly as a
/// missing one, in both directions, and changes nothing.
#[tokio::test]
async fn zulip_resolve_send_is_isolated_in_both_directions() {
    let h = H::new().await;
    let a_send = h.seed_zulip(DEFAULT_ORG, "a", "uncertain");
    let b_send = h.seed_zulip(ORG_B, "b", "uncertain");
    let resolve = |id: i64| json!({ "send_id": id, "outcome": "not_delivered" });
    let missing = h.call(&human(DEFAULT_ORG), "zulip_resolve_send", resolve(9999)).await.unwrap_err();
    for (who, other) in [(human(DEFAULT_ORG), b_send), (human(ORG_B), a_send)] {
        let e = h.call(&who, "zulip_resolve_send", resolve(other)).await.unwrap_err();
        assert_eq!(e.code(), missing.code(), "{}: {e}", who.org_id);
        assert_eq!(e.to_string().replace(&other.to_string(), "N"), missing.to_string().replace("9999", "N"));
    }
    assert_eq!(h.zulip_row(a_send).1, "uncertain");
    assert_eq!(h.zulip_row(b_send).1, "uncertain");

    // Each organization resolves its own.
    for (who, own) in [(human(DEFAULT_ORG), a_send), (human(ORG_B), b_send)] {
        let v = h.ok(&who, "zulip_resolve_send", resolve(own)).await;
        assert_eq!(v["status"], "failed", "{v}");
    }
    let e = h.call(&human(UNKNOWN), "zulip_resolve_send", resolve(a_send)).await.unwrap_err();
    assert!(e.to_string().contains("unknown organization"), "{e}");
}
