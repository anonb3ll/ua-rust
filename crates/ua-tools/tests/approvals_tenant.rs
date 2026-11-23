//! The approval queue is tenant data (`docs/organization.md`, Scoping per
//! subsystem): `approvals` (`organization.v1.tools.approvals`,
//! `approvals.v3.org_indexes`). An approval belongs to its requester's
//! organization. No key needed a rebuild: the table's only key is an
//! AUTOINCREMENT id, and the gate's match on `(tool, payload,
//! requested_by)` is a query key that now filters on `org_id`, so there is
//! no rebuild to crash or roll back here.
//!
//! A second organization is created at the storage level, as no tool creates
//! one yet, and its callers are built by hand. Organization-B approvals are
//! parked through the gate with an organization-B caller. An organization-B
//! *pass* (an approved row) cannot be made through the tools while
//! `ua_org::authz` admits only the default organization's humans, so the
//! tests that need one seed it by SQL and say so.

use serde_json::{Value, json};
use ua_core::{ActorKind, Caller, Config, DEFAULT_ORG, Profile, UaError, identity::Transport};
use ua_tools::approvals::{self, GateOutcome, RequestState};
use ua_tools::{Hub, Registry, builtin_registry};

const ORG_B: &str = "org-b";
const UNKNOWN: &str = "missing-org";
const PARTS: [&str; 2] = ["organization.v1.tools.approvals", "approvals.v3.org_indexes"];
/// Both organizations' agents use this label (labels are one hub namespace
/// in production; the tests use one to show the label alone never matches).
const AGENT: &str = "builder-1";
/// A distinctive organization-B requester that must never reach the
/// default organization's ledger payloads.
const B_AGENT: &str = "kestrel-nightshift-7781";
const TOOL: &str = "task_add";

fn old_parts() -> Vec<ua_store::Part> {
    ua_tools::schema_parts().into_iter().filter(|p| !PARTS.contains(&p.name)).collect()
}

fn cfg(home: &std::path::Path) -> Config {
    let mut cfg = Config::for_home(home);
    cfg.human_identities = vec!["operator".into()];
    cfg.approval_tools = vec![TOOL.into()];
    cfg
}

fn add_org(hub: &Hub, id: &str) {
    hub.db()
        .write(|tx| {
            tx.execute(
                "INSERT INTO orgs (id, slug, display_name, allowed_profiles, created_at)
                 VALUES (?1, ?1, 'Org B', '[\"coordinator\"]', '2026-01-01T00:00:00+00:00')",
                [id],
            )?;
            Ok(())
        })
        .unwrap();
}

fn caller(label: &str, kind: ActorKind, org: &str) -> Caller {
    Caller {
        label: label.into(),
        kind,
        // A profile that sees the approval tools; it grants no authority.
        profile: Profile::Coordinator,
        enforce_profile: true,
        session_key: None,
        transport: Transport::Mcp,
        org_id: org.into(),
    }
}

fn agent(org: &str) -> Caller {
    caller(AGENT, ActorKind::Agent, org)
}

fn human(org: &str) -> Caller {
    caller("operator", ActorKind::Human, org)
}

fn reason(e: &UaError) -> String {
    e.reason_code().map(str::to_string).unwrap_or_else(|| e.code().to_string())
}

fn names(c: &rusqlite::Connection, kind: &str) -> Vec<String> {
    c.prepare(
        "SELECT name FROM sqlite_master WHERE type = ?1 AND tbl_name = 'approvals' AND sql IS NOT NULL ORDER BY name",
    )
    .unwrap()
    .query_map([kind], |r| r.get(0))
    .unwrap()
    .collect::<Result<_, _>>()
    .unwrap()
}

struct H {
    hub: Hub,
    reg: Registry,
    _dir: tempfile::TempDir,
}

impl H {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let hub = Hub::in_memory(cfg(dir.path())).unwrap();
        add_org(&hub, ORG_B);
        Self { hub, reg: builtin_registry(), _dir: dir }
    }

    async fn call(&self, who: &Caller, tool: &str, args: Value) -> Result<Value, UaError> {
        self.reg.call(&self.hub, who, tool, args).await
    }

    /// Run the gate for `who`'s `task_add {title}` in a write of its own.
    fn gate(&self, who: &Caller, title: &str) -> Result<GateOutcome, UaError> {
        let who = who.clone();
        let args = json!({ "title": title });
        self.hub.db().write(move |tx| approvals::gate(tx, self.hub.cfg(), &who, TOOL, &args))
    }

    fn pending(&self, who: &Caller, title: &str) -> i64 {
        match self.gate(who, title).unwrap() {
            GateOutcome::Pending { approval_id } => approval_id,
            other => panic!("expected a pending request, got {other:?}"),
        }
    }

    /// Seed an approved, unconsumed pass of `org` resolved at `resolved_at`
    /// (no tool can approve outside the default organization yet).
    fn seed_pass(&self, org: &str, requester: &str, title: &str, resolved_at: &str) -> i64 {
        let payload = approvals::canonical_payload(&json!({ "title": title }));
        let (org, requester, resolved_at) = (org.to_string(), requester.to_string(), resolved_at.to_string());
        self.hub
            .db()
            .write(move |tx| {
                tx.execute(
                    "INSERT INTO approvals (org_id, tool, payload, requested_by, status, resolved_by, created_at, \
                     updated_at, resolved_at) VALUES (?1, ?2, ?3, ?4, 'approved', 'operator', ?5, ?5, ?5)",
                    rusqlite::params![org, TOOL, payload, requester, resolved_at],
                )?;
                Ok(tx.last_insert_rowid())
            })
            .unwrap()
    }

    fn count(&self, sql: &str) -> i64 {
        let sql = sql.to_string();
        self.hub.db().read(move |c| Ok(c.query_row(&sql, [], |r| r.get(0))?)).unwrap()
    }

    fn status(&self, id: i64) -> String {
        self.hub
            .db()
            .read(move |c| Ok(c.query_row("SELECT status FROM approvals WHERE id = ?1", [id], |r| r.get(0))?))
            .unwrap()
    }

    fn org_of(&self, id: i64) -> String {
        self.hub
            .db()
            .read(move |c| Ok(c.query_row("SELECT org_id FROM approvals WHERE id = ?1", [id], |r| r.get(0))?))
            .unwrap()
    }

    /// Every approvals row, as text: a refused call leaves it identical.
    fn snapshot(&self) -> String {
        self.hub
            .db()
            .read(|c| {
                let mut stmt = c.prepare("SELECT * FROM approvals ORDER BY id")?;
                let n = stmt.column_count();
                let rows = stmt.query_map([], |r| {
                    let mut row = Vec::new();
                    for i in 0..n {
                        row.push(format!("{:?}", r.get_ref(i)?));
                    }
                    Ok(row.join("|"))
                })?;
                Ok(rows.collect::<Result<Vec<_>, _>>()?.join("\n"))
            })
            .unwrap()
    }

    fn events(&self) -> i64 {
        self.count("SELECT COUNT(*) FROM event_log")
    }

    /// Every ledger payload on `channel`, oldest first.
    fn payloads(&self, channel: &str) -> Vec<Value> {
        let channel = channel.to_string();
        self.hub
            .db()
            .read(move |c| {
                let rows: Vec<String> = c
                    .prepare("SELECT payload FROM event_log WHERE channel = ?1 ORDER BY seq")?
                    .query_map([&channel], |r| r.get(0))?
                    .collect::<Result<_, _>>()?;
                Ok(rows.iter().map(|p| serde_json::from_str(p).unwrap()).collect())
            })
            .unwrap()
    }

    /// The ids in each bucket of `approval_pending` as `who` reads it.
    async fn queue(&self, who: &Caller) -> (Vec<i64>, Vec<i64>, Vec<i64>) {
        let v = self.call(who, "approval_pending", json!({ "newest_expired": true })).await.unwrap();
        let ids = |k: &str| -> Vec<i64> {
            v[k].as_array().unwrap().iter().map(|r| r["id"].as_i64().unwrap()).collect()
        };
        (ids("pending"), ids("approved_unconsumed"), ids("expired_passes"))
    }
}

const LONG_AGO: &str = "2020-01-01T00:00:00+00:00";

fn now() -> String {
    ua_core::time::now()
}

// --- schema ------------------------------------------------------------------------------------

#[tokio::test]
async fn a_legacy_database_upgrades_into_the_default_organization() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = cfg(dir.path());
    let fresh = now();
    {
        let db = ua_store::Db::open(&cfg.db_path(), &old_parts()).unwrap();
        let payload = approvals::canonical_payload(&json!({ "title": "legacy pass" }));
        let pending = approvals::canonical_payload(&json!({ "title": "legacy pending" }));
        db.write(move |tx| {
            tx.execute(
                "INSERT INTO approvals (tool, payload, requested_by, status, resolved_by, created_at, updated_at, \
                 resolved_at) VALUES ('task_add', ?1, 'builder-1', 'approved', 'operator', ?2, ?2, ?2)",
                rusqlite::params![payload, fresh],
            )?;
            tx.execute(
                "INSERT INTO approvals (tool, payload, requested_by, status, created_at, updated_at) \
                 VALUES ('task_add', ?1, 'builder-1', 'pending', ?2, ?2)",
                rusqlite::params![pending, fresh],
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
                let orgs: Vec<String> = c
                    .prepare("SELECT DISTINCT org_id FROM approvals")?
                    .query_map([], |r| r.get(0))?
                    .collect::<Result<_, _>>()?;
                assert_eq!(orgs, [DEFAULT_ORG]);
                let notnull: i64 = c.query_row(
                    "SELECT \"notnull\" FROM pragma_table_info('approvals') WHERE name = 'org_id'",
                    [],
                    |r| r.get(0),
                )?;
                assert_eq!(notnull, 1);
                assert_eq!(names(c, "trigger"), ["approvals_org_exists", "approvals_org_immutable"]);
                assert_eq!(
                    names(c, "index"),
                    ["idx_approvals_lookup", "idx_approvals_org_lookup", "idx_approvals_org_status"]
                );
                let parts: i64 = c.query_row(
                    "SELECT COUNT(*) FROM schema_parts WHERE name IN (?1, ?2)",
                    [PARTS[0], PARTS[1]],
                    |r| r.get(0),
                )?;
                assert_eq!(parts, 2);
                Ok(())
            })
            .unwrap();
    }

    // The legacy rows keep working for the default organization, and only
    // for it.
    let hub = Hub::open(cfg).unwrap();
    add_org(&hub, ORG_B);
    let h = H { hub, reg: builtin_registry(), _dir: dir };
    let (pending, live, _) = h.queue(&human(DEFAULT_ORG)).await;
    assert_eq!((pending, live), (vec![2], vec![1]));
    assert_eq!(h.queue(&human(ORG_B)).await, (vec![], vec![], vec![]));
    // Organization B's identical call does not spend the legacy pass.
    assert!(matches!(h.gate(&agent(ORG_B), "legacy pass").unwrap(), GateOutcome::Pending { .. }));
    assert_eq!(h.status(1), "approved");
    assert_eq!(h.gate(&agent(DEFAULT_ORG), "legacy pass").unwrap(), GateOutcome::Pass { approval_id: 1 });
    // The legacy pending request is reused by the default organization only.
    assert_eq!(
        h.gate(&agent(DEFAULT_ORG), "legacy pending").unwrap(),
        GateOutcome::Pending { approval_id: 2 }
    );
    let b = h.pending(&agent(ORG_B), "legacy pending");
    assert_ne!(b, 2);
    assert_eq!(h.org_of(b), ORG_B);
    // `org_id` cannot be moved.
    let e = h
        .hub
        .db()
        .write(|tx| Ok(tx.execute("UPDATE approvals SET org_id = 'org-b' WHERE id = 2", [])?))
        .unwrap_err();
    assert!(e.to_string().contains("org_id cannot change"), "{e}");
}

// --- isolation ---------------------------------------------------------------------------------

#[tokio::test]
async fn pending_queues_are_isolated_in_both_directions() {
    let h = H::new();
    let a = h.pending(&agent(DEFAULT_ORG), "alpha");
    let b = h.pending(&agent(ORG_B), "beta");
    let a_pass = h.seed_pass(DEFAULT_ORG, AGENT, "alpha pass", &now());
    let b_pass = h.seed_pass(ORG_B, AGENT, "beta pass", &now());
    let a_old = h.seed_pass(DEFAULT_ORG, AGENT, "alpha old", LONG_AGO);
    let b_old = h.seed_pass(ORG_B, AGENT, "beta old", LONG_AGO);

    assert_eq!(h.queue(&human(DEFAULT_ORG)).await, (vec![a], vec![a_pass], vec![a_old]));
    assert_eq!(h.queue(&agent(DEFAULT_ORG)).await, (vec![a], vec![a_pass], vec![a_old]));
    assert_eq!(h.queue(&human(ORG_B)).await, (vec![b], vec![b_pass], vec![b_old]));
    assert_eq!(h.queue(&agent(ORG_B)).await, (vec![b], vec![b_pass], vec![b_old]));
    let total =
        h.call(&human(DEFAULT_ORG), "approval_pending", json!({ "newest_expired": true })).await.unwrap();
    assert_eq!(total["expired_passes_total"], 1, "{total}");

    // The tool filter keeps the organization filter.
    let v = h.call(&human(DEFAULT_ORG), "approval_pending", json!({ "tool": TOOL })).await.unwrap();
    assert_eq!(v["pending"].as_array().unwrap().len(), 1, "{v}");

    // Peek sees only its own organization's request.
    let args = json!({ "title": "beta" });
    let cfg = h.hub.cfg().clone();
    let (d, o) = h
        .hub
        .db()
        .read(move |c| {
            Ok((
                approvals::peek(c, &cfg, DEFAULT_ORG, AGENT, TOOL, &args)?,
                approvals::peek(c, &cfg, ORG_B, AGENT, TOOL, &args)?,
            ))
        })
        .unwrap();
    assert_eq!((d, o), (None, Some(RequestState::Pending { approval_id: b })));

    // The platform object reader answers another organization's approval as
    // a missing one.
    let get = |who: Caller, id: i64| {
        let h = &h;
        async move {
            h.call(&who, "platform_object_get", json!({ "kind": "approval", "id": id.to_string() })).await
        }
    };
    assert_eq!(get(human(DEFAULT_ORG), a).await.unwrap()["approval"]["id"], a);
    let cross = get(human(DEFAULT_ORG), b).await.unwrap_err();
    let missing = get(human(DEFAULT_ORG), 99_999).await.unwrap_err();
    assert_eq!(reason(&cross), reason(&missing));
    assert_eq!(cross.to_string().replace(&b.to_string(), "N"), missing.to_string().replace("99999", "N"));
}

#[tokio::test]
async fn resolving_another_organizations_approval_answers_as_a_missing_one() {
    let h = H::new();
    let a = h.pending(&agent(DEFAULT_ORG), "alpha");
    let b = h.pending(&agent(ORG_B), "beta");
    let b_pass = h.seed_pass(ORG_B, AGENT, "beta pass", &now());
    let a_pass = h.seed_pass(DEFAULT_ORG, AGENT, "alpha pass", &now());
    let before = h.snapshot();
    let events = h.events();

    let cases = [
        // A default-organization human, on organization B's rows.
        (human(DEFAULT_ORG), b, "approve"),
        (human(DEFAULT_ORG), b, "deny"),
        (human(DEFAULT_ORG), b_pass, "revoke"),
        // Organization B's requester and human, on the default organization's.
        (agent(ORG_B), a, "deny"),
        (agent(ORG_B), a_pass, "revoke"),
        (human(ORG_B), a, "approve"),
        (human(ORG_B), a, "deny"),
    ];
    for (who, id, decision) in cases {
        let e =
            h.call(&who, "approval_resolve", json!({ "id": id, "decision": decision })).await.unwrap_err();
        let expected = UaError::not_found(format!("approval {id}"));
        assert_eq!(e.to_string(), expected.to_string(), "{} {decision} {id}", who.org_id);
        assert_eq!(e.code(), expected.code());
        // Exactly what an id no organization holds answers.
        let missing = h
            .call(&who, "approval_resolve", json!({ "id": 99_999, "decision": decision }))
            .await
            .unwrap_err();
        assert_eq!(missing.to_string(), UaError::not_found("approval 99999").to_string());
    }
    assert_eq!(h.snapshot(), before, "nothing changed");
    assert_eq!(h.events(), events, "nothing was ledgered");
}

#[tokio::test]
async fn a_pass_never_crosses_organizations() {
    let h = H::new();
    // Granted in the default organization: organization B's identical call
    // (same tool, payload and requester label) parks a request of its own.
    let a = h.pending(&agent(DEFAULT_ORG), "same call");
    h.call(&human(DEFAULT_ORG), "approval_resolve", json!({ "id": a, "decision": "approve" })).await.unwrap();
    let b = h.pending(&agent(ORG_B), "same call");
    assert_ne!(a, b);
    assert_eq!(h.status(a), "approved", "organization B did not spend it");
    assert_eq!(h.org_of(b), ORG_B);
    // Through the registry too: B's call is held, not run.
    let e = h.call(&agent(ORG_B), TOOL, json!({ "title": "same call" })).await.unwrap_err();
    assert!(matches!(e, UaError::ApprovalRequired { approval_id, .. } if approval_id == b), "{e:?}");
    assert_eq!(h.status(a), "approved");
    assert_eq!(h.gate(&agent(DEFAULT_ORG), "same call").unwrap(), GateOutcome::Pass { approval_id: a });

    // And the reverse: organization B's pass never satisfies the default
    // organization's identical call, but does satisfy B's.
    let b_pass = h.seed_pass(ORG_B, AGENT, "other call", &now());
    let d = h.pending(&agent(DEFAULT_ORG), "other call");
    assert_ne!(d, b_pass);
    assert_eq!(h.status(b_pass), "approved");
    assert_eq!(h.gate(&agent(ORG_B), "other call").unwrap(), GateOutcome::Pass { approval_id: b_pass });
    assert_eq!(h.status(b_pass), "consumed");

    // A denial binds its own organization only.
    let denied = h.pending(&agent(DEFAULT_ORG), "denied call");
    h.call(&human(DEFAULT_ORG), "approval_resolve", json!({ "id": denied, "decision": "deny" }))
        .await
        .unwrap();
    assert!(matches!(h.gate(&agent(ORG_B), "denied call").unwrap(), GateOutcome::Pending { .. }));
    assert!(matches!(h.gate(&agent(DEFAULT_ORG), "denied call").unwrap(), GateOutcome::Denied { .. }));
}

#[tokio::test]
async fn expiry_stays_in_its_organization() {
    let h = H::new();
    let a_old = h.seed_pass(DEFAULT_ORG, AGENT, "old call", LONG_AGO);
    let b_old = h.seed_pass(ORG_B, AGENT, "old call", LONG_AGO);
    // The default organization's call expires its own lapsed pass only.
    let a_new = h.pending(&agent(DEFAULT_ORG), "old call");
    assert_eq!((h.status(a_old), h.status(b_old)), ("expired".into(), "approved".into()));
    assert_eq!(h.org_of(a_new), DEFAULT_ORG);
    let b_new = h.pending(&agent(ORG_B), "old call");
    assert_eq!(h.status(b_old), "expired");
    assert_eq!(h.org_of(b_new), ORG_B);
    let refused = h.payloads(approvals::REFUSED);
    let ids: Vec<i64> = refused.iter().map(|p| p["approval_id"].as_i64().unwrap()).collect();
    assert_eq!(ids, [a_old, b_old], "{refused:?}");
}

#[tokio::test]
async fn organization_b_writes_land_in_organization_b() {
    let h = H::new();
    let a = h.pending(&agent(DEFAULT_ORG), "alpha");
    let b_agent = caller(B_AGENT, ActorKind::Agent, ORG_B);
    let b = h.pending(&b_agent, "beta");
    assert_eq!((h.org_of(a), h.org_of(b)), (DEFAULT_ORG.to_string(), ORG_B.to_string()));
    // A retry reuses B's row.
    assert_eq!(h.gate(&b_agent, "beta").unwrap(), GateOutcome::Pending { approval_id: b });
    // `request` (the HTTP request route's write) parks in the caller's organization.
    let (hb, who) = (h.hub.clone(), b_agent.clone());
    let state = h
        .hub
        .db()
        .write(move |tx| approvals::request(tx, hb.cfg(), &who, TOOL, &json!({ "title": "gamma" })))
        .unwrap();
    assert_eq!(h.org_of(state.approval_id()), ORG_B);

    // Until memberships exist, `ua_org::authz` admits only default-organization
    // humans, so an organization-B human cannot approve, deny or revoke an
    // organization-B approval; it stays pending.
    let before = h.snapshot();
    for decision in ["approve", "deny"] {
        let e = h
            .call(&human(ORG_B), "approval_resolve", json!({ "id": b, "decision": decision }))
            .await
            .unwrap_err();
        assert_eq!(reason(&e), "org_mismatch", "{decision}: {e}");
    }
    assert_eq!(h.snapshot(), before);
    // Every existing rule still holds before that: an agent cannot approve.
    let e = h
        .call(&agent(ORG_B), "approval_resolve", json!({ "id": b, "decision": "approve" }))
        .await
        .unwrap_err();
    assert_eq!(reason(&e), "not_human");
    // The requester may still withdraw its own request in its organization.
    let v = h.call(&b_agent, "approval_resolve", json!({ "id": b, "decision": "deny" })).await.unwrap();
    assert_eq!(v["approval"]["status"], "denied", "{v}");
    assert_eq!(h.org_of(b), ORG_B);
    assert_eq!(h.status(a), "pending", "the default organization's row is untouched");
}

#[tokio::test]
async fn the_default_organizations_rules_are_unchanged() {
    let h = H::new();
    let a = h.pending(&agent(DEFAULT_ORG), "alpha");
    // Self-approval is still refused.
    let me = caller("operator", ActorKind::Human, DEFAULT_ORG);
    let mine = h.pending(&me, "mine");
    let e = h.call(&me, "approval_resolve", json!({ "id": mine, "decision": "approve" })).await.unwrap_err();
    assert_eq!(reason(&e), "self_approval");
    // A default human approves, then the requester's identical call passes.
    let v = h
        .call(&human(DEFAULT_ORG), "approval_resolve", json!({ "id": a, "decision": "approve" }))
        .await
        .unwrap();
    assert_eq!(v["approval"]["status"], "approved");
    assert!(v["approval"].get("org_id").is_none(), "the client shape is unchanged: {v}");
    h.call(&agent(DEFAULT_ORG), TOOL, json!({ "title": "alpha" })).await.unwrap();
    assert_eq!(h.status(a), "consumed");
    let r = h.payloads("agent.approval.resolved");
    assert_eq!(r[0]["resolved_by"], "operator");
    assert_eq!(h.payloads("agent.approval.requested")[0]["requested_by"], AGENT);
}

#[tokio::test]
async fn an_unknown_organization_is_refused_before_any_write() {
    let h = H::new();
    let a = h.pending(&agent(DEFAULT_ORG), "alpha");
    h.seed_pass(DEFAULT_ORG, AGENT, "alpha pass", &now());
    h.seed_pass(DEFAULT_ORG, AGENT, "alpha old", LONG_AGO);
    let before = h.snapshot();
    let events = h.events();
    let who = agent(UNKNOWN);
    let guard = format!("unknown organization {UNKNOWN:?}; no approval was changed");

    // A gate that would consume, expire or park.
    for title in ["alpha pass", "alpha old", "new call"] {
        let e = h.gate(&who, title).unwrap_err();
        assert_eq!(reason(&e), "unknown_organization", "{title}: {e}");
        assert!(e.to_string().contains(&guard), "{title}: {e}");
    }
    let (hb, w) = (h.hub.clone(), who.clone());
    let e = h
        .hub
        .db()
        .write(move |tx| approvals::request(tx, hb.cfg(), &w, TOOL, &json!({ "title": "x" })))
        .unwrap_err();
    assert_eq!(reason(&e), "unknown_organization");
    let e = h.call(&who, TOOL, json!({ "title": "new call" })).await.unwrap_err();
    assert_eq!(reason(&e), "unknown_organization", "{e:?}");
    assert_eq!(h.snapshot(), before);
    assert_eq!(h.events(), events);

    // Reads in an unknown organization see nothing; a decision finds nothing.
    assert_eq!(h.queue(&caller("operator", ActorKind::Human, UNKNOWN)).await, (vec![], vec![], vec![]));
    let e = h
        .call(
            &caller("operator", ActorKind::Human, UNKNOWN),
            "approval_resolve",
            json!({ "id": a, "decision": "approve" }),
        )
        .await
        .unwrap_err();
    assert_eq!(e.to_string(), UaError::not_found(format!("approval {a}")).to_string());
    assert_eq!(h.snapshot(), before);
}

// --- the ledger --------------------------------------------------------------------------------

#[tokio::test]
async fn organization_b_labels_never_reach_the_default_ledger() {
    let h = H::new();
    let b_agent = caller(B_AGENT, ActorKind::Agent, ORG_B);
    // Requested, withdrawn by the requester (resolved), then refused as denied.
    let b = h.pending(&b_agent, "kestrel secret plan");
    h.call(&b_agent, "approval_resolve", json!({ "id": b, "decision": "deny", "reason": "kestrel reason" }))
        .await
        .unwrap();
    assert!(matches!(h.gate(&b_agent, "kestrel secret plan").unwrap(), GateOutcome::Denied { .. }));
    // Consumed, and refused as expired.
    h.seed_pass(ORG_B, B_AGENT, "kestrel pass", &now());
    assert!(matches!(h.gate(&b_agent, "kestrel pass").unwrap(), GateOutcome::Pass { .. }));
    h.seed_pass(ORG_B, B_AGENT, "kestrel lapsed", LONG_AGO);
    assert!(matches!(h.gate(&b_agent, "kestrel lapsed").unwrap(), GateOutcome::Pending { .. }));

    let requested = h.payloads("agent.approval.requested");
    assert_eq!(requested.len(), 2, "{requested:?}");
    assert!(
        requested.iter().all(|p| p["requested_by"].is_null() && p["approval_id"].is_i64()),
        "{requested:?}"
    );
    let resolved = h.payloads("agent.approval.resolved");
    assert_eq!((resolved.len(), resolved[0]["resolved_by"].clone()), (1, Value::Null), "{resolved:?}");
    assert_eq!(resolved[0]["decision"], "deny");
    let refused = h.payloads(approvals::REFUSED);
    let reasons: Vec<&str> = refused.iter().map(|p| p["reason"].as_str().unwrap()).collect();
    assert_eq!(reasons, ["denied", "expired"], "{refused:?}");
    assert!(refused.iter().all(|p| p["requested_by"].is_null()), "{refused:?}");
    assert_eq!(h.payloads("agent.approval.consumed").len(), 1);
    for needle in ["kestrel", "nightshift"] {
        let leaked = h.count(&format!("SELECT COUNT(*) FROM event_log WHERE payload LIKE '%{needle}%'"));
        assert_eq!(leaked, 0, "{needle:?} reached the default organization's ledger");
    }
    // Organization B keeps its own text.
    let v = h.call(&b_agent, "approval_pending", json!({})).await.unwrap();
    assert_eq!(v["pending"][0]["requested_by"], B_AGENT, "{v}");
}

// --- other readers -----------------------------------------------------------------------------

#[tokio::test]
async fn the_anomaly_check_counts_only_the_readers_organization() {
    let h = H::new();
    let b = h.pending(&agent(ORG_B), "beta");
    h.hub
        .db()
        .write(move |tx| {
            tx.execute("UPDATE approvals SET created_at = ?2 WHERE id = ?1", rusqlite::params![b, LONG_AGO])?;
            Ok(())
        })
        .unwrap();
    let rules = |v: &Value| -> Vec<String> {
        v["anomalies"]
            .as_array()
            .map(|a| a.iter().filter_map(|x| x["rule"].as_str().map(str::to_string)).collect())
            .unwrap_or_default()
    };
    let d = h.call(&human(DEFAULT_ORG), "check_anomalies", json!({})).await.unwrap();
    assert!(!rules(&d).contains(&"approval_queue_age".to_string()), "{d}");
    let o = h.call(&human(ORG_B), "check_anomalies", json!({})).await.unwrap();
    assert!(rules(&o).contains(&"approval_queue_age".to_string()), "{o}");
}

/// The stale-pass check (a live pass for the same subject bound to other
/// values, as a merge's) reads only the caller's organization.
#[test]
fn a_stale_pass_is_found_only_in_its_organization() {
    let h = H::new();
    let bound = approvals::canonical_payload(&json!({ "task_id": 7, "head": "aaa" }));
    let fresh = now();
    h.hub
        .db()
        .write(move |tx| {
            tx.execute(
                "INSERT INTO approvals (org_id, tool, payload, requested_by, status, resolved_by, created_at, \
                 updated_at, resolved_at) VALUES ('org-b', 'merge', ?1, ?2, 'approved', 'operator', ?3, ?3, ?3)",
                rusqlite::params![bound, AGENT, fresh],
            )?;
            Ok(())
        })
        .unwrap();
    let presented = json!({ "task_id": 7, "head": "bbb" });
    let cfg = h.hub.cfg().clone();
    let (d, o) = h
        .hub
        .db()
        .read(move |c| {
            Ok((
                approvals::stale_pass(c, &cfg, DEFAULT_ORG, AGENT, "merge", &presented, &["task_id"])?,
                approvals::stale_pass(c, &cfg, ORG_B, AGENT, "merge", &presented, &["task_id"])?,
            ))
        })
        .unwrap();
    assert_eq!(d, None);
    assert_eq!(o.map(|s| s.changed), Some(vec!["head".to_string()]));
}

/// `peek` (the HTTP request route's and the harness config's read) reports a
/// denial or a live pass only to its own organization.
#[tokio::test]
async fn peek_sees_only_its_organizations_denial_and_pass() {
    let h = H::new();
    let pass = h.seed_pass(DEFAULT_ORG, AGENT, "passed call", &now());
    let denied = h.pending(&agent(DEFAULT_ORG), "denied call");
    h.call(&human(DEFAULT_ORG), "approval_resolve", json!({ "id": denied, "decision": "deny" }))
        .await
        .unwrap();
    let cfg = h.hub.cfg().clone();
    let peek = |org: &'static str, title: &'static str| {
        let cfg = cfg.clone();
        h.hub
            .db()
            .read(move |c| approvals::peek(c, &cfg, org, AGENT, TOOL, &json!({ "title": title })))
            .unwrap()
    };
    assert_eq!(peek(DEFAULT_ORG, "passed call"), Some(RequestState::Approved { approval_id: pass }));
    assert!(
        matches!(peek(DEFAULT_ORG, "denied call"), Some(RequestState::Denied { approval_id, .. }) if approval_id == denied)
    );
    assert_eq!(peek(ORG_B, "passed call"), None);
    assert_eq!(peek(ORG_B, "denied call"), None);
}
