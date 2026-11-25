//! Organization keys, standalone table rebuild and tool isolation for
//! `managed_secrets`, and the per-organization GitHub credentials stored in
//! it (`docs/organization.md`, `docs/github.md`).
//!
//! Every value here is fake. Until memberships exist no caller outside the
//! default organization holds operator authority, so another
//! organization's rows are written directly; the unit tests in
//! `families/github/credentials.rs` store and resolve them through the
//! shared write path with real encryption.

use serde_json::{Value, json};
use ua_core::{ActorKind, Caller, Config, DEFAULT_ORG, Profile, UaError, identity::Transport};
use ua_tools::families::github::credentials::{
    API_CONSUMER, CredentialKind, CredentialSource, TOKEN_SECRET, WEBHOOK_SECRET, github_credential_for,
};
use ua_tools::{Hub, Registry, builtin_registry};

const ORG_B: &str = "org-b";
const ORG_C: &str = "org-c";
const UNKNOWN: &str = "missing-org";
const PARTS: [&str; 2] = ["managed_secrets.v2.tenant_keys", "organization.v1.tools.managed_secrets"];
const KEY: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

const HUB_TOKEN: &str = "fake-hub-github-token-not-real-7f3a";
const HUB_HOOK: &str = "fake-hub-webhook-secret-not-real-7f3a";
const DOCS_V1: &str = "fake-docs-token-value-one-not-real-7f3a";
const DOCS_V2: &str = "fake-docs-token-value-two-not-real-7f3a";
const ORG_TOKEN: &str = "fake-org-github-token-not-real-7f3a";
const VALUES: [&str; 5] = [HUB_TOKEN, HUB_HOOK, DOCS_V1, DOCS_V2, ORG_TOKEN];

fn old_parts() -> Vec<ua_store::Part> {
    ua_tools::schema_parts().into_iter().filter(|p| !PARTS.contains(&p.name)).collect()
}

fn cfg(home: &std::path::Path) -> Config {
    let mut cfg = Config::for_home(home);
    cfg.human_identities = vec!["operator".into(), "approver".into()];
    cfg.managed_secret_key = Some(KEY.to_string().into());
    cfg.github_token_value = Some(HUB_TOKEN.to_string().into());
    cfg.github_webhook_secret_value = Some(HUB_HOOK.to_string().into());
    cfg
}

fn caller(label: &str, kind: ActorKind, org: &str) -> Caller {
    Caller {
        label: label.into(),
        kind,
        // A profile that sees the secret tools; it grants no authority.
        profile: Profile::Operator,
        enforce_profile: kind != ActorKind::Human,
        session_key: Some(format!("{label}-s")),
        transport: Transport::Mcp,
        org_id: org.into(),
    }
}

fn agent(org: &str) -> Caller {
    caller("lead-1", ActorKind::Agent, org)
}

fn human(org: &str) -> Caller {
    caller("operator", ActorKind::Human, org)
}

fn approver() -> Caller {
    caller("approver", ActorKind::Human, DEFAULT_ORG)
}

fn anonymous() -> Caller {
    Caller { session_key: None, ..caller("anonymous", ActorKind::Anonymous, DEFAULT_ORG) }
}

fn reason(e: &UaError) -> String {
    e.reason_code().map(str::to_string).unwrap_or_else(|| e.code().to_string())
}

struct H {
    hub: Hub,
    reg: Registry,
    _dir: tempfile::TempDir,
}

impl H {
    fn new() -> Self {
        Self::with(|_| {})
    }

    fn with(f: impl FnOnce(&mut Config)) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let mut c = cfg(&dir.path().join("home"));
        f(&mut c);
        let hub = Hub::in_memory(c).unwrap();
        for org in [ORG_B, ORG_C] {
            hub.db()
                .write(|tx| {
                    tx.execute(
                        "INSERT INTO orgs (id, slug, display_name, allowed_profiles, created_at)
                         VALUES (?1, ?1, ?1, '[\"developer\",\"coordinator\",\"operator\"]', '2026-01-01T00:00:00+00:00')",
                        [org],
                    )?;
                    Ok(())
                })
                .unwrap();
        }
        Self { hub, reg: builtin_registry(), _dir: dir }
    }

    async fn call(&self, who: &Caller, tool: &str, args: Value) -> Result<Value, UaError> {
        self.reg.call(&self.hub, who, tool, args).await
    }

    async fn ok(&self, who: &Caller, tool: &str, args: Value) -> Value {
        match self.call(who, tool, args.clone()).await {
            Ok(v) => v,
            Err(e) => panic!("{tool}({args}) as {} failed: {e:?}", who.label),
        }
    }

    async fn err(&self, who: &Caller, tool: &str, args: Value) -> UaError {
        match self.call(who, tool, args.clone()).await {
            Ok(v) => panic!("{tool}({args}) as {} should fail, got {v}", who.label),
            Err(e) => e,
        }
    }

    /// Every secret row as `(org_id, name, consumer)`.
    fn rows(&self) -> Vec<(String, String, String)> {
        self.hub
            .db()
            .read(|c| {
                Ok(c.prepare("SELECT org_id, name, consumer FROM managed_secrets ORDER BY org_id, name")?
                    .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
                    .collect::<Result<_, _>>()?)
            })
            .unwrap()
    }

    fn events(&self) -> i64 {
        self.hub.db().read(|c| Ok(c.query_row("SELECT COUNT(*) FROM event_log", [], |r| r.get(0))?)).unwrap()
    }

    /// Copy the default organization's `from` row into `org` as `name` bound
    /// to `consumer`: a sealed row whose associated data names the default
    /// organization and the old name, so it must never decrypt there.
    fn copy_row(&self, from: &str, org: &str, name: &str, consumer: &str) {
        self.hub
            .db()
            .write(|tx| {
                tx.execute(
                    "INSERT INTO managed_secrets (org_id, name, consumer, key_id, nonce, ciphertext, fingerprint, \
                     value_bytes, created_by, created_at, updated_by, updated_at, aad_v) \
                     SELECT ?1, ?2, ?3, key_id, nonce, ciphertext, fingerprint, value_bytes, created_by, \
                     created_at, updated_by, updated_at, aad_v FROM managed_secrets \
                     WHERE org_id = 'default' AND name = ?4",
                    [org, name, consumer, from],
                )?;
                Ok(())
            })
            .unwrap();
    }

    /// Every cell of every table, as text or bytes, that contains `needle`.
    fn cells_containing(&self, needle: &str) -> Vec<String> {
        self.hub
            .db()
            .read(|c| {
                let tables: Vec<String> = c
                    .prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")?
                    .query_map([], |r| r.get(0))?
                    .collect::<Result<_, _>>()?;
                let mut hits = Vec::new();
                for t in tables {
                    let mut stmt = c.prepare(&format!("SELECT * FROM \"{}\"", t.replace('"', "\"\"")))?;
                    let n = stmt.column_count();
                    let mut rows = stmt.query([])?;
                    while let Some(row) = rows.next()? {
                        for i in 0..n {
                            use rusqlite::types::ValueRef;
                            let hit = match row.get_ref(i)? {
                                ValueRef::Text(b) | ValueRef::Blob(b) => {
                                    b.windows(needle.len()).any(|w| w == needle.as_bytes())
                                }
                                _ => false,
                            };
                            if hit {
                                hits.push(t.clone());
                            }
                        }
                    }
                }
                Ok(hits)
            })
            .unwrap()
    }

    /// Overwrite one row's metadata (never its organization, which is
    /// immutable) to simulate a row sealed differently.
    fn set_meta(&self, org: &str, name: &str, column: &str, value: Value) {
        let sql = format!("UPDATE managed_secrets SET {column} = ?3 WHERE org_id = ?1 AND name = ?2");
        self.hub
            .db()
            .write(move |tx| {
                let v: rusqlite::types::Value = match value {
                    Value::Number(n) => rusqlite::types::Value::Integer(n.as_i64().unwrap()),
                    Value::String(s) => rusqlite::types::Value::Text(s),
                    other => panic!("unsupported {other}"),
                };
                assert_eq!(tx.execute(&sql, rusqlite::params![org, name, v])?, 1);
                Ok(())
            })
            .unwrap();
    }

    fn resolve(&self, org: &str, kind: CredentialKind) -> Result<Option<String>, UaError> {
        let cfg = self.hub.cfg().clone();
        let org = org.to_string();
        self.hub
            .db()
            .read(move |c| {
                use secrecy::ExposeSecret;
                Ok(github_credential_for(c, &cfg, &org, kind)
                    .map(|o| o.map(|cred| cred.secret().expose_secret().to_string())))
            })
            .unwrap()
    }
}

fn count(c: &rusqlite::Connection, sql: &str, arg: &str) -> i64 {
    c.query_row(sql, [arg], |r| r.get(0)).unwrap()
}

#[test]
fn legacy_upgrade_rebuilds_the_key_and_keeps_secrets_triggers_and_views() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = cfg(dir.path());
    {
        let db = ua_store::Db::open(&cfg.db_path(), &old_parts()).unwrap();
        db.write(|tx| {
            tx.execute(
                "INSERT INTO managed_secrets (name, consumer, key_id, nonce, ciphertext, fingerprint, value_bytes,
                     created_by, created_at, updated_by, updated_at)
                 VALUES ('docs-token', 'mcp:docs', 'k1', x'000102030405060708090a0b', x'aabbcc', 'fp1', 12,
                         'operator', '2026-01-02T00:00:00+00:00', 'operator', '2026-01-03T00:00:00+00:00'),
                        ('relay-gh', 'relay:github', 'k1', x'0c0d0e0f1011121314151617', x'ddeeff', 'fp2', 20,
                         'operator', '2026-01-04T00:00:00+00:00', 'operator', '2026-01-04T00:00:00+00:00')",
                [],
            )?;
            // An extra index, trigger and view prove the rebuild keeps them.
            tx.execute_batch(
                "CREATE INDEX idx_managed_secrets_updated ON managed_secrets(updated_at);
                 CREATE VIEW v_secret_names AS SELECT name, consumer FROM managed_secrets;
                 CREATE TRIGGER trg_secrets_touch AFTER INSERT ON managed_secrets BEGIN SELECT 1; END;",
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
                type Row = (String, String, String, String, Vec<u8>, Vec<u8>, String, i64, String, i64);
                let rows: Vec<Row> = c
                    .prepare(
                        "SELECT org_id, name, consumer, key_id, nonce, ciphertext, fingerprint, value_bytes,
                                updated_at, aad_v FROM managed_secrets ORDER BY name",
                    )?
                    .query_map([], |r| {
                        Ok((
                            r.get(0)?,
                            r.get(1)?,
                            r.get(2)?,
                            r.get(3)?,
                            r.get(4)?,
                            r.get(5)?,
                            r.get(6)?,
                            r.get(7)?,
                            r.get(8)?,
                            r.get(9)?,
                        ))
                    })?
                    .collect::<Result<_, _>>()?;
                assert_eq!(rows.len(), 2);
                let (org, name, consumer, key_id, nonce, ct, fp, size, updated, aad_v) = &rows[0];
                assert_eq!(
                    (org.as_str(), name.as_str(), consumer.as_str(), key_id.as_str()),
                    (DEFAULT_ORG, "docs-token", "mcp:docs", "k1")
                );
                assert_eq!(nonce, &(0u8..12).collect::<Vec<_>>());
                assert_eq!(ct, &vec![0xaa, 0xbb, 0xcc]);
                assert_eq!((fp.as_str(), *size, updated.as_str()), ("fp1", 12, "2026-01-03T00:00:00+00:00"));
                assert_eq!(*aad_v, 1, "a legacy row keeps the associated-data form it was sealed under");
                assert_eq!((rows[1].0.as_str(), rows[1].1.as_str(), rows[1].9), (DEFAULT_ORG, "relay-gh", 1));

                let mut pk: Vec<(i64, String)> = c
                    .prepare("SELECT pk, name FROM pragma_table_info('managed_secrets') WHERE pk > 0")?
                    .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
                    .collect::<Result<_, _>>()?;
                pk.sort();
                assert_eq!(pk.into_iter().map(|(_, n)| n).collect::<Vec<_>>(), ["org_id", "name"]);
                for idx in [
                    "idx_managed_secrets_consumer",
                    "idx_managed_secrets_updated",
                    "idx_managed_secrets_org_consumer",
                ] {
                    let n = count(
                        c,
                        "SELECT count(*) FROM sqlite_master WHERE type = 'index' AND name = ?1",
                        idx,
                    );
                    assert_eq!(n, 1, "index {idx}");
                }
                for trg in
                    ["trg_secrets_touch", "managed_secrets_org_exists", "managed_secrets_org_immutable"]
                {
                    let n = count(
                        c,
                        "SELECT count(*) FROM sqlite_master \
                         WHERE type = 'trigger' AND tbl_name = 'managed_secrets' AND name = ?1",
                        trg,
                    );
                    assert_eq!(n, 1, "trigger {trg}");
                }
                assert_eq!(count(c, "SELECT count(*) FROM v_secret_names WHERE consumer LIKE ?1", "%:%"), 2);
                for part in PARTS {
                    assert_eq!(
                        count(c, "SELECT count(*) FROM schema_parts WHERE name = ?1", part),
                        1,
                        "{part}"
                    );
                }
                let fk: i64 = c.query_row("PRAGMA foreign_keys", [], |r| r.get(0))?;
                assert_eq!(fk, 1, "foreign keys restored");
                Ok(())
            })
            .unwrap();
    }

    // Two organizations may now hold the same name; an unknown one may not,
    // and a row never moves between organizations.
    let hub = Hub::open(cfg).unwrap();
    hub.db()
        .write(|tx| {
            tx.execute(
                "INSERT INTO orgs (id, slug, display_name, allowed_profiles, created_at)
                 VALUES (?1, ?1, ?1, '[\"developer\"]', '2026-01-01T00:00:00+00:00')",
                [ORG_B],
            )?;
            let insert = "INSERT INTO managed_secrets (org_id, name, consumer, key_id, nonce, ciphertext, \
                          fingerprint, value_bytes, created_by, created_at, updated_by, updated_at, aad_v) \
                          VALUES (?1, 'docs-token', 'mcp:docs', 'k1', x'00', x'00', 'fp', 1, 'x', 'now', 'x', \
                          'now', 2)";
            tx.execute(insert, [ORG_B])?;
            assert!(tx.execute(insert, [UNKNOWN]).is_err(), "an unknown organization is refused");
            assert!(
                tx.execute("UPDATE managed_secrets SET org_id = 'default' WHERE org_id = ?1", [ORG_B]).is_err(),
                "org_id is immutable"
            );
            Ok(())
        })
        .unwrap();
}

#[tokio::test]
async fn the_secret_tools_act_in_the_callers_organization_only() {
    let h = H::new();
    let op = human(DEFAULT_ORG);
    h.ok(
        &op,
        "managed_secret_set",
        json!({ "name": "docs-token", "consumer": "mcp:docs", "value": DOCS_V1 }),
    )
    .await;
    // Organization B's row of the same name: no caller of B may write it yet.
    h.copy_row("docs-token", ORG_B, "docs-token", "mcp:docs");

    let mine = h.ok(&op, "managed_secret_list", json!({})).await;
    assert_eq!(mine["count"], 1);
    let theirs = h.ok(&agent(ORG_B), "managed_secret_list", json!({})).await;
    assert_eq!(theirs["count"], 1);
    assert_eq!(h.ok(&agent(ORG_C), "managed_secret_list", json!({})).await["count"], 0);

    // B's callers cannot write B's secrets (no operator authority outside
    // the default organization yet), and nobody writes into an unknown one.
    for who in [human(ORG_B), agent(ORG_B)] {
        let e = h
            .err(
                &who,
                "managed_secret_set",
                json!({ "name": "docs-token", "consumer": "mcp:docs", "value": DOCS_V2 }),
            )
            .await;
        assert_eq!(reason(&e), "operator_only", "{e:?}");
        let e = h.err(&who, "managed_secret_delete", json!({ "name": "docs-token" })).await;
        assert_eq!(reason(&e), "operator_only", "{e:?}");
    }
    let e = h
        .err(
            &human(UNKNOWN),
            "managed_secret_set",
            json!({ "name": "x", "consumer": "mcp:docs", "value": DOCS_V2 }),
        )
        .await;
    assert_eq!(reason(&e), "unknown_organization", "{e:?}");

    // Replacing the default secret is gated, approved by another human, and
    // changes only the default organization's row.
    let args = json!({ "name": "docs-token", "consumer": "mcp:docs", "value": DOCS_V2 });
    let e = h.err(&op, "managed_secret_set", args.clone()).await;
    let UaError::ApprovalRequired { approval_id, .. } = e else { panic!("{e:?}") };
    h.ok(&approver(), "approval_resolve", json!({ "id": approval_id, "decision": "approve" })).await;
    let out = h.ok(&op, "managed_secret_set", args).await;
    assert_eq!(out["replaced"], true);
    let fp_default = out["fingerprint"].as_str().unwrap().to_string();
    let fp_b: String = h
        .hub
        .db()
        .read(|c| {
            Ok(c.query_row("SELECT fingerprint FROM managed_secrets WHERE org_id = ?1", [ORG_B], |r| {
                r.get(0)
            })?)
        })
        .unwrap();
    assert_ne!(fp_default, fp_b, "organization B's row was not touched");

    // Deleting removes the default organization's row only.
    let e = h.err(&op, "managed_secret_delete", json!({ "name": "docs-token" })).await;
    let UaError::ApprovalRequired { approval_id, .. } = e else { panic!("{e:?}") };
    h.ok(&approver(), "approval_resolve", json!({ "id": approval_id, "decision": "approve" })).await;
    h.ok(&op, "managed_secret_delete", json!({ "name": "docs-token" })).await;
    assert_eq!(h.rows(), vec![(ORG_B.into(), "docs-token".into(), "mcp:docs".into())]);
    let e = h.err(&op, "managed_secret_delete", json!({ "name": "docs-token" })).await;
    assert_eq!(e.code(), "not_found", "B's row answers as a missing one: {e:?}");
}

#[tokio::test]
async fn github_names_and_consumers_are_reserved_for_their_tools() {
    let h = H::new();
    let op = human(DEFAULT_ORG);
    for (name, consumer) in
        [(TOKEN_SECRET, "mcp:docs"), ("GitHub:Webhook-Secret", "mcp:docs"), ("docs-token", API_CONSUMER)]
    {
        let e = h
            .err(&op, "managed_secret_set", json!({ "name": name, "consumer": consumer, "value": DOCS_V1 }))
            .await;
        assert_eq!(reason(&e), "reserved_secret", "{name} {consumer}: {e:?}");
    }
    // The relay keeps its own consumer.
    h.ok(
        &op,
        "managed_secret_set",
        json!({ "name": "relay-gh", "consumer": "relay:github", "value": DOCS_V1 }),
    )
    .await;
    assert_eq!(h.rows().len(), 1);
}

#[tokio::test]
async fn setting_or_clearing_a_github_credential_is_refused_to_every_caller_today() {
    let h = H::new();
    let events = h.events();
    let set = json!({ "kind": "token", "value": ORG_TOKEN });
    let clear = json!({ "kind": "token" });
    let cases: [(Caller, &str); 6] = [
        // The default organization's credentials are the hub's configuration.
        (human(DEFAULT_ORG), "github_credential_in_hub_config"),
        // An agent is never a secret admin, whatever its profile.
        (agent(DEFAULT_ORG), "operator_only"),
        // Another organization's callers hold no operator authority yet.
        (human(ORG_B), "operator_only"),
        (agent(ORG_B), "operator_only"),
        (human(UNKNOWN), "unknown_organization"),
        (anonymous(), "identity_required"),
    ];
    for (who, want) in &cases {
        for (tool, args) in [("github_credential_set", &set), ("github_credential_clear", &clear)] {
            let e = h.err(who, tool, args.clone()).await;
            let got = reason(&e);
            // The registry refuses an anonymous caller of an always-gated
            // tool before its handler runs.
            let ok = got == *want || (who.kind == ActorKind::Anonymous && got.starts_with("anonymous"));
            assert!(ok, "{tool} as {} in {}: want {want}, got {e:?}", who.label, who.org_id);
            assert!(!format!("{e:?}").contains(ORG_TOKEN));
        }
    }
    assert!(h.rows().is_empty(), "nothing was stored");
    // Refusals may be ledgered as gateway decisions; none names the value
    // (the leak test scans every table).
    assert!(h.events() >= events);
}

#[tokio::test]
async fn github_credentials_resolve_per_organization_with_no_fallback() {
    let h = H::new();
    let op = human(DEFAULT_ORG);
    // The default organization resolves to the hub's configuration, as before.
    assert_eq!(h.resolve(DEFAULT_ORG, CredentialKind::Token).unwrap().as_deref(), Some(HUB_TOKEN));
    assert_eq!(h.resolve(DEFAULT_ORG, CredentialKind::WebhookSecret).unwrap().as_deref(), Some(HUB_HOOK));
    // Another organization with none is off: neither the hub's nor anyone's.
    assert_eq!(h.resolve(ORG_B, CredentialKind::Token).unwrap(), None);
    assert_eq!(h.resolve(ORG_B, CredentialKind::WebhookSecret).unwrap(), None);

    // A default-organization secret copied into B under B's reserved name
    // and consumer does not decrypt there: B never gets another
    // organization's value.
    h.ok(
        &op,
        "managed_secret_set",
        json!({ "name": "docs-token", "consumer": "mcp:docs", "value": DOCS_V1 }),
    )
    .await;
    h.copy_row("docs-token", ORG_B, TOKEN_SECRET, API_CONSUMER);
    let e = h.resolve(ORG_B, CredentialKind::Token).unwrap_err();
    assert!(!format!("{e:?}").contains(DOCS_V1));
    // Org C and the default organization are unaffected by B's row.
    assert_eq!(h.resolve(ORG_C, CredentialKind::Token).unwrap(), None);
    assert_eq!(h.resolve(DEFAULT_ORG, CredentialKind::Token).unwrap().as_deref(), Some(HUB_TOKEN));

    // A default-organization row under the reserved names is never read:
    // the default organization's credential is its configuration.
    h.copy_row("docs-token", DEFAULT_ORG, TOKEN_SECRET, API_CONSUMER);
    assert_eq!(h.resolve(DEFAULT_ORG, CredentialKind::Token).unwrap().as_deref(), Some(HUB_TOKEN));
    let cfg = h.hub.cfg().clone();
    let src = h
        .hub
        .db()
        .read(move |c| {
            Ok(github_credential_for(c, &cfg, DEFAULT_ORG, CredentialKind::Token)?.map(|c| c.source()))
        })
        .unwrap();
    assert_eq!(src, Some(CredentialSource::HubConfig));

    // Without the configuration the default organization is off, even though
    // a reserved row sits in it and another organization holds one.
    let mut bare = h.hub.cfg().clone();
    bare.github_token_value = None;
    bare.github_token_env = None;
    let none = h
        .hub
        .db()
        .read(move |c| Ok(github_credential_for(c, &bare, DEFAULT_ORG, CredentialKind::Token)?.is_none()));
    assert!(none.unwrap());
}

#[tokio::test]
async fn status_and_doctor_report_each_organization_without_values() {
    let h = H::new();
    let op = human(DEFAULT_ORG);
    h.ok(
        &op,
        "managed_secret_set",
        json!({ "name": "docs-token", "consumer": "mcp:docs", "value": DOCS_V1 }),
    )
    .await;
    // B's token row, sealed under the current key (status reads metadata only).
    h.copy_row("docs-token", ORG_B, TOKEN_SECRET, API_CONSUMER);

    let d = h.ok(&op, "github_credential_status", json!({})).await;
    assert_eq!(d["token"]["state"], "configured");
    assert_eq!(d["token"]["source"], "hub_config");
    assert_eq!(d["webhook_secret"]["state"], "configured");
    let b = h.ok(&agent(ORG_B), "github_credential_status", json!({})).await;
    assert_eq!(b["token"]["state"], "configured");
    assert_eq!(b["token"]["source"], "managed_secret");
    assert_eq!(b["webhook_secret"]["state"], "off");
    let c = h.ok(&agent(ORG_C), "github_credential_status", json!({})).await;
    assert_eq!(c["token"]["state"], "off");
    assert_eq!(c["token"]["source"], Value::Null);
    assert_eq!(c["automation_scope"], "per_organization");

    let line = |report: &Value| {
        report["checks"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["capability"] == "github_credentials")
            .cloned()
            .unwrap()
    };
    let hub_view = line(&h.ok(&op, "system_doctor", json!({})).await);
    let detail = hub_view["detail"].as_str().unwrap();
    assert!(detail.contains("default: token configured (hub config)"), "{detail}");
    assert!(detail.contains("org-b: token configured (managed secret), webhook_secret off"), "{detail}");
    assert!(detail.contains("org-c: token off, webhook_secret off"), "{detail}");
    assert_eq!(hub_view["status"], "LIVE");
    // Anyone but a hub operator gets counts only: a default-organization
    // agent over every organization, another organization's caller over its
    // own. No organization is named to them.
    let dev_default = Caller { profile: Profile::Developer, ..agent(DEFAULT_ORG) };
    let agent_view = line(&h.ok(&dev_default, "system_doctor", json!({})).await);
    let detail = agent_view["detail"].as_str().unwrap();
    assert!(
        detail.starts_with(
            "3 organization(s): token 2 configured, 0 unusable, 1 off, webhook_secret 1 configured, 0 unusable, \
             2 off"
        ),
        "{detail}"
    );
    assert_eq!(agent_view["status"], "LIVE");
    let developer = Caller { profile: Profile::Developer, ..agent(ORG_C) };
    let c_view = line(&h.ok(&developer, "system_doctor", json!({})).await);
    let detail = c_view["detail"].as_str().unwrap();
    assert!(
        detail.starts_with(
            "1 organization(s): token 0 configured, 0 unusable, 1 off, webhook_secret 0 configured, 0 unusable, \
             1 off"
        ),
        "{detail}"
    );
    assert_eq!(c_view["status"], "DORMANT");
    for view in [&agent_view, &c_view] {
        let detail = view["detail"].as_str().unwrap();
        for org in [DEFAULT_ORG, ORG_B, ORG_C] {
            assert!(!detail.contains(&format!("{org}:")), "{detail}");
        }
        assert!(!detail.contains("hub config") && !detail.contains("managed secret"), "{detail}");
    }

    for out in [&d, &b, &c, &hub_view, &agent_view, &c_view] {
        let text = out.to_string();
        for v in VALUES {
            assert!(!text.contains(v), "{text}");
        }
        assert!(!text.contains("fingerprint"), "{text}");
    }
}

#[tokio::test]
async fn no_secret_value_reaches_any_table_reply_or_event() {
    let h = H::new();
    let op = human(DEFAULT_ORG);
    let mut replies = Vec::new();
    replies.push(
        h.ok(
            &op,
            "managed_secret_set",
            json!({ "name": "docs-token", "consumer": "mcp:docs", "value": DOCS_V1 }),
        )
        .await,
    );
    let args = json!({ "name": "docs-token", "consumer": "mcp:docs", "value": DOCS_V2 });
    let UaError::ApprovalRequired { approval_id, .. } = h.err(&op, "managed_secret_set", args.clone()).await
    else {
        panic!("a replacement is gated")
    };
    h.ok(&approver(), "approval_resolve", json!({ "id": approval_id, "decision": "approve" })).await;
    // The registry did not gate this call (managed_secret_set is not in
    // approval_tools), so put() parked and then consumed the approval
    // itself.
    assert!(!h.hub.cfg().approval_tools.iter().any(|t| t == "managed_secret_set"));
    let replaced = h.ok(&op, "managed_secret_set", args).await;
    assert_eq!(replaced["replaced"], true);
    assert_eq!(replaced["approval_id"], approval_id);
    let fingerprint = replaced["fingerprint"].as_str().unwrap().to_string();
    replies.push(replaced);
    // That approval binds the new value's keyed fingerprint, never the value.
    let (tool, status, payload): (String, String, String) = h
        .hub
        .db()
        .read(move |c| {
            Ok(c.query_row(
                "SELECT tool, status, payload FROM approvals WHERE id = ?1",
                [approval_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )?)
        })
        .unwrap();
    assert_eq!((tool.as_str(), status.as_str()), ("managed_secret_set", "consumed"));
    let bound: Value = serde_json::from_str(&payload).unwrap();
    assert_eq!(bound["fingerprint"], fingerprint.as_str(), "{payload}");
    assert_eq!(bound["value_bytes"], DOCS_V2.len());
    for v in VALUES {
        assert!(!payload.contains(v), "{v} in the approval: {payload}");
    }
    assert!(!h.cells_containing(DOCS_V2).iter().any(|t| t == "approvals"));
    assert!(h.cells_containing(&fingerprint).iter().any(|t| t == "approvals"));

    // Reserved GitHub rows, in B and (inert) in the default organization,
    // with metadata markers: no list shows their fingerprint, size or key.
    const RESERVED_FP: &str = "fake-reserved-fingerprint-not-real";
    const RESERVED_KEY: &str = "fake-reserved-key-id-not-real";
    for (org, name) in [(ORG_B, TOKEN_SECRET), (DEFAULT_ORG, WEBHOOK_SECRET)] {
        let consumer = if name == TOKEN_SECRET { API_CONSUMER } else { "relay:github" };
        h.copy_row("docs-token", org, name, consumer);
        h.set_meta(org, name, "fingerprint", json!(RESERVED_FP));
        h.set_meta(org, name, "key_id", json!(RESERVED_KEY));
        h.set_meta(org, name, "value_bytes", json!(4242));
    }
    for who in [op.clone(), agent(ORG_B)] {
        let list = h.ok(&who, "managed_secret_list", json!({})).await;
        let text = list.to_string();
        assert!(!text.contains(RESERVED_FP) && !text.contains(RESERVED_KEY), "{text}");
        let reserved: Vec<&Value> =
            list["secrets"].as_array().unwrap().iter().filter(|r| r["reserved"] == true).collect();
        assert_eq!(reserved.len(), 1, "{text}");
        for field in ["fingerprint", "value_bytes", "key_id", "key_current", "decryptable"] {
            assert_eq!(reserved[0][field], Value::Null, "{field}: {text}");
        }
        replies.push(list);
    }
    // Every GitHub credential attempt carries a value, and every one is refused.
    for who in [human(DEFAULT_ORG), agent(DEFAULT_ORG), human(ORG_B), agent(ORG_B), anonymous()] {
        for kind in ["token", "webhook_secret"] {
            let e = h.err(&who, "github_credential_set", json!({ "kind": kind, "value": ORG_TOKEN })).await;
            replies.push(json!({ "error": format!("{e:?}") }));
        }
    }
    replies.push(h.ok(&op, "github_credential_status", json!({})).await);
    replies.push(h.ok(&op, "system_doctor", json!({})).await);

    for v in VALUES {
        assert_eq!(h.cells_containing(v), Vec::<String>::new(), "{v} was stored in plain text");
        for r in &replies {
            assert!(!r.to_string().contains(v), "{v} in a reply: {r}");
        }
    }
    // The ledger names secrets, never their keyed fingerprint.
    let ledgered = h.cells_containing(&fingerprint);
    assert!(!ledgered.iter().any(|t| t == "event_log"), "{ledgered:?}");
    assert!(!ledgered.iter().any(|t| t == "tool_calls"), "{ledgered:?}");
    // And the calls were recorded, without their arguments.
    let calls: i64 = h
        .hub
        .db()
        .read(|c| {
            let sql = "SELECT COUNT(*) FROM tool_calls \
                       WHERE tool LIKE '%secret%' OR tool LIKE 'github_credential%'";
            Ok(c.query_row(sql, [], |r| r.get(0))?)
        })
        .unwrap();
    assert!(calls > 0);
}

#[tokio::test]
async fn status_calls_a_row_the_resolver_refuses_unusable() {
    let h = H::new();
    let op = human(DEFAULT_ORG);
    h.ok(
        &op,
        "managed_secret_set",
        json!({ "name": "docs-token", "consumer": "mcp:docs", "value": DOCS_V1 }),
    )
    .await;
    h.copy_row("docs-token", ORG_B, TOKEN_SECRET, API_CONSUMER);
    let doctor = |report: Value| {
        report["checks"].as_array().unwrap().iter().find(|c| c["capability"] == "github_credentials").cloned()
    };

    // A pre-organization form (aad_v 1) outside the default organization,
    // and a form this build does not know: never decrypted, so never
    // reported configured.
    for aad_v in [1, 7] {
        h.set_meta(ORG_B, TOKEN_SECRET, "aad_v", json!(aad_v));
        let b = h.ok(&agent(ORG_B), "github_credential_status", json!({})).await;
        assert_eq!(b["token"]["state"], "unusable", "aad_v {aad_v}: {b}");
        assert_eq!(b["token"]["source"], "managed_secret");
        let e = h.resolve(ORG_B, CredentialKind::Token).unwrap_err();
        assert!(!format!("{e:?}").contains(DOCS_V1));
        let line = doctor(h.ok(&op, "system_doctor", json!({})).await).unwrap();
        assert_eq!(line["status"], "DEGRADED", "{line}");
        assert!(line["detail"].as_str().unwrap().contains("org-b: token unusable"), "{line}");
    }
    // The key rotated away is unusable too, whatever the form.
    h.set_meta(ORG_B, TOKEN_SECRET, "aad_v", json!(2));
    h.set_meta(ORG_B, TOKEN_SECRET, "key_id", json!("fake-retired-key-not-real"));
    let b = h.ok(&agent(ORG_B), "github_credential_status", json!({})).await;
    assert_eq!(b["token"]["state"], "unusable", "{b}");
}

#[tokio::test]
async fn hub_scoped_secret_users_refuse_another_organizations_caller() {
    // A reviewed config server that injects a hub secret. The refusal comes
    // before anything is spawned, so the command never runs.
    let h = H::with(|c| {
        c.mcp_servers.insert(
            "docs".into(),
            json!({
                "transport": "stdio",
                "command": "/nonexistent/fake-mcp-server-not-real",
                "secrets": [{ "secret": "docs-token", "inject": "env:FAKE_TOKEN" }],
                "tools": { "echo": "read" },
                "read_profiles": ["developer", "operator"],
                "review_expires_at": "2099-01-01",
            }),
        );
    });
    let events = h.events();
    // mcp_gateway is a developer tool, relay_manage a coordinator one.
    let dev = |c: Caller| Caller { profile: Profile::Developer, ..c };
    let coord = |c: Caller| Caller { profile: Profile::Coordinator, ..c };
    for who in [agent(ORG_B), human(ORG_B)] {
        let (gw, who) = (dev(who.clone()), coord(who));
        // mcp_gateway exists only in a build with the `mcp-gateway` feature;
        // the relay half runs in every build.
        if cfg!(feature = "mcp-gateway") {
            for args in [
                json!({ "server": "docs", "tool": "echo" }),
                json!({ "action": "list", "server": "docs", "live": true }),
            ] {
                let e = h.err(&gw, "mcp_gateway", args.clone()).await;
                assert_eq!(reason(&e), "org_unsupported", "{args}: {e:?}");
            }
            // A static list reads no secret and is not refused.
            h.ok(&gw, "mcp_gateway", json!({ "action": "list", "server": "docs" })).await;
        }

        for (action, params) in [
            ("request_send", json!({ "draft_id": 1 })),
            ("send", json!({ "draft_id": 1, "text": "fake relay text not real" })),
        ] {
            let e = h.err(&who, "relay_manage", json!({ "action": action, "params": params })).await;
            assert_eq!(reason(&e), "org_unsupported", "{action}: {e:?}");
        }
    }
    // The default organization's caller passes the check and fails later,
    // for the ordinary reason (no secret stored, no such draft).
    if cfg!(feature = "mcp-gateway") {
        let e =
            h.err(&dev(agent(DEFAULT_ORG)), "mcp_gateway", json!({ "server": "docs", "tool": "echo" })).await;
        assert_eq!(reason(&e), "secret_unavailable", "{e:?}");
    }
    let e = h
        .err(
            &coord(agent(DEFAULT_ORG)),
            "relay_manage",
            json!({ "action": "request_send", "params": { "draft_id": 1 } }),
        )
        .await;
    assert_eq!(e.code(), "not_found", "{e:?}");
    assert!(h.rows().is_empty());
    assert!(h.events() >= events);
}

/// A stdio MCP server is a process the hub spawns on its own host, the
/// default organization's: another organization's caller is refused its
/// `call` and live `list` even when it injects no secret, before anything is
/// spawned. A static `list` reads nothing and is not refused.
#[tokio::test]
async fn a_stdio_mcp_server_refuses_another_organizations_caller_without_secrets() {
    if !cfg!(feature = "mcp-gateway") {
        return;
    }
    let h = H::with(|c| {
        c.mcp_servers.insert(
            "local-docs".into(),
            json!({
                "transport": "stdio",
                "command": "/nonexistent/fake-mcp-server-not-real",
                "tools": { "echo": "read" },
                "read_profiles": ["developer", "operator"],
                "review_expires_at": "2099-01-01",
            }),
        );
    });
    let dev = |c: Caller| Caller { profile: Profile::Developer, ..c };
    for who in [agent(ORG_B), human(ORG_B)] {
        let gw = dev(who);
        for args in [
            json!({ "server": "local-docs", "tool": "echo" }),
            json!({ "action": "list", "server": "local-docs", "live": true }),
        ] {
            let e = h.err(&gw, "mcp_gateway", args.clone()).await;
            assert_eq!(reason(&e), "org_unsupported", "{args}: {e:?}");
            assert!(e.to_string().contains("process on the hub"), "{e:?}");
        }
        h.ok(&gw, "mcp_gateway", json!({ "action": "list", "server": "local-docs" })).await;
    }
    // The default organization's caller passes the check and fails later,
    // trying to start the (nonexistent) command.
    let e = h
        .err(&dev(agent(DEFAULT_ORG)), "mcp_gateway", json!({ "server": "local-docs", "tool": "echo" }))
        .await;
    assert_ne!(reason(&e), "org_unsupported", "{e:?}");
}

#[test]
fn a_legacy_row_with_a_null_name_stops_the_upgrade_with_its_row_id() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = cfg(dir.path());
    let insert = |name: Option<&str>| {
        format!(
            "INSERT INTO managed_secrets (name, consumer, key_id, nonce, ciphertext, fingerprint, value_bytes, \
             created_by, created_at, updated_by, updated_at) VALUES ({}, 'mcp:docs', 'k1', x'00', x'00', 'fp', 1, \
             'operator', 'now', 'operator', 'now')",
            name.map(|n| format!("'{n}'")).unwrap_or_else(|| "NULL".into())
        )
    };
    {
        let db = ua_store::Db::open(&cfg.db_path(), &old_parts()).unwrap();
        db.write(|tx| {
            tx.execute_batch(&insert(Some("docs-token")))?;
            tx.execute_batch(&insert(None))?;
            Ok(())
        })
        .unwrap();
    }
    let e = Hub::open(cfg.clone()).err().expect("the upgrade stops");
    let msg = format!("{e:#}");
    assert!(msg.contains("1 row(s) with a NULL name (rowid 2)"), "{msg}");
    assert!(msg.contains("DELETE FROM managed_secrets WHERE name IS NULL"), "{msg}");

    // Nothing changed: both rows are there, under the v1 shape.
    let conn = rusqlite::Connection::open(cfg.db_path()).unwrap();
    let n: i64 = conn.query_row("SELECT count(*) FROM managed_secrets", [], |r| r.get(0)).unwrap();
    assert_eq!(n, 2);
    let has_org: i64 = conn
        .query_row(
            "SELECT count(*) FROM pragma_table_info('managed_secrets') WHERE name = 'org_id'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(has_org, 0);

    // After the operator removes it, the upgrade runs.
    conn.execute("DELETE FROM managed_secrets WHERE name IS NULL", []).unwrap();
    drop(conn);
    let hub = Hub::open(cfg).unwrap();
    let rows: i64 = hub
        .db()
        .read(|c| {
            Ok(c.query_row("SELECT count(*) FROM managed_secrets WHERE org_id = 'default'", [], |r| {
                r.get(0)
            })?)
        })
        .unwrap();
    assert_eq!(rows, 1);
}
