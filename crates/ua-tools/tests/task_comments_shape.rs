//! Pinned JSON shape and two-organization isolation tests for the
//! `task_comments` pilot repository (`docs/store.md`).
//!
//! Pins the exact pre-migration `SELECT *` JSON keys and types for both
//! `task_comment` (`append`, `get`, `list`) and
//! `platform_object_get(kind = "comment")`, including their distinct handling
//! of malformed JSON stored in `mentions` / `refs`.

use std::collections::BTreeSet;

use serde_json::{Value, json};
use ua_core::{ActorKind, Caller, Config, DEFAULT_ORG, Profile, UaError, identity::Transport};
use ua_tools::{Hub, Registry, builtin_registry};

const ORG_B: &str = "org-b";

struct H {
    hub: Hub,
    reg: Registry,
}

impl H {
    fn new() -> Self {
        let mut cfg = Config::for_home(std::env::temp_dir());
        cfg.human_identities = vec!["operator".into()];
        let hub = Hub::in_memory(cfg).unwrap();
        hub.db()
            .write(|tx| {
                tx.execute(
                    "INSERT INTO orgs (id, slug, display_name, allowed_profiles, created_at) \
                     VALUES (?1, ?1, 'Org B', '[\"developer\",\"coordinator\"]', '2026-01-01T00:00:00+00:00')",
                    [ORG_B],
                )?;
                Ok(())
            })
            .unwrap();
        Self { hub, reg: builtin_registry() }
    }

    async fn ok(&self, who: &Caller, tool: &str, args: Value) -> Value {
        match self.reg.call(&self.hub, who, tool, args.clone()).await {
            Ok(v) => v,
            Err(e) => panic!("{tool}({args}) failed: {e}"),
        }
    }

    async fn err(&self, who: &Caller, tool: &str, args: Value) -> UaError {
        match self.reg.call(&self.hub, who, tool, args.clone()).await {
            Ok(v) => panic!("{tool}({args}) should fail, got {v}"),
            Err(e) => e,
        }
    }
}

fn agent(label: &str, org: &str) -> Caller {
    Caller {
        label: label.into(),
        kind: ActorKind::Agent,
        profile: Profile::Developer,
        enforce_profile: true,
        session_key: Some(format!("{label}-s")),
        transport: Transport::Mcp,
        org_id: org.into(),
    }
}

fn keys(v: &Value) -> BTreeSet<String> {
    v.as_object().unwrap().keys().cloned().collect()
}

#[tokio::test]
async fn pins_valid_and_invalid_json_shapes_for_task_comment_and_platform_object_get() {
    let h = H::new();
    let dev = agent("builder-1", DEFAULT_ORG);

    let task_id =
        h.ok(&dev, "task_add", json!({ "title": "Comment shape task" })).await["id"].as_i64().unwrap();

    // 1. Valid JSON mentions & refs via `task_comment(append)`.
    let appended = h
        .ok(
            &dev,
            "task_comment",
            json!({
                "action": "append",
                "params": {
                    "task_id": task_id,
                    "body": "first comment",
                    "mentions": ["reviewer-1", "coordinator-1"],
                    "refs": { "plan_id": "plan-7", "handoff_id": 42 },
                    "idempotency_key": "idem-1"
                }
            }),
        )
        .await;
    assert_eq!(appended["idempotent_replay"], json!(false));
    let comment_id = appended["comment"]["id"].as_i64().unwrap();

    let expected_task_comment_keys: BTreeSet<String> = [
        "id",
        "task_id",
        "parent_comment_id",
        "author",
        "body",
        "mentions",
        "refs",
        "idempotency_key",
        "thread_revision",
        "created_at",
        "participants",
    ]
    .into_iter()
    .map(String::from)
    .collect();

    let expected_platform_keys: BTreeSet<String> = [
        "id",
        "task_id",
        "parent_comment_id",
        "author",
        "body",
        "mentions",
        "refs",
        "idempotency_key",
        "thread_revision",
        "created_at",
    ]
    .into_iter()
    .map(String::from)
    .collect();

    // Verify `append`, `get`, and `list` emit the exact 11-key shape (no `org_id`, with `participants`).
    let got =
        h.ok(&dev, "task_comment", json!({ "action": "get", "params": { "comment_id": comment_id } })).await;
    let listed =
        h.ok(&dev, "task_comment", json!({ "action": "list", "params": { "task_id": task_id } })).await;
    assert_eq!(listed["revision"], json!(1));
    assert_eq!(listed["notes_are_spec"], json!(true));
    assert!(listed["updated_at"].is_string());

    for view in [&appended["comment"], &got["comment"], &listed["comments"][0]] {
        assert_eq!(keys(view), expected_task_comment_keys);
        assert!(view.get("org_id").is_none(), "org_id must never leak: {view}");
        assert_eq!(view["id"], json!(comment_id));
        assert_eq!(view["task_id"], json!(task_id));
        assert_eq!(view["parent_comment_id"], Value::Null);
        assert_eq!(view["author"], json!("builder-1"));
        assert_eq!(view["body"], json!("first comment"));
        assert_eq!(view["mentions"], json!(["reviewer-1", "coordinator-1"]));
        assert_eq!(view["refs"], json!({ "plan_id": "plan-7", "handoff_id": 42 }));
        assert_eq!(view["idempotency_key"], json!("idem-1"));
        assert_eq!(view["thread_revision"], json!(1));
        assert!(view["created_at"].is_string());
        assert_eq!(view["participants"], json!(["builder-1", "reviewer-1", "coordinator-1"]));
    }

    // Verify `platform_object_get(kind = "comment")` emits the exact 10-key shape (no `org_id`, no `participants`).
    let plat =
        h.ok(&dev, "platform_object_get", json!({ "kind": "comment", "id": comment_id.to_string() })).await;
    let plat_obj = &plat["comment"];
    assert_eq!(keys(plat_obj), expected_platform_keys);
    assert!(plat_obj.get("org_id").is_none());
    assert!(plat_obj.get("participants").is_none());
    assert_eq!(plat_obj["id"], json!(comment_id));
    assert_eq!(plat_obj["task_id"], json!(task_id));
    assert_eq!(plat_obj["parent_comment_id"], Value::Null);
    assert_eq!(plat_obj["author"], json!("builder-1"));
    assert_eq!(plat_obj["body"], json!("first comment"));
    assert_eq!(plat_obj["mentions"], json!(["reviewer-1", "coordinator-1"]));
    assert_eq!(plat_obj["refs"], json!({ "plan_id": "plan-7", "handoff_id": 42 }));
    assert_eq!(plat_obj["idempotency_key"], json!("idem-1"));
    assert_eq!(plat_obj["thread_revision"], json!(1));
    assert!(plat_obj["created_at"].is_string());

    // Non-integer id on `platform_object_get(kind = "comment")` returns NotFound cleanly.
    let bad_id = h.err(&dev, "platform_object_get", json!({ "kind": "comment", "id": "not-an-int" })).await;
    assert!(matches!(bad_id, UaError::NotFound(_)), "expected NotFound, got {bad_id:?}");

    // 2. Invalid JSON stored in `mentions` and `refs` (neither column has a json_valid CHECK):
    //    - `task_comment` falls back to `mentions: []`, `refs: {}`, `participants: [author]`
    //    - `platform_object_get(kind = "comment")` leaves the raw string untouched
    let malformed_id: i64 = h
        .hub
        .db()
        .write(|tx| {
            tx.execute(
                "INSERT INTO task_comments (org_id, task_id, parent_comment_id, author, body, mentions, refs, \
                 idempotency_key, thread_revision, created_at) \
                 VALUES (?1, ?2, ?3, 'builder-1', 'corrupt json row', '{not-json-mentions', '[not-json-refs', \
                 NULL, 2, '2026-01-01T00:00:05+00:00')",
                rusqlite::params![DEFAULT_ORG, task_id, comment_id],
            )?;
            Ok(tx.last_insert_rowid())
        })
        .unwrap();

    let tc_bad = h
        .ok(&dev, "task_comment", json!({ "action": "get", "params": { "comment_id": malformed_id } }))
        .await;
    assert_eq!(keys(&tc_bad["comment"]), expected_task_comment_keys);
    assert_eq!(tc_bad["comment"]["parent_comment_id"], json!(comment_id));
    assert_eq!(tc_bad["comment"]["mentions"], json!([]));
    assert_eq!(tc_bad["comment"]["refs"], json!({}));
    assert_eq!(tc_bad["comment"]["participants"], json!(["builder-1"]));

    let tc_list_bad =
        h.ok(&dev, "task_comment", json!({ "action": "list", "params": { "task_id": task_id } })).await;
    let listed_bad = &tc_list_bad["comments"][1];
    assert_eq!(listed_bad["id"], json!(malformed_id));
    assert_eq!(listed_bad["mentions"], json!([]));
    assert_eq!(listed_bad["refs"], json!({}));
    assert_eq!(listed_bad["participants"], json!(["builder-1"]));

    let plat_bad =
        h.ok(&dev, "platform_object_get", json!({ "kind": "comment", "id": malformed_id.to_string() })).await;
    assert_eq!(keys(&plat_bad["comment"]), expected_platform_keys);
    assert!(plat_bad["comment"].get("participants").is_none());
    assert_eq!(plat_bad["comment"]["parent_comment_id"], json!(comment_id));
    assert_eq!(plat_bad["comment"]["mentions"], json!("{not-json-mentions"));
    assert_eq!(plat_bad["comment"]["refs"], json!("[not-json-refs"));
}

#[tokio::test]
async fn task_comment_and_platform_comment_isolate_organizations() {
    let h = H::new();
    let dev_a = agent("builder-1", DEFAULT_ORG);
    let dev_b = agent("builder-1", ORG_B);

    let task_a = h.ok(&dev_a, "task_add", json!({ "title": "Org A task" })).await["id"].as_i64().unwrap();
    let task_b = h.ok(&dev_b, "task_add", json!({ "title": "Org B task" })).await["id"].as_i64().unwrap();

    let c_a = h
        .ok(
            &dev_a,
            "task_comment",
            json!({ "action": "append", "params": { "task_id": task_a, "body": "org-a secret", "idempotency_key": "k1" } }),
        )
        .await["comment"]["id"]
        .as_i64()
        .unwrap();
    let c_b = h
        .ok(
            &dev_b,
            "task_comment",
            json!({ "action": "append", "params": { "task_id": task_b, "body": "org-b secret", "idempotency_key": "k1" } }),
        )
        .await["comment"]["id"]
        .as_i64()
        .unwrap();

    // Cross-org `task_comment(get)` and `platform_object_get(kind = "comment")` return neutral NotFound.
    assert!(matches!(
        h.err(&dev_b, "task_comment", json!({ "action": "get", "params": { "comment_id": c_a } })).await,
        UaError::NotFound(_)
    ));
    assert!(matches!(
        h.err(&dev_a, "task_comment", json!({ "action": "get", "params": { "comment_id": c_b } })).await,
        UaError::NotFound(_)
    ));
    assert!(matches!(
        h.err(&dev_b, "platform_object_get", json!({ "kind": "comment", "id": c_a.to_string() })).await,
        UaError::NotFound(_)
    ));
    assert!(matches!(
        h.err(&dev_a, "platform_object_get", json!({ "kind": "comment", "id": c_b.to_string() })).await,
        UaError::NotFound(_)
    ));

    // Own-org `platform_object_get(kind = "comment")` succeeds in org B.
    let plat_b =
        h.ok(&dev_b, "platform_object_get", json!({ "kind": "comment", "id": c_b.to_string() })).await;
    assert_eq!(plat_b["comment"]["body"], json!("org-b secret"));
    assert!(plat_b["comment"].get("org_id").is_none());

    // Cross-org parent_comment_id is rejected on append.
    let err = h
        .err(
            &dev_b,
            "task_comment",
            json!({ "action": "append", "params": { "task_id": task_b, "body": "cross-parent", "parent_comment_id": c_a } }),
        )
        .await;
    assert!(matches!(err, UaError::InvalidArgument(_)), "expected InvalidArgument, got {err:?}");
}
