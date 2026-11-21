//! The memory family, exercised through the governed registry.

use std::sync::Arc;

use serde_json::{Value, json};
use ua_core::{ActorKind, Caller, Config, Profile, identity::Transport};
use ua_tools::families::memory::{EmbedError, Embedder, register_embedder};
use ua_tools::{Hub, Registry, builtin_registry};

fn hub_with_model(model: &str) -> Hub {
    let mut cfg = Config::for_home(std::env::temp_dir());
    cfg.human_identities = vec!["operator".into()];
    cfg.embed_model = model.into();
    Hub::in_memory(cfg).unwrap()
}

/// A hub whose model has no registered embedder: lexical search only
/// (without the `embeddings` feature every unregistered model is a no-op).
fn hub() -> Hub {
    hub_with_model("lexical-only-test-model")
}

fn agent(label: &str) -> Caller {
    Caller {
        label: label.into(),
        kind: ActorKind::Agent,
        profile: Profile::Developer,
        enforce_profile: true,
        session_key: Some("s1".into()),
        transport: Transport::Mcp,
        org_id: ua_core::DEFAULT_ORG.into(),
    }
}

fn human() -> Caller {
    Caller { kind: ActorKind::Human, profile: Profile::Coordinator, ..agent("operator") }
}

fn anon() -> Caller {
    Caller::local("local-ide", Transport::Stdio)
}

struct T {
    hub: Hub,
    reg: Registry,
}

impl T {
    fn new(hub: Hub) -> Self {
        Self { hub, reg: builtin_registry() }
    }

    async fn ok(&self, who: &Caller, tool: &str, args: Value) -> Value {
        match self.reg.call(&self.hub, who, tool, args.clone()).await {
            Ok(v) => v,
            Err(e) => panic!("{tool}({args}) failed: {e}"),
        }
    }

    async fn err(&self, who: &Caller, tool: &str, args: Value) -> ua_core::UaError {
        match self.reg.call(&self.hub, who, tool, args.clone()).await {
            Ok(v) => panic!("{tool}({args}) should fail, got {v}"),
            Err(e) => e,
        }
    }

    async fn save(&self, who: &Caller, args: Value) -> String {
        self.ok(who, "memory_save", args).await["id"].as_str().unwrap().to_string()
    }

    async fn search_ids(&self, who: &Caller, args: Value) -> Vec<String> {
        let r = self.ok(who, "memory_search", args).await;
        r["results"].as_array().unwrap().iter().map(|h| h["id"].as_str().unwrap().to_string()).collect()
    }

    async fn list_ids(&self, args: Value) -> Vec<String> {
        let r = self.ok(&anon(), "memory_list", args).await;
        r["items"].as_array().unwrap().iter().map(|h| h["id"].as_str().unwrap().to_string()).collect()
    }

    async fn events(&self, channel: &str) -> usize {
        let r = self.ok(&human(), "event_log_query", json!({ "channels": [channel] })).await;
        r["count"].as_u64().unwrap() as usize
    }
}

#[tokio::test]
async fn save_append_overwrite_and_version_history() {
    let t = T::new(hub());
    let b1 = agent("builder-1");
    let b2 = agent("builder-2");

    let created = t
        .ok(
            &b1,
            "memory_save",
            json!({ "content": "Use uv for this repo.", "title": "Package manager", "tags": ["pref"] }),
        )
        .await;
    assert_eq!(created["created"], true);
    assert!(created["revision"].as_str().unwrap().starts_with("sha256:"));
    let id = created["id"].as_str().unwrap().to_string();
    assert_eq!(id.len(), 12);

    // A verified caller cannot claim another author.
    let e = t.err(&b1, "memory_save", json!({ "content": "x", "author": "builder-2" })).await;
    assert_eq!(e.code(), "denied");

    // Replacing a peer's note is refused; appending is allowed.
    let e = t.err(&b2, "memory_save", json!({ "id": id, "content": "Use pip." })).await;
    assert_eq!(e.code(), "denied");
    t.ok(&b2, "memory_save", json!({ "id": id, "content": "Also pin the version.", "append": true })).await;
    let got = t.ok(&b1, "memory_get", json!({ "id": id })).await;
    let content = got["content"].as_str().unwrap();
    assert!(content.starts_with("Use uv for this repo."), "{content}");
    assert!(content.contains("*[builder-2 · ") && content.ends_with("Also pin the version."), "{content}");
    // Omitted title and tags are kept on update.
    assert_eq!(got["title"], "Package manager");
    assert_eq!(got["tags"], json!(["pref"]));
    assert_eq!(got["author"], "builder-1");
    assert_eq!(got["updated_by"], "builder-2");

    // Compare-and-set: a stale revision is a conflict and writes nothing.
    let stale = created["revision"].as_str().unwrap();
    let e =
        t.err(&b1, "memory_save", json!({ "id": id, "content": "stale", "expected_revision": stale })).await;
    assert_eq!(e.code(), "conflict");
    let fresh = got["revision"].as_str().unwrap();
    t.ok(
        &b1,
        "memory_save",
        json!({ "id": id, "content": "Use uv; pin it.", "expected_revision": fresh, "tags": [] }),
    )
    .await;

    // overwrite=True replaces a peer's note but keeps the old text as a tombstone.
    t.ok(&b2, "memory_save", json!({ "id": id, "content": "Use uv 0.9.", "overwrite": true })).await;
    let got = t.ok(&b1, "memory_get", json!({ "id": id, "include_versions": true })).await;
    let content = got["content"].as_str().unwrap();
    assert!(content.starts_with("Use uv 0.9."));
    assert!(content.contains("tombstone · content by builder-1 overwritten by builder-2"), "{content}");
    assert!(content.contains("Use uv; pin it."));
    assert_eq!(got["tags"], json!([]));

    // Every content or tag change is a version, newest first.
    assert_eq!(got["versions_total"], 3);
    let v = got["versions"].as_array().unwrap();
    assert_eq!(v[0]["version"], 3);
    assert!(v[0]["content"].as_str().unwrap().starts_with("Use uv; pin it."));
    assert_eq!(v[2]["content"], "Use uv for this repo.");
    assert_eq!(v[2]["tags"], json!(["pref"]));
    assert_eq!(v[2]["actor"], "builder-1");
    assert_eq!(v[1]["actor"], "builder-2");

    // Argument errors.
    for bad in [
        json!({ "content": "  " }),
        json!({ "content": "x", "append": true }),
        json!({ "id": id, "content": "x", "append": true, "overwrite": true }),
        json!({ "content": "x", "expires_at": "not a date" }),
        json!({ "content": "x", "epistemic": "inferred" }),
        json!({ "content": "x", "evidence": ["nonsense"] }),
        json!({ "id": id, "content": "x", "expected_revision": "abc" }),
    ] {
        assert_eq!(t.err(&b1, "memory_save", bad.clone()).await.code(), "invalid_argument", "{bad}");
    }
    assert_eq!(t.err(&b1, "memory_save", json!({ "id": "nope", "content": "x" })).await.code(), "not_found");

    assert_eq!(t.events("agent.memory.saved").await, 4);
}

#[tokio::test]
async fn idempotent_save_replays_the_receipt() {
    let t = T::new(hub());
    let b1 = agent("builder-1");
    let a = t.ok(&b1, "memory_save", json!({ "content": "once", "idempotency_key": "k-1" })).await;
    let b = t.ok(&b1, "memory_save", json!({ "content": "once", "idempotency_key": "k-1" })).await;
    assert_eq!(a["id"], b["id"]);
    assert_eq!(t.list_ids(json!({})).await.len(), 1);
}

#[tokio::test]
async fn search_ranks_lexically_and_filters() {
    let t = T::new(hub());
    let b1 = agent("builder-1");
    let b2 = agent("builder-2");
    let runbook = t
        .save(
            &b1,
            json!({
                "title": "Deploy runbook",
                "content": "How we deploy the hub: build, test, deploy, verify health.",
                "tags": ["ops", "project:hub"],
            }),
        )
        .await;
    let passing = t
        .save(&b2, json!({ "title": "Coffee", "content": "The kettle broke after the deploy party.", "tags": ["misc"] }))
        .await;
    let unrelated =
        t.save(&b1, json!({ "title": "Fonts", "content": "Prefer a monospace font in terminals." })).await;

    let r = t.ok(&b1, "memory_search", json!({ "query": "deploy" })).await;
    let ids: Vec<&str> = r["results"].as_array().unwrap().iter().map(|h| h["id"].as_str().unwrap()).collect();
    assert_eq!(ids, vec![runbook.as_str(), passing.as_str()]);
    let top = &r["results"][0];
    assert_eq!(top["explanation"]["lexical_mode"], "and");
    assert_eq!(top["explanation"]["ranks"]["lexical"], 1);
    assert_eq!(top["explanation"]["why"][0], "lexical");
    assert_eq!(top["trust"]["level"], "untrusted");
    assert!(top["combined_score"].as_f64().unwrap() > r["results"][1]["combined_score"].as_f64().unwrap());
    assert!(top["snippet"].as_str().unwrap().contains("[deploy]"), "{}", top["snippet"]);
    assert_eq!(r["retrieval"]["mode"], "lexical_fallback");
    assert_eq!(r["retrieval"]["semantic"]["status"], "unavailable");
    assert_eq!(r["retrieval"]["lexical"]["matched_count"], 2);
    // Hits count as accesses.
    assert_eq!(top["access_count"], 1);

    // Stemming: inflections match.
    assert!(t.search_ids(&b1, json!({ "query": "deploying" })).await.contains(&runbook));
    assert!(t.search_ids(&b1, json!({ "query": "terminal" })).await.contains(&unrelated));
    // Tags are indexed too.
    assert_eq!(t.search_ids(&b1, json!({ "query": "ops" })).await, vec![runbook.clone()]);
    // AND finds nothing, so the OR fallback (stopwords dropped) runs.
    let r = t.ok(&b1, "memory_search", json!({ "query": "the monospace zebra" })).await;
    assert_eq!(r["results"][0]["id"], unrelated.as_str());
    assert_eq!(r["results"][0]["explanation"]["lexical_mode"], "or");

    // Filters apply before the cap.
    assert_eq!(
        t.search_ids(&b1, json!({ "query": "deploy", "tags": ["misc"] })).await,
        vec![passing.clone()]
    );
    assert_eq!(
        t.search_ids(&b1, json!({ "query": "deploy", "tags": ["ops", "project:hub"] })).await,
        vec![runbook.clone()]
    );
    assert_eq!(
        t.search_ids(&b1, json!({ "query": "deploy", "author": "builder-2" })).await,
        vec![passing.clone()]
    );
    assert_eq!(t.search_ids(&b1, json!({ "query": "deploy", "limit": 1 })).await, vec![runbook.clone()]);
    assert!(t.search_ids(&b1, json!({ "query": "deploy", "source_host": "no-such-host" })).await.is_empty());
    assert_eq!(
        t.search_ids(&b1, json!({ "query": "fonts", "tags": ["untagged"] })).await,
        vec![unrelated.clone()]
    );

    // Operators in the query are neutralised, not errors.
    t.ok(&b1, "memory_search", json!({ "query": "deploy OR NOT ( *" })).await;
    assert_eq!(t.err(&b1, "memory_search", json!({ "query": " \" " })).await.code(), "invalid_argument");

    // memory_list: newest first, filtered.
    assert_eq!(t.list_ids(json!({})).await, vec![unrelated.clone(), passing.clone(), runbook.clone()]);
    assert_eq!(t.list_ids(json!({ "tag": "ops" })).await, vec![runbook.clone()]);
    assert_eq!(t.list_ids(json!({ "author": "builder-1", "limit": 1 })).await, vec![unrelated.clone()]);
}

#[tokio::test]
async fn expiry_and_supersede_hide_notes_by_default() {
    let t = T::new(hub());
    let b1 = agent("builder-1");
    let expired = t
        .save(&b1, json!({ "content": "The staging token rotates weekly.", "expires_at": "2020-01-01" }))
        .await;
    assert!(t.search_ids(&b1, json!({ "query": "staging" })).await.is_empty());
    assert!(t.list_ids(json!({})).await.is_empty());
    assert_eq!(
        t.search_ids(&b1, json!({ "query": "staging", "include_expired": true })).await,
        vec![expired.clone()]
    );
    assert_eq!(t.list_ids(json!({ "include_expired": true })).await, vec![expired.clone()]);
    let got = t.ok(&b1, "memory_get", json!({ "id": expired })).await;
    assert_eq!(got["expires_at"], "2020-01-01T00:00:00+00:00");
    // Clearing the expiry brings it back.
    t.ok(
        &b1,
        "memory_save",
        json!({ "id": expired, "content": "The staging token rotates weekly.", "clear_expires_at": true }),
    )
    .await;
    assert_eq!(t.search_ids(&b1, json!({ "query": "staging" })).await, vec![expired.clone()]);

    // Supersede: the old note leaves search and listing but stays readable.
    let old = t.save(&b1, json!({ "content": "The release branch is called stable." })).await;
    let old_created =
        t.ok(&b1, "memory_get", json!({ "id": old, "count_access": false })).await["created_at"]
            .as_str()
            .unwrap()
            .to_string();
    let new = t
        .ok(
            &b1,
            "memory_save",
            json!({ "content": "The release branch is called release.", "supersedes": old }),
        )
        .await;
    assert_eq!(new["supersedes"], old.as_str());
    let new = new["id"].as_str().unwrap().to_string();
    assert_eq!(t.search_ids(&b1, json!({ "query": "release branch" })).await, vec![new.clone()]);
    assert!(!t.list_ids(json!({})).await.contains(&old));
    let got = t.ok(&b1, "memory_get", json!({ "id": old })).await;
    assert_eq!(got["superseded_by"], new.as_str());
    assert!(got["valid_to"].is_string());
    let got_new = t.ok(&b1, "memory_get", json!({ "id": new })).await;
    assert_eq!(got_new["supersedes"], json!([old]));
    assert_eq!(got_new["links"]["out"][0]["rel"], "supersedes");

    // Historical search: at the old note's creation it was the valid one.
    let hist = t.search_ids(&b1, json!({ "query": "release branch", "as_of": old_created })).await;
    assert!(hist.contains(&old), "{hist:?}");
    t.ok(&b1, "memory_get", json!({ "id": old, "as_of": old_created })).await;
    let e = t.err(&b1, "memory_get", json!({ "id": old, "as_of": "2000-01-01T00:00:00+00:00" })).await;
    assert!(e.to_string().contains("was not valid at"), "{e}");
    // as_of needs an offset.
    let e = t.err(&b1, "memory_search", json!({ "query": "release", "as_of": "2026-01-01T00:00:00" })).await;
    assert_eq!(e.code(), "invalid_argument");

    // A note can be superseded only once; restore re-promotes it.
    let e = t.err(&b1, "memory_save", json!({ "content": "again", "supersedes": old })).await;
    assert!(e.to_string().contains("already superseded"), "{e}");
    let r = t.ok(&b1, "memory_restore", json!({ "id": old })).await;
    assert_eq!(r["was_superseded_by"], new.as_str());
    assert!(t.search_ids(&b1, json!({ "query": "stable" })).await.contains(&old));

    // Superseding another author's note needs overwrite.
    let peer = t.save(&agent("builder-2"), json!({ "content": "peer note" })).await;
    let e = t.err(&b1, "memory_save", json!({ "content": "mine", "supersedes": peer })).await;
    assert_eq!(e.code(), "denied");
    assert_eq!(t.events("agent.memory.superseded").await, 1);
}

#[tokio::test]
async fn feedback_counters_and_ranking() {
    let t = T::new(hub());
    let b1 = agent("builder-1");
    let a = t.save(&b1, json!({ "title": "Same", "content": "Rotate the signing key yearly." })).await;
    let b = t.save(&b1, json!({ "title": "Same", "content": "Rotate the signing key yearly." })).await;

    let r = t.ok(&b1, "memory_feedback", json!({ "id": b, "signal": "helpful" })).await;
    assert_eq!(r["feedback_helpful"], 1);
    assert_eq!(r["confidence_posterior"]["alpha"], 2.0);
    t.ok(&b1, "memory_feedback", json!({ "id": a, "signal": "Wrong" })).await;
    let r = t.ok(&b1, "memory_feedback", json!({ "id": a, "signal": "stale" })).await;
    assert_eq!(r["feedback_wrong"], 1);
    assert_eq!(r["feedback_stale"], 1);
    assert_eq!(r["confidence_posterior"]["beta"], 3.5);
    assert_eq!(
        t.err(&b1, "memory_feedback", json!({ "id": a, "signal": "meh" })).await.code(),
        "invalid_argument"
    );
    assert_eq!(
        t.err(&b1, "memory_feedback", json!({ "id": "missing", "signal": "helpful" })).await.code(),
        "not_found"
    );

    // Identical text: the note with better feedback ranks first.
    let r = t.ok(&b1, "memory_search", json!({ "query": "signing key" })).await;
    assert_eq!(r["results"][0]["id"], b.as_str());
    assert_eq!(r["results"][1]["id"], a.as_str());
    let p0 = r["results"][0]["explanation"]["prior"].as_f64().unwrap();
    let p1 = r["results"][1]["explanation"]["prior"].as_f64().unwrap();
    assert!(p0 > 1.0 && p1 < 1.0, "{p0} {p1}");

    // Feedback is not an edit.
    let got = t.ok(&b1, "memory_get", json!({ "id": a, "count_access": false })).await;
    assert_eq!(got["updated_by"], "builder-1");
    let before = got["access_count"].as_i64().unwrap();
    let got = t.ok(&b1, "memory_get", json!({ "id": a, "count_access": false })).await;
    assert_eq!(got["access_count"].as_i64().unwrap(), before);
    let got = t.ok(&b1, "memory_get", json!({ "id": a })).await;
    assert_eq!(got["access_count"].as_i64().unwrap(), before + 1);

    // An open contradiction lowers effective confidence.
    t.save(&b1, json!({ "content": "Rotate it monthly.", "contradicts": [b] })).await;
    let got = t.ok(&b1, "memory_get", json!({ "id": b })).await;
    assert_eq!(got["confidence_posterior"]["open_contradictions"], 1);
    assert_eq!(got["links"]["in"][0]["rel"], "contradicts");
    assert_eq!(t.events("agent.memory.feedback").await, 3);
}

#[tokio::test]
async fn human_only_guards() {
    let t = T::new(hub());
    let b1 = agent("builder-1");
    let op = human();

    let e = t.err(&b1, "memory_save", json!({ "content": "all hands", "tags": ["Broadcast "] })).await;
    assert_eq!(e.code(), "denied");
    let e = t.err(&b1, "memory_save", json!({ "content": "urgent", "salience": 0.9 })).await;
    assert_eq!(e.code(), "denied");
    // The claimed author is not authority when there is no verified identity.
    let e = t
        .err(&anon(), "memory_save", json!({ "content": "x", "tags": ["broadcast"], "author": "operator" }))
        .await;
    assert_eq!(e.code(), "denied");
    t.ok(&b1, "memory_save", json!({ "content": "fine", "salience": 0.8 })).await;

    let bc = t
        .save(&op, json!({ "content": "Freeze merges today.", "tags": ["broadcast"], "salience": 1.0 }))
        .await;
    // An update that keeps the broadcast tag stays human-only, even when appending.
    let e = t.err(&b1, "memory_save", json!({ "id": bc, "content": "ack", "append": true })).await;
    assert_eq!(e.code(), "denied");
    t.ok(&op, "memory_save", json!({ "id": bc, "content": "Lifted.", "append": true })).await;
    // Superseding a broadcast note is human-only too.
    let e = t.err(&b1, "memory_save", json!({ "content": "x", "supersedes": bc, "overwrite": true })).await;
    assert_eq!(e.code(), "denied");
}

#[tokio::test]
async fn delete_and_restore() {
    let t = T::new(hub());
    let b1 = agent("builder-1");
    let b2 = agent("builder-2");
    let id = t.save(&b1, json!({ "content": "Cache TTL is 300 seconds.", "tags": ["perf"] })).await;

    assert_eq!(t.err(&anon(), "memory_delete", json!({ "id": id })).await.code(), "denied");
    assert_eq!(t.err(&b2, "memory_delete", json!({ "id": id })).await.code(), "denied");
    assert_eq!(t.ok(&b1, "memory_delete", json!({ "id": id })).await["deleted"], true);
    assert_eq!(t.ok(&b1, "memory_delete", json!({ "id": id })).await["deleted"], false);
    assert_eq!(t.ok(&b1, "memory_delete", json!({ "id": "missing" })).await["deleted"], false);

    assert!(t.search_ids(&b1, json!({ "query": "cache" })).await.is_empty());
    assert!(t.list_ids(json!({})).await.is_empty());
    let got = t.ok(&b1, "memory_get", json!({ "id": id })).await;
    assert_eq!(got["deleted"], true);
    assert!(got["content"].as_str().unwrap().contains("Cache TTL is 300 seconds."));
    let e = t.err(&b1, "memory_save", json!({ "id": id, "content": "revive" })).await;
    assert!(e.to_string().contains("is deleted"), "{e}");

    assert_eq!(t.err(&b2, "memory_restore", json!({ "id": id })).await.code(), "denied");
    let r = t.ok(&b1, "memory_restore", json!({ "id": id })).await;
    assert_eq!(r["was_deleted"], true);
    assert_eq!(r["restored_version"], 1);
    let got = t.ok(&b1, "memory_get", json!({ "id": id })).await;
    assert_eq!(got["content"], "Cache TTL is 300 seconds.");
    assert_eq!(got["tags"], json!(["perf"]));
    assert_eq!(t.search_ids(&b1, json!({ "query": "cache" })).await, vec![id.clone()]);

    // A note a human deleted needs a human to restore it.
    t.ok(&human(), "memory_delete", json!({ "id": id })).await;
    assert_eq!(t.err(&b1, "memory_restore", json!({ "id": id })).await.code(), "denied");
    t.ok(&human(), "memory_restore", json!({ "id": id })).await;
    assert_eq!(t.events("agent.memory.deleted").await, 2);
    assert_eq!(t.events("agent.memory.restored").await, 2);
}

#[tokio::test]
async fn prune_candidates_and_recall_maintenance_only_report() {
    let t = T::new(hub());
    let b1 = agent("builder-1");
    let low = t.save(&b1, json!({ "content": "minor detail", "salience": 0.1, "confidence": 0.2 })).await;
    let ok = t.save(&b1, json!({ "content": "important", "salience": 0.7, "confidence": 0.9 })).await;

    let r = t.ok(&b1, "memory_prune_candidates", json!({})).await;
    assert_eq!(r["candidate_count"], 1);
    assert_eq!(r["candidates"][0]["id"], low.as_str());
    assert_eq!(r["candidates"][0]["reasons"], json!(["low_salience"]));
    // A negative age puts the cutoff in the future: every unaccessed note
    // with salience <= 0.5 counts as decayed.
    let r = t.ok(&b1, "memory_prune_candidates", json!({ "max_age_days": -1 })).await;
    assert_eq!(r["candidates"][0]["reasons"], json!(["low_salience", "decayed_unused"]));

    let r = t.ok(&b1, "recall_maintenance", json!({})).await;
    assert_eq!(r["deletes_nothing"], true);
    assert_eq!(r["low_confidence_count"], 1);
    assert_eq!(r["low_confidence"][0]["id"], low.as_str());
    let r = t.ok(&b1, "recall_maintenance", json!({ "stale_days": -1 })).await;
    assert_eq!(r["stale_count"], 1);
    let e = t.err(&b1, "recall_maintenance", json!({ "dry_run": false })).await;
    assert_eq!(e.code(), "invalid_argument");
    assert_eq!(t.list_ids(json!({})).await.len(), 2, "{ok}");
}

#[tokio::test]
async fn unknown_arguments_are_refused() {
    let t = T::new(hub());
    let b1 = agent("builder-1");
    for (tool, args) in [
        ("memory_save", json!({ "content": "x", "bogus": 1 })),
        ("memory_save", json!({ "content": "x", "links": ["extends:abc"] })),
        ("memory_search", json!({ "query": "x", "bogus": 1 })),
        ("memory_list", json!({ "bogus": 1 })),
        ("memory_get", json!({ "id": "x", "bogus": 1 })),
        ("memory_delete", json!({ "id": "x", "bogus": 1 })),
        ("memory_restore", json!({ "id": "x", "bogus": 1 })),
        ("memory_feedback", json!({ "id": "x", "signal": "helpful", "bogus": 1 })),
        ("memory_prune_candidates", json!({ "bogus": 1 })),
        ("recall_maintenance", json!({ "bogus": 1 })),
    ] {
        assert_eq!(t.err(&b1, tool, args.clone()).await.code(), "invalid_argument", "{tool} {args}");
    }
}

#[tokio::test]
async fn read_only_profiles_see_only_reads() {
    let t = T::new(hub());
    let viewer = Caller { profile: Profile::Operator, ..agent("viewer-1") };
    let e = t.err(&viewer, "memory_save", json!({ "content": "x" })).await;
    assert_eq!(e.code(), "denied");
    t.ok(&viewer, "memory_list", json!({})).await;
}

/// A deterministic test embedder: each word maps to a concept dimension, so
/// synonyms land on the same axis.
struct ConceptEmbedder;

const CONCEPTS: &[&[&str]] = &[
    &["car", "automobile", "vehicle"],
    &["database", "sqlite", "postgres"],
    &["fruit", "apple", "banana"],
    &["garage", "parking"],
];

impl Embedder for ConceptEmbedder {
    fn model(&self) -> &str {
        "test-concepts"
    }

    fn embed(&self, texts: &[String]) -> Result<Vec<Vec<f32>>, EmbedError> {
        Ok(texts
            .iter()
            .map(|text| {
                let mut v = vec![0f32; CONCEPTS.len() + 1];
                for w in text.to_lowercase().split(|c: char| !c.is_alphanumeric()).filter(|w| !w.is_empty()) {
                    match CONCEPTS.iter().position(|c| c.contains(&w)) {
                        Some(i) => v[i] += 1.0,
                        None => v[CONCEPTS.len()] += 0.05,
                    }
                }
                v
            })
            .collect())
    }
}

#[tokio::test]
async fn hybrid_search_with_an_embedder() {
    register_embedder(Arc::new(ConceptEmbedder));
    let t = T::new(hub_with_model("test-concepts"));
    let b1 = agent("builder-1");
    let car = t.save(&b1, json!({ "title": "Car", "content": "The car lives in the garage." })).await;
    t.save(&b1, json!({ "title": "Fruit", "content": "Buy an apple and a banana." })).await;

    // No lexical match: the semantic leg alone finds the note.
    let r = t.ok(&b1, "memory_search", json!({ "query": "automobile" })).await;
    assert_eq!(r["retrieval"]["mode"], "hybrid");
    assert_eq!(r["retrieval"]["semantic"]["status"], "available");
    assert_eq!(r["retrieval"]["lexical"]["matched_count"], 0);
    assert_eq!(r["results"].as_array().unwrap().len(), 1);
    assert_eq!(r["results"][0]["id"], car.as_str());
    assert_eq!(r["results"][0]["explanation"]["why"][0], "semantic");
    assert!(r["results"][0]["similarity"].as_f64().unwrap() > 0.65);

    // check_only reports near-duplicates and writes nothing.
    let before = t.list_ids(json!({})).await.len();
    let r = t.ok(&b1, "memory_save", json!({ "content": "A car in the garage.", "check_only": true })).await;
    let similar = r["similar"].as_array().unwrap();
    assert!(similar.iter().any(|s| s["id"] == car.as_str()), "{r}");
    assert_eq!(t.list_ids(json!({})).await.len(), before);

    // An update re-embeds the note: now it is about a database.
    t.ok(
        &b1,
        "memory_save",
        json!({ "id": car, "title": "Storage", "content": "The sqlite database file." }),
    )
    .await;
    let r = t.ok(&b1, "memory_search", json!({ "query": "postgres" })).await;
    assert_eq!(r["results"][0]["id"], car.as_str());
}

/// `memory_search` and `memory_get` are registered read-only: the only write
/// is the best-effort access telemetry, which moves neither the note's
/// revision nor the ledger. The graph leg says it is disabled, and why.
#[tokio::test]
async fn search_and_get_are_reads_with_access_telemetry_only() {
    let t = T::new(hub());
    for name in ["memory_search", "memory_get", "memory_list"] {
        assert!(t.reg.get(name).unwrap().read_only, "{name} is read-only");
    }
    let b1 = agent("builder-1");
    let id =
        t.save(&b1, json!({ "title": "Cache rule", "content": "Keep the shared build cache warm." })).await;
    let first = t.ok(&b1, "memory_get", json!({ "id": id, "count_access": false })).await;
    let ledger = || async {
        let r = t.ok(&human(), "event_log_query", json!({ "channel_prefix": "agent.memory." })).await;
        r["count"].as_u64().unwrap()
    };
    let ledger_before = ledger().await;
    assert!(ledger_before > 0, "the save was ledgered");

    let r = t.ok(&b1, "memory_search", json!({ "query": "build cache" })).await;
    assert_eq!(r["results"][0]["id"], id.as_str());
    assert_eq!(r["retrieval"]["graph"]["status"], "disabled");
    assert!(r["retrieval"]["graph"]["reason"].as_str().unwrap().contains("vault_query"), "{r}");
    let counted = t.ok(&b1, "memory_get", json!({ "id": id })).await;

    // Two accesses counted, nothing else moved.
    assert_eq!(counted["access_count"].as_i64().unwrap(), first["access_count"].as_i64().unwrap() + 2);
    assert_eq!(counted["revision"], first["revision"]);
    assert_eq!(counted["updated_at"], first["updated_at"]);
    assert_eq!(ledger().await, ledger_before, "reads append no memory events");

    // A missing note is still an error, and counts nothing.
    assert_eq!(t.err(&b1, "memory_get", json!({ "id": "missing" })).await.code(), "not_found");
}
