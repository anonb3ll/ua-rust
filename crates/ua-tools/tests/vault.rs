//! The vault family, exercised through the governed registry against a temp vault.

use std::path::PathBuf;

use serde_json::{Value, json};
use ua_core::{ActorKind, Caller, Config, Profile, UaError, identity::Transport};
use ua_tools::{Hub, Registry, builtin_registry};

fn agent(label: &str) -> Caller {
    Caller {
        label: label.into(),
        kind: ActorKind::Agent,
        profile: Profile::Developer,
        enforce_profile: true,
        session_key: Some("s1".into()),
        transport: Transport::Mcp,
    }
}

fn human() -> Caller {
    Caller { kind: ActorKind::Human, profile: Profile::ChiefOfStaff, ..agent("operator") }
}

fn anon() -> Caller {
    Caller::local("local-ide", Transport::Stdio)
}

struct T {
    hub: Hub,
    reg: Registry,
    root: PathBuf,
    _dir: tempfile::TempDir,
}

impl T {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let mut cfg = Config::for_home(std::env::temp_dir());
        cfg.human_identities = vec!["operator".into()];
        cfg.vault_path = Some(root.clone());
        Self { hub: Hub::in_memory(cfg).unwrap(), reg: builtin_registry(), root, _dir: dir }
    }

    fn put(&self, rel: &str, text: &str) -> PathBuf {
        let p = self.root.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, text).unwrap();
        p
    }

    fn get(&self, rel: &str) -> String {
        std::fs::read_to_string(self.root.join(rel)).unwrap()
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

    async fn events(&self, channel: &str) -> Vec<Value> {
        let r = self.ok(&human(), "event_log_query", json!({ "channels": [channel] })).await;
        r["events"].as_array().unwrap().clone()
    }
}

fn reason(e: &UaError) -> String {
    match e {
        UaError::Denied { reason_code, .. } => reason_code.clone(),
        other => other.code().to_string(),
    }
}

#[tokio::test]
async fn unconfigured_vault_is_refused() {
    let hub = Hub::in_memory(Config::for_home(std::env::temp_dir())).unwrap();
    let reg = builtin_registry();
    for (tool, args) in [
        ("vault_read", json!({"path": "a.md"})),
        ("vault_write", json!({"path": "Wiki/a.md", "content": "x"})),
        ("vault_journal", json!({"entry": "x", "agent": "a"})),
        ("vault_query", json!({"query": "x"})),
    ] {
        let e = reg.call(&hub, &agent("builder-1"), tool, args).await.unwrap_err();
        assert_eq!(reason(&e), "vault_not_configured", "{tool}");
    }
    // The Obsidian client reports itself unconfigured without failing.
    let s = reg.call(&hub, &agent("builder-1"), "obsidian_status", json!({})).await.unwrap();
    assert_eq!(s["configured"], false);
    assert_eq!(s["missing"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn read_write_modes_and_paging() {
    let t = T::new();
    let a = agent("builder-1");
    let w = t.ok(&a, "vault_write", json!({"path": "Wiki/Note.md", "content": "one\ntwo\n"})).await;
    assert_eq!(w["mode"], "overwrite");
    assert_eq!(w["total_lines_after"], 2);
    assert!(w["revision"].as_str().unwrap().starts_with("sha256:"));

    let w = t
        .ok(&a, "vault_write", json!({"path": "Wiki/Note.md", "content": "three\n", "mode": "append"}))
        .await;
    assert_eq!(w["append"], true);
    assert_eq!(w["total_lines_after"], 3);
    // The legacy append flag reports the effective mode.
    let w =
        t.ok(&a, "vault_write", json!({"path": "Wiki/Note.md", "content": "four\n", "append": true})).await;
    assert_eq!(w["mode"], "append");
    assert_eq!(t.get("Wiki/Note.md"), "one\ntwo\nthree\nfour\n");

    let e = t.err(&a, "vault_write", json!({"path": "Wiki/Note.md", "content": "x", "mode": "create"})).await;
    assert_eq!(e.code(), "conflict");
    let w =
        t.ok(&a, "vault_write", json!({"path": "Wiki/New/Deep.md", "content": "x", "mode": "create"})).await;
    assert_eq!(w["path"], "Wiki/New/Deep.md");
    let e = t.err(&a, "vault_write", json!({"path": "Wiki/Note.md", "content": "x", "mode": "patch"})).await;
    assert_eq!(e.code(), "invalid_argument");

    let r = t.ok(&a, "vault_read", json!({"path": "Wiki/Note.md", "offset": 1, "limit": 2})).await;
    assert_eq!(r["content"], "two\nthree");
    assert_eq!(r["total_lines"], 4);
    assert_eq!(r["truncated"], true);
    assert_eq!(r["locked"], false);
    let e = t.err(&a, "vault_read", json!({"path": "Wiki/Missing.md"})).await;
    assert_eq!(e.code(), "not_found");

    // Writes leave hashes in the ledger, never content.
    let ev = t.events("agent.vault.written").await;
    assert_eq!(ev.len(), 4);
    assert_eq!(ev[0]["payload"]["path"], "Wiki/Note.md");
    assert!(!ev.iter().any(|e| e["payload"].to_string().contains("three")));
}

#[tokio::test]
async fn templates_fill_placeholders() {
    let t = T::new();
    let a = agent("builder-1");
    t.put("Templates/Daily.md", "# {{title}}\nDate: {{date}}\n\n{{content}}\n");
    let w = t
        .ok(
            &a,
            "vault_write",
            json!({"path": "Inbox/Standup.md", "content": "Body text", "template": "Templates/Daily.md"}),
        )
        .await;
    assert_eq!(w["path"], "Inbox/Standup.md");
    let text = t.get("Inbox/Standup.md");
    assert!(text.starts_with("# Standup\nDate: 20"), "{text}");
    assert!(text.contains("\n\nBody text\n"));
    assert!(!text.contains("{{"));

    // Without a {{content}} placeholder the content is appended.
    t.put("Templates/Plain.md", "Title: {{title}}\n");
    t.ok(
        &a,
        "vault_write",
        json!({"path": "Inbox/P.md", "content": "tail", "template": "Templates/Plain.md"}),
    )
    .await;
    assert_eq!(t.get("Inbox/P.md"), "Title: P\n\ntail");

    let e = t.err(&a, "vault_write", json!({"path": "Inbox/Q.md", "template": "Templates/None.md"})).await;
    assert_eq!(e.code(), "not_found");
}

#[tokio::test]
async fn lock_guard_and_human_force() {
    let t = T::new();
    let a = agent("builder-1");
    t.put("Wiki/Locked.md", "---\ntitle: L\nlocked: true\n---\nkeep\n");
    let r = t.ok(&a, "vault_read", json!({"path": "Wiki/Locked.md"})).await;
    assert_eq!(r["locked"], true);

    for mode in ["overwrite", "append"] {
        let e =
            t.err(&a, "vault_write", json!({"path": "Wiki/Locked.md", "content": "x", "mode": mode})).await;
        assert_eq!(reason(&e), "note_locked");
    }
    let e = t.err(&a, "vault_write", json!({"path": "Wiki/Locked.md", "content": "x", "force": true})).await;
    assert_eq!(reason(&e), "force_requires_human");
    assert!(t.get("Wiki/Locked.md").contains("keep"));

    t.ok(&human(), "vault_write", json!({"path": "Wiki/Locked.md", "content": "replaced", "force": true}))
        .await;
    assert_eq!(t.get("Wiki/Locked.md"), "replaced");

    // Real-world spellings lock too; falsy values do not.
    for (text, locked) in [
        ("\u{feff}---\r\nlocked: yes # keep\r\n---\r\nbody", true),
        ("---\n'locked': On\n---\n", true),
        ("---\nlocked:\n---\n", true),
        ("---\nlocked: maybe\n", true),
        ("---\nlocked: false\n---\n", false),
        ("---\nlocked: no\n---\n", false),
        ("plain\nlocked: true\n", false),
    ] {
        t.put("Wiki/Spelling.md", text);
        let r = t.ok(&a, "vault_read", json!({"path": "Wiki/Spelling.md"})).await;
        assert_eq!(r["locked"], locked, "{text:?}");
    }
}

#[tokio::test]
async fn revision_conflicts() {
    let t = T::new();
    let a = agent("builder-1");
    t.ok(&a, "vault_write", json!({"path": "Wiki/R.md", "content": "v1"})).await;
    let rev =
        t.ok(&a, "vault_read", json!({"path": "Wiki/R.md"})).await["revision"].as_str().unwrap().to_string();

    // Someone edits the note between the read and the write.
    t.put("Wiki/R.md", "v2 from elsewhere");
    let e = t
        .err(&a, "vault_write", json!({"path": "Wiki/R.md", "content": "v1b", "expected_revision": rev}))
        .await;
    assert_eq!(e.code(), "conflict");
    assert_eq!(t.get("Wiki/R.md"), "v2 from elsewhere");

    let rev2 =
        t.ok(&a, "vault_read", json!({"path": "Wiki/R.md"})).await["revision"].as_str().unwrap().to_string();
    let w = t
        .ok(&a, "vault_write", json!({"path": "Wiki/R.md", "content": "v3", "expected_revision": rev2}))
        .await;
    assert_ne!(w["revision"], json!(rev2));

    let e = t
        .err(&a, "vault_write", json!({"path": "Wiki/R.md", "content": "x", "expected_revision": "absent"}))
        .await;
    assert_eq!(e.code(), "conflict");
    t.ok(&a, "vault_write", json!({"path": "Wiki/Fresh.md", "content": "x", "expected_revision": "absent"}))
        .await;
    let e = t
        .err(&a, "vault_write", json!({"path": "Wiki/R.md", "content": "x", "expected_revision": "abc"}))
        .await;
    assert_eq!(e.code(), "invalid_argument");
}

#[tokio::test]
async fn write_confinement_and_escapes() {
    let t = T::new();
    let a = agent("builder-1");
    t.put("Projects/Curated.md", "curated");
    let r = t.ok(&a, "vault_read", json!({"path": "Projects/Curated.md"})).await;
    assert_eq!(r["content"], "curated");

    for (path, code) in [
        ("Projects/Curated.md", "vault_write_dir"),
        ("Wikipedia/x.md", "vault_write_dir"),
        ("Wiki/image.png", "vault_file_type"),
        ("Wiki/../Projects/x.md", "parent_traversal"),
        (".obsidian/app.md", "hidden_path"),
        ("Wiki/.trash/x.md", "hidden_path"),
        ("/etc/x.md", "outside_vault"),
    ] {
        let e = t.err(&a, "vault_write", json!({"path": path, "content": "x"})).await;
        assert_eq!(reason(&e), code, "{path}");
    }
    t.put(".obsidian/workspace.md", "x");
    let e = t.err(&a, "vault_read", json!({"path": ".obsidian/workspace.md"})).await;
    assert_eq!(reason(&e), "hidden_path");
    assert_eq!(t.get("Projects/Curated.md"), "curated");

    #[cfg(unix)]
    {
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("secret.md"), "outside").unwrap();
        std::fs::create_dir_all(t.root.join("Wiki")).unwrap();
        std::os::unix::fs::symlink(outside.path(), t.root.join("Wiki/out")).unwrap();
        let e = t.err(&a, "vault_read", json!({"path": "Wiki/out/secret.md"})).await;
        assert_eq!(reason(&e), "outside_vault");
        let e = t.err(&a, "vault_write", json!({"path": "Wiki/out/new.md", "content": "x"})).await;
        assert_eq!(reason(&e), "outside_vault");
        // Listing and search skip the escaping link.
        let l = t.ok(&a, "vault_list", json!({"path": "Wiki"})).await;
        assert!(!l["entries"].to_string().contains("out"));
        let s = t.ok(&a, "vault_search", json!({"pattern": "outside"})).await;
        assert_eq!(s["matches"].as_array().unwrap().len(), 0);
    }
}

#[tokio::test]
async fn embeds_expand_with_depth_and_cycle_limits() {
    let t = T::new();
    let a = agent("builder-1");
    t.put("Notes/A.md", "Top\n![[B]]\nEnd");
    t.put("Notes/B.md", "Bee\n![[C#Part]]");
    t.put("Notes/C.md", "Sea\n![[D|alias]]");
    t.put("Notes/D.md", "Dee");
    let r = t.ok(&a, "vault_read", json!({"path": "Notes/A.md", "expand_embeds": true})).await;
    let c = r["content"].as_str().unwrap();
    assert!(c.contains("--- [Transclusion: B] ---\nBee"), "{c}");
    assert!(c.contains("--- [Transclusion: C] ---\nSea"), "{c}");
    // Two levels deep: C's own embed stays a link.
    assert!(c.contains("![[D|alias]]") && !c.contains("Dee"), "{c}");
    // The revision covers the raw note, not the expansion.
    let raw = t.ok(&a, "vault_read", json!({"path": "Notes/A.md"})).await;
    assert_eq!(raw["revision"], r["revision"]);
    assert!(raw["content"].as_str().unwrap().contains("![[B]]"));

    t.put("Notes/X.md", "x1 ![[Y]]");
    t.put("Notes/Y.md", "y1 ![[X]]");
    let r = t.ok(&a, "vault_read", json!({"path": "Notes/X.md", "expand_embeds": true})).await;
    assert!(r["content"].as_str().unwrap().contains("[Transclusion cycle: X]"), "{}", r["content"]);

    // Embedded inbox text marks the whole result untrusted.
    t.put("Inbox/cap.md", "captured");
    t.put("Notes/E.md", "![[cap]]");
    let r = t.ok(&a, "vault_read", json!({"path": "Notes/E.md", "expand_embeds": true})).await;
    assert_eq!(r["trust"]["level"], "untrusted");
    assert!(t.ok(&a, "vault_read", json!({"path": "Notes/D.md"})).await.get("trust").is_none());
}

#[tokio::test]
async fn links_and_backlinks() {
    let t = T::new();
    let a = agent("builder-1");
    t.put("Wiki/Hub.md", "See [[Topic]] and [[Wiki/Other|other]] and ![[Pic.png]].\n`[[NotALink]]`\n");
    t.put("Wiki/Topic.md", "Back to [[Hub#Intro]].");
    t.put("Notes/Ref.md", "| a | [[Wiki/Hub\\|hub]] |\n|---|---|\n");
    t.put("Notes/None.md", "no links here");
    let l = t.ok(&a, "vault_links", json!({"path": "Wiki/Hub.md"})).await;
    assert_eq!(l["outgoing"], json!(["Pic.png", "Topic", "Wiki/Other"]));
    assert_eq!(l["embeds"], json!(["Pic.png"]));
    assert_eq!(l["backlinks"], json!(["Notes/Ref.md", "Wiki/Topic.md"]));
}

#[tokio::test]
async fn journal_appends_attributed_lines() {
    let t = T::new();
    let a = agent("builder-1");
    let r = t.ok(&a, "vault_journal", json!({"entry": "Shipped  the\nfix, see task #7", "agent": "builder-1", "tags": ["commit"], "date": "2026-01-02"})).await;
    assert_eq!(r["path"], "Logs/2026-01-02.md");
    assert_eq!(r["created_note"], true);
    let r2 = t
        .ok(&a, "vault_journal", json!({"entry": "second", "agent": "builder-1", "date": "2026-01-02"}))
        .await;
    assert_eq!(r2["created_note"], false);
    let text = t.get("Logs/2026-01-02.md");
    assert!(text.starts_with("---\ndate: 2026-01-02\ntype: journal\n---\n"), "{text}");
    let lines: Vec<&str> = text.lines().filter(|l| l.starts_with("- **")).collect();
    assert_eq!(lines.len(), 2);
    assert!(lines[0].ends_with("[builder-1] Shipped the fix, see task #7 #commit"), "{}", lines[0]);

    // A verified caller cannot journal as someone else.
    let e = t.err(&a, "vault_journal", json!({"entry": "x", "agent": "builder-2"})).await;
    assert_eq!(reason(&e), "identity_mismatch");
    let e = t.err(&a, "vault_journal", json!({"entry": "x".repeat(241), "agent": "builder-1"})).await;
    assert_eq!(e.code(), "invalid_argument");
    let e = t.err(&anon(), "vault_journal", json!({"entry": "x", "agent": "  "})).await;
    assert_eq!(e.code(), "invalid_argument");

    // A locked day note takes no appends.
    t.put("Logs/2026-01-03.md", "---\nlocked: true\n---\n");
    let e =
        t.err(&a, "vault_journal", json!({"entry": "x", "agent": "builder-1", "date": "2026-01-03"})).await;
    assert_eq!(reason(&e), "note_locked");

    let ev = t.events("agent.journal.appended").await;
    assert_eq!(ev.len(), 2);
    assert_eq!(ev[0]["payload"]["path"], "Logs/2026-01-02.md");
    assert!(!ev[0]["payload"].to_string().contains("Shipped"));

    // The digest merges streams and drops a second mention of the same #id.
    t.put(
        "Logs/ci/2026-01-02.md",
        "- **00:00** [ci-bot] build green for task #7\n- **23:59** [ci-bot] nightly done\n",
    );
    let d = t.ok(&a, "vault_briefing_digest", json!({"date": "2026-01-02", "include_inbox": false})).await;
    assert_eq!(d["deduped_count"], 1);
    assert_eq!(d["source_counts"]["journal"], 2);
    assert_eq!(d["source_counts"]["ci"], 2);
    let entries = d["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 3);
    assert_eq!(entries.last().unwrap()["text"], "nightly done");
    assert_eq!(entries[0]["tags"], json!(["commit"]));
}

#[tokio::test]
async fn query_ranks_by_lexical_seeds_and_pagerank() {
    let t = T::new();
    let a = agent("builder-1");
    // Rust is the seed; Cargo is unmentioned but linked from both seeds;
    // Island matches nothing and links nowhere.
    t.put("Wiki/Rust.md", "# Rust language\nRust is fast. See [[Cargo]].");
    t.put("Wiki/Ownership.md", "# Ownership\nA rust idea. See [[Cargo]] and [[Rust]].");
    t.put("Wiki/Cargo.md", "# Cargo\nThe build tool.");
    t.put("Wiki/Island.md", "# Island\nUnrelated text.");
    let q = t.ok(&a, "vault_query", json!({"query": "rust"})).await;
    let paths: Vec<&str> =
        q["results"].as_array().unwrap().iter().map(|r| r["path"].as_str().unwrap()).collect();
    assert_eq!(paths, ["Wiki/Rust.md", "Wiki/Ownership.md", "Wiki/Cargo.md"]);
    let cargo = &q["results"][2];
    assert_eq!(cargo["lexical"], 0.0);
    assert!(cargo["pagerank"].as_f64().unwrap() > 0.0);
    assert_eq!(cargo["links_in"], 2);
    assert_eq!(q["graph"], json!({"notes": 4, "edges": 3, "seeds": 2}));
    assert_eq!(q["results"][0]["score"], 1.0);

    let none = t.ok(&a, "vault_query", json!({"query": "zzz"})).await;
    assert_eq!(none["results"].as_array().unwrap().len(), 0);
    let e = t.err(&a, "vault_query", json!({"query": "  "})).await;
    assert_eq!(e.code(), "invalid_argument");
}

#[tokio::test]
async fn ingest_status_gate_and_archive_plan() {
    let t = T::new();
    let a = agent("steward-1");
    t.put("Inbox/idea.md", "An idea.\nprocessed → [[Wiki/Idea]]\n");
    t.put("Inbox/blank.md", "  \n");
    t.put("Inbox/old.md", "superseded: [[Inbox/idea]]\n");
    let s = t.ok(&a, "vault_ingest_status", json!({"path": "Inbox/idea.md"})).await;
    assert_eq!(s["status"], "new");
    assert_eq!(s["trust"], Value::Null);

    let m = t
        .ok(
            &a,
            "vault_ingest_status",
            json!({"path": "Inbox/idea.md", "mark": true, "agent": "steward-1", "pages": ["Wiki/Idea.md"]}),
        )
        .await;
    assert_eq!(m["status"], "marked");
    let s = t.ok(&a, "vault_ingest_status", json!({"path": "Inbox/idea.md"})).await;
    assert_eq!(s["status"], "unchanged");
    assert_eq!(s["pages"], json!(["Wiki/Idea.md"]));
    assert_eq!(s["agent"], "steward-1");

    let plan = t.ok(&human(), "vault_archive_plan", json!({"as_of": "2026-01-05"})).await;
    assert_eq!(plan["read_only"], true);
    assert_eq!(
        plan["counts"],
        json!({"archive_ready": 2, "archive_only": 2, "authoritative": 0, "pending": 1})
    );
    let idea =
        plan["candidates"].as_array().unwrap().iter().find(|c| c["source"] == "Inbox/idea.md").unwrap();
    assert_eq!(idea["destination"], "Archive/inbox-archive/2026-01-05/idea.md");
    assert_eq!(idea["action"], "move");

    t.put("Inbox/idea.md", "An idea, edited.\nprocessed → [[Wiki/Idea]]\n");
    let s = t.ok(&a, "vault_ingest_status", json!({"path": "Inbox/idea.md"})).await;
    assert_eq!(s["status"], "changed");
    let s = t.ok(&a, "vault_ingest_status", json!({"path": "Inbox/blank.md"})).await;
    assert_eq!(s["status"], "empty");
    let e = t
        .err(&a, "vault_ingest_status", json!({"path": "Inbox/blank.md", "mark": true, "agent": "steward-1"}))
        .await;
    assert_eq!(e.code(), "invalid_argument");

    let d = t.ok(&a, "vault_briefing_digest", json!({"date": "2026-01-05"})).await;
    assert_eq!(d["inbox"].as_array().unwrap().len(), 3);
    assert_eq!(d["inbox_pending_count"], 2);
    assert_eq!(t.events("agent.vault.ingest_marked").await.len(), 1);
}

#[tokio::test]
async fn memory_promote_dry_run_and_write() {
    let t = T::new();
    let a = agent("builder-1");
    let id = t
        .ok(&a, "memory_save", json!({"content": "Prefer small PRs.\nThey review faster.", "title": "Small PRs win", "confidence": 0.9}))
        .await["id"]
        .as_str()
        .unwrap()
        .to_string();
    let weak = t
        .ok(&a, "memory_save", json!({"content": "Maybe tabs.", "title": "Tabs", "confidence": 0.3}))
        .await["id"]
        .as_str()
        .unwrap()
        .to_string();

    let dry = t.ok(&a, "memory_promote", json!({"id": id, "dry_run": true})).await;
    assert_eq!(dry["promoted"], false);
    assert_eq!(dry["path"], "Wiki/Learnings/small-prs-win.md");
    assert_eq!(dry["index_line"], "- [[Wiki/Learnings/small-prs-win|Small PRs win]] — Prefer small PRs.");
    assert!(dry["markdown"].as_str().unwrap().contains("type: promoted-learning"));
    assert!(!t.root.join("Wiki/Learnings/small-prs-win.md").exists());

    t.put("Wiki/Index.md", "# Index\n\nCurated text.\n");
    let done = t.ok(&a, "memory_promote", json!({"id": id})).await;
    assert_eq!(done["promoted"], true);
    assert_eq!(done["index_updated"], true);
    assert_eq!(done["promoted_by"], "builder-1");
    let page = t.get("Wiki/Learnings/small-prs-win.md");
    assert!(page.contains(&format!("source_memory_id: \"{id}\"")), "{page}");
    assert!(page.contains("# Small PRs win\n\nPrefer small PRs.\nThey review faster."));
    let index = t.get("Wiki/Index.md");
    assert!(index.starts_with("# Index\n\nCurated text.\n\n## Promoted learnings\n\n<!-- promoted-learnings:start -->\n- [[Wiki/Learnings/small-prs-win|"), "{index}");
    // Promoting again keeps one index line.
    t.ok(&a, "memory_promote", json!({"id": id})).await;
    assert_eq!(t.get("Wiki/Index.md").matches("small-prs-win|").count(), 1);

    let e = t.err(&a, "memory_promote", json!({"id": weak})).await;
    assert_eq!(e.code(), "invalid_argument");
    let e = t.err(&a, "memory_promote", json!({"id": "nope"})).await;
    assert_eq!(e.code(), "not_found");

    // A locked page is never overwritten.
    t.put("Wiki/Learnings/small-prs-win.md", "---\nlocked: true\n---\n");
    let e = t.err(&a, "memory_promote", json!({"id": id})).await;
    assert_eq!(reason(&e), "note_locked");
    assert_eq!(t.events("agent.memory.promoted").await.len(), 2);
}

#[tokio::test]
async fn move_list_search_custodian_and_memory_ingest() {
    let t = T::new();
    let a = agent("builder-1");
    t.put("Inbox/cap.md", "a capture");
    // Developers cannot move notes; the chief-of-staff profile can.
    let e = t.err(&a, "vault_move", json!({"source": "Inbox/cap.md", "destination": "Wiki/Cap.md"})).await;
    assert_eq!(reason(&e), "profile_denied");
    let cos = Caller { profile: Profile::ChiefOfStaff, ..agent("chief-1") };
    let m =
        t.ok(&cos, "vault_move", json!({"source": "Inbox/cap.md", "destination": "Wiki/Moved/Cap.md"})).await;
    assert_eq!(m["destination"], "Wiki/Moved/Cap.md");
    assert!(!t.root.join("Inbox/cap.md").exists());
    t.put("Inbox/two.md", "two");
    let e = t
        .err(&cos, "vault_move", json!({"source": "Inbox/two.md", "destination": "Wiki/Moved/Cap.md"}))
        .await;
    assert_eq!(e.code(), "conflict");

    let l = t.ok(&a, "vault_list", json!({"path": "Wiki", "glob": "**/*.md"})).await;
    assert_eq!(l["entries"][0]["name"], "Moved/Cap.md");
    let l = t.ok(&a, "vault_list", json!({})).await;
    let names: Vec<&str> =
        l["entries"].as_array().unwrap().iter().map(|e| e["name"].as_str().unwrap()).collect();
    assert_eq!(names, ["Inbox", "Wiki"]);
    let s = t.ok(&a, "vault_search", json!({"pattern": "^a cap"})).await;
    assert_eq!(s["matches"][0]["path"], "Wiki/Moved/Cap.md");
    assert_eq!(s["matches"][0]["line_no"], 1);

    // Custodian: one broken link, one orphan, missing aliases; dry run writes nothing.
    t.put("Wiki/Index.md", "# Index\n[[Alpha]]\n");
    t.put("Wiki/Alpha.md", "---\naliases: [First]\n---\n# Alpha\nLinks to [[Beta]] and [[Ghost]].\n");
    t.put("Wiki/Beta.md", "# Beta\nBack to [[First]].\n");
    let r = t.ok(&a, "vault_wiki_custodian", json!({"dry_run": true})).await;
    assert_eq!(r["broken_links"], json!([{"source": "Alpha", "target": "Ghost"}]));
    assert_eq!(r["orphans"], json!(["Cap"]));
    assert_eq!(r["unindexed_pages"], json!(["Beta", "Cap"]));
    assert_eq!(r["missing_aliases"], json!(["Beta", "Cap"]));
    assert_eq!(r["index_rebuilt"], false);
    assert!(!t.root.join("Wiki/Health.md").exists());
    let r = t.ok(&a, "vault_wiki_custodian", json!({})).await;
    assert_eq!(r["index_rebuilt"], true);
    assert!(t.get("Wiki/Health.md").contains("broken link to `[[Ghost]]`"));
    assert_eq!(t.get("Wiki/Index.md"), "# Index\n[[Alpha]]\n");

    // Vault notes copied into memory; a second run changes nothing.
    let r = t.ok(&a, "vault_to_memory_ingest", json!({"subdirs": ["Wiki"]})).await;
    assert_eq!(r["ingested_count"], 4); // Alpha, Beta, Health, Index
    let r = t.ok(&a, "vault_to_memory_ingest", json!({"subdirs": ["Wiki"]})).await;
    assert_eq!(r["ingested_count"], 0);
    assert_eq!(r["unchanged_count"], 4);
    let hits = t.ok(&a, "memory_search", json!({"query": "Ghost"})).await;
    assert!(hits["results"].to_string().contains("Alpha"));
}

#[tokio::test]
async fn obsidian_url_must_be_loopback() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = Config::for_home(std::env::temp_dir());
    cfg.vault_path = Some(dir.path().to_path_buf());
    cfg.obsidian_api_url = Some("https://example.com:27124".into());
    cfg.obsidian_api_key = Some("test-key".to_string().into());
    let hub = Hub::in_memory(cfg).unwrap();
    let e =
        builtin_registry().call(&hub, &agent("builder-1"), "obsidian_status", json!({})).await.unwrap_err();
    assert_eq!(reason(&e), "obsidian_url");
    assert!(!e.to_string().contains("test-key"));
}
