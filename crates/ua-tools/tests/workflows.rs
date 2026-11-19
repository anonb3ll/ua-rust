//! Workflows, the langgraph tools and routines, through the governed registry.

use std::path::Path;

use serde_json::{Value, json};
use ua_core::{ActorKind, Caller, Config, Profile, identity::Transport};
use ua_tools::families::routines;
use ua_tools::{Hub, Registry, builtin_registry};

struct H {
    hub: Hub,
    reg: Registry,
    _dir: tempfile::TempDir,
}

fn write_def(dir: &Path, name: &str, yaml: &str) {
    std::fs::write(dir.join("workflows").join(format!("{name}.yaml")), yaml).unwrap();
}

impl H {
    fn with(tweak: impl FnOnce(&mut Config)) -> Self {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("workflows")).unwrap();
        let mut cfg = Config::for_home(dir.path());
        cfg.human_identities = vec!["operator".into()];
        cfg.profiles.insert("lead-1".into(), "chief-of-staff".into());
        tweak(&mut cfg);
        Self { hub: Hub::in_memory(cfg).unwrap(), reg: builtin_registry(), _dir: dir }
    }

    fn new() -> Self {
        Self::with(|_| {})
    }

    fn def(&self, name: &str, yaml: &str) {
        write_def(self._dir.path(), name, yaml);
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

    async fn approve(&self, id: i64) {
        self.ok(&human(), "approval_resolve", json!({ "id": id, "decision": "approve" })).await;
    }

    async fn task_count(&self) -> i64 {
        self.hub.db().read(|c| Ok(c.query_row("SELECT count(*) FROM tasks", [], |r| r.get(0))?)).unwrap()
    }

    async fn notes(&self, id: i64) -> String {
        self.hub
            .db()
            .read(|c| {
                Ok(c.query_row("SELECT COALESCE(notes, '') FROM tasks WHERE id = ?1", [id], |r| r.get(0))?)
            })
            .unwrap()
    }
}

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

fn lead(label: &str) -> Caller {
    Caller { profile: Profile::ChiefOfStaff, ..agent(label) }
}

fn human() -> Caller {
    Caller { kind: ActorKind::Human, profile: Profile::Operator, enforce_profile: false, ..agent("operator") }
}

const TWO_STEP: &str = r#"
name: make-and-note
description: Create a task and note on another one.
inputs: [title, target]
steps:
  - name: make
    tool: task_add
    args:
      title: "{{ inputs.title }}"
  - name: note
    tool: task_update
    args:
      id: "{{ inputs.target }}"
      append_note: "made {{ steps.make.id }}"
"#;

#[tokio::test]
async fn list_shows_definitions_and_flags_bad_ones() {
    let h = H::new();
    h.def("make-and-note", TWO_STEP);
    h.def("bad", "steps:\n  - name: a\n    tool: workflow_run\n");
    let out = h.ok(&agent("builder-1"), "workflow_list", json!({})).await;
    let list = out["workflows"].as_array().unwrap();
    assert_eq!(list.len(), 2);
    let good = list.iter().find(|w| w["name"] == "make-and-note").unwrap();
    assert_eq!(good["steps"], json!(["make", "note"]));
    assert_eq!(good["inputs"], json!(["title", "target"]));
    let bad = list.iter().find(|w| w["name"] == "bad").unwrap();
    assert_eq!(bad["description"], "(unparseable definition)");
    assert!(bad["error"].as_str().unwrap().contains("curated"));
}

#[tokio::test]
async fn data_passes_between_steps_and_inputs_are_explicit() {
    let h = H::new();
    let b = agent("builder-1");
    h.def("make-and-note", TWO_STEP);
    let target = h.ok(&b, "task_add", json!({ "title": "Target" })).await["id"].as_i64().unwrap();

    let e = h.err(&b, "workflow_run", json!({ "name": "make-and-note", "inputs": { "title": "x" } })).await;
    assert!(e.to_string().contains("missing required inputs"), "{e}");
    let e = h
        .err(
            &b,
            "workflow_run",
            json!({ "name": "make-and-note", "inputs": { "title": "x", "target": 1, "extra": 1 } }),
        )
        .await;
    assert!(e.to_string().contains("undeclared"), "{e}");
    let e = h.err(&b, "workflow_run", json!({ "name": "make-and-note", "author": "someone-else" })).await;
    assert_eq!(e.code(), "denied", "{e}");

    let out = h
        .ok(
            &b,
            "workflow_run",
            json!({ "name": "make-and-note", "inputs": { "title": "New", "target": target } }),
        )
        .await;
    assert_eq!(out["status"], "done", "{out}");
    let made = out["outputs"]["make"]["id"].as_i64().unwrap();
    assert!(h.notes(target).await.contains(&format!("made {made}")));
    assert_eq!(out["steps"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn a_step_calling_a_profile_denied_tool_is_refused() {
    let h = H::new();
    h.def(
        "make-then-notify",
        r#"
steps:
  - name: make
    tool: task_add
    args: { title: "before" }
  - name: tell
    tool: notify
    args: { message: "hello" }
"#,
    );
    // Developer profiles do not see `notify`; the workflow must not either.
    let out = h.ok(&agent("builder-1"), "workflow_run", json!({ "name": "make-then-notify" })).await;
    assert_eq!(out["status"], "denied", "{out}");
    assert_eq!(out["code"], "profile_denied");
    let tell = &out["steps"][1];
    assert_eq!(tell["status"], "denied");
    assert_eq!(tell["attempts"], 1);
    assert_eq!(out["steps"][0]["status"], "done");
}

#[tokio::test]
async fn only_read_only_steps_are_retried() {
    let vault = tempfile::tempdir().unwrap();
    let path = vault.path().to_path_buf();
    let h = H::with(|c| c.vault_path = Some(path));
    let b = agent("builder-1");
    // A definition may not ask to retry a mutating tool.
    h.def(
        "retry-write",
        "steps:\n  - name: make\n    tool: task_add\n    args: { title: x }\n    retries: 2\n",
    );
    let e = h.err(&b, "workflow_run", json!({ "name": "retry-write" })).await;
    assert!(e.to_string().contains("read-only"), "{e}");
    assert_eq!(h.task_count().await, 0);

    // A failing read-only step is retried up to `retries`, then fails.
    h.def(
        "retry-read",
        "steps:\n  - name: look\n    tool: vault_read\n    args: { path: missing.md }\n    retries: 2\n",
    );
    let out = h.ok(&b, "workflow_run", json!({ "name": "retry-read" })).await;
    assert_eq!(out["status"], "failed", "{out}");
    assert_eq!(out["steps"][0]["attempts"], 3, "{out}");

    // A failing mutating step runs once and is left for an operator.
    h.def(
        "write-once",
        "steps:\n  - name: note\n    tool: task_update\n    args: { id: 999, append_note: x }\n",
    );
    let out = h.ok(&b, "workflow_run", json!({ "name": "write-once" })).await;
    assert_eq!(out["status"], "indeterminate", "{out}");
    assert_eq!(out["steps"][0]["status"], "indeterminate", "{out}");
    assert_eq!(out["steps"][0]["attempts"], 1, "{out}");
}

#[tokio::test]
async fn resume_continues_after_a_failed_step_without_replaying() {
    let h = H::new();
    let b = agent("builder-1");
    h.def("make-and-note", TWO_STEP);
    // The note step targets a task that does not exist yet.
    let out = h
        .ok(
            &b,
            "workflow_run",
            json!({ "name": "make-and-note", "inputs": { "title": "First", "target": 2 } }),
        )
        .await;
    // task_update changes state, so its failure needs an operator: never
    // retried, the run stops as indeterminate.
    assert_eq!(out["status"], "indeterminate", "{out}");
    assert_eq!(out["steps"][1]["attempts"], 1, "{out}");
    let run_id = out["run_id"].as_str().unwrap().to_string();
    assert_eq!(h.task_count().await, 1);

    // Another agent may not resume it; run_id without resume is refused.
    let e = h
        .err(
            &agent("builder-2"),
            "workflow_run",
            json!({ "name": "make-and-note", "run_id": run_id, "resume": true }),
        )
        .await;
    assert!(e.to_string().contains("only its owner"), "{e}");
    let e = h.err(&b, "workflow_run", json!({ "name": "make-and-note", "run_id": run_id })).await;
    assert!(e.to_string().contains("resume=true"), "{e}");

    h.ok(&b, "task_add", json!({ "title": "Now task 2 exists" })).await;
    let out =
        h.ok(&b, "workflow_run", json!({ "name": "make-and-note", "run_id": run_id, "resume": true })).await;
    assert_eq!(out["status"], "done", "{out}");
    assert_eq!(out["resumed"], true);
    assert_eq!(h.task_count().await, 2, "the completed `make` step was not run again");
    assert!(h.notes(2).await.contains("made 1"));

    // A finished run resumes as a duplicate and executes nothing.
    let again =
        h.ok(&b, "workflow_run", json!({ "name": "make-and-note", "run_id": run_id, "resume": true })).await;
    assert_eq!(again["duplicate"], true);
    assert_eq!(h.task_count().await, 2);

    // A changed definition refuses the resume of an older run.
    let out = h
        .ok(
            &b,
            "workflow_run",
            json!({ "name": "make-and-note", "inputs": { "title": "Third", "target": 99 } }),
        )
        .await;
    let stale = out["run_id"].as_str().unwrap().to_string();
    h.def("make-and-note", &TWO_STEP.replace("Create a task", "Create one task"));
    let e =
        h.err(&b, "workflow_run", json!({ "name": "make-and-note", "run_id": stale, "resume": true })).await;
    assert_eq!(e.code(), "conflict");
}

#[tokio::test]
async fn approval_held_step_resumes_after_the_decision() {
    let h = H::with(|c| c.approval_tools = vec!["task_add".into()]);
    let b = agent("builder-1");
    h.def("make-and-note", TWO_STEP);
    let out = h
        .ok(
            &b,
            "workflow_run",
            json!({ "name": "make-and-note", "inputs": { "title": "Gated", "target": 1 } }),
        )
        .await;
    assert_eq!(out["status"], "pending-approval", "{out}");
    assert_eq!(out["pending_step"], "make");
    let approval = out["approval_id"].as_i64().unwrap();
    h.approve(approval).await;
    let run_id = out["run_id"].as_str().unwrap();
    let out =
        h.ok(&b, "workflow_run", json!({ "name": "make-and-note", "run_id": run_id, "resume": true })).await;
    assert_eq!(out["status"], "done", "{out}");
    assert!(h.notes(1).await.contains("made 1"));

    let cps = h.ok(&b, "langgraph_checkpoints", json!({ "run_id": run_id })).await;
    let statuses: Vec<&str> =
        cps["records"].as_array().unwrap().iter().map(|r| r["status"].as_str().unwrap()).collect();
    assert_eq!(statuses, vec!["done", "done", "pending-approval"], "newest first");
}

#[tokio::test]
async fn role_workflows_and_their_arguments_are_refused() {
    let h = H::new();
    h.def("roles", "roles: { builder: { team: x } }\nsteps:\n  - name: a\n    tool: task_list\n");
    let b = agent("builder-1");
    let e = h.err(&b, "workflow_run", json!({ "name": "roles" })).await;
    assert!(e.to_string().contains("role workflow"), "{e}");
    let e = h.err(&b, "workflow_run", json!({ "name": "roles", "instance_id": "x" })).await;
    assert!(e.to_string().contains("not supported"), "{e}");
}

async fn claimed_task(h: &H, who: &Caller) -> i64 {
    let id = h.ok(who, "task_add", json!({ "title": "Graph work" })).await["id"].as_i64().unwrap();
    h.ok(who, "task_claim", json!({ "id": id })).await;
    id
}

#[tokio::test]
async fn langgraph_progress_note_waits_for_approval_then_records_once() {
    let h = H::new();
    let b = agent("builder-1");
    let task = claimed_task(&h, &b).await;
    let digest = "a".repeat(64);
    let e = h.err(&b, "langgraph_progress_note", json!({ "task_id": task, "output_digest": "ABC" })).await;
    assert_eq!(e.code(), "invalid_argument");
    let e = h
        .err(
            &agent("builder-2"),
            "langgraph_progress_note",
            json!({ "task_id": task, "output_digest": digest }),
        )
        .await;
    assert_eq!(e.code(), "denied");

    let first =
        h.ok(&b, "langgraph_progress_note", json!({ "task_id": task, "output_digest": digest })).await;
    assert_eq!(first["status"], "interrupted", "{first}");
    assert_eq!(first["outcome"], "approval_interrupted");
    let run_id = first["run_id"].as_str().unwrap().to_string();
    assert!(!h.notes(task).await.contains("[langgraph progress]"));
    h.approve(first["interrupted_by"]["approval_id"].as_i64().unwrap()).await;

    let done = h
        .ok(
            &b,
            "langgraph_progress_note",
            json!({ "task_id": task, "output_digest": digest, "run_id": run_id }),
        )
        .await;
    assert_eq!(done["status"], "completed", "{done}");
    assert_eq!(done["outcome"], "run_completed");
    assert!(done["output"]["note"].as_str().unwrap().contains(&digest));
    let notes = h.notes(task).await;
    assert_eq!(notes.matches("[langgraph progress]").count(), 1);

    let dup = h
        .ok(
            &b,
            "langgraph_progress_note",
            json!({ "task_id": task, "output_digest": digest, "run_id": run_id }),
        )
        .await;
    assert_eq!(dup["duplicate"], true);
    assert_eq!(h.notes(task).await.matches("[langgraph progress]").count(), 1);
}

#[tokio::test]
async fn langgraph_workflow_run_stops_at_build_and_merge_gates() {
    let h = H::new();
    let b = agent("builder-1");
    let task = claimed_task(&h, &b).await;
    let args = json!({ "task_id": task, "query": "ship it" });
    let first = h.ok(&b, "langgraph_workflow_run", args.clone()).await;
    assert_eq!(first["status"], "interrupted", "{first}");
    assert_eq!(first["pending_hop"], "build");
    let run_id = first["run_id"].as_str().unwrap().to_string();
    h.approve(first["interrupted_by"]["approval_id"].as_i64().unwrap()).await;

    let mut again = args.clone();
    again["run_id"] = json!(run_id);
    let second = h.ok(&b, "langgraph_workflow_run", again.clone()).await;
    assert_eq!(second["pending_hop"], "merge", "{second}");
    assert!(h.notes(task).await.contains("[langgraph build]"));
    h.approve(second["interrupted_by"]["approval_id"].as_i64().unwrap()).await;

    let third = h.ok(&b, "langgraph_workflow_run", again.clone()).await;
    assert_eq!(third["status"], "completed", "{third}");
    assert!(third["output"]["receipts"]["merge"].is_string());
    assert!(h.notes(task).await.contains("[langgraph merge]"));

    // A different query is refused; a released claim denies further resumes.
    let mut wrong = again.clone();
    wrong["query"] = json!("something else");
    assert_eq!(h.err(&b, "langgraph_workflow_run", wrong).await.code(), "invalid_argument");
}

#[tokio::test]
async fn langgraph_run_is_gated_and_refuses_stale_authority() {
    let h = H::new();
    let b = agent("builder-1");
    let task = claimed_task(&h, &b).await;
    let e = h.err(&b, "langgraph_run", json!({ "task_id": task })).await;
    assert!(e.to_string().contains("query"), "{e}");
    let first = h.ok(&b, "langgraph_run", json!({ "task_id": task, "query": "rust cron crates" })).await;
    assert_eq!(first["outcome"], "approval_interrupted", "{first}");
    assert!(first["budget_revision"].as_str().unwrap().len() == 64);
    let run_id = first["run_id"].as_str().unwrap().to_string();

    // The task leaves `doing`: the resume is refused as stale authority.
    h.ok(&b, "task_update", json!({ "id": task, "status": "blocked" })).await;
    let out = h.ok(&b, "langgraph_run", json!({ "run_id": run_id, "resume": true })).await;
    assert_eq!(out["outcome"], "run_denied", "{out}");
    assert_eq!(out["code"], "stale_authority");

    let missing =
        h.ok(&b, "langgraph_run", json!({ "run_id": "01ARZ3NDEKTSV4RRFFQ69G5FAV", "resume": true })).await;
    assert_eq!(missing["code"], "checkpoint_missing");
}

// ---------------------------------------------------------------------------
// Routines

fn ts(s: &str) -> jiff::Timestamp {
    s.parse().unwrap()
}

async fn routine_rows(h: &H) -> Vec<Value> {
    let out = h.ok(&lead("lead-1"), "routine_list", json!({ "recent_runs": 20 })).await;
    out["routines"][0]["recent_runs"].as_array().unwrap().clone()
}

#[tokio::test]
async fn cron_tick_is_deterministic_and_idempotent() {
    let h = H::new();
    let l = lead("lead-1");
    // Developers cannot manage routines.
    assert_eq!(
        h.err(&agent("builder-1"), "routine_add", json!({ "title": "x", "schedule": "* * * * *" }))
            .await
            .code(),
        "denied"
    );
    let e = h.err(&l, "routine_add", json!({ "title": "x", "schedule": "* * * * * *" })).await;
    assert!(e.to_string().contains("five"), "{e}");
    let id = h
        .ok(
            &l,
            "routine_add",
            json!({ "title": "Quarter-hourly sweep", "schedule": "*/15 * * * *", "start_at": "2026-01-01T10:00:00+00:00" }),
        )
        .await["id"]
        .as_i64()
        .unwrap();

    // Disabled hubs do nothing unless forced.
    let off = routines::tick(&h.hub, ts("2026-01-01T10:20:00Z"), false).await.unwrap();
    assert_eq!(off["status"], "disabled");

    let first = routines::tick(&h.hub, ts("2026-01-01T10:20:10Z"), true).await.unwrap();
    assert_eq!(first["created"], 1, "{first}");
    let again = routines::tick(&h.hub, ts("2026-01-01T10:20:40Z"), true).await.unwrap();
    assert_eq!(again["created"], 0, "a repeated tick in the same minute fires nothing: {again}");
    let runs = routine_rows(&h).await;
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0]["fire_key"], "cron:2026-01-01T10:15:00+00:00");
    let task = runs[0]["task_id"].as_i64().unwrap();
    assert!(h.notes(task).await.contains(&format!("[routine: {id}]")));

    // Two slots later the first task is still open: concurrency=skip skips.
    let skipped = routines::tick(&h.hub, ts("2026-01-01T10:50:00Z"), true).await.unwrap();
    assert_eq!(skipped["skipped"], 1, "{skipped}");
    assert_eq!(skipped["skip_reasons"]["overlap"], 1);
    assert_eq!(
        routine_rows(&h).await[0]["fire_key"],
        "cron:2026-01-01T10:45:00+00:00",
        "catch_up=last fires the latest slot only"
    );

    // Paused routines do not fire; cron routines cannot be fired by hand.
    h.ok(&l, "routine_pause", json!({ "routine_id": id })).await;
    let paused = routines::tick(&h.hub, ts("2026-01-01T12:00:00Z"), true).await.unwrap();
    assert_eq!(paused["created"], 0);
    assert_eq!(paused["skipped"], 0);
}

#[tokio::test]
async fn catch_up_all_queues_behind_open_work() {
    let h = H::new();
    let l = lead("lead-1");
    h.ok(
        &l,
        "routine_add",
        json!({
            "title": "Hourly",
            "schedule": "0 * * * *",
            "start_at": "2026-01-01T00:30:00+00:00",
            "catch_up": "all",
            "concurrency": "queue",
        }),
    )
    .await;
    let out = routines::tick(&h.hub, ts("2026-01-01T03:10:00Z"), true).await.unwrap();
    assert_eq!(out["created"], 1, "{out}");
    assert_eq!(out["queued"], 2);
    let runs = routine_rows(&h).await;
    let first_task = runs.last().unwrap()["task_id"].as_i64().unwrap();
    h.ok(&l, "task_update", json!({ "id": first_task, "status": "done" })).await;
    let out = routines::tick(&h.hub, ts("2026-01-01T03:11:00Z"), true).await.unwrap();
    assert_eq!(out["released"], 1, "{out}");
}

#[tokio::test]
async fn api_routines_fire_once_per_key_and_run_their_workflow_as_owner() {
    let h = H::with(|c| c.routines_enabled = true);
    h.def(
        "list-tasks",
        "inputs: [status]\nsteps:\n  - name: list\n    tool: task_list\n    args: { status: \"{{ inputs.status }}\" }\n",
    );
    h.def("say", "steps:\n  - name: tell\n    tool: notify\n    args: { message: hi }\n");
    let l = lead("lead-1");
    let e =
        h.err(&l, "routine_add", json!({ "title": "x", "trigger": "api", "workflow": "list-tasks" })).await;
    assert!(e.to_string().contains("missing required inputs"), "{e}");
    let id = h
        .ok(
            &l,
            "routine_add",
            json!({ "title": "On event", "trigger": "api", "workflow": "list-tasks", "inputs": { "status": "open" } }),
        )
        .await["id"]
        .as_i64()
        .unwrap();
    let fired = h.ok(&l, "routine_fire", json!({ "routine_id": id, "idempotency_key": "evt-1" })).await;
    assert_eq!(fired["status"], "created", "{fired}");
    assert_eq!(fired["workflow"]["status"], "done", "{fired}");
    let replay = h.ok(&l, "routine_fire", json!({ "routine_id": id, "idempotency_key": "evt-1" })).await;
    assert_eq!(replay["task_id"], fired["task_id"]);
    assert_eq!(replay["replayed"], true);

    // The owner `lead-2` holds chief-of-staff in this session, but its
    // configured default is developer: the routine's workflow runs with the
    // default, so a step the developer profile cannot see is refused.
    let l2 = lead("lead-2");
    let id2 = h
        .ok(&l2, "routine_add", json!({ "title": "Tell", "trigger": "webhook", "workflow": "say" }))
        .await["id"]
        .as_i64()
        .unwrap();
    let fired = h.ok(&l2, "routine_fire", json!({ "routine_id": id2, "idempotency_key": "evt-9" })).await;
    assert_eq!(fired["workflow"]["status"], "denied", "{fired}");

    // Cron routines are fired by the scheduler only.
    let cron = h.ok(&l, "routine_add", json!({ "title": "c", "schedule": "0 0 * * *" })).await["id"]
        .as_i64()
        .unwrap();
    let e = h.err(&l, "routine_fire", json!({ "routine_id": cron, "idempotency_key": "k" })).await;
    assert!(e.to_string().contains("scheduler"), "{e}");
}

fn paused_events(h: &H) -> Vec<Value> {
    h.hub
        .db()
        .read(|c| {
            let mut stmt = c.prepare(
                "SELECT payload FROM event_log WHERE channel = 'agent.routine.paused' ORDER BY seq",
            )?;
            let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
            Ok(rows.map(|r| serde_json::from_str(&r.unwrap()).unwrap()).collect())
        })
        .unwrap()
}

#[tokio::test]
async fn only_the_owner_or_a_human_fires_or_pauses_a_routine() {
    let h = H::with(|c| c.routines_enabled = true);
    h.def("list-open", "steps:\n  - name: list\n    tool: task_list\n    args: { status: open }\n");
    let owner = lead("lead-1");
    let other = lead("lead-3");
    let id = h
        .ok(&owner, "routine_add", json!({ "title": "On event", "trigger": "api", "workflow": "list-open" }))
        .await["id"]
        .as_i64()
        .unwrap();

    // Another agent, even one allowed the tool, may not fire or pause it.
    let e = h.err(&other, "routine_fire", json!({ "routine_id": id, "idempotency_key": "evt-1" })).await;
    assert_eq!(e.code(), "denied", "{e}");
    assert!(e.to_string().contains("owner"), "{e}");
    assert_eq!(h.task_count().await, 0, "a refused fire creates nothing");
    let e = h.err(&other, "routine_pause", json!({ "routine_id": id })).await;
    assert_eq!(e.code(), "denied", "{e}");
    assert!(paused_events(&h).is_empty());

    // A verified human may fire it; the workflow still runs as the agent owner.
    let fired = h.ok(&human(), "routine_fire", json!({ "routine_id": id, "idempotency_key": "evt-2" })).await;
    assert_eq!(fired["status"], "created", "{fired}");
    assert_eq!(fired["workflow"]["actor_kind"], "agent", "{fired}");

    // Pause and resume record the previous state.
    let out = h.ok(&owner, "routine_pause", json!({ "routine_id": id })).await;
    assert_eq!(out["previous_paused"], 0);
    let out = h.ok(&human(), "routine_pause", json!({ "routine_id": id, "paused": false })).await;
    assert_eq!(out["previous_paused"], 1);
    let events = paused_events(&h);
    assert_eq!(events.len(), 2);
    assert_eq!(events[0]["paused"], true);
    assert_eq!(events[0]["previous_paused"], false);
    assert_eq!(events[1]["paused"], false);
    assert_eq!(events[1]["previous_paused"], true);
}

#[tokio::test]
async fn a_humans_routine_never_runs_unattended_with_human_authority() {
    let h = H::with(|c| c.routines_enabled = true);
    h.def("list-open", "steps:\n  - name: list\n    tool: task_list\n    args: { status: open }\n");
    let op = human();
    h.ok(
        &op,
        "routine_add",
        json!({ "title": "Hourly", "schedule": "0 * * * *", "start_at": "2026-01-01T00:30:00+00:00", "workflow": "list-open" }),
    )
    .await;
    let out = routines::tick(&h.hub, ts("2026-01-01T01:00:30Z"), true).await.unwrap();
    assert_eq!(out["created"], 1, "{out}");
    let run = &out["workflows"][0];
    assert_eq!(run["status"], "done", "{out}");
    assert_eq!(run["actor_kind"], "agent", "a scheduled fire is never human: {out}");

    // The human owner firing in person keeps human authority.
    let api = h
        .ok(&op, "routine_add", json!({ "title": "Now", "trigger": "api", "workflow": "list-open" }))
        .await["id"]
        .as_i64()
        .unwrap();
    let fired = h.ok(&op, "routine_fire", json!({ "routine_id": api, "idempotency_key": "evt-1" })).await;
    assert_eq!(fired["workflow"]["actor_kind"], "human", "{fired}");
}
