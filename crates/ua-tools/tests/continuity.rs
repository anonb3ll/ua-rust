//! Continuity through the governed registry: the task workflow record and
//! graded checks, session handoff notes, conversation handoff, queue closure
//! (park, fold, unpark, sweep, health) and delegation stats.

use std::sync::{Arc, Mutex};

use serde_json::{Value, json};
use ua_core::{ActorKind, Caller, Config, Profile, UaError, identity::Transport};
use ua_tools::ci::{CiOutcome, CiRun, CiVerifier, Verdict, VerifyFuture};
use ua_tools::{Hub, Registry, builtin_registry};

const HEAD: &str = "abcdef1234567";
const OTHER_HEAD: &str = "1234567abcdef";
/// A full 40-hex head: only a check at a full SHA may be graded verified.
const FULL: &str = "abcdef1234567abcdef1234567abcdef12345678";

fn caller(label: &str, kind: ActorKind, profile: Profile) -> Caller {
    Caller {
        label: label.into(),
        kind,
        profile,
        enforce_profile: true,
        session_key: Some(format!("{label}-s")),
        transport: Transport::Mcp,
    }
}

fn builder() -> Caller {
    caller("builder-1", ActorKind::Agent, Profile::Developer)
}

fn other() -> Caller {
    caller("builder-2", ActorKind::Agent, Profile::Developer)
}

fn researcher() -> Caller {
    caller("research-1", ActorKind::Agent, Profile::Research)
}

fn human() -> Caller {
    Caller { enforce_profile: false, ..caller("operator", ActorKind::Human, Profile::Operator) }
}

/// A configured lifecycle operator that is an agent, not a human.
fn lifecycle_op() -> Caller {
    caller("lead-op", ActorKind::Agent, Profile::Lead)
}

fn outsider() -> Caller {
    caller("builder-3", ActorKind::Agent, Profile::Developer)
}

fn unverified() -> Caller {
    Caller::local("builder-1", Transport::Mcp)
}

fn reason(e: &UaError) -> String {
    e.reason_code().map(str::to_string).unwrap_or_else(|| e.code().to_string())
}

/// A scripted CI verifier: a run verdict and a job verdict, and every call.
struct FakeCi {
    run: Verdict,
    job: Verdict,
    calls: Mutex<Vec<String>>,
}

impl FakeCi {
    fn new(run: Verdict, job: Verdict) -> Arc<Self> {
        Arc::new(Self { run, job, calls: Mutex::new(Vec::new()) })
    }
}

impl CiVerifier for FakeCi {
    fn verify_run<'a>(&'a self, run: &'a CiRun) -> VerifyFuture<'a> {
        self.calls
            .lock()
            .unwrap()
            .push(format!("run {} {} {} {}", run.repo, run.run_id, run.head_sha, run.expect));
        let v = self.run;
        Box::pin(
            async move { CiOutcome::new(v, "run looked up").observed(json!({ "conclusion": "success" })) },
        )
    }

    fn verify_job<'a>(&'a self, run: &'a CiRun, job: &'a str) -> VerifyFuture<'a> {
        self.calls.lock().unwrap().push(format!("job {} {job}", run.run_id));
        let v = self.job;
        Box::pin(
            async move { CiOutcome::new(v, format!("job {job} looked up")).observed(json!({ "job": job })) },
        )
    }
}

struct H {
    hub: Hub,
    reg: Registry,
}

impl H {
    fn new() -> Self {
        Self::with_ci(None)
    }

    fn with_ci(ci: Option<Arc<dyn CiVerifier>>) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = Config::for_home(dir.path().join("home"));
        cfg.human_identities = vec!["operator".into()];
        cfg.lifecycle_operators = Some(vec!["operator".into(), "lead-op".into()]);
        let mut hub = Hub::in_memory(cfg).unwrap();
        if let Some(ci) = ci {
            hub = hub.with_ci_verifier(ci);
        }
        Self { hub, reg: builtin_registry() }
    }

    async fn call(&self, who: &Caller, tool: &str, args: Value) -> Result<Value, UaError> {
        self.reg.call(&self.hub, who, tool, args).await
    }

    async fn ok(&self, who: &Caller, tool: &str, args: Value) -> Value {
        match self.call(who, tool, args.clone()).await {
            Ok(v) => v,
            Err(e) => panic!("{tool}({args}) failed: {e:?}"),
        }
    }

    async fn act(&self, who: &Caller, action: &str, params: Value) -> Result<Value, UaError> {
        self.call(who, "coordination_manage", json!({ "action": action, "params": params })).await
    }

    async fn act_ok(&self, who: &Caller, action: &str, params: Value) -> Value {
        match self.act(who, action, params.clone()).await {
            Ok(v) => v,
            Err(e) => panic!("{action}({params}) failed: {e:?}"),
        }
    }

    async fn act_err(&self, who: &Caller, action: &str, params: Value) -> UaError {
        match self.act(who, action, params.clone()).await {
            Ok(v) => panic!("{action}({params}) should fail, got {v}"),
            Err(e) => e,
        }
    }

    async fn task(&self, title: &str, parent: Option<i64>) -> i64 {
        let mut args = json!({ "title": title });
        if let Some(p) = parent {
            args["parent_id"] = json!(p);
        }
        self.ok(&builder(), "task_add", args).await["id"].as_i64().unwrap()
    }

    fn sql(&self, sql: &str) {
        let sql = sql.to_string();
        self.hub.db().write(move |tx| Ok(tx.execute_batch(&sql)?)).unwrap();
    }

    fn n(&self, sql: &str) -> i64 {
        let sql = sql.to_string();
        self.hub.db().read(move |c| Ok(c.query_row(&sql, [], |r| r.get(0))?)).unwrap()
    }

    fn events(&self, channel: &str) -> i64 {
        self.n(&format!("SELECT COUNT(*) FROM event_log WHERE channel = '{channel}'"))
    }

    /// Bind the default project stream (every test task's) to `repo`.
    async fn bind(&self, repo: &str) {
        self.act_ok(&human(), "project_repo_bind", json!({ "project": "default", "repo": repo })).await;
    }
}

fn check<'a>(view: &'a Value, name: &str) -> &'a Value {
    view["checks"].as_array().unwrap().iter().find(|c| c["name"] == name).unwrap_or_else(|| panic!("{view}"))
}

// --- task workflow ------------------------------------------------------------------

#[tokio::test]
async fn workflow_capsule_is_written_by_the_claimant_and_fenced_on_revision() {
    let h = H::new();
    let t = h.task("Ship the parser", None).await;
    // Nobody holds the task yet: an agent may not write its record.
    let e = h.act_err(&builder(), "task_workflow_set", json!({ "task_id": t, "stage": "plan" })).await;
    assert_eq!(reason(&e), "not_task_owner");
    h.ok(&builder(), "task_claim", json!({ "id": t })).await;

    let v = h
        .act_ok(
            &builder(),
            "task_workflow_set",
            json!({ "task_id": t, "stage": "implement", "goal": "parse it", "done": ["lexer", " "],
                    "focus": "the parser", "head_sha": HEAD.to_uppercase(), "expected_checks": ["Tests", "lint"] }),
        )
        .await;
    assert_eq!(v["stage"], "implement");
    assert_eq!(v["revision"], 1);
    assert_eq!(v["capsule"]["done"], json!(["lexer"]));
    assert_eq!(v["head_sha"], HEAD);
    assert_eq!(v["expected_checks"], json!(["lint", "tests"]));
    // Expected checks nobody recorded read as unknown at the capsule's head.
    assert_eq!(check(&v, "tests")["grade"], "unknown");
    assert_eq!(v["summary"]["unknown"], json!(["lint", "tests"]));
    assert_eq!(v["trust"]["level"], "untrusted");

    // Another agent may not write; the next owner and a human may.
    let e = h.act_err(&other(), "task_workflow_set", json!({ "task_id": t, "stage": "verify" })).await;
    assert_eq!(reason(&e), "not_task_owner");
    let e = h
        .act_err(
            &builder(),
            "task_workflow_set",
            json!({ "task_id": t, "stage": "verify", "expected_revision": 0 }),
        )
        .await;
    assert_eq!(e.code(), "conflict");
    h.ok(&builder(), "task_update", json!({ "id": t, "next_owner": "builder-2" })).await;
    let v = h
        .act_ok(
            &other(),
            "task_workflow_set",
            json!({ "task_id": t, "stage": "verify", "expected_revision": 1 }),
        )
        .await;
    assert_eq!(
        (v["stage"].as_str(), v["revision"].as_i64(), v["updated_by"].as_str()),
        (Some("verify"), Some(2), Some("builder-2"))
    );
    assert_eq!(v["capsule"]["goal"], "parse it", "omitted fields keep their value");
    h.act_ok(&human(), "task_workflow_set", json!({ "task_id": t, "focus": "" })).await;

    // Validation.
    for bad in [
        json!({ "task_id": t, "stage": "ponder" }),
        json!({ "task_id": t, "head_sha": "xyz" }),
        json!({ "task_id": t, "expected_checks": ["Bad Name"] }),
        json!({ "task_id": t }),
    ] {
        assert_eq!(h.act_err(&builder(), "task_workflow_set", bad).await.code(), "invalid_argument");
    }
    assert_eq!(h.events("agent.task.workflow"), 3);

    // Research may read the record but not write it.
    let read = h.act_ok(&researcher(), "task_workflow_get", json!({ "task_id": t })).await;
    assert_eq!(read["revision"], 3);
    assert!(
        h.act(&researcher(), "task_workflow_set", json!({ "task_id": t, "stage": "done" })).await.is_err()
    );
    assert_eq!(
        h.act_err(&builder(), "task_workflow_get", json!({ "task_id": 999 })).await.code(),
        "not_found"
    );
}

#[tokio::test]
async fn checks_are_graded_attested_verified_or_unknown_at_a_head() {
    let ci = FakeCi::new(Verdict::Verified, Verdict::Verified);
    let h = H::with_ci(Some(ci.clone()));
    let t = h.task("Grade me", None).await;
    h.ok(&builder(), "task_claim", json!({ "id": t })).await;
    h.bind("example/repo").await;

    // No reference: attested, and the verifier is never asked.
    let v = h
        .act_ok(
            &builder(),
            "task_check_record",
            json!({ "task_id": t, "name": "lint", "outcome": "pass", "head_sha": FULL }),
        )
        .await;
    assert_eq!(check(&v, "lint")["grade"], "attested");
    assert!(ci.calls.lock().unwrap().is_empty());

    // A run with no job named: verified, but on the whole run only.
    let v = h
        .act_ok(
            &builder(),
            "task_check_record",
            json!({ "task_id": t, "name": "ci", "outcome": "pass", "head_sha": FULL,
                    "ref": { "kind": "ci_run", "ref": "#4242", "repo": "example/repo" } }),
        )
        .await;
    let c = check(&v, "ci");
    assert_eq!((c["grade"].as_str(), c["verified_scope"].as_str()), (Some("verified"), Some("run")), "{c}");
    assert_eq!(v["summary"]["verified_run_only"], json!(["ci"]));
    assert_eq!(ci.calls.lock().unwrap()[0], format!("run example/repo 4242 {FULL} success"));

    // A named job: graded on the job.
    let v = h
        .act_ok(
            &builder(),
            "task_check_record",
            json!({ "task_id": t, "name": "tests", "outcome": "pass", "head_sha": FULL,
                    "ref": { "kind": "ci_run", "ref": 4243, "repo": "example/repo", "job": "unit" } }),
        )
        .await;
    let c = check(&v, "tests");
    assert_eq!((c["grade"].as_str(), c["verified_scope"].as_str()), (Some("verified"), Some("job")), "{c}");
    assert_eq!(c["verification"]["observed"]["job"], "unit");
    assert_eq!(v["summary"]["verified"], json!(["ci", "tests"]));

    // Re-recording at the same head resets the grade until verified again.
    let v = h
        .act_ok(
            &builder(),
            "task_check_record",
            json!({ "task_id": t, "name": "tests", "outcome": "fail", "head_sha": FULL, "verify": false,
                    "ref": { "kind": "ci_run", "ref": "4243", "repo": "example/repo", "job": "unit" } }),
        )
        .await;
    assert_eq!(check(&v, "tests")["grade"], "attested");
    assert_eq!(v["summary"]["failing"], json!(["tests"]));
    let v = h
        .act_ok(&other(), "task_check_verify", json!({ "task_id": t, "name": "tests", "head_sha": FULL }))
        .await;
    assert_eq!(check(&v, "tests")["grade"], "verified", "anyone may ask for a re-verify");
    assert!(ci.calls.lock().unwrap().iter().any(|c| c.ends_with("failure")), "a fail expects a failed run");

    // At another head every check is unknown, with the head it was seen at.
    let v = h.act_ok(&builder(), "task_workflow_get", json!({ "task_id": t, "head_sha": OTHER_HEAD })).await;
    let c = check(&v, "lint");
    assert_eq!((c["grade"].as_str(), c["stale_head"].as_str()), (Some("unknown"), Some(FULL)), "{c}");

    // Writers only; a check never recorded cannot be verified.
    let e = h
        .act_err(
            &other(),
            "task_check_record",
            json!({ "task_id": t, "name": "x", "outcome": "pass", "head_sha": FULL }),
        )
        .await;
    assert_eq!(reason(&e), "not_task_owner");
    let e = h
        .act_err(&builder(), "task_check_verify", json!({ "task_id": t, "name": "nope", "head_sha": FULL }))
        .await;
    assert_eq!(e.code(), "not_found");
    for bad in [
        json!({ "task_id": t, "name": "x", "outcome": "maybe", "head_sha": FULL }),
        json!({ "task_id": t, "name": "x", "outcome": "pass", "head_sha": FULL, "ref": { "kind": "pr", "ref": "1" } }),
        json!({ "task_id": t, "name": "x", "outcome": "pass", "head_sha": FULL, "ref": { "kind": "ci_run", "ref": "abc" } }),
        json!({ "task_id": t, "name": "x", "outcome": "pass", "head_sha": FULL,
                "ref": { "kind": "ci_run", "ref": "1", "repo": "no-slash" } }),
    ] {
        assert_eq!(h.act_err(&builder(), "task_check_record", bad).await.code(), "invalid_argument");
    }
}

#[tokio::test]
async fn a_contradiction_stays_attested_and_the_default_verifier_cannot_verify() {
    let ci = FakeCi::new(Verdict::Verified, Verdict::Mismatch);
    let h = H::with_ci(Some(ci));
    let t = h.task("Contradicted", None).await;
    h.ok(&builder(), "task_claim", json!({ "id": t })).await;
    h.bind("example/repo").await;
    let v = h
        .act_ok(
            &builder(),
            "task_check_record",
            json!({ "task_id": t, "name": "tests", "outcome": "pass", "head_sha": FULL,
                    "ref": { "kind": "ci_run", "ref": "7", "repo": "example/repo", "job": "unit" } }),
        )
        .await;
    assert_eq!(check(&v, "tests")["grade"], "attested");
    assert_eq!(v["summary"]["contradicted"], json!(["tests"]));

    // The built-in GitHub verifier is a stub until the native client lands.
    let h = H::new();
    let t = h.task("Stubbed", None).await;
    h.ok(&builder(), "task_claim", json!({ "id": t })).await;
    h.bind("example/repo").await;
    let v = h
        .act_ok(
            &builder(),
            "task_check_record",
            json!({ "task_id": t, "name": "ci", "outcome": "pass", "head_sha": FULL,
                    "ref": { "kind": "ci_run", "ref": "7", "repo": "example/repo" } }),
        )
        .await;
    let c = check(&v, "ci");
    assert_eq!(
        (c["grade"].as_str(), c["verification"]["verdict"].as_str()),
        (Some("attested"), Some("unverifiable"))
    );
    assert_eq!(v["summary"]["contradicted"], json!([]));
}

#[tokio::test]
async fn the_session_packet_carries_the_workflow_and_the_sealed_handoff_note() {
    let h = H::new();
    let t = h.task("Resume me", None).await;
    h.ok(&builder(), "task_claim", json!({ "id": t })).await;
    let sid =
        h.ok(&builder(), "session_start", json!({ "kind": "interactive", "task_id": t })).await["session_id"]
            .as_str()
            .unwrap()
            .to_string();
    let p = h.ok(&builder(), "session_packet", json!({ "session_id": sid })).await;
    assert!(p["workflow"].is_null() && p["handoff_note"].is_null(), "{p}");

    h.act_ok(&builder(), "task_workflow_set", json!({ "task_id": t, "stage": "review", "head_sha": HEAD }))
        .await;
    h.act_ok(
        &builder(),
        "task_check_record",
        json!({ "task_id": t, "name": "tests", "outcome": "fail", "head_sha": HEAD }),
    )
    .await;
    let note = h
        .act_ok(
            &builder(),
            "session_handoff_propose",
            json!({ "session_id": sid, "done": ["a"], "next_steps": ["b"] }),
        )
        .await;
    let p = h.ok(&builder(), "session_packet", json!({ "session_id": sid })).await;
    assert!(p["handoff_note"].is_null(), "a draft is never in the packet");
    h.act_ok(&builder(), "session_handoff_seal", json!({ "note_id": note["id"] })).await;

    let p = h.ok(&builder(), "session_packet", json!({ "session_id": sid })).await;
    assert_eq!(p["workflow"]["stage"], "review");
    assert_eq!(p["workflow"]["checks"]["tests"], "attested");
    assert_eq!(p["workflow"]["failing"], json!(["tests"]));
    assert_eq!(p["handoff_note"]["id"], note["id"]);
    assert_eq!(p["handoff_note"]["trust"]["level"], "untrusted");
    assert_eq!(p["labels"]["source_tiers"]["workflow"], "T2");
}

// --- session handoff notes ----------------------------------------------------------

async fn session(h: &H, who: &Caller) -> String {
    h.ok(who, "session_start", json!({ "kind": "interactive" })).await["session_id"]
        .as_str()
        .unwrap()
        .to_string()
}

#[tokio::test]
async fn a_handoff_note_is_drafted_edited_sealed_and_recovered() {
    let h = H::new();
    let sid = session(&h, &builder()).await;

    // done and next_steps need one non-empty item each.
    let e = h
        .act_err(
            &builder(),
            "session_handoff_propose",
            json!({ "session_id": sid, "done": [" "], "next_steps": ["x"] }),
        )
        .await;
    assert_eq!(e.code(), "invalid_argument");
    // Only the session's owner writes its note.
    let e = h
        .act_err(
            &other(),
            "session_handoff_propose",
            json!({ "session_id": sid, "done": ["a"], "next_steps": ["b"] }),
        )
        .await;
    assert_eq!(reason(&e), "not_session_owner");

    let draft = h
        .act_ok(
            &builder(),
            "session_handoff_propose",
            json!({ "session_id": sid, "done": ["wrote the lexer", "token sk-test-00000000000000000000000000000000"],
                    "next_steps": ["parser"], "open_questions": ["which grammar?"] }),
        )
        .await;
    let id = draft["id"].as_i64().unwrap();
    assert_eq!(draft["state"], "draft");
    assert!(!draft["done"].to_string().contains("sk-test-0000"), "items are redacted: {draft}");
    // Recover never returns a draft.
    let r = h.act_ok(&builder(), "session_handoff_recover", json!({ "session_id": sid })).await;
    assert!(r["note"].is_null());
    // One draft at a time, with or without supersede.
    let e = h
        .act_err(
            &builder(),
            "session_handoff_propose",
            json!({ "session_id": sid, "done": ["a"], "next_steps": ["b"], "supersede": true }),
        )
        .await;
    assert_eq!(e.code(), "conflict");

    let edited = h
        .act_ok(
            &builder(),
            "session_handoff_update",
            json!({ "note_id": id, "next_steps": ["parser", "tests"] }),
        )
        .await;
    assert_eq!(edited["next_steps"], json!(["parser", "tests"]));
    let e = h.act_err(&other(), "session_handoff_seal", json!({ "note_id": id })).await;
    assert_eq!(reason(&e), "not_note_owner");
    let sealed = h.act_ok(&builder(), "session_handoff_seal", json!({ "note_id": id })).await;
    assert_eq!(sealed["state"], "sealed");
    assert!(sealed["sealed_at"].is_string());

    // A sealed note is immutable and cannot be discarded.
    for action in ["session_handoff_discard", "session_handoff_seal"] {
        assert_eq!(h.act_err(&builder(), action, json!({ "note_id": id })).await.code(), "conflict");
    }
    let e = h.act_err(&builder(), "session_handoff_update", json!({ "note_id": id, "done": ["x"] })).await;
    assert_eq!(e.code(), "conflict");
    let r = h.act_ok(&builder(), "session_handoff_recover", json!({ "session_id": sid })).await;
    assert_eq!(r["note"]["id"], id);
    assert_eq!(r["note"]["trust"]["level"], "untrusted");

    // The database enforces forward-only states too.
    let back = h.hub.db().write(move |tx| {
        Ok(tx.execute("UPDATE session_handoff_notes SET state = 'draft' WHERE id = ?1", [id])?)
    });
    assert!(back.is_err(), "a sealed note never returns to draft");
    assert_eq!(h.events("agent.lifecycle.handoff"), 3);
}

#[tokio::test]
async fn handoff_proposals_are_rate_limited_and_superseded_on_seal() {
    let h = H::new();
    let sid = session(&h, &builder()).await;
    let propose = |supersede: bool| json!({ "session_id": sid, "done": ["a"], "next_steps": ["b"], "supersede": supersede });
    let first = h.act_ok(&builder(), "session_handoff_propose", propose(false)).await;
    let first_id = first["id"].as_i64().unwrap();
    h.act_ok(&builder(), "session_handoff_discard", json!({ "note_id": first_id })).await;

    // The 5-minute cooldown counts from the last proposal, discarded or not.
    let e = h.act_err(&builder(), "session_handoff_propose", propose(false)).await;
    assert_eq!(reason(&e), "handoff_cooldown");

    let age = |minutes: i64| {
        let ts = jiff::Timestamp::now().checked_sub(jiff::SignedDuration::from_mins(minutes)).unwrap();
        ua_core::time::format_ts(ts)
    };
    h.sql(&format!("UPDATE session_handoff_notes SET created_at = '{}'", age(6)));
    let second = h.act_ok(&builder(), "session_handoff_propose", propose(false)).await;
    let second_id = second["id"].as_i64().unwrap();
    h.act_ok(&builder(), "session_handoff_seal", json!({ "note_id": second_id })).await;

    // A sealed note is pending: a new one needs supersede, and its seal
    // supersedes the old one.
    h.sql(&format!("UPDATE session_handoff_notes SET created_at = '{}' WHERE id = {second_id}", age(6)));
    let e = h.act_err(&builder(), "session_handoff_propose", propose(false)).await;
    assert_eq!(e.code(), "conflict");
    let third = h.act_ok(&builder(), "session_handoff_propose", propose(true)).await;
    assert_eq!(third["supersedes"], second_id);
    h.act_ok(&builder(), "session_handoff_seal", json!({ "note_id": third["id"] })).await;
    assert_eq!(
        h.n(&format!("SELECT state = 'superseded' FROM session_handoff_notes WHERE id = {second_id}")),
        1
    );
    let r = h.act_ok(&builder(), "session_handoff_recover", json!({ "session_id": sid })).await;
    assert_eq!(r["note"]["id"], third["id"]);

    // Five proposals in the last hour is the limit, whatever the cooldown says.
    h.sql(&format!(
        "INSERT INTO session_handoff_notes (session_id, agent, done, next_steps, state, created_at, updated_at) \
         VALUES ('{sid}', 'builder-1', '[\"a\"]', '[\"b\"]', 'discarded', '{t}', '{t}'), \
                ('{sid}', 'builder-1', '[\"a\"]', '[\"b\"]', 'discarded', '{t}', '{t}')",
        t = age(10)
    ));
    h.sql(&format!("UPDATE session_handoff_notes SET created_at = '{}'", age(10)));
    let e = h.act_err(&builder(), "session_handoff_propose", propose(true)).await;
    assert_eq!(reason(&e), "handoff_rate_limited");
}

#[tokio::test]
async fn only_the_receiver_acknowledges_an_assigned_note() {
    let h = H::new();
    let sid = session(&h, &builder()).await;
    let note = h
        .act_ok(
            &builder(),
            "session_handoff_propose",
            json!({ "session_id": sid, "done": ["a"], "next_steps": ["b"] }),
        )
        .await;
    let id = note["id"].as_i64().unwrap();
    h.act_ok(&builder(), "session_handoff_seal", json!({ "note_id": id })).await;
    let e = h.act_err(&other(), "session_handoff_ack", json!({ "note_id": id })).await;
    assert_eq!(reason(&e), "not_note_receiver", "a sealed note is handed to nobody yet");

    // Failover is hub-side; an imported or assigned note looks like this.
    h.sql(&format!(
        "UPDATE session_handoff_notes SET state = 'assigned', assigned_to = 'builder-2' WHERE id = {id}"
    ));
    let e = h.act_err(&builder(), "session_handoff_ack", json!({ "note_id": id })).await;
    assert_eq!(reason(&e), "not_note_receiver");
    let acked = h.act_ok(&other(), "session_handoff_ack", json!({ "note_id": id })).await;
    assert_eq!(
        (acked["state"].as_str(), acked["delivered_to"].as_str()),
        (Some("delivered"), Some("builder-2"))
    );
    let again = h.act_ok(&other(), "session_handoff_ack", json!({ "note_id": id })).await;
    assert_eq!(again["acknowledged_at"], acked["acknowledged_at"], "repeating is a no-op");
}

// --- conversation handoff -----------------------------------------------------------

#[tokio::test]
async fn a_conversation_is_handed_off_to_a_task_without_copying_it() {
    let h = H::new();
    h.ok(
        &builder(),
        "message_send",
        json!({ "act": "request", "to_agent": "builder-2", "body": "the secret plan", "conversation_id": "conv-1" }),
    )
    .await;

    // Someone outside the conversation sees nothing.
    let outsider = caller("builder-3", ActorKind::Agent, Profile::Developer);
    let e = h
        .act_err(&outsider, "conversation_handoff", json!({ "conversation_id": "conv-1", "title": "x" }))
        .await;
    assert_eq!(e.code(), "not_found");
    let e = h.act_err(&outsider, "conversation_handoffs", json!({ "conversation_id": "conv-1" })).await;
    assert_eq!(e.code(), "not_found", "missing and not yours read alike");

    let created = h
        .act_ok(
            &other(),
            "conversation_handoff",
            json!({ "conversation_id": "conv-1", "title": "Plan it", "priority": "high" }),
        )
        .await;
    let t = created["task_id"].as_i64().unwrap();
    assert_eq!(created["created"], true);
    let task = h.ok(&other(), "task_list", json!({ "status": "all" })).await;
    let row = task["tasks"].as_array().unwrap().iter().find(|r| r["id"] == t).unwrap().clone();
    assert_eq!(row["priority"], "high");
    assert!(row["notes"].as_str().unwrap().contains("[conversation: conv-1]"));
    assert!(!row["notes"].as_str().unwrap().contains("secret plan"), "the transcript is never copied");

    // A repeat returns the same task.
    let again = h
        .act_ok(
            &other(),
            "conversation_handoff",
            json!({ "conversation_id": "conv-1", "title": "Plan it", "priority": "high" }),
        )
        .await;
    assert_eq!((again["task_id"].as_i64(), again["created"].as_bool()), (Some(t), Some(false)));

    // Link an existing task, twice: one note line.
    let existing = h.task("Existing work", None).await;
    for _ in 0..2 {
        let linked = h
            .act_ok(
                &builder(),
                "conversation_handoff",
                json!({ "conversation_id": "conv-1", "task_id": existing }),
            )
            .await;
        assert_eq!(linked["created"], false);
    }
    let notes: String = {
        let id = existing;
        h.hub
            .db()
            .read(move |c| Ok(c.query_row("SELECT notes FROM tasks WHERE id = ?1", [id], |r| r.get(0))?))
            .unwrap()
    };
    assert_eq!(notes.matches("[conversation: conv-1]").count(), 1);

    let listed = h.act_ok(&builder(), "conversation_handoffs", json!({ "conversation_id": "conv-1" })).await;
    let ids: Vec<i64> =
        listed["handoffs"].as_array().unwrap().iter().map(|r| r["task_id"].as_i64().unwrap()).collect();
    assert_eq!(ids, vec![t, existing]);
    assert_eq!(listed["handoffs"][0]["by"], "builder-2");
    assert_eq!(h.events("agent.conversation.handoff"), 2, "one event per participant and task");

    // Validation.
    for bad in [
        json!({ "conversation_id": "conv-1" }),
        json!({ "conversation_id": "conv-1", "title": "a", "task_id": existing }),
        json!({ "conversation_id": "bad]id", "title": "a" }),
    ] {
        assert_eq!(h.act_err(&builder(), "conversation_handoff", bad).await.code(), "invalid_argument");
    }
}

// --- queue closure ------------------------------------------------------------------

fn days_ago(days: i64) -> String {
    let ts = jiff::Timestamp::now().checked_sub(jiff::SignedDuration::from_hours(24 * days)).unwrap();
    ua_core::time::format_ts(ts)
}

fn listed_ids(v: &Value) -> Vec<i64> {
    v["tasks"].as_array().unwrap().iter().map(|r| r["id"].as_i64().unwrap()).collect()
}

#[tokio::test]
async fn parking_folds_children_hides_them_and_unpark_restores_them() {
    let h = H::new();
    let root = h.task("Epic", None).await;
    let child = h.task("Child", Some(root)).await;
    let grandchild = h.task("Grandchild", Some(child)).await;
    let done = h.task("Finished child", Some(root)).await;
    h.ok(&builder(), "task_update", json!({ "id": done, "status": "done" })).await;

    // A reason is required; fold_children=false refuses with open children.
    let e = h.act_err(&builder(), "queue_park", json!({ "task_id": root, "reason": "  " })).await;
    assert_eq!(e.code(), "invalid_argument");
    let e = h
        .act_err(
            &builder(),
            "queue_park",
            json!({ "task_id": root, "reason": "idle", "fold_children": false }),
        )
        .await;
    assert_eq!(e.code(), "conflict");
    let dry = h
        .act_ok(&builder(), "queue_park", json!({ "task_id": root, "reason": "idle", "dry_run": true }))
        .await;
    assert_eq!(dry["folded"], json!([child, grandchild]));
    assert_eq!(h.n("SELECT COUNT(*) FROM tasks WHERE parked_at IS NOT NULL"), 0, "a dry run writes nothing");

    let parked =
        h.act_ok(&builder(), "queue_park", json!({ "task_id": root, "reason": "no movement" })).await;
    assert_eq!(parked["folded"], json!([child, grandchild]));
    assert_eq!(h.n(&format!("SELECT folded_into FROM tasks WHERE id = {grandchild}")), root);
    assert_eq!(
        h.n(&format!("SELECT folded_into IS NULL AND parked_by = 'builder-1' FROM tasks WHERE id = {root}")),
        1
    );
    assert_eq!(h.n(&format!("SELECT parked_at IS NULL FROM tasks WHERE id = {done}")), 1);
    assert_eq!(
        h.n(&format!("SELECT archived_at IS NULL AND status = 'open' FROM tasks WHERE id = {root}")),
        1
    );
    assert_eq!(h.events("agent.queue.parked"), 1);

    // Parked tasks leave the working queue and come back in the parked view.
    let open = h.ok(&builder(), "task_list", json!({})).await;
    assert!(listed_ids(&open).is_empty(), "{open}");
    let view = h.ok(&builder(), "task_list", json!({ "parked": true })).await;
    assert_eq!(listed_ids(&view), vec![root, child, grandchild]);
    assert_eq!(view["tasks"][0]["parked_reason"], "no movement");
    let e = h.call(&builder(), "task_list", json!({ "parked": true, "archived": true })).await.unwrap_err();
    assert_eq!(e.code(), "invalid_argument");

    // The claim gate refuses parked and folded tasks.
    for id in [root, grandchild] {
        let e = h.call(&builder(), "task_claim", json!({ "id": id })).await.unwrap_err();
        assert_eq!(reason(&e), "task_parked", "{e:?}");
    }
    let e = h.call(&builder(), "task_update", json!({ "id": child, "status": "doing" })).await.unwrap_err();
    assert_eq!(reason(&e), "task_parked");

    // A folded child is restored through its root.
    let e = h.act_err(&builder(), "queue_unpark", json!({ "task_id": child, "reason": "back" })).await;
    assert_eq!(e.code(), "conflict");
    // A child added after the park is folded in on its own.
    let late = h.task("Late child", Some(root)).await;
    let e =
        h.act_err(&builder(), "queue_fold", json!({ "task_id": late, "into": child, "reason": "x" })).await;
    assert_eq!(e.code(), "conflict", "fold only into a parked root");
    let e =
        h.act_err(&builder(), "queue_fold", json!({ "task_id": done, "into": root, "reason": "x" })).await;
    assert_eq!(e.code(), "conflict", "a finished task has nothing to fold");
    h.act_ok(&builder(), "queue_fold", json!({ "task_id": late, "into": root, "reason": "joined late" }))
        .await;
    let unrelated = h.task("Unrelated", None).await;
    let e = h
        .act_err(&builder(), "queue_fold", json!({ "task_id": unrelated, "into": root, "reason": "x" }))
        .await;
    assert_eq!(e.code(), "invalid_argument");

    let restored =
        h.act_ok(&builder(), "queue_unpark", json!({ "task_id": root, "reason": "picked up again" })).await;
    // Parents before children.
    assert_eq!(restored["restored"], json!([root, child, late, grandchild]));
    assert_eq!(h.n("SELECT COUNT(*) FROM tasks WHERE parked_at IS NOT NULL OR folded_into IS NOT NULL"), 0);
    let e = h.act_err(&builder(), "queue_unpark", json!({ "task_id": root, "reason": "again" })).await;
    assert_eq!(e.code(), "conflict");
    h.ok(&builder(), "task_claim", json!({ "id": child })).await;
    assert_eq!(h.events("agent.queue.unparked"), 1);
    assert_eq!(h.events("agent.queue.folded"), 1);
}

#[tokio::test]
async fn live_work_and_protected_rows_are_not_parked_silently() {
    let h = H::new();
    let busy = h.task("Being worked", None).await;
    h.ok(&builder(), "task_claim", json!({ "id": busy })).await;
    let e = h.act_err(&other(), "queue_park", json!({ "task_id": busy, "reason": "stale" })).await;
    assert_eq!(reason(&e), "task_live");

    let parent = h.task("Parent of live work", None).await;
    let kid = h.task("Live kid", Some(parent)).await;
    h.ok(&builder(), "task_claim", json!({ "id": kid })).await;
    let e = h.act_err(&other(), "queue_park", json!({ "task_id": parent, "reason": "stale" })).await;
    assert_eq!(reason(&e), "task_live");

    let gated = h.task("Waiting on a person", None).await;
    h.ok(&builder(), "task_update", json!({ "id": gated, "append_note": "[waiting-for: operator]" })).await;
    let e = h.act_err(&other(), "queue_park", json!({ "task_id": gated, "reason": "stale" })).await;
    assert_eq!(reason(&e), "protected_task");
    let v = h.act_ok(&human(), "queue_park", json!({ "task_id": gated, "reason": "stale" })).await;
    assert_eq!(v["approved_by"], "operator");
    assert_eq!(
        h.n(&format!("SELECT parked_reason = 'stale (approved by operator)' FROM tasks WHERE id = {gated}")),
        1
    );
    let e = h.act_err(&other(), "queue_park", json!({ "task_id": gated, "reason": "again" })).await;
    assert_eq!(e.code(), "conflict");

    // Closing a parked task ends the park; a finished task cannot be parked.
    h.ok(&builder(), "task_update", json!({ "id": gated, "status": "cancelled" })).await;
    assert_eq!(h.n(&format!("SELECT parked_at IS NULL FROM tasks WHERE id = {gated}")), 1);
    let e = h.act_err(&other(), "queue_park", json!({ "task_id": gated, "reason": "x" })).await;
    assert_eq!(e.code(), "conflict");

    // Research may read queue health but not park.
    h.act_ok(&researcher(), "queue_health", json!({})).await;
    let e = h.act_err(&researcher(), "queue_park", json!({ "task_id": busy, "reason": "x" })).await;
    assert_ne!(e.code(), "invalid_argument", "refused by the profile, not by validation: {e:?}");
}

#[tokio::test]
async fn the_sweep_proposes_and_health_counts_without_writing() {
    let h = H::new();
    let stale_root = h.task("Stale epic", None).await;
    let stale_child = h.task("Stale child", Some(stale_root)).await;
    let fresh = h.task("Fresh", None).await;
    let gated = h.task("Gated", None).await;
    h.ok(&builder(), "task_update", json!({ "id": gated, "append_note": "[waiting-for: review]" })).await;
    let tracking = h.task("Umbrella", None).await;
    h.ok(&builder(), "task_update", json!({ "id": tracking, "lane": "tracking" })).await;
    let parked_root = h.task("Already parked", None).await;
    h.act_ok(&builder(), "queue_park", json!({ "task_id": parked_root, "reason": "idle" })).await;
    let late = h.task("Late child of a parked root", Some(parked_root)).await;
    h.sql(&format!(
        "UPDATE tasks SET updated_at = '{old}', created_at = '{old}' WHERE id IN ({stale_root}, {stale_child}, {gated}, {tracking})",
        old = days_ago(40)
    ));

    let sweep = h.act_ok(&builder(), "queue_sweep", json!({})).await;
    assert_eq!(sweep["writes"], 0);
    let proposals: Vec<(i64, String)> = sweep["proposals"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| (p["task_id"].as_i64().unwrap(), p["proposed_action"].as_str().unwrap().to_string()))
        .collect();
    assert!(proposals.contains(&(late, "fold".into())), "{sweep}");
    assert!(proposals.contains(&(stale_root, "park".into())), "{sweep}");
    assert!(proposals.contains(&(stale_child, "fold".into())), "a stale child goes with its parent: {sweep}");
    assert!(!proposals.iter().any(|(id, _)| [fresh, gated, tracking].contains(id)), "{sweep}");
    let skipped: Vec<i64> =
        sweep["skipped"].as_array().unwrap().iter().map(|s| s["task_id"].as_i64().unwrap()).collect();
    assert!(skipped.contains(&gated) && skipped.contains(&tracking), "{sweep}");
    assert_eq!(sweep["counts"]["fold"], 2);
    assert_eq!(h.n("SELECT COUNT(*) FROM tasks WHERE parked_at IS NOT NULL"), 1, "the sweep writes nothing");

    let stale = h.act_ok(&builder(), "queue_stale", json!({ "limit": 2 })).await;
    assert_eq!(stale["total"], 4);
    assert_eq!(stale["truncated"], true);
    let fresh_window = h.act_ok(&builder(), "queue_stale", json!({ "stale_days": 60 })).await;
    assert_eq!(fresh_window["total"], 0);

    let health = h.act_ok(&builder(), "queue_health", json!({})).await;
    assert_eq!(health["parked"], 1);
    assert_eq!(health["parked_folded"], 0);
    assert_eq!(health["stale"], 4);
    assert_eq!(health["stale_actionable"], 2, "{health}");
    assert_eq!(health["open"], 6);
    let e = h.act_err(&builder(), "queue_health", json!({ "stale_days": 0 })).await;
    assert_eq!(e.code(), "invalid_argument");
}

#[tokio::test]
async fn health_reports_review_ready_milestones_and_ready_unowned_work() {
    let h = H::new();
    let a = h.task("Gate A", None).await;
    let b = h.task("Gate B", None).await;
    let m = h.task("Milestone", None).await;
    h.ok(
        &builder(),
        "task_update",
        json!({ "id": m, "append_note": format!("[milestone-review]\nGate: #{a}, #{b}. Later #{m}") }),
    )
    .await;
    let follow = h.task("Follow-up", None).await;
    h.ok(&builder(), "dependency_add", json!({ "task_id": follow, "depends_on_task_id": a })).await;

    let health = h.act_ok(&builder(), "queue_health", json!({})).await;
    assert_eq!(health["milestones"]["review_ready"], 0);
    assert_eq!(health["ready_unowned"], 0);
    for t in [a, b] {
        h.ok(&builder(), "task_update", json!({ "id": t, "status": "done" })).await;
    }
    let health = h.act_ok(&builder(), "queue_health", json!({})).await;
    assert_eq!(health["milestones_review_ready_unjudged"], 1, "{health}");
    assert_eq!(health["milestones"]["unjudged_ids"], json!([m]));
    assert_eq!(health["ready_unowned"], 1);
    h.ok(&builder(), "task_update", json!({ "id": m, "append_note": "VERDICT: pass" })).await;
    h.ok(&builder(), "task_update", json!({ "id": follow, "next_owner": "builder-2" })).await;
    let health = h.act_ok(&builder(), "queue_health", json!({})).await;
    assert_eq!(health["milestones"]["review_ready_unjudged"], 0);
    assert_eq!(health["milestones"]["review_ready"], 1);
    assert_eq!(health["ready_unowned"], 0);
}

// --- delegation stats ---------------------------------------------------------------

#[tokio::test]
async fn delegation_stats_count_states_and_latencies_per_agent() {
    let h = H::new();
    let t = h.task("Delegated", None).await;
    let (old, recent) = (days_ago(60), days_ago(2));
    let at = |hours: i64| {
        let base = jiff::Timestamp::now().checked_sub(jiff::SignedDuration::from_hours(48)).unwrap();
        ua_core::time::format_ts(base.checked_add(jiff::SignedDuration::from_hours(hours)).unwrap())
    };
    h.sql(&format!(
        "INSERT INTO delegations (from_agent, to_agent, task_id, task_spec, status, attempts, last_attempt_at, \
         created_at, updated_at, completed_at) VALUES \
         ('lead-1', 'builder-1', {t}, 's', 'completed', 1, '{c1}', '{recent}', '{recent}', '{d1}'), \
         ('lead-1', 'builder-1', {t}, 's', 'failed', 2, '{c1}', '{recent}', '{recent}', '{d2}'), \
         ('lead-1', 'builder-2', {t}, 's', 'pending', 0, NULL, '{recent}', '{recent}', NULL), \
         ('builder-1', 'builder-2', {t}, 's', 'in_flight', 1, '{c1}', '{recent}', '{recent}', NULL), \
         ('lead-1', 'builder-1', {t}, 's', 'completed', 1, NULL, '{old}', '{old}', '{old}')",
        c1 = at(1),
        d1 = at(2),
        d2 = at(4),
    ));
    let me = builder();
    let call = |params: Value| {
        h.call(&me, "observability_manage", json!({ "action": "delegation_stats", "params": params }))
    };
    let v = call(json!({})).await.unwrap();
    assert_eq!(v["total"], 4, "the 60-day-old row is outside the default window: {v}");
    assert_eq!(v["states"]["pending"], 1);
    assert_eq!(v["states"]["cancelled"], 0);
    let agents = v["agents"].as_array().unwrap();
    let b1 = agents.iter().find(|a| a["agent"] == "builder-1").unwrap();
    assert_eq!((b1["sent"].as_i64(), b1["received"].as_i64()), (Some(1), Some(2)));
    assert_eq!(b1["completion_rate"], 0.5);
    assert_eq!(b1["latency_seconds"]["completion"]["count"], 2);
    assert_eq!(b1["latency_seconds"]["completion"]["p50"], 7200);
    assert_eq!(b1["latency_seconds"]["completion"]["max"], 14400);
    assert_eq!(b1["latency_seconds"]["first_claim"]["count"], 1);
    let lead = agents.iter().find(|a| a["agent"] == "lead-1").unwrap();
    assert_eq!((lead["sent"].as_i64(), lead["received"].as_i64()), (Some(3), Some(0)));

    let v = call(json!({ "agent": "builder-2", "window_days": 90 })).await.unwrap();
    assert_eq!(v["total"], 2);
    assert_eq!(v["agents"].as_array().unwrap().len(), 1);
    assert_eq!(v["agents"][0]["open"], 2);
    let v = h
        .call(
            &builder(),
            "observability_manage",
            json!({ "action": "delegation_ledger", "params": { "window_days": 90 } }),
        )
        .await
        .unwrap();
    assert_eq!(v["total"], 5, "the Python name is an alias");
    assert_eq!(v["pairs"].as_array().unwrap().len(), 3);
}

#[tokio::test]
async fn a_large_handoff_note_keeps_the_packet_bounded() {
    let h = H::new();
    let sid = session(&h, &builder()).await;
    let item = "x".repeat(500);
    let many: Vec<String> = (0..20).map(|i| format!("{i}{item}")).collect();
    let note = h
        .act_ok(
            &builder(),
            "session_handoff_propose",
            json!({ "session_id": sid, "done": many, "next_steps": many, "open_questions": many }),
        )
        .await;
    h.act_ok(&builder(), "session_handoff_seal", json!({ "note_id": note["id"] })).await;
    let p = h.ok(&builder(), "session_packet", json!({ "session_id": sid })).await;
    assert!(p.to_string().len() <= 16_384, "{} bytes", p.to_string().len());
    assert_eq!(p["labels"]["truncated"], true);
    assert_eq!(p["handoff_note"]["id"], note["id"], "the note is trimmed before it is dropped");
}

// --- review regressions -------------------------------------------------------------

#[tokio::test]
async fn a_protected_park_needs_a_verified_operator_not_a_named_approver() {
    let h = H::new();
    let red = h.task("Rotate the red-tier keys", None).await;
    let lane = h.task("Human lane", None).await;
    h.ok(&builder(), "task_update", json!({ "id": lane, "lane": "operator-only" })).await;

    // Free text naming an approver is not authority, for any agent.
    for id in [red, lane] {
        let e = h
            .act_err(
                &builder(),
                "queue_park",
                json!({ "task_id": id, "reason": "idle", "approved_by": "operator" }),
            )
            .await;
        assert_eq!(reason(&e), "operator_required", "{e:?}");
        let e = h.act_err(&builder(), "queue_park", json!({ "task_id": id, "reason": "idle" })).await;
        assert_eq!(reason(&e), "protected_task");
    }
    // An unprotected row cannot carry a self-attested approval either.
    let plain = h.task("Plain", None).await;
    let e = h
        .act_err(
            &builder(),
            "queue_park",
            json!({ "task_id": plain, "reason": "idle", "approved_by": "operator" }),
        )
        .await;
    assert_eq!(reason(&e), "operator_required");
    assert_eq!(h.n("SELECT COUNT(*) FROM tasks WHERE parked_at IS NOT NULL"), 0);

    // A lifecycle operator parks; the approval recorded is its own identity
    // and approved_by rides along as a note.
    let v = h
        .act_ok(
            &lifecycle_op(),
            "queue_park",
            json!({ "task_id": red, "reason": "idle", "approved_by": "agreed in standup" }),
        )
        .await;
    assert_eq!(
        (v["approved_by"].as_str(), v["approval_note"].as_str()),
        (Some("lead-op"), Some("agreed in standup"))
    );
    assert_eq!(
        h.n(&format!(
            "SELECT parked_reason = 'idle (approved by lead-op: agreed in standup)' FROM tasks WHERE id = {red}"
        )),
        1
    );
    let v = h.act_ok(&human(), "queue_park", json!({ "task_id": lane, "reason": "idle" })).await;
    assert_eq!(v["approved_by"], "operator");
}

#[tokio::test]
async fn park_fold_and_unpark_need_writer_authority() {
    let h = H::new();
    // An unverified caller cannot park at all.
    let free = h.task("Nobody holds this", None).await;
    let e = h.act_err(&unverified(), "queue_park", json!({ "task_id": free, "reason": "idle" })).await;
    assert_eq!(reason(&e), "identity_required", "{e:?}");

    // A task someone else holds: only the holder or an operator parks it.
    let held = h.task("Next up for builder-2", None).await;
    h.ok(&builder(), "task_update", json!({ "id": held, "next_owner": "builder-2" })).await;
    let e = h.act_err(&builder(), "queue_park", json!({ "task_id": held, "reason": "idle" })).await;
    assert_eq!(reason(&e), "not_task_owner");
    h.act_ok(&other(), "queue_park", json!({ "task_id": held, "reason": "idle", "dry_run": true })).await;
    h.act_ok(&lifecycle_op(), "queue_park", json!({ "task_id": held, "reason": "idle", "dry_run": true }))
        .await;

    // A lapsed claim still names a holder.
    let lapsed = h.task("Claim lapsed", None).await;
    h.sql(&format!("UPDATE tasks SET claimed_by = 'builder-2' WHERE id = {lapsed}"));
    let e = h.act_err(&outsider(), "queue_park", json!({ "task_id": lapsed, "reason": "idle" })).await;
    assert_eq!(reason(&e), "not_task_owner");

    // An unowned root whose subtree holds someone else's task needs an operator.
    let root = h.task("Epic", None).await;
    let kid = h.task("Kid for builder-2", Some(root)).await;
    h.ok(&builder(), "task_update", json!({ "id": kid, "next_owner": "builder-2" })).await;
    let e = h.act_err(&builder(), "queue_park", json!({ "task_id": root, "reason": "idle" })).await;
    assert_eq!(reason(&e), "not_task_owner", "{e:?}");
    assert_eq!(h.n("SELECT COUNT(*) FROM tasks WHERE parked_at IS NOT NULL"), 0);
    let v = h.act_ok(&human(), "queue_park", json!({ "task_id": root, "reason": "idle" })).await;
    assert_eq!(v["folded"], json!([kid]));

    // Folding a held late child: the holder or an operator, not a bystander.
    let late = h.task("Late, for builder-2", Some(root)).await;
    h.ok(&builder(), "task_update", json!({ "id": late, "next_owner": "builder-2" })).await;
    let e =
        h.act_err(&builder(), "queue_fold", json!({ "task_id": late, "into": root, "reason": "late" })).await;
    assert_eq!(reason(&e), "not_task_owner");
    h.act_ok(&other(), "queue_fold", json!({ "task_id": late, "into": root, "reason": "late" })).await;

    // Unpark is judged on the root.
    h.act_ok(&human(), "queue_park", json!({ "task_id": held, "reason": "idle" })).await;
    let e = h.act_err(&builder(), "queue_unpark", json!({ "task_id": held, "reason": "back" })).await;
    assert_eq!(reason(&e), "not_task_owner");
    h.act_ok(&other(), "queue_unpark", json!({ "task_id": held, "reason": "back" })).await;
    // An unowned root is any queue writer's.
    h.act_ok(&builder(), "queue_unpark", json!({ "task_id": root, "reason": "back" })).await;
    assert_eq!(h.n("SELECT COUNT(*) FROM tasks WHERE parked_at IS NOT NULL"), 0);
}

#[tokio::test]
async fn only_the_owner_receiver_or_an_operator_recovers_a_handoff_note() {
    let h = H::new();
    let sid = session(&h, &builder()).await;
    let note = h
        .act_ok(
            &builder(),
            "session_handoff_propose",
            json!({ "session_id": sid, "done": ["a"], "next_steps": ["b"] }),
        )
        .await;
    let id = note["id"].as_i64().unwrap();
    h.act_ok(&builder(), "session_handoff_seal", json!({ "note_id": id })).await;

    let params = json!({ "session_id": sid });
    for who in [researcher(), other(), unverified()] {
        let e = h.act_err(&who, "session_handoff_recover", params.clone()).await;
        assert_eq!(e.code(), "not_found", "{} {e:?}", who.label);
    }
    // The same answer as for a session that does not exist.
    let e = h.act_err(&other(), "session_handoff_recover", json!({ "session_id": "no-such" })).await;
    assert_eq!(e.code(), "not_found");

    for who in [builder(), human(), lifecycle_op()] {
        let r = h.act_ok(&who, "session_handoff_recover", params.clone()).await;
        assert_eq!(r["note"]["id"], id, "{}", who.label);
    }
    // The receiver of an assigned note may read it.
    h.sql(&format!(
        "UPDATE session_handoff_notes SET state = 'assigned', assigned_to = 'builder-2' WHERE id = {id}"
    ));
    let r = h.act_ok(&other(), "session_handoff_recover", params.clone()).await;
    assert_eq!(r["note"]["id"], id);
    assert_eq!(h.act_err(&outsider(), "session_handoff_recover", params).await.code(), "not_found");
}

#[tokio::test]
async fn conversation_handoffs_need_a_verified_viewer_and_count_only_ledgered_links() {
    let h = H::new();
    h.ok(
        &builder(),
        "message_send",
        json!({ "act": "request", "to_agent": "builder-2", "body": "hi", "conversation_id": "conv-9" }),
    )
    .await;
    let params = json!({ "conversation_id": "conv-9" });
    let e = h.act_err(&unverified(), "conversation_handoffs", params.clone()).await;
    assert_eq!(reason(&e), "identity_required", "{e:?}");

    let real = h
        .act_ok(&builder(), "conversation_handoff", json!({ "conversation_id": "conv-9", "title": "Real" }))
        .await["task_id"]
        .as_i64()
        .unwrap();
    // A notes line typed by hand is not a handoff.
    let forged = h.task("Typed the marker", None).await;
    h.ok(
        &outsider(),
        "task_update",
        json!({ "id": forged, "append_note": "[conversation: conv-9] handed off from the agent conversation" }),
    )
    .await;

    let listed = h.act_ok(&other(), "conversation_handoffs", params.clone()).await;
    let ids = |key: &str| -> Vec<i64> {
        listed[key].as_array().unwrap().iter().map(|r| r["task_id"].as_i64().unwrap()).collect()
    };
    assert_eq!(ids("handoffs"), vec![real]);
    assert_eq!(ids("unaudited"), vec![forged]);
    assert_eq!(listed["handoffs"][0]["by"], "builder-1");
    assert_eq!(listed["handoffs"][0]["note_reference"], true);
    // The coordinator sees every conversation; an outsider sees none.
    let coord = caller("coord-1", ActorKind::Agent, Profile::Coordinator);
    h.act_ok(&coord, "conversation_handoffs", params.clone()).await;
    assert_eq!(h.act_err(&outsider(), "conversation_handoffs", params).await.code(), "not_found");
}

#[tokio::test]
async fn a_check_is_verified_only_against_the_bound_repo_a_full_head_and_its_job() {
    let ci = FakeCi::new(Verdict::Verified, Verdict::Verified);
    let h = H::with_ci(Some(ci.clone()));
    let t = h.task("Hardened", None).await;
    h.ok(&builder(), "task_claim", json!({ "id": t })).await;
    let record = |name: &str, head: &str, reference: Value| json!({ "task_id": t, "name": name, "outcome": "pass", "head_sha": head, "ref": reference });
    let run = |extra: Value| {
        let mut r = json!({ "kind": "ci_run", "ref": "77" });
        r.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
        r
    };

    // No binding: the reference is kept, never verified, and CI is not asked.
    let v = h
        .act_ok(&builder(), "task_check_record", record("ci", FULL, run(json!({ "repo": "example/repo" }))))
        .await;
    let c = check(&v, "ci");
    assert_eq!(
        (c["grade"].as_str(), c["verification"]["verdict"].as_str()),
        (Some("attested"), Some("unverifiable"))
    );
    assert!(c["verification"]["detail"].as_str().unwrap().contains("no bound repository"), "{c}");
    assert!(ci.calls.lock().unwrap().is_empty());

    h.bind("Example/Repo").await;
    // A caller-chosen repo is refused; an omitted one comes from the binding.
    let e = h
        .act_err(&builder(), "task_check_record", record("ci", FULL, run(json!({ "repo": "attacker/repo" }))))
        .await;
    assert_eq!(reason(&e), "repo_mismatch");
    let v = h.act_ok(&builder(), "task_check_record", record("ci", FULL, run(json!({})))).await;
    let c = check(&v, "ci");
    assert_eq!(
        (c["grade"].as_str(), c["ref"]["repo"].as_str()),
        (Some("verified"), Some("example/repo")),
        "{c}"
    );

    // An abbreviated head cannot carry a reference; a bare attestation still can.
    let e = h.act_err(&builder(), "task_check_record", record("ci", HEAD, run(json!({})))).await;
    assert_eq!(e.code(), "invalid_argument");
    h.act_ok(
        &builder(),
        "task_check_record",
        json!({ "task_id": t, "name": "lint", "outcome": "pass", "head_sha": HEAD }),
    )
    .await;

    // A check bound to a job: another job is refused; no job means that job.
    h.act_ok(
        &builder(),
        "task_workflow_set",
        json!({ "task_id": t, "expected_checks": ["lint", { "name": "tests", "job": "unit" }] }),
    )
    .await;
    let e = h
        .act_err(&builder(), "task_check_record", record("tests", FULL, run(json!({ "job": "lint" }))))
        .await;
    assert_eq!(reason(&e), "job_mismatch");
    ci.calls.lock().unwrap().clear();
    let v = h.act_ok(&builder(), "task_check_record", record("tests", FULL, run(json!({})))).await;
    let c = check(&v, "tests");
    assert_eq!((c["grade"].as_str(), c["verified_scope"].as_str()), (Some("verified"), Some("job")), "{c}");
    assert_eq!(c["ref"]["job"], "unit");
    assert!(ci.calls.lock().unwrap().contains(&"job 77 unit".to_string()), "{:?}", ci.calls.lock().unwrap());
    assert_eq!(v["expected_jobs"], json!({ "tests": "unit" }));

    // A binding set after recording is applied when the check is verified.
    h.act_ok(&builder(), "task_check_record", record("smoke", FULL, run(json!({ "job": "e2e" })))).await;
    h.act_ok(
        &builder(),
        "task_workflow_set",
        json!({ "task_id": t, "expected_checks": [{ "name": "smoke", "job": "smoke-suite" }] }),
    )
    .await;
    let v = h
        .act_ok(&other(), "task_check_verify", json!({ "task_id": t, "name": "smoke", "head_sha": FULL }))
        .await;
    let c = check(&v, "smoke");
    assert_eq!(
        (c["grade"].as_str(), c["verification"]["verdict"].as_str()),
        (Some("attested"), Some("unverifiable"))
    );

    // So is a binding moved to another repository.
    h.bind("example/other").await;
    let v = h
        .act_ok(&other(), "task_check_verify", json!({ "task_id": t, "name": "ci", "head_sha": FULL }))
        .await;
    assert_eq!(check(&v, "ci")["grade"], "attested");

    let e = h
        .act_err(
            &builder(),
            "task_workflow_set",
            json!({ "task_id": t, "expected_checks": [{ "name": "a", "job": "x" }, { "name": "a", "job": "y" }] }),
        )
        .await;
    assert_eq!(e.code(), "invalid_argument");
}
