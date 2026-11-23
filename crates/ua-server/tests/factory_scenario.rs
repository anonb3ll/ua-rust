//! The software factory acceptance scenario (`docs/software-factory.md`) as
//! runnable evidence, scored against a checked-in scorecard.
//!
//! One disposable in-process hub, one disposable git repository, and the
//! entry points agents and operators use: registered tools through the
//! governed `Registry::call` with `Caller` identities (the human built by
//! the hub's bearer-token identity check, the agents built directly), and
//! the HTTP event stream, opened with the outsider's bearer token, for the
//! stream check. The forge is a scripted CI verifier behind the hub's
//! verifier interface. Each sentence of the scenario's five
//! steps becomes one or more named checks, and every check ends in exactly
//! one status:
//!
//! - `pass`: the test drove the behaviour through an entry point and
//!   verified the effect in the hub's own records (ledger events, rows,
//!   responses) or in the disposable repository;
//! - `fail`: the product has the capability and got it wrong (the reason
//!   says how);
//! - `not-built`: the capability does not exist yet (the reason names what
//!   is missing).
//!
//! The expected scorecard is `tests/fixtures/factory_scenario.txt`. The test
//! fails when the actual scorecard differs from it in any line, a regression
//! or an improvement, and says which line to change. See
//! `docs/software-factory-status.md`.
//!
//! Run it with the scorecard printed:
//! `cargo test -p ua-server --test factory_scenario -- --nocapture`.

mod common;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use axum::body::Body;
use axum::http::{Response, StatusCode};
use common::{TestHub, get};
use http_body_util::BodyExt;
use rusqlite::OptionalExtension;
use secrecy::SecretString;
use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;
use ua_core::{ActorKind, Caller, Config, Profile, UaError, identity::Transport};
use ua_server::AppState;
use ua_server::auth::{caller_for, resolve_bearer_blocking};
use ua_tools::ci::{CiOutcome, CiRun, CiVerifier, Verdict, VerifyFuture};
use ua_tools::families::dispatch::reap_expired_leases;
use ua_tools::{Hub, builtin_registry};

// --- the scorecard ---------------------------------------------------------------------

const FIXTURE: &str = "tests/fixtures/factory_scenario.txt";

const STEPS: [&str; 5] = [
    "Plan and delegate",
    "Resume and review",
    "Approve and release",
    "Check isolation",
    "Verify independently",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Status {
    Pass,
    Fail,
    NotBuilt,
}

impl Status {
    fn as_str(self) -> &'static str {
        match self {
            Status::Pass => "pass",
            Status::Fail => "fail",
            Status::NotBuilt => "not-built",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        match s {
            "pass" => Some(Status::Pass),
            "fail" => Some(Status::Fail),
            "not-built" => Some(Status::NotBuilt),
            _ => None,
        }
    }
}

/// How one check ended: what was verified, or what went wrong or is missing.
enum Outcome {
    Pass(String),
    Fail(String),
    NotBuilt(String),
}

/// `Ok(how it was verified)` is a pass; `Err(what went wrong)` is a fail.
type Verified = Result<String, String>;

fn ensure(cond: bool, msg: impl Into<String>) -> Result<(), String> {
    if cond { Ok(()) } else { Err(msg.into()) }
}

struct Row {
    step: u8,
    id: &'static str,
    status: Status,
    note: String,
}

#[derive(Default)]
struct Card {
    rows: Vec<Row>,
}

impl Card {
    fn record(&mut self, step: u8, id: &'static str, outcome: Outcome) {
        assert!(!self.rows.iter().any(|r| r.id == id), "check {id} recorded twice");
        let (status, note) = match outcome {
            Outcome::Pass(n) => (Status::Pass, n),
            Outcome::Fail(n) => (Status::Fail, n),
            Outcome::NotBuilt(n) => (Status::NotBuilt, n),
        };
        self.rows.push(Row { step, id, status, note });
    }

    /// A check the test exercises: pass when verified, fail otherwise.
    fn check(&mut self, step: u8, id: &'static str, verified: Verified) {
        let outcome = match verified {
            Ok(how) => Outcome::Pass(how),
            Err(why) => Outcome::Fail(why),
        };
        self.record(step, id, outcome);
    }

    /// A check the product has nothing to exercise for yet.
    fn not_built(&mut self, step: u8, id: &'static str, why: &str) {
        self.record(step, id, Outcome::NotBuilt(why.to_string()));
    }

    fn render(&self) -> String {
        let mut out = String::from("\nSoftware factory scenario scorecard\n");
        for (i, name) in STEPS.iter().enumerate() {
            let step = (i + 1) as u8;
            out.push_str(&format!("\n{step}. {name}\n"));
            for r in self.rows.iter().filter(|r| r.step == step) {
                out.push_str(&format!("  {:<10} {}\n", r.status.as_str(), r.id));
                out.push_str(&format!("             {}\n", r.note));
            }
        }
        let count = |s: Status| self.rows.iter().filter(|r| r.status == s).count();
        out.push_str(&format!(
            "\n{} checks: {} pass, {} fail, {} not-built\n",
            self.rows.len(),
            count(Status::Pass),
            count(Status::Fail),
            count(Status::NotBuilt)
        ));
        out
    }

    /// Every difference from the fixture, with the line to change.
    fn ratchet(&self, fixture: &str) -> Vec<String> {
        let mut expected: BTreeMap<String, (u8, Status)> = BTreeMap::new();
        let mut problems = Vec::new();
        for (n, line) in fixture.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let parts: Vec<&str> = line.split_whitespace().collect();
            let parsed = match parts.as_slice() {
                [step, id, status] => {
                    step.parse::<u8>().ok().zip(Status::parse(status)).map(|(s, st)| (id, s, st))
                }
                _ => None,
            };
            let Some((id, step, status)) = parsed else {
                problems.push(format!("{FIXTURE}:{}: cannot read `{line}`", n + 1));
                continue;
            };
            if expected.insert(id.to_string(), (step, status)).is_some() {
                problems.push(format!("{FIXTURE}:{}: check {id} is listed twice", n + 1));
            }
        }
        for r in &self.rows {
            let line = format!("{} {} {}", r.step, r.id, r.status.as_str());
            match expected.remove(r.id) {
                None => problems.push(format!("new check {}: add the line `{line}` to {FIXTURE}", r.id)),
                Some((step, status)) if step == r.step && status == r.status => {}
                Some((step, status)) => {
                    let old = format!("{step} {} {}", r.id, status.as_str());
                    problems.push(if status == Status::Pass {
                        format!(
                            "REGRESSION: {} is `{old}` in {FIXTURE} but is now {} ({}); fix the product. A line \
                             moves away from pass only to correct an overstated check, in a change whose message \
                             says it corrects the scorecard, never to accommodate a product regression",
                            r.id,
                            r.status.as_str(),
                            r.note
                        )
                    } else if r.status == Status::Pass {
                        format!(
                            "improvement: {} passes now; change `{old}` to `{line}` in {FIXTURE} in the same change ({})",
                            r.id, r.note
                        )
                    } else {
                        format!("{} changed status: change `{old}` to `{line}` in {FIXTURE} ({})", r.id, r.note)
                    });
                }
            }
        }
        for (id, (step, status)) in expected {
            problems.push(format!(
                "check {id} is in {FIXTURE} (`{step} {id} {}`) but the test no longer records it",
                status.as_str()
            ));
        }
        problems
    }
}

// --- identities -------------------------------------------------------------------------

fn caller(label: &str, kind: ActorKind, profile: Profile, transport: Transport) -> Caller {
    Caller {
        label: label.into(),
        kind,
        profile,
        enforce_profile: true,
        session_key: Some(format!("{label}-session")),
        transport,
        org_id: ua_core::DEFAULT_ORG.into(),
    }
}

/// Plans and delegates, and runs the merge (there is no separate release
/// agent).
fn lead() -> Caller {
    caller("lead-1", ActorKind::Agent, Profile::Coordinator, Transport::Mcp)
}

/// The first harness: implements the change.
fn builder() -> Caller {
    caller("builder-1", ActorKind::Agent, Profile::Developer, Transport::Mcp)
}

/// The second harness: resumes and reviews. Its calls are in-process
/// registry calls like everyone's; only the transport label differs.
fn reviewer() -> Caller {
    caller("builder-2", ActorKind::Agent, Profile::Developer, Transport::Http)
}

/// A dispatched worker.
fn worker() -> Caller {
    caller("worker-1", ActorKind::Agent, Profile::Developer, Transport::Mcp)
}

/// A verified agent in the same organization with no access to the
/// restricted records.
fn outsider() -> Caller {
    caller("builder-3", ActorKind::Agent, Profile::Developer, Transport::Mcp)
}

/// The auditor: a coordinator agent (the manifest tools need that profile).
fn auditor() -> Caller {
    caller("auditor-1", ActorKind::Agent, Profile::Coordinator, Transport::Mcp)
}

/// The verified human approver, as the hub's own identity check built it
/// from the human's bearer token ([`Scenario::new`]).
static HUMAN: OnceLock<Caller> = OnceLock::new();

fn human() -> Caller {
    HUMAN.get().expect("the scenario resolves the human first").clone()
}

/// An unverified caller that names the human's label.
fn unverified() -> Caller {
    Caller::local("operator", Transport::Mcp)
}

const OUTSIDER_TOKEN: &str = "builder-3-scenario-token-0001";
const HUMAN_TOKEN: &str = "operator-scenario-token-0002";
const REPO: &str = "example/widgets";
const OTHER_REPO: &str = "example/other";
/// A full head no commit has.
const OTHER_HEAD: &str = "0123456789abcdef0123456789abcdef01234567";
const MARKERS: [&str; 3] = ["hidden-marker-mailbox", "hidden-marker-handoff", "hidden-marker-note"];

const SPEC: &str = "\
### Objective
Add a changelog generator to the release script.

### Scope
- scripts/changelog.sh

### Definition of Done
- Running the generator on a tagged history writes CHANGELOG.md with one section per tag
- Running it with no tags is refused with an error naming the missing tag
- Gates: the test suite, lint, format check and a review pass

### TDD Constraints
- Stub: none

### Boundaries
- Do not change the release tag format
";

fn reason(e: &UaError) -> String {
    e.reason_code().map(str::to_string).unwrap_or_else(|| e.code().to_string())
}

// --- the disposable environment -------------------------------------------------------

/// A directory under the system temp dir, removed on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let nanos =
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_nanos());
        let dir = std::env::temp_dir().join(format!("ua-factory-{name}-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir.canonicalize().unwrap())
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// `git` in `dir` and nowhere else: every inherited `GIT_*` variable is
/// dropped (inside a git hook, `GIT_DIR`, `GIT_WORK_TREE` or
/// `GIT_INDEX_FILE` would point at the developer's repository), and system
/// and global config are ignored.
fn git_cmd(dir: &Path) -> Command {
    let mut cmd = Command::new("git");
    for (k, _) in std::env::vars_os() {
        if k.to_string_lossy().starts_with("GIT_") {
            cmd.env_remove(&k);
        }
    }
    cmd.current_dir(dir).env("GIT_CONFIG_NOSYSTEM", "1").env("GIT_CONFIG_GLOBAL", "/dev/null");
    cmd
}

fn git(dir: &Path, args: &[&str]) -> String {
    let out = git_cmd(dir).args(args).output().expect("git is required by the factory scenario");
    assert!(out.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&out.stderr));
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

fn commit_file(dir: &Path, file: &str, content: &str, message: &str) -> String {
    std::fs::write(dir.join(file), content).unwrap();
    git(dir, &["add", file]);
    git(dir, &["commit", "-q", "-m", message]);
    git(dir, &["rev-parse", "HEAD"])
}

fn init_repo(dir: &Path) {
    git(dir, &["init", "-q", "-b", "main"]);
    for (k, v) in [
        ("user.name", "builder-1"),
        ("user.email", "builder-1@example.com"),
        ("commit.gpgsign", "false"),
        ("core.hooksPath", "/dev/null"),
    ] {
        git(dir, &["config", k, v]);
    }
    commit_file(dir, ".gitignore", ".worktrees/\n", "chore: initial commit");
}

/// A CI verifier that confirms every run and job it is asked about, standing
/// in for the forge behind the hub's verifier interface.
struct ScriptedCi;

impl CiVerifier for ScriptedCi {
    fn verify_run<'a>(&'a self, run: &'a CiRun) -> VerifyFuture<'a> {
        let head = run.head_sha.clone();
        Box::pin(async move {
            CiOutcome::new(Verdict::Verified, "run looked up").observed(json!({ "head_sha": head }))
        })
    }

    fn verify_job<'a>(&'a self, _run: &'a CiRun, job: &'a str) -> VerifyFuture<'a> {
        Box::pin(
            async move { CiOutcome::new(Verdict::Verified, "job looked up").observed(json!({ "job": job })) },
        )
    }
}

/// One ledger row as stored.
#[derive(Debug, Clone)]
struct Ev {
    seq: i64,
    channel: String,
    originator: Option<String>,
    payload: Value,
}

struct Scenario {
    th: TestHub,
    ws: PathBuf,
    _home: Scratch,
    _ws: Scratch,
}

impl Scenario {
    fn new() -> Self {
        let home = Scratch::new("home");
        let ws = Scratch::new("ws");
        init_repo(&ws.0);
        let mut cfg = Config::for_home(&home.0);
        cfg.workspace = Some(ws.0.clone());
        cfg.public_url = Some(common::BASE.into());
        cfg.enforce_auth = true;
        cfg.human_identities = vec!["operator".into()];
        cfg.agent_tokens =
            Some(SecretString::from(format!("builder-3:{OUTSIDER_TOKEN},operator:{HUMAN_TOKEN}")));
        // A profile is a tool list, not authority: the human's authority
        // comes from its identity. The coordinator list has every tool.
        cfg.profiles.insert("operator".into(), "coordinator".into());
        // The forge is replaced by a scripted CI verifier, as the continuity
        // tests do; every other part of the hub is the real one.
        let hub = Hub::in_memory(cfg).unwrap().with_ci_verifier(Arc::new(ScriptedCi));
        let state = AppState::new(hub, Arc::new(builtin_registry()));
        let app = ua_server::router(state.clone(), CancellationToken::new());
        let th = TestHub { state, app };
        // The human, built by the hub's own bearer-token identity check.
        let id = resolve_bearer_blocking(&th.state, HUMAN_TOKEN, "/api/tools/call")
            .expect("the human's token resolves");
        assert_eq!(id.kind, ActorKind::Human, "the operator token resolves to a human");
        let human = caller_for(&th.state, &id, Some("operator-session".into()), Transport::Http);
        let _ = HUMAN.set(human);
        Self { th, ws: ws.0.clone(), _home: home, _ws: ws }
    }

    fn hub(&self) -> &Hub {
        &self.th.state.hub
    }

    async fn call(&self, who: &Caller, tool: &str, args: Value) -> Result<Value, UaError> {
        self.th.state.registry.call(self.hub(), who, tool, args).await
    }

    async fn ok(&self, who: &Caller, tool: &str, args: Value) -> Result<Value, String> {
        self.call(who, tool, args.clone()).await.map_err(|e| format!("{tool}({args}) as {}: {e}", who.label))
    }

    async fn act(&self, who: &Caller, action: &str, params: Value) -> Result<Value, UaError> {
        self.call(who, "coordination_manage", json!({ "action": action, "params": params })).await
    }

    async fn act_ok(&self, who: &Caller, action: &str, params: Value) -> Result<Value, String> {
        self.act(who, action, params.clone())
            .await
            .map_err(|e| format!("{action}({params}) as {}: {e}", who.label))
    }

    /// A setup call the scenario cannot continue without.
    async fn must(&self, who: &Caller, tool: &str, args: Value) -> Value {
        self.ok(who, tool, args).await.unwrap_or_else(|e| panic!("scenario setup failed: {e}"))
    }

    async fn must_act(&self, who: &Caller, action: &str, params: Value) -> Value {
        self.act_ok(who, action, params).await.unwrap_or_else(|e| panic!("scenario setup failed: {e}"))
    }

    /// Call an always-gated tool: park it, approve it as the human, retry.
    async fn gated(&self, who: &Caller, tool: &str, args: Value) -> Result<Value, String> {
        let approval_id = match self.call(who, tool, args.clone()).await {
            Err(UaError::ApprovalRequired { approval_id, .. }) => approval_id,
            other => return Err(format!("{tool} did not park for approval: {other:?}")),
        };
        self.ok(&human(), "approval_resolve", json!({ "id": approval_id, "decision": "approve" })).await?;
        self.ok(who, tool, args).await
    }

    fn sql(&self, stmt: &str) {
        let stmt = stmt.to_string();
        self.hub().db().write(move |tx| Ok(tx.execute_batch(&stmt)?)).unwrap();
    }

    fn text(&self, q: &str) -> Option<String> {
        let q = q.to_string();
        self.hub()
            .db()
            .read(move |c| {
                let row = c
                    .query_row(&q, [], |r| {
                        Ok(match r.get_ref(0)? {
                            rusqlite::types::ValueRef::Null => None,
                            rusqlite::types::ValueRef::Integer(n) => Some(n.to_string()),
                            rusqlite::types::ValueRef::Text(t) => {
                                Some(String::from_utf8_lossy(t).into_owned())
                            }
                            other => Some(format!("{other:?}")),
                        })
                    })
                    .optional()?;
                Ok(row.flatten())
            })
            .unwrap()
    }

    /// Ledger rows after `seq`, in commit order.
    fn ledger_after(&self, seq: i64) -> Vec<Ev> {
        self.hub()
            .db()
            .read(move |c| {
                let mut stmt = c.prepare(
                    "SELECT seq, channel, originator, payload FROM event_log WHERE seq > ?1 ORDER BY seq",
                )?;
                let rows = stmt.query_map([seq], |r| {
                    let payload: String = r.get(3)?;
                    Ok(Ev {
                        seq: r.get(0)?,
                        channel: r.get(1)?,
                        originator: r.get(2)?,
                        payload: serde_json::from_str(&payload).unwrap_or(Value::String(payload)),
                    })
                })?;
                Ok(rows.collect::<Result<Vec<_>, _>>()?)
            })
            .unwrap()
    }

    fn ledger(&self) -> Vec<Ev> {
        self.ledger_after(0)
    }

    fn last_seq(&self) -> i64 {
        self.ledger().last().map_or(0, |e| e.seq)
    }

    fn tool_call_outcome(&self, tool: &str) -> Option<String> {
        self.text(&format!("SELECT outcome FROM tool_calls WHERE tool = '{tool}' ORDER BY id DESC LIMIT 1"))
    }

    /// The audit-record check for a refused call made after `mark`, under
    /// approval `approval` (a policy authorization id).
    ///
    /// The criterion, whatever the event is called: a ledger row appended
    /// after `mark` by the refused caller that names this approval
    /// (`authorization_id` or `approval_id`) and carries a non-empty reason
    /// (`reason` or `reason_code`). A row that names another approval, or no
    /// reason, does not count.
    /// `approval` names the decision the refused call presented, in its own
    /// id space: [`Grant::Authorization`] for a policy authorization
    /// (`authorization_id` on the event), [`Grant::Approval`] for a one-time
    /// approval (`approval_id`). The two are separate tables, so an id of one
    /// never counts for the other.
    fn refusal_audited(&self, mark: i64, caller: &str, approval: Grant, what: &str) -> Verified {
        let rows = self.ledger_after(mark);
        let (key, approval) = match approval {
            Grant::Authorization(id) => ("authorization_id", id),
            Grant::Approval(id) => ("approval_id", id),
        };
        let audited = rows.iter().find(|e| {
            let p = &e.payload;
            let names = p[key] == approval;
            let why = ["reason", "reason_code"]
                .iter()
                .any(|k| p[*k].as_str().is_some_and(|s| !s.trim().is_empty()));
            e.originator.as_deref() == Some(caller) && names && why
        });
        match audited {
            Some(ev) => Ok(format!(
                "the refused {what} is ledger event {} ({}), naming approval {approval} and the reason: {}",
                ev.seq, ev.channel, ev.payload
            )),
            None => Err(format!(
                "scored: an audited refusal. The refused {what} appends no ledger row naming approval {approval} \
                 and a reason (rows appended since: {:?}); the only record is a tool_calls row with outcome {:?}, \
                 which names neither the approval nor the reason and is not hash-chained",
                rows.iter().map(|e| e.channel.as_str()).collect::<Vec<_>>(),
                self.tool_call_outcome("git_merge_task")
            )),
        }
    }
}

/// Which decision a refused call presented, by id space.
#[derive(Debug, Clone, Copy)]
enum Grant {
    /// A policy authorization (`policy_authorizations`).
    Authorization(i64),
    /// A one-time approval (`approvals`).
    Approval(i64),
}

/// The scenario's state as the steps hand it on.
#[derive(Default)]
struct Ctx {
    task: i64,
    head: String,
    worktree: String,
    branch: String,
    builder_session: String,
    decision_old: String,
    decision_new: String,
    constraint: String,
    unrelated: String,
    authorization: i64,
    release_commit: String,
}

fn check_of<'a>(view: &'a Value, name: &str) -> Option<&'a Value> {
    view["checks"].as_array()?.iter().find(|c| c["name"] == name)
}

// --- step 1: plan and delegate ----------------------------------------------------------

async fn plan_and_delegate(s: &Scenario, card: &mut Card, cx: &mut Ctx) {
    // A lead delegates the task; the first harness accepts it.
    let delegated = s.must(&lead(), "delegate", json!({ "task_spec": SPEC, "to_agent": "builder-1" })).await;
    cx.task = delegated["task_id"].as_i64().unwrap();
    let delegation = delegated["delegation_id"].as_i64().unwrap();
    let claimed = s.ok(&builder(), "delegate_claim", json!({ "id": delegation })).await;
    card.check(
        1,
        "delegate.task-delegated-to-first-harness",
        (|| {
            let claimed = claimed?;
            ensure(claimed["claimed"] == true, format!("delegate_claim did not claim: {claimed}"))?;
            ensure(claimed["delegation"]["status"] == "in_flight", format!("{claimed}"))?;
            let ev = s
                .ledger()
                .into_iter()
                .find(|e| e.channel == "agent.delegation.created" && e.payload["task_id"] == cx.task)
                .ok_or("no agent.delegation.created event for the task")?;
            ensure(ev.originator.as_deref() == Some("lead-1"), format!("{ev:?}"))?;
            Ok(format!(
                "delegate created task {} for builder-1 (ledger seq {}); delegate_claim moved it to in_flight",
                cx.task, ev.seq
            ))
        })(),
    );
    card.not_built(
        1,
        "delegate.team-accepts-task",
        "teams do not exist: a task is delegated to and claimed by one agent, never accepted by a team",
    );

    // Planning decisions and a constraint, one of them later superseded.
    let save = |content: &str, title: &str, extra: Value| {
        let mut args =
            json!({ "title": title, "content": content, "evidence": [format!("task:{}", cx.task)] });
        args.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
        args
    };
    cx.decision_old = s
        .must(
            &lead(),
            "memory_save",
            save(
                "Decision: the changelog generator writes its release notes to CHANGES.txt.",
                "Changelog generator output",
                json!({}),
            ),
        )
        .await["id"]
        .as_str()
        .unwrap()
        .to_string();
    cx.decision_new = s
        .must(
            &lead(),
            "memory_save",
            save(
                "Decision: the changelog generator writes its release notes to CHANGELOG.md, one section per tag.",
                "Changelog generator output (revised)",
                json!({ "supersedes": cx.decision_old }),
            ),
        )
        .await["id"]
        .as_str()
        .unwrap()
        .to_string();
    cx.constraint = s
        .must(
            &lead(),
            "memory_save",
            save(
                "Constraint: the release script and its changelog generator never call the network.",
                "Release script constraint",
                json!({}),
            ),
        )
        .await["id"]
        .as_str()
        .unwrap()
        .to_string();
    // A note about something else, which a context pack for this task leaves out.
    cx.unrelated = s
        .must(
            &lead(),
            "memory_save",
            json!({ "title": "Terminal fonts", "content": "Prefer a monospace font in terminals." }),
        )
        .await["id"]
        .as_str()
        .unwrap()
        .to_string();

    // The first harness implements the change on a task branch.
    cx.branch = format!("task-{}", cx.task);
    cx.worktree = format!(".worktrees/{}", cx.branch);
    s.must(&builder(), "git_worktree_add", json!({ "path": cx.worktree, "branch": cx.branch })).await;
    let wt = s.ws.join(&cx.worktree);
    cx.head = commit_file(
        &wt,
        "CHANGELOG.md",
        "# Changelog\n\n## v1.0.0\n- first release\n",
        "feat: add changelog generator",
    );
    let claim = s
        .ok(
            &builder(),
            "task_claim",
            json!({ "id": cx.task, "worktree_path": cx.worktree, "branch": cx.branch }),
        )
        .await;
    let workflow = s
        .act_ok(
            &builder(),
            "task_workflow_set",
            json!({ "task_id": cx.task, "stage": "implement", "goal": "a changelog generator",
                    "head_sha": cx.head, "expected_checks": ["review", "tests"] }),
        )
        .await;
    card.check(
        1,
        "delegate.task-claimed-with-review-requirement",
        (|| {
            let claim = claim?;
            ensure(claim["claimed_by"] == "builder-1" && claim["status"] == "doing", format!("{claim}"))?;
            ensure(claim["branch"] == cx.branch.as_str(), format!("the claim lost the branch: {claim}"))?;
            let w = workflow?;
            ensure(w["expected_checks"] == json!(["review", "tests"]), format!("{w}"))?;
            ensure(w["head_sha"] == cx.head.as_str(), format!("{w}"))?;
            let review = check_of(&w, "review").ok_or("no review entry in the workflow view")?;
            ensure(review["grade"] == "unknown", format!("an unrecorded review must read unknown: {review}"))?;
            Ok(format!(
                "task_claim holds the task for builder-1 on {}; task_workflow_set records head {} with expected \
                 checks review and tests, and the review reads unknown until recorded (enforced at merge; see \
                 release.requires-review-at-head)",
                cx.branch,
                &cx.head[..12]
            ))
        })(),
    );

    // Tests pass at the head; the builder hands off to the reviewer.
    s.must_act(
        &builder(),
        "task_check_record",
        json!({ "task_id": cx.task, "name": "tests", "outcome": "pass", "head_sha": cx.head }),
    )
    .await;
    let sent = s
        .ok(
            &builder(),
            "message_send",
            json!({ "act": "handoff", "to_agent": "builder-2", "task_id": cx.task, "body": "Ready for review.",
                    "handoff": { "done": ["changelog generator", "tests pass"], "next_action": "review the generator",
                                 "reviewed_head_sha": cx.head, "repo": REPO } }),
        )
        .await;
    card.check(
        1,
        "delegate.handoff-tied-to-revision",
        (|| {
            sent?;
            let ev = s
                .ledger()
                .into_iter()
                .find(|e| e.channel == "agent.message.handoff" && e.payload["task_id"] == cx.task)
                .ok_or("no agent.message.handoff event for the task")?;
            ensure(
                ev.payload["handoff"]["reviewed_head_sha"] == cx.head.as_str(),
                format!("{:?}", ev.payload),
            )?;
            ensure(ev.originator.as_deref() == Some("builder-1"), format!("{ev:?}"))?;
            Ok(format!(
                "message_send(act=handoff) is ledger event {} naming task {} and reviewed_head_sha {}",
                ev.seq,
                cx.task,
                &cx.head[..12]
            ))
        })(),
    );

    // The builder's own session closes with a sealed handoff note.
    let session = s
        .must(
            &builder(),
            "session_start",
            json!({ "kind": "interactive", "task_id": cx.task, "meta": { "harness": "harness-a" } }),
        )
        .await;
    cx.builder_session = session["session_id"].as_str().unwrap().to_string();
    let sealed = async {
        let note = s
            .act_ok(
                &builder(),
                "session_handoff_propose",
                json!({ "session_id": cx.builder_session, "done": ["changelog generator"], "next_steps": ["review"] }),
            )
            .await?;
        s.act_ok(&builder(), "session_handoff_seal", json!({ "note_id": note["id"] })).await
    }
    .await;
    card.check(
        1,
        "delegate.session-handoff-sealed",
        (|| {
            let sealed = sealed?;
            ensure(sealed["state"] == "sealed", format!("{sealed}"))?;
            let ev = s
                .ledger()
                .into_iter()
                .find(|e| {
                    e.channel == "agent.lifecycle.handoff"
                        && e.payload["state"] == "sealed"
                        && e.payload["task_id"] == cx.task
                })
                .ok_or("no sealed agent.lifecycle.handoff event for the task")?;
            Ok(format!(
                "session_handoff_seal sealed note {} for task {} (ledger seq {})",
                sealed["id"], cx.task, ev.seq
            ))
        })(),
    );

    // The change is a deliverable of the task, and its commit a recorded
    // revision in the project's bound repository.
    s.must_act(&human(), "project_repo_bind", json!({ "project": "default", "repo": REPO })).await;
    let recorded = async {
        let made = s
            .ok(
                &builder(),
                "deliverable_create",
                json!({ "task_id": cx.task, "title": "changelog generator" }),
            )
            .await?;
        let id = made["deliverable"]["id"].clone();
        let rev = s
            .ok(
                &builder(),
                "deliverable_revise",
                json!({ "deliverable_id": id, "commit": cx.head, "summary": "first version" }),
            )
            .await?;
        let wf = s.act_ok(&builder(), "task_workflow_get", json!({ "task_id": cx.task })).await?;
        Ok::<_, String>((made, rev, wf))
    }
    .await;
    card.check(
        1,
        "delegate.deliverable-revision-object",
        (|| {
            let (made, rev, wf) = recorded?;
            ensure(made["created"] == true && made["deliverable"]["task_id"] == cx.task, format!("{made}"))?;
            ensure(made["deliverable"]["repo"] == REPO, format!("the deliverable lost the binding: {made}"))?;
            let d = made["deliverable"]["id"].as_i64().ok_or("no deliverable id")?;
            let r = &rev["revision"];
            ensure(rev["recorded"] == true && r["rev_no"] == 1, format!("{rev}"))?;
            ensure(r["commit"] == cx.head.as_str() && r["producer"] == "builder-1", format!("{rev}"))?;
            let rid = r["id"].as_i64().ok_or("no revision id")?;
            let row = s
                .text(&format!(
                    "SELECT identity || ' ' || repo || ' ' || org_id FROM deliverable_revisions \
                     WHERE id = {rid} AND deliverable_id = {d} AND rev_no = 1"
                ))
                .ok_or("no deliverable_revisions row for the revision")?;
            ensure(row == format!("{} {REPO} default", cx.head), format!("the stored revision is {row}"))?;
            let ev = s
                .ledger()
                .into_iter()
                .find(|e| e.channel == "agent.deliverable.revised" && e.payload["revision_id"] == rid)
                .ok_or("no agent.deliverable.revised event for the revision")?;
            ensure(
                ev.payload["identity"] == cx.head.as_str()
                    && ev.payload["deliverable_id"] == d
                    && ev.payload["task_id"] == cx.task
                    && ev.originator.as_deref() == Some("builder-1"),
                format!("{ev:?}"),
            )?;
            ensure(wf["head_sha"] == cx.head.as_str(), format!("the workflow head is not the revision: {wf}"))?;
            ensure(rev["latest_is_workflow_head"] == true, format!("{rev}"))?;
            Ok(format!(
                "deliverable_create attaches deliverable {d} in {REPO} to task {}; deliverable_revise records {} as \
                 its revision 1 (row {rid}, ledger event {}), and the task's workflow head is that commit",
                cx.task,
                &cx.head[..12],
                ev.seq
            ))
        })(),
    );
}

// --- step 2: resume and review ----------------------------------------------------------

async fn resume_and_review(s: &Scenario, card: &mut Card, cx: &mut Ctx) {
    // The first harness lets go and hands the task to the reviewer's lane;
    // the second harness opens the same task.
    s.must(&builder(), "task_update", json!({ "id": cx.task, "release_claim": true })).await;
    s.must(
        &builder(),
        "task_update",
        json!({ "id": cx.task, "next_owner": "builder-2", "lane": "builder-2" }),
    )
    .await;
    let claim = s.ok(&reviewer(), "task_claim", json!({ "id": cx.task })).await;
    let session = s
        .must(
            &reviewer(),
            "session_start",
            json!({ "kind": "review", "task_id": cx.task, "meta": { "harness": "harness-b" } }),
        )
        .await;
    let sid = session["session_id"].as_str().unwrap().to_string();
    let packet = s.ok(&reviewer(), "session_packet", json!({ "session_id": sid })).await;
    let packet = match packet {
        Ok(p) => p,
        Err(e) => panic!("scenario setup failed: {e}"),
    };
    card.check(
        2,
        "review.second-harness-opens-same-task",
        (|| {
            let claim = claim?;
            ensure(claim["claimed_by"] == "builder-2", format!("{claim}"))?;
            ensure(
                packet["task"]["id"] == cx.task,
                format!("the packet is for another task: {}", packet["task"]),
            )?;
            ensure(packet["task"]["branch"] == cx.branch.as_str(), format!("{}", packet["task"]))?;
            ensure(packet["workflow"]["stage"] == "implement", format!("{}", packet["workflow"]))?;
            Ok(format!(
                "builder-2 (an in-process caller labelled with the HTTP transport) claims task {}; its \
                 session_packet names the same task, branch {} and the workflow record",
                cx.task, cx.branch
            ))
        })(),
    );
    card.check(
        2,
        "review.packet-carries-handoff-at-revision",
        (|| {
            let h = &packet["prior_handoff"];
            ensure(h["from_agent"] == "builder-1", format!("prior_handoff: {h}"))?;
            ensure(h["handoff"]["reviewed_head_sha"] == cx.head.as_str(), format!("prior_handoff: {h}"))?;
            Ok("the packet's prior_handoff is builder-1's typed handoff with the reviewed head".into())
        })(),
    );
    let cited = |id: &str| packet["memory"].as_array().into_iter().flatten().find(|m| m["id"] == id).cloned();
    card.check(
        2,
        "review.packet-cites-decisions-and-constraints",
        (|| {
            let decision = cited(&cx.decision_new).ok_or(format!("the current decision is missing: {}", packet["memory"]))?;
            let constraint = cited(&cx.constraint).ok_or(format!("the constraint is missing: {}", packet["memory"]))?;
            let source = json!([format!("task:{}", cx.task)]);
            for row in [&decision, &constraint] {
                let evidence: Value = match &row["evidence"] {
                    Value::String(t) => serde_json::from_str(t).unwrap_or(Value::Null),
                    other => other.clone(),
                };
                ensure(evidence == source, format!("a cited note does not name its source: {row}"))?;
            }
            ensure(cited(&cx.unrelated).is_none(), "the packet carries an unrelated note, so it is not selective")?;
            Ok(format!(
                "the packet's memory section cites decision {} and constraint {}, each with its id and evidence \
                 task:{}, and leaves out an unrelated note",
                cx.decision_new, cx.constraint, cx.task
            ))
        })(),
    );
    card.check(
        2,
        "review.packet-excludes-superseded-decision",
        (|| {
            ensure(cited(&cx.decision_old).is_none(), "the superseded decision is offered as current")?;
            Ok(format!("the superseded decision {} is not in the packet's memory section", cx.decision_old))
        })(),
    );
    let marked = packet.to_string().contains(&cx.decision_old)
        || cited(&cx.decision_new).is_some_and(|m| m.get("supersedes").is_some());
    card.record(
        2,
        "review.packet-marks-superseded-decision",
        if marked {
            Outcome::Pass("the packet names the superseded decision".into())
        } else {
            Outcome::NotBuilt(
                "the session packet drops a superseded decision silently; no context pack cites it as superseded \
                 or says what replaced it"
                    .into(),
            )
        },
    );
    let old = s.ok(&reviewer(), "memory_get", json!({ "id": cx.decision_old })).await;
    let new = s.ok(&reviewer(), "memory_get", json!({ "id": cx.decision_new })).await;
    card.check(
        2,
        "review.superseded-decision-identifiable",
        (|| {
            let (old, new) = (old?, new?);
            ensure(old["superseded_by"] == cx.decision_new.as_str(), format!("{old}"))?;
            ensure(new["supersedes"] == json!([cx.decision_old]), format!("{new}"))?;
            Ok("memory_get on the cited decision shows supersedes, and on the old one superseded_by".into())
        })(),
    );

    // Checks are read at the exact head under review.
    let at_head =
        s.act_ok(&reviewer(), "task_workflow_get", json!({ "task_id": cx.task, "head_sha": cx.head })).await;
    let elsewhere = s
        .act_ok(&reviewer(), "task_workflow_get", json!({ "task_id": cx.task, "head_sha": OTHER_HEAD }))
        .await;
    let review = s
        .act_ok(
            &reviewer(),
            "task_check_record",
            json!({ "task_id": cx.task, "name": "review", "outcome": "pass", "head_sha": cx.head }),
        )
        .await;
    card.check(
        2,
        "review.checks-bound-to-exact-revision",
        (|| {
            let (at_head, elsewhere, review) = (at_head?, elsewhere?, review?);
            let tests = check_of(&at_head, "tests").ok_or("no tests check at the head")?;
            ensure(tests["grade"] == "attested" && tests["outcome"] == "pass", format!("{tests}"))?;
            let stale = check_of(&elsewhere, "tests").ok_or("no tests entry at another head")?;
            ensure(stale["grade"] == "unknown", format!("a check recorded at one head counts at another: {stale}"))?;
            ensure(stale["stale_head"] == cx.head.as_str(), format!("{stale}"))?;
            let r = check_of(&review, "review").ok_or("no review check")?;
            ensure(r["grade"] == "attested" && r["head_sha"] == cx.head.as_str(), format!("{r}"))?;
            Ok(format!(
                "bound, self-reported: task_workflow_get at head {} shows tests attested (not verified); at another \
                 head it reads unknown with the head it was seen at; builder-2 records the review at the same head",
                &cx.head[..12]
            ))
        })(),
    );

    // A check verified against CI at the head, through the hub's verifier
    // interface (a scripted verifier stands in for the forge).
    s.must_act(&human(), "project_repo_bind", json!({ "project": "default", "repo": REPO })).await;
    let ci = s
        .act_ok(
            &reviewer(),
            "task_check_record",
            json!({ "task_id": cx.task, "name": "ci", "outcome": "pass", "head_sha": cx.head,
                    "ref": { "kind": "ci_run", "ref": "4242" } }),
        )
        .await;
    let ci_elsewhere = s
        .act_ok(&reviewer(), "task_workflow_get", json!({ "task_id": cx.task, "head_sha": OTHER_HEAD }))
        .await;
    card.check(
        2,
        "review.checks-verified-against-ci",
        (|| {
            let (ci, elsewhere) = (ci?, ci_elsewhere?);
            let c = check_of(&ci, "ci").ok_or("no ci check")?;
            ensure(
                c["grade"] == "verified" && c["verification"]["verdict"] == "verified",
                format!("the run was not verified: {c}"),
            )?;
            ensure(c["verification"]["observed"]["head_sha"] == cx.head.as_str(), format!("{c}"))?;
            ensure(c["ref"]["repo"] == REPO, format!("not checked against the bound repository: {c}"))?;
            let other = check_of(&elsewhere, "ci").ok_or("no ci entry at another head")?;
            ensure(other["grade"] == "unknown", format!("a verified check counts at another head: {other}"))?;
            Ok(format!(
                "task_check_record with a ci_run reference is graded verified after the hub asked the CI verifier \
                 about run 4242 of {REPO} at head {} (a scripted verifier stands in for the forge); at another \
                 head it reads unknown",
                &cx.head[..12]
            ))
        })(),
    );

    // A dispatched worker is interrupted after its durable claim and resumed.
    let make_task = |title: &'static str| async move {
        let id = s.must(&lead(), "task_add", json!({ "title": title })).await["id"].as_i64().unwrap();
        let dir = s.ws.join(".worktrees").join(format!("dispatch-{id}"));
        std::fs::create_dir_all(&dir).unwrap();
        s.sql(&format!("UPDATE tasks SET worktree_path = '{}' WHERE id = {id}", dir.display()));
        id
    };
    let run_task = make_task("Run the release checks").await;
    let dispatched =
        s.gated(&worker(), "dispatch_task", json!({ "task_id": run_task, "agent": "worker-1" })).await;
    let rid = dispatched.as_ref().ok().and_then(|d| d["run_id"].as_str()).unwrap_or_default().to_string();
    let durable = s.text(&format!("SELECT state FROM dispatch_runs WHERE run_id = '{rid}'"));
    s.sql(&format!(
        "UPDATE dispatch_runs SET lease_expires_at = '2000-01-01T00:00:00+00:00' WHERE run_id = '{rid}'"
    ));
    let swept = reap_expired_leases(s.hub()).map_err(|e| e.to_string());
    let resumed = s.gated(&worker(), "dispatch_resume", json!({ "run_id": rid })).await;
    card.check(
        2,
        "review.resumed-attempt-keeps-task-link",
        (|| {
            let d = dispatched.clone()?;
            ensure(d["fence"] == 1 && durable.as_deref() == Some("launched"), format!("{d} state {durable:?}"))?;
            let swept = swept?;
            ensure(swept["reclaimed"][0]["run_id"] == rid.as_str(), format!("the interrupted run was not reclaimed: {swept}"))?;
            let r = resumed?;
            ensure(r["fence"] == 2 && r["run_id"] == rid.as_str(), format!("{r}"))?;
            let attempt = s.text(&format!("SELECT attempt FROM dispatch_runs WHERE run_id = '{rid}'"));
            let task_of_run = s.text(&format!("SELECT task_id FROM dispatch_runs WHERE run_id = '{rid}'"));
            let current = s.text(&format!("SELECT current_run_id FROM tasks WHERE id = {run_task}"));
            ensure(attempt.as_deref() == Some("2"), format!("attempt {attempt:?}"))?;
            ensure(task_of_run == Some(run_task.to_string()), format!("the run moved to task {task_of_run:?}"))?;
            ensure(current.as_deref() == Some(rid.as_str()), format!("the task points at run {current:?}"))?;
            Ok(format!(
                "dispatch_task claimed task {run_task} as run {rid}; after the lease lapsed the reaper reclaimed it and \
                 dispatch_resume continued the same run (attempt 2, fence 2) still linked to the task"
            ))
        })(),
    );
    let stale = s
        .ok(
            &worker(),
            "dispatch_report_self",
            json!({ "state": "finished", "run_id": rid, "evidence": "first", "fence": 1 }),
        )
        .await;
    let fresh = s
        .ok(
            &worker(),
            "dispatch_report_self",
            json!({ "state": "finished", "run_id": rid, "evidence": "second", "fence": 2 }),
        )
        .await;
    let receipt = s.ok(&human(), "dispatch_delivery_receipt", json!({ "run_id": rid })).await;
    card.check(
        2,
        "review.interrupted-attempt-fenced",
        (|| {
            let (stale, fresh, receipt) = (stale?, fresh?, receipt?);
            ensure(
                stale["outcome"]["reason"] == "stale_fence",
                format!("the first attempt's report counted: {stale}"),
            )?;
            ensure(fresh["ok"] == true, format!("{fresh}"))?;
            let finished = receipt["transitions"]
                .as_array()
                .into_iter()
                .flatten()
                .filter(|t| t["state"] == "finished")
                .count();
            ensure(finished == 1 && receipt["run_state"] == "finished", format!("{receipt}"))?;
            Ok("the interrupted attempt's report (fence 1) is refused as stale_fence; the run finishes once"
                .into())
        })(),
    );
    card.not_built(
        2,
        "review.at-most-one-external-effect",
        "external effects (a merge, a release, a message) are not recorded against the run attempt that made \
         them, so the hub cannot show that a resumed attempt produced at most one",
    );

    // An attempt whose outcome cannot be known is left for reconciliation.
    let unsure_task = make_task("Publish the release notes").await;
    let unsure =
        s.gated(&worker(), "dispatch_task", json!({ "task_id": unsure_task, "agent": "worker-1" })).await;
    let urid = unsure.as_ref().ok().and_then(|d| d["run_id"].as_str()).unwrap_or_default().to_string();
    s.sql(&format!(
        "UPDATE dispatch_runs SET pid = {}, lease_expires_at = '2000-01-01T00:00:00+00:00' WHERE run_id = '{urid}'",
        std::process::id()
    ));
    let swept = reap_expired_leases(s.hub()).map_err(|e| e.to_string());
    let resume = s.call(&worker(), "dispatch_resume", json!({ "run_id": urid })).await;
    let receipt = s.ok(&human(), "dispatch_delivery_receipt", json!({ "run_id": urid })).await;
    card.check(
        2,
        "review.uncertain-outcome-visible",
        (|| {
            unsure?;
            let swept = swept?;
            ensure(swept["failed"][0]["run_id"] == urid.as_str(), format!("{swept}"))?;
            let e = match resume {
                Ok(v) => return Err(format!("a run with an unknown outcome was resumed: {v}")),
                Err(e) => e,
            };
            ensure(e.to_string().contains("outcome_unknown"), format!("{e}"))?;
            let receipt = receipt?;
            ensure(receipt.to_string().contains("outcome_unknown"), format!("the receipt hides it: {receipt}"))?;
            Ok(format!(
                "a lapsed run whose process may still be alive is failed as lease_expired_outcome_unknown, shown so \
                 on dispatch_delivery_receipt, and dispatch_resume refuses it (run {urid})"
            ))
        })(),
    );
}

// --- step 3: approve and release --------------------------------------------------------

async fn approve_and_release(s: &Scenario, card: &mut Card, cx: &mut Ctx) {
    s.must_act(&human(), "project_repo_bind", json!({ "project": "default", "repo": REPO })).await;
    let record = |head: &str| json!({ "repo": REPO, "head_sha": head, "task_id": cx.task, "policy_ref": "release-policy-1" });

    // Only a verified human records the approval for the reviewed head.
    let by_agent = s.call(&lead(), "policy_authorization_record", record(&cx.head)).await;
    let by_unverified = s.call(&unverified(), "policy_authorization_record", record(&cx.head)).await;
    let by_reviewer = s.call(&reviewer(), "policy_authorization_record", record(&cx.head)).await;
    let approved = s.ok(&human(), "policy_authorization_record", record(&cx.head)).await;
    let expiring = s.ok(&human(), "policy_authorization_record", record(&cx.head)).await;
    cx.authorization = approved.as_ref().map(|a| a["authorization"]["id"].as_i64().unwrap_or(0)).unwrap_or(0);
    let expiring_id = expiring.as_ref().map(|a| a["authorization"]["id"].as_i64().unwrap_or(0)).unwrap_or(0);
    s.must(&reviewer(), "task_update", json!({ "id": cx.task, "status": "done" })).await;
    let merge = |auth: i64| json!({ "task_id": cx.task, "policy_authorization_id": auth });

    // An expired approval is refused.
    s.sql(&format!(
        "UPDATE policy_authorizations SET expires_at = '2020-01-01T00:00:00+00:00' WHERE id = {expiring_id}"
    ));
    let mark = s.last_seq();
    let expired = s.call(&lead(), "git_merge_task", merge(expiring_id)).await;
    card.check(
        3,
        "release.expired-approval-refused",
        (|| {
            expiring.clone()?;
            let e = match &expired {
                Ok(v) => return Err(format!("an expired authorization covered the merge: {v}")),
                Err(e) => e,
            };
            ensure(reason(e) == "policy_authorization_mismatch", format!("{e:?}"))?;
            ensure(e.to_string().contains("has expired"), format!("refused for another reason: {e}"))?;
            let listed =
                s.text(&format!("SELECT expires_at FROM policy_authorizations WHERE id = {expiring_id}"));
            Ok(format!(
                "git_merge_task under authorization {expiring_id} (expires_at {listed:?}) is refused: {e}"
            ))
        })(),
    );
    card.check(
        3,
        "release.expired-refusal-audited",
        s.refusal_audited(
            mark,
            "lead-1",
            Grant::Authorization(expiring_id),
            "merge under an expired approval",
        ),
    );

    // A changed revision is refused.
    let wt = s.ws.join(&cx.worktree);
    let moved = commit_file(&wt, "NOTES.md", "unreviewed\n", "feat: an unreviewed change");
    let mark = s.last_seq();
    let changed_rev = s.call(&lead(), "git_merge_task", merge(cx.authorization)).await;
    git(&wt, &["reset", "-q", "--hard", &cx.head]);
    card.check(
        3,
        "release.changed-revision-refused",
        (|| {
            approved.clone()?;
            let e = match &changed_rev {
                Ok(v) => return Err(format!("a merge of an unreviewed head ran under the approval: {v}")),
                Err(e) => e,
            };
            ensure(reason(e) == "policy_authorization_mismatch", format!("{e:?}"))?;
            let msg = e.to_string();
            ensure(
                msg.contains(&format!("covers head {}", cx.head)) && msg.contains(&moved),
                format!("refused for another reason: {e}"),
            )?;
            Ok(format!(
                "with the branch moved to {} the merge under the approval for {} is refused, naming both heads",
                &moved[..12],
                &cx.head[..12],
            ))
        })(),
    );
    card.check(
        3,
        "release.changed-revision-refusal-audited",
        s.refusal_audited(
            mark,
            "lead-1",
            Grant::Authorization(cx.authorization),
            "merge of a changed revision",
        ),
    );

    // A changed target is refused.
    s.must_act(&human(), "project_repo_bind", json!({ "project": "default", "repo": OTHER_REPO })).await;
    let mark = s.last_seq();
    let changed_target = s.call(&lead(), "git_merge_task", merge(cx.authorization)).await;
    s.must_act(&human(), "project_repo_bind", json!({ "project": "default", "repo": REPO })).await;
    card.check(
        3,
        "release.changed-target-refused",
        (|| {
            let e = match &changed_target {
                Ok(v) => return Err(format!("a merge into another repository ran under the approval: {v}")),
                Err(e) => e,
            };
            ensure(reason(e) == "policy_authorization_mismatch", format!("{e:?}"))?;
            ensure(e.to_string().contains("another repository"), format!("refused for another reason: {e}"))?;
            Ok(format!(
                "with the project rebound to {OTHER_REPO} the merge under the approval is refused: {e}"
            ))
        })(),
    );
    card.check(
        3,
        "release.changed-target-refusal-audited",
        s.refusal_audited(
            mark,
            "lead-1",
            Grant::Authorization(cx.authorization),
            "merge into a changed target",
        ),
    );

    // The approved attempt merges exactly the reviewed head.
    let mark = s.last_seq();
    let released = s.ok(&lead(), "git_merge_task", merge(cx.authorization)).await;
    let after = s.ledger_after(mark);
    card.check(
        3,
        "release.verified-human-approves-exact-action",
        (|| {
            for (who, r) in [("lead-1 (agent)", &by_agent), ("an unverified caller", &by_unverified), ("builder-2", &by_reviewer)] {
                if let Ok(v) = r {
                    return Err(format!("{who} recorded an approval: {v}"));
                }
            }
            let a = approved.clone()?;
            let auth = &a["authorization"];
            ensure(auth["authorized_by"] == "operator" && auth["head_sha"] == cx.head.as_str(), format!("{a}"))?;
            ensure(auth["task_id"] == cx.task && auth["repo"] == REPO, format!("{a}"))?;
            let consumed = after
                .iter()
                .find(|e| e.channel == "agent.github.policy_authorization.consumed")
                .ok_or("the merge spent no approval")?;
            ensure(consumed.payload["authorization_id"] == cx.authorization, format!("{:?}", consumed.payload))?;
            ensure(consumed.payload["head_sha"] == cx.head.as_str(), format!("{:?}", consumed.payload))?;
            Ok(format!(
                "via the policy authorization path (the one-time approval path is scored separately, \
                 release.one-time-approval-binds-revision): agents ({}, {}, {}) cannot record it; the human, built \
                 from its bearer token by the hub's identity check, records one that binds task {}, {REPO} and head \
                 {}, and the merge spends exactly that one (ledger seq {})",
                by_agent.as_ref().err().map(reason).unwrap_or_default(),
                by_unverified.as_ref().err().map(reason).unwrap_or_default(),
                by_reviewer.as_ref().err().map(reason).unwrap_or_default(),
                cx.task,
                &cx.head[..12],
                consumed.seq
            ))
        })(),
    );
    card.check(
        3,
        "release.approved-attempt-produces-artifact",
        (|| {
            let r = released?;
            ensure(r["success"] == true, format!("{r}"))?;
            let merged =
                after.iter().find(|e| e.channel == "agent.git.merged").ok_or("no agent.git.merged event")?;
            ensure(
                merged.payload["head"] == cx.head.as_str() && merged.payload["task_id"] == cx.task,
                format!("{:?}", merged.payload),
            )?;
            let main = git(&s.ws, &["rev-parse", "main"]);
            ensure(
                merged.payload["commit_hash"] == main.as_str(),
                format!("main is {main}: {:?}", merged.payload),
            )?;
            let ancestor = git_cmd(&s.ws)
                .args(["merge-base", "--is-ancestor", &cx.head, "main"])
                .status()
                .is_ok_and(|st| st.success());
            ensure(ancestor, "the reviewed head is not on main")?;
            ensure(s.ws.join("CHANGELOG.md").exists(), "the change is not on main")?;
            ensure(!s.ws.join("NOTES.md").exists(), "the unreviewed commit reached main")?;
            cx.release_commit = main.clone();
            Ok(format!(
                "git_merge_task merged head {} into main of the disposable repository, main now at {} \
                 (agent.git.merged, ledger seq {}); the unreviewed commit is not on main",
                &cx.head[..12],
                &main[..12],
                merged.seq
            ))
        })(),
    );

    // The one-time approval path: the approver approves a call, not a revision.
    let t2 =
        s.must(&lead(), "task_add", json!({ "title": "Bump the version" })).await["id"].as_i64().unwrap();
    let (b2, w2) = (format!("task-{t2}"), format!(".worktrees/task-{t2}"));
    s.must(&builder(), "git_worktree_add", json!({ "path": w2, "branch": b2 })).await;
    let wt2 = s.ws.join(&w2);
    let approved_head = commit_file(&wt2, "VERSION", "1.0.1\n", "chore: bump the version");
    s.must(&builder(), "task_claim", json!({ "id": t2, "worktree_path": w2, "branch": b2 })).await;
    s.must(&builder(), "task_update", json!({ "id": t2, "status": "done" })).await;
    let parked = s.call(&lead(), "git_merge_task", json!({ "task_id": t2 })).await;
    let approval_id = match parked {
        Err(UaError::ApprovalRequired { approval_id, .. }) => approval_id,
        other => panic!("scenario setup failed: the merge did not park for approval: {other:?}"),
    };
    let payload =
        s.text(&format!("SELECT payload FROM approvals WHERE id = {approval_id}")).unwrap_or_default();
    s.must(&human(), "approval_resolve", json!({ "id": approval_id, "decision": "approve" })).await;
    let unreviewed = commit_file(&wt2, "VERSION", "9.9.9\n", "chore: an unapproved version");
    let mark = s.last_seq();
    let late = s.call(&lead(), "git_merge_task", json!({ "task_id": t2 })).await;
    card.check(
        3,
        "release.one-time-approval-binds-revision",
        match &late {
            Err(e) => (|| {
                ensure(reason(e) == "approval_binding_changed", format!("refused for another reason: {e:?}"))?;
                ensure(
                    payload.contains(&approved_head) && !payload.contains(&unreviewed),
                    format!("the approval does not bind the approved head: {payload}"),
                )?;
                let audited = s.refusal_audited(
                    mark,
                    "lead-1",
                    Grant::Approval(approval_id),
                    "merge of a branch moved after the approval",
                )?;
                Ok(format!(
                    "the approval binds head {} (payload {payload}); with the branch moved to {} the merge is \
                     refused: {}; {audited}",
                    &approved_head[..12],
                    &unreviewed[..12],
                    reason(e)
                ))
            })(),
            Ok(_) => {
                let merged = s
                    .ledger_after(mark)
                    .into_iter()
                    .find(|e| e.channel == "agent.git.merged")
                    .map(|e| e.payload["head"].as_str().unwrap_or_default().to_string())
                    .unwrap_or_default();
                Err(format!(
                    "scored: an approval bound to the revision. A one-time approval of git_merge_task records the \
                     task, not the head (payload {payload}), so the merge it allows is not bound to the revision \
                     shown at approval: the branch head was {} at approval and {} at the merge{}",
                    &approved_head[..12],
                    &merged[..merged.len().min(12)],
                    if merged == unreviewed { "" } else { " (the merged head differs from both)" }
                ))
            }
        },
    );

    // A release requires the review at the head it releases.
    let t3 = s.must(&lead(), "task_add", json!({ "title": "Add a release checklist" })).await["id"]
        .as_i64()
        .unwrap();
    let (b3, w3) = (format!("task-{t3}"), format!(".worktrees/task-{t3}"));
    s.must(&builder(), "git_worktree_add", json!({ "path": w3, "branch": b3 })).await;
    let head3 =
        commit_file(&s.ws.join(&w3), "CHECKLIST.md", "- tag\n- notes\n", "docs: add a release checklist");
    s.must(&builder(), "task_claim", json!({ "id": t3, "worktree_path": w3, "branch": b3 })).await;
    s.must_act(
        &builder(),
        "task_workflow_set",
        json!({ "task_id": t3, "stage": "review", "head_sha": head3, "expected_checks": ["review"] }),
    )
    .await;
    let auth3 = s
        .must(
            &human(),
            "policy_authorization_record",
            json!({ "repo": REPO, "head_sha": head3, "task_id": t3, "policy_ref": "release-policy-1" }),
        )
        .await["authorization"]["id"]
        .as_i64()
        .unwrap();
    s.must(&builder(), "task_update", json!({ "id": t3, "status": "done" })).await;
    let view3 = s.must_act(&lead(), "task_workflow_get", json!({ "task_id": t3, "head_sha": head3 })).await;
    let unreviewed_grade = check_of(&view3, "review").map(|c| c["grade"].clone()).unwrap_or(Value::Null);
    let merged3 =
        s.call(&lead(), "git_merge_task", json!({ "task_id": t3, "policy_authorization_id": auth3 })).await;
    card.record(
        3,
        "release.requires-review-at-head",
        match merged3 {
            Ok(_) => Outcome::NotBuilt(format!(
                "nothing gates a merge on the recorded review: with the expected review at head {} reading \
                 {unreviewed_grade}, a merge under a valid authorization for that head runs",
                &head3[..12]
            )),
            Err(e) if e.to_string().contains("review") => {
                Outcome::Pass(format!("a merge with no review at head {} is refused: {e}", &head3[..12]))
            }
            Err(e) => Outcome::Fail(format!("the merge was refused for another reason: {e}")),
        },
    );
}

// --- step 4: check isolation ------------------------------------------------------------

/// What one caller sees through each surface, normalized: fields that move
/// with the caller's own records or with the clock are dropped, so the only
/// differences between two views are what other callers' records show.
#[derive(Debug, Default)]
struct View {
    surfaces: BTreeMap<&'static str, Value>,
}

impl View {
    fn markers_shown(&self, surface: &str) -> Vec<&'static str> {
        let text = self.surfaces.get(surface).map(Value::to_string).unwrap_or_default();
        MARKERS.iter().copied().filter(|m| text.contains(m)).collect()
    }
}

/// Fields that change with the clock or with every ledger append (the
/// caller's own appends included), never with someone else's hidden record.
/// The chain fields among them (head_ulid, head_hash, total_verified) are
/// also the owner-accepted integrity exception for task 2775: ledger chain
/// metadata stays visible to restricted readers so the chain still proves
/// intact, and the scorecard strips it here rather than scoring it.
const VOLATILE: [&str; 9] = [
    "generated_at",
    "until",
    "head_hash",
    "head_ulid",
    "total_verified",
    "access_count",
    "last_accessed_at",
    "fingerprint",
    "bytes",
];

/// `v` without the [`VOLATILE`] fields, without rows the caller wrote itself
/// (`originator`, `created_by` or `author` naming it) and without its own
/// sentinel tasks. Chain metadata on a compared row (seq, prev_hash,
/// entry_hash) is left in place: it is the owner-accepted integrity
/// exception for task 2775 and stays identical while the visible rows do.
fn normalized(v: Value, me: &str) -> Value {
    match v {
        Value::Object(m) => Value::Object(
            m.into_iter()
                .filter(|(k, _)| !VOLATILE.contains(&k.as_str()))
                .map(|(k, v)| (k, normalized(v, me)))
                .collect(),
        ),
        Value::Array(a) => Value::Array(
            a.into_iter()
                .filter(|row| {
                    let own =
                        ["originator", "created_by", "author", "reported_by"].iter().any(|k| row[*k] == me);
                    let sentinel = row["title"].as_str().is_some_and(|t| t.starts_with("Stream sentinel"));
                    !own && !sentinel
                })
                .map(|row| normalized(row, me))
                .collect(),
        ),
        other => other,
    }
}

fn shown(r: Result<Value, UaError>) -> Value {
    match r {
        Ok(v) => normalized(v, "builder-3"),
        Err(e) => Value::String(format!("refused: {}", reason(&e))),
    }
}

/// An export's `content` parsed (JSON, or one JSON value per line).
fn export_content(r: Result<Value, UaError>) -> Value {
    match r {
        Ok(v) => {
            let text = v["content"].as_str().unwrap_or_default();
            let parsed = serde_json::from_str(text).unwrap_or_else(|_| {
                Value::Array(text.lines().filter_map(|l| serde_json::from_str(l).ok()).collect())
            });
            normalized(parsed, "builder-3")
        }
        Err(e) => Value::String(format!("refused: {}", reason(&e))),
    }
}

/// Up to `limit` places where `a` and `b` differ, as `path: summary`.
fn differences(a: &Value, b: &Value, path: &str, out: &mut Vec<String>, limit: usize) {
    if out.len() >= limit || a == b {
        return;
    }
    let brief = |v: &Value| {
        if let Some(ch) = v["channel"].as_str() {
            format!("{ch} by {}", v["originator"].as_str().unwrap_or("?"))
        } else {
            let t = v.to_string();
            if t.len() > 80 { format!("{}...", &t[..80]) } else { t }
        }
    };
    match (a, b) {
        (Value::Object(x), Value::Object(y)) => {
            let keys: std::collections::BTreeSet<&String> = x.keys().chain(y.keys()).collect();
            for k in keys {
                differences(
                    x.get(k).unwrap_or(&Value::Null),
                    y.get(k).unwrap_or(&Value::Null),
                    &format!("{path}.{k}"),
                    out,
                    limit,
                );
            }
        }
        (Value::Array(x), Value::Array(y)) => {
            // A row present on both sides under the same id is a change, not
            // a new row: name the fields that changed.
            let same_id =
                |r: &Value, o: &Value| ["id", "task_id"].iter().any(|k| !r[*k].is_null() && r[*k] == o[*k]);
            let mut added = Vec::new();
            for r in y.iter().filter(|r| !x.contains(r)) {
                match x.iter().find(|o| same_id(r, o)) {
                    Some(o) => {
                        let fields: Vec<String> = match (o, r) {
                            (Value::Object(a), Value::Object(b)) => b
                                .iter()
                                .filter(|(k, v)| a.get(*k) != Some(*v))
                                .map(|(k, _)| k.clone())
                                .collect(),
                            _ => Vec::new(),
                        };
                        let id = if r["id"].is_null() {
                            format!("task_id {}", r["task_id"])
                        } else {
                            format!("id {}", r["id"])
                        };
                        out.push(format!("{path}: row {id} changed ({})", fields.join(", ")));
                    }
                    None => added.push(brief(r)),
                }
            }
            let removed = x.iter().filter(|o| !y.contains(o) && !y.iter().any(|r| same_id(r, o))).count();
            if !added.is_empty() || removed > 0 {
                out.push(format!("{path}: {} new ({}), {removed} gone", added.len(), added.join("; ")));
            } else if x.len() == y.len() && !out.iter().any(|d| d.starts_with(path)) {
                out.push(format!("{path}: reordered"));
            }
        }
        _ => out.push(format!("{path}: {} -> {}", brief(a), brief(b))),
    }
}

/// Read an SSE body until `done` holds. A stream that stops short of it is a
/// setup failure, never a scored outcome: a partial read would hide rows.
async fn read_sse(resp: Response<Body>, done: impl Fn(&str) -> bool) -> String {
    let mut body = resp.into_body();
    let mut text = String::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    while !done(&text) {
        match tokio::time::timeout_at(deadline, body.frame()).await {
            Ok(Some(Ok(frame))) => {
                if let Ok(data) = frame.into_data() {
                    text.push_str(&String::from_utf8_lossy(&data));
                }
            }
            other => panic!(
                "scenario setup failed: the event stream ended before the caller's own sentinel row arrived \
                 ({}); refusing to score a partial read",
                if other.is_err() { "timed out" } else { "closed" }
            ),
        }
    }
    text
}

/// The `data:` rows of an SSE text, as JSON.
fn sse_rows(text: &str) -> Value {
    Value::Array(
        text.lines()
            .filter_map(|l| l.strip_prefix("data: "))
            .filter_map(|d| serde_json::from_str(d).ok())
            .collect(),
    )
}

async fn outsider_view(
    s: &Scenario,
    tag: &str,
    hidden_task: i64,
    hidden_session: &str,
    conversation: &str,
) -> View {
    let me = outsider();
    let mut v = View::default();
    v.surfaces.insert("inbox", shown(s.call(&me, "message_list", json!({})).await));
    v.surfaces
        .insert("mailbox", shown(s.call(&me, "message_list", json!({ "to_agent": "builder-2" })).await));
    let mut ledger = Vec::new();
    let mut after = 0;
    loop {
        let page = s.call(&me, "event_log_query", json!({ "after_seq": after, "limit": 1000 })).await;
        let page = page.unwrap_or_else(|e| panic!("scenario setup failed: event_log_query: {e}"));
        ledger.extend(page["events"].as_array().cloned().unwrap_or_default());
        match page["next_after_seq"].as_i64() {
            Some(n) if page["count"].as_u64() == Some(1000) => after = n,
            _ => break,
        }
    }
    v.surfaces.insert("ledger", normalized(Value::Array(ledger), "builder-3"));
    v.surfaces.insert(
        "observability",
        json!({
            "activity builder-1": shown(
                s.call(&me, "observability_manage", json!({ "action": "activity", "params": { "agent": "builder-1" } })).await,
            ),
            "activity builder-2": shown(
                s.call(&me, "observability_manage", json!({ "action": "activity", "params": { "agent": "builder-2" } })).await,
            ),
            // Only the per-agent event counts are compared: the rest of the
            // snapshot (task counts, tool-call totals, db size) is not
            // visibility-scoped and moves with builder-3's own calls.
            "metrics": match s.call(&me, "observability_manage", json!({ "action": "metrics", "params": {} })).await
            {
                Ok(mut v) => {
                    if let Some(m) = v["events_last_7_days"].as_object_mut() {
                        m.remove("builder-3");
                    }
                    normalized(v["events_last_7_days"].clone(), "builder-3")
                }
                Err(e) => Value::String(format!("refused: {}", reason(&e))),
            },
        }),
    );
    v.surfaces.insert(
        "handoff-note",
        shown(s.act(&me, "session_handoff_recover", json!({ "session_id": hidden_session })).await),
    );
    v.surfaces.insert(
        "conversation",
        shown(s.act(&me, "conversation_handoffs", json!({ "conversation_id": conversation })).await),
    );
    // Naming the conversation to join it: a missing id ("before") and a
    // foreign one ("after") must answer alike.
    v.surfaces.insert(
        "conversation-send",
        shown(
            s.call(
                &me,
                "message_send",
                json!({ "act": "inform", "to_agent": "builder-2", "body": "let me in",
                        "conversation_id": conversation, "message_id": format!("probe-{tag}") }),
            )
            .await,
        ),
    );
    // The crew view of the owner's session lists only builder-3's own mail.
    v.surfaces.insert(
        "crew",
        match s.call(&me, "crew_view", json!({ "session_id": hidden_session })).await {
            Ok(c) => {
                normalized(json!({ "messages": c["messages"], "total": c["message_total"] }), "builder-3")
            }
            Err(e) => Value::String(format!("refused: {}", reason(&e))),
        },
    );
    v.surfaces
        .insert("packet", shown(s.call(&me, "session_packet", json!({ "task_id": hidden_task })).await));
    v.surfaces
        .insert("evidence", shown(s.call(&me, "evidence_report", json!({ "task_id": hidden_task })).await));
    v.surfaces.insert(
        "retrieval",
        json!({
            "memory_search": shown(s.call(&me, "memory_search", json!({ "query": "signing key vault rotation" })).await),
            "task_search": shown(s.call(&me, "task_list", json!({ "query": "signing key vault rotation", "status": "all" })).await),
        }),
    );
    v.surfaces.insert(
        "exports",
        json!({
            "export_data tasks": export_content(
                s.call(&me, "export_data", json!({ "action": "tasks", "params": { "format": "json", "write_to_vault": false } })).await,
            ),
            "export_data memory": export_content(
                s.call(&me, "export_data", json!({ "action": "memory", "params": { "write_to_vault": false } })).await,
            ),
            "export_migration_manifest": shown(
                s.call(&me, "export_migration_manifest", json!({ "events_since_ulid": "00000000000000000000000000" })).await,
            ),
        }),
    );

    // The live stream, backfilled from the start of the ledger. builder-3's
    // own write after opening it is a row it sees under any scoping, and it
    // arrives after the backfill, so reading up to it reads everything.
    let mut req = get("/api/events/stream?channel_prefix=agent.", None, Some(OUTSIDER_TOKEN));
    req.headers_mut().insert("last-event-id", "0".parse().unwrap());
    let resp = s.th.send(req).await;
    let stream = if resp.status() == StatusCode::OK {
        s.must(&me, "task_add", json!({ "title": format!("Stream sentinel ({tag})") })).await;
        let own = s.last_seq();
        normalized(sse_rows(&read_sse(resp, |t| t.contains(&format!("id: {own}\n"))).await), "builder-3")
    } else {
        Value::String(format!("refused: {}", resp.status()))
    };
    v.surfaces.insert("stream", stream);
    v
}

async fn check_isolation(s: &Scenario, card: &mut Card) {
    let other_org = "only the default organization can exist (no second organization can be created or \
                     authenticated into), so there is no caller in another organization to test";
    card.not_built(4, "isolation.other-org-direct-reads", other_org);
    card.not_built(4, "isolation.other-org-retrieval-and-explanations", other_org);
    card.not_built(4, "isolation.other-org-handoffs", other_org);
    card.not_built(4, "isolation.other-org-streams", other_org);
    card.not_built(4, "isolation.other-org-exports", other_org);
    card.not_built(
        4,
        "isolation.same-org-restricted-memory",
        "memory notes carry no access restriction: every caller in the organization can read and retrieve every note",
    );
    card.not_built(
        4,
        "isolation.same-org-hidden-task",
        "tasks carry no access restriction: every caller in the organization can list and read every task",
    );

    // The hidden records: a message and a typed handoff in builder-2's
    // mailbox, builder-2's sealed handoff note and a conversation handoff,
    // none of them builder-3's.
    let hidden = s.must(&lead(), "task_add", json!({ "title": "Rotate the signing key" })).await["id"]
        .as_i64()
        .unwrap();
    let session = s
        .must(&reviewer(), "session_start", json!({ "kind": "interactive", "task_id": hidden }))
        .await["session_id"]
        .as_str()
        .unwrap()
        .to_string();
    // Not yet minted: the outsider's "before" probe names a missing id.
    let conversation = "conv-signing-key";
    let before = outsider_view(s, "before", hidden, &session, conversation).await;
    let real_conversation = s
        .must(
            &builder(),
            "message_send",
            json!({ "act": "request", "to_agent": "builder-2", "task_id": hidden,
                    "body": format!("Private: the old key is in the vault ({}).", MARKERS[0]) }),
        )
        .await["conversation_id"]
        .as_str()
        .unwrap()
        .to_string();
    s.must(
        &builder(),
        "message_send",
        json!({ "act": "handoff", "to_agent": "builder-2", "task_id": hidden, "body": "Over to you.",
                "handoff": { "done": ["drafted the rotation"], "next_action": format!("rotate it ({})", MARKERS[1]) } }),
    )
    .await;
    let note = s
        .must_act(
            &reviewer(),
            "session_handoff_propose",
            json!({ "session_id": session, "done": [format!("found the key ({})", MARKERS[2])], "next_steps": ["rotate"] }),
        )
        .await;
    s.must_act(&reviewer(), "session_handoff_seal", json!({ "note_id": note["id"] })).await;
    s.must_act(
        &reviewer(),
        "conversation_handoff",
        json!({ "conversation_id": real_conversation, "task_id": hidden }),
    )
    .await;
    // Reading its inbox writes the owner's own agent.mailbox.* receipts.
    s.must_act(&reviewer(), "message_inbox", json!({})).await;
    // "before" probed a conversation id that does not exist; "after" probes
    // the real, foreign one. The two must answer alike.
    let after = outsider_view(s, "after", hidden, &session, &real_conversation).await;

    // The owner reads what the outsider must not, so the records are real.
    let owner_mailbox = shown(s.call(&reviewer(), "message_list", json!({})).await).to_string();
    assert!(owner_mailbox.contains(MARKERS[0]), "scenario setup failed: builder-2 cannot read its own mail");

    // The document's rule: builder-3's view through each surface is the same
    // before and after the hidden records exist.
    let unchanged = |surface: &str| -> Result<(), String> {
        let (b, a) = (&before.surfaces[surface], &after.surfaces[surface]);
        let mut diff = Vec::new();
        differences(b, a, surface, &mut diff, 4);
        ensure(diff.is_empty(), diff.join(" | "))?;
        ensure(after.markers_shown(surface).is_empty(), format!("shows {:?}", after.markers_shown(surface)))
    };
    let unchanged_refusal = |surface: &str, what: &str| -> Verified {
        unchanged(surface)
            .map_err(|d| format!("{what} answers builder-3 differently once the records exist: {d}"))?;
        let a = &after.surfaces[surface];
        ensure(
            a.as_str().is_some_and(|t| t.starts_with("refused")),
            format!("{what} answered builder-3: {a}"),
        )?;
        Ok(format!("{what} refuses builder-3 identically before and after the hidden records exist ({a})"))
    };
    card.check(
        4,
        "isolation.same-org-mailbox-direct-read",
        unchanged_refusal("mailbox", "message_list(to_agent=builder-2)"),
    );
    card.check(
        4,
        "isolation.same-org-handoff-note",
        unchanged_refusal("handoff-note", "session_handoff_recover"),
    );
    card.check(
        4,
        "isolation.same-org-conversation-handoffs",
        unchanged_refusal("conversation", "conversation_handoffs"),
    );
    card.check(
        4,
        "isolation.same-org-conversation-naming",
        unchanged_refusal("conversation-send", "message_send(conversation_id)"),
    );
    card.check(
        4,
        "isolation.same-org-own-inbox",
        unchanged("inbox")
            .map(|()| {
                "control check, not a sentence of the document: builder-3's own message_list is identical before \
                 and after"
                    .to_string()
            })
            .map_err(|d| format!("control check: builder-3's own inbox changed: {d}")),
    );
    // `fact` says what the product does today when the views differ.
    let compared = |surface: &str, label: &str, fact: &str, scored: &str| -> Verified {
        match unchanged(surface) {
            Ok(()) => Ok(format!(
                "{label}: builder-3's view is identical before and after the hidden records exist"
            )),
            Err(d) => Err(format!(
                "scored: {scored}. {fact}. builder-3's {label} view changes once the hidden records exist: {d}"
            )),
        }
    };
    card.check(
        4,
        "isolation.same-org-ledger-read",
        match unchanged("ledger").and_then(|()| unchanged("observability")) {
            Ok(()) => Ok(
                "event_log_query and observability: builder-3's view is identical before and after the hidden \
                 records exist"
                    .to_string(),
            ),
            Err(d) => Err(format!(
                "scored: the mailbox and handoff restriction applied to ledger reads. Ledger reads \
                 (event_log_query) and observability (agent_activity, metrics_snapshot) are not scoped per \
                 caller: message and handoff events are returned to every caller whose profile allows them. \
                 builder-3's ledger/observability view changes once the hidden records exist: {d}"
            )),
        },
    );
    card.check(
        4,
        "isolation.same-org-stream",
        compared(
            "stream",
            "event stream",
            "The event stream (/api/events/stream, backfilled from the start) uses the same unscoped rule as \
             ledger reads",
            "the mailbox and handoff restriction applied to the event stream",
        ),
    );
    card.check(
        4,
        "isolation.same-org-crew-view",
        compared(
            "crew",
            "crew_view(owner's session)",
            "crew_view on a session lists every message on its task, delegation or crew thread, with bodies, \
             whoever they are addressed to",
            "the mailbox restriction applied to crew views",
        ),
    );
    card.check(
        4,
        "isolation.same-org-handoffs-in-retrieval",
        compared(
            "packet",
            "session_packet(task_id)",
            "session_packet for a task includes the latest typed handoff on it, and the task's recent events, \
             whoever they are addressed to",
            "the mailbox and handoff restriction applied to resume packets",
        ),
    );
    card.check(
        4,
        "isolation.same-org-evidence",
        compared(
            "evidence",
            "evidence_report(task_id)",
            "evidence_report on a task lists the ledger events of messages and handoffs on it, with sender and \
             time, to callers who cannot read them",
            "the mailbox and handoff restriction applied to evidence reports",
        ),
    );
    card.check(
        4,
        "isolation.same-org-retrieval-and-explanations",
        compared(
            "retrieval",
            "memory_search and ranked task_list",
            "Retrieval (memory_search, ranked task_list with explanations) for the hidden records' terms returns \
             tasks, which carry no access restriction; conversation_handoff writes a line naming the conversation \
             into the task's notes, which every caller reads",
            "the mailbox and handoff restriction applied to retrieval and its explanations",
        ),
    );
    let manifest_refused = after.surfaces["exports"]["export_migration_manifest"].clone();
    card.check(
        4,
        "isolation.same-org-exports",
        compared(
            "exports",
            "export",
            &format!(
                "export_data (tasks, memory) answers and export_migration_manifest is refused by builder-3's \
                 profile ({manifest_refused}), so the manifest is out of reach rather than shown clean; the tasks \
                 export carries the task notes line conversation_handoff writes"
            ),
            "the mailbox and handoff restriction applied to exports",
        ),
    );
}

// --- step 5: verify independently -------------------------------------------------------

async fn verify_independently(s: &Scenario, card: &mut Card, cx: &Ctx) {
    // Client-asserted evidence, so the export has some to label.
    s.must(
        &builder(),
        "evidence_append",
        json!({ "channel": "sdk.note", "payload": { "note": "benchmarks look fine" } }),
    )
    .await;

    let exported = s
        .ok(
            &auditor(),
            "export_migration_manifest",
            json!({ "events_since_ulid": "00000000000000000000000000" }),
        )
        .await;
    let manifest = match exported {
        Ok(e) => e["manifest"].clone(),
        Err(e) => panic!("scenario setup failed: {e}"),
    };
    // The bundle crosses to the auditor's machine as bytes.
    let carried: Value = serde_json::from_str(&manifest.to_string()).unwrap();
    let rows: Vec<Value> = carried["event_log"]["rows"].as_array().cloned().unwrap_or_default();
    let payload = |r: &Value| -> Value {
        match &r["payload"] {
            Value::String(t) => serde_json::from_str(t).unwrap_or(Value::Null),
            other => other.clone(),
        }
    };
    let find = |channel: &str, pred: &dyn Fn(&Value) -> bool| -> Option<Value> {
        rows.iter().find(|r| r["channel"] == channel && pred(&payload(r))).map(payload)
    };
    let task = cx.task;
    let head = cx.head.as_str();

    card.check(
        5,
        "verify.trace-artifact-to-task",
        (|| {
            let merged = find("agent.git.merged", &|p| p["task_id"] == task)
                .ok_or("the export carries no agent.git.merged row for the task")?;
            ensure(
                merged["commit_hash"] == cx.release_commit.as_str() && merged["head"] == head,
                format!("{merged}"),
            )?;
            let listed = carried["tasks"].as_array().into_iter().flatten().any(|t| t["id"] == task);
            ensure(listed, "the export does not list the task")?;
            Ok(format!(
                "the auditor's copy of the export links release commit {} to task {task} and head {}",
                &cx.release_commit[..12],
                &head[..12]
            ))
        })(),
    );
    card.check(
        5,
        "verify.trace-artifact-to-handoff",
        (|| {
            let h = find("agent.message.handoff", &|p| {
                p["task_id"] == task && p["handoff"]["reviewed_head_sha"] == head
            })
            .ok_or("the export carries no handoff row for the task at the reviewed head")?;
            let sealed = find("agent.lifecycle.handoff", &|p| p["task_id"] == task && p["state"] == "sealed");
            ensure(sealed.is_some(), "the export carries no sealed handoff note for the task")?;
            Ok(format!(
                "the export carries the handoff from {} at the reviewed head and the sealed note",
                h["from_agent"]
            ))
        })(),
    );
    card.check(
        5,
        "verify.trace-artifact-to-approval",
        (|| {
            let consumed = find("agent.github.policy_authorization.consumed", &|p| p["task_id"] == task)
                .ok_or("the export carries no spent approval for the task")?;
            ensure(consumed["head_sha"] == head && consumed["authorization_id"] == cx.authorization, format!("{consumed}"))?;
            let recorded = rows
                .iter()
                .find(|r| {
                    r["channel"] == "agent.github.policy_authorization.recorded"
                        && payload(r)["authorization_id"] == cx.authorization
                })
                .ok_or("the export carries no record of who approved")?;
            ensure(recorded["originator"] == "operator", format!("{recorded}"))?;
            Ok(format!(
                "the export carries authorization {} recorded by operator and spent by the merge at the reviewed head",
                cx.authorization
            ))
        })(),
    );
    card.not_built(
        5,
        "verify.trace-artifact-to-policy",
        "the approval carries a caller-supplied policy reference (free text); no policy record exists to resolve \
         it against",
    );
    card.check(
        5,
        "verify.policy-reference-recorded",
        (|| {
            let recorded = find("agent.github.policy_authorization.recorded", &|p| {
                p["authorization_id"] == cx.authorization
            })
            .ok_or("no recorded approval row")?;
            ensure(recorded["policy_ref"] == "release-policy-1", format!("{recorded}"))?;
            Ok("the exported approval row carries the policy reference the human typed (release-policy-1); it is \
                a label, not a resolvable policy"
                .into())
        })(),
    );
    card.not_built(
        5,
        "verify.trace-artifact-to-run-attempt",
        "a merge or release is not recorded against a run attempt: git_merge_task takes no run, and its ledger event \
         names none",
    );
    card.check(
        5,
        "verify.trace-artifact-to-checks-at-revision",
        (|| {
            for name in ["tests", "review"] {
                find("agent.task.workflow", &|p| {
                    p["kind"] == "check" && p["task_id"] == task && p["name"] == name && p["head_sha"] == head
                })
                .ok_or(format!("the export carries no {name} check at the reviewed head"))?;
            }
            Ok("the export carries the tests and review checks recorded at the reviewed head".into())
        })(),
    );

    // On the auditor's own machine: a separate hub with none of the data.
    let auditor_home = Scratch::new("auditor");
    let auditor_hub = Hub::in_memory(Config::for_home(&auditor_home.0)).unwrap();
    let reg = builtin_registry();
    let compare = |left: &Value, right: &Value| {
        let args = json!({ "left": left, "right": right });
        let (reg, hub) = (&reg, &auditor_hub);
        async move { reg.call(hub, &auditor(), "compare_migration_manifests", args).await }
    };
    let clean = compare(&carried, &carried).await;
    // Conflicts the untouched bundle already has (say, two tasks that look
    // alike) say nothing about tampering; only new ones are a rejection.
    let baseline: Vec<Value> =
        clean.as_ref().ok().and_then(|v| v["conflicts"].as_array().cloned()).unwrap_or_default();
    let rejected = |v: &Value| -> Vec<Value> {
        v["conflicts"].as_array().into_iter().flatten().filter(|c| !baseline.contains(c)).cloned().collect()
    };
    let mut edited = carried.clone();
    if let Some(t) = edited["tasks"].as_array_mut().and_then(|ts| ts.iter_mut().find(|t| t["id"] == task)) {
        t["title"] = json!("a different task");
    }
    let tampered_record = compare(&edited, &edited).await;
    card.check(
        5,
        "verify.record-fingerprint-recomputed-offline",
        (|| {
            let clean = clean.as_ref().map_err(|e| e.to_string())?;
            let integrity = |c: &Value| {
                c["type"] == "fingerprint_mismatch"
                    || c["type"].as_str().is_some_and(|t| t.starts_with("event_log"))
            };
            ensure(
                !baseline.iter().any(integrity),
                format!("the untouched bundle fails its own checks: {clean}"),
            )?;
            let t = tampered_record.map_err(|e| e.to_string())?;
            let caught = rejected(&t).iter().any(|c| c["type"] == "fingerprint_mismatch");
            ensure(caught && t["same"] == false, format!("an edited task passed: {t}"))?;
            Ok("on a second hub used only for this comparison, compare_migration_manifests recomputes the \
                manifest fingerprint: a task edited without updating the stated fingerprint is flagged \
                fingerprint_mismatch. This detects only an edit that leaves the fingerprint stale"
                .into())
        })(),
    );
    card.not_built(
        5,
        "verify.integrity-an-editor-cannot-recompute",
        "the fingerprint is an unkeyed SHA-256 stored inside the bundle, so whoever edits the bundle can recompute \
         it; the listed ledger rows the trace relies on are outside it, and the chain flag is the exporter's own \
         claim",
    );

    let mut forged = carried.clone();
    let merged_at = forged["event_log"]["rows"]
        .as_array()
        .and_then(|rs| rs.iter().position(|r| r["channel"] == "agent.git.merged"));
    if let Some(i) = merged_at {
        let mut p = payload(&forged["event_log"]["rows"][i]);
        p["head"] = json!(OTHER_HEAD);
        forged["event_log"]["rows"][i]["payload"] = json!(p.to_string());
    }
    let tampered_row = compare(&forged, &forged).await;
    card.record(
        5,
        "verify.rejects-tampered-ledger-row",
        match tampered_row {
            Ok(v) if !rejected(&v).is_empty() => {
                Outcome::Pass(format!("an edited ledger row is rejected: {:?}", rejected(&v)))
            }
            Ok(_) => Outcome::NotBuilt(
                "no verifier checks a single bundle: compare_migration_manifests trusts the exporter's chain_ok and \
                 leaves listed ledger rows outside the fingerprint, so a bundle with an edited merge row checks out"
                    .into(),
            ),
            Err(e) => Outcome::Fail(format!("the verifier failed on the bundle: {e}")),
        },
    );
    let mut cut = carried.clone();
    if let Some(rs) = cut["event_log"]["rows"].as_array_mut() {
        rs.retain(|r| r["channel"] != "agent.github.policy_authorization.consumed");
    }
    let incomplete = compare(&cut, &cut).await;
    card.record(
        5,
        "verify.rejects-incomplete-bundle",
        match incomplete {
            Ok(v) if !rejected(&v).is_empty() => {
                Outcome::Pass(format!("a bundle missing a row is rejected: {:?}", rejected(&v)))
            }
            Ok(_) => Outcome::NotBuilt(
                "no bundle states a scope and interval it claims to be complete for, and no verifier checks the \
                 listed rows against the declared count and rolling hash: a bundle missing the spent approval checks out"
                    .into(),
            ),
            Err(e) => Outcome::Fail(format!("the verifier failed on the bundle: {e}")),
        },
    );
    card.not_built(
        5,
        "verify.authenticity-against-trusted-key",
        "exports carry no signature or signed checkpoint, so nothing can be checked against a separately trusted key",
    );
    card.check(
        5,
        "verify.asserted-evidence-labelled",
        (|| {
            let row = rows
                .iter()
                .find(|r| r["channel"] == "sdk.note")
                .ok_or("the client evidence is not exported")?;
            ensure(
                row["trust"]["level"] == "untrusted" && row["trust"]["author"] == "builder-1",
                format!("{row}"),
            )?;
            Ok("client-written evidence (sdk.note) is exported labelled untrusted, with its author".into())
        })(),
    );
    card.not_built(
        5,
        "verify.unavailable-and-unhashed-evidence-reported",
        "no bundle verifier exists to report evidence it could not obtain or legacy rows without hashes; only the \
         hub-side evidence_report counts an unhashed legacy prefix",
    );
    let auditor_mailbox = s.call(&auditor(), "message_list", json!({ "to_agent": "builder-2" })).await;
    card.check(
        5,
        "verify.private-content-kept-out",
        (|| {
            ensure(auditor_mailbox.is_err(), "the auditor may read builder-2's mailbox, so the check proves nothing")?;
            let text = carried.to_string();
            let shown_markers: Vec<&str> = MARKERS.iter().copied().filter(|m| text.contains(m)).collect();
            ensure(
                shown_markers.is_empty(),
                format!(
                    "scored: content kept out of an export unless the exporter may read it. The only bundle is a \
                     full migration manifest, not a scoped audit export; it carries the message and handoff \
                     payloads ({shown_markers:?}) that message_list refuses the exporting auditor"
                ),
            )?;
            Ok("the export carries no private content the auditor may not read".into())
        })(),
    );

    // An unauthorized caller asks for the bundle.
    let unauthorized = s
        .call(
            &outsider(),
            "export_migration_manifest",
            json!({ "events_since_ulid": "00000000000000000000000000" }),
        )
        .await;
    card.check(
        5,
        "verify.unauthorized-caller-refused-export",
        match unauthorized {
            Err(e) => Ok(format!(
                "builder-3 (developer profile) is refused the export ({}); the gate is the coordinator profile, \
                 not an auditor grant",
                reason(&e)
            )),
            Ok(_) => Err("a developer-profile caller exported the whole hub".into()),
        },
    );
    card.not_built(
        5,
        "verify.auditor-authorization",
        "no auditor role or grant exists: any coordinator-profile agent may export the whole hub, and no export is \
         scoped to what its requester is authorized to audit",
    );
}

// --- the test ---------------------------------------------------------------------------

#[tokio::test]
async fn software_factory_scenario_scorecard() {
    let s = Scenario::new();
    let mut card = Card::default();
    let mut cx = Ctx::default();

    let revision = Command::new("git")
        .args(["rev-parse", "--short=12", "HEAD"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|| "unknown".into());
    println!(
        "hub {} at revision {revision}; harnesses: builder-1 (mcp, harness-a) and builder-2 (http, harness-b); \
         features: {}; fixture inputs: one disposable git repository, the task spec and three memory notes in this file",
        env!("CARGO_PKG_VERSION"),
        ua_tools::build_features()
    );

    plan_and_delegate(&s, &mut card, &mut cx).await;
    resume_and_review(&s, &mut card, &mut cx).await;
    approve_and_release(&s, &mut card, &mut cx).await;
    check_isolation(&s, &mut card).await;
    verify_independently(&s, &mut card, &cx).await;

    let report = card.render();
    println!("{report}");
    let fixture = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(FIXTURE))
        .unwrap_or_else(|e| panic!("cannot read {FIXTURE}: {e}"));
    let problems = card.ratchet(&fixture);
    assert!(
        problems.is_empty(),
        "the scorecard differs from {FIXTURE}:\n- {}\n{report}",
        problems.join("\n- ")
    );
}
