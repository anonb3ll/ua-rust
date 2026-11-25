//! The executor: starts a harness as a child process for a run, supervises
//! it, and reports its exit.
//!
//! - No shell: `argv[0]` is executed directly, placeholders are substituted
//!   literally into single arguments.
//! - The child environment is built from an allowlist ([`child_env`]); the
//!   hub's own secrets are never passed.
//! - The child leads its own process group. Timeout and cancel kill the whole
//!   group.
//! - Combined stdout/stderr go to `$UA_HOME/runs/<run_id>.log`, capped at the
//!   harness's `output_cap_bytes`; the rest is read and discarded so the
//!   child never blocks on a full pipe. The tail of standard error (and, for
//!   a harness with `quota_json_errors`, of standard output) is also kept
//!   apart in memory, so a quota signal is read from the stream the harness
//!   declared, never from the model's text ([`quota_line`]).
//! - The program is the absolute path the approval bound
//!   ([`resolve_program`]), not a name looked up again at launch.
//! - The run log directory is created 0700 and each log 0600.
//! - Every supervisor runs in one [`TaskTracker`]. On a hub shutdown
//!   ([`drain_supervisors`]) runs get until shortly before the deadline to
//!   finish; then each live child's group gets SIGTERM, SIGKILL after
//!   [`TERM_GRACE`], a final SIGKILL sweep for any grandchild left in the
//!   group, and the run is recorded `retryable` with failure reason and
//!   receipt source `hub_shutdown`, so it can be resumed.
//! - Children this process started are kept in an in-process registry keyed
//!   by run id and are signalled directly. A process group recorded by an
//!   earlier hub process is signalled only when it is proven to be that
//!   run's orphan ([`orphan_proof`]): on Linux and macOS the recorded child
//!   must still be the same process (start time) in the same group, or have
//!   exited while a member of its group lives on, and the hub process that
//!   started it must be gone. A run is reported stopped only when its whole
//!   group is empty. Anything short of that proof is reported as `not_ours`
//!   (cessation unknown) and nothing is signalled.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;

use secrecy::ExposeSecret;
use serde_json::{Value, json};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::sync::Notify;
use ua_core::config::HarnessConfig;
use ua_core::{Config, UaError, UaResult};

pub use super::procinfo::{ProcIdentity, proc_identity};
use super::procinfo::{group_alive, kill_group, pid_alive, term_group};
use super::{
    Edge, ExitInfo, Outcome, Run, after_seconds, load_run, now, record_transition, refusal, transition,
};
use crate::hub::Hub;
use tokio_util::task::TaskTracker;

/// Parent environment names any child may inherit.
pub const SAFE_ENV: &[&str] = &[
    "PATH",
    "HOME",
    "USER",
    "LOGNAME",
    "SHELL",
    "TMPDIR",
    "TMP",
    "TEMP",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "LC_MESSAGES",
    "TERM",
    "COLORTERM",
    "TZ",
    "XDG_RUNTIME_DIR",
    "XDG_CACHE_HOME",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "XDG_STATE_HOME",
];

/// Names never passed to a child, even when a harness lists them: the hub's
/// own credentials and the parent's agent socket.
pub const DENY_ENV: &[&str] = &[
    "UA_AGENT_TOKENS",
    "UA_MANAGED_SECRET_KEY",
    "UA_MANAGED_SECRET_KEYS",
    "UA_EXECUTOR_TOKEN",
    "UA_HTTP_BEARER",
    "DATABASE_URL",
    "SSH_AUTH_SOCK",
    "BRAVE_API_KEY",
    "TAVILY_API_KEY",
];

/// Names the dispatch binding sets; a parent value is never inherited.
pub const BINDING_ENV: &[&str] = &[
    "UA_DISPATCH_RUN_ID",
    "UA_DISPATCH_TASK_ID",
    "UA_DISPATCH_AGENT",
    "UA_DISPATCH_FENCE",
    "UA_AGENT_LABEL",
    "UA_AGENT_BEARER_TOKEN",
];

/// Whether a name reads like a credential.
pub fn looks_secret(name: &str) -> bool {
    ua_core::config::env_name_looks_secret(name)
}

/// Whether a harness may list `name` in its `env_allowlist`. Everything in
/// the hub's `UA_` namespace is refused (it is hub configuration, and holds
/// the hub's secrets), as are [`DENY_ENV`] and the binding names. A
/// credential-looking name is allowed here because the allowlist is already
/// scoped to one harness, as the original's `backend:NAME` passthrough is.
pub fn harness_may_pass(name: &str) -> bool {
    !name.is_empty()
        && !DENY_ENV.contains(&name)
        && !BINDING_ENV.contains(&name)
        && !name.to_ascii_uppercase().starts_with("UA_")
}

/// What identifies the child to the hub.
#[derive(Debug, Clone)]
pub struct Binding {
    pub run_id: String,
    pub task_id: i64,
    pub agent: String,
    pub fence: i64,
    /// The agent's own hub bearer, when the harness opts in.
    pub agent_token: Option<String>,
}

/// The child environment: [`SAFE_ENV`] names from `parent` (unless they look
/// secret), the harness's allowlisted names, its fixed `env` values (rendered
/// with `vars`), its `path_prepend` in front of `PATH`, minus its
/// `env_denylist`, then the binding.
pub fn child_env(
    parent: impl IntoIterator<Item = (String, String)>,
    harness: &HarnessConfig,
    binding: &Binding,
    vars: &[(&str, String)],
) -> BTreeMap<String, String> {
    let mut env = BTreeMap::new();
    for (k, v) in parent {
        let safe = SAFE_ENV.contains(&k.as_str()) && !looks_secret(&k);
        let listed = harness.env_allowlist.iter().any(|n| n == &k) && harness_may_pass(&k);
        if safe || listed {
            env.insert(k, v);
        }
    }
    for (k, v) in &harness.env {
        if harness_may_pass(k) {
            env.insert(k.clone(), render_one(v, vars));
        }
    }
    if !harness.path_prepend.is_empty() {
        let mut parts: Vec<String> = harness.path_prepend.iter().map(|p| p.display().to_string()).collect();
        if let Some(path) = env.get("PATH").filter(|p| !p.is_empty()) {
            let inherited: Vec<String> =
                path.split(':').filter(|p| !parts.iter().any(|q| q == p)).map(str::to_string).collect();
            parts.extend(inherited);
        }
        env.insert("PATH".into(), parts.join(":"));
    }
    for name in &harness.env_denylist {
        env.remove(name);
    }
    env.insert("UA_DISPATCH_RUN_ID".into(), binding.run_id.clone());
    env.insert("UA_DISPATCH_TASK_ID".into(), binding.task_id.to_string());
    env.insert("UA_DISPATCH_AGENT".into(), binding.agent.clone());
    env.insert("UA_DISPATCH_FENCE".into(), binding.fence.to_string());
    env.insert("UA_AGENT_LABEL".into(), binding.agent.clone());
    if let Some(t) = &binding.agent_token {
        env.insert("UA_AGENT_BEARER_TOKEN".into(), t.clone());
    }
    env
}

/// Substitute placeholders in each argument. One template argument stays one
/// argument whatever the values contain.
pub fn render_argv(template: &[String], vars: &[(&str, String)]) -> Vec<String> {
    template.iter().map(|arg| render_one(arg, vars)).collect()
}

/// Substitute `{name}` placeholders in one pass: a value is never scanned
/// again, so a prompt that contains `{run_id}` stays as written.
pub fn render_one(template: &str, vars: &[(&str, String)]) -> String {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(i) = rest.find('{') {
        out.push_str(&rest[..i]);
        let tail = &rest[i..];
        let hit = vars.iter().find(|(k, _)| {
            tail.len() > k.len() + 1 && tail[1..].starts_with(k) && tail.as_bytes()[k.len() + 1] == b'}'
        });
        match hit {
            Some((k, v)) => {
                out.push_str(v);
                rest = &tail[k.len() + 2..];
            }
            None => {
                out.push('{');
                rest = &tail[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

/// The placeholder values of a launch.
pub(crate) fn launch_vars(spec: &LaunchSpec) -> Vec<(&'static str, String)> {
    vec![
        ("run_id", spec.run_id.clone()),
        ("task_id", spec.task_id.to_string()),
        ("agent", spec.agent.clone()),
        ("fence", spec.fence.to_string()),
        ("worktree", spec.workdir.display().to_string()),
        ("prompt_json", serde_json::to_string(&spec.prompt).unwrap_or_default()),
        ("prompt", spec.prompt.clone()),
    ]
}

/// The configured hub bearer of `agent`, if any.
fn agent_token(cfg: &Config, agent: &str) -> Option<String> {
    cfg.static_tokens().into_iter().find(|(l, _)| l == agent).map(|(_, t)| t.expose_secret().to_string())
}

/// Where a run's log lives.
pub fn log_path(cfg: &Config, run_id: &str) -> PathBuf {
    cfg.home.join("runs").join(format!("{run_id}.log"))
}

// ---------------------------------------------------------------------------
// The in-process registry of children
// ---------------------------------------------------------------------------

struct LiveChild {
    fence: i64,
    pgid: Option<u32>,
    kill: Arc<Notify>,
}

static LIVE: LazyLock<Mutex<HashMap<String, LiveChild>>> = LazyLock::new(Mutex::default);

/// Every supervisor task this process started.
static SUPERVISORS: LazyLock<TaskTracker> = LazyLock::new(TaskTracker::new);

/// Set once the hub stops its runs for a shutdown: a supervisor woken then
/// stops its child gracefully and records `hub_shutdown`.
static HUB_SHUTDOWN: AtomicBool = AtomicBool::new(false);

/// How long a child's group has after SIGTERM before SIGKILL.
pub const TERM_GRACE: Duration = Duration::from_secs(2);

/// Time kept back before the shutdown deadline to stop runs and record them.
const STOP_BUDGET: Duration = Duration::from_secs(3);

/// What [`drain_supervisors`] did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DrainReport {
    /// Runs still going when stopping began, stopped and recorded.
    pub stopped: usize,
    /// Supervisors still running at the deadline.
    pub unfinished: usize,
}

/// Drain the dispatch supervisors for a hub shutdown ending at `deadline`.
/// Runs may finish on their own until [`STOP_BUDGET`] before it; then every
/// live child is stopped (SIGTERM to its group, SIGKILL after
/// [`TERM_GRACE`], a SIGKILL sweep of the group) and its run recorded
/// `retryable` with a `hub_shutdown` receipt.
pub async fn drain_supervisors(deadline: tokio::time::Instant) -> DrainReport {
    SUPERVISORS.close();
    let stop_at = deadline.checked_sub(STOP_BUDGET).unwrap_or(deadline).max(tokio::time::Instant::now());
    if tokio::time::timeout_at(stop_at, SUPERVISORS.wait()).await.is_ok() {
        return DrainReport::default();
    }
    HUB_SHUTDOWN.store(true, Ordering::SeqCst);
    let kills: Vec<Arc<Notify>> =
        LIVE.lock().map(|m| m.values().map(|c| c.kill.clone()).collect()).unwrap_or_default();
    for k in &kills {
        // A permit is stored when the supervisor is not waiting yet.
        k.notify_one();
    }
    let finished = tokio::time::timeout_at(deadline, SUPERVISORS.wait()).await.is_ok();
    DrainReport { stopped: kills.len(), unfinished: if finished { 0 } else { SUPERVISORS.len() } }
}

/// SIGKILL every live child's group at once, recording nothing: the last
/// resort of a forced exit (a second shutdown signal). The next hub
/// process's startup sweep reconciles the runs.
pub fn kill_live_groups() -> usize {
    let groups: Vec<Option<u32>> =
        LIVE.lock().map(|m| m.values().map(|c| c.pgid).collect()).unwrap_or_default();
    for g in &groups {
        kill_group(*g);
    }
    groups.len()
}

/// Stop a child for a hub shutdown: SIGTERM its group, SIGKILL after
/// [`TERM_GRACE`], then sweep the group so no grandchild outlives the run.
async fn stop_for_shutdown(
    pid: Option<u32>,
    child: &mut tokio::process::Child,
) -> Option<std::process::ExitStatus> {
    term_group(pid);
    let status = match tokio::time::timeout(TERM_GRACE, child.wait()).await {
        Ok(st) => st.ok(),
        Err(_) => {
            kill_group(pid);
            let _ = child.start_kill();
            child.wait().await.ok()
        }
    };
    kill_group(pid);
    status
}

fn live_insert(run_id: &str, fence: i64, pgid: Option<u32>, kill: Arc<Notify>) {
    if let Ok(mut m) = LIVE.lock() {
        m.insert(run_id.to_string(), LiveChild { fence, pgid, kill });
    }
}

/// Drop this process's registration of `run_id` at `fence`. Returns false
/// when it was already gone (replaced by a newer fence, or forgotten).
fn live_remove(run_id: &str, fence: i64) -> bool {
    if let Ok(mut m) = LIVE.lock()
        && m.get(run_id).is_some_and(|c| c.fence == fence)
    {
        m.remove(run_id);
        return true;
    }
    false
}

/// Whether this process supervises `run_id` at `fence`.
pub fn supervises(run_id: &str, fence: i64) -> bool {
    LIVE.lock().map(|m| m.get(run_id).is_some_and(|c| c.fence == fence)).unwrap_or(false)
}

/// Whether a recorded pid names a live process (any owner).
pub fn pid_is_alive(pid: Option<i64>) -> bool {
    pid.is_some_and(pid_alive)
}

/// This hub process's pid and start time, when the platform reports it.
pub fn own_identity() -> Option<(i64, i64)> {
    static OWN: LazyLock<Option<(i64, i64)>> = LazyLock::new(|| {
        let pid = i64::from(std::process::id());
        proc_identity(pid).map(|p| (pid, p.start_time))
    });
    *OWN
}

/// What a recorded pid turned out to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proof {
    /// The recorded child and every member of its process group are gone.
    Gone,
    /// The recorded child or a member of its group is still running and the
    /// hub process that started it is gone (or is this process, which no
    /// longer supervises it): the group may be signalled.
    Orphan { pgid: i64 },
    /// Not enough evidence to touch it, or to claim it stopped.
    Unproven,
}

/// What a pid lookup found.
enum Seen {
    /// No such process.
    Gone,
    /// A live process this platform cannot inspect.
    Unknown,
    Is(ProcIdentity),
}

fn look(pid: i64) -> Seen {
    match proc_identity(pid) {
        Some(p) => Seen::Is(p),
        None if pid_alive(pid) => Seen::Unknown,
        None => Seen::Gone,
    }
}

/// Decide whether a run's recorded child (and its process group) is this
/// hub's orphan. The child led its own group, so the recorded group id is
/// its pid; the OS does not hand that number to a new process while the
/// group still has a member.
pub(crate) fn orphan_proof(run: &Run) -> Proof {
    let (Some(pid), Some(pgid)) = (run.pid, run.pgid) else {
        return Proof::Unproven;
    };
    if pgid != pid || pgid <= 1 {
        return Proof::Unproven;
    }
    match look(pid) {
        Seen::Unknown => return Proof::Unproven,
        Seen::Is(now) => match run.pid_start_time {
            None => return Proof::Unproven,
            // The pid names another process: it could only be reused after
            // the recorded group emptied.
            Some(start) if now.start_time != start => return Proof::Gone,
            // Still running, but it left its group.
            Some(_) if !now.exited() && now.pgrp != pgid => return Proof::Unproven,
            Some(_) => {}
        },
        // The leader exited; members it forked may still hold the group.
        Seen::Gone => {}
    }
    if !group_alive(pgid) {
        return Proof::Gone;
    }
    // Something in the group lives. Signal it only when the hub process
    // that started it is proven gone, and never the hub's own group.
    let Some(own) = own_identity() else { return Proof::Unproven };
    if proc_identity(own.0).map(|p| p.pgrp) == Some(pgid) {
        return Proof::Unproven;
    }
    let (Some(spid), Some(sstart)) = (run.supervisor_pid, run.supervisor_start_time) else {
        return Proof::Unproven;
    };
    if (spid, sstart) == own {
        // We started it and no longer supervise it (the caller checked).
        return Proof::Orphan { pgid };
    }
    match look(spid) {
        Seen::Gone => Proof::Orphan { pgid },
        Seen::Is(sup) if sup.start_time != sstart || sup.exited() => Proof::Orphan { pgid },
        Seen::Is(_) | Seen::Unknown => Proof::Unproven,
    }
}

/// Wait up to two seconds for a signalled group to empty.
fn wait_group_gone(pgid: i64) -> bool {
    for _ in 0..40 {
        if !group_alive(pgid) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    !group_alive(pgid)
}

/// Attempt to stop a run's process. Blocking (it may wait briefly for an
/// orphan group to exit). Returns `killed` (a child this process
/// supervises, signalled), `killed_orphan` (a proven orphan group,
/// signalled and empty), `kill_unconfirmed` (a proven orphan group,
/// signalled, a member still present), `already_gone` (no process recorded,
/// or the recorded child and its whole group no longer exist) or `not_ours`
/// (something may still run that this process cannot vouch for; nothing is
/// signalled).
pub(crate) fn terminate(run: &Run) -> &'static str {
    let ours = LIVE.lock().ok().and_then(|m| m.get(&run.run_id).map(|c| (c.pgid, c.kill.clone())));
    if let Some((pgid, kill)) = ours {
        kill_group(pgid);
        kill.notify_one();
        return "killed";
    }
    let Some(pid) = run.pid else { return "already_gone" };
    if run.pgid.is_none() {
        // No group recorded: the pid is all there is to check.
        return if pid_alive(pid) { "not_ours" } else { "already_gone" };
    }
    match orphan_proof(run) {
        Proof::Gone => "already_gone",
        Proof::Unproven => "not_ours",
        Proof::Orphan { pgid } => {
            kill_group(u32::try_from(pgid).ok());
            if wait_group_gone(pgid) { "killed_orphan" } else { "kill_unconfirmed" }
        }
    }
}

// ---------------------------------------------------------------------------
// Launch
// ---------------------------------------------------------------------------

/// Everything a launch needs.
#[derive(Debug, Clone)]
pub(crate) struct LaunchSpec {
    /// The run's organization.
    pub org: String,
    pub run_id: String,
    pub task_id: i64,
    pub agent: String,
    pub fence: i64,
    pub harness_name: String,
    pub harness: HarnessConfig,
    pub workdir: PathBuf,
    pub prompt: String,
    pub actor: String,
    /// The absolute program the approval bound; `None` when `argv[0]` was
    /// found nowhere, which fails the launch as a missing program.
    pub program: Option<PathBuf>,
}

/// The absolute program a launch of `h` in `workdir` executes: `argv[0]`
/// itself when it holds a `/` (joined to `workdir` when relative), else the
/// first executable file of that name on the child's `PATH` (its
/// `path_prepend` in front of the hub's own). `None` when nothing is found.
pub fn resolve_program(h: &HarnessConfig, workdir: Option<&Path>) -> Option<PathBuf> {
    let argv0 = h.argv.first()?.trim();
    if argv0.is_empty() {
        return None;
    }
    if argv0.contains('/') {
        let p = Path::new(argv0);
        return if p.is_absolute() { Some(p.to_path_buf()) } else { workdir.map(|w| w.join(p)) };
    }
    let probe =
        Binding { run_id: String::new(), task_id: 0, agent: String::new(), fence: 0, agent_token: None };
    let path = child_env(std::env::vars(), h, &probe, &[]).remove("PATH")?;
    path.split(':')
        .filter(|d| !d.is_empty() && Path::new(d).is_absolute())
        .map(|d| Path::new(d).join(argv0))
        .find(|c| {
            std::fs::metadata(c).is_ok_and(|m| {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    m.is_file() && m.permissions().mode() & 0o111 != 0
                }
                #[cfg(not(unix))]
                {
                    m.is_file()
                }
            })
        })
}

/// Move a claimed run to `launched` without a process (no harness).
pub(crate) async fn launch_stub(hub: &Hub, org: String, run_id: String, actor: String) -> UaResult<Value> {
    hub.db()
        .write_async(move |tx| {
            let Some(run) = load_run(tx, &org, &run_id)? else {
                return Ok(refusal("unknown_run", &run_id, json!({})));
            };
            if let Err(why) = transition(tx, &run, Edge::to("launched"))? {
                return Ok(refusal(why, &run_id, json!({ "state": run.state })));
            }
            record_transition(tx, &org, &run_id, "launched", &actor, json!({ "stub": true }))?;
            Ok(json!({
                "ok": true, "run_id": run_id, "state": "launched", "fence": run.fence,
                "spawned": false, "stub": true,
            }))
        })
        .await
}

/// Start the harness for a claimed run and hand it to a supervisor task.
pub(crate) async fn launch(hub: &Hub, spec: LaunchSpec) -> UaResult<Value> {
    if spec.harness.argv.is_empty() {
        return Err(UaError::invalid(format!("harness {:?} has an empty argv", spec.harness_name)));
    }
    // claimed -> launched, under the fence.
    let (rid, fence, actor, name) =
        (spec.run_id.clone(), spec.fence, spec.actor.clone(), spec.harness_name.clone());
    let org = spec.org.clone();
    let started = hub
        .db()
        .write_async(move |tx| {
            let Some(run) = load_run(tx, &org, &rid)? else {
                return Ok(Err(refusal("unknown_run", &rid, json!({}))));
            };
            if run.fence != fence {
                return Ok(Err(refusal("stale_fence", &rid, json!({ "current_fence": run.fence }))));
            }
            if let Err(why) = transition(tx, &run, Edge::to("launched"))? {
                return Ok(Err(refusal(why, &rid, json!({ "state": run.state }))));
            }
            record_transition(tx, &org, &rid, "launched", &actor, json!({ "harness": name }))?;
            Ok(Ok(()))
        })
        .await?;
    if let Err(r) = started {
        return Ok(r);
    }

    let cfg = hub.cfg();
    let log = log_path(cfg, &spec.run_id);
    let binding = Binding {
        run_id: spec.run_id.clone(),
        task_id: spec.task_id,
        agent: spec.agent.clone(),
        fence: spec.fence,
        agent_token: if spec.harness.pass_agent_token { agent_token(cfg, &spec.agent) } else { None },
    };
    let vars = launch_vars(&spec);
    let env = child_env(std::env::vars(), &spec.harness, &binding, &vars);
    let argv = render_argv(&spec.harness.argv, &vars);
    let stdin_text = spec.harness.stdin.as_deref().map(|t| render_one(t, &vars));

    let spawned = open_log(&log, &spec).await.and_then(|file| {
        // Run the bound program; a name found nowhere fails as missing.
        let program =
            spec.program.clone().ok_or_else(|| std::io::Error::from(std::io::ErrorKind::NotFound))?;
        let mut cmd = tokio::process::Command::new(&program);
        #[cfg(unix)]
        cmd.arg0(&argv[0]);
        cmd.args(&argv[1..])
            .current_dir(&spec.workdir)
            .env_clear()
            .envs(&env)
            .stdin(if stdin_text.is_some() { Stdio::piped() } else { Stdio::null() })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        #[cfg(unix)]
        cmd.process_group(0);
        cmd.spawn().map(|c| (c, file))
    });
    let (mut child, file) = match spawned {
        Ok(v) => v,
        Err(e) => {
            let reason = format!("spawn_failed: {}", e.kind());
            // A missing or unexecutable program, or an argument list the OS
            // refuses, will fail the same way on every retry.
            let (state, class) =
                if spawn_error_is_config(&e) { ("failed", "config") } else { ("retryable", "launch") };
            let (rid, actor, org) = (spec.run_id.clone(), spec.actor.clone(), spec.org.clone());
            let res = hub
                .db()
                .write_async(move |tx| {
                    super::record_outcome(
                        tx,
                        Outcome {
                            org: &org,
                            run_id: &rid,
                            fence: Some(fence),
                            state,
                            actor: &actor,
                            source: "launcher",
                            evidence: None,
                            failure_reason: Some(reason),
                            failure_class: Some(class.into()),
                            usage: None,
                            quota_signal: None,
                        },
                    )
                })
                .await?;
            return Ok(refusal(
                "launch_failed",
                &spec.run_id,
                json!({ "error": res["failure_reason"].clone(), "state": res["state"].clone() }),
            ));
        }
    };
    let pid = child.id();
    let kill = Arc::new(Notify::new());
    live_insert(&spec.run_id, spec.fence, pid, kill.clone());
    // The child leads its own group (unix), so its pgid is its pid. The start
    // time (read while the child is certainly ours) proves later that a pid
    // was not reused.
    let pid_i = pid.map(i64::from);
    let pgid = if cfg!(unix) { pid_i } else { None };
    let start_time = pid_i.and_then(proc_identity).map(|p| p.start_time);
    let (sup_pid, sup_start) = own_identity().unzip();

    // launched -> running, recording the pid. A cancel that landed first
    // refuses this write; the launcher then stops its own child.
    let lease = hub.cfg().dispatch_lease_seconds.max(1);
    let (rid, actor, log_s) = (spec.run_id.clone(), spec.actor.clone(), log.display().to_string());
    let org = spec.org.clone();
    let persisted = hub
        .db()
        .write_async(move |tx| {
            let Some(run) = load_run(tx, &org, &rid)? else { return Ok(false) };
            if run.fence != fence {
                return Ok(false);
            }
            let edge = Edge::to("running")
                .set("pid", pid_i)
                .set("pgid", pgid)
                .set("pid_start_time", start_time)
                .set("supervisor_pid", sup_pid)
                .set("supervisor_start_time", sup_start)
                .set("started_at", now())
                .set("log_path", log_s)
                .set("lease_expires_at", after_seconds(lease));
            if transition(tx, &run, edge)?.is_err() {
                return Ok(false);
            }
            record_transition(tx, &org, &rid, "running", &actor, json!({ "pid": pid }))?;
            Ok(true)
        })
        .await?;
    if !persisted {
        kill_group(pid);
        let _ = child.kill().await;
        live_remove(&spec.run_id, spec.fence);
        let (rid, actor, org) = (spec.run_id.clone(), spec.actor.clone(), spec.org.clone());
        let res = hub
            .db()
            .write_async(move |tx| {
                let run = load_run(tx, &org, &rid)?;
                match run {
                    Some(r) if r.termination_outcome.as_deref() == Some("requested") && r.fence == fence => {
                        super::finalize_cancellation(
                            tx,
                            &org,
                            &rid,
                            &actor,
                            "launcher",
                            "cancelled_during_launch",
                            "killed",
                            "confirmed",
                        )
                    }
                    Some(r) => Ok(json!({ "state": r.state })),
                    None => Ok(json!({})),
                }
            })
            .await?;
        return Ok(refusal(
            "cancelled_during_launch",
            &spec.run_id,
            json!({ "state": res.get("state").cloned().unwrap_or(Value::Null), "cessation": res.get("cessation").cloned().unwrap_or(Value::Null) }),
        ));
    }

    if let (Some(text), Some(mut input)) = (stdin_text, child.stdin.take()) {
        // Written from its own task so a child that never reads cannot
        // stall the launch; dropping the handle closes the pipe.
        tokio::spawn(async move {
            let _ = input.write_all(text.as_bytes()).await;
            let _ = input.shutdown().await;
        });
    }
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let reply = json!({
        "ok": true,
        "run_id": spec.run_id,
        "state": "running",
        "fence": spec.fence,
        "pid": pid,
        "log_path": log.display().to_string(),
        "spawned": true,
        "stub": false,
    });
    let hub2 = hub.clone();
    SUPERVISORS.spawn(async move {
        supervise(hub2, spec, child, stdout, stderr, file, pid, kill).await;
    });
    Ok(reply)
}

fn spawn_error_is_config(e: &std::io::Error) -> bool {
    #[cfg(unix)]
    if e.raw_os_error() == Some(libc::E2BIG) {
        return true;
    }
    matches!(e.kind(), std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied)
}

/// Open (append) a run log: the directory 0700, the file 0600, both
/// tightened if they already existed.
async fn open_log(path: &Path, spec: &LaunchSpec) -> std::io::Result<tokio::fs::File> {
    if let Some(dir) = path.parent() {
        let mut b = tokio::fs::DirBuilder::new();
        b.recursive(true);
        #[cfg(unix)]
        b.mode(0o700);
        b.create(dir).await?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            tokio::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).await?;
        }
    }
    let mut o = tokio::fs::OpenOptions::new();
    o.create(true).append(true);
    #[cfg(unix)]
    o.mode(0o600);
    let mut f = o.open(path).await?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        f.set_permissions(std::fs::Permissions::from_mode(0o600)).await?;
    }
    let header = format!(
        "== run {} fence {} harness {} started {} ==\n",
        spec.run_id,
        spec.fence,
        spec.harness_name,
        now()
    );
    f.write_all(header.as_bytes()).await?;
    Ok(f)
}

/// Bounded log writer shared by the stdout and stderr readers.
struct LogSink {
    file: tokio::fs::File,
    written: u64,
    total: u64,
    cap: u64,
}

type Sink = Arc<tokio::sync::Mutex<LogSink>>;

/// The last bytes of one stream, kept apart from the combined log.
struct Tail {
    buf: Vec<u8>,
    cap: usize,
}

impl Tail {
    fn shared(cap: usize) -> Arc<Mutex<Tail>> {
        Arc::new(Mutex::new(Tail { buf: Vec::new(), cap }))
    }

    fn push(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
        if self.buf.len() > self.cap {
            let cut = self.buf.len() - self.cap;
            self.buf.drain(..cut);
        }
    }

    fn text(t: &Arc<Mutex<Tail>>) -> String {
        let t = t.lock().unwrap_or_else(|e| e.into_inner());
        String::from_utf8_lossy(&t.buf).into_owned()
    }
}

/// Bytes of standard error, and of standard output for JSON error events,
/// kept for the quota check.
const STDERR_TAIL_BYTES: usize = 8 * 1024;
const STDOUT_TAIL_BYTES: usize = 64 * 1024;

async fn drain<R: AsyncRead + Unpin>(mut r: R, sink: Sink, tail: Option<Arc<Mutex<Tail>>>) {
    let mut chunk = [0u8; 8192];
    loop {
        match r.read(&mut chunk).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if let Some(t) = &tail {
                    t.lock().unwrap_or_else(|e| e.into_inner()).push(&chunk[..n]);
                }
                let mut s = sink.lock().await;
                s.total += n as u64;
                if s.written < s.cap {
                    let take = (s.cap - s.written).min(n as u64) as usize;
                    if s.file.write_all(&chunk[..take]).await.is_err() {
                        break;
                    }
                    s.written += take as u64;
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn supervise(
    hub: Hub,
    spec: LaunchSpec,
    mut child: tokio::process::Child,
    stdout: Option<tokio::process::ChildStdout>,
    stderr: Option<tokio::process::ChildStderr>,
    file: tokio::fs::File,
    pid: Option<u32>,
    kill: Arc<Notify>,
) {
    let sink: Sink = Arc::new(tokio::sync::Mutex::new(LogSink {
        file,
        written: 0,
        total: 0,
        cap: spec.harness.output_cap_bytes,
    }));
    let err_tail = Tail::shared(STDERR_TAIL_BYTES);
    let out_tail = spec.harness.quota_json_errors.then(|| Tail::shared(STDOUT_TAIL_BYTES));
    let mut readers = Vec::new();
    if let Some(o) = stdout {
        readers.push(tokio::spawn(drain(o, sink.clone(), out_tail.clone())));
    }
    if let Some(e) = stderr {
        readers.push(tokio::spawn(drain(e, sink.clone(), Some(err_tail.clone()))));
    }

    let lease = hub.cfg().dispatch_lease_seconds.max(1);
    let renew_every = Duration::from_secs((lease / 3).max(1));
    let deadline = tokio::time::Instant::now() + Duration::from_secs(spec.harness.timeout_s.max(1));
    let mut timed_out = false;
    let mut hub_shutdown = false;
    let status = loop {
        tokio::select! {
            st = child.wait() => break st.ok(),
            _ = tokio::time::sleep_until(deadline) => {
                timed_out = true;
                kill_group(pid);
                let _ = child.start_kill();
                break child.wait().await.ok();
            }
            _ = kill.notified() => {
                if HUB_SHUTDOWN.load(Ordering::SeqCst) {
                    hub_shutdown = true;
                    break stop_for_shutdown(pid, &mut child).await;
                }
                kill_group(pid);
                let _ = child.start_kill();
                break child.wait().await.ok();
            }
            _ = tokio::time::sleep(renew_every) => {
                let (rid, fence, org) = (spec.run_id.clone(), spec.fence, spec.org.clone());
                let res = hub.db().write_async(move |tx| {
                    tx.execute(
                        "UPDATE dispatch_runs SET lease_expires_at = ?3, updated_at = ?4 WHERE run_id = ?1 \
                         AND org_id = ?5 AND fence = ?2 AND state IN ('claimed','launched','running') \
                         AND termination_outcome IS NULL",
                        rusqlite::params![rid, fence, after_seconds(lease), now(), org],
                    )?;
                    Ok(())
                }).await;
                if let Err(e) = res {
                    tracing::warn!(error = %e, "could not renew a dispatch lease");
                }
            }
        }
    };

    // A grandchild may still hold the pipes: give the readers a moment, then
    // kill what is left of the group and stop reading.
    let mut pending = Vec::new();
    for mut h in readers {
        if tokio::time::timeout(Duration::from_secs(2), &mut h).await.is_err() {
            pending.push(h);
        }
    }
    if !pending.is_empty() {
        kill_group(pid);
        for mut h in pending {
            if tokio::time::timeout(Duration::from_secs(2), &mut h).await.is_err() {
                h.abort();
            }
        }
    }
    // A supervisor whose registration is gone (superseded, or forgotten as
    // after a restart) records the exit but leaves the outcome to whoever
    // owns the run now.
    let still_ours = live_remove(&spec.run_id, spec.fence);

    let (written, total) = {
        let mut s = sink.lock().await;
        let _ = s.file.flush().await;
        (s.written, s.total)
    };
    let (code, signal) = match status {
        Some(st) => split_status(st),
        None => (None, None),
    };
    let exit = ExitInfo {
        exit_code: code,
        exit_signal: signal,
        timed_out,
        output_bytes: i64::try_from(total).unwrap_or(i64::MAX),
        output_truncated: total > written,
    };
    let mut quota_signal = None;
    let source = if hub_shutdown { "hub_shutdown" } else { "supervisor" };
    let (state, reason, class, evidence) = if hub_shutdown {
        // Not the run's failure: hand it back for a resume.
        ("retryable", Some("hub_shutdown".to_string()), Some("hub_shutdown".to_string()), None)
    } else if timed_out {
        (
            "failed",
            Some(format!("timeout_after_{}s", spec.harness.timeout_s)),
            Some("timeout".to_string()),
            None,
        )
    } else if code == Some(0) {
        ("finished", None, None, Some(format!("run-log:{}", log_path(hub.cfg(), &spec.run_id).display())))
    } else {
        let why = match (code, signal) {
            (Some(c), _) => format!("exit_code:{c}"),
            (None, Some(s)) => format!("signal:{s}"),
            _ => "exit_code:not observed".into(),
        };
        // Only the harness's declared signal is quota evidence: one of its
        // quota_patterns on stderr, or in a structured JSON error event.
        let stderr_text = Tail::text(&err_tail);
        let stdout_text = out_tail.as_ref().map(Tail::text);
        match quota_line(&spec.harness.quota_patterns, &stderr_text, stdout_text.as_deref()) {
            Some((source, line)) => {
                quota_signal = Some(json!({ "source": source, "line": line }));
                (
                    "failed",
                    Some(format!("{why} (provider quota exhausted)")),
                    Some(QUOTA_CLASS.to_string()),
                    None,
                )
            }
            None => ("failed", Some(why), Some("exit".to_string()), None),
        }
    };
    let (rid, fence, org) = (spec.run_id.clone(), spec.fence, spec.org.clone());
    let res = hub
        .db()
        .write_async(move |tx| {
            super::record_exit(tx, &org, &rid, fence, &exit)?;
            if !still_ours {
                return Ok(json!({ "ok": false, "reason": "not_supervised" }));
            }
            super::record_outcome(
                tx,
                Outcome {
                    org: &org,
                    run_id: &rid,
                    fence: Some(fence),
                    state,
                    actor: "dispatch-supervisor",
                    source,
                    evidence,
                    failure_reason: reason,
                    failure_class: class,
                    usage: None,
                    quota_signal,
                },
            )
        })
        .await;
    if let Err(e) = res {
        tracing::warn!(error = %e, run_id = %spec.run_id, "could not record a dispatch exit");
    }
}

const QUOTA_CLASS: &str = crate::families::provider_accounts::QUOTA_CLASS;
use crate::families::provider_accounts::quota_line;

fn split_status(st: std::process::ExitStatus) -> (Option<i64>, Option<i64>) {
    if let Some(c) = st.code() {
        return (Some(i64::from(c)), None);
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(sig) = st.signal() {
            return (None, Some(i64::from(sig)));
        }
    }
    (None, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding() -> Binding {
        Binding {
            run_id: "run-1-ab".into(),
            task_id: 1,
            agent: "agent-1".into(),
            fence: 2,
            agent_token: None,
        }
    }

    /// Review finding: the approval did not bind which program argv[0]
    /// resolves to. It now binds an absolute path, found on the child's PATH
    /// (its path_prepend first) or joined to the workdir.
    #[cfg(unix)]
    #[test]
    fn the_program_resolves_to_an_absolute_path() {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        let tool = bin.join("agent-cli");
        std::fs::write(&tool, "#!/bin/sh\n").unwrap();
        let h = |argv0: &str, prepend: Vec<PathBuf>| HarnessConfig {
            argv: vec![argv0.into()],
            path_prepend: prepend,
            ..HarnessConfig::default()
        };
        // Not executable: not a match.
        assert_eq!(resolve_program(&h("agent-cli", vec![bin.clone()]), None), None);
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tool, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(resolve_program(&h("agent-cli", vec![bin.clone()]), None), Some(tool.clone()));
        assert_eq!(resolve_program(&h("agent-cli-missing", vec![bin.clone()]), None), None);
        assert_eq!(resolve_program(&h("/opt/x/agent", vec![]), None), Some(PathBuf::from("/opt/x/agent")));
        assert_eq!(
            resolve_program(&h("./bin/agent-cli", vec![]), Some(dir.path())),
            Some(dir.path().join("./bin/agent-cli"))
        );
    }

    #[test]
    fn env_is_an_allowlist() {
        let parent = vec![
            ("PATH".to_string(), "/usr/bin".to_string()),
            ("UA_AGENT_TOKENS".to_string(), "a:b".to_string()),
            ("UA_HOME".to_string(), "/data".to_string()),
            ("OPENAI_API_KEY".to_string(), "k".to_string()),
            ("RANDOM_VAR".to_string(), "x".to_string()),
            ("UA_DISPATCH_RUN_ID".to_string(), "forged".to_string()),
        ];
        let mut h = HarnessConfig::default();
        let env = child_env(parent.clone(), &h, &binding(), &[]);
        assert_eq!(env.get("PATH").map(String::as_str), Some("/usr/bin"));
        for denied in ["UA_AGENT_TOKENS", "UA_HOME", "OPENAI_API_KEY", "RANDOM_VAR"] {
            assert!(!env.contains_key(denied), "{denied} leaked");
        }
        assert_eq!(env["UA_DISPATCH_RUN_ID"], "run-1-ab", "the binding wins over a parent value");
        assert_eq!(env["UA_DISPATCH_FENCE"], "2");

        // A harness may scope a provider key to itself, never a hub secret.
        h.env_allowlist = vec!["OPENAI_API_KEY".into(), "UA_AGENT_TOKENS".into(), "UA_HOME".into()];
        let env = child_env(parent.clone(), &h, &binding(), &[]);
        assert_eq!(env.get("OPENAI_API_KEY").map(String::as_str), Some("k"));
        assert!(!env.contains_key("UA_AGENT_TOKENS"));
        assert!(!env.contains_key("UA_HOME"));

        // Fixed values, a denylist that beats every other source, and PATH
        // entries in front.
        h.env = [
            ("FIXED".to_string(), "run={run_id}".to_string()),
            ("UA_HOME".to_string(), "/elsewhere".to_string()),
            ("UA_DISPATCH_FENCE".to_string(), "9".to_string()),
        ]
        .into_iter()
        .collect();
        h.env_denylist = vec!["OPENAI_API_KEY".into(), "FIXED_GONE".into()];
        h.path_prepend = vec!["/opt/pi/bin".into(), "/usr/bin".into()];
        let env = child_env(parent, &h, &binding(), &[("run_id", "run-1-ab".into())]);
        assert_eq!(env["FIXED"], "run=run-1-ab");
        assert!(!env.contains_key("OPENAI_API_KEY"), "denied even when allowlisted");
        assert!(!env.contains_key("UA_HOME"), "no fixed value in the hub's namespace");
        assert_eq!(env["UA_DISPATCH_FENCE"], "2", "the binding wins");
        assert_eq!(env["PATH"], "/opt/pi/bin:/usr/bin");
    }

    #[test]
    fn argv_placeholders_stay_single_arguments() {
        let argv = render_argv(
            &["agent".into(), "--print".into(), "{prompt}".into(), "--run={run_id}".into()],
            &[("prompt", "a; rm -rf / && b".into()), ("run_id", "run-9".into())],
        );
        assert_eq!(argv, vec!["agent", "--print", "a; rm -rf / && b", "--run=run-9"]);
        // One pass: a value that looks like a placeholder is not expanded.
        let vars = [("run_id", "run-9".to_string()), ("prompt", "say {run_id} {nope".to_string())];
        assert_eq!(render_one("{prompt}|{run_id}|{other}", &vars), "say {run_id} {nope|run-9|{other}");
    }

    #[test]
    fn secret_names() {
        for n in ["GITHUB_TOKEN", "AWS_SECRET_ACCESS_KEY", "SSH_KEY", "MY_API_KEY", "DB_PASSWORD"] {
            assert!(looks_secret(n), "{n}");
        }
        for n in ["PATH", "HOME", "KEYBOARD", "MONKEY_PATCH"] {
            assert!(!looks_secret(n), "{n}");
        }
    }
}
