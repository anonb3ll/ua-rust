//! Workspace family: sandboxed files (`fs_*`), allowlisted commands
//! (`run_cmd*`) and git (`git_*`).
//!
//! Every path goes through `ua_core::safety`. Reads resolve inside the
//! workspace root or, for absolute paths, one of `cfg.read_roots`; writes,
//! commands and git stay inside the workspace root. `cfg.agent_workspaces`
//! can give an agent its own root, or `deny` to refuse it every tool here.
//!
//! Programs run with `tokio::process`, never a shell, in their own process
//! group (`Command::process_group(0)`). On timeout the whole group is killed
//! with one `killpg(SIGKILL)`, so grandchildren cannot outlive the call or
//! keep the output pipes open. This needs only `libc` (already in the
//! dependency graph through tokio) and keeps output capping in our code.

mod fs;
mod git;
mod shell;

pub(crate) use shell::ScratchHome;
pub use shell::sweep_run_homes;

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::Value;
use tokio::io::{AsyncRead, AsyncReadExt};
use ua_core::{UaError, UaResult};
use ua_store::{EventInput, ledger};

use crate::registry::{Registry, ToolCtx};

pub fn register(r: &mut Registry) {
    fs::register(r);
    git::register(r);
    shell::register(r);
}

/// The roots one caller works in.
#[derive(Debug, Clone)]
pub(crate) struct Sandbox {
    /// Canonical workspace root: reads, writes, commands and git.
    pub root: PathBuf,
    /// Canonical extra read-only roots that exist on this host.
    pub read_roots: Vec<PathBuf>,
}

impl Sandbox {
    /// Workspace root first, then the read roots.
    pub fn all_read_roots(&self) -> Vec<PathBuf> {
        let mut v = vec![self.root.clone()];
        v.extend(self.read_roots.iter().filter(|r| **r != self.root).cloned());
        v
    }

    /// `p` relative to the root that contains it, for events and results.
    pub fn rel(&self, p: &Path) -> String {
        for root in std::iter::once(&self.root).chain(self.read_roots.iter()) {
            if let Ok(rest) = p.strip_prefix(root) {
                let s = rest.to_string_lossy();
                return if s.is_empty() { ".".into() } else { s.into_owned() };
            }
        }
        p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default()
    }
}

fn expand_tilde(raw: &str) -> PathBuf {
    if let Some(rest) = raw.strip_prefix("~/")
        && let Some(home) = std::env::var_os("HOME")
    {
        return PathBuf::from(home).join(rest);
    }
    PathBuf::from(raw)
}

/// Resolve the caller's sandbox, honouring a per-agent workspace override.
pub(crate) fn sandbox(ctx: &ToolCtx) -> UaResult<Sandbox> {
    let cfg = ctx.hub.cfg();
    let configured = match cfg.agent_workspaces.get(&ctx.caller.label) {
        Some(v) if v.trim().eq_ignore_ascii_case("deny") => {
            return Err(UaError::denied(
                "workspace_denied",
                format!(
                    "hub-mediated filesystem, command and git access is denied for agent {:?}",
                    ctx.caller.label
                ),
            ));
        }
        Some(v) => expand_tilde(v.trim()),
        None => cfg.workspace_root(),
    };
    let root = configured
        .canonicalize()
        .map_err(|_| UaError::not_found("the workspace root does not exist on this host"))?;
    let read_roots = cfg.read_roots.iter().filter_map(|r| r.canonicalize().ok()).collect();
    Ok(Sandbox { root, read_roots })
}

/// Append one ledger event attributed to the caller.
pub(crate) async fn record(ctx: &ToolCtx, channel: &'static str, payload: Value) -> UaResult<()> {
    let by = ctx.caller.label.clone();
    ctx.hub
        .db()
        .write_async(move |tx| {
            ledger::append(tx, EventInput::new(channel, payload).by(by))?;
            Ok(())
        })
        .await
}

/// Hex SHA-256 of some bytes.
pub(crate) fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(data))
}

/// Captured result of one program run.
#[derive(Debug, Default)]
pub(crate) struct RunOutput {
    /// Exit code; `-N` when killed by signal N, `-1` on timeout.
    pub exit_code: i32,
    /// At most `cap` bytes of stdout.
    pub stdout: Vec<u8>,
    /// At most `cap` bytes of stderr.
    pub stderr: Vec<u8>,
    /// Bytes the program wrote to stdout, including those past the cap.
    pub stdout_total: usize,
    pub stderr_total: usize,
    pub timed_out: bool,
}

type Sink = Arc<Mutex<(Vec<u8>, usize)>>;

async fn drain<R: AsyncRead + Unpin>(mut r: R, cap: usize, sink: Sink) {
    let mut chunk = [0u8; 8192];
    loop {
        match r.read(&mut chunk).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                let Ok(mut s) = sink.lock() else { break };
                s.1 += n;
                if s.0.len() < cap {
                    let take = (cap - s.0.len()).min(n);
                    s.0.extend_from_slice(&chunk[..take]);
                }
            }
        }
    }
}

#[cfg(unix)]
fn kill_group(pid: Option<u32>) {
    if let Some(pid) = pid.and_then(|p| libc::pid_t::try_from(p).ok())
        && pid > 0
    {
        // SAFETY: killpg only sends a signal. The group id is the pid of a
        // child we spawned as group leader and have not reaped yet (or whose
        // group still has members), so it cannot name an unrelated group.
        unsafe {
            libc::killpg(pid, libc::SIGKILL);
        }
    }
}

#[cfg(not(unix))]
fn kill_group(_pid: Option<u32>) {}

fn exit_code(status: std::process::ExitStatus) -> i32 {
    if let Some(c) = status.code() {
        return c;
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(sig) = status.signal() {
            return -sig;
        }
    }
    -1
}

/// Run `program` with `args` in `cwd` with exactly `env` (the parent
/// environment is not inherited), no stdin, a timeout and a per-stream
/// output cap. Output past the cap is read and discarded so the program never
/// blocks on a full pipe. `Err` only when the program could not be started.
pub(crate) async fn run_program(
    program: &str,
    args: &[String],
    cwd: &Path,
    env: &[(String, String)],
    timeout: Duration,
    cap: usize,
) -> std::io::Result<RunOutput> {
    let mut cmd = tokio::process::Command::new(program);
    cmd.args(args)
        .current_dir(cwd)
        .env_clear()
        .envs(env.iter().map(|(k, v)| (k.as_str(), v.as_str())))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    #[cfg(unix)]
    cmd.process_group(0);
    let mut child = cmd.spawn()?;
    let pid = child.id();

    let out_sink: Sink = Arc::default();
    let err_sink: Sink = Arc::default();
    let mut readers = Vec::new();
    if let Some(o) = child.stdout.take() {
        readers.push(tokio::spawn(drain(o, cap, out_sink.clone())));
    }
    if let Some(e) = child.stderr.take() {
        readers.push(tokio::spawn(drain(e, cap, err_sink.clone())));
    }

    let (code, timed_out) = match tokio::time::timeout(timeout, child.wait()).await {
        Ok(Ok(status)) => (exit_code(status), false),
        Ok(Err(e)) => {
            kill_group(pid);
            return Err(e);
        }
        Err(_) => {
            // Not reaped yet, so the group id is still ours.
            kill_group(pid);
            let _ = child.kill().await;
            (-1, true)
        }
    };

    // A grandchild may still hold the pipes open. Give the readers a moment,
    // then kill what is left of the group and stop reading.
    let mut pending = Vec::new();
    for h in readers {
        let mut h = h;
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

    let take = |s: &Sink| s.lock().map(|g| (g.0.clone(), g.1)).unwrap_or_default();
    let (stdout, stdout_total) = take(&out_sink);
    let (stderr, stderr_total) = take(&err_sink);
    Ok(RunOutput { exit_code: code, stdout, stderr, stdout_total, stderr_total, timed_out })
}

/// The minimal environment child programs get: PATH, HOME and LANG.
pub(crate) fn base_env() -> Vec<(String, String)> {
    let get = |k: &str, d: &str| std::env::var(k).unwrap_or_else(|_| d.to_string());
    vec![
        ("PATH".into(), get("PATH", "/usr/bin:/bin:/usr/local/bin")),
        ("HOME".into(), get("HOME", "")),
        ("LANG".into(), get("LANG", "C.UTF-8")),
    ]
}

/// `base_env` plus settings that keep git from discovering a bare repository
/// an agent laid out, starting a filesystem monitor, or prompting.
pub(crate) fn git_env() -> Vec<(String, String)> {
    let mut env = base_env();
    for (k, v) in [
        ("GIT_TERMINAL_PROMPT", "0"),
        ("GIT_CONFIG_COUNT", "2"),
        ("GIT_CONFIG_KEY_0", "safe.bareRepository"),
        ("GIT_CONFIG_VALUE_0", "explicit"),
        ("GIT_CONFIG_KEY_1", "core.fsmonitor"),
        ("GIT_CONFIG_VALUE_1", "false"),
    ] {
        env.push((k.into(), v.into()));
    }
    env
}
