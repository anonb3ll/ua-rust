//! The `ua` command.

mod ops;

use std::io::Read;
use std::process::ExitCode;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use rand::RngCore;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio_util::sync::CancellationToken;
use ua_core::identity::Transport;
use ua_core::{ActorKind, Caller, Config};
use ua_server::AppState;
use ua_tools::{Hub, builtin_registry};

/// `ua --version`: the version and the optional Cargo features compiled in,
/// the same list system_doctor and capability_catalog report as
/// `build_features`.
fn version_text() -> &'static str {
    static TEXT: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    TEXT.get_or_init(|| {
        let names = |on: bool| -> String {
            let v: Vec<&str> =
                ua_tools::BUILD_FEATURES.iter().filter(|f| f.enabled == on).map(|f| f.feature).collect();
            if v.is_empty() { "none".into() } else { v.join(", ") }
        };
        format!("{} (features: {}; without: {})", env!("CARGO_PKG_VERSION"), names(true), names(false))
    })
}

/// ua: agent-operations hub.
#[derive(Parser)]
#[command(version = version_text(), about, propagate_version = true)]
struct Cli {
    /// Config file (default: $UA_CONFIG, then $UA_HOME/config.toml).
    #[arg(long, global = true, env = "UA_CONFIG")]
    config: Option<std::path::PathBuf>,
    /// Open a database written by a newer build anyway, ignoring the schema
    /// parts this build does not know (also `UA_ALLOW_NEWER_SCHEMA=1`). For
    /// recovery only: logged at every open; see docs/operations.md.
    #[arg(long, global = true)]
    allow_newer_schema: bool,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the HTTP hub (MCP at /mcp, JSON API at /api).
    Serve,
    /// Serve MCP over stdin/stdout for one local client (needs the
    /// mcp-server feature, on by default).
    Mcp {
        /// Identity label to act as.
        #[arg(long, env = "UA_AGENT_LABEL")]
        label: Option<String>,
    },
    /// List tools.
    Tools {
        /// Print names only.
        #[arg(long)]
        names: bool,
    },
    /// Call a tool locally. Arguments are JSON (an argument, or stdin with `-`).
    Call {
        tool: String,
        args: Option<String>,
        /// Identity label to act as (a configured human identity acts as human).
        #[arg(long, env = "UA_AGENT_LABEL")]
        label: Option<String>,
    },
    /// Manage agent tokens.
    Token {
        #[command(subcommand)]
        cmd: TokenCmd,
    },
    /// Print a single-use, short-lived browser sign-in URL for a human
    /// identity (the first Control Center login on a fresh install).
    LoginLink {
        /// A label listed in `human_identities`.
        label: String,
    },
    /// Print the effective configuration (secrets redacted).
    Config,
    /// Import data from another hub into this hub's database.
    Import {
        #[command(subcommand)]
        cmd: ImportCmd,
    },
    /// Initialize `$UA_HOME` with a starter config.toml, optional policy.yaml,
    /// and local harness MCP setup snippets.
    Init(ops::init::InitArgs),
    /// Run read-only health, security, permission, database, and ledger checks.
    Doctor(ops::doctor::DoctorArgs),
    /// Manage evidence signing keys and checkpoint signatures.
    Evidence(ops::evidence::EvidenceArgs),
    /// Manage memory subsystem assets (pinned local embedding models).
    Memory(ops::memory_models::MemoryArgs),
    /// Take a verified, consistent SQLite snapshot of the hub database (safe while serving).
    Backup(ops::backup::BackupArgs),
    /// Verify and atomically restore a hub database snapshot (requires hub to be stopped).
    Restore(ops::backup::RestoreArgs),
}

#[derive(Subcommand)]
enum ImportCmd {
    /// Import a Python hub database (opened read-only). Re-running resumes
    /// and skips rows already copied. Prints a JSON report. Take a target
    /// snapshot first when importing into a non-empty database: post-import
    /// ledger verification runs after batches commit, so a failed verification
    /// leaves imported rows in place without rollback.
    PythonHub {
        /// Path to the Python hub's SQLite database.
        #[arg(long = "from")]
        from: std::path::PathBuf,
        /// Report counts, unmapped tables and columns and the source ledger
        /// check without writing anything.
        #[arg(long)]
        dry_run: bool,
        /// Import even if some source rows carry an `org_id`. ua-rust has no
        /// tenant scope, so those rows lose their boundary.
        #[arg(long)]
        drop_org_scope: bool,
    },
}

#[derive(Subcommand)]
enum TokenCmd {
    /// Issue a token for an identity. The raw value is printed once.
    Issue {
        label: String,
        #[arg(long)]
        note: Option<String>,
    },
    /// Revoke every active token of an identity.
    Revoke { label: String },
}

pub(crate) fn load_config(explicit: Option<&std::path::Path>) -> anyhow::Result<Config> {
    let _ = dotenvy::dotenv();
    match explicit {
        Some(p) => Config::load_from(p),
        None => Config::load(),
    }
}

pub(crate) fn issue_agent_token(
    cfg: &Config,
    hub: &Hub,
    label: &str,
    note: Option<&str>,
    by: &str,
) -> anyhow::Result<String> {
    // A token for a human identity grants approval rights over HTTP;
    // mint one only on an operator's explicit confirmation.
    if cfg.is_human(label) && (std::env::var_os("UA_AGENT_LABEL").is_some() || !confirm_on_tty(label)) {
        anyhow::bail!("issuing a token for human {label:?} needs an operator at an interactive terminal");
    }
    let mut raw = [0u8; 32];
    rand::rng().fill_bytes(&mut raw);
    let token = format!("ua_{}", hex::encode(raw));
    let hash = hex::encode(Sha256::digest(token.as_bytes()));
    let now = ua_core::time::now();
    let reserved = ua_tools::families::agents::Reserved::of(hub.cfg());
    hub.db().write(|tx| {
        // The CLI runs on the hub host and issues default-organization
        // tokens; a label another organization's agent holds is refused.
        if ua_tools::families::tokens::held_outside_default(tx, &reserved, label)? {
            return Err(ua_core::UaError::conflict_code(
                "agent_label_taken",
                format!("agent label {label:?} is taken; agent labels are one hub-wide namespace"),
            ));
        }
        tx.execute(
            "INSERT INTO agent_tokens (org_id, agent_label, token_hash, issued_at, issued_by, note) \
             VALUES (?6, ?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![label, hash, now, by, note, ua_core::DEFAULT_ORG],
        )?;
        ua_store::ledger::append(
            tx,
            ua_store::EventInput::new(
                ua_core::DEFAULT_ORG,
                "agent.token.issued",
                serde_json::json!({ "agent": label }),
            )
            .by(by),
        )?;
        Ok(())
    })?;
    Ok(token)
}

/// The caller for a local CLI invocation.
///
/// Acting as a human (who may approve gated calls) needs all of:
/// - an explicit `--label` naming a configured human identity (never a
///   default, and never a label that only came from `UA_AGENT_LABEL`, which
///   is how agent processes are launched);
/// - no `UA_AGENT_LABEL` in the environment at all;
/// - the operator typing the label back on an interactive terminal.
///
/// These are speed bumps, not a security boundary. Anything running as the
/// hub's OS user can read the database file directly, so the real boundary
/// is the OS account: run agents under a different user than the hub (see
/// SECURITY.md).
fn local_caller(cfg: &Config, label: Option<String>) -> Caller {
    let from_env = std::env::var("UA_AGENT_LABEL").ok();
    local_caller_with(cfg, label, from_env.as_deref(), confirm_on_tty)
}

fn local_caller_with(
    cfg: &Config,
    label: Option<String>,
    agent_env: Option<&str>,
    confirm: impl FnOnce(&str) -> bool,
) -> Caller {
    let explicit = label.is_some() && agent_env.is_none();
    let mut c = Caller::local(label.unwrap_or_else(|| ua_core::identity::LOCAL_LABEL.into()), Transport::Cli);
    if explicit && cfg.is_human(&c.label) && confirm(&c.label) {
        c.kind = ActorKind::Human;
    }
    c
}

/// Crates whose debug and trace logs are always dropped. rmcp logs whole
/// requests and responses: tool arguments (a managed_secret_set value) and
/// downstream MCP results (a reflected credential). tungstenite and
/// tokio-tungstenite (Slack Socket Mode) log the WebSocket handshake
/// request, whose URL carries Slack's one-time connection ticket.
const CAPPED_TARGETS: [&str; 3] = ["rmcp", "tungstenite", "tokio_tungstenite"];

/// Whether a log at `level` from `target` is dropped ([`CAPPED_TARGETS`]).
fn capped(target: &str, level: &tracing::Level) -> bool {
    CAPPED_TARGETS.iter().any(|c| target == *c || target.strip_prefix(c).is_some_and(|r| r.starts_with("::")))
        && matches!(*level, tracing::Level::DEBUG | tracing::Level::TRACE)
}

/// The log layer: `filter` (from UA_LOG), then a cap no directive can lift
/// (not even a more specific one such as `rmcp::service=debug`): rmcp,
/// tungstenite and tokio-tungstenite never log below info.
fn log_layer<S, W>(
    filter: tracing_subscriber::EnvFilter,
    writer: W,
) -> impl tracing_subscriber::Layer<S> + Send + Sync + 'static
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
    W: for<'w> tracing_subscriber::fmt::MakeWriter<'w> + Send + Sync + 'static,
{
    use tracing_subscriber::Layer;
    use tracing_subscriber::filter::{FilterExt, filter_fn};
    let cap = filter_fn(|meta| !capped(meta.target(), meta.level()));
    tracing_subscriber::fmt::layer().with_writer(writer).with_filter(filter.and(cap))
}

/// Ask the operator to type `label` on an interactive terminal.
fn confirm_on_tty(label: &str) -> bool {
    use std::io::{BufRead, IsTerminal, Write};
    if !std::io::stdin().is_terminal() || !std::io::stderr().is_terminal() {
        eprintln!("note: acting as human {label:?} needs an interactive terminal; continuing as non-human");
        return false;
    }
    eprint!("Act as human {label:?}? Type the label to confirm: ");
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line).is_ok() && line.trim() == label
}

/// How long a shutdown waits for open connections and background tasks.
const SHUTDOWN_GRACE: std::time::Duration = std::time::Duration::from_secs(10);

/// Wait for SIGINT (Ctrl-C) or, on Unix, SIGTERM (service managers,
/// containers). Returns the signal's name.
async fn shutdown_signal() -> &'static str {
    #[cfg(unix)]
    let term = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(e) => {
                tracing::warn!(error = %e, "cannot listen for SIGTERM; only Ctrl-C stops the hub gracefully");
                std::future::pending::<()>().await;
            }
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! {
        _ = tokio::signal::ctrl_c() => "SIGINT",
        _ = term => "SIGTERM",
    }
}

/// How long the runtime waits, after the drain, for tasks still running
/// (blocking work included) before the process exits.
const RUNTIME_SHUTDOWN: std::time::Duration = std::time::Duration::from_secs(3);

/// Serve until `ct` is cancelled (or the server stops on its own), then
/// drain everything at once against one deadline ([`SHUTDOWN_GRACE`]):
/// - the HTTP server's open requests (event streams and MCP sessions end on
///   the token);
/// - MCP tool calls in flight ([`AppState::calls`]);
/// - dispatch runs: they may finish until shortly before the deadline, then
///   each child's process group gets SIGTERM, then SIGKILL, and the run is
///   recorded `retryable` with a `hub_shutdown` receipt;
/// - the background loops (stopped between ticks; aborted at the deadline).
///
/// Then the WAL is checkpointed and truncated.
async fn serve_until_shutdown(
    state: AppState,
    ct: CancellationToken,
    background: Vec<tokio::task::JoinHandle<()>>,
) -> anyhow::Result<()> {
    let (hub, calls) = (state.hub.clone(), state.calls.clone());
    let server = ua_server::serve_http(state, ct.clone());
    tokio::pin!(server);
    let ended = tokio::select! {
        r = &mut server => Some(r),
        _ = ct.cancelled() => None,
    };
    let deadline = tokio::time::Instant::now() + SHUTDOWN_GRACE;
    // The server stopped by itself (a bind error): stop everything else too.
    ct.cancel();
    let http = async {
        match ended {
            Some(r) => r,
            None => match tokio::time::timeout_at(deadline, &mut server).await {
                Ok(r) => r,
                Err(_) => {
                    tracing::warn!(
                        grace_s = SHUTDOWN_GRACE.as_secs(),
                        "connections still open after the grace period; closing them"
                    );
                    Ok(())
                }
            },
        }
    };
    let mcp_calls = async {
        calls.close();
        if tokio::time::timeout_at(deadline, calls.wait()).await.is_err() {
            tracing::warn!(open = calls.len(), "MCP tool calls still running after the grace period");
        }
    };
    let loops = async {
        let mut abandoned = 0;
        for task in background {
            let abort = task.abort_handle();
            if tokio::time::timeout_at(deadline, task).await.is_err() {
                abort.abort();
                abandoned += 1;
            }
        }
        if abandoned > 0 {
            tracing::warn!(abandoned, "background tasks still running after the grace period were stopped");
        }
    };
    let (served, (), (), runs) = tokio::join!(
        http,
        mcp_calls,
        loops,
        ua_tools::families::dispatch::executor::drain_supervisors(deadline)
    );
    if runs.stopped > 0 || runs.unfinished > 0 {
        tracing::info!(
            stopped = runs.stopped,
            unfinished = runs.unfinished,
            "dispatch runs stopped for the shutdown (recorded retryable, hub_shutdown)"
        );
    }
    match tokio::task::spawn_blocking(move || hub.db().checkpoint_truncate()).await {
        Ok(Ok((false, _, done))) => {
            tracing::info!(checkpointed_frames = done, "WAL checkpointed and truncated")
        }
        Ok(Ok((true, log, done))) => {
            tracing::warn!(
                wal_frames = log,
                checkpointed_frames = done,
                "WAL checkpoint incomplete: a reader was busy"
            )
        }
        Ok(Err(e)) => tracing::warn!(error = %e, "WAL checkpoint failed"),
        Err(e) => tracing::warn!(error = %e, "WAL checkpoint task failed"),
    }
    tracing::info!("hub stopped");
    served
}

/// The locks a command holds until the process is about to exit.
#[derive(Default)]
struct Held {
    /// The shared hub lock (every command that opens the hub).
    hub: Option<ua_import::HubLock>,
    /// The one-serving-process lock (`ua serve` only).
    serve: Option<ua_import::ServeLock>,
}

/// Build the runtime, run the command, then give the runtime
/// [`RUNTIME_SHUTDOWN`] for what is still running. The locks are released
/// only after that, so an import (or a second `ua serve`) cannot start while
/// this process's tasks may still write.
fn main() -> ExitCode {
    let rt = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("Error: {e:#}");
            return ExitCode::from(1);
        }
    };
    let mut held = Held::default();
    let result = rt.block_on(run(&mut held));
    rt.shutdown_timeout(RUNTIME_SHUTDOWN);
    drop(held);
    match result {
        Ok(code) => code,
        Err(e) => {
            eprintln!("Error: {e:#}");
            ExitCode::from(1)
        }
    }
}

/// What `ua mcp` answers in a build without the `mcp-server` feature.
#[cfg(not(feature = "mcp-server"))]
const NO_MCP_SERVER: &str = "ua mcp: this ua was built without the mcp-server feature, so it serves no MCP. \
Rebuild with default features (or `--features mcp-server`), or call tools with `ua call` or the JSON API.";

async fn run(held: &mut Held) -> anyhow::Result<ExitCode> {
    let cli = Cli::parse();
    let filter = tracing_subscriber::EnvFilter::try_from_env("UA_LOG").unwrap_or_else(|_| "info".into());
    {
        use tracing_subscriber::layer::SubscriberExt;
        use tracing_subscriber::util::SubscriberInitExt;
        tracing_subscriber::registry().with(log_layer(filter, std::io::stderr)).init();
    }

    let is_evidence_verify = matches!(
        &cli.cmd,
        Cmd::Evidence(ops::evidence::EvidenceArgs { cmd: ops::evidence::EvidenceCmd::Verify { .. } })
    );
    match run_cmd(cli, held).await {
        Ok(code) => Ok(code),
        Err(e) if is_evidence_verify => {
            // `ua evidence verify` reserves exit 1 for cryptographic or ledger
            // refusals; config, lock, open (including newer-schema refusal),
            // and database errors exit 2 ("cannot verify").
            eprintln!("Error: {e:#}");
            Ok(ExitCode::from(2))
        }
        Err(e) => Err(e),
    }
}

async fn run_cmd(cli: Cli, held: &mut Held) -> anyhow::Result<ExitCode> {
    let explicit_config = cli.config.clone();
    // Read before any `.env` file is loaded (`load_config`): the override comes
    // only from the command line or the real process environment.
    let allow_newer_var = std::env::var_os(ua_tools::hub::ALLOW_NEWER_SCHEMA_ENV);
    let allow_newer_flag = cli.allow_newer_schema;
    let allow_newer = || allow_newer_schema(allow_newer_flag, allow_newer_var.clone());
    match cli.cmd {
        Cmd::Init(args) => {
            ops::init::run(args, explicit_config.as_deref(), allow_newer()?).await?;
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Doctor(args) => ops::doctor::run(args, explicit_config.as_deref()),
        // Offline evidence commands never touch the hub database: no lock, no
        // open, no migration. A signing key must not require a hub to exist.
        Cmd::Evidence(ops::evidence::EvidenceArgs {
            cmd: ops::evidence::EvidenceCmd::KeyGenerate { out },
        }) => {
            ops::evidence::run_key_generate(&out)?;
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Evidence(ops::evidence::EvidenceArgs {
            cmd: ops::evidence::EvidenceCmd::Sign { key_file, checkpoint_file, prev_checkpoint, out },
        }) => {
            ops::evidence::run_sign(&key_file, &checkpoint_file, prev_checkpoint.as_deref(), out.as_deref())?;
            Ok(ExitCode::SUCCESS)
        }
        cmd => {
            let cfg = load_config(explicit_config.as_deref())?;

            // Refused before the hub lock and Hub::open, which may migrate the
            // database: a build that cannot serve MCP touches nothing.
            #[cfg(not(feature = "mcp-server"))]
            if let Cmd::Mcp { .. } = cmd {
                anyhow::bail!("{NO_MCP_SERVER}");
            }

            match cmd {
                Cmd::Config => {
                    println!("{}", serde_json::to_string_pretty(&cfg)?);
                    Ok(ExitCode::SUCCESS)
                }
                Cmd::Memory(args) => {
                    ops::memory_models::run(&cfg, args).await?;
                    Ok(ExitCode::SUCCESS)
                }
                Cmd::Import { cmd: ImportCmd::PythonHub { from, dry_run, drop_org_scope } } => {
                    let report = if dry_run {
                        ua_import::dry_run(&from)?
                    } else {
                        // Held until the import ends: no hub may run on this database.
                        let _lock = ua_import::HubLock::acquire(&cfg.db_path(), "import")?;
                        let db = ua_tools::hub::open_db(
                            &cfg.db_path(),
                            &ua_import::schema_parts(),
                            allow_newer()?,
                            None,
                        )?;
                        let opts = ua_import::Options { drop_org_scope, ..Default::default() };
                        ua_import::import(&db, &from, &opts)?
                    };
                    println!("{}", serde_json::to_string_pretty(&report)?);
                    Ok(ExitCode::SUCCESS)
                }
                Cmd::Backup(args) => {
                    ops::backup::run_backup(&cfg, args)?;
                    Ok(ExitCode::SUCCESS)
                }
                Cmd::Restore(args) => {
                    ops::backup::run_restore(&cfg, args)?;
                    Ok(ExitCode::SUCCESS)
                }
                cmd => {
                    // Every command that opens the hub holds a shared lock while it runs, so an
                    // import or restore (which takes it exclusively) refuses while any of them is live.
                    held.hub = Some(ua_import::HubLock::acquire_shared(&cfg.db_path(), "this command")?);
                    // One `ua serve` per database (docs/ingress.md, Limits): taken before the
                    // database is opened, a port is bound or any inbound state is touched.
                    if let Cmd::Serve = cmd {
                        held.serve = Some(ua_import::ServeLock::acquire(&cfg.db_path())?);
                    }
                    // Refuses a database a newer build wrote, unless overridden (docs/operations.md).
                    // `ua serve` refuses it even then: serving it reopens the replay window.
                    let override_on = allow_newer()?;
                    let hub = match held.serve.as_ref() {
                        // The serving process migrates under its own serve lock.
                        Some(serving) => open_for_serve(&cfg, override_on, serving)?,
                        // Every other command: the default open refuses to migrate
                        // underneath a running `ua serve`.
                        None => Hub::open_with(cfg.clone(), override_on)?,
                    };
                    let registry = Arc::new(builtin_registry());
                    let state = AppState::new(hub.clone(), registry.clone());

                    match cmd {
                        Cmd::Serve => {
                            // Fail closed before starting background loops or binding any port:
                            // `enforce_auth = false` is single-organization mode only.
                            ua_server::auth::check_auth_policy(&hub)?;
                            warn_if_locked_out(&state).await;
                            // One token for the server and every background loop: a signal
                            // cancels it, then `serve_until_shutdown` drains them.
                            let ct = CancellationToken::new();
                            let mut background = Vec::new();
                            if cfg.routines_enabled {
                                background.push(tokio::spawn(ua_tools::families::routines::run_ticker(
                                    hub.clone(),
                                    ct.clone(),
                                )));
                            }
                            if let Some(w) = ua_server::login::insecure_origin_warning(&cfg) {
                                tracing::warn!("{w}");
                            }
                            match ua_server::oauth::register::prune_unused_clients(&hub).await {
                                Ok(0) => {}
                                Ok(n) => {
                                    tracing::info!(
                                        pruned = n,
                                        "removed registered OAuth clients that never got a grant"
                                    )
                                }
                                Err(e) => tracing::warn!(error = %e, "could not prune unused OAuth clients"),
                            }
                            ua_tools::families::workspace::sweep_run_homes();
                            if let Some(w) = ua_tools::families::workspace::cargo_config_warning(&cfg) {
                                tracing::warn!("{w}");
                            }
                            // One toolchain lookup in the background, so cargo started by a
                            // build tool or script finds the toolchain on a fresh hub.
                            ua_tools::families::workspace::warm_host_rust(&cfg.home);
                            let pruned = ua_tools::families::workspace::prune_run_caches(
                                &cfg.home,
                                ua_tools::families::workspace::RUN_CACHE_MAX_AGE,
                            );
                            if pruned > 0 {
                                tracing::info!(pruned, "removed run_cmd caches unused for 30 days");
                            }
                            // Reconcile runs a previous hub process left behind, then keep
                            // sweeping. Only the server reaps: a short-lived `ua call` or a
                            // stdio session must not judge another process's children.
                            ua_tools::families::dispatch::startup_sweep(&hub).await;
                            background.extend(ua_tools::families::dispatch::spawn_reaper(&hub, ct.clone()));
                            // Expire waits and lapsed node leases, and retry owed command
                            // notices, for every node.
                            background
                                .extend(ua_tools::families::node_queue::spawn_sweeper(&hub, ct.clone()));
                            // Poll the bound repositories' open pull requests when no webhook
                            // can reach this hub (github_poll_interval_s; 0 = off).
                            background.extend(ua_tools::families::github::spawn_poller(&hub, ct.clone()));
                            // Automatically backfill missing or stale memory vectors/chunks on
                            // startup (e.g. after an upgrade or identity change) and periodically
                            // thereafter, strictly per active organization.
                            background.extend(ua_tools::families::memory::spawn_backfill(&hub, ct.clone()));
                            // Routine fires a previous process left mid-workflow or unstarted.
                            let h = hub.clone();
                            background.push(tokio::spawn(async move {
                                match ua_tools::families::routines::reconcile_fires(&h).await {
                                    Ok(v) => {
                                        let n = |k: &str| v[k].as_array().map_or(0, Vec::len);
                                        if n("interrupted") + n("not_run") + n("rerun") > 0 {
                                            tracing::info!(
                                                interrupted = n("interrupted"),
                                                not_run = n("not_run"),
                                                rerun = n("rerun"),
                                                "reconciled routine fires"
                                            );
                                        }
                                    }
                                    Err(e) => tracing::warn!(error = %e, "could not reconcile routine fires"),
                                }
                            }));
                            let signal_ct = ct.clone();
                            tokio::spawn(async move {
                                let which = shutdown_signal().await;
                                tracing::info!(
                                    signal = which,
                                    "shutting down: draining connections and background tasks"
                                );
                                signal_ct.cancel();
                                // A second signal does not wait for the drain.
                                let again = shutdown_signal().await;
                                let killed = ua_tools::families::dispatch::executor::kill_live_groups();
                                tracing::warn!(
                                    signal = again,
                                    killed_run_groups = killed,
                                    "second signal: exiting now"
                                );
                                std::process::exit(if again == "SIGTERM" { 143 } else { 130 });
                            });
                            serve_until_shutdown(state, ct, background).await?;
                        }
                        #[cfg(feature = "mcp-server")]
                        Cmd::Mcp { label } => ua_server::mcp::serve_stdio(state, label).await?,
                        #[cfg(not(feature = "mcp-server"))]
                        // Refused before the hub was opened (above).
                        Cmd::Mcp { .. } => anyhow::bail!("{NO_MCP_SERVER}"),
                        Cmd::Tools { names } => {
                            for t in registry.all() {
                                if names {
                                    println!("{}", t.name);
                                } else {
                                    println!("{:<28} {:<14} {}", t.name, t.family, t.description);
                                }
                            }
                        }
                        Cmd::Call { tool, args, label } => {
                            let args: Value = match args.as_deref() {
                                None => Value::Null,
                                Some("-") => {
                                    let mut s = String::new();
                                    std::io::stdin().read_to_string(&mut s)?;
                                    serde_json::from_str(&s)?
                                }
                                Some(s) => serde_json::from_str(s)?,
                            };
                            let caller = local_caller(&cfg, label);
                            match registry.call(&hub, &caller, &tool, args).await {
                                Ok(v) => println!("{}", serde_json::to_string_pretty(&v)?),
                                Err(e) => {
                                    eprintln!("{}", serde_json::to_string_pretty(&e.to_json())?);
                                    return Ok(ExitCode::from(1));
                                }
                            }
                        }
                        Cmd::Token { cmd } => match cmd {
                            TokenCmd::Issue { label, note } => {
                                let token = issue_agent_token(&cfg, &hub, &label, note.as_deref(), "cli")?;
                                eprintln!(
                                    "Token for {label} (shown once; store it in the agent's secret store):"
                                );
                                println!("{token}");
                            }
                            TokenCmd::Revoke { label } => {
                                let now = ua_core::time::now();
                                let n = hub.db().write(|tx| {
                                    let n = tx.execute(
                                        "UPDATE agent_tokens SET status = 'revoked', revoked_at = ?2 \
                                         WHERE org_id = ?3 AND agent_label = ?1 AND status = 'active'",
                                        rusqlite::params![label, now, ua_core::DEFAULT_ORG],
                                    )?;
                                    ua_store::ledger::append(
                                        tx,
                                        ua_store::EventInput::new(
                                            ua_core::DEFAULT_ORG,
                                            "agent.token.revoked",
                                            serde_json::json!({ "agent": label }),
                                        )
                                        .by("cli"),
                                    )?;
                                    Ok(n)
                                })?;
                                println!("revoked {n} token(s) for {label}");
                            }
                        },
                        Cmd::Evidence(args) => return ops::evidence::run(&hub, args),
                        Cmd::LoginLink { label } => {
                            // A login link signs a browser in as a human; same bar as acting
                            // as a human from the CLI.
                            if std::env::var_os("UA_AGENT_LABEL").is_some() || !confirm_on_tty(&label) {
                                anyhow::bail!(
                                    "a sign-in link for {label:?} needs an operator at an interactive terminal"
                                );
                            }
                            let url = ua_server::login::create_login_link(&hub, &label, "cli")?;
                            eprintln!(
                                "Sign-in link for {label} (single use, expires in {} s; open it in the browser you will use):",
                                cfg.login_link_ttl_secs
                            );
                            println!("{url}");
                        }
                        Cmd::Init(_)
                        | Cmd::Doctor(_)
                        | Cmd::Config
                        | Cmd::Memory(_)
                        | Cmd::Import { .. }
                        | Cmd::Backup(_)
                        | Cmd::Restore(_) => unreachable!(),
                    }
                    Ok(ExitCode::SUCCESS)
                }
            }
        }
    }
}

/// Whether to open a database written by a newer build anyway: the
/// `--allow-newer-schema` flag, or `UA_ALLOW_NEWER_SCHEMA` (`value`, read from
/// the process environment before any `.env` file was loaded) set to `1`. Any
/// value other than an explicit yes or no is refused rather than guessed at.
fn allow_newer_schema(flag: bool, value: Option<std::ffi::OsString>) -> anyhow::Result<bool> {
    if flag {
        return Ok(true);
    }
    let var = ua_tools::hub::ALLOW_NEWER_SCHEMA_ENV;
    let Some(v) = value else { return Ok(false) };
    let Some(v) = v.to_str() else { anyhow::bail!("{var} must be 1 or 0") };
    match v.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" => Ok(true),
        "" | "0" | "false" | "no" => Ok(false),
        _ => {
            anyhow::bail!("{var} must be 1 (open a database written by a newer build anyway) or 0, not {v:?}")
        }
    }
}

/// Open the hub for `ua serve`. The override never lets a serve start on a
/// database written by a newer build: it would take GitHub and Slack
/// deliveries while reading only the delivery tables this build knows, which
/// reopens the replay window the fence closes. The fenced open runs first, so
/// a refused serve has written nothing.
fn open_for_serve(
    cfg: &ua_core::Config,
    override_on: bool,
    serving: &ua_import::ServeLock,
) -> anyhow::Result<Hub> {
    let var = ua_tools::hub::ALLOW_NEWER_SCHEMA_ENV;
    match Hub::open_serving(cfg.clone(), serving) {
        Ok(hub) => {
            if override_on {
                tracing::warn!(
                    "--allow-newer-schema / {var} has no effect on ua serve (and this database needs none); unset it"
                );
            }
            Ok(hub)
        }
        Err(e) if override_on => match e.downcast_ref::<ua_store::NewerSchema>() {
            Some(newer) => anyhow::bail!(
                "ua serve refuses the database {} even with --allow-newer-schema / {var}: it was written by a newer \
                 build and records schema parts this build does not know ([{}]). Serving it would take GitHub and \
                 Slack deliveries while reading only the delivery tables this build knows, so copies of deliveries \
                 the newer build already handled would be accepted again. The override is for recovery through the \
                 commands that do not serve (ua call, ua tools, ua mcp, ua backup, ua doctor). Run the newer build, \
                 or restore a backup taken before the upgrade",
                newer.db,
                newer.unknown.join(", ")
            ),
            None => Err(e),
        },
        Err(e) => Err(e),
    }
}

/// With auth enforced and no credential configured, every non-public request
/// gets a 401. Say so at startup instead of leaving a bare 401 to puzzle over.
async fn warn_if_locked_out(state: &ua_server::AppState) {
    let cfg = state.hub.cfg();
    if !cfg.enforce_auth || !cfg.static_tokens().is_empty() {
        return;
    }
    let issued: i64 = state
        .hub
        .db()
        .read_async(|conn| {
            Ok(conn
                .query_row("SELECT COUNT(*) FROM agent_tokens WHERE status = 'active'", [], |r| r.get(0))?)
        })
        .await
        .unwrap_or(0);
    if issued == 0 {
        tracing::warn!(
            "enforce_auth is on and no tokens are configured, so every request except /healthz will get 401; \
             run `ua token issue <label>`"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Default)]
    struct Buf(Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for Buf {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'w> tracing_subscriber::fmt::MakeWriter<'w> for Buf {
        type Writer = Buf;
        fn make_writer(&'w self) -> Buf {
            self.clone()
        }
    }

    /// The Socket Mode handshake request (with the ticket in its URL) is
    /// logged by tungstenite at trace through the `log` bridge, under module
    /// targets; none of it passes, whatever UA_LOG says.
    #[test]
    fn tungstenite_never_logs_below_info() {
        use tracing_subscriber::layer::SubscriberExt;
        for directive in ["trace", "info,tungstenite=trace,tokio_tungstenite=trace", "debug"] {
            let buf = Buf::default();
            let filter = tracing_subscriber::EnvFilter::new(directive);
            let sub = tracing_subscriber::registry().with(log_layer(filter, buf.clone()));
            tracing::subscriber::with_default(sub, || {
                tracing::trace!(target: "tungstenite::handshake::client", "GET /link/?ticket=SECRET-TICKET");
                tracing::debug!(target: "tungstenite::protocol", "SECRET-FRAME");
                tracing::trace!(target: "tokio_tungstenite::compat", "SECRET-POLL");
                tracing::debug!(target: "tokio_tungstenite", "SECRET-ROOT");
                tracing::info!(target: "tungstenite::protocol", "tungstenite info kept");
                tracing::debug!(target: "tungstenitex", "lookalike kept");
            });
            let out = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
            assert!(!out.contains("SECRET"), "{directive}: {out}");
            assert!(out.contains("tungstenite info kept"), "{directive}: {out}");
            if directive != "info,tungstenite=trace,tokio_tungstenite=trace" {
                assert!(out.contains("lookalike kept"), "{directive}: {out}");
            }
        }
        assert!(capped("tungstenite::handshake::client", &tracing::Level::TRACE));
        assert!(capped("tokio_tungstenite", &tracing::Level::DEBUG));
        assert!(!capped("tungstenite", &tracing::Level::INFO));
    }

    #[test]
    fn rmcp_never_logs_below_info() {
        for directive in [
            "debug",
            "info,rmcp=trace",
            "info,rmcp::service=trace",
            "info,rmcp::service::server=debug",
            "trace",
        ] {
            let buf = Buf::default();
            let filter = tracing_subscriber::EnvFilter::new(directive);
            use tracing_subscriber::layer::SubscriberExt;
            let sub = tracing_subscriber::registry().with(log_layer(filter, buf.clone()));
            tracing::subscriber::with_default(sub, || {
                tracing::debug!(target: "rmcp::service::server", "body uas_secret_debug");
                tracing::trace!(target: "rmcp::service", "body uas_secret_trace");
                let span = tracing::debug_span!(target: "rmcp::service", "serve", req = "uas_secret_span");
                span.in_scope(|| tracing::info!(target: "ua_server", "inside the rmcp span"));
                tracing::info!(target: "rmcp::service", "rmcp info kept");
                tracing::debug!(target: "ua_server", "own debug");
            });
            let out = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
            assert!(!out.contains("uas_secret"), "{directive}: {out}");
            assert!(out.contains("rmcp info kept"), "{directive}: {out}");
            assert!(out.contains("inside the rmcp span"), "{directive}: {out}");
        }
    }

    fn cfg() -> Config {
        let mut c = Config::for_home(std::env::temp_dir());
        c.human_identities = vec!["operator".into()];
        c
    }

    #[test]
    fn no_label_is_never_human() {
        let c = local_caller_with(&cfg(), None, None, |_| true);
        assert_eq!(c.kind, ActorKind::Anonymous);
        assert_eq!(c.label, "local");
    }

    #[test]
    fn explicit_human_label_is_human_only_when_confirmed() {
        let c = local_caller_with(&cfg(), Some("operator".into()), None, |l| l == "operator");
        assert_eq!(c.kind, ActorKind::Human);
        let c = local_caller_with(&cfg(), Some("operator".into()), None, |_| false);
        assert_eq!(c.kind, ActorKind::Anonymous, "no terminal confirmation, no human");
    }

    #[test]
    fn an_agent_environment_cannot_claim_a_human_label() {
        // UA_AGENT_LABEL=agent-1 and an explicit --label operator: still not human.
        let c = local_caller_with(&cfg(), Some("operator".into()), Some("agent-1"), |_| true);
        assert_eq!(c.kind, ActorKind::Anonymous);
    }

    #[test]
    fn rmcp_debug_logs_stay_capped_whatever_ua_log_says() {
        use std::sync::{Arc, Mutex};
        use tracing_subscriber::layer::SubscriberExt;
        #[derive(Clone, Default)]
        struct Buf(Arc<Mutex<Vec<u8>>>);
        impl std::io::Write for Buf {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(b);
                Ok(b.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let buf = Buf::default();
        let out = buf.clone();
        let filter = tracing_subscriber::EnvFilter::new("debug,rmcp=trace,rmcp::service=debug");
        let sub = tracing_subscriber::registry().with(log_layer(filter, move || buf.clone()));
        tracing::subscriber::with_default(sub, || {
            tracing::debug!(target: "rmcp::service", "SECRET-REQUEST-BODY");
            tracing::trace!(target: "rmcp", "SECRET-TRACE");
            tracing::info!(target: "rmcp::service", "rmcp-info-kept");
            tracing::debug!(target: "ua_tools", "other-debug-kept");
            tracing::debug!(target: "rmcpx", "lookalike-kept");
        });
        let text = String::from_utf8(out.0.lock().unwrap().clone()).unwrap();
        assert!(!text.contains("SECRET"), "{text}");
        assert!(text.contains("rmcp-info-kept") && text.contains("other-debug-kept"), "{text}");
        assert!(text.contains("lookalike-kept"), "{text}");
        assert!(capped("rmcp::transport::worker", &tracing::Level::TRACE));
        assert!(!capped("rmcp", &tracing::Level::WARN));
    }

    #[test]
    fn agent_env_label_is_never_human() {
        // `--label` falls back to UA_AGENT_LABEL; a label from there is not
        // an operator's explicit choice.
        let c = local_caller_with(&cfg(), Some("operator".into()), Some("operator"), |_| true);
        assert_eq!(c.kind, ActorKind::Anonymous);
    }
}
