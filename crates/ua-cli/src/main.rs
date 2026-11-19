//! The `ua` command.

use std::io::Read;
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

/// ua: agent-operations hub.
#[derive(Parser)]
#[command(version, about, propagate_version = true)]
struct Cli {
    /// Config file (default: $UA_CONFIG, then $UA_HOME/config.toml).
    #[arg(long, global = true, env = "UA_CONFIG")]
    config: Option<std::path::PathBuf>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the HTTP hub (MCP at /mcp, JSON API at /api).
    Serve,
    /// Serve MCP over stdin/stdout for one local client.
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
}

#[derive(Subcommand)]
enum ImportCmd {
    /// Import a Python hub database (opened read-only). Re-running resumes
    /// and skips rows already copied. Prints a JSON report.
    PythonHub {
        /// Path to the Python hub's SQLite database.
        #[arg(long = "from")]
        from: std::path::PathBuf,
        /// Report counts, unmapped tables and columns and the source ledger
        /// check without writing anything.
        #[arg(long)]
        dry_run: bool,
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

fn load_config(cli: &Cli) -> anyhow::Result<Config> {
    let _ = dotenvy::dotenv();
    match &cli.config {
        Some(p) => Config::load_from(p),
        None => Config::load(),
    }
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
    let mut c = Caller::local(label.unwrap_or_else(|| "local".into()), Transport::Cli);
    if explicit && cfg.is_human(&c.label) && confirm(&c.label) {
        c.kind = ActorKind::Human;
    }
    c
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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("UA_LOG").unwrap_or_else(|_| "info".into()),
        )
        .with_writer(std::io::stderr)
        .init();
    let cfg = load_config(&cli)?;

    if let Cmd::Config = cli.cmd {
        println!("{}", serde_json::to_string_pretty(&cfg)?);
        return Ok(());
    }

    if let Cmd::Import { cmd: ImportCmd::PythonHub { from, dry_run } } = &cli.cmd {
        let report = if *dry_run {
            ua_import::dry_run(from)?
        } else {
            let db = ua_store::Db::open(&cfg.db_path(), &ua_import::schema_parts())?;
            ua_import::import(&db, from, &ua_import::Options::default())?
        };
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    let hub = Hub::open(cfg.clone())?;
    let registry = Arc::new(builtin_registry());
    let state = AppState { hub: hub.clone(), registry: registry.clone() };

    match cli.cmd {
        Cmd::Serve => {
            warn_if_locked_out(&state).await;
            let ct = CancellationToken::new();
            let ct2 = ct.clone();
            tokio::spawn(async move {
                let _ = tokio::signal::ctrl_c().await;
                ct2.cancel();
            });
            ua_server::serve_http(state, ct).await?;
        }
        Cmd::Mcp { label } => ua_server::mcp::serve_stdio(state, label).await?,
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
                    std::process::exit(1);
                }
            }
        }
        Cmd::Token { cmd } => match cmd {
            TokenCmd::Issue { label, note } => {
                // A token for a human identity grants approval rights over HTTP;
                // mint one only on an operator's explicit confirmation.
                if cfg.is_human(&label)
                    && (std::env::var_os("UA_AGENT_LABEL").is_some() || !confirm_on_tty(&label))
                {
                    anyhow::bail!(
                        "issuing a token for human {label:?} needs an operator at an interactive terminal"
                    );
                }
                let mut raw = [0u8; 32];
                rand::rng().fill_bytes(&mut raw);
                let token = format!("ua_{}", hex::encode(raw));
                let hash = hex::encode(Sha256::digest(token.as_bytes()));
                let now = ua_core::time::now();
                hub.db().write(|tx| {
                    tx.execute(
                        "INSERT INTO agent_tokens (agent_label, token_hash, issued_at, issued_by, note) \
                         VALUES (?1, ?2, ?3, 'cli', ?4)",
                        rusqlite::params![label, hash, now, note],
                    )?;
                    ua_store::ledger::append(
                        tx,
                        ua_store::EventInput::new(
                            "agent.token.issued",
                            serde_json::json!({ "agent": label }),
                        )
                        .by("cli"),
                    )?;
                    Ok(())
                })?;
                eprintln!("Token for {label} (shown once; store it in the agent's secret store):");
                println!("{token}");
            }
            TokenCmd::Revoke { label } => {
                let now = ua_core::time::now();
                let n = hub.db().write(|tx| {
                    let n = tx.execute(
                        "UPDATE agent_tokens SET status = 'revoked', revoked_at = ?2 \
                         WHERE agent_label = ?1 AND status = 'active'",
                        rusqlite::params![label, now],
                    )?;
                    ua_store::ledger::append(
                        tx,
                        ua_store::EventInput::new(
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
        Cmd::LoginLink { label } => {
            // A login link signs a browser in as a human; same bar as acting
            // as a human from the CLI.
            if std::env::var_os("UA_AGENT_LABEL").is_some() || !confirm_on_tty(&label) {
                anyhow::bail!("a sign-in link for {label:?} needs an operator at an interactive terminal");
            }
            let url = ua_server::login::create_login_link(&hub, &label, "cli")?;
            eprintln!(
                "Sign-in link for {label} (single use, expires in {} s; open it in the browser you will use):",
                cfg.login_link_ttl_secs
            );
            println!("{url}");
        }
        Cmd::Config | Cmd::Import { .. } => unreachable!(),
    }
    Ok(())
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
    fn agent_env_label_is_never_human() {
        // `--label` falls back to UA_AGENT_LABEL; a label from there is not
        // an operator's explicit choice.
        let c = local_caller_with(&cfg(), Some("operator".into()), Some("operator"), |_| true);
        assert_eq!(c.kind, ActorKind::Anonymous);
    }
}
