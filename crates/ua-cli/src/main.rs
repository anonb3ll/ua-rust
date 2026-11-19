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
    /// Print the effective configuration (secrets redacted).
    Config,
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
/// Acting as a human (who may approve gated calls) needs an explicit
/// `--label` naming a configured human identity. The label is never
/// defaulted to a human, and a label that only came from `UA_AGENT_LABEL`
/// never makes the caller human: that variable is how agent processes are
/// launched, so an agent's shell cannot approve its own calls.
fn local_caller(cfg: &Config, label: Option<String>) -> Caller {
    let from_env = std::env::var("UA_AGENT_LABEL").ok();
    local_caller_with(cfg, label, from_env.as_deref())
}

fn local_caller_with(cfg: &Config, label: Option<String>, agent_env: Option<&str>) -> Caller {
    let explicit = label.as_deref().is_some_and(|l| agent_env != Some(l));
    let mut c = Caller::local(label.unwrap_or_else(|| "local".into()), Transport::Cli);
    if explicit && cfg.is_human(&c.label) {
        c.kind = ActorKind::Human;
    }
    c
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
        Cmd::Config => unreachable!(),
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
        let c = local_caller_with(&cfg(), None, None);
        assert_eq!(c.kind, ActorKind::Anonymous);
        assert_eq!(c.label, "local");
    }

    #[test]
    fn explicit_human_label_is_human() {
        let c = local_caller_with(&cfg(), Some("operator".into()), None);
        assert_eq!(c.kind, ActorKind::Human);
    }

    #[test]
    fn agent_env_label_is_never_human() {
        // `--label` falls back to UA_AGENT_LABEL; a label from there is not
        // an operator's explicit choice.
        let c = local_caller_with(&cfg(), Some("operator".into()), Some("operator"));
        assert_eq!(c.kind, ActorKind::Anonymous);
    }
}
