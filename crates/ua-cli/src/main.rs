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

fn local_caller(cfg: &Config, label: Option<String>) -> Caller {
    let label =
        label.unwrap_or_else(|| cfg.human_identities.first().cloned().unwrap_or_else(|| "local".into()));
    let mut c = Caller::local(label, Transport::Cli);
    if cfg.is_human(&c.label) {
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
        Cmd::LoginLink { label } => {
            let url = ua_server::login::create_login_link(&hub, &label, "cli")?;
            eprintln!(
                "Sign-in link for {label} (single use, expires in {} s; open it in the browser you will use):",
                cfg.login_link_ttl_secs
            );
            println!("{url}");
        }
        Cmd::Config => unreachable!(),
    }
    Ok(())
}
