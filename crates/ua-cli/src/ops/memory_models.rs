//! `ua memory models fetch|status`: offline preparation and inspection for
//! local ONNX embedding models.

use clap::{Args, Subcommand};
use ua_core::Config;
use ua_tools::families::memory::models_fetch;

#[derive(Debug, Clone, Args)]
pub struct MemoryArgs {
    #[command(subcommand)]
    pub cmd: MemoryCmd,
}

#[derive(Debug, Clone, Subcommand)]
pub enum MemoryCmd {
    /// Manage pinned local embedding model files under `$UA_HOME/models`.
    Models {
        #[command(subcommand)]
        cmd: ModelsCmd,
    },
}

#[derive(Debug, Clone, Subcommand)]
pub enum ModelsCmd {
    /// Download and SHA-256 verify the pinned local embedding model for offline use.
    Fetch {
        /// Model name (defaults to `embed_model` from config, e.g. `BAAI/bge-small-en-v1.5`).
        #[arg(long)]
        model: Option<String>,
        /// Re-download all files even if already present and verified.
        #[arg(long)]
        force: bool,
        /// Print structured JSON output.
        #[arg(long)]
        json: bool,
    },
    /// Report whether the pinned local embedding model is present on disk (never downloads).
    Status {
        /// Model name (defaults to `embed_model` from config).
        #[arg(long)]
        model: Option<String>,
        /// Verify full SHA-256 digests of every file on disk.
        #[arg(long)]
        verify: bool,
        /// Print structured JSON output.
        #[arg(long)]
        json: bool,
    },
}

pub async fn run(cfg: &Config, args: MemoryArgs) -> anyhow::Result<()> {
    match args.cmd {
        MemoryCmd::Models { cmd } => match cmd {
            ModelsCmd::Fetch { model, force, json } => {
                let name = model.as_deref().unwrap_or(&cfg.embed_model);
                let report = models_fetch::fetch_local_model(&cfg.home, name, force).await?;
                if json {
                    println!("{}", serde_json::to_string_pretty(&report)?);
                } else {
                    println!("Fetched and verified {}@{}", report.model, report.revision);
                    println!("  dir:              {}", report.dir);
                    println!("  downloaded:       {}", report.downloaded.len());
                    println!("  already present:  {}", report.already_present.len());
                }
                Ok(())
            }
            ModelsCmd::Status { model, verify, json } => {
                let name = model.as_deref().unwrap_or(&cfg.embed_model);
                let report = models_fetch::local_model_status(&cfg.home, name, verify);
                if json {
                    println!("{}", serde_json::to_string_pretty(&report)?);
                } else {
                    println!(
                        "Model {}: {} ({})",
                        report.canonical_id.as_deref().unwrap_or(&report.requested),
                        if report.present { "present" } else { "missing" },
                        report.detail
                    );
                    if let Some(dir) = &report.dir {
                        println!("  dir: {dir}");
                    }
                }
                Ok(())
            }
        },
    }
}
