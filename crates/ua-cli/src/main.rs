use clap::Parser;

/// ua: agent-operations hub.
#[derive(Parser)]
#[command(version, about)]
struct Cli {}

fn main() -> anyhow::Result<()> {
    let _cli = Cli::parse();
    let cfg = ua_core::Config::load()?;
    println!("ua-rust {} (home: {})", env!("CARGO_PKG_VERSION"), cfg.home.display());
    Ok(())
}
