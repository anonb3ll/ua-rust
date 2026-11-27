//! Invocable entry for the memory retrieval bench.
//!
//! `ua memory bench` is not wired here: `crates/ua-cli` is owned by another
//! change. Run this binary until that command exists.
//!
//! ```text
//! cargo run -p ua-memory --bin memory-bench
//! cargo run -p ua-memory --bin memory-bench -- --longmemeval
//! cargo run -p ua-memory --bin memory-bench -- --longmemeval --ids sample.txt
//! ```

use std::path::PathBuf;

use ua_memory::bench::{Kind, Options};

#[tokio::main]
async fn main() {
    let code = match entry().await {
        Ok(code) => code,
        Err(err) => {
            eprintln!("{err}");
            1
        }
    };
    std::process::exit(code);
}

async fn entry() -> Result<i32, String> {
    let args = parse_args()?;
    let report = ua_memory::bench::run(Options {
        kind: if args.longmemeval { Kind::LongMemEval } else { Kind::Fixture },
        data: args.data,
        limit: args.limit,
        ids: args.ids,
    })
    .await
    .map_err(|e| e.to_string())?;
    eprintln!("{}", ua_memory::bench::table(&report));
    let body = serde_json::to_string_pretty(&report).map_err(|e| e.to_string())? + "\n";
    if let Some(path) = &args.out {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent).map_err(|e| format!("create {}: {e}", parent.display()))?;
        }
        std::fs::write(path, &body).map_err(|e| format!("write {}: {e}", path.display()))?;
    }
    print!("{body}");
    let below = report.get("floor").and_then(|f| f.get("ok")).and_then(|v| v.as_bool()) == Some(false);
    Ok(if below { 1 } else { 0 })
}

struct Args {
    longmemeval: bool,
    data: Option<PathBuf>,
    out: Option<PathBuf>,
    limit: Option<usize>,
    ids: Option<Vec<String>>,
}

/// Question ids from a file: one per line or comma-separated; blank lines and
/// lines starting with `#` are skipped.
fn read_ids(path: &str) -> Result<Vec<String>, String> {
    let raw = std::fs::read_to_string(path).map_err(|e| format!("read --ids {path}: {e}"))?;
    let ids: Vec<String> = raw
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .flat_map(|l| l.split(','))
        .map(|id| id.trim().to_string())
        .filter(|id| !id.is_empty())
        .collect();
    if ids.is_empty() {
        return Err(format!("--ids {path} lists no question ids"));
    }
    Ok(ids)
}

fn parse_args() -> Result<Args, String> {
    let mut args = Args { longmemeval: false, data: None, out: None, limit: None, ids: None };
    let mut rest = std::env::args().skip(1);
    while let Some(arg) = rest.next() {
        match arg.as_str() {
            "--longmemeval" => args.longmemeval = true,
            "--data" => args.data = Some(PathBuf::from(next_value(&mut rest, "--data")?)),
            "--out" => args.out = Some(PathBuf::from(next_value(&mut rest, "--out")?)),
            "--limit" => {
                let raw = next_value(&mut rest, "--limit")?;
                let n: usize =
                    raw.parse().map_err(|_| format!("--limit must be a positive integer, got {raw}"))?;
                if n == 0 {
                    return Err("--limit must be at least 1".into());
                }
                args.limit = Some(n);
            }
            "--ids" => args.ids = Some(read_ids(&next_value(&mut rest, "--ids")?)?),
            "-h" | "--help" => {
                eprintln!(
                    "memory-bench [--longmemeval] [--data PATH] [--out PATH] [--limit N] [--ids FILE]\n\n\
                     Scores the checked-in fixture corpus. --longmemeval scores pinned LongMemEval-S.\n\
                     Without --data it reads the cache and downloads a missing file with curl.\n\
                     --ids FILE scores only those question ids (one per line or comma-separated).\n\
                     A table goes to stderr and JSON to stdout. The fixture exits 1 below its floor.\n\
                     `ua memory bench` is not wired in this binary."
                );
                std::process::exit(0);
            }
            other => return Err(format!("unknown argument {other}; try --help")),
        }
    }
    if (args.limit.is_some() || args.ids.is_some() || args.data.is_some()) && !args.longmemeval {
        return Err("--limit, --ids and --data apply only with --longmemeval".into());
    }
    Ok(args)
}

fn next_value(args: &mut impl Iterator<Item = String>, flag: &str) -> Result<String, String> {
    args.next().filter(|v| !v.starts_with("--")).ok_or_else(|| format!("{flag} needs a value"))
}
