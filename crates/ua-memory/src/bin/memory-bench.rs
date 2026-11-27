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

use ua_memory::bench::{EmbedOptions, Kind, Options};

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

fn default_models_home() -> PathBuf {
    std::env::var_os("UA_HOME").map(PathBuf::from).unwrap_or_else(|| {
        std::env::var_os("HOME").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(".")).join(".ua-rust")
    })
}

async fn entry() -> Result<i32, String> {
    let args = parse_args()?;
    let embed = if args.embed {
        Some(EmbedOptions {
            home: args.models_home.unwrap_or_else(default_models_home),
            model: args.model.unwrap_or_else(|| ua_core::Config::default().embed_model),
            no_chunks: args.no_chunks,
        })
    } else {
        None
    };
    let report = ua_memory::bench::run(Options {
        kind: if args.longmemeval { Kind::LongMemEval } else { Kind::Fixture },
        data: args.data,
        limit: args.limit,
        ids: args.ids,
        embed,
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
    embed: bool,
    models_home: Option<PathBuf>,
    model: Option<String>,
    no_chunks: bool,
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
    parse_args_from(std::env::args().skip(1))
}

fn parse_args_from(raw_args: impl IntoIterator<Item = String>) -> Result<Args, String> {
    let mut args = Args {
        longmemeval: false,
        data: None,
        out: None,
        limit: None,
        ids: None,
        embed: false,
        models_home: None,
        model: None,
        no_chunks: false,
    };
    let mut rest = raw_args.into_iter();
    while let Some(arg) = rest.next() {
        match arg.as_str() {
            "--longmemeval" => args.longmemeval = true,
            "--data" => args.data = Some(PathBuf::from(next_value(&mut rest, "--data")?)),
            "--out" => args.out = Some(PathBuf::from(next_value(&mut rest, "--out")?)),
            "--embed" => args.embed = true,
            "--models-home" => {
                args.models_home = Some(PathBuf::from(next_value(&mut rest, "--models-home")?))
            }
            "--model" => args.model = Some(next_value(&mut rest, "--model")?),
            "--no-chunks" => args.no_chunks = true,
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
                    "memory-bench [--longmemeval] [--data PATH] [--out PATH] [--limit N] [--ids FILE] \
                     [--embed] [--models-home PATH] [--model NAME] [--no-chunks]\n\n\
                     Scores the checked-in fixture corpus. --longmemeval scores pinned LongMemEval-S.\n\
                     Without --data it reads the cache and downloads a missing file with curl.\n\
                     --ids FILE scores only those question ids (one per line or comma-separated).\n\
                     --embed runs hybrid retrieval using the fetched local ONNX model (requires --features embeddings).\n\
                     --no-chunks drops memory_chunks after ingest (single-vector ablation, requires --embed).\n\
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
    if (args.models_home.is_some() || args.model.is_some() || args.no_chunks) && !args.embed {
        return Err("--models-home, --model and --no-chunks apply only with --embed".into());
    }
    Ok(args)
}

fn next_value(args: &mut impl Iterator<Item = String>, flag: &str) -> Result<String, String> {
    args.next().filter(|v| !v.starts_with("--")).ok_or_else(|| format!("{flag} needs a value"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(xs: &[&str]) -> Result<Args, String> {
        parse_args_from(xs.iter().map(|s| (*s).to_string()))
    }

    #[test]
    fn embed_flag_is_opt_in_and_off_by_default() {
        let def = parse(&[]).unwrap();
        assert!(!def.embed, "--embed must stay off by default so CI remains lexical");
        assert!(!def.longmemeval);
        assert!(!def.no_chunks);
        assert!(def.models_home.is_none());
        assert!(def.model.is_none());

        let lme = parse(&["--longmemeval"]).unwrap();
        assert!(lme.longmemeval);
        assert!(!lme.embed, "--longmemeval alone must not enable --embed");
    }

    #[test]
    fn embed_subflags_require_embed_and_parse_when_enabled() {
        assert!(parse(&["--no-chunks"]).is_err());
        assert!(parse(&["--models-home", "/tmp/ua"]).is_err());
        assert!(parse(&["--model", "BAAI/bge-small-en-v1.5"]).is_err());

        let ok = parse(&["--embed", "--no-chunks", "--models-home", "/tmp/ua", "--model", "m"]).unwrap();
        assert!(ok.embed);
        assert!(ok.no_chunks);
        assert_eq!(ok.models_home, Some(PathBuf::from("/tmp/ua")));
        assert_eq!(ok.model.as_deref(), Some("m"));
    }
}
