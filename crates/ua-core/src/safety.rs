//! Sandbox chokepoints. Every tool that touches the filesystem or starts a
//! program goes through these functions first.
//!
//! - [`resolve_in_root`] confines a path to one or more roots, following
//!   symlinks and `..`, so a link pointing outside is refused.
//! - Hook-execution directories (`.git`, `.hg`, `.svn`, `.husky`) are refused:
//!   a write there would run unattended on the next commit.
//! - [`guard_secret_filename`] refuses reading credential-bearing files.
//! - [`vet_command`] splits a command line without a shell and accepts only
//!   allowlisted programs.

use std::path::{Component, Path, PathBuf};

use crate::error::{UaError, UaResult};

/// Directory names that hold scripts git or a hook manager executes.
pub const HOOK_DIRS: &[&str] = &[".git", ".hg", ".svn", ".husky"];

/// Dependency trees: refused for agent tools, they are large and vendor-owned.
pub const DEPENDENCY_DIRS: &[&str] = &["node_modules", ".venv", "venv", "target"];

/// Characters that only mean something to a shell. `run_cmd` runs no shell, so
/// their presence means the caller expected one: refuse rather than surprise.
const SHELL_META: &[char] = &['|', '&', ';', '<', '>', '`', '$', '(', ')', '\n'];

/// Normalize a path lexically (no filesystem access): drop `.`, apply `..`.
fn lexical_normalize(p: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// Canonicalize a path that may not exist yet: resolve the deepest existing
/// ancestor (following symlinks) and append the remainder.
pub fn canonicalize_lenient(p: &Path) -> std::io::Result<PathBuf> {
    let norm = lexical_normalize(p);
    let mut existing = norm.as_path();
    let mut rest: Vec<&std::ffi::OsStr> = Vec::new();
    loop {
        match existing.canonicalize() {
            Ok(mut base) => {
                for part in rest.iter().rev() {
                    base.push(part);
                }
                return Ok(base);
            }
            Err(_) => {
                let Some(name) = existing.file_name() else {
                    return Err(std::io::Error::new(std::io::ErrorKind::NotFound, "no existing ancestor"));
                };
                rest.push(name);
                existing = existing.parent().unwrap_or(Path::new("/"));
            }
        }
    }
}

/// Resolve `path` against the first root (relative paths) and require that
/// the result lies inside one of `roots`.
///
/// Hook-execution and dependency directories are checked on the part of the
/// path inside the containing root (case-insensitively, so a
/// case-insensitive filesystem cannot evade the check). Reads
/// (`for_write == false`) also refuse a credential-looking name anywhere
/// inside the root, so `service.env/notes.txt` is refused too.
pub fn resolve_in_root(path: &str, roots: &[PathBuf], for_write: bool) -> UaResult<PathBuf> {
    let Some(primary) = roots.first() else {
        return Err(UaError::denied("no_root", "no sandbox root is configured"));
    };
    if path.contains('\0') {
        return Err(UaError::invalid("path contains a NUL byte"));
    }
    let raw = Path::new(path);
    let joined = if raw.is_absolute() { raw.to_path_buf() } else { primary.join(raw) };
    let resolved = canonicalize_lenient(&joined)
        .map_err(|e| UaError::invalid(format!("cannot resolve {path:?}: {e}")))?;

    let Some(root) = containing_root(&resolved, roots) else {
        return Err(UaError::denied("outside_sandbox", format!("{path:?} is outside the sandbox")));
    };
    guard_inside_root(&resolved, &root, path, for_write)?;
    Ok(resolved)
}

/// Resolve a path for a read-only tool.
///
/// A relative path resolves against `workspace` and must stay inside it, so a
/// relative `..` can never reach an extra read root. An absolute path may
/// point into the workspace or any of `read_roots`.
pub fn resolve_for_read(path: &str, workspace: &Path, read_roots: &[PathBuf]) -> UaResult<PathBuf> {
    let mut roots = vec![workspace.to_path_buf()];
    if Path::new(path).is_absolute() {
        roots.extend(read_roots.iter().cloned());
    }
    resolve_in_root(path, &roots, false)
}

/// The canonical root among `roots` that contains the canonical `resolved`.
pub fn containing_root(resolved: &Path, roots: &[PathBuf]) -> Option<PathBuf> {
    roots.iter().filter_map(|r| canonicalize_lenient(r).ok()).find(|r| resolved.starts_with(r))
}

/// Check the components of `resolved` below `root` against the hook,
/// dependency and (for reads) secret-name rules. `shown` is the path as the
/// caller gave it, for messages.
pub fn guard_inside_root(resolved: &Path, root: &Path, shown: &str, for_write: bool) -> UaResult<()> {
    let rel = resolved.strip_prefix(root).unwrap_or(resolved);
    for comp in rel.components() {
        if let Component::Normal(name) = comp {
            let lower = name.to_string_lossy().to_lowercase();
            if HOOK_DIRS.contains(&lower.as_str()) {
                return Err(UaError::denied(
                    "hook_dir",
                    format!("{shown:?} reaches into {lower}, which holds executable hooks"),
                ));
            }
            if DEPENDENCY_DIRS.contains(&lower.as_str()) {
                return Err(UaError::denied(
                    "dependency_dir",
                    format!("{shown:?} reaches into the dependency tree {lower}"),
                ));
            }
            if !for_write {
                guard_secret_filename(Path::new(name))?;
            }
        }
    }
    Ok(())
}

/// For an entry found while listing or walking a directory: its real path and
/// containing root when a direct read of it would be allowed, else `None`.
/// Symlinks are followed, so a link out of every root is dropped.
pub fn readable_entry(entry: &Path, roots: &[PathBuf]) -> Option<(PathBuf, PathBuf)> {
    let real = entry.canonicalize().ok()?;
    let root = containing_root(&real, roots)?;
    guard_inside_root(&real, &root, &entry.to_string_lossy(), false).ok()?;
    Some((real, root))
}

/// Refuse files whose name marks them as credentials or databases.
pub fn guard_secret_filename(p: &Path) -> UaResult<()> {
    let name = p.file_name().map(|n| n.to_string_lossy().to_lowercase()).unwrap_or_default();
    let secret = name == ".env"
        || name.starts_with(".env.") && name != ".env.example"
        || name.ends_with(".env")
        || name.ends_with(".pem")
        || name.ends_with(".key")
        || name.ends_with(".p12")
        || name.ends_with(".db")
        || name.ends_with(".sqlite")
        || name.ends_with(".sqlite3")
        || name.starts_with("id_rsa")
        || name.starts_with("id_ed25519")
        || name == "credentials.json"
        || name == ".netrc"
        || name == ".pgpass"
        || name.contains("token") && !name.ends_with(".md") && !name.ends_with(".rs");
    if secret {
        return Err(UaError::denied("secret_file", format!("{name:?} looks like a credential file")));
    }
    Ok(())
}

/// A vetted command: program plus arguments, split without a shell.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VettedCommand {
    pub program: String,
    pub args: Vec<String>,
}

/// Split a command line POSIX-style (quotes and backslashes, no expansion).
pub fn split_command(cmd: &str) -> UaResult<Vec<String>> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_word = false;
    let mut chars = cmd.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\'' => {
                in_word = true;
                loop {
                    match chars.next() {
                        Some('\'') => break,
                        Some(ch) => cur.push(ch),
                        None => return Err(UaError::invalid("unterminated single quote")),
                    }
                }
            }
            '"' => {
                in_word = true;
                loop {
                    match chars.next() {
                        Some('"') => break,
                        Some('\\') => match chars.next() {
                            Some(ch @ ('"' | '\\')) => cur.push(ch),
                            Some(ch) => {
                                cur.push('\\');
                                cur.push(ch);
                            }
                            None => return Err(UaError::invalid("unterminated double quote")),
                        },
                        Some(ch) => cur.push(ch),
                        None => return Err(UaError::invalid("unterminated double quote")),
                    }
                }
            }
            '\\' => {
                in_word = true;
                if let Some(ch) = chars.next() {
                    cur.push(ch);
                }
            }
            c if c.is_whitespace() => {
                if in_word {
                    out.push(std::mem::take(&mut cur));
                    in_word = false;
                }
            }
            c => {
                if SHELL_META.contains(&c) {
                    return Err(UaError::denied(
                        "shell_syntax",
                        format!("{c:?} is shell syntax; run_cmd runs no shell"),
                    ));
                }
                in_word = true;
                cur.push(c);
            }
        }
    }
    if in_word {
        out.push(cur);
    }
    Ok(out)
}

/// Split and check a command against the allowlist. The program must be a
/// bare name (no path), so `./evil` or `/tmp/git` cannot stand in for `git`.
pub fn vet_command(cmd: &str, allowlist: &[String]) -> UaResult<VettedCommand> {
    let mut parts = split_command(cmd)?;
    if parts.is_empty() {
        return Err(UaError::invalid("empty command"));
    }
    let program = parts.remove(0);
    if program.contains('/') {
        return Err(UaError::denied("program_path", "give the program by name, not by path"));
    }
    if !allowlist.iter().any(|a| a == &program) {
        return Err(UaError::denied(
            "program_not_allowed",
            format!("{program:?} is not in the command allowlist"),
        ));
    }
    if program == "git"
        && parts.iter().any(|a| a == "-c" || a.starts_with("--exec-path") || a.starts_with("--config"))
    {
        return Err(UaError::denied("git_config_override", "git config overrides are refused"));
    }
    if program == "git" && git_global_options(&parts).iter().any(|a| a.starts_with("-c")) {
        return Err(UaError::denied("git_config_override", "git config overrides are refused"));
    }
    let vetted = VettedCommand { program, args: parts };
    if let Some(reason) = destructive_command_reason(&vetted) {
        return Err(UaError::denied(
            "destructive",
            format!("destructive command refused: {reason}; an approval cannot override this"),
        ));
    }
    Ok(vetted)
}

/// git options that take their value in the next argument.
const GIT_VALUE_FLAGS: &[&str] = &["-C", "-c", "--git-dir", "--work-tree", "--namespace"];

/// The global options before a git subcommand.
pub fn git_global_options(args: &[String]) -> &[String] {
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if GIT_VALUE_FLAGS.contains(&a.as_str()) {
            i += 2;
        } else if a.starts_with('-') {
            i += 1;
        } else {
            return &args[..i];
        }
    }
    &args[..args.len().min(i)]
}

/// The git subcommand (lowercased) and the arguments after it.
pub fn git_subcommand(args: &[String]) -> Option<(String, &[String])> {
    let n = git_global_options(args).len();
    args.get(n).map(|s| (s.to_lowercase(), &args[n + 1..]))
}

fn short_flags(tok: &str) -> &str {
    if tok.len() >= 2 && tok.starts_with('-') && !tok.starts_with("--") { &tok[1..] } else { "" }
}

/// Why an argv would destroy data no approval can bring back, if it would:
/// recursive force `rm`, hard resets and other working-tree discards, and
/// `find -delete` or a `find -exec` running one of those.
pub fn destructive_command_reason(cmd: &VettedCommand) -> Option<String> {
    destructive_argv(&cmd.program, &cmd.args)
}

fn destructive_argv(program: &str, args: &[String]) -> Option<String> {
    let base = program.rsplit('/').next().unwrap_or(program).to_lowercase();
    match base.as_str() {
        "rm" => {
            let (mut r, mut f) = (false, false);
            for a in args {
                r |= a == "--recursive" || short_flags(a).contains(['r', 'R']);
                f |= a == "--force" || short_flags(a).contains('f');
            }
            (r && f).then(|| "recursive force-delete (rm -rf)".to_string())
        }
        "git" => {
            let (sub, rest) = git_subcommand(args)?;
            let has = |pred: &dyn Fn(&str) -> bool| rest.iter().any(|a| pred(a));
            match sub.as_str() {
                "reset" if has(&|a| a == "--hard") => {
                    Some("git reset --hard discards uncommitted work".into())
                }
                "checkout"
                    if has(&|a| {
                        matches!(a, "--" | "--force" | "." | "./") || short_flags(a).contains('f')
                    }) =>
                {
                    Some("git checkout with force or a path discards uncommitted work".into())
                }
                "restore" => {
                    let staged = has(&|a| a == "--staged" || short_flags(a).contains('S'));
                    let worktree = has(&|a| a == "--worktree" || short_flags(a).contains('W'));
                    (worktree || !staged).then(|| "git restore overwrites the working tree".into())
                }
                "switch"
                    if has(&|a| {
                        a == "--discard-changes" || a == "--force" || short_flags(a).contains(['f', 'C'])
                    }) =>
                {
                    Some("git switch with force discards uncommitted work".into())
                }
                "clean" if has(&|a| a == "--force" || short_flags(a).contains('f')) => {
                    Some("git clean -f deletes untracked files".into())
                }
                "rm" if has(&|a| short_flags(a).contains(['r', 'R'])) => {
                    Some("git rm -r recursively removes tracked files".into())
                }
                _ => None,
            }
        }
        "find" => {
            if args.iter().any(|a| a == "-delete") {
                return Some("find -delete removes matched files".into());
            }
            let mut i = 0;
            while i < args.len() {
                if matches!(args[i].as_str(), "-exec" | "-execdir" | "-ok" | "-okdir") {
                    let start = i + 1;
                    let mut end = start;
                    while end < args.len() && args[end] != ";" && args[end] != "+" {
                        end += 1;
                    }
                    if let Some((prog, rest)) = args[start..end].split_first() {
                        let pbase = prog.rsplit('/').next().unwrap_or(prog).to_lowercase();
                        if matches!(pbase.as_str(), "rm" | "rmdir" | "unlink")
                            || destructive_argv(prog, rest).is_some()
                        {
                            return Some(format!("find {} runs a destructive command", args[i]));
                        }
                    }
                    i = end;
                }
                i += 1;
            }
            None
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn confines_paths() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        std::fs::create_dir_all(root.join("src")).unwrap();
        let roots = vec![root.clone()];
        assert_eq!(resolve_in_root("src/new.rs", &roots, true).unwrap(), root.join("src/new.rs"));
        assert!(resolve_in_root("../escape", &roots, true).is_err());
        assert!(resolve_in_root("/etc/passwd", &roots, false).is_err());
        assert!(resolve_in_root(".git/hooks/pre-commit", &roots, true).is_err());
        assert!(resolve_in_root("node_modules/x", &roots, false).is_err());
        assert!(resolve_in_root(".env", &roots, false).is_err());
        assert!(resolve_in_root(".gitignore", &roots, false).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn refuses_symlink_escape() {
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        std::os::unix::fs::symlink(outside.path(), root.join("link")).unwrap();
        assert!(resolve_in_root("link/file", &[root], true).is_err());
    }

    #[test]
    fn vets_commands() {
        let allow: Vec<String> = ["git", "ls", "echo"].iter().map(|s| s.to_string()).collect();
        let v = vet_command("git log --oneline -n 3", &allow).unwrap();
        assert_eq!(v.program, "git");
        assert_eq!(v.args, ["log", "--oneline", "-n", "3"]);
        assert_eq!(vet_command("echo 'a b' \"c\\\"d\"", &allow).unwrap().args, ["a b", "c\"d"]);
        assert!(vet_command("rm -rf /", &allow).is_err());
        assert!(vet_command("ls | sh", &allow).is_err());
        assert!(vet_command("echo $(id)", &allow).is_err());
        assert!(vet_command("/usr/bin/git status", &allow).is_err());
        assert!(vet_command("git -c core.pager=sh log", &allow).is_err());
        // Quoted metacharacters are plain argument text.
        assert_eq!(vet_command("echo 'a|b'", &allow).unwrap().args, ["a|b"]);
        // Attached global -c is an override too; `log -c` after the subcommand is a diff option.
        assert!(vet_command("git -calias.x=!id x", &allow).is_err());
    }

    #[test]
    fn refuses_destructive_commands() {
        let allow: Vec<String> = ["git", "rm", "find"].iter().map(|s| s.to_string()).collect();
        let code = |c: &str| {
            vet_command(c, &allow).err().map(|e| match e {
                UaError::Denied { reason_code, .. } => reason_code,
                other => other.code().to_string(),
            })
        };
        assert_eq!(code("rm -rf build").as_deref(), Some("destructive"));
        assert_eq!(code("rm -r -f build").as_deref(), Some("destructive"));
        assert_eq!(code("rm notes.txt"), None);
        assert_eq!(code("git reset --hard HEAD~1").as_deref(), Some("destructive"));
        assert_eq!(code("git checkout -- src").as_deref(), Some("destructive"));
        assert_eq!(code("git checkout main"), None);
        assert_eq!(code("git restore src/a.rs").as_deref(), Some("destructive"));
        assert_eq!(code("git restore --staged src/a.rs"), None);
        assert_eq!(code("git clean -fd").as_deref(), Some("destructive"));
        assert_eq!(code("find . -delete").as_deref(), Some("destructive"));
        assert_eq!(code(r"find . -exec rm {} \;").as_deref(), Some("destructive"));
        assert_eq!(code("find . -name x"), None);
    }

    #[test]
    fn read_resolution_and_entries() {
        let ws = tempfile::tempdir().unwrap();
        let extra = tempfile::tempdir().unwrap();
        let ws_root = ws.path().canonicalize().unwrap();
        let extra_root = extra.path().canonicalize().unwrap();
        std::fs::write(extra_root.join("doc.txt"), "x").unwrap();
        std::fs::create_dir_all(ws_root.join("service.env")).unwrap();
        std::fs::write(ws_root.join("service.env/notes.txt"), "x").unwrap();
        std::fs::create_dir_all(ws_root.join(".GIT")).unwrap();
        let reads = vec![extra_root.clone()];
        let abs = extra_root.join("doc.txt");
        assert_eq!(resolve_for_read(abs.to_str().unwrap(), &ws_root, &reads).unwrap(), abs);
        // A relative path never reaches an extra read root.
        let name = extra_root.file_name().unwrap().to_str().unwrap();
        assert!(resolve_for_read(&format!("../{name}/doc.txt"), &ws_root, &reads).is_err());
        // Secret names anywhere inside the root, hook dirs in any case.
        assert!(resolve_for_read("service.env/notes.txt", &ws_root, &reads).is_err());
        assert!(resolve_in_root(".GIT/config", std::slice::from_ref(&ws_root), true).is_err());
        assert!(readable_entry(&ws_root.join("service.env"), std::slice::from_ref(&ws_root)).is_none());
        assert!(readable_entry(&abs, &[ws_root.clone(), extra_root.clone()]).is_some());
    }
}
