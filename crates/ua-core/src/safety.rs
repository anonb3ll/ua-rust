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

    let inside =
        roots.iter().any(|r| canonicalize_lenient(r).map(|r| resolved.starts_with(&r)).unwrap_or(false));
    if !inside {
        return Err(UaError::denied("outside_sandbox", format!("{path:?} is outside the sandbox")));
    }
    for comp in resolved.components() {
        if let Component::Normal(name) = comp {
            let name = name.to_string_lossy();
            if HOOK_DIRS.contains(&name.as_ref()) {
                return Err(UaError::denied(
                    "hook_dir",
                    format!("{path:?} reaches into {name}, which holds executable hooks"),
                ));
            }
            if DEPENDENCY_DIRS.contains(&name.as_ref()) {
                return Err(UaError::denied(
                    "dependency_dir",
                    format!("{path:?} reaches into the dependency tree {name}"),
                ));
            }
        }
    }
    if !for_write {
        guard_secret_filename(&resolved)?;
    }
    Ok(resolved)
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
    Ok(VettedCommand { program, args: parts })
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
    }
}
