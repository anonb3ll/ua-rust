//! Plumbing-only Git tree/blob/diff operations for skill sources (`docs/skill-sources.md` §2–§4).
//!
//! Never checks out a working tree. All tree enumeration uses `ls-tree -r -l -z`
//! capped at 16 MiB / 50,000 entries / 200 candidate packages, refusing symlinks
//! (`120000`), gitlinks (`160000`), and any non-regular mode. All blob reads use
//! `cat-file blob <oid>` by validated 40-char object id with per-file and total
//! byte caps enforced before and after reading.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde_json::{Value, json};
use ua_core::{UaError, UaResult};

use super::fetch::{
    DnsResolver, FetchOptions, ParsedSourceUrl, SourceScheme, build_fetch_command, build_git_command,
    cache_dir, classify_and_pin_ip, commit_present, dir_size_bytes, ensure_bare_repo,
    ensure_supported_git_version, fetch_exact_sha, hex_prefix, run_git, run_git_watched, validate_sha,
    validate_tracking_ref, with_locked_cache,
};
use crate::families::skill_registry::{
    MAX_PACKAGE_BYTES, MAX_PACKAGE_ENTRIES, MAX_PACKAGE_FILE_BYTES, MAX_PACKAGE_FILES, MAX_SKILL_FILE_BYTES,
    MODE_FILE, PackageMember, check_name, portable_collision_key, sha256_bytes, validate_package_path,
};

/// Maximum stdout bytes accepted from `git ls-tree -r -l -z` or `diff-tree` (`docs/skill-sources.md` §3).
pub const MAX_LS_TREE_BYTES: usize = 16 * 1024 * 1024;
/// Maximum tree entries accepted from `git ls-tree -r -l -z` (`docs/skill-sources.md` §3).
pub const MAX_LS_TREE_ENTRIES: usize = 50_000;
/// Maximum candidate skill packages returned by `source_discover` (`docs/skill-sources.md` §3).
pub const MAX_DISCOVERED_PACKAGES: usize = 200;
/// Maximum changed file paths returned in a `source_refresh` summary.
pub const MAX_REFRESH_DIFF_FILES: usize = 500;

/// One parsed entry from `git ls-tree -r -l -z`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeEntry {
    pub mode: String,
    pub kind: String,
    pub oid: String,
    pub size: Option<u64>,
    pub path: String,
}

/// One candidate skill package discovered by `source_discover`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredPackage {
    pub path: String,
    pub suggested_name: Option<String>,
    pub file_count: usize,
    pub total_bytes: u64,
    pub skill_md_oid: String,
}

impl DiscoveredPackage {
    pub fn to_json(&self) -> Value {
        json!({
            "path": self.path,
            "suggested_name": self.suggested_name,
            "file_count": self.file_count,
            "total_bytes": self.total_bytes,
            "skill_md_oid": self.skill_md_oid,
        })
    }
}

/// One changed path reported by `source_refresh`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangedFile {
    pub path: String,
    pub status: String,
}

impl ChangedFile {
    pub fn to_json(&self) -> Value {
        json!({ "path": self.path, "status": self.status })
    }
}

/// Result of `source_refresh`: candidate SHA and bounded change summary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefreshReport {
    pub tracking_ref: String,
    pub pinned_sha: String,
    pub candidate_sha: String,
    pub changed: bool,
    pub diff_available: bool,
    pub diff_note: Option<String>,
    pub changed_files: Vec<ChangedFile>,
    pub changed_packages: Vec<String>,
    pub truncated: bool,
}

/// Parse NUL-delimited output of `git ls-tree -r -l -z`, enforcing
/// [`MAX_LS_TREE_ENTRIES`], valid UTF-8 paths, and valid 40-char object IDs.
pub fn parse_ls_tree_z(raw: &[u8]) -> UaResult<Vec<TreeEntry>> {
    let mut entries = Vec::new();
    for record in raw.split(|&b| b == 0) {
        if record.is_empty() {
            continue;
        }
        if entries.len() >= MAX_LS_TREE_ENTRIES {
            return Err(UaError::invalid(format!(
                "git ls-tree exceeded the {MAX_LS_TREE_ENTRIES}-entry limit"
            )));
        }
        let line = std::str::from_utf8(record)
            .map_err(|_| UaError::invalid("git tree contains a non-UTF-8 file path"))?;
        let Some((meta, path)) = line.split_once('\t') else {
            return Err(UaError::invalid("malformed git ls-tree entry"));
        };
        if path.is_empty() {
            return Err(UaError::invalid("git ls-tree entry has an empty path"));
        }
        let parts: Vec<&str> = meta.split_whitespace().collect();
        if parts.len() != 4 {
            return Err(UaError::invalid(format!("malformed git ls-tree metadata {meta:?}")));
        }
        let mode = parts[0].to_string();
        let kind = parts[1].to_string();
        let oid = validate_sha(parts[2])
            .map_err(|_| UaError::invalid(format!("invalid git object id {:?} for {path:?}", parts[2])))?;
        let size = if parts[3] == "-" {
            None
        } else {
            let n = parts[3].parse::<u64>().map_err(|_| {
                UaError::invalid(format!("invalid git blob size {:?} for {path:?}", parts[3]))
            })?;
            Some(n)
        };
        entries.push(TreeEntry { mode, kind, oid, size, path: path.to_string() });
    }
    Ok(entries)
}

/// Verify a `git ls-tree` entry is a regular blob (`100644` or `100755`),
/// refusing symlinks (`120000`), gitlinks (`160000`), and any other mode.
pub fn ensure_safe_tree_entry(entry: &TreeEntry) -> UaResult<u64> {
    if entry.mode == "120000" {
        return Err(UaError::invalid(format!(
            "git tree entry {:?} is a symlink (mode 120000); symlinks are refused",
            entry.path
        )));
    }
    if entry.mode == "160000" || entry.kind == "commit" {
        return Err(UaError::invalid(format!(
            "git tree entry {:?} is a gitlink/submodule (mode 160000); submodules are refused",
            entry.path
        )));
    }
    if entry.kind != "blob" || (entry.mode != "100644" && entry.mode != "100755") {
        return Err(UaError::invalid(format!(
            "git tree entry {:?} has non-regular mode {} ({}); only regular files (100644/100755) are allowed",
            entry.path, entry.mode, entry.kind
        )));
    }
    entry.size.ok_or_else(|| UaError::invalid(format!("git blob {:?} is missing a byte size", entry.path)))
}

/// Whether `repo_path` (e.g. `"skills/demo"` or `"."`) falls within `allowed_subpaths`.
pub fn path_allowed(repo_path: &str, allowed_subpaths: &[String]) -> bool {
    if allowed_subpaths.is_empty() {
        return true;
    }
    if repo_path == "." || repo_path.is_empty() {
        return false;
    }
    allowed_subpaths.iter().any(|prefix| repo_path == prefix || repo_path.starts_with(&format!("{prefix}/")))
}

/// Validate a caller-supplied skill directory path inside a source repository
/// and check it against `allowed_subpaths`.
pub fn validate_skill_repo_path(raw: &str, allowed_subpaths: &[String]) -> UaResult<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(UaError::invalid("skill path is required"));
    }
    if trimmed == "." {
        if !allowed_subpaths.is_empty() {
            return Err(UaError::denied(
                "subpath_not_allowed",
                "repository root '.' is outside this source's allowed_subpaths",
            ));
        }
        return Ok(".".into());
    }
    let cleaned = trimmed.trim_end_matches('/');
    let validated = validate_package_path(cleaned)?;
    if !path_allowed(&validated, allowed_subpaths) {
        return Err(UaError::denied(
            "subpath_not_allowed",
            format!("path {validated:?} is outside this source's allowed_subpaths"),
        ));
    }
    Ok(validated)
}

/// Group `ls-tree` entries into candidate skill packages (directories holding a
/// `SKILL.md`) under `allowed_subpaths`, refusing symlinks, gitlinks,
/// non-regular modes, nested `SKILL.md` directories, and >200 packages.
pub fn discover_packages_from_entries(
    entries: &[TreeEntry],
    allowed_subpaths: &[String],
) -> UaResult<Vec<DiscoveredPackage>> {
    // First pass: refuse any symlink, gitlink, or non-regular mode in scope,
    // and collect every directory containing a `SKILL.md`.
    let mut skill_dirs: BTreeMap<String, String> = BTreeMap::new();
    let mut sized_entries: Vec<(&TreeEntry, u64)> = Vec::with_capacity(entries.len());
    for entry in entries {
        let size = ensure_safe_tree_entry(entry)?;
        sized_entries.push((entry, size));
        if entry.path == "SKILL.md" {
            if path_allowed(".", allowed_subpaths) {
                skill_dirs.insert(".".to_string(), entry.oid.clone());
            }
        } else if let Some(dir) = entry.path.strip_suffix("/SKILL.md")
            && path_allowed(dir, allowed_subpaths)
        {
            skill_dirs.insert(dir.to_string(), entry.oid.clone());
        }
    }

    if skill_dirs.len() > MAX_DISCOVERED_PACKAGES {
        return Err(UaError::invalid(format!(
            "source discovery found {} candidate skill packages, exceeding the {MAX_DISCOVERED_PACKAGES}-package limit",
            skill_dirs.len()
        )));
    }

    // Refuse nested SKILL.md directories (a skill package must not contain another SKILL.md).
    let dir_keys: Vec<&String> = skill_dirs.keys().collect();
    for (i, dir) in dir_keys.iter().enumerate() {
        for other in dir_keys.iter().skip(i + 1) {
            let nested =
                if dir.as_str() == "." { true } else { other.starts_with(&format!("{}/", dir.as_str())) };
            if nested {
                return Err(UaError::invalid(format!(
                    "nested SKILL.md directory {:?} inside {:?} is not allowed",
                    other, dir
                )));
            }
        }
    }

    // Second pass: count files and bytes inside each candidate package.
    let mut counts: BTreeMap<String, (usize, u64)> = BTreeMap::new();
    for dir in skill_dirs.keys() {
        counts.insert(dir.clone(), (0, 0));
    }
    for (entry, size) in sized_entries {
        if skill_dirs.contains_key(".") {
            let stat = counts.get_mut(".").expect("root key exists");
            stat.0 += 1;
            stat.1 = stat.1.saturating_add(size);
            continue;
        }
        // Walk path prefixes to find which skill dir owns this entry (at most one,
        // because nested SKILL.md directories were already refused above).
        let mut cursor = entry.path.as_str();
        while let Some((parent, _)) = cursor.rsplit_once('/') {
            if let Some(stat) = counts.get_mut(parent) {
                stat.0 += 1;
                stat.1 = stat.1.saturating_add(size);
                break;
            }
            cursor = parent;
        }
    }

    let mut out = Vec::with_capacity(skill_dirs.len());
    for (dir, skill_md_oid) in skill_dirs {
        let (file_count, total_bytes) = counts.get(&dir).copied().unwrap_or((0, 0));
        let suggested_name = if dir == "." {
            None
        } else {
            let leaf = dir.rsplit('/').next().unwrap_or(&dir);
            check_name(leaf).ok()
        };
        out.push(DiscoveredPackage { path: dir, suggested_name, file_count, total_bytes, skill_md_oid });
    }
    Ok(out)
}

fn run_ls_tree(
    cache: &Path,
    sha: &str,
    subpaths: &[String],
    opts: &FetchOptions,
) -> UaResult<Vec<TreeEntry>> {
    let mut args: Vec<&str> = vec!["ls-tree", "-r", "-l", "-z", sha];
    if !subpaths.is_empty() {
        args.push("--");
        for p in subpaths {
            args.push(p.as_str());
        }
    }
    let spec = build_git_command(Some(cache), None, None, &args, opts)?;
    let raw = run_git(&spec, opts.timeout, MAX_LS_TREE_BYTES.min(opts.max_output_bytes))?;
    parse_ls_tree_z(&raw)
}

fn parse_diff_tree_z(raw: &[u8]) -> UaResult<Vec<ChangedFile>> {
    let tokens: Vec<&[u8]> = raw.split(|&b| b == 0).collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i + 1 < tokens.len() {
        let header = tokens[i];
        if header.is_empty() {
            i += 1;
            continue;
        }
        let path_bytes = tokens[i + 1];
        let header_str =
            std::str::from_utf8(header).map_err(|_| UaError::invalid("malformed git diff-tree header"))?;
        let path = std::str::from_utf8(path_bytes)
            .map_err(|_| UaError::invalid("git diff-tree contains non-UTF-8 path"))?;
        let status_code = header_str.split_whitespace().last().unwrap_or("M");
        let status = match status_code.chars().next() {
            Some('A') => "added",
            Some('D') => "deleted",
            Some('T') => "type_changed",
            _ => "modified",
        };
        out.push(ChangedFile { path: path.to_string(), status: status.to_string() });
        i += 2;
    }
    Ok(out)
}

/// Common context for plumbing operations against one org's allowlisted source.
pub struct SourceFetchCtx<'a> {
    pub data_home: &'a Path,
    pub org_id: &'a str,
    pub url: &'a ParsedSourceUrl,
    pub allowed_subpaths: &'a [String],
    pub resolver: &'a dyn DnsResolver,
    pub opts: &'a FetchOptions,
}

/// Resolve `tracking_ref` on an allowlisted source to a candidate commit SHA
/// and report what changed since `pinned_sha`. Never mutates `pinned_sha`,
/// versions, or assignments.
pub fn refresh_source(
    src: &SourceFetchCtx<'_>,
    tracking_ref: &str,
    pinned_sha: &str,
) -> UaResult<RefreshReport> {
    let tracking = validate_tracking_ref(tracking_ref)?;
    let pinned = validate_sha(pinned_sha)?;
    let pinned_ip = match src.url.scheme {
        SourceScheme::Https => Some(classify_and_pin_ip(&src.url.host, src.url.port, src.resolver)?),
        #[cfg(any(test, feature = "test-util"))]
        SourceScheme::File => {
            if !src.opts.is_file_allowed() {
                return Err(UaError::invalid("file:// skill sources are disabled"));
            }
            None
        }
    };
    ensure_supported_git_version(src.opts)?;

    let cache = cache_dir(src.data_home, src.org_id, &src.url.canonical_url);
    with_locked_cache(&cache, || {
        ensure_bare_repo(&cache, src.opts)?;
        let dst = format!("refs/ua/refresh/{}", hex_prefix(tracking.as_bytes(), 16));
        let spec = build_fetch_command(&cache, src.url, pinned_ip, &tracking, &dst, src.opts)?;
        if let Err(e) = run_git_watched(
            &spec,
            src.opts.timeout,
            src.opts.max_output_bytes,
            Some((&cache, src.opts.max_cache_bytes)),
        ) {
            if dir_size_bytes(&cache) > src.opts.max_cache_bytes {
                let _ = std::fs::remove_dir_all(&cache);
            }
            return Err(e);
        }
        let rev_spec = build_git_command(
            Some(&cache),
            None,
            None,
            &["rev-parse", "--verify", "--quiet", &format!("{dst}^{{commit}}")],
            src.opts,
        )?;
        let out = run_git(&rev_spec, src.opts.timeout, src.opts.max_output_bytes)?;
        let candidate_sha = validate_sha(String::from_utf8_lossy(&out).trim())?;

        if candidate_sha == pinned {
            return Ok(RefreshReport {
                tracking_ref: tracking,
                pinned_sha: pinned,
                candidate_sha,
                changed: false,
                diff_available: true,
                diff_note: None,
                changed_files: Vec::new(),
                changed_packages: Vec::new(),
                truncated: false,
            });
        }

        // Try to ensure `pinned_sha` is in cache via shallow direct SHA want (never full fetch).
        if !commit_present(&cache, &pinned, src.opts) {
            let pin_dst = format!("refs/ua/fetch/{}", &pinned[..16]);
            if let Ok(pin_spec) = build_fetch_command(&cache, src.url, pinned_ip, &pinned, &pin_dst, src.opts)
            {
                let _ = run_git_watched(
                    &pin_spec,
                    src.opts.timeout,
                    src.opts.max_output_bytes,
                    Some((&cache, src.opts.max_cache_bytes)),
                );
            }
        }

        if !commit_present(&cache, &pinned, src.opts) {
            return Ok(RefreshReport {
                tracking_ref: tracking,
                pinned_sha: pinned,
                candidate_sha,
                changed: true,
                diff_available: false,
                diff_note: Some(
                    "pinned_sha is not in the local bare cache and the remote did not serve a shallow SHA want; no full-history fallback was attempted"
                        .into(),
                ),
                changed_files: Vec::new(),
                changed_packages: Vec::new(),
                truncated: false,
            });
        }

        let mut diff_args: Vec<&str> = vec!["diff-tree", "-r", "--no-renames", "-z", &pinned, &candidate_sha];
        if !src.allowed_subpaths.is_empty() {
            diff_args.push("--");
            for p in src.allowed_subpaths {
                diff_args.push(p.as_str());
            }
        }
        let diff_spec = build_git_command(Some(&cache), None, None, &diff_args, src.opts)?;
        let diff_raw =
            run_git(&diff_spec, src.opts.timeout, MAX_LS_TREE_BYTES.min(src.opts.max_output_bytes))?;
        let mut all_changed = parse_diff_tree_z(&diff_raw)?;
        all_changed.retain(|f| path_allowed(&f.path, src.allowed_subpaths));

        // Identify candidate skill package dirs present at either commit that overlap changed files.
        let mut pkg_dirs: BTreeSet<String> = BTreeSet::new();
        for sha in [&pinned, &candidate_sha] {
            if let Ok(tree) = run_ls_tree(&cache, sha, src.allowed_subpaths, src.opts) {
                for entry in tree {
                    if entry.path == "SKILL.md" && path_allowed(".", src.allowed_subpaths) {
                        pkg_dirs.insert(".".into());
                    } else if let Some(dir) = entry.path.strip_suffix("/SKILL.md")
                        && path_allowed(dir, src.allowed_subpaths)
                    {
                        pkg_dirs.insert(dir.to_string());
                    }
                }
            }
        }
        let mut changed_packages: BTreeSet<String> = BTreeSet::new();
        for f in &all_changed {
            for dir in &pkg_dirs {
                let matches =
                    if dir == "." { true } else { f.path == *dir || f.path.starts_with(&format!("{dir}/")) };
                if matches {
                    changed_packages.insert(dir.clone());
                }
            }
        }

        let truncated = all_changed.len() > MAX_REFRESH_DIFF_FILES;
        all_changed.truncate(MAX_REFRESH_DIFF_FILES);

        Ok(RefreshReport {
            tracking_ref: tracking,
            pinned_sha: pinned,
            candidate_sha,
            changed: true,
            diff_available: true,
            diff_note: None,
            changed_files: all_changed,
            changed_packages: changed_packages.into_iter().collect(),
            truncated,
        })
    })
}

/// Fetch `target_sha` (verifying `tracking_ref` when provided) and list
/// candidate skill packages under `allowed_subpaths` via `ls-tree -r -l -z`.
pub fn discover_source(
    src: &SourceFetchCtx<'_>,
    target_sha: &str,
    verify_tracking_ref: Option<&str>,
) -> UaResult<Vec<DiscoveredPackage>> {
    let fetched = fetch_exact_sha(
        src.data_home,
        src.org_id,
        src.url,
        target_sha,
        verify_tracking_ref,
        src.resolver,
        src.opts,
    )?;
    with_locked_cache(&fetched.cache_dir, || {
        let entries = run_ls_tree(&fetched.cache_dir, &fetched.commit_sha, src.allowed_subpaths, src.opts)?;
        discover_packages_from_entries(&entries, src.allowed_subpaths)
    })
}

/// Fetch `target_sha` and read every blob of the skill package at `skill_path`
/// strictly by object ID (`cat-file blob <oid>`), enforcing every D1 path,
/// symlink, gitlink, mode, collision, count, and size cap before returning the
/// in-memory `PackageMember` map. Never materializes a working tree.
pub(crate) fn read_package_from_source(
    src: &SourceFetchCtx<'_>,
    target_sha: &str,
    verify_tracking_ref: Option<&str>,
    skill_path: &str,
) -> UaResult<BTreeMap<String, PackageMember>> {
    let clean_path = validate_skill_repo_path(skill_path, src.allowed_subpaths)?;
    let fetched = fetch_exact_sha(
        src.data_home,
        src.org_id,
        src.url,
        target_sha,
        verify_tracking_ref,
        src.resolver,
        src.opts,
    )?;

    with_locked_cache(&fetched.cache_dir, || {
        let filter: Vec<String> = if clean_path == "." { Vec::new() } else { vec![clean_path.clone()] };
        let entries = run_ls_tree(&fetched.cache_dir, &fetched.commit_sha, &filter, src.opts)?;
        if entries.is_empty() {
            return Err(UaError::not_found(format!(
                "no files found at path {clean_path:?} in commit {}",
                fetched.commit_sha
            )));
        }
        if entries.len() > MAX_PACKAGE_ENTRIES {
            return Err(UaError::invalid(format!(
                "skill package exceeds the {MAX_PACKAGE_ENTRIES}-entry limit"
            )));
        }

        let prefix = if clean_path == "." { String::new() } else { format!("{clean_path}/") };
        let mut plan: Vec<(String, String, u64, usize)> = Vec::new();
        let mut portable_names: BTreeSet<String> = BTreeSet::new();
        let mut declared_total = 0usize;

        for entry in &entries {
            let declared_size = ensure_safe_tree_entry(entry)?;
            let rel_raw = if prefix.is_empty() {
                entry.path.as_str()
            } else {
                let Some(stripped) = entry.path.strip_prefix(&prefix) else {
                    if entry.path == clean_path {
                        return Err(UaError::invalid(format!(
                            "skill path {clean_path:?} is a single file, not a skill directory"
                        )));
                    }
                    continue;
                };
                stripped
            };
            let rel = validate_package_path(rel_raw)?;
            if rel.ends_with("/SKILL.md") {
                return Err(UaError::invalid(format!(
                    "nested SKILL.md at {rel:?} is not allowed inside a skill package"
                )));
            }
            if !portable_names.insert(portable_collision_key(&rel)) {
                return Err(UaError::invalid(format!(
                    "skill package refuses case-insensitive or Unicode path collision at {rel:?}"
                )));
            }
            if plan.len() >= MAX_PACKAGE_FILES {
                return Err(UaError::invalid(format!(
                    "skill package exceeds the {MAX_PACKAGE_FILES}-file limit"
                )));
            }
            let cap = if rel == "SKILL.md" { MAX_SKILL_FILE_BYTES } else { MAX_PACKAGE_FILE_BYTES };
            if declared_size > cap as u64 {
                return Err(UaError::invalid(format!(
                    "skill package member {rel:?} ({declared_size} bytes) exceeds the {cap}-byte limit"
                )));
            }
            declared_total = declared_total.saturating_add(declared_size as usize);
            if declared_total > MAX_PACKAGE_BYTES {
                return Err(UaError::invalid(format!(
                    "skill package exceeds the {MAX_PACKAGE_BYTES}-byte total size limit"
                )));
            }
            plan.push((rel, entry.oid.clone(), declared_size, cap));
        }

        if !plan.iter().any(|(rel, _, _, _)| rel == "SKILL.md") {
            return Err(UaError::invalid(format!("path {clean_path:?} has no SKILL.md at its root")));
        }

        let mut members: BTreeMap<String, PackageMember> = BTreeMap::new();
        let mut actual_total = 0usize;
        for (rel, oid, declared_size, cap) in plan {
            let spec = build_git_command(
                Some(&fetched.cache_dir),
                None,
                None,
                &["cat-file", "blob", &oid],
                src.opts,
            )?;
            let bytes = run_git(&spec, src.opts.timeout, cap)?;
            if bytes.len() as u64 != declared_size || bytes.len() > cap {
                return Err(UaError::conflict(format!(
                    "git blob {oid} for {rel:?} changed size (expected {declared_size}, got {})",
                    bytes.len()
                )));
            }
            actual_total = actual_total.saturating_add(bytes.len());
            if actual_total > MAX_PACKAGE_BYTES {
                return Err(UaError::invalid(format!(
                    "skill package exceeds the {MAX_PACKAGE_BYTES}-byte total size limit"
                )));
            }
            let sha256 = sha256_bytes(&bytes);
            members.insert(rel.clone(), PackageMember { path: rel, bytes, sha256, mode: MODE_FILE });
        }

        let md = members
            .get("SKILL.md")
            .ok_or_else(|| UaError::invalid(format!("path {clean_path:?} has no SKILL.md at its root")))?;
        if md.bytes.contains(&0) || std::str::from_utf8(&md.bytes).is_err() {
            return Err(UaError::invalid("SKILL.md must be valid UTF-8 without NUL bytes"));
        }
        Ok(members)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ls_tree_parser_handles_regular_symlink_and_gitlink_and_refuses_bad_modes() {
        let oid1 = "1".repeat(40);
        let oid2 = "2".repeat(40);
        let oid3 = "3".repeat(40);
        let raw = format!(
            "100644 blob {oid1}     123\tskills/demo/SKILL.md\0\
             100755 blob {oid2}      42\tskills/demo/scripts/run.sh\0"
        );
        let entries = parse_ls_tree_z(raw.as_bytes()).unwrap();
        assert_eq!(entries.len(), 2);
        let pkgs = discover_packages_from_entries(&entries, &["skills".into()]).unwrap();
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].path, "skills/demo");
        assert_eq!(pkgs[0].suggested_name.as_deref(), Some("demo"));
        assert_eq!(pkgs[0].file_count, 2);
        assert_eq!(pkgs[0].total_bytes, 165);

        let symlink_raw = format!(
            "100644 blob {oid1}     123\tskills/demo/SKILL.md\0\
             120000 blob {oid2}      10\tskills/demo/link\0"
        );
        let symlink_entries = parse_ls_tree_z(symlink_raw.as_bytes()).unwrap();
        let e = discover_packages_from_entries(&symlink_entries, &[]).unwrap_err();
        assert!(e.to_string().contains("symlink"), "{e}");

        let gitlink_raw = format!(
            "100644 blob {oid1}     123\tskills/demo/SKILL.md\0\
             160000 commit {oid3}       -\tskills/demo/submod\0"
        );
        let gitlink_entries = parse_ls_tree_z(gitlink_raw.as_bytes()).unwrap();
        let e = discover_packages_from_entries(&gitlink_entries, &[]).unwrap_err();
        assert!(e.to_string().contains("gitlink"), "{e}");
    }

    #[test]
    fn discovery_refuses_over_200_packages_and_nested_skill_md() {
        let oid = "a".repeat(40);
        let mut raw = String::new();
        for i in 0..=MAX_DISCOVERED_PACKAGES {
            raw.push_str(&format!("100644 blob {oid}      10\tskills/s-{i}/SKILL.md\0"));
        }
        let entries = parse_ls_tree_z(raw.as_bytes()).unwrap();
        let e = discover_packages_from_entries(&entries, &[]).unwrap_err();
        assert!(e.to_string().contains("200"), "{e}");

        let nested = format!(
            "100644 blob {oid}      10\tskills/outer/SKILL.md\0\
             100644 blob {oid}      10\tskills/outer/inner/SKILL.md\0"
        );
        let entries = parse_ls_tree_z(nested.as_bytes()).unwrap();
        let e = discover_packages_from_entries(&entries, &[]).unwrap_err();
        assert!(e.to_string().contains("nested"), "{e}");
    }
}
