//! Descriptor-relative file operations for D2. The release directory is
//! operator-configured and private to the hub's OS user.

use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path};

use rustix::fs::{self, AtFlags, FileType, Mode, OFlags};
use rustix::io::Errno;
use ua_core::{UaError, UaResult, safety};
use ua_deliverables::files::{MAX_BYTES, digest};

use crate::families::workspace::{sandbox, sha256_hex};
use crate::registry::ToolCtx;

const DIRECTORY: OFlags =
    OFlags::RDONLY.union(OFlags::DIRECTORY).union(OFlags::NOFOLLOW).union(OFlags::CLOEXEC);
const READ_FILE: OFlags =
    OFlags::RDONLY.union(OFlags::NOFOLLOW).union(OFlags::NONBLOCK).union(OFlags::CLOEXEC);

fn directory(path: &Path) -> rustix::io::Result<OwnedFd> {
    let mut fd = fs::open("/", DIRECTORY, Mode::empty())?;
    for part in path.strip_prefix("/").map_err(|_| Errno::INVAL)?.components() {
        let Component::Normal(name) = part else { return Err(Errno::INVAL) };
        fd = fs::openat(&fd, name, DIRECTORY, Mode::empty())?;
    }
    Ok(fd)
}

fn file_error(e: impl std::fmt::Display) -> UaError {
    UaError::denied("deliverable_file_unavailable", format!("cannot access the deliverable file safely: {e}"))
}

fn limited_read(file: &File, max_links: u64) -> UaResult<Vec<u8>> {
    let meta = file.metadata().map_err(file_error)?;
    if !meta.is_file() || meta.nlink() > max_links {
        return Err(UaError::denied(
            "unsafe_deliverable_file",
            "a deliverable must be a regular file without other links",
        ));
    }
    if meta.len() > MAX_BYTES as u64 {
        return Err(UaError::invalid("deliverable file exceeds 1 MiB"));
    }
    let mut bytes = Vec::new();
    file.take(MAX_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| UaError::internal(format!("read deliverable: {e}")))?;
    if bytes.len() > MAX_BYTES {
        return Err(UaError::invalid("deliverable file exceeds 1 MiB"));
    }
    Ok(bytes)
}

pub fn source(ctx: &ToolCtx, worktree: &str, path: &str) -> UaResult<Vec<u8>> {
    let raw = Path::new(path);
    if path.is_empty()
        || path.len() > 1024
        || path.contains('\0')
        || !raw.components().all(|c| matches!(c, Component::Normal(_)))
        || raw.file_name().is_none()
    {
        return Err(UaError::invalid(
            "source path must be relative to the task worktree and contain no traversal",
        ));
    }

    let sandbox = sandbox(ctx)?;
    // Walking the lexical components relative to the anchored sandbox
    // refuses each symlink without a check followed by an unsafe reopen.
    let candidate = sandbox.root.join(worktree);
    let relative = candidate.strip_prefix(&sandbox.root).map_err(|_| {
        UaError::denied("outside_sandbox", "the task worktree is outside this caller's workspace")
    })?;
    let mut fd = directory(&sandbox.root).map_err(file_error)?;
    let full = candidate.join(raw);
    safety::guard_inside_root(&full, &sandbox.root, path, false)?;
    for part in relative.components().chain(raw.parent().unwrap_or(Path::new("")).components()) {
        let Component::Normal(name) = part else {
            return Err(UaError::invalid("worktree path must contain no traversal"));
        };
        fd = fs::openat(&fd, name, DIRECTORY, Mode::empty()).map_err(file_error)?;
    }
    let name = raw.file_name().expect("validated source name");
    let entry = fs::statat(&fd, name, AtFlags::SYMLINK_NOFOLLOW).map_err(file_error)?;
    if FileType::from_raw_mode(entry.st_mode) != FileType::RegularFile || entry.st_nlink != 1 {
        return Err(UaError::denied(
            "unsafe_deliverable_file",
            "a deliverable source must be a regular file without other links",
        ));
    }
    let file = fs::openat(&fd, name, READ_FILE, Mode::empty()).map_err(file_error)?;
    let opened = fs::fstat(&file).map_err(file_error)?;
    if (entry.st_dev, entry.st_ino) != (opened.st_dev, opened.st_ino) || opened.st_nlink != 1 {
        return Err(UaError::denied("unsafe_deliverable_file", "the deliverable source changed during open"));
    }
    limited_read(&File::from(file), 1)
}

pub struct Destination {
    fd: OwnedFd,
    pub identity: String,
}

impl Destination {
    pub fn configured(ctx: &ToolCtx) -> UaResult<Self> {
        let cfg = ctx.hub.cfg();
        let configured =
            cfg.deliverable_release_root.as_ref().filter(|p| p.is_absolute()).ok_or_else(|| {
                UaError::denied("release_unconfigured", "configure an absolute deliverable_release_root")
            })?;
        let root = configured.canonicalize().map_err(|_| {
            UaError::denied("release_unconfigured", "the configured release directory must exist")
        })?;
        if configured.as_os_str() != root.as_os_str() {
            return Err(UaError::denied(
                "unsafe_release_root",
                "the configured release directory must be a canonical path without symlinks",
            ));
        }
        let home = std::env::var_os("HOME").map(std::path::PathBuf::from);
        let os_home = home.as_ref().and_then(|path| path.canonicalize().ok());
        let private_home = os_home.as_ref().is_some_and(|home| {
            home.starts_with(&root)
                || root.strip_prefix(home).is_ok_and(|relative| {
                    relative.components().any(|part| part.as_os_str().as_encoded_bytes().starts_with(b"."))
                })
        });
        let mut workspace_roots = vec![cfg.workspace_root(), cfg.home.clone()];
        workspace_roots.extend(cfg.read_roots.iter().cloned());
        workspace_roots.extend(cfg.vault_path.iter().cloned());
        workspace_roots.extend(cfg.agent_workspaces.values().filter(|p| p.trim() != "deny").map(|p| {
            let p = p.trim();
            if let Some(rest) = p.strip_prefix("~/")
                && let Some(home) = &home
            {
                return home.join(rest);
            }
            Path::new(p).to_path_buf()
        }));
        if private_home
            || workspace_roots.iter().any(|p| {
                safety::canonicalize_lenient(p).is_ok_and(|p| root.starts_with(&p) || p.starts_with(&root))
            })
        {
            return Err(UaError::denied(
                "unsafe_release_root",
                "the release directory must be separate from the hub home, private home directories, workspaces, read roots and the vault",
            ));
        }
        let fd = directory(&root).map_err(file_error)?;
        let stat = fs::fstat(&fd).map_err(file_error)?;
        if stat.st_uid != rustix::process::geteuid().as_raw() || stat.st_mode & 0o777 != 0o700 {
            return Err(UaError::denied(
                "unsafe_release_root",
                "the release directory must belong to the hub user and have mode 0700",
            ));
        }
        let path_hash = sha256_hex(root.as_os_str().as_encoded_bytes());
        Ok(Self { fd, identity: format!("{}:{}:{path_hash}", stat.st_dev, stat.st_ino) })
    }

    pub fn check_absent(&self, name: &str) -> UaResult<()> {
        match fs::statat(&self.fd, name, AtFlags::SYMLINK_NOFOLLOW) {
            Err(Errno::NOENT) => Ok(()),
            Ok(_) => Err(UaError::conflict_code(
                "release_destination_exists",
                "the release destination already exists",
            )),
            Err(e) => Err(file_error(e)),
        }
    }

    pub fn matches(&self, name: &str, sha256: &str) -> UaResult<bool> {
        let file = fs::openat(&self.fd, name, READ_FILE, Mode::empty()).map_err(file_error)?;
        Ok(digest(&limited_read(&File::from(file), 2)?) == sha256)
    }

    /// Pending publication keeps its private staging name until a receipt
    /// commits. Inspect it under the same database write lock as publication.
    pub fn check_unpublished(&self, staging: &str, name: &str) -> UaResult<()> {
        let staged = match fs::statat(&self.fd, staging, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) => stat,
            Err(Errno::NOENT) => return Ok(()),
            Err(e) => return Err(file_error(e)),
        };
        if FileType::from_raw_mode(staged.st_mode) == FileType::RegularFile && staged.st_nlink == 1 {
            return Ok(());
        }
        match fs::statat(&self.fd, name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) if (stat.st_dev, stat.st_ino) == (staged.st_dev, staged.st_ino) => {
                return Err(UaError::conflict_code(
                    "release_already_published",
                    "a published file release cannot be cancelled",
                ));
            }
            Ok(_) | Err(Errno::NOENT) => {}
            Err(e) => return Err(file_error(e)),
        }
        Err(UaError::conflict_code(
            "release_publication_uncertain",
            "the staged file changed and publication status cannot be confirmed",
        ))
    }

    /// Prove a prior publication using the staged inode and approved digest.
    /// A file with identical bytes at a different inode is no proof.
    pub fn confirm_published(&self, staging: &str, name: &str, sha256: &str) -> UaResult<bool> {
        let destination = match fs::statat(&self.fd, name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) => stat,
            Err(Errno::NOENT) => return Ok(false),
            Err(e) => return Err(file_error(e)),
        };
        if FileType::from_raw_mode(destination.st_mode) != FileType::RegularFile {
            return Ok(false);
        }
        let file = match fs::openat(&self.fd, staging, READ_FILE | OFlags::RDWR, Mode::empty()) {
            Ok(fd) => File::from(fd),
            Err(Errno::NOENT) => return Ok(false),
            Err(e) => return Err(file_error(e)),
        };
        let staged = fs::fstat(&file).map_err(file_error)?;
        if (staged.st_dev, staged.st_ino) != (destination.st_dev, destination.st_ino) {
            return Ok(false);
        }
        if digest(&limited_read(&file, 2)?) != sha256 {
            return Err(UaError::denied("deliverable_tampered", "published bytes changed before recovery"));
        }
        file.sync_all().map_err(|e| UaError::internal(format!("sync recovered release: {e}")))?;
        fs::fsync(&self.fd).map_err(file_error)?;
        Ok(true)
    }

    pub fn publish(&self, staging: &str, name: &str, bytes: &[u8], sha256: &str) -> UaResult<()> {
        // A previously completed link is recognized only by the staged
        // inode, never because an unrelated destination has matching bytes.
        let staged = match fs::openat(&self.fd, staging, READ_FILE | OFlags::RDWR, Mode::empty()) {
            Ok(fd) => {
                let stat = fs::fstat(&fd).map_err(file_error)?;
                let staged_file = File::from(fd);
                let valid = FileType::from_raw_mode(stat.st_mode) == FileType::RegularFile
                    && digest(&limited_read(&staged_file, 2)?) == sha256;
                if valid {
                    staged_file
                        .sync_all()
                        .map_err(|e| UaError::internal(format!("sync recovered release: {e}")))?;
                    Some(stat)
                } else if stat.st_nlink == 1 && FileType::from_raw_mode(stat.st_mode) == FileType::RegularFile
                {
                    fs::unlinkat(&self.fd, staging, AtFlags::empty()).map_err(file_error)?;
                    None
                } else {
                    return Err(UaError::conflict_code(
                        "release_staging_changed",
                        "the staged release file changed",
                    ));
                }
            }
            Err(Errno::NOENT) => None,
            Err(e) => return Err(file_error(e)),
        };
        let staged = if let Some(staged) = staged {
            staged
        } else {
            self.check_absent(name)?;
            let flags = OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW;
            let fd = fs::openat(&self.fd, staging, flags, Mode::RUSR | Mode::WUSR).map_err(file_error)?;
            let mut file = File::from(fd);
            file.write_all(bytes).map_err(|e| UaError::internal(format!("write staged release: {e}")))?;
            file.sync_all().map_err(|e| UaError::internal(format!("sync staged release: {e}")))?;
            fs::fstat(&file).map_err(file_error)?
        };
        match fs::linkat(&self.fd, staging, &self.fd, name, AtFlags::empty()) {
            Ok(()) => {}
            Err(Errno::EXIST) => {
                let file = fs::statat(&self.fd, name, AtFlags::SYMLINK_NOFOLLOW).map_err(file_error)?;
                if (file.st_dev, file.st_ino) != (staged.st_dev, staged.st_ino) {
                    return Err(UaError::conflict_code(
                        "release_destination_exists",
                        "the release destination already exists",
                    ));
                }
            }
            Err(e) => return Err(file_error(e)),
        }
        fs::fsync(&self.fd).map_err(file_error)?;
        Ok(())
    }

    pub fn clean_staging(&self, staging: &str) {
        let _ = fs::unlinkat(&self.fd, staging, AtFlags::empty());
    }
}
