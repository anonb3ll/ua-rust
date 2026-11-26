//! Operational CLI commands: `ua init`, `ua doctor`, `ua backup`, and `ua restore`.

pub mod backup;
pub mod doctor;
pub mod evidence;
pub mod init;
pub mod memory_models;

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, bail};

static TEMP_SEQ: AtomicU64 = AtomicU64::new(1);

pub(crate) fn default_home() -> PathBuf {
    std::env::var_os("HOME").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(".")).join(".ua-rust")
}

pub(crate) fn expand_tilde(p: &Path) -> PathBuf {
    let s = p.to_string_lossy();
    if let Some(rest) = s.strip_prefix("~/")
        && let Some(home) = std::env::var_os("HOME")
    {
        return PathBuf::from(home).join(rest);
    }
    p.to_path_buf()
}

pub(crate) fn reject_if_symlink(path: &Path, role: &str) -> anyhow::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_symlink() => {
            bail!("{role} path {} is a symbolic link; refusing to follow it", path.display());
        }
        Ok(m) if m.is_dir() => {
            bail!("{role} path {} is a directory, expected a file", path.display());
        }
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).with_context(|| format!("inspecting {role} path {}", path.display())),
    }
}

pub(crate) fn ensure_dir_private(path: &Path) -> anyhow::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_symlink() => {
            bail!("directory path {} is a symbolic link; refusing to use it", path.display());
        }
        Ok(m) if !m.is_dir() => {
            bail!("path {} exists and is not a directory", path.display());
        }
        Ok(_) => return Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e).with_context(|| format!("inspecting directory {}", path.display())),
    }
    fs::create_dir_all(path).with_context(|| format!("creating directory {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .with_context(|| format!("setting 0700 permissions on {}", path.display()))?;
    }
    Ok(())
}

pub(crate) fn set_owner_only_file(path: &Path) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .with_context(|| format!("setting 0600 permissions on {}", path.display()))?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

fn exclusive_create_file(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
        opts.custom_flags(libc::O_NOFOLLOW);
    }
    let mut f = match opts.open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            bail!("file {} already exists (pass --force to overwrite)", path.display());
        }
        Err(e) => return Err(e).with_context(|| format!("creating {}", path.display())),
    };
    let res = (|| -> anyhow::Result<()> {
        f.write_all(bytes)?;
        f.sync_all()?;
        set_owner_only_file(path)?;
        Ok(())
    })();
    if res.is_err() {
        let _ = fs::remove_file(path);
    }
    res
}

pub(crate) fn write_atomic_file(path: &Path, bytes: &[u8], force: bool) -> anyhow::Result<()> {
    reject_if_symlink(path, "target")?;
    if !force && fs::symlink_metadata(path).is_ok() {
        bail!("file {} already exists (pass --force to overwrite)", path.display());
    }
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .ok_or_else(|| anyhow::anyhow!("path {} must have a parent directory", path.display()))?;
    fs::create_dir_all(parent).with_context(|| format!("creating directory {}", parent.display()))?;

    let stem = path.file_name().and_then(|s| s.to_str()).unwrap_or("file");
    let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let tmp = parent.join(format!(".{stem}.{}.{seq}.tmp", std::process::id()));

    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
        opts.custom_flags(libc::O_NOFOLLOW);
    }
    let write_res = (|| -> anyhow::Result<()> {
        let mut f = opts.open(&tmp).with_context(|| format!("creating temporary file {}", tmp.display()))?;
        f.write_all(bytes)?;
        f.sync_all()?;
        set_owner_only_file(&tmp)?;
        if force {
            fs::rename(&tmp, path).with_context(|| format!("installing {}", path.display()))?;
        } else {
            #[cfg(unix)]
            {
                match fs::hard_link(&tmp, path) {
                    Ok(()) => {
                        let _ = fs::remove_file(&tmp);
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                        bail!("file {} already exists (pass --force to overwrite)", path.display());
                    }
                    Err(e)
                        if matches!(
                            e.kind(),
                            std::io::ErrorKind::Unsupported | std::io::ErrorKind::PermissionDenied
                        ) =>
                    {
                        exclusive_create_file(path, bytes)?;
                        let _ = fs::remove_file(&tmp);
                    }
                    Err(e) => {
                        return Err(e).with_context(|| format!("installing {}", path.display()));
                    }
                }
            }
            #[cfg(not(unix))]
            {
                exclusive_create_file(path, bytes)?;
                let _ = fs::remove_file(&tmp);
            }
        }
        #[cfg(unix)]
        if let Ok(dir) = File::open(parent) {
            let _ = dir.sync_all();
        }
        Ok(())
    })();

    if write_res.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    write_res
}

/// Preserve a `0600` timestamped `.bak` copy before overwriting an existing file.
pub(crate) fn backup_existing_file(path: &Path) -> anyhow::Result<Option<PathBuf>> {
    let meta = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("inspecting {}", path.display())),
    };
    if meta.file_type().is_symlink() || !meta.is_file() {
        bail!("existing path {} is not a regular file", path.display());
    }
    let ts = ua_core::time::now();
    let base_ts = ts.split('+').next().unwrap_or(&ts);
    let stamp: String = base_ts.chars().filter(|c| c.is_ascii_alphanumeric()).collect();
    let mut name = path.file_name().map(|n| n.to_os_string()).unwrap_or_default();
    name.push(format!(".bak-{stamp}Z"));
    let base_bak = path.with_file_name(name);
    let mut bak = base_bak.clone();
    let mut idx = 1usize;
    while fs::symlink_metadata(&bak).is_ok() {
        let mut n = base_bak.file_name().map(|s| s.to_os_string()).unwrap_or_default();
        n.push(format!(".{idx}"));
        bak = base_bak.with_file_name(n);
        idx += 1;
    }
    let mut bytes = Vec::new();
    File::open(path)?.read_to_end(&mut bytes)?;
    write_atomic_file(&bak, &bytes, false)?;
    Ok(Some(bak))
}
