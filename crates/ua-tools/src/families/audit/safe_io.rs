//! Read or write a file only when it is a regular file, never blocking.
//!
//! Opening a FIFO with no writer blocks forever, and a device reports a size
//! of zero, so a size check alone never refuses one. Every audit reader and
//! writer of a path inside a scanned tree goes through here: the type is
//! checked on the path (so a device or FIFO is never opened) and again on the
//! open descriptor (so a file swapped for a FIFO in between cannot block).

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;

fn open_flags(opts: &mut OpenOptions) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY);
    }
    #[cfg(not(unix))]
    let _ = opts;
}

/// The bytes of `path`, or `None` when it is not a regular file (or a link to
/// one), cannot be read, or is larger than `limit` bytes.
pub fn read_regular_file(path: &Path, limit: Option<usize>) -> Option<Vec<u8>> {
    if !std::fs::metadata(path).ok()?.is_file() {
        return None;
    }
    let mut opts = OpenOptions::new();
    opts.read(true);
    open_flags(&mut opts);
    let mut file: File = opts.open(path).ok()?;
    let meta = file.metadata().ok()?;
    if !meta.is_file() {
        return None;
    }
    if limit.is_some_and(|l| meta.len() > l as u64) {
        return None;
    }
    let mut buf = Vec::new();
    match limit {
        // One byte past the limit: a file that grew after the check is refused.
        Some(l) => {
            (&mut file).take(l as u64 + 1).read_to_end(&mut buf).ok()?;
            if buf.len() > l {
                return None;
            }
        }
        None => {
            file.read_to_end(&mut buf).ok()?;
        }
    }
    Some(buf)
}

/// Config-sized text (decoded lossily), capped at 8 MB.
pub fn read_regular_text(path: &Path) -> Option<String> {
    read_regular_file(path, Some(8 << 20)).map(|b| String::from_utf8_lossy(&b).into_owned())
}

/// Write `text` into a regular file. A FIFO, device, directory or symlink at
/// the path is refused and left untouched, on the path and (via `O_NOFOLLOW`)
/// on the open descriptor. With `create_only` the file is created with
/// `create_new`, so one that appeared after the scan is never truncated;
/// otherwise a missing file is created and an existing one replaced.
pub fn write_regular_text(path: &Path, text: &str, create_only: bool) -> std::io::Result<()> {
    let refuse = || std::io::Error::new(std::io::ErrorKind::InvalidInput, "not a regular file");
    match std::fs::symlink_metadata(path) {
        Ok(m) if !m.is_file() => return Err(refuse()),
        Ok(_) if create_only => {
            return Err(std::io::Error::new(std::io::ErrorKind::AlreadyExists, "file already exists"));
        }
        Ok(_) | Err(_) => {}
    }
    let mut opts = OpenOptions::new();
    opts.write(true);
    if create_only {
        opts.create_new(true);
    } else {
        opts.create(true).truncate(false);
    }
    open_flags(&mut opts);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY | libc::O_NOFOLLOW);
    }
    let mut file = opts.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(refuse());
    }
    if !create_only {
        file.set_len(0)?;
    }
    file.write_all(text.as_bytes())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn create_only_never_truncates_an_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("a.txt");
        write_regular_text(&f, "one", true).unwrap();
        let err = write_regular_text(&f, "two", true).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read_to_string(&f).unwrap(), "one");
    }

    #[test]
    fn symlinks_are_refused_for_both_modes() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target.txt");
        std::fs::write(&target, "keep").unwrap();
        let link = dir.path().join("link.txt");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(write_regular_text(&link, "x", false).is_err());
        assert!(write_regular_text(&link, "x", true).is_err());
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "keep");
    }

    #[test]
    fn nofollow_holds_on_the_descriptor_when_the_path_check_is_raced() {
        // A dangling link passes no metadata check as a regular file; the open
        // itself must still refuse to follow it and create the target.
        let dir = tempfile::tempdir().unwrap();
        let link = dir.path().join("dangling");
        std::os::unix::fs::symlink(dir.path().join("missing"), &link).unwrap();
        assert!(write_regular_text(&link, "x", false).is_err());
        assert!(!dir.path().join("missing").exists());
    }
}
