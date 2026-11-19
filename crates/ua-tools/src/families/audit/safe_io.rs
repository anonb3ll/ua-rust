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

/// Write `text` into a regular file (created when missing). A FIFO, device,
/// directory or symlink at the path is refused and left untouched.
pub fn write_regular_text(path: &Path, text: &str) -> std::io::Result<()> {
    let refuse = || std::io::Error::new(std::io::ErrorKind::InvalidInput, "not a regular file");
    match std::fs::symlink_metadata(path) {
        Ok(m) if !m.is_file() => return Err(refuse()),
        Ok(_) | Err(_) => {}
    }
    let mut opts = OpenOptions::new();
    opts.write(true).create(true).truncate(false);
    open_flags(&mut opts);
    let mut file = opts.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(refuse());
    }
    file.set_len(0)?;
    file.write_all(text.as_bytes())
}
