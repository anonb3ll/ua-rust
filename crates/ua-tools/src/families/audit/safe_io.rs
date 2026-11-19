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

fn nofollow_flags(opts: &mut OpenOptions) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY | libc::O_NOFOLLOW);
    }
    #[cfg(not(unix))]
    let _ = opts;
}

/// Payload of the hard-link refusal, so callers can name the cause.
#[derive(Debug)]
pub struct HardLink;

impl std::fmt::Display for HardLink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("file has more than one hard link")
    }
}

impl std::error::Error for HardLink {}

pub fn is_hardlink(e: &std::io::Error) -> bool {
    e.get_ref().is_some_and(|x| x.downcast_ref::<HardLink>().is_some())
}

fn refuse() -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidInput, "not a regular file")
}

const REPLACE_LIMIT: u64 = 8 << 20;

/// Create `path` with `text`; it must not exist. `create_new` never truncates
/// a file that appeared after the scan, and `O_NOFOLLOW` plus the exclusive
/// create refuse a symlink at the path.
pub fn create_regular_text(path: &Path, text: &str) -> std::io::Result<()> {
    create_with(path, |f| f.write_all(text.as_bytes()))
}

/// Create `path` exclusively and fill it with `write`. We created the file,
/// so any failure after the create removes it again: a partial file would
/// block every later run with "already exists".
fn create_with(path: &Path, write: impl FnOnce(&mut File) -> std::io::Result<()>) -> std::io::Result<()> {
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    nofollow_flags(&mut opts);
    let mut file = opts.open(path)?;
    if let Err(e) = write(&mut file).and_then(|()| file.sync_all()) {
        drop(file);
        let _ = std::fs::remove_file(path);
        return Err(e);
    }
    #[cfg(unix)]
    if let Some(dir) = path.parent()
        && let Err(e) = File::open(dir).and_then(|d| d.sync_all())
    {
        tracing::warn!(kind = ?e.kind(), "audit: created file but the directory sync failed");
    }
    Ok(())
}

/// Read `path` (a regular file, never followed through a symlink) from ONE
/// open descriptor, let `decide` turn those bytes into the new text, and
/// replace the file with a temp file renamed over it. `decide` returning
/// `None` leaves the file alone (`Ok(false)`). Nothing is written when
/// `decide` fails, so the check and the write act on the same file.
pub fn replace_regular_text(
    path: &Path,
    decide: impl FnOnce(&[u8]) -> std::io::Result<Option<String>>,
) -> std::io::Result<bool> {
    let mut opts = OpenOptions::new();
    opts.read(true);
    nofollow_flags(&mut opts);
    let mut file = opts.open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() || meta.len() > REPLACE_LIMIT {
        return Err(refuse());
    }
    // A rename over a hardlinked file would split the link.
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if meta.nlink() > 1 {
            return Err(std::io::Error::other(HardLink));
        }
    }
    let mut buf = Vec::new();
    (&mut file).take(REPLACE_LIMIT + 1).read_to_end(&mut buf)?;
    if buf.len() as u64 > REPLACE_LIMIT {
        return Err(refuse());
    }
    let Some(new) = decide(&buf)? else { return Ok(false) };

    let dir = path.parent().ok_or_else(refuse)?;
    let name = path.file_name().ok_or_else(refuse)?.to_string_lossy();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let tmp = dir.join(format!(".{name}.ua-tmp-{}-{nanos}", std::process::id()));
    let result = (|| {
        let mut topts = OpenOptions::new();
        topts.write(true).create_new(true);
        nofollow_flags(&mut topts);
        // Never wider than the original, even before the final chmod.
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
            topts.mode(meta.mode() & 0o7777);
        }
        let mut t = topts.open(&tmp)?;
        t.write_all(new.as_bytes())?;
        t.set_permissions(meta.permissions())?;
        t.sync_all()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let now = std::fs::symlink_metadata(path)?;
            if now.dev() != meta.dev() || now.ino() != meta.ino() {
                return Err(std::io::Error::other("file was replaced during the update"));
            }
            // The same descriptor must still show what was read: an in-place
            // edit since then would be silently overwritten.
            let cur = file.metadata()?;
            if cur.len() != meta.len()
                || cur.mtime() != meta.mtime()
                || cur.mtime_nsec() != meta.mtime_nsec()
                || cur.ctime() != meta.ctime()
                || cur.ctime_nsec() != meta.ctime_nsec()
                || cur.nlink() != 1
            {
                return Err(std::io::Error::other("file was modified during the update"));
            }
        }
        std::fs::rename(&tmp, path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
        return result.map(|()| true);
    }
    // The file is already replaced: a failing directory sync must not report
    // the change as not applied (the caller would leave it out of the ledger).
    #[cfg(unix)]
    if let Err(e) = File::open(dir).and_then(|d| d.sync_all()) {
        tracing::warn!(kind = ?e.kind(), "audit: replaced file but the directory sync failed");
    }
    Ok(true)
}

/// The whole file as strictly valid UTF-8, read from one descriptor that never
/// follows a symlink. A file that is not UTF-8 is an error, never decoded
/// lossily.
pub fn read_regular_text_strict(path: &Path) -> std::io::Result<(String, Vec<u8>)> {
    let mut seen = None;
    replace_regular_text(path, |b| {
        seen = Some(b.to_vec());
        Ok(None)
    })?;
    let bytes = seen.unwrap_or_default();
    let text = String::from_utf8(bytes.clone())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "not valid UTF-8"))?;
    Ok((text, bytes))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn create_never_truncates_an_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("a.txt");
        create_regular_text(&f, "one").unwrap();
        let err = create_regular_text(&f, "two").unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read_to_string(&f).unwrap(), "one");
    }

    #[test]
    fn a_failed_create_leaves_no_partial_file() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("a.txt");
        let err = create_with(&f, |w| {
            w.write_all(b"par")?;
            Err(std::io::Error::other("disk full"))
        })
        .unwrap_err();
        assert_eq!(err.to_string(), "disk full");
        assert!(!f.exists(), "partial file removed");
        create_regular_text(&f, "ok").unwrap();
        // An existing file we did not create is never removed on refusal.
        assert!(create_with(&f, |_| Ok(())).is_err());
        assert_eq!(std::fs::read_to_string(&f).unwrap(), "ok");
    }

    #[test]
    fn symlinks_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target.txt");
        std::fs::write(&target, "keep").unwrap();
        let link = dir.path().join("link.txt");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(replace_regular_text(&link, |_| Ok(Some("x".into()))).is_err());
        assert!(create_regular_text(&link, "x").is_err());
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "keep");
        let dangling = dir.path().join("dangling");
        std::os::unix::fs::symlink(dir.path().join("missing"), &dangling).unwrap();
        assert!(create_regular_text(&dangling, "x").is_err());
        assert!(!dir.path().join("missing").exists());
    }

    #[test]
    fn replace_checks_and_writes_the_same_bytes_and_keeps_mode() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("a.txt");
        std::fs::write(&f, "old").unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o640)).unwrap();
        // A refusing decide writes nothing.
        let err = replace_regular_text(&f, |_| Err(std::io::Error::other("no"))).unwrap_err();
        assert_eq!(err.to_string(), "no");
        assert_eq!(std::fs::read_to_string(&f).unwrap(), "old");
        assert!(replace_regular_text(&f, |b| Ok(Some(format!("{}!", String::from_utf8_lossy(b))))).unwrap());
        assert_eq!(std::fs::read_to_string(&f).unwrap(), "old!");
        assert_eq!(std::fs::metadata(&f).unwrap().permissions().mode() & 0o777, 0o640);
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1, "no temp file is left");
    }

    #[test]
    fn hardlinked_files_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("a.txt");
        std::fs::write(&f, "old").unwrap();
        std::fs::hard_link(&f, dir.path().join("b.txt")).unwrap();
        assert!(replace_regular_text(&f, |_| Ok(Some("new".into()))).is_err());
        assert_eq!(std::fs::read_to_string(&f).unwrap(), "old");
        assert_eq!(std::fs::read_to_string(dir.path().join("b.txt")).unwrap(), "old");
    }

    #[test]
    fn an_in_place_edit_between_read_and_commit_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("a.txt");
        std::fs::write(&f, "old").unwrap();
        let err = replace_regular_text(&f, |_| {
            // Same length, different bytes, edited in place.
            let w = OpenOptions::new().write(true).open(&f)?;
            (&w).write_all(b"mid")?;
            w.set_modified(std::time::SystemTime::now() + std::time::Duration::from_secs(10))?;
            Ok(Some("new".into()))
        })
        .unwrap_err();
        assert!(err.to_string().contains("modified"), "{err}");
        assert_eq!(std::fs::read_to_string(&f).unwrap(), "mid");
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1, "no temp file is left");
    }

    #[test]
    fn strict_read_rejects_non_utf8() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("a.txt");
        std::fs::write(&f, b"ok \xff").unwrap();
        assert_eq!(read_regular_text_strict(&f).unwrap_err().kind(), std::io::ErrorKind::InvalidData);
    }
}
