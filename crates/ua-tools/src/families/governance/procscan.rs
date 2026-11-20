//! Which paths running processes use, for `cleanup_stale_worktrees`.
//!
//! Depends only on `std` and `libc`, so the macOS code can be type-checked
//! for an Apple target in isolation.
//!
//! - Linux reads `/proc`: each process's working directory, executable and
//!   absolute command-line arguments.
//! - macOS lists every pid with `proc_listallpids` and asks
//!   `proc_pidinfo(PROC_PIDVNODEPATHINFO)` for the working directory,
//!   `proc_pidpath` for the executable and `sysctl(KERN_PROCARGS2)` for the
//!   absolute arguments.
//! - Elsewhere the scan cannot run, so liveness is unknown and the caller
//!   keeps every worktree.
//!
//! A process with this hub's own credentials whose working directory cannot
//! be read (a non-dumpable daemon such as an SSH agent on Linux, a hardened
//! process on macOS) is listed in [`Live::unreadable`]. Processes of other
//! users are read where the platform allows and otherwise skipped, as on
//! Linux.

use std::path::PathBuf;

/// What the process scan saw.
#[derive(Debug, Default)]
pub struct Live {
    pub paths: Vec<PathBuf>,
    /// Processes with our credentials whose working directory is hidden.
    pub unreadable: Vec<String>,
}

/// Scan the process table. `None` when it cannot be read at all.
#[cfg(target_os = "linux")]
pub fn live_process_paths() -> Option<Live> {
    use std::path::Path;

    // Equal Uid, Gid, Groups and CapPrm lines: the same credentials as ours.
    fn creds(status: &Path) -> Option<Vec<String>> {
        let text = std::fs::read_to_string(status).ok()?;
        Some(
            text.lines()
                .filter(|l| ["Uid:", "Gid:", "Groups:", "CapPrm:"].iter().any(|k| l.starts_with(k)))
                .map(|l| l.split_whitespace().collect::<Vec<_>>().join(" "))
                .collect(),
        )
    }
    let own = creds(Path::new("/proc/self/status"));
    let mut live = Live::default();
    for entry in std::fs::read_dir("/proc").ok()?.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.is_empty() || !name.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        let dir = entry.path();
        let theirs = creds(&dir.join("status"));
        let mut denied = false;
        for link in ["cwd", "exe"] {
            match std::fs::read_link(dir.join(link)) {
                Ok(p) => live.paths.push(p),
                Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => denied = true,
                Err(_) => {}
            }
        }
        if let Ok(raw) = std::fs::read(dir.join("cmdline")) {
            for arg in raw.split(|b| *b == 0).filter(|a| a.first() == Some(&b'/')) {
                live.paths.push(PathBuf::from(String::from_utf8_lossy(arg).into_owned()));
            }
        }
        if denied && theirs.is_some() && theirs == own {
            let comm = std::fs::read_to_string(dir.join("comm")).unwrap_or_default();
            live.unreadable.push(format!("pid {name} ({})", comm.trim()));
        }
    }
    Some(live)
}

/// Scan the process table. `None` when it cannot be read at all.
#[cfg(target_os = "macos")]
pub fn live_process_paths() -> Option<Live> {
    use std::mem::{MaybeUninit, size_of};

    let pids = macos::all_pids()?;
    // SAFETY: geteuid has no preconditions and cannot fail.
    let own_uid = unsafe { libc::geteuid() };
    let mut live = Live::default();
    for pid in pids.into_iter().filter(|p| *p > 0) {
        let size = libc::c_int::try_from(size_of::<libc::proc_vnodepathinfo>()).ok()?;
        let mut info = MaybeUninit::<libc::proc_vnodepathinfo>::zeroed();
        // SAFETY: the buffer is a zero-initialized `proc_vnodepathinfo` and
        // `size` is its exact size; the call writes at most `size` bytes.
        let n = unsafe {
            libc::proc_pidinfo(pid, libc::PROC_PIDVNODEPATHINFO, 0, info.as_mut_ptr().cast(), size)
        };
        if n == size {
            // SAFETY: plain old data, zero-initialized and filled (`n == size`).
            let info = unsafe { info.assume_init() };
            if let Some(p) = macos::vnode_path(&info.pvi_cdir.vip_path) {
                live.paths.push(p);
            }
        } else if macos::uid_of(pid) == Some(own_uid) {
            // Ours, but the working directory is hidden; an exited pid has
            // no uid any more and is not listed.
            live.unreadable.push(format!("pid {pid} ({})", macos::name_of(pid)));
        }
        if let Some(exe) = macos::exe_of(pid) {
            live.paths.push(exe);
        }
        live.paths.extend(macos::absolute_args(pid));
    }
    Some(live)
}

#[cfg(target_os = "macos")]
mod macos {
    use std::ffi::OsStr;
    use std::mem::{MaybeUninit, size_of};
    use std::os::unix::ffi::OsStrExt;
    use std::path::PathBuf;

    /// Every pid on the system, or `None` when the list cannot be read.
    pub fn all_pids() -> Option<Vec<libc::pid_t>> {
        // SAFETY: a null buffer asks only for the current count.
        let n = unsafe { libc::proc_listallpids(std::ptr::null_mut(), 0) };
        let n = usize::try_from(n).ok().filter(|n| *n > 0)?;
        // Room for processes started between the two calls.
        let mut pids: Vec<libc::pid_t> = vec![0; n + 256];
        let bytes = libc::c_int::try_from(pids.len() * size_of::<libc::pid_t>()).ok()?;
        // SAFETY: `pids` holds `bytes` bytes of writable, initialized memory.
        let got = unsafe { libc::proc_listallpids(pids.as_mut_ptr().cast(), bytes) };
        let got = usize::try_from(got).ok().filter(|g| *g > 0)?;
        pids.truncate(got.min(pids.len()));
        Some(pids)
    }

    /// A NUL-terminated path out of `vnode_info_path::vip_path`.
    pub fn vnode_path(raw: &[[libc::c_char; 32]; 32]) -> Option<PathBuf> {
        let bytes: Vec<u8> = raw.iter().flatten().map(|c| *c as u8).take_while(|b| *b != 0).collect();
        (bytes.first() == Some(&b'/')).then(|| PathBuf::from(OsStr::from_bytes(&bytes)))
    }

    fn bsdinfo(pid: libc::pid_t) -> Option<libc::proc_bsdinfo> {
        let size = libc::c_int::try_from(size_of::<libc::proc_bsdinfo>()).ok()?;
        let mut info = MaybeUninit::<libc::proc_bsdinfo>::zeroed();
        // SAFETY: a zero-initialized `proc_bsdinfo` of exactly `size` bytes.
        let n = unsafe { libc::proc_pidinfo(pid, libc::PROC_PIDTBSDINFO, 0, info.as_mut_ptr().cast(), size) };
        // SAFETY: plain old data, zero-initialized and filled (`n == size`).
        (n == size).then(|| unsafe { info.assume_init() })
    }

    /// The process's effective uid, when it can be read.
    pub fn uid_of(pid: libc::pid_t) -> Option<libc::uid_t> {
        bsdinfo(pid).map(|i| i.pbi_uid)
    }

    /// The process's short name, for a report line.
    pub fn name_of(pid: libc::pid_t) -> String {
        let Some(info) = bsdinfo(pid) else { return String::new() };
        let bytes: Vec<u8> = info.pbi_comm.iter().map(|c| *c as u8).take_while(|b| *b != 0).collect();
        String::from_utf8_lossy(&bytes).into_owned()
    }

    /// The process's executable path.
    pub fn exe_of(pid: libc::pid_t) -> Option<PathBuf> {
        let mut buf = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
        let len = u32::try_from(buf.len()).ok()?;
        // SAFETY: `buf` holds `len` writable bytes; the call writes at most that.
        let n = unsafe { libc::proc_pidpath(pid, buf.as_mut_ptr().cast(), len) };
        let n = usize::try_from(n).ok().filter(|n| *n > 0)?;
        let path = buf[..n.min(buf.len())].split(|b| *b == 0).next().unwrap_or_default();
        (path.first() == Some(&b'/')).then(|| PathBuf::from(OsStr::from_bytes(path)))
    }

    /// The process's absolute command-line arguments, from
    /// `KERN_PROCARGS2`: an `int` argc, the executable path, NUL padding,
    /// then argc NUL-terminated arguments (then the environment, not read).
    /// Empty when the table cannot be read (another user's process).
    pub fn absolute_args(pid: libc::pid_t) -> Vec<PathBuf> {
        let mut mib = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid];
        let mut size: libc::size_t = 0;
        // SAFETY: a null buffer asks only for the size; `mib` is 3 ints.
        let rc = unsafe {
            libc::sysctl(mib.as_mut_ptr(), 3, std::ptr::null_mut(), &mut size, std::ptr::null_mut(), 0)
        };
        if rc != 0 || size == 0 {
            return Vec::new();
        }
        let mut buf = vec![0u8; size];
        // SAFETY: `buf` holds `size` writable bytes and `size` says so.
        let rc = unsafe {
            libc::sysctl(mib.as_mut_ptr(), 3, buf.as_mut_ptr().cast(), &mut size, std::ptr::null_mut(), 0)
        };
        if rc != 0 {
            return Vec::new();
        }
        parse_procargs(&buf[..size.min(buf.len())])
    }

    /// The absolute arguments in a `KERN_PROCARGS2` buffer. Bounded by the
    /// buffer and by argc; malformed input yields what was parsed so far.
    pub fn parse_procargs(buf: &[u8]) -> Vec<PathBuf> {
        let int = size_of::<libc::c_int>();
        let Some(head) = buf.get(..int) else { return Vec::new() };
        let argc = libc::c_int::from_ne_bytes(head.try_into().unwrap_or([0; 4]));
        let Ok(argc) = usize::try_from(argc) else { return Vec::new() };
        let mut rest = &buf[int..];
        // Skip the executable path, then the NUL padding after it.
        let Some(end) = rest.iter().position(|b| *b == 0) else { return Vec::new() };
        rest = &rest[end..];
        let start = rest.iter().position(|b| *b != 0).unwrap_or(rest.len());
        rest = &rest[start..];
        rest.split(|b| *b == 0)
            .take(argc)
            .filter(|a| a.first() == Some(&b'/'))
            .map(|a| PathBuf::from(OsStr::from_bytes(a)))
            .collect()
    }
}

/// Scan the process table. Unsupported here: liveness is unknown.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn live_process_paths() -> Option<Live> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn the_scan_sees_a_child_processs_working_directory() {
        let dir = tempfile::tempdir().unwrap();
        let mut child =
            std::process::Command::new("sleep").arg("30").current_dir(dir.path()).spawn().unwrap();
        let live = live_process_paths();
        let _ = child.kill();
        let _ = child.wait();
        let live = live.expect("the process table is readable on this platform");
        let want = dir.path().canonicalize().unwrap();
        assert!(
            live.paths.iter().any(|p| p == &want || p.as_path() == dir.path()),
            "{} not among {} scanned paths",
            want.display(),
            live.paths.len()
        );
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    #[test]
    fn without_a_process_table_liveness_is_unknown() {
        assert!(live_process_paths().is_none());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn procargs_are_parsed_within_bounds() {
        let mut buf = 3i32.to_ne_bytes().to_vec();
        buf.extend_from_slice(b"/bin/sleep\0\0\0\0sleep\0/tmp/work\0rel/path\0HOME=/x\0");
        assert_eq!(macos::parse_procargs(&buf), [PathBuf::from("/tmp/work")]);
        // argc larger than the buffer, a missing terminator, an empty buffer.
        let mut long = 99i32.to_ne_bytes().to_vec();
        long.extend_from_slice(b"/bin/x\0/a\0/b");
        assert_eq!(macos::parse_procargs(&long), [PathBuf::from("/a"), PathBuf::from("/b")]);
        assert!(macos::parse_procargs(&[1, 0]).is_empty());
        assert!(macos::parse_procargs(&5i32.to_ne_bytes()).is_empty());
    }
}
