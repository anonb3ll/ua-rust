//! Platform process inspection for the executor: a process's identity
//! (state, process group, start time), liveness probes for a pid and a
//! process group, and the group kill.
//!
//! Depends only on `std` and `libc`, so the macOS code can be type-checked
//! for an Apple target in isolation.
//!
//! - Linux reads `/proc/<pid>/stat`; the start time is in clock ticks after
//!   boot.
//! - macOS asks `proc_pidinfo(PROC_PIDTBSDINFO)`; the start time is in
//!   microseconds since the epoch.
//! - Elsewhere no identity is available, so nothing is ever proven.

/// What the platform reports about a process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcIdentity {
    /// Process state letter (`R`, `S`, `T`, `Z`, ...).
    pub state: char,
    /// Process group id.
    pub pgrp: i64,
    /// Start time, in a platform-specific unit; only ever compared with a
    /// value read on the same host.
    pub start_time: i64,
}

impl ProcIdentity {
    /// Whether the process has exited (a zombie not yet reaped).
    pub fn exited(&self) -> bool {
        matches!(self.state, 'Z' | 'X' | 'x')
    }
}

/// Read a process's identity. `None` when the process does not exist or
/// cannot be inspected, and always on platforms without support.
#[cfg(target_os = "linux")]
pub fn proc_identity(pid: i64) -> Option<ProcIdentity> {
    if pid <= 0 {
        return None;
    }
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // `comm` (field 2) may hold spaces and parentheses; fields resume after
    // the last `)`, starting with field 3 (state).
    let rest = stat.get(stat.rfind(')')? + 1..)?;
    let f: Vec<&str> = rest.split_whitespace().collect();
    Some(ProcIdentity {
        state: f.first()?.chars().next()?,
        // Field 5.
        pgrp: f.get(2)?.parse().ok()?,
        // Field 22.
        start_time: f.get(19)?.parse().ok()?,
    })
}

/// Read a process's identity. `None` when the process does not exist or
/// cannot be inspected.
#[cfg(target_os = "macos")]
pub fn proc_identity(pid: i64) -> Option<ProcIdentity> {
    let pid = libc::c_int::try_from(pid).ok().filter(|p| *p > 0)?;
    let size = libc::c_int::try_from(std::mem::size_of::<libc::proc_bsdinfo>()).ok()?;
    let mut info = std::mem::MaybeUninit::<libc::proc_bsdinfo>::zeroed();
    // SAFETY: the buffer is a zero-initialized `proc_bsdinfo` and `size` is
    // its exact size; the call writes at most `size` bytes into it.
    let n = unsafe { libc::proc_pidinfo(pid, libc::PROC_PIDTBSDINFO, 0, info.as_mut_ptr().cast(), size) };
    if n != size {
        return None;
    }
    // SAFETY: the struct is plain old data, was zero-initialized, and the
    // call filled all of it (`n == size`).
    let info = unsafe { info.assume_init() };
    let start = i64::try_from(info.pbi_start_tvsec)
        .ok()?
        .checked_mul(1_000_000)?
        .checked_add(i64::try_from(info.pbi_start_tvusec).ok()?)?;
    let state = match info.pbi_status {
        libc::SIDL => 'I',
        libc::SRUN => 'R',
        libc::SSTOP => 'T',
        libc::SZOMB => 'Z',
        _ => 'S',
    };
    Some(ProcIdentity { state, pgrp: i64::from(info.pbi_pgid), start_time: start })
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn proc_identity(_pid: i64) -> Option<ProcIdentity> {
    None
}

/// Whether `pid` names a live process (any owner; a zombie counts).
#[cfg(unix)]
pub fn pid_alive(pid: i64) -> bool {
    let Ok(p) = libc::pid_t::try_from(pid) else { return false };
    if p <= 0 {
        return false;
    }
    // SAFETY: signal 0 performs only the existence and permission check.
    let rc = unsafe { libc::kill(p, 0) };
    rc == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

#[cfg(not(unix))]
pub fn pid_alive(_pid: i64) -> bool {
    true
}

/// Whether the process group `pgid` has any member left (a zombie counts).
/// Group ids 0 and 1 never count: they are not a child's group.
#[cfg(unix)]
pub fn group_alive(pgid: i64) -> bool {
    let Ok(g) = libc::pid_t::try_from(pgid) else { return false };
    if g <= 1 {
        return false;
    }
    // SAFETY: signal 0 performs only the existence and permission check.
    let rc = unsafe { libc::killpg(g, 0) };
    rc == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

#[cfg(not(unix))]
pub fn group_alive(_pgid: i64) -> bool {
    true
}

/// SIGKILL the process group `pgid` (ids 0 and 1 are ignored).
#[cfg(unix)]
pub fn kill_group(pgid: Option<u32>) {
    if let Some(g) = pgid.and_then(|p| libc::pid_t::try_from(p).ok())
        && g > 1
    {
        // SAFETY: killpg only sends a signal. Callers pass the group of a
        // child this hub spawned as group leader.
        unsafe {
            libc::killpg(g, libc::SIGKILL);
        }
    }
}

#[cfg(not(unix))]
pub fn kill_group(_pgid: Option<u32>) {}

/// SIGTERM the process group `pgid` (ids 0 and 1 are ignored): ask it to
/// stop before [`kill_group`].
#[cfg(unix)]
pub fn term_group(pgid: Option<u32>) {
    if let Some(g) = pgid.and_then(|p| libc::pid_t::try_from(p).ok())
        && g > 1
    {
        // SAFETY: killpg only sends a signal. Callers pass the group of a
        // child this hub spawned as group leader.
        unsafe {
            libc::killpg(g, libc::SIGTERM);
        }
    }
}

#[cfg(not(unix))]
pub fn term_group(_pgid: Option<u32>) {}
