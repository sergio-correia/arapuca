//! Seccomp user notification (unotify) infrastructure.
//!
//! Provides syscall interception via `SECCOMP_RET_USER_NOTIF` for audit
//! purposes. A supervisor child process receives notifications when the
//! sandboxed process makes intercepted syscalls, reads arguments from
//! `/proc/<pid>/mem`, emits NDJSON audit events, and either allows the
//! syscall through (observation) or blocks it (network enforcement).
//!
//! The supervisor is forked BEFORE any seccomp filters are installed
//! (to avoid inheriting the USER_NOTIF filter, which would deadlock
//! on the supervisor's own `openat` calls). The listener FD is passed
//! to the supervisor via `SCM_RIGHTS` after filter installation.
//!
//! Requires kernel ≥ 5.5 (`SECCOMP_USER_NOTIF_FLAG_CONTINUE`).

use std::os::unix::io::RawFd;
use std::sync::OnceLock;

use crate::Error;

// ─── IOCTL constants ──────────────────────────────────────────────
//
// Not in libc 0.2.186. Computed from the kernel's _IOWR/_IOR macros:
//   _IOC(dir, type, nr, size) = (dir << 30) | (type << 8) | nr | (size << 16)
//   type = '!' = 0x21
//
// struct seccomp_notif:      size = 80 bytes (u64 + u32 + u32 + seccomp_data(64))
// struct seccomp_notif_resp: size = 24 bytes (u64 + i64 + i32 + u32)
// u64:                       size = 8 bytes

const IOC_WRITE: u32 = 1;
const IOC_READ: u32 = 2;
const IOC_TYPE: u32 = b'!' as u32;

const fn ioc(dir: u32, nr: u32, size: u32) -> libc::c_ulong {
    ((dir << 30) | (IOC_TYPE << 8) | nr | (size << 16)) as libc::c_ulong
}

/// `ioctl(fd, SECCOMP_IOCTL_NOTIF_RECV, &notif)` — receive a notification.
const SECCOMP_IOCTL_NOTIF_RECV: libc::c_ulong = ioc(IOC_WRITE | IOC_READ, 0, 80);

/// `ioctl(fd, SECCOMP_IOCTL_NOTIF_SEND, &resp)` — send a response.
const SECCOMP_IOCTL_NOTIF_SEND: libc::c_ulong = ioc(IOC_WRITE | IOC_READ, 1, 24);

/// `ioctl(fd, SECCOMP_IOCTL_NOTIF_ID_VALID, &id)` — check if notification is still valid.
/// Kernel 5.17+ uses `_IOWR`; kernels 5.0–5.16 use `_IOR`. The 5.17+
/// kernel accepts both, so we try the new one first and fall back.
const SECCOMP_IOCTL_NOTIF_ID_VALID_NEW: libc::c_ulong = ioc(IOC_WRITE | IOC_READ, 2, 8);
const SECCOMP_IOCTL_NOTIF_ID_VALID_OLD: libc::c_ulong = ioc(IOC_READ, 2, 8);

// ─── BPF construction ─────────────────────────────────────────────

const BPF_LD: u16 = 0x00;
const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_JMP: u16 = 0x05;
const BPF_JEQ: u16 = 0x10;
const BPF_K: u16 = 0x00;
const BPF_RET: u16 = 0x06;

#[cfg(target_arch = "x86_64")]
const AUDIT_ARCH: u32 = 0xc000003e; // AUDIT_ARCH_X86_64
#[cfg(target_arch = "aarch64")]
const AUDIT_ARCH: u32 = 0xc00000b7; // AUDIT_ARCH_AARCH64

const fn bpf_stmt(code: u16, k: u32) -> libc::sock_filter {
    libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

const fn bpf_jump(code: u16, k: u32, jt: u8, jf: u8) -> libc::sock_filter {
    libc::sock_filter { code, jt, jf, k }
}

/// Build a raw BPF program that returns `SECCOMP_RET_USER_NOTIF` for
/// the specified syscalls and `SECCOMP_RET_ALLOW` for all others.
///
/// The program structure:
/// 1. Load arch, verify it matches
/// 2. Load syscall number
/// 3. Linear scan: for each target syscall, compare and return USER_NOTIF
/// 4. Default: return ALLOW
pub fn build_unotify_bpf(syscalls: &[i64]) -> crate::Result<Vec<libc::sock_filter>> {
    if syscalls.len() > 127 {
        return Err(Error::Seccomp(format!(
            "unotify BPF: too many syscalls ({}, max 127)",
            syscalls.len()
        )));
    }
    let mut prog = Vec::with_capacity(4 + syscalls.len() * 2 + 1);

    // Load seccomp_data.arch (offset 4)
    prog.push(bpf_stmt(BPF_LD | BPF_W | BPF_ABS, 4));
    // Check arch matches — skip 1 instruction if match, else jump to ALLOW
    let allow_offset = (syscalls.len() * 2) as u8;
    prog.push(bpf_jump(
        BPF_JMP | BPF_JEQ | BPF_K,
        AUDIT_ARCH,
        0,
        allow_offset + 1,
    ));

    // Load seccomp_data.nr (offset 0)
    prog.push(bpf_stmt(BPF_LD | BPF_W | BPF_ABS, 0));

    // For each syscall: compare and return USER_NOTIF
    for (i, &nr) in syscalls.iter().enumerate() {
        let remaining = (syscalls.len() - i - 1) as u8;
        // If match: jump to the next instruction (USER_NOTIF return)
        // If no match: skip the USER_NOTIF return
        prog.push(bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, nr as u32, 0, 1));
        // Return USER_NOTIF
        prog.push(bpf_stmt(BPF_RET | BPF_K, libc::SECCOMP_RET_USER_NOTIF));
        let _ = remaining; // used for documentation clarity
    }

    // Default: ALLOW
    prog.push(bpf_stmt(BPF_RET | BPF_K, 0x7fff_0000)); // SECCOMP_RET_ALLOW

    Ok(prog)
}

/// Collect the syscall numbers to intercept based on the audit config.
pub fn target_syscalls(audit_file_access: bool, audit_network: bool) -> Vec<i64> {
    let mut syscalls = Vec::new();

    if audit_file_access {
        syscalls.push(libc::SYS_openat);
        // openat2 (kernel 5.6+, syscall 437 on both x86_64 and aarch64)
        syscalls.push(437);
        #[cfg(target_arch = "x86_64")]
        syscalls.push(libc::SYS_open);
        syscalls.push(libc::SYS_execve);
        syscalls.push(libc::SYS_execveat);
    }

    if audit_network {
        syscalls.push(libc::SYS_connect);
        syscalls.push(libc::SYS_sendto);
        syscalls.push(libc::SYS_sendmsg);
        syscalls.push(libc::SYS_sendmmsg);
    }

    syscalls
}

// ─── Filter installation ──────────────────────────────────────────

/// Install a USER_NOTIF BPF filter and return the listener FD.
///
/// Uses `seccomp(SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_NEW_LISTENER)`
/// directly (seccompiler doesn't support USER_NOTIF).
///
/// The caller must have `PR_SET_NO_NEW_PRIVS` set before calling this.
/// The returned FD has `FD_CLOEXEC` set immediately.
pub fn install_unotify_filter(bpf: &[libc::sock_filter]) -> crate::Result<RawFd> {
    let prog = libc::sock_fprog {
        len: bpf.len() as u16,
        filter: bpf.as_ptr() as *mut libc::sock_filter,
    };

    // SAFETY: seccomp syscall with valid prog pointer. The return value
    // is the listener FD on success, or -1 on error.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_SET_MODE_FILTER,
            libc::SECCOMP_FILTER_FLAG_NEW_LISTENER,
            &prog as *const libc::sock_fprog,
        )
    } as i32;

    if fd < 0 {
        return Err(Error::Seccomp(format!(
            "seccomp USER_NOTIF filter installation failed: {}",
            std::io::Error::last_os_error()
        )));
    }

    // Defense-in-depth: set CLOEXEC so the target process can't inherit
    // the listener FD if the explicit close is missed.
    // SAFETY: fd is a valid descriptor just returned by seccomp().
    unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };

    Ok(fd)
}

// ─── Ioctl wrappers ───────────────────────────────────────────────

/// Receive a seccomp notification from the listener FD.
///
/// Blocks until a notification is available.
/// Returns `ENOENT` when the filter is destroyed (target exited).
pub fn notif_recv(listener_fd: RawFd) -> std::io::Result<libc::seccomp_notif> {
    // SAFETY: zeroed seccomp_notif is valid for the ioctl.
    let mut notif: libc::seccomp_notif = unsafe { std::mem::zeroed() };
    let ret = unsafe { libc::ioctl(listener_fd, SECCOMP_IOCTL_NOTIF_RECV, &mut notif) };
    if ret < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(notif)
}

/// Send a response to a seccomp notification.
pub fn notif_send(listener_fd: RawFd, resp: &libc::seccomp_notif_resp) -> std::io::Result<()> {
    let ret = unsafe { libc::ioctl(listener_fd, SECCOMP_IOCTL_NOTIF_SEND, resp) };
    if ret < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Check if a notification ID is still valid (the target process hasn't
/// exited or been killed since the notification was received).
///
/// Tries the kernel 5.17+ ioctl encoding first, falls back to the
/// 5.0–5.16 encoding if the new one returns ENOTTY.
pub fn notif_id_valid(listener_fd: RawFd, id: u64) -> bool {
    let mut id_mut = id;
    let ret = unsafe { libc::ioctl(listener_fd, SECCOMP_IOCTL_NOTIF_ID_VALID_NEW, &mut id_mut) };
    if ret == 0 {
        return true;
    }
    if std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOTTY) {
        id_mut = id;
        let ret =
            unsafe { libc::ioctl(listener_fd, SECCOMP_IOCTL_NOTIF_ID_VALID_OLD, &mut id_mut) };
        return ret == 0;
    }
    false
}

// ─── SCM_RIGHTS helpers ───────────────────────────────────────────

/// Send a file descriptor over a Unix socket using SCM_RIGHTS.
pub fn send_fd(socket_fd: RawFd, fd_to_send: RawFd) -> std::io::Result<()> {
    let iov = libc::iovec {
        iov_base: b"\x00" as *const u8 as *mut libc::c_void,
        iov_len: 1,
    };

    // cmsg buffer: header + one i32 FD
    let cmsg_space = unsafe { libc::CMSG_SPACE(std::mem::size_of::<i32>() as u32) } as usize;
    let mut cmsg_buf = vec![0u8; cmsg_space];

    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &iov as *const libc::iovec as *mut libc::iovec;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr().cast();
    msg.msg_controllen = cmsg_space as _;

    // SAFETY: CMSG_FIRSTHDR on a valid msghdr with allocated control buffer.
    let cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
    if cmsg.is_null() {
        return Err(std::io::Error::from_raw_os_error(libc::EINVAL));
    }
    unsafe {
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<i32>() as u32) as usize;
        std::ptr::copy_nonoverlapping(
            &fd_to_send as *const i32 as *const u8,
            libc::CMSG_DATA(cmsg),
            std::mem::size_of::<i32>(),
        );
    }

    let ret = unsafe { libc::sendmsg(socket_fd, &msg, 0) };
    if ret < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Receive a file descriptor from a Unix socket using SCM_RIGHTS.
///
/// Blocks until the FD is received.
pub fn recv_fd(socket_fd: RawFd) -> std::io::Result<RawFd> {
    let mut byte = [0u8; 1];
    let mut iov = libc::iovec {
        iov_base: byte.as_mut_ptr().cast(),
        iov_len: 1,
    };

    let cmsg_space = unsafe { libc::CMSG_SPACE(std::mem::size_of::<i32>() as u32) } as usize;
    let mut cmsg_buf = vec![0u8; cmsg_space];

    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr().cast();
    msg.msg_controllen = cmsg_space as _;

    let ret = unsafe { libc::recvmsg(socket_fd, &mut msg, 0) };
    if ret < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if ret == 0 {
        return Err(std::io::Error::from_raw_os_error(libc::ECONNRESET));
    }

    let cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
    if cmsg.is_null() {
        return Err(std::io::Error::from_raw_os_error(libc::ENODATA));
    }
    unsafe {
        if (*cmsg).cmsg_level != libc::SOL_SOCKET || (*cmsg).cmsg_type != libc::SCM_RIGHTS {
            return Err(std::io::Error::from_raw_os_error(libc::ENODATA));
        }
        let mut fd: i32 = -1;
        std::ptr::copy_nonoverlapping(
            libc::CMSG_DATA(cmsg),
            &mut fd as *mut i32 as *mut u8,
            std::mem::size_of::<i32>(),
        );
        if fd < 0 {
            return Err(std::io::Error::from_raw_os_error(libc::EBADF));
        }
        // Set CLOEXEC on the received FD.
        libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC);
        Ok(fd)
    }
}

// ─── Availability probe ───────────────────────────────────────────

static AVAILABLE: OnceLock<bool> = OnceLock::new();

/// Check if the running kernel supports seccomp user notification with
/// `SECCOMP_USER_NOTIF_FLAG_CONTINUE` (kernel ≥ 5.5).
///
/// Also probes cross-process `/proc/<pid>/mem` readability to detect
/// Yama `ptrace_scope` restrictions. Without a user namespace (which
/// grants `CAP_SYS_PTRACE`), `ptrace_scope=1` blocks the supervisor
/// from reading the target's memory.
///
/// Result is cached for the lifetime of the process.
pub fn unotify_available() -> bool {
    *AVAILABLE.get_or_init(probe_unotify_support)
}

fn probe_unotify_support() -> bool {
    // Phase 1: Check that we can read a sibling process's /proc/<pid>/mem.
    // This catches Yama ptrace_scope=1 without a user namespace.
    if !probe_proc_mem_access() {
        log::info!("unotify: /proc/<pid>/mem access blocked (Yama ptrace_scope?)");
        return false;
    }

    // Phase 2: Check that seccomp USER_NOTIF + CONTINUE works.
    probe_seccomp_unotify()
}

fn probe_proc_mem_access() -> bool {
    // The supervisor (a child process) reads a sibling's /proc/<pid>/mem.
    // Under Yama ptrace_scope=1, parent→child always succeeds but
    // child→parent (or sibling→sibling) is blocked. We must test the
    // actual relationship: have a child try to read the parent's mem.
    let parent_pid = unsafe { libc::getpid() };
    // SAFETY: single-threaded at probe time (called during sandbox init).
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return false;
    }
    if pid == 0 {
        // Child: try to open the parent's /proc/<pid>/mem.
        let mem_path = format!("/proc/{parent_pid}/mem");
        let ok = std::fs::File::open(&mem_path).is_ok();
        unsafe { libc::_exit(if ok { 0 } else { 1 }) };
    }

    // Parent: wait for child and check exit code.
    let mut status: libc::c_int = 0;
    let ret = unsafe { libc::waitpid(pid, &mut status, 0) };
    ret > 0 && libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0
}

fn probe_seccomp_unotify() -> bool {
    // We need to test in a clone child because installing a USER_NOTIF
    // filter on the current process would affect it permanently.
    // Build the BPF program before fork to avoid heap allocation in the
    // child (which is unsafe in multi-threaded processes).
    let bpf = match build_unotify_bpf(&[libc::SYS_getpid]) {
        Ok(b) => b,
        Err(_) => return false,
    };

    // SAFETY: fork with pre-allocated BPF program. The child only uses
    // the inherited COW copy — no heap allocation needed.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return false;
    }
    if pid == 0 {
        // Child: attempt to install a USER_NOTIF filter.
        // PR_SET_NO_NEW_PRIVS is required.
        unsafe {
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1i64, 0i64, 0i64, 0i64) != 0 {
                libc::_exit(1);
            }
        }

        match install_unotify_filter(&bpf) {
            Ok(fd) => {
                unsafe { libc::close(fd) };
                // If we got here, USER_NOTIF is supported.
                // We can't easily test CONTINUE without a second thread,
                // but the fd creation confirms kernel >= 5.0 and the
                // SECCOMP_FILTER_FLAG_NEW_LISTENER flag. CONTINUE was
                // added in 5.5 — checking that the listener FD was
                // created is a strong signal (5.0 is very rare without 5.5).
                unsafe { libc::_exit(0) };
            }
            Err(_) => unsafe { libc::_exit(1) },
        }
    }

    // Parent: wait for child and check exit code.
    let mut status: libc::c_int = 0;
    let ret = unsafe { libc::waitpid(pid, &mut status, 0) };
    if ret <= 0 {
        return false;
    }
    libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0
}

// ─── Configuration ────────────────────────────────────────────────

/// Configuration for the unotify supervisor.
pub struct UnotifyConfig {
    /// Intercept openat/openat2/open/execve/execveat.
    pub audit_file_access: bool,
    /// Intercept connect/sendto/sendmsg/sendmmsg.
    pub audit_network: bool,
    /// Bridge port to allow through (127.0.0.1:<port>).
    pub bridge_port: Option<u16>,
}

impl UnotifyConfig {
    pub fn any_enabled(&self) -> bool {
        self.audit_file_access || self.audit_network
    }
}

/// FDs returned by `fork_unotify_supervisor` for the caller to use.
pub struct UnotifyFds {
    /// Parent end of the socketpair for sending the listener FD.
    pub socketpair_parent: RawFd,
    /// Read end of the readiness pipe.
    pub readiness_read: RawFd,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bpf_program_has_correct_structure() {
        let syscalls = vec![libc::SYS_openat, libc::SYS_execve];
        let bpf = build_unotify_bpf(&syscalls).unwrap();
        // 3 header (load arch, arch check, load nr) +
        // 2 syscalls × 2 (compare + return) + 1 default allow = 8
        assert_eq!(bpf.len(), 8);
    }

    #[test]
    fn bpf_program_empty_syscalls() {
        let bpf = build_unotify_bpf(&[]).unwrap();
        // load arch + arch check + load nr + default allow = 4
        assert_eq!(bpf.len(), 4);
    }

    #[test]
    fn bpf_first_instruction_loads_arch() {
        let bpf = build_unotify_bpf(&[libc::SYS_openat]).unwrap();
        assert_eq!(bpf[0].code, BPF_LD | BPF_W | BPF_ABS);
        assert_eq!(bpf[0].k, 4); // offset of arch in seccomp_data
    }

    #[test]
    fn bpf_last_instruction_is_allow() {
        let bpf = build_unotify_bpf(&[libc::SYS_openat]).unwrap();
        let last = bpf.last().unwrap();
        assert_eq!(last.code, BPF_RET | BPF_K);
        assert_eq!(last.k, 0x7fff_0000); // SECCOMP_RET_ALLOW
    }

    #[test]
    fn bpf_contains_user_notif_return() {
        let bpf = build_unotify_bpf(&[libc::SYS_openat]).unwrap();
        let has_notif = bpf
            .iter()
            .any(|i| i.code == BPF_RET | BPF_K && i.k == libc::SECCOMP_RET_USER_NOTIF);
        assert!(
            has_notif,
            "BPF should contain SECCOMP_RET_USER_NOTIF return"
        );
    }

    #[test]
    fn target_syscalls_file_access() {
        let syscalls = target_syscalls(true, false);
        assert!(syscalls.contains(&libc::SYS_openat));
        assert!(syscalls.contains(&437)); // openat2
        assert!(syscalls.contains(&libc::SYS_execve));
        assert!(syscalls.contains(&libc::SYS_execveat));
        assert!(!syscalls.contains(&libc::SYS_connect));
    }

    #[test]
    fn target_syscalls_network() {
        let syscalls = target_syscalls(false, true);
        assert!(syscalls.contains(&libc::SYS_connect));
        assert!(syscalls.contains(&libc::SYS_sendto));
        assert!(syscalls.contains(&libc::SYS_sendmsg));
        assert!(syscalls.contains(&libc::SYS_sendmmsg));
        assert!(!syscalls.contains(&libc::SYS_openat));
    }

    #[test]
    fn target_syscalls_both() {
        let syscalls = target_syscalls(true, true);
        assert!(syscalls.contains(&libc::SYS_openat));
        assert!(syscalls.contains(&libc::SYS_connect));
    }

    #[test]
    fn target_syscalls_neither() {
        let syscalls = target_syscalls(false, false);
        assert!(syscalls.is_empty());
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn target_syscalls_includes_open_on_x86_64() {
        let syscalls = target_syscalls(true, false);
        assert!(syscalls.contains(&libc::SYS_open));
    }

    #[test]
    fn ioctl_constants_are_nonzero() {
        assert_ne!(SECCOMP_IOCTL_NOTIF_RECV, 0);
        assert_ne!(SECCOMP_IOCTL_NOTIF_SEND, 0);
        assert_ne!(SECCOMP_IOCTL_NOTIF_ID_VALID_NEW, 0);
        assert_ne!(SECCOMP_IOCTL_NOTIF_ID_VALID_OLD, 0);
    }

    #[test]
    fn ioctl_constants_are_distinct() {
        assert_ne!(SECCOMP_IOCTL_NOTIF_RECV, SECCOMP_IOCTL_NOTIF_SEND);
        assert_ne!(SECCOMP_IOCTL_NOTIF_RECV, SECCOMP_IOCTL_NOTIF_ID_VALID_NEW);
        assert_ne!(SECCOMP_IOCTL_NOTIF_SEND, SECCOMP_IOCTL_NOTIF_ID_VALID_NEW);
    }

    #[test]
    fn ioctl_id_valid_old_differs_from_new() {
        assert_ne!(
            SECCOMP_IOCTL_NOTIF_ID_VALID_OLD,
            SECCOMP_IOCTL_NOTIF_ID_VALID_NEW
        );
    }

    #[test]
    fn bpf_rejects_too_many_syscalls() {
        let many: Vec<i64> = (0..128).collect();
        assert!(build_unotify_bpf(&many).is_err());
    }

    #[test]
    fn bpf_accepts_max_syscalls() {
        let max: Vec<i64> = (0..127).collect();
        assert!(build_unotify_bpf(&max).is_ok());
    }

    #[test]
    fn scm_rights_round_trip() {
        // Create a socketpair, send a pipe FD through it, verify receipt.
        let mut sv = [0i32; 2];
        let ret = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sv.as_mut_ptr()) };
        assert_eq!(ret, 0, "socketpair failed");

        // Create a pipe to use as the FD to send.
        let mut pipe_fds = [0i32; 2];
        let ret = unsafe { libc::pipe(pipe_fds.as_mut_ptr()) };
        assert_eq!(ret, 0, "pipe failed");

        // Send pipe read end through the socketpair.
        send_fd(sv[0], pipe_fds[0]).expect("send_fd failed");

        // Receive it on the other end.
        let received_fd = recv_fd(sv[1]).expect("recv_fd failed");
        assert!(received_fd >= 0, "received FD should be valid");
        assert_ne!(
            received_fd, pipe_fds[0],
            "received FD should be a new descriptor"
        );

        // Verify it's actually the same pipe: write on write-end, read on received.
        let msg = b"hello";
        let written = unsafe { libc::write(pipe_fds[1], msg.as_ptr().cast(), msg.len()) };
        assert_eq!(written, 5);

        let mut buf = [0u8; 5];
        let read = unsafe { libc::read(received_fd, buf.as_mut_ptr().cast(), buf.len()) };
        assert_eq!(read, 5);
        assert_eq!(&buf, b"hello");

        // Cleanup.
        unsafe {
            libc::close(sv[0]);
            libc::close(sv[1]);
            libc::close(pipe_fds[0]);
            libc::close(pipe_fds[1]);
            libc::close(received_fd);
        }
    }

    #[test]
    fn unotify_config_any_enabled() {
        assert!(
            !UnotifyConfig {
                audit_file_access: false,
                audit_network: false,
                bridge_port: None,
            }
            .any_enabled()
        );
        assert!(
            UnotifyConfig {
                audit_file_access: true,
                audit_network: false,
                bridge_port: None,
            }
            .any_enabled()
        );
        assert!(
            UnotifyConfig {
                audit_file_access: false,
                audit_network: true,
                bridge_port: Some(8080),
            }
            .any_enabled()
        );
    }

    #[test]
    fn probe_function_returns_result() {
        // Just verify the probe doesn't panic or hang.
        // The actual result depends on kernel version.
        let _ = unotify_available();
    }
}
