//! PID namespace isolation for sandboxed processes.
//!
//! After the bridge fork and before seccomp, the wrapper calls
//! `unshare(CLONE_NEWPID)` + `fork()`. The parent stays in the host
//! PID namespace as a signal relay; the child becomes PID 1 in the
//! new namespace and continues to seccomp + exec.

use std::sync::atomic::{AtomicI32, Ordering};

use crate::wrapper::write_stderr;

/// Child PID stored for the signal handler.
static CHILD_PID: AtomicI32 = AtomicI32::new(-1);

/// Call `unshare(CLONE_NEWPID)` to configure a new PID namespace for
/// future children. The calling process stays in the host namespace.
pub fn unshare_pidns() -> std::io::Result<()> {
    let ret = unsafe { libc::unshare(libc::CLONE_NEWPID) };
    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Fork into a new PID namespace. The parent never returns — it
/// relays signals and exits with the child's status. The child
/// returns normally so the caller can continue with seccomp + exec.
///
/// `audit_fd` and `dns_audit_fd` are closed in the parent (so the
/// orchestrator's audit pipe reader sees EOF). `pid_report_fd` is
/// written with the child's host PID and closed.
pub fn fork_into_pidns(
    audit_fd: Option<i32>,
    dns_audit_fd: Option<i32>,
    pid_report_fd: Option<i32>,
) {
    // SAFETY: single-threaded, no async-signal-unsafe state.
    let child_pid = unsafe { libc::fork() };

    if child_pid < 0 {
        write_stderr(&format!(
            "arapuca: pidns fork: {}\n",
            std::io::Error::last_os_error()
        ));
        unsafe { libc::_exit(1) };
    }

    if child_pid == 0 {
        // Child (PID 1 in new namespace) — return to caller.
        // Close the PID report pipe write end (parent's responsibility).
        if let Some(fd) = pid_report_fd {
            unsafe { libc::close(fd) };
        }
        return;
    }

    // ── Parent: signal relay + waitpid ────────────────────────────
    // This path never returns.
    parent_relay(child_pid, audit_fd, dns_audit_fd, pid_report_fd);
}

/// Parent relay loop. Writes child PID to the report pipe, closes
/// audit FDs, installs signal handlers, and waits for the child.
fn parent_relay(
    child_pid: i32,
    audit_fd: Option<i32>,
    dns_audit_fd: Option<i32>,
    pid_report_fd: Option<i32>,
) -> ! {
    // 1. Hold a pidfd to prevent the kernel from recycling the
    // child's PID while the orchestrator reads the report pipe and
    // opens its own pidfd. Opened BEFORE publishing the PID so the
    // guard is in place before anyone can learn the PID. The raw FD
    // is intentionally leaked — it closes at _exit.
    let _pidfd_guard = unsafe { libc::syscall(libc::SYS_pidfd_open, child_pid, 0) };
    if _pidfd_guard < 0 {
        write_stderr("arapuca: pidns: pidfd_open for TOCTOU guard failed\n");
    }

    // 1b. Write child's host PID to PID report pipe.
    if let Some(fd) = pid_report_fd {
        let pid_bytes = child_pid.to_le_bytes();
        let _ = unsafe {
            libc::write(
                fd,
                pid_bytes.as_ptr().cast::<libc::c_void>(),
                pid_bytes.len(),
            )
        };
        unsafe { libc::close(fd) };
    }

    // 2. Close audit pipe write ends so orchestrator sees EOF.
    if let Some(fd) = audit_fd {
        unsafe { libc::close(fd) };
    }
    if let Some(fd) = dns_audit_fd {
        unsafe { libc::close(fd) };
    }

    // 3. Install signal handlers to forward to child.
    CHILD_PID.store(child_pid, Ordering::Release);
    install_signal_handlers();

    // 4. Reap child (and any adopted orphans in the PID namespace).
    loop {
        let mut wstatus: i32 = 0;
        let ret = unsafe { libc::waitpid(-1, &mut wstatus, 0) };
        if ret == child_pid {
            exit_with_child_status(wstatus);
        }
        if ret == -1 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            // ECHILD: no children remain (should not happen since
            // no SIGCHLD handler is installed to race with waitpid).
            unsafe { libc::_exit(125) };
        }
        // Reaped an orphan — continue waiting for our child.
    }
}

/// Install `sigaction`-based handlers for SIGTERM, SIGINT, SIGHUP,
/// and SIGQUIT that forward the signal to the child process.
fn install_signal_handlers() {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = forward_signal_handler as *const () as usize;
        sa.sa_flags = libc::SA_RESTART;
        libc::sigemptyset(&mut sa.sa_mask);

        libc::sigaction(libc::SIGTERM, &sa, std::ptr::null_mut());
        libc::sigaction(libc::SIGINT, &sa, std::ptr::null_mut());
        libc::sigaction(libc::SIGHUP, &sa, std::ptr::null_mut());
        libc::sigaction(libc::SIGQUIT, &sa, std::ptr::null_mut());
    }
}

/// Async-signal-safe handler: forward the signal to the child.
extern "C" fn forward_signal_handler(sig: libc::c_int) {
    let pid = CHILD_PID.load(Ordering::Acquire);
    if pid > 0 {
        unsafe { libc::kill(pid, sig) };
    }
}

/// Exit with the child's status, preserving signal-killed semantics.
///
/// For normal exits, uses `_exit(code)`. For signal deaths, re-raises
/// with default disposition so the parent's `waitpid` sees
/// `WIFSIGNALED` (not `WIFEXITED` with 128+sig).
fn exit_with_child_status(wstatus: i32) -> ! {
    if libc::WIFEXITED(wstatus) {
        unsafe { libc::_exit(libc::WEXITSTATUS(wstatus)) };
    }
    if libc::WIFSIGNALED(wstatus) {
        let sig = libc::WTERMSIG(wstatus);
        unsafe {
            libc::signal(sig, libc::SIG_DFL);
            libc::raise(sig);
            // Fallback if raise didn't kill us.
            libc::_exit(128 + sig);
        }
    }
    // Unexpected wait status.
    unsafe { libc::_exit(125) };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unshare_pidns_in_fork() {
        // Fork a child to avoid affecting the test process.
        let child_pid = unsafe { libc::fork() };
        assert!(child_pid >= 0, "fork failed");

        if child_pid == 0 {
            // Child: try unshare. It may fail without a user namespace
            // (EPERM), which is expected in unprivileged test envs.
            let result = unshare_pidns();
            let code = match result {
                Ok(()) => 0,
                Err(ref e) if e.raw_os_error() == Some(libc::EPERM) => 42,
                Err(_) => 1,
            };
            unsafe { libc::_exit(code) };
        }

        let mut wstatus: i32 = 0;
        unsafe { libc::waitpid(child_pid, &mut wstatus, 0) };
        assert!(libc::WIFEXITED(wstatus));
        let code = libc::WEXITSTATUS(wstatus);
        // 0 = success, 42 = EPERM (expected without user namespace).
        assert!(code == 0 || code == 42, "unexpected exit code: {code}");
    }

    #[test]
    fn exit_status_normal() {
        let child_pid = unsafe { libc::fork() };
        assert!(child_pid >= 0);
        if child_pid == 0 {
            // Grandchild exits with code 7.
            let gc = unsafe { libc::fork() };
            if gc == 0 {
                unsafe { libc::_exit(7) };
            }
            let mut ws: i32 = 0;
            unsafe { libc::waitpid(gc, &mut ws, 0) };
            exit_with_child_status(ws);
        }
        let mut wstatus: i32 = 0;
        unsafe { libc::waitpid(child_pid, &mut wstatus, 0) };
        assert!(libc::WIFEXITED(wstatus));
        assert_eq!(libc::WEXITSTATUS(wstatus), 7);
    }

    #[test]
    fn exit_status_signal() {
        let child_pid = unsafe { libc::fork() };
        assert!(child_pid >= 0);
        if child_pid == 0 {
            // Grandchild killed by SIGKILL.
            let gc = unsafe { libc::fork() };
            if gc == 0 {
                unsafe { libc::pause() };
                unreachable!();
            }
            unsafe { libc::kill(gc, libc::SIGKILL) };
            let mut ws: i32 = 0;
            unsafe { libc::waitpid(gc, &mut ws, 0) };
            exit_with_child_status(ws);
        }
        let mut wstatus: i32 = 0;
        unsafe { libc::waitpid(child_pid, &mut wstatus, 0) };
        assert!(libc::WIFSIGNALED(wstatus));
        assert_eq!(libc::WTERMSIG(wstatus), libc::SIGKILL);
    }
}
