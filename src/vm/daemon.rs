//! Double-fork daemonization for persistent VMs.
//!
//! The daemon process runs the VM via `krun_start_enter()` which
//! blocks forever. The double-fork ensures the daemon is not a
//! session leader and is properly orphaned from the CLI parent.
//!
//! `PR_SET_PDEATHSIG` is intentionally NOT set — the daemon must
//! outlive its parent by design. Compensating controls: lockfile
//! liveness, max-lifetime, `vm prune`.

use std::io;
use std::os::fd::RawFd;
use std::path::Path;

/// Outcome of daemonize: tells the caller which process it is.
pub enum DaemonResult {
    /// This is the original parent. Contains the daemon PID.
    Parent { daemon_pid: u32 },
    /// This is the daemon process. Run the VM.
    Daemon,
}

/// Double-fork daemonization with daemon PID communicated back
/// to the parent via a pipe.
///
/// The daemon process:
/// - Detaches from the terminal (setsid)
/// - Is not a session leader (second fork)
/// - Redirects stdout/stderr to `log_path`, stdin to /dev/null
/// - Applies `PR_SET_NO_NEW_PRIVS`
/// - Closes all FDs except those in `keep_fds`
pub fn daemonize(log_path: &Path, keep_fds: &[RawFd]) -> io::Result<DaemonResult> {
    let mut pipe_fds = [0i32; 2];
    // SAFETY: pipe2 with valid array and O_CLOEXEC.
    let ret = unsafe { libc::pipe2(pipe_fds.as_mut_ptr(), libc::O_CLOEXEC) };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }
    let pipe_read = pipe_fds[0];
    let pipe_write = pipe_fds[1];

    // First fork.
    // SAFETY: no threads running at this point (called before any
    // thread-spawning code).
    let pid1 = unsafe { libc::fork() };
    if pid1 < 0 {
        // SAFETY: closing valid pipe fds on error.
        unsafe {
            libc::close(pipe_read);
            libc::close(pipe_write);
        }
        return Err(io::Error::last_os_error());
    }
    if pid1 > 0 {
        // ── Original parent ───────────────────────────────────
        // SAFETY: close write end, read daemon PID from pipe.
        unsafe { libc::close(pipe_write) };

        let mut wstatus = 0i32;
        // SAFETY: pid1 is a valid child PID. Retry on EINTR.
        loop {
            let ret = unsafe { libc::waitpid(pid1, &mut wstatus, 0) };
            if ret >= 0 || io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
                break;
            }
        }

        let mut pid_buf = [0u8; 4];
        // SAFETY: pipe_read is valid, pid_buf is stack-local.
        let n = unsafe { libc::read(pipe_read, pid_buf.as_mut_ptr().cast(), pid_buf.len()) };
        unsafe { libc::close(pipe_read) };

        let daemon_pid = if n == 4 {
            u32::from_ne_bytes(pid_buf)
        } else {
            0
        };

        return Ok(DaemonResult::Parent { daemon_pid });
    }

    // ── Intermediate child ────────────────────────────────────
    // SAFETY: close read end (only the parent needs it).
    unsafe { libc::close(pipe_read) };

    // SAFETY: setsid is always safe in a child process.
    if unsafe { libc::setsid() } < 0 {
        unsafe { libc::_exit(1) };
    }

    // Second fork — the grandchild becomes the daemon.
    // SAFETY: safe in the child process.
    let pid2 = unsafe { libc::fork() };
    if pid2 < 0 {
        unsafe { libc::_exit(1) };
    }
    if pid2 > 0 {
        // Write daemon (grandchild) PID back to the parent.
        let pid_bytes = (pid2 as u32).to_ne_bytes();
        // SAFETY: pipe_write is valid, pid_bytes is stack-local.
        unsafe {
            libc::write(pipe_write, pid_bytes.as_ptr().cast(), pid_bytes.len());
            libc::close(pipe_write);
            libc::_exit(0);
        };
    }

    // ── Daemon (grandchild) ───────────────────────────────────
    // SAFETY: close the pipe (no longer needed in the daemon).
    unsafe { libc::close(pipe_write) };

    // Redirect stdin to /dev/null.
    // SAFETY: /dev/null is always available.
    let devnull = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY) };
    if devnull >= 0 {
        unsafe { libc::dup2(devnull, 0) };
        if devnull > 2 {
            unsafe { libc::close(devnull) };
        }
    }

    // Redirect stdout/stderr to the log file.
    let log_path_c = match std::ffi::CString::new(log_path.as_os_str().as_encoded_bytes()) {
        Ok(c) => c,
        Err(_) => unsafe { libc::_exit(1) },
    };
    // SAFETY: valid path, standard open flags.
    let log_fd = unsafe {
        libc::open(
            log_path_c.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC,
            0o600,
        )
    };
    if log_fd >= 0 {
        // SAFETY: valid fds for dup2.
        unsafe {
            libc::dup2(log_fd, 1);
            libc::dup2(log_fd, 2);
        }
        if log_fd > 2 {
            unsafe { libc::close(log_fd) };
        }
    }

    // SAFETY: prctl with simple integer args.
    unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };

    // Close all FDs except stdin/stdout/stderr and keep_fds.
    // SAFETY: close on valid fd range.
    unsafe {
        for fd in 3..1024 {
            if !keep_fds.contains(&fd) {
                libc::close(fd);
            }
        }
    }

    Ok(DaemonResult::Daemon)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn daemon_result_variants() {
        let parent = DaemonResult::Parent { daemon_pid: 42 };
        assert!(matches!(parent, DaemonResult::Parent { daemon_pid: 42 }));

        let daemon = DaemonResult::Daemon;
        assert!(matches!(daemon, DaemonResult::Daemon));
    }
}
