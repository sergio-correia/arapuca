//! Shared FD helpers for platform sandbox implementations.
//!
//! Provides extra_fds validation and the two-pass FD remapping used
//! inside pre_exec closures.

use std::os::unix::io::RawFd;

use crate::{Config, Error};

// Upper bound on caller-supplied extra FDs. The remap uses a Vec
// (via ManuallyDrop) so any count works; 16 is a practical limit
// that bounds pre_exec syscall overhead (~96 calls at n=16).
const MAX_EXTRA_FDS: usize = 16;

pub(super) fn validate_extra_fds(fds: &[RawFd], cfg: &Config) -> crate::Result<()> {
    if fds.len() > MAX_EXTRA_FDS {
        return Err(Error::Validation(format!(
            "extra_fds: too many FDs ({}, max {MAX_EXTRA_FDS})",
            fds.len()
        )));
    }
    for (i, &fd) in fds.iter().enumerate() {
        if fd < 0 {
            return Err(Error::Validation(format!(
                "extra_fds[{i}]: negative FD {fd}"
            )));
        }
        if fd <= 2 {
            return Err(Error::Validation(format!(
                "extra_fds[{i}]: FD {fd} is stdin/stdout/stderr \
                 (use cfg.stdin/stdout/stderr instead)"
            )));
        }
        if fds[..i].contains(&fd) {
            return Err(Error::Validation(format!(
                "extra_fds[{i}]: duplicate FD {fd}"
            )));
        }
        let stdio_fds = [cfg.stdin, cfg.stdout, cfg.stderr];
        if stdio_fds.contains(&Some(fd)) {
            return Err(Error::Validation(format!(
                "extra_fds[{i}]: FD {fd} overlaps with stdio config"
            )));
        }
    }
    Ok(())
}

/// Remap extra FDs to deterministic positions (3, 4, ...).
///
/// Must only be called inside a pre_exec closure (between fork and
/// exec). All operations are async-signal-safe. The ManuallyDrop
/// wrapper on the caller's Vec prevents free() from running in the
/// child process.
///
/// Uses a two-pass approach to avoid FD collisions when source FDs
/// overlap with the target range [3..3+N):
/// - Phase 1: evacuate sources in the target range to high FDs.
/// - Phase 2: dup2 to final positions and clear CLOEXEC.
pub(super) unsafe fn remap_fds(
    fds: &mut std::mem::ManuallyDrop<Vec<RawFd>>,
) -> std::io::Result<()> {
    let fds = fds.as_mut_slice();
    let base = 3i32;
    let ceiling = base + fds.len() as i32;

    // Phase 1: evacuate source FDs in [base..ceiling) to above
    // the target range.
    for slot in fds.iter_mut() {
        if *slot >= base && *slot < ceiling {
            // SAFETY: F_DUPFD_CLOEXEC returns a new FD >= ceiling
            // that we own, with CLOEXEC set atomically.
            let high = unsafe { libc::fcntl(*slot, libc::F_DUPFD_CLOEXEC, ceiling) };
            if high == -1 {
                return Err(std::io::Error::last_os_error());
            }
            // Non-fatal: original has CLOEXEC, kernel cleans up at exec.
            unsafe { libc::close(*slot) };
            *slot = high;
        }
    }

    // Phase 2: place into final positions.
    for (i, &fd) in fds.iter().enumerate() {
        let target = base + i as i32;
        if fd != target {
            // SAFETY: dup2 atomically copies fd to target.
            if unsafe { libc::dup2(fd, target) } == -1 {
                return Err(std::io::Error::last_os_error());
            }
            // Non-fatal: source has CLOEXEC, kernel cleans up at exec.
            unsafe { libc::close(fd) };
        }
        // Clear CLOEXEC so the FD survives exec.
        // SAFETY: fcntl F_GETFD/F_SETFD are simple flag operations.
        let flags = unsafe { libc::fcntl(target, libc::F_GETFD) };
        if flags == -1 {
            return Err(std::io::Error::last_os_error());
        }
        if unsafe { libc::fcntl(target, libc::F_SETFD, flags & !libc::FD_CLOEXEC) } == -1 {
            return Err(std::io::Error::last_os_error());
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn test_config() -> Config {
        Config {
            profile: crate::Profile::default(),
            socket_dir: PathBuf::from("/tmp"),
            task_id: "test".into(),
            phase: String::new(),
            work_dir: None,
            stdin: None,
            stdout: None,
            stderr: None,
            extra_fds: vec![],
            tty: false,
            network_proxy_socket: None,
            #[cfg(target_os = "linux")]
            allowed_hosts: Vec::new(),
            env: vec![],
            audit_sink: None,
            audit_verbosity: crate::audit::AuditVerbosity::default(),
            audit_principal: None,
            audit_correlation_id: None,
        }
    }

    #[test]
    fn validate_empty() {
        assert!(validate_extra_fds(&[], &test_config()).is_ok());
    }

    #[test]
    fn validate_valid_fds() {
        assert!(validate_extra_fds(&[5, 10, 20], &test_config()).is_ok());
    }

    #[test]
    fn validate_fd_three_ok() {
        assert!(validate_extra_fds(&[3], &test_config()).is_ok());
    }

    #[test]
    fn validate_negative_fd() {
        let err = validate_extra_fds(&[-1], &test_config()).unwrap_err();
        assert!(err.to_string().contains("negative FD"));
    }

    #[test]
    fn validate_fd_zero() {
        let err = validate_extra_fds(&[0], &test_config()).unwrap_err();
        assert!(err.to_string().contains("stdin/stdout/stderr"));
    }

    #[test]
    fn validate_fd_one() {
        let err = validate_extra_fds(&[1], &test_config()).unwrap_err();
        assert!(err.to_string().contains("stdin/stdout/stderr"));
    }

    #[test]
    fn validate_fd_two() {
        let err = validate_extra_fds(&[2], &test_config()).unwrap_err();
        assert!(err.to_string().contains("stdin/stdout/stderr"));
    }

    #[test]
    fn validate_duplicate() {
        let err = validate_extra_fds(&[5, 5], &test_config()).unwrap_err();
        assert!(err.to_string().contains("duplicate FD 5"));
    }

    #[test]
    fn validate_stdio_overlap() {
        let mut cfg = test_config();
        cfg.stdin = Some(7);
        let err = validate_extra_fds(&[7], &cfg).unwrap_err();
        assert!(err.to_string().contains("overlaps with stdio"));
    }

    #[test]
    fn validate_too_many() {
        let fds: Vec<RawFd> = (3..3 + MAX_EXTRA_FDS as i32 + 1).collect();
        let err = validate_extra_fds(&fds, &test_config()).unwrap_err();
        assert!(err.to_string().contains("too many FDs"));
    }

    #[test]
    fn validate_exactly_max() {
        let fds: Vec<RawFd> = (3..3 + MAX_EXTRA_FDS as i32).collect();
        assert!(validate_extra_fds(&fds, &test_config()).is_ok());
    }

    // ── remap_fds tests ───────────────────────────────────────────
    //
    // remap_fds overwrites FDs 3, 4, ... in the calling process, so
    // these tests fork a child to isolate the FD table. The child
    // calls remap_fds, reads from the remapped targets, and reports
    // success via _exit(42) or failure via _exit(1).

    fn make_pipe() -> (RawFd, RawFd) {
        let mut fds = [0i32; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        (fds[0], fds[1])
    }

    fn run_remap_test(test_fn: fn()) -> (bool, i32) {
        // SAFETY: fork is safe in single-threaded test context.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed");
        if pid == 0 {
            test_fn();
            unsafe { libc::_exit(0) };
        }
        let mut status: libc::c_int = 0;
        assert!(unsafe { libc::waitpid(pid, &mut status, 0) } > 0);
        if libc::WIFEXITED(status) {
            (true, libc::WEXITSTATUS(status))
        } else {
            (false, libc::WTERMSIG(status))
        }
    }

    #[test]
    fn remap_high_fds() {
        let (exited, code) = run_remap_test(|| {
            let (r1, w1) = make_pipe();
            let (r2, w2) = make_pipe();
            unsafe { libc::write(w1, b"AA".as_ptr().cast(), 2) };
            unsafe { libc::write(w2, b"BB".as_ptr().cast(), 2) };
            unsafe { libc::close(w1) };
            unsafe { libc::close(w2) };

            let mut fds = std::mem::ManuallyDrop::new(vec![r1, r2]);
            if unsafe { remap_fds(&mut fds) }.is_err() {
                unsafe { libc::_exit(1) };
            }

            let mut buf = [0u8; 2];
            if unsafe { libc::read(3, buf.as_mut_ptr().cast(), 2) } != 2 || &buf != b"AA" {
                unsafe { libc::_exit(1) };
            }
            if unsafe { libc::read(4, buf.as_mut_ptr().cast(), 2) } != 2 || &buf != b"BB" {
                unsafe { libc::_exit(1) };
            }
            unsafe { libc::_exit(42) };
        });
        assert!(exited);
        assert_eq!(code, 42, "remap of high FDs failed");
    }

    #[test]
    fn remap_source_in_target_range() {
        let (exited, code) = run_remap_test(|| {
            // Close FDs 3-6 in the child so pipe() allocates them.
            for fd in 3..=6 {
                unsafe { libc::close(fd) };
            }
            // pipe() returns the lowest available FDs: (3,4) and (5,6).
            let (r1, w1) = make_pipe(); // r1=3, w1=4
            let (r2, w2) = make_pipe(); // r2=5, w2=6
            unsafe { libc::write(w1, b"XX".as_ptr().cast(), 2) };
            unsafe { libc::write(w2, b"YY".as_ptr().cast(), 2) };
            unsafe { libc::close(w1) };
            unsafe { libc::close(w2) };

            // r1=3, r2=5. For a 2-element remap, target range is [3,5).
            // FD 3 is in range and must be evacuated. FD 5 is not.
            let mut fds = std::mem::ManuallyDrop::new(vec![r1, r2]);
            if unsafe { remap_fds(&mut fds) }.is_err() {
                unsafe { libc::_exit(1) };
            }

            let mut buf = [0u8; 2];
            if unsafe { libc::read(3, buf.as_mut_ptr().cast(), 2) } != 2 || &buf != b"XX" {
                unsafe { libc::_exit(2) };
            }
            if unsafe { libc::read(4, buf.as_mut_ptr().cast(), 2) } != 2 || &buf != b"YY" {
                unsafe { libc::_exit(3) };
            }
            unsafe { libc::_exit(42) };
        });
        assert!(exited);
        assert_eq!(code, 42, "remap with source in target range failed");
    }

    #[test]
    fn remap_swap() {
        let (exited, code) = run_remap_test(|| {
            // Close FDs 3-6 so pipe() allocates them predictably.
            for fd in 3..=6 {
                unsafe { libc::close(fd) };
            }
            let (r1, w1) = make_pipe(); // r1=3, w1=4
            let (r2, w2) = make_pipe(); // r2=5, w2=6
            unsafe { libc::write(w1, b"11".as_ptr().cast(), 2) };
            unsafe { libc::write(w2, b"22".as_ptr().cast(), 2) };
            unsafe { libc::close(w1) };
            unsafe { libc::close(w2) };

            // Swap: place r2 (data "22") at FD 3, r1 (data "11") at FD 4.
            // For a 2-element remap, fds[0]->target 3, fds[1]->target 4.
            // r2=5, r1=3. fds=[5, 3]: target 3 gets r2's data ("22"),
            // target 4 gets r1's data ("11"). FD 3 is in range [3,5)
            // and must be evacuated.
            let mut fds = std::mem::ManuallyDrop::new(vec![r2, r1]);
            if unsafe { remap_fds(&mut fds) }.is_err() {
                unsafe { libc::_exit(1) };
            }

            let mut buf = [0u8; 2];
            if unsafe { libc::read(3, buf.as_mut_ptr().cast(), 2) } != 2 || &buf != b"22" {
                unsafe { libc::_exit(2) };
            }
            if unsafe { libc::read(4, buf.as_mut_ptr().cast(), 2) } != 2 || &buf != b"11" {
                unsafe { libc::_exit(3) };
            }
            unsafe { libc::_exit(42) };
        });
        assert!(exited);
        assert_eq!(code, 42, "remap swap failed");
    }

    #[test]
    fn remap_single_fd() {
        let (exited, code) = run_remap_test(|| {
            let (r, w) = make_pipe();
            unsafe { libc::write(w, b"OK".as_ptr().cast(), 2) };
            unsafe { libc::close(w) };

            let mut fds = std::mem::ManuallyDrop::new(vec![r]);
            if unsafe { remap_fds(&mut fds) }.is_err() {
                unsafe { libc::_exit(1) };
            }

            let mut buf = [0u8; 2];
            if unsafe { libc::read(3, buf.as_mut_ptr().cast(), 2) } != 2 || &buf != b"OK" {
                unsafe { libc::_exit(1) };
            }
            unsafe { libc::_exit(42) };
        });
        assert!(exited);
        assert_eq!(code, 42, "remap single FD failed");
    }

    #[test]
    fn remap_clears_cloexec() {
        let (exited, code) = run_remap_test(|| {
            let (r, w) = make_pipe();
            // Set CLOEXEC on the read end.
            unsafe { libc::fcntl(r, libc::F_SETFD, libc::FD_CLOEXEC) };
            unsafe { libc::write(w, b"CE".as_ptr().cast(), 2) };
            unsafe { libc::close(w) };

            let mut fds = std::mem::ManuallyDrop::new(vec![r]);
            if unsafe { remap_fds(&mut fds) }.is_err() {
                unsafe { libc::_exit(1) };
            }

            let flags = unsafe { libc::fcntl(3, libc::F_GETFD) };
            if flags == -1 || (flags & libc::FD_CLOEXEC) != 0 {
                unsafe { libc::_exit(1) };
            }
            unsafe { libc::_exit(42) };
        });
        assert!(exited);
        assert_eq!(code, 42, "CLOEXEC should be cleared after remap");
    }
}
