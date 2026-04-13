//! Degraded sandbox for non-Linux, non-macOS platforms.
//!
//! Provides minimal isolation — only environment hardening. No Landlock,
//! no seccomp, no cgroups, no network namespace. Suitable for development
//! and testing only. Production workloads should use Linux.

use std::os::unix::io::{FromRawFd, RawFd};
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};

use crate::platform::Sandbox;
use crate::{Config, Error, process::Process};

/// Degraded sandbox (no OS-level isolation).
pub struct Other;

impl Sandbox for Other {
    fn launch(
        &self,
        cfg: &Config,
        cmd: &str,
        args: &[&str],
        extra_fds: &[RawFd],
    ) -> crate::Result<Process> {
        let tmp_dir = crate::env::make_tmp_dir(&cfg.task_id)?;

        let mut command = Command::new(cmd);
        command.args(args);

        if let Some(work_dir) = &cfg.work_dir {
            command.current_dir(work_dir);
        }

        let env_vars = crate::env::minimal_env(&tmp_dir);
        command.env_clear();
        for (k, v) in &env_vars {
            command.env(k, v);
        }

        // stdin/stdout/stderr redirection. Dup with CLOEXEC so Rust
        // doesn't take caller's FD and concurrent forks can't leak it.
        match cfg.stdin {
            Some(fd) => {
                // SAFETY: F_DUPFD_CLOEXEC on a valid fd returns a new
                // fd we own, with CLOEXEC set atomically.
                let duped = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
                if duped == -1 {
                    return Err(Error::Process(format!(
                        "dup stdin fd: {}",
                        std::io::Error::last_os_error()
                    )));
                }
                command.stdin(unsafe { Stdio::from_raw_fd(duped) });
            }
            None => {
                command.stdin(Stdio::inherit());
            }
        }
        match cfg.stdout {
            Some(fd) => {
                // SAFETY: F_DUPFD_CLOEXEC on a valid fd returns a new
                // fd we own, with CLOEXEC set atomically.
                let duped = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
                if duped == -1 {
                    return Err(Error::Process(format!(
                        "dup stdout fd: {}",
                        std::io::Error::last_os_error()
                    )));
                }
                command.stdout(unsafe { Stdio::from_raw_fd(duped) });
            }
            None => {
                command.stdout(Stdio::inherit());
            }
        }
        match cfg.stderr {
            Some(fd) => {
                // SAFETY: F_DUPFD_CLOEXEC on a valid fd returns a new
                // fd we own, with CLOEXEC set atomically.
                let duped = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
                if duped == -1 {
                    return Err(Error::Process(format!(
                        "dup stderr fd: {}",
                        std::io::Error::last_os_error()
                    )));
                }
                command.stderr(unsafe { Stdio::from_raw_fd(duped) });
            }
            None => {
                command.stderr(Stdio::inherit());
            }
        }

        // Extra FD inheritance.
        let fds_to_inherit: Vec<RawFd> = extra_fds.to_vec();
        if !fds_to_inherit.is_empty() {
            unsafe {
                command.pre_exec(move || {
                    for (i, &fd) in fds_to_inherit.iter().enumerate() {
                        let target_fd = (3 + i) as libc::c_int;
                        if fd != target_fd {
                            if libc::dup2(fd, target_fd) == -1 {
                                return Err(std::io::Error::last_os_error());
                            }
                            libc::close(fd);
                        }
                        let flags = libc::fcntl(target_fd, libc::F_GETFD);
                        if flags != -1 {
                            libc::fcntl(target_fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC);
                        }
                    }
                    Ok(())
                });
            }
        }

        let child = command.spawn().map_err(|e| {
            let _ = std::fs::remove_dir_all(&tmp_dir);
            Error::Process(format!("start process: {e}"))
        })?;

        Ok(Process { child, tmp_dir })
    }

    fn available(&self) -> crate::Result<()> {
        Err(Error::Process(format!(
            "platform {} has degraded sandbox security (development only)",
            std::env::consts::OS
        )))
    }

    fn netns_available(&self) -> bool {
        false
    }

    fn cgroups_available(&self) -> bool {
        false
    }
}
