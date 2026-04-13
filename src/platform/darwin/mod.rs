//! macOS sandbox implementation using Apple's Seatbelt (`sandbox-exec`).
//!
//! Provides kernel-enforced filesystem and network restrictions on macOS.
//! Unlike Linux (Landlock + seccomp + cgroups), macOS uses a single
//! Seatbelt profile for filesystem/network policy and relies on rlimits
//! for resource limits (no cgroups).
//!
//! Memory enforcement is best-effort via polling (500ms interval) since
//! macOS has no cgroup-based OOM killer. A parent-PID watchdog replaces
//! Linux's `PR_SET_PDEATHSIG`.
//!
//! `sandbox-exec` is deprecated by Apple but still works on macOS 15.

mod darwin_profile;

use std::os::unix::io::{FromRawFd, RawFd};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use crate::platform::Sandbox;
use crate::{Config, Error, process::Process};

/// macOS sandbox implementation.
pub struct Darwin;

impl Darwin {
    /// Create a new macOS sandbox.
    pub fn new() -> crate::Result<Self> {
        Ok(Darwin)
    }

    /// Find the arapuca wrapper binary.
    fn wrapper_path() -> Option<PathBuf> {
        crate::env::wrapper_path()
    }

    /// Resolve the uv cache path on macOS.
    fn uv_cache_path() -> Option<PathBuf> {
        // uv uses ~/Library/Caches/uv on macOS.
        std::env::var("HOME")
            .ok()
            .map(|h| PathBuf::from(h).join("Library/Caches/uv"))
    }

    /// Convert CPU percentage and max duration to RLIMIT_CPU seconds.
    ///
    /// The Go implementation uses: cpu_pct / 100 * duration_seconds.
    /// Example: 200% for 30 minutes = 2.0 * 1800 = 3600 seconds.
    fn cpu_pct_to_seconds(cpu_pct: u32, duration_minutes: u64) -> u64 {
        if cpu_pct == 0 || duration_minutes == 0 {
            return 0;
        }
        let factor = f64::from(cpu_pct) / 100.0;
        let duration_secs = duration_minutes * 60;
        (factor * duration_secs as f64) as u64
    }

    /// Start a memory monitoring thread that polls RSS and kills the
    /// process group if it exceeds the limit.
    ///
    /// This is a best-effort mechanism — the 500ms polling window means
    /// a process can briefly exceed the limit before being killed.
    fn start_memory_monitor(pid: u32, limit_mb: u64) {
        if limit_mb == 0 {
            return;
        }
        let limit_kb = limit_mb * 1024;
        std::thread::spawn(move || {
            loop {
                std::thread::sleep(std::time::Duration::from_millis(500));

                // Check if process still exists.
                // SAFETY: kill with signal 0 checks process existence
                // without sending a signal.
                let alive = unsafe { libc::kill(pid as libc::pid_t, 0) } == 0;
                if !alive {
                    break;
                }

                // Read RSS via ps.
                let output = Command::new("ps")
                    .args(["-o", "rss=", "-p", &pid.to_string()])
                    .stdout(Stdio::piped())
                    .stderr(Stdio::null())
                    .output();

                let rss_kb = match output {
                    Ok(out) => {
                        let s = String::from_utf8_lossy(&out.stdout);
                        s.trim().parse::<u64>().unwrap_or(0)
                    }
                    Err(_) => continue,
                };

                if rss_kb > limit_kb {
                    log::warn!(
                        "memory limit exceeded: {rss_kb}KB > {limit_kb}KB, \
                         killing process group {pid}"
                    );
                    // Kill the entire process group.
                    // SAFETY: Sending SIGKILL to a process group. The
                    // negative PID targets the group.
                    unsafe {
                        libc::kill(-(pid as libc::pid_t), libc::SIGKILL);
                    }
                    break;
                }
            }
        });
    }

    /// Start a parent-PID watchdog thread.
    ///
    /// On macOS there is no `PR_SET_PDEATHSIG`. Instead, we poll
    /// `getppid()` every 2 seconds. If the parent PID changes (process
    /// was reparented to init/launchd), the subprocess is killed.
    fn start_parent_watchdog(child_pid: u32) {
        let original_ppid = std::process::id();
        std::thread::spawn(move || {
            loop {
                std::thread::sleep(std::time::Duration::from_secs(2));
                // SAFETY: getppid() is a simple getter with no arguments.
                let current_ppid = unsafe { libc::getppid() } as u32;
                if current_ppid != original_ppid {
                    log::warn!(
                        "parent died (ppid changed {} -> {}), killing child {}",
                        original_ppid,
                        current_ppid,
                        child_pid
                    );
                    // SAFETY: Sending SIGKILL to the child's process group.
                    unsafe {
                        libc::kill(-(child_pid as libc::pid_t), libc::SIGKILL);
                    }
                    break;
                }
                // Also check if child is still alive.
                let alive = unsafe { libc::kill(child_pid as libc::pid_t, 0) } == 0;
                if !alive {
                    break;
                }
            }
        });
    }
}

impl Sandbox for Darwin {
    fn launch(
        &self,
        cfg: &Config,
        cmd: &str,
        args: &[&str],
        _extra_fds: &[RawFd],
    ) -> crate::Result<Process> {
        // Validate task ID.
        crate::sanitize_task_id(&cfg.task_id)?;

        let tmp_dir = crate::env::make_tmp_dir(&cfg.task_id)?;

        // Build profile data from config.
        let mut read_paths: Vec<String> = cfg
            .profile
            .read_paths
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect();

        let mut write_paths: Vec<String> = cfg
            .profile
            .write_paths
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect();

        // Add socket dir to read paths so the agent can connect.
        read_paths.push(cfg.socket_dir.to_string_lossy().into_owned());

        // Add tmp_dir to write paths.
        write_paths.push(tmp_dir.to_string_lossy().into_owned());

        // Add uv cache to read paths if it exists.
        if let Some(uv_cache) = Self::uv_cache_path() {
            if uv_cache.exists() {
                read_paths.push(uv_cache.to_string_lossy().into_owned());
            }
        }

        let exec_paths: Vec<String> = Vec::new();

        let control_socket = Some(
            cfg.socket_dir
                .join("control.sock")
                .to_string_lossy()
                .into_owned(),
        );
        let llm_socket = cfg
            .network_proxy_socket
            .as_ref()
            .map(|p| p.to_string_lossy().into_owned());

        let profile_data = darwin_profile::ProfileData {
            read_paths,
            write_paths,
            exec_paths,
            control_socket,
            llm_socket,
        };

        // Generate the Seatbelt profile.
        let profile_path = darwin_profile::generate_profile(&tmp_dir, &profile_data)?;

        // Build the command: sandbox-exec -f profile.sb -- cmd args...
        let mut actual_cmd = cmd.to_string();
        let mut actual_args: Vec<String> = args.iter().map(|a| a.to_string()).collect();

        // Wrap with sandbox-exec.
        let sb_args = vec![
            "-f".to_string(),
            profile_path.to_string_lossy().into_owned(),
            "--".to_string(),
            actual_cmd,
        ];
        actual_cmd = "sandbox-exec".to_string();
        let mut new_args = sb_args;
        new_args.extend(actual_args);
        actual_args = new_args;

        // Optionally wrap with arapuca binary for rlimits.
        // On macOS the wrapper only applies rlimits (Landlock/seccomp
        // are gated behind cfg(linux)).
        let wrapper = Self::wrapper_path();
        if let Some(ref wrapper_path) = wrapper {
            let mut wrapper_args = vec!["--".to_string(), actual_cmd];
            wrapper_args.extend(actual_args);
            actual_cmd = wrapper_path.to_string_lossy().into_owned();
            actual_args = wrapper_args;
        }

        let mut command = Command::new(&actual_cmd);
        command.args(&actual_args);

        // Set working directory.
        if let Some(ref work_dir) = cfg.work_dir {
            command.current_dir(work_dir);
        }

        // Build minimal environment with Homebrew PATH.
        let mut env_vars = crate::env::minimal_env(&tmp_dir);

        // Override PATH to include Homebrew.
        for entry in &mut env_vars {
            if entry.0 == "PATH" {
                entry.1 = "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:\
                            /usr/local/sbin:/usr/sbin:/sbin"
                    .into();
            }
        }

        // Add rlimit env vars for the wrapper (if using it).
        if wrapper.is_some() {
            let mut rlimit_profile = cfg.profile.clone();

            // Skip RLIMIT_AS on Apple Silicon — macOS aggressively maps
            // virtual memory and setting it causes immediate SIGKILL.
            if std::env::consts::ARCH == "aarch64" {
                rlimit_profile.max_memory_mb = 0;
            }

            let wrapper_env = crate::env::wrapper_env(&rlimit_profile);
            env_vars.extend(wrapper_env);

            // Add RLIMIT_CPU if cpu_pct is set (convert % to seconds).
            // Use 30 minutes as default max duration.
            let cpu_seconds = Self::cpu_pct_to_seconds(cfg.profile.max_cpu_pct, 30);
            if cpu_seconds > 0 {
                env_vars.push(("ARAPUCA_RLIMIT_CPU".into(), cpu_seconds.to_string()));
            }
        }

        // Add network proxy socket (non-ARAPUCA prefix, not stripped).
        if let Some(ref proxy) = cfg.network_proxy_socket {
            env_vars.push((
                "AGENT_NETWORK_PROXY".into(),
                proxy.to_string_lossy().into_owned(),
            ));
        }

        command.env_clear();
        for (k, v) in &env_vars {
            command.env(k, v);
        }

        // Set stdin/stdout/stderr. Dup the FD with CLOEXEC so Rust
        // doesn't take ownership of the caller's FD (from_raw_fd
        // consumes it) and a concurrent fork can't leak the duped FD.
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

        // Setsid: detach from host's terminal session (same as Linux).
        // SAFETY: setsid is a simple setter with no pointer arguments.
        unsafe {
            command.pre_exec(|| {
                libc::setsid();
                Ok(())
            });
        }

        let child = command.spawn().map_err(|e| {
            let _ = std::fs::remove_dir_all(&tmp_dir);
            Error::Process(format!("start sandboxed process: {e}"))
        })?;

        let pid = child.id();

        // Start memory monitor thread (best-effort RSS polling).
        Self::start_memory_monitor(pid, cfg.profile.max_memory_mb);

        // Start parent-PID watchdog (replaces PR_SET_PDEATHSIG).
        Self::start_parent_watchdog(pid);

        Ok(Process { child, tmp_dir })
    }

    fn available(&self) -> crate::Result<()> {
        // Check that sandbox-exec exists.
        Command::new("sandbox-exec")
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|e| {
                Error::Process(format!(
                    "sandbox-exec not found: {e} \
                     (required for macOS sandbox)"
                ))
            })?;
        Ok(())
    }

    fn netns_available(&self) -> bool {
        false
    }

    fn cgroups_available(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpu_pct_to_seconds_basic() {
        // 200% for 30 min = 3600 seconds.
        assert_eq!(Darwin::cpu_pct_to_seconds(200, 30), 3600);
        // 100% for 30 min = 1800 seconds.
        assert_eq!(Darwin::cpu_pct_to_seconds(100, 30), 1800);
        // 0% = no limit.
        assert_eq!(Darwin::cpu_pct_to_seconds(0, 30), 0);
        // 0 duration = no limit.
        assert_eq!(Darwin::cpu_pct_to_seconds(200, 0), 0);
    }
}
