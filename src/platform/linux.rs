//! Linux sandbox implementation.
//!
//! Coordinates Landlock, seccomp, cgroups v2, and network namespace
//! isolation to launch fully sandboxed subprocesses.
//!
//! The subprocess is spawned with:
//! - CLONE_NEWNET (if UseNetNS) for network namespace isolation
//! - Setsid to detach from the host's session
//! - Minimal environment (HOME, TMPDIR, PATH, LANG only)
//! - Only explicitly listed FDs inherited (via extra_fds)
//! - All other FDs have CLOEXEC set by the Rust runtime
//!
//! Landlock, seccomp, and rlimits are applied by the arapuca wrapper
//! binary at startup (before exec-ing the agent).

use std::os::unix::io::RawFd;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::Arc;

use crate::cgroup::{CgroupLimits, CgroupManager};
use crate::platform::Sandbox;
use crate::{Config, Error, process::Process};

/// Linux sandbox implementation.
pub struct Linux {
    cgroup_mgr: Option<Arc<CgroupManager>>,
}

impl Linux {
    /// Create a new Linux sandbox, probing available features.
    pub fn new() -> crate::Result<Self> {
        let cgroup_mgr = CgroupManager::new()?.map(Arc::new);
        Ok(Self { cgroup_mgr })
    }

    /// Find the arapuca wrapper binary.
    fn wrapper_path() -> Option<PathBuf> {
        crate::env::wrapper_path()
    }
}

impl Sandbox for Linux {
    fn launch(&self, cfg: &Config, cmd: &str, args: &[&str]) -> crate::Result<Process> {
        // Validate task ID.
        crate::sanitize_task_id(&cfg.task_id)?;

        // Defense-in-depth: reject /sys/fs/cgroup in sandbox paths.
        crate::reject_cgroup_paths(&cfg.profile.read_paths)?;
        crate::reject_cgroup_paths(&cfg.profile.write_paths)?;

        let tmp_dir = crate::env::make_tmp_dir(&cfg.task_id)?;

        // Determine the actual command. We may wrap it with the
        // arapuca binary (Landlock+seccomp) and/or unshare (netns).
        let mut actual_cmd = cmd.to_string();
        let mut actual_args: Vec<String> = args.iter().map(|a| a.to_string()).collect();

        // Layer 1: Landlock wrapper. If the arapuca binary is available
        // and filesystem paths are configured, wrap through it.
        let wrapper = Self::wrapper_path();
        let use_landlock = wrapper.is_some()
            && (!cfg.profile.read_paths.is_empty() || !cfg.profile.write_paths.is_empty());

        if use_landlock {
            let wrapper_path = wrapper.as_ref().unwrap();
            let mut wrapper_args = vec!["--".to_string(), actual_cmd];
            wrapper_args.extend(actual_args);
            actual_cmd = wrapper_path.to_string_lossy().into_owned();
            actual_args = wrapper_args;
        }

        // Layer 2: Network namespace.
        let mut command = if cfg.profile.use_netns {
            let mut c = Command::new("unshare");
            c.args(["--user", "--net", "--map-current-user", "--"]);
            c.arg(&actual_cmd);
            c.args(&actual_args);
            c
        } else {
            let mut c = Command::new(&actual_cmd);
            c.args(&actual_args);
            c
        };

        // Set working directory.
        if let Some(ref work_dir) = cfg.work_dir {
            command.current_dir(work_dir);
        }

        // Build minimal environment.
        let mut env_vars = crate::env::minimal_env(&tmp_dir);

        // Add Landlock/rlimit env vars for the wrapper.
        if use_landlock {
            let mut profile = cfg.profile.clone();
            profile.write_paths.push(tmp_dir.clone());
            profile.read_paths.push(tmp_dir.clone());
            env_vars.extend(crate::env::wrapper_env(&profile));
        }

        // Add network proxy socket (non-ARAPUCA prefix, not stripped).
        if let Some(ref proxy) = cfg.network_proxy_socket {
            env_vars.push((
                "AGENT_NETWORK_PROXY".into(),
                proxy.to_string_lossy().into_owned(),
            ));
        }

        // Append caller-supplied env vars (filtered for safety).
        env_vars.extend(crate::env::filter_caller_env(&cfg.env));

        command.env_clear();
        for (k, v) in &env_vars {
            command.env(k, v);
        }

        // Set stdin/stdout/stderr redirection.
        super::setup_stdio(&mut command, cfg.stdin, "stdin", Command::stdin)?;
        super::setup_stdio(&mut command, cfg.stdout, "stdout", Command::stdout)?;
        super::setup_stdio(&mut command, cfg.stderr, "stderr", Command::stderr)?;

        let fds_to_inherit: Vec<RawFd> = cfg.extra_fds.clone();

        // SAFETY: pre_exec runs between fork and exec. Only
        // async-signal-safe functions are permitted. We use raw libc
        // calls (setsid, prctl, dup2, fcntl) — no std::fs or allocation.
        unsafe {
            command.pre_exec(move || {
                // Setsid: detach from host's terminal session.
                libc::setsid();
                // Pdeathsig: kill subprocess if parent dies.
                libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);

                // Map extra FDs to deterministic positions (3, 4, ...).
                // The Go orchestrator expects the nonce pipe at FD 3.
                for (i, &fd) in fds_to_inherit.iter().enumerate() {
                    let target_fd = (3 + i) as libc::c_int;
                    if fd != target_fd {
                        if libc::dup2(fd, target_fd) == -1 {
                            return Err(std::io::Error::last_os_error());
                        }
                        libc::close(fd);
                    }
                    // Clear CLOEXEC so the FD survives exec.
                    let flags = libc::fcntl(target_fd, libc::F_GETFD);
                    if flags != -1 {
                        libc::fcntl(target_fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC);
                    }
                }

                Ok(())
            });
        }

        // Create cgroup if available and limits are set.
        let limits = CgroupLimits {
            memory_max_mb: cfg.profile.max_memory_mb,
            pids_max: cfg.profile.max_pids,
            cpu_max_pct: cfg.profile.max_cpu_pct,
        };

        let mut cgroup_path = None;
        if let Some(ref mgr) = self.cgroup_mgr {
            if limits.has_limits() {
                match mgr.create(&cfg.task_id, &limits) {
                    Ok(path) => cgroup_path = Some(path),
                    Err(e) => log::warn!("cgroup creation failed: {e} (continuing without)"),
                }
            }
        }

        let child = command.spawn().map_err(|e| {
            // Clean up on failure.
            if let Some(ref path) = cgroup_path {
                if let Some(ref mgr) = self.cgroup_mgr {
                    let _ = mgr.destroy(path);
                }
            }
            let _ = std::fs::remove_dir_all(&tmp_dir);
            Error::Process(format!("start sandboxed process: {e}"))
        })?;

        // Add subprocess PID to cgroup.
        if let (Some(mgr), Some(path)) = (&self.cgroup_mgr, &cgroup_path) {
            if let Err(e) = mgr.add_pid(path, child.id()) {
                log::warn!("failed to add PID to cgroup: {e}");
            }
        }

        Ok(Process {
            child,
            tmp_dir,
            cgroup_path,
            cgroup_mgr: self.cgroup_mgr.clone(),
        })
    }

    fn available(&self) -> crate::Result<()> {
        std::process::Command::new("unshare")
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|e| {
                Error::Process(format!(
                    "unshare not found: {e} (required for network namespace isolation)"
                ))
            })?;
        Ok(())
    }

    fn netns_available(&self) -> bool {
        crate::netns::available()
    }

    fn cgroups_available(&self) -> bool {
        self.cgroup_mgr.is_some()
    }
}
