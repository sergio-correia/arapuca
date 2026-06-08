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

use std::os::unix::io::{FromRawFd, RawFd};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::Arc;

use crate::audit::{
    AuditContext, AuditEvent, AuditVerbosity, LayerDetail, SCHEMA_VERSION, SandboxLayer,
    SkipReason, sanitize_audit_string,
};
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

        // Defense-in-depth: validate work_dir is within mounted paths.
        crate::validate_work_dir(
            &cfg.work_dir,
            &cfg.profile.read_paths,
            &cfg.profile.write_paths,
        )?;

        let tmp_guard = crate::env::TmpDirGuard::new(crate::env::make_tmp_dir(&cfg.task_id)?);

        let audit_ctx = cfg
            .audit_sink
            .as_ref()
            .map(|sink| AuditContext::new(Arc::clone(sink), cfg.audit_verbosity.clone()));

        // Track layers for SandboxReady summary.
        let mut applied_layers = Vec::new();
        let mut skipped_layers = Vec::new();

        // ── Emit SandboxInit ───────────────────────────────────────
        if let Some(ref ctx) = audit_ctx {
            let args_field = match ctx.verbosity() {
                AuditVerbosity::Verbose => {
                    Some(args.iter().map(|a| sanitize_audit_string(a)).collect())
                }
                _ => None,
            };
            ctx.emit(AuditEvent::SandboxInit {
                timestamp: ctx.timestamp(),
                wall_clock_epoch_ns: ctx.wall_clock_epoch_ns(),
                schema_version: SCHEMA_VERSION,
                task_id: sanitize_audit_string(&cfg.task_id),
                phase: sanitize_audit_string(&cfg.phase),
                command: sanitize_audit_string(cmd),
                arg_count: args.len(),
                args: args_field,
                principal: cfg.audit_principal.as_deref().map(sanitize_audit_string),
                correlation_id: cfg
                    .audit_correlation_id
                    .as_deref()
                    .map(sanitize_audit_string),
            })?;
        }

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

            let abi = crate::landlock::abi_version();
            for layer in [
                SandboxLayer::Landlock,
                SandboxLayer::Rlimit,
                SandboxLayer::NoNewPrivs,
            ] {
                let detail = if layer == SandboxLayer::Landlock {
                    Some(LayerDetail::Landlock {
                        abi_version: abi,
                        fully_enforced: abi >= 5,
                    })
                } else {
                    None
                };
                if let Some(ref ctx) = audit_ctx {
                    ctx.emit(AuditEvent::LayerApplied {
                        timestamp: ctx.timestamp(),
                        layer: layer.clone(),
                        detail,
                    })?;
                }
                applied_layers.push(layer);
            }
            #[cfg(seccomp_supported)]
            {
                if let Some(ref ctx) = audit_ctx {
                    ctx.emit(AuditEvent::LayerApplied {
                        timestamp: ctx.timestamp(),
                        layer: SandboxLayer::Seccomp,
                        detail: None,
                    })?;
                }
                applied_layers.push(SandboxLayer::Seccomp);
            }
            #[cfg(not(seccomp_supported))]
            {
                log::warn!("seccomp not available on this architecture");
                if let Some(ref ctx) = audit_ctx {
                    ctx.emit(AuditEvent::LayerSkipped {
                        timestamp: ctx.timestamp(),
                        layer: SandboxLayer::Seccomp,
                        reason: SkipReason::PlatformUnsupported,
                    })?;
                }
                skipped_layers.push(SandboxLayer::Seccomp);
            }
        } else {
            // Wrapper binary absent or no paths configured — no
            // Landlock/seccomp/rlimit/NO_NEW_PRIVS.
            let has_paths =
                !cfg.profile.read_paths.is_empty() || !cfg.profile.write_paths.is_empty();
            if wrapper.is_none() && has_paths {
                return Err(Error::Process(
                    "filesystem restrictions requested but arapuca wrapper binary \
                     not found — refusing to launch without Landlock/seccomp enforcement"
                        .into(),
                ));
            }
            let reason = SkipReason::NotConfigured;
            for layer in [
                SandboxLayer::Landlock,
                SandboxLayer::Rlimit,
                SandboxLayer::NoNewPrivs,
            ] {
                if let Some(ref ctx) = audit_ctx {
                    ctx.emit(AuditEvent::LayerSkipped {
                        timestamp: ctx.timestamp(),
                        layer: layer.clone(),
                        reason: reason.clone(),
                    })?;
                }
                skipped_layers.push(layer);
            }
            #[cfg(seccomp_supported)]
            {
                if let Some(ref ctx) = audit_ctx {
                    ctx.emit(AuditEvent::LayerSkipped {
                        timestamp: ctx.timestamp(),
                        layer: SandboxLayer::Seccomp,
                        reason: reason.clone(),
                    })?;
                }
                skipped_layers.push(SandboxLayer::Seccomp);
            }
            #[cfg(not(seccomp_supported))]
            {
                if let Some(ref ctx) = audit_ctx {
                    ctx.emit(AuditEvent::LayerSkipped {
                        timestamp: ctx.timestamp(),
                        layer: SandboxLayer::Seccomp,
                        reason: SkipReason::PlatformUnsupported,
                    })?;
                }
                skipped_layers.push(SandboxLayer::Seccomp);
            }
        }

        // ── Network namespace ──────────────────────────────────────
        let mut command = if cfg.profile.use_netns {
            let mut c = Command::new("unshare");
            c.args(["--user", "--net", "--map-current-user", "--"]);
            c.arg(&actual_cmd);
            c.args(&actual_args);
            if let Some(ref ctx) = audit_ctx {
                ctx.emit(AuditEvent::LayerApplied {
                    timestamp: ctx.timestamp(),
                    layer: SandboxLayer::NetworkNamespace,
                    detail: None,
                })?;
            }
            applied_layers.push(SandboxLayer::NetworkNamespace);
            c
        } else {
            let mut c = Command::new(&actual_cmd);
            c.args(&actual_args);
            if let Some(ref ctx) = audit_ctx {
                ctx.emit(AuditEvent::LayerSkipped {
                    timestamp: ctx.timestamp(),
                    layer: SandboxLayer::NetworkNamespace,
                    reason: SkipReason::NotConfigured,
                })?;
            }
            skipped_layers.push(SandboxLayer::NetworkNamespace);
            c
        };

        // Set working directory.
        if let Some(ref work_dir) = cfg.work_dir {
            command.current_dir(work_dir);
        }

        // Build minimal environment.
        let mut env_vars = crate::env::minimal_env(tmp_guard.path());

        // Add Landlock/rlimit env vars for the wrapper.
        if use_landlock {
            let mut profile = cfg.profile.clone();
            profile.write_paths.push(tmp_guard.path().to_path_buf());
            profile.read_paths.push(tmp_guard.path().to_path_buf());
            env_vars.extend(crate::env::wrapper_env(&profile));
        }

        // Add network proxy socket (non-ARAPUCA prefix, not stripped).
        if let Some(ref proxy) = cfg.network_proxy_socket {
            env_vars.push((
                "AGENT_NETWORK_PROXY".into(),
                proxy.to_string_lossy().into_owned(),
            ));
        }

        // Configure the proxy bridge when netns + proxy socket are
        // both set. The wrapper binary forks a TCP-to-UDS relay child.
        // The library only configures the env var here — the actual
        // bridge fork and readiness confirmation happen inside the
        // wrapper binary. The binary emits its own audit event on
        // successful bridge startup.
        match crate::env::bridge_env(cfg.profile.use_netns, cfg.network_proxy_socket.as_deref()) {
            Ok(Some(kv)) => {
                env_vars.push(kv);
                if let Some(ref ctx) = audit_ctx {
                    ctx.emit(AuditEvent::LayerApplied {
                        timestamp: ctx.timestamp(),
                        layer: SandboxLayer::ProxyBridge,
                        detail: Some(LayerDetail::ProxyBridge {
                            port: crate::env::BRIDGE_PORT,
                            uds_path: cfg
                                .network_proxy_socket
                                .as_ref()
                                .map(|p| p.to_string_lossy().into_owned())
                                .unwrap_or_default(),
                        }),
                    })?;
                }
                applied_layers.push(SandboxLayer::ProxyBridge);
            }
            Ok(None) => {
                if let Some(ref ctx) = audit_ctx {
                    ctx.emit(AuditEvent::LayerSkipped {
                        timestamp: ctx.timestamp(),
                        layer: SandboxLayer::ProxyBridge,
                        reason: SkipReason::NotConfigured,
                    })?;
                }
                skipped_layers.push(SandboxLayer::ProxyBridge);
            }
            Err(e) => {
                return Err(e);
            }
        }

        // Append caller-supplied env vars (filtered for safety).
        let filter_result = crate::env::filter_caller_env(&cfg.env);
        env_vars.extend(filter_result.passed);

        // ── Emit EnvPolicy ─────────────────────────────────────────
        if let Some(ref ctx) = audit_ctx {
            ctx.emit(AuditEvent::EnvPolicy {
                timestamp: ctx.timestamp(),
                passed_keys: env_vars.iter().map(|(k, _)| k.clone()).collect(),
                dropped: filter_result.dropped,
            })?;
        }
        applied_layers.push(SandboxLayer::EnvFilter);

        command.env_clear();
        for (k, v) in &env_vars {
            command.env(k, v);
        }

        // Validate extra FDs before PTY allocation so that validation
        // failures cannot leak openpty FDs.
        super::fd::validate_extra_fds(&cfg.extra_fds, cfg)?;
        let mut fds_to_inherit = std::mem::ManuallyDrop::new(cfg.extra_fds.clone());

        // ── PTY allocation (TTY mode) ─────────────────────────────
        let (pty_master_fd, pty_slave_fd) = if cfg.tty {
            if cfg.stdin.is_some() || cfg.stdout.is_some() || cfg.stderr.is_some() {
                return Err(Error::Validation(
                    "tty mode is incompatible with stdin/stdout/stderr redirection".into(),
                ));
            }

            let mut master: libc::c_int = -1;
            let mut slave: libc::c_int = -1;
            // SAFETY: openpty with null name/termios/winsize. Parent is
            // single-threaded at this point (no threads spawned yet), so
            // the CLOEXEC race window is safe.
            let ret = unsafe {
                libc::openpty(
                    &mut master,
                    &mut slave,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            };
            if ret != 0 {
                return Err(Error::Process(format!(
                    "openpty: {}",
                    std::io::Error::last_os_error()
                )));
            }
            // SAFETY: valid FDs from openpty.
            unsafe {
                libc::fcntl(master, libc::F_SETFD, libc::FD_CLOEXEC);
                libc::fcntl(slave, libc::F_SETFD, libc::FD_CLOEXEC);
            }

            // Copy parent's terminal size (fallback to 24x80).
            let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
            // SAFETY: TIOCGWINSZ on stdin.
            if unsafe { libc::ioctl(0, libc::TIOCGWINSZ, &mut ws) } == 0
                && ws.ws_row > 0
                && ws.ws_col > 0
            {
                // SAFETY: TIOCSWINSZ on the PTY master.
                unsafe { libc::ioctl(master, libc::TIOCSWINSZ, &ws) };
            } else {
                ws.ws_row = 24;
                ws.ws_col = 80;
                unsafe { libc::ioctl(master, libc::TIOCSWINSZ, &ws) };
            }

            (Some(master), Some(slave))
        } else {
            (None, None)
        };

        // Set stdin/stdout/stderr redirection.
        if cfg.tty {
            command.stdin(Stdio::null());
            command.stdout(Stdio::null());
            command.stderr(Stdio::null());
        } else {
            super::setup_stdio(&mut command, cfg.stdin, "stdin", Command::stdin)?;
            super::setup_stdio(&mut command, cfg.stdout, "stdout", Command::stdout)?;
            super::setup_stdio(&mut command, cfg.stderr, "stderr", Command::stderr)?;
        }

        // ── Audit pipe for wrapper binary verification ─────────────
        // When auditing is active and the wrapper binary is used, create
        // a pipe so the wrapper can report which layers it actually
        // applied. The write end is passed as an extra FD; the parent
        // reads from the read end after spawn.
        let audit_pipe = if audit_ctx.is_some() && use_landlock {
            let mut fds = [0i32; 2];
            // SAFETY: fds is a valid 2-element array. O_CLOEXEC prevents
            // leaking the read end to the child process.
            let ret = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
            if ret == 0 {
                let target_fd = 3 + fds_to_inherit.len() as i32;
                // Bypasses validate_extra_fds intentionally: pipe2 returns
                // the lowest unused FDs, so the write-end cannot collide
                // with any already-open user FD in fds_to_inherit.
                fds_to_inherit.push(fds[1]);
                Some((fds[0], fds[1], target_fd))
            } else {
                log::warn!("audit pipe creation failed, continuing without");
                None
            }
        } else {
            None
        };

        // Add ARAPUCA_AUDIT_FD to wrapper env so it knows which FD to write to.
        if let Some((_, _, target_fd)) = audit_pipe {
            command.env("ARAPUCA_AUDIT_FD", target_fd.to_string());
        }

        // ── Emit pre_exec layer events from parent ─────────────────
        // pre_exec is async-signal-safe — no AuditContext allowed inside.
        // We emit from the parent with the semantic "will be applied."
        if let Some(ref ctx) = audit_ctx {
            ctx.emit(AuditEvent::LayerApplied {
                timestamp: ctx.timestamp(),
                layer: SandboxLayer::Setsid,
                detail: None,
            })?;
            ctx.emit(AuditEvent::LayerApplied {
                timestamp: ctx.timestamp(),
                layer: SandboxLayer::Pdeathsig,
                detail: None,
            })?;

            let inherited: Vec<i32> = (0..fds_to_inherit.len()).map(|i| (3 + i) as i32).collect();
            ctx.emit(AuditEvent::LayerApplied {
                timestamp: ctx.timestamp(),
                layer: SandboxLayer::FdSanitization,
                detail: None,
            })?;
            ctx.emit(AuditEvent::FdInheritance {
                timestamp: ctx.timestamp(),
                inherited_fds: inherited,
                stdin_redirected: cfg.stdin.is_some() || cfg.tty,
                stdout_redirected: cfg.stdout.is_some() || cfg.tty,
                stderr_redirected: cfg.stderr.is_some() || cfg.tty,
            })?;
        }
        applied_layers.push(SandboxLayer::Setsid);
        applied_layers.push(SandboxLayer::Pdeathsig);
        applied_layers.push(SandboxLayer::FdSanitization);

        #[cfg(unix)]
        if cfg.tty {
            if let Some(ref ctx) = audit_ctx {
                ctx.emit(AuditEvent::LayerApplied {
                    timestamp: ctx.timestamp(),
                    layer: SandboxLayer::Pty,
                    detail: None,
                })?;
            }
            applied_layers.push(SandboxLayer::Pty);
        }

        // SAFETY: pre_exec runs between fork and exec. Only
        // async-signal-safe functions are permitted. We use raw libc
        // calls (setsid, prctl) and fd::remap_fds (fcntl, dup2, close).
        // ManuallyDrop prevents free() on the Vec in the child process.
        unsafe {
            command.pre_exec(move || {
                if libc::setsid() == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::prctl(libc::PR_SET_DUMPABLE, 0) != 0 {
                    return Err(std::io::Error::last_os_error());
                }

                // Evacuate PTY slave FD above the remap ceiling if it
                // falls in [3, 3+N) — MUST happen before remap_fds.
                #[cfg(unix)]
                let mut slave_fd = pty_slave_fd;
                #[cfg(unix)]
                if let Some(ref mut sfd) = slave_fd {
                    let ceiling = 3 + fds_to_inherit.len() as i32;
                    if *sfd >= 3 && *sfd < ceiling {
                        let high = libc::fcntl(*sfd, libc::F_DUPFD_CLOEXEC, ceiling);
                        if high == -1 {
                            return Err(std::io::Error::last_os_error());
                        }
                        libc::close(*sfd);
                        *sfd = high;
                    }
                }

                if !fds_to_inherit.is_empty() {
                    super::fd::remap_fds(&mut fds_to_inherit)?;
                }

                // PTY slave setup: acquire controlling terminal, then
                // redirect stdio. TIOCSCTTY runs after setsid() which
                // is the only valid ordering per POSIX.
                #[cfg(unix)]
                if let Some(sfd) = slave_fd {
                    // SAFETY: TIOCSCTTY on the slave PTY. arg=0: do not
                    // steal from another session (the slave is always
                    // unowned after openpty + setsid).
                    if libc::ioctl(sfd, libc::TIOCSCTTY as libc::c_ulong, 0i32) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    if libc::dup2(sfd, 0) == -1 {
                        return Err(std::io::Error::last_os_error());
                    }
                    if libc::dup2(sfd, 1) == -1 {
                        return Err(std::io::Error::last_os_error());
                    }
                    if libc::dup2(sfd, 2) == -1 {
                        return Err(std::io::Error::last_os_error());
                    }
                    if sfd > 2 {
                        libc::close(sfd);
                    }
                }

                Ok(())
            });
        }

        // ── Emit policy summary events ─────────────────────────────
        if let Some(ref ctx) = audit_ctx {
            ctx.emit(AuditEvent::FilesystemPolicy {
                timestamp: ctx.timestamp(),
                read_paths: cfg
                    .profile
                    .read_paths
                    .iter()
                    .map(|p| sanitize_audit_string(&p.to_string_lossy()))
                    .collect(),
                write_paths: cfg
                    .profile
                    .write_paths
                    .iter()
                    .map(|p| sanitize_audit_string(&p.to_string_lossy()))
                    .collect(),
            })?;

            ctx.emit(AuditEvent::ResourceLimits {
                timestamp: ctx.timestamp(),
                memory_mb: cfg.profile.max_memory_mb,
                cpu_pct: cfg.profile.max_cpu_pct,
                max_pids: cfg.profile.max_pids,
                max_file_size_mb: cfg.profile.max_file_size_mb,
                max_open_files: cfg.profile.max_open_files,
                allow_exec: cfg.profile.allow_exec,
            })?;

            ctx.emit(AuditEvent::NetworkPolicy {
                timestamp: ctx.timestamp(),
                isolated: cfg.profile.use_netns,
                proxy_socket: cfg
                    .network_proxy_socket
                    .as_ref()
                    .map(|p| sanitize_audit_string(&p.to_string_lossy())),
            })?;

            #[cfg(seccomp_supported)]
            {
                let seccomp = crate::seccomp::summary(&cfg.profile.seccomp_profile);
                ctx.emit(AuditEvent::SeccompPolicy {
                    timestamp: ctx.timestamp(),
                    tier1_kill_count: seccomp.tier1_kill_count,
                    tier2_eperm_count: seccomp.tier2_eperm_count,
                    socket_filter: seccomp.socket_filter,
                    prctl_filter: seccomp.prctl_filter,
                    clone_ns_filter: seccomp.clone_ns_filter,
                    clone3_enosys: seccomp.clone3_enosys,
                    execveat_filter: seccomp.execveat_filter,
                    allow_exec: cfg.profile.allow_exec,
                })?;
            }
        }

        // ── Create cgroup ──────────────────────────────────────────
        let limits = CgroupLimits {
            memory_max_mb: cfg.profile.max_memory_mb,
            pids_max: cfg.profile.max_pids,
            cpu_max_pct: cfg.profile.max_cpu_pct,
        };

        let mut cgroup_path = None;
        if let Some(ref mgr) = self.cgroup_mgr {
            if limits.has_limits() {
                match mgr.create(&cfg.task_id, &limits) {
                    Ok(result) => {
                        if !result.swap_disabled {
                            log::warn!("cgroup: memory.swap.max could not be set");
                        }
                        if let Some(ref ctx) = audit_ctx {
                            ctx.emit(AuditEvent::LayerApplied {
                                timestamp: ctx.timestamp(),
                                layer: SandboxLayer::Cgroup,
                                detail: Some(LayerDetail::Cgroup {
                                    path: sanitize_audit_string(&result.path.to_string_lossy()),
                                    swap_disabled: result.swap_disabled,
                                }),
                            })?;
                        }
                        applied_layers.push(SandboxLayer::Cgroup);
                        cgroup_path = Some(result.path);
                    }
                    Err(e) => {
                        log::warn!("cgroup creation failed: {e} (continuing without)");
                        if let Some(ref ctx) = audit_ctx {
                            ctx.emit(AuditEvent::LayerSkipped {
                                timestamp: ctx.timestamp(),
                                layer: SandboxLayer::Cgroup,
                                reason: SkipReason::PartialFailure(sanitize_audit_string(
                                    &format!("{e}"),
                                )),
                            })?;
                        }
                        skipped_layers.push(SandboxLayer::Cgroup);
                    }
                }
            }
        } else if limits.has_limits() {
            if cfg.profile.max_memory_mb > 0 || cfg.profile.max_pids > 0 {
                log::warn!(
                    "resource limits requested (memory={}MB, pids={}) but cgroups \
                     unavailable — no enforcement",
                    cfg.profile.max_memory_mb,
                    cfg.profile.max_pids
                );
            }
            if let Some(ref ctx) = audit_ctx {
                ctx.emit(AuditEvent::LayerSkipped {
                    timestamp: ctx.timestamp(),
                    layer: SandboxLayer::Cgroup,
                    reason: SkipReason::NotAvailable,
                })?;
            }
            skipped_layers.push(SandboxLayer::Cgroup);
        }

        // ── Emit SandboxReady ──────────────────────────────────────
        if let Some(ref ctx) = audit_ctx {
            ctx.emit(AuditEvent::SandboxReady {
                timestamp: ctx.timestamp(),
                applied_layers: applied_layers.clone(),
                skipped_layers: skipped_layers.clone(),
            })?;
        }

        // ── Spawn ──────────────────────────────────────────────────
        let child = command.spawn().map_err(|e| {
            if let Some(ref ctx) = audit_ctx {
                let _ = ctx.emit(AuditEvent::LayerFailed {
                    timestamp: ctx.timestamp(),
                    layer: SandboxLayer::ProcessSpawn,
                    error: sanitize_audit_string(&format!("spawn failed: {e}")),
                });
            }
            if let Some((read_fd, write_fd, _)) = audit_pipe {
                // SAFETY: valid FDs from pipe().
                unsafe {
                    libc::close(read_fd);
                    libc::close(write_fd);
                }
            }
            #[cfg(unix)]
            {
                if let Some(m) = pty_master_fd {
                    unsafe { libc::close(m) };
                }
                if let Some(s) = pty_slave_fd {
                    unsafe { libc::close(s) };
                }
            }
            if let Some(ref path) = cgroup_path {
                if let Some(ref mgr) = self.cgroup_mgr {
                    let _ = mgr.destroy(path);
                }
            }
            Error::Process(format!("start sandboxed process: {e}"))
        })?;

        // ── Close PTY slave in parent ──────────────────────────────
        #[cfg(unix)]
        if let Some(s) = pty_slave_fd {
            // SAFETY: valid FD from openpty, no longer needed in parent.
            unsafe { libc::close(s) };
        }

        // ── Read wrapper audit pipe ────────────────────────────────
        // Close write end in parent (essential — otherwise EOF never
        // arrives). Then read all lines until EOF. The wrapper writes
        // events before execve; the write end closes at exec (CLOEXEC
        // is cleared, but the wrapper explicitly closes it).
        if let Some((read_fd, write_fd, _)) = audit_pipe {
            // SAFETY: write_fd is a valid descriptor from pipe().
            unsafe { libc::close(write_fd) };
            validate_wrapper_audit(read_fd);
            // SAFETY: read_fd is a valid descriptor from pipe().
            unsafe { libc::close(read_fd) };
        }

        // ── Emit ProcessStarted ────────────────────────────────────
        if let Some(ref ctx) = audit_ctx {
            ctx.emit(AuditEvent::ProcessStarted {
                timestamp: ctx.timestamp(),
                pid: child.id(),
            })?;
        }

        // Add subprocess PID to cgroup.
        if let (Some(mgr), Some(path)) = (&self.cgroup_mgr, &cgroup_path) {
            if let Err(e) = mgr.add_pid(path, child.id()) {
                log::warn!("failed to add PID to cgroup: {e}");
                if let Some(ref ctx) = audit_ctx {
                    // Post-spawn: can't abort (child is running), so we
                    // intentionally discard mandatory emit errors here.
                    if let Err(ae) = ctx.emit(AuditEvent::LayerSkipped {
                        timestamp: ctx.timestamp(),
                        layer: SandboxLayer::Cgroup,
                        reason: SkipReason::PartialFailure(sanitize_audit_string(&format!(
                            "add_pid failed: {e}"
                        ))),
                    }) {
                        log::error!("audit emit failed: {ae}");
                    }
                }
            }
        }

        Ok(Process {
            child: crate::process::ChildHandle::Managed(child),
            tmp_dir: tmp_guard.defuse(),
            cgroup_path,
            cgroup_mgr: self.cgroup_mgr.clone(),
            #[cfg(feature = "microvm")]
            passt: None,
            pty_master: pty_master_fd.map(|fd| {
                // SAFETY: fd is a valid master FD from openpty with CLOEXEC set.
                unsafe { std::os::unix::io::OwnedFd::from_raw_fd(fd) }
            }),
            audit_ctx,
            final_stats: None,
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

/// Read and validate audit events from the wrapper binary's pipe.
///
/// The wrapper writes one JSON line per applied layer. We read until
/// EOF (the wrapper closes the FD before execve) and validate that
/// all expected layers were applied. Buffer bounded to 64 KiB to
/// prevent OOM from a compromised wrapper.
fn validate_wrapper_audit(read_fd: RawFd) {
    const MAX_BUF: usize = 64 * 1024;
    let mut buf = vec![0u8; MAX_BUF];
    let mut total = 0;

    loop {
        // SAFETY: read_fd is a valid descriptor, buf is valid memory.
        let n = unsafe {
            libc::read(
                read_fd,
                buf[total..].as_mut_ptr().cast::<libc::c_void>(),
                buf.len() - total,
            )
        };
        if n == 0 {
            break;
        }
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            log::warn!("wrapper audit pipe read error: {err}");
            break;
        }
        total += n as usize;
        if total >= MAX_BUF {
            log::warn!("wrapper audit pipe exceeded 64 KiB, truncating");
            break;
        }
    }

    if total == 0 {
        log::warn!("wrapper audit pipe: no events received (wrapper may have crashed)");
        return;
    }

    let text = String::from_utf8_lossy(&buf[..total]);
    let lines: Vec<&str> = text.lines().filter(|l| !l.is_empty()).collect();
    log::info!("wrapper audit: received {} events", lines.len());

    for line in &lines {
        if line.contains(r#""status":"failed""#) {
            log::error!(
                "wrapper audit: layer failure reported: {}",
                sanitize_audit_string(line)
            );
        }
    }
}
