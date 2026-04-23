//! Degraded sandbox for non-Linux, non-macOS platforms.
//!
//! Provides minimal isolation — only environment hardening. No Landlock,
//! no seccomp, no cgroups, no network namespace. Suitable for development
//! and testing only. Production workloads should use Linux.

use std::os::unix::io::RawFd;
use std::os::unix::process::CommandExt;
use std::process::Command;
use std::sync::Arc;

use crate::audit::{
    AuditContext, AuditEvent, AuditVerbosity, SCHEMA_VERSION, SandboxLayer, SkipReason,
    sanitize_audit_string,
};
use crate::platform::Sandbox;
use crate::{Config, Error, process::Process};

/// Degraded sandbox (no OS-level isolation).
pub struct Other;

impl Sandbox for Other {
    fn launch(&self, cfg: &Config, cmd: &str, args: &[&str]) -> crate::Result<Process> {
        let tmp_dir = crate::env::make_tmp_dir(&cfg.task_id)?;

        let audit_ctx = cfg
            .audit_sink
            .as_ref()
            .map(|sink| AuditContext::new(Arc::clone(sink), cfg.audit_verbosity.clone()));

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

            // All security layers are unavailable on this platform.
            for layer in [
                SandboxLayer::Landlock,
                SandboxLayer::Seccomp,
                SandboxLayer::Cgroup,
                SandboxLayer::NetworkNamespace,
                SandboxLayer::Rlimit,
                SandboxLayer::NoNewPrivs,
                SandboxLayer::Setsid,
                SandboxLayer::Pdeathsig,
            ] {
                ctx.emit(AuditEvent::LayerSkipped {
                    timestamp: ctx.timestamp(),
                    layer,
                    reason: SkipReason::PlatformUnsupported,
                })?;
            }

            ctx.emit(AuditEvent::SandboxReady {
                timestamp: ctx.timestamp(),
                applied_layers: vec![SandboxLayer::EnvFilter, SandboxLayer::FdSanitization],
                skipped_layers: vec![
                    SandboxLayer::Landlock,
                    SandboxLayer::Seccomp,
                    SandboxLayer::Cgroup,
                    SandboxLayer::NetworkNamespace,
                    SandboxLayer::Rlimit,
                    SandboxLayer::NoNewPrivs,
                    SandboxLayer::Setsid,
                    SandboxLayer::Pdeathsig,
                ],
            })?;
        }

        let mut command = Command::new(cmd);
        command.args(args);

        if let Some(work_dir) = &cfg.work_dir {
            command.current_dir(work_dir);
        }

        let mut env_vars = crate::env::minimal_env(&tmp_dir);
        let filter_result = crate::env::filter_caller_env(&cfg.env);
        env_vars.extend(filter_result.passed);

        if let Some(ref ctx) = audit_ctx {
            ctx.emit(AuditEvent::EnvPolicy {
                timestamp: ctx.timestamp(),
                passed_keys: env_vars.iter().map(|(k, _)| k.clone()).collect(),
                dropped: filter_result.dropped,
            })?;
        }

        command.env_clear();
        for (k, v) in &env_vars {
            command.env(k, v);
        }

        // stdin/stdout/stderr redirection.
        super::setup_stdio(&mut command, cfg.stdin, "stdin", Command::stdin)?;
        super::setup_stdio(&mut command, cfg.stdout, "stdout", Command::stdout)?;
        super::setup_stdio(&mut command, cfg.stderr, "stderr", Command::stderr)?;

        // Extra FD inheritance.
        let fds_to_inherit: Vec<RawFd> = cfg.extra_fds.clone();
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

        if let Some(ref ctx) = audit_ctx {
            if let Err(e) = ctx.emit(AuditEvent::ProcessStarted {
                timestamp: ctx.timestamp(),
                pid: child.id(),
            }) {
                log::error!("audit emit failed: {e}");
            }
        }

        Ok(Process {
            child,
            tmp_dir,
            audit_ctx,
            final_stats: None,
        })
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
