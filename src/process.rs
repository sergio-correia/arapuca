//! Sandboxed process lifecycle.
//!
//! Represents a running sandboxed subprocess with methods for waiting,
//! reading resource usage, and cleanup.

use std::path::PathBuf;

use crate::ResourceUsage;
use crate::audit::{AuditContext, AuditEvent};

/// Child process variant — either a std::process::Child or a raw
/// PID from fork() (used by the micro-VM path where we fork
/// directly instead of going through Command).
#[cfg(not(windows))]
pub(crate) enum ChildHandle {
    Managed(std::process::Child),
    #[cfg_attr(not(feature = "microvm"), allow(dead_code))]
    Forked(u32),
}

/// A running sandboxed subprocess.
pub struct Process {
    /// The child process handle (Unix platforms).
    #[cfg(not(windows))]
    pub(crate) child: ChildHandle,
    /// Process handle (Windows). Owned — CloseHandle on drop.
    #[cfg(windows)]
    pub(crate) process_handle: std::os::windows::io::OwnedHandle,
    /// Process ID (Windows).
    #[cfg(windows)]
    pub(crate) process_id: u32,
    /// Sandbox-created temp directory (HOME for the subprocess).
    pub(crate) tmp_dir: PathBuf,
    /// Cgroup path (None if no cgroup). Linux only.
    #[cfg(target_os = "linux")]
    pub(crate) cgroup_path: Option<PathBuf>,
    /// Reference to the cgroup manager for stats/cleanup. Linux only.
    #[cfg(target_os = "linux")]
    pub(crate) cgroup_mgr: Option<std::sync::Arc<crate::cgroup::CgroupManager>>,
    /// Job Object handle. Kept alive for JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE:
    /// when the handle closes (drop or parent crash), Windows kills all
    /// processes in the Job Object.
    #[cfg(windows)]
    #[allow(dead_code)]
    pub(crate) job_handle: Option<std::os::windows::io::OwnedHandle>,
    /// AppContainer profile name for cleanup.
    #[cfg(windows)]
    pub(crate) container_name: Option<String>,
    /// Saved DACLs for restoration during cleanup.
    #[cfg(windows)]
    pub(crate) saved_dacls: Vec<crate::platform::windows::SavedDacl>,
    /// Audit context for emitting lifecycle events.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) audit_ctx: Option<AuditContext>,
    /// Resource stats captured in wait() while cgroup still exists.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) final_stats: Option<ResourceUsage>,
}

impl Process {
    /// Get the PID of the sandboxed process.
    #[cfg(not(windows))]
    pub fn pid(&self) -> u32 {
        match &self.child {
            ChildHandle::Managed(c) => c.id(),
            ChildHandle::Forked(pid) => *pid,
        }
    }

    /// Get the PID of the sandboxed process.
    #[cfg(windows)]
    pub fn pid(&self) -> u32 {
        self.process_id
    }

    /// Wait for the process to exit and return the exit status.
    #[cfg(not(windows))]
    pub fn wait(&mut self) -> crate::Result<std::process::ExitStatus> {
        let pid = self.pid();
        let status = match &mut self.child {
            ChildHandle::Managed(c) => c
                .wait()
                .map_err(|e| crate::Error::Process(format!("wait: {e}")))?,
            ChildHandle::Forked(child_pid) => {
                use std::os::unix::process::ExitStatusExt;
                let mut wstatus: libc::c_int = 0;
                // SAFETY: child_pid is a valid PID from fork.
                let ret = unsafe { libc::waitpid(*child_pid as libc::pid_t, &mut wstatus, 0) };
                if ret < 0 {
                    return Err(crate::Error::Process(format!(
                        "waitpid: {}",
                        std::io::Error::last_os_error()
                    )));
                }
                std::process::ExitStatus::from_raw(wstatus)
            }
        };

        // Capture stats while cgroup still exists (before cleanup
        // destroys it). Eliminates the TOCTOU gap.
        self.final_stats = Some(self.resource_stats());
        let oom = self.oom_count();

        if let Some(ref ctx) = self.audit_ctx {
            use std::os::unix::process::ExitStatusExt;
            // Post-exit: can't abort, so discard mandatory emit errors.
            if let Err(e) = ctx.emit(AuditEvent::ProcessExited {
                timestamp: ctx.timestamp(),
                pid,
                exit_code: status.code(),
                signal: status.signal(),
                oom_kill_count: oom,
            }) {
                log::error!("audit emit failed: {e}");
            }

            if let Some(ref stats) = self.final_stats {
                if let Err(e) = ctx.emit(AuditEvent::ResourceUsage {
                    timestamp: ctx.timestamp(),
                    memory_current_bytes: stats.memory_current_bytes,
                    memory_peak_bytes: stats.memory_peak_bytes,
                    cpu_seconds: stats.cpu_usage_seconds,
                    pid_count: stats.pid_count,
                    io_read_bytes: stats.io_read_bytes,
                    io_write_bytes: stats.io_write_bytes,
                }) {
                    log::error!("audit emit failed: {e}");
                }
            }
        }

        Ok(status)
    }

    /// Wait for the process to exit and return the exit status.
    #[cfg(windows)]
    pub fn wait(&mut self) -> crate::Result<std::process::ExitStatus> {
        use std::os::windows::io::AsRawHandle;
        use std::os::windows::process::ExitStatusExt;
        use windows_sys::Win32::Foundation::{HANDLE, WAIT_FAILED};
        use windows_sys::Win32::System::Threading::{
            GetExitCodeProcess, INFINITE, WaitForSingleObject,
        };

        // SAFETY: process_handle is a valid process HANDLE.
        let ret =
            unsafe { WaitForSingleObject(self.process_handle.as_raw_handle() as HANDLE, INFINITE) };
        if ret == WAIT_FAILED {
            return Err(crate::Error::Process(format!(
                "WaitForSingleObject: {}",
                std::io::Error::last_os_error()
            )));
        }

        let mut exit_code: u32 = 1;
        // SAFETY: process_handle is valid, exit_code is a valid pointer.
        let ret = unsafe {
            GetExitCodeProcess(
                self.process_handle.as_raw_handle() as HANDLE,
                &mut exit_code,
            )
        };
        if ret == 0 {
            return Err(crate::Error::Process(format!(
                "GetExitCodeProcess: {}",
                std::io::Error::last_os_error()
            )));
        }

        let status = std::process::ExitStatus::from_raw(exit_code);
        let pid = self.process_id;

        if let Some(ref ctx) = self.audit_ctx {
            if let Err(e) = ctx.emit(AuditEvent::ProcessExited {
                timestamp: ctx.timestamp(),
                pid,
                exit_code: Some(exit_code as i32),
                signal: None,
                oom_kill_count: 0,
            }) {
                log::error!("audit emit failed: {e}");
            }
        }

        Ok(status)
    }

    /// Read resource usage from the agent's cgroup.
    ///
    /// Must be called before `cleanup()` which destroys the cgroup.
    /// Returns zero values if cgroups are unavailable.
    pub fn resource_stats(&self) -> ResourceUsage {
        #[cfg(target_os = "linux")]
        if let (Some(mgr), Some(path)) = (&self.cgroup_mgr, &self.cgroup_path) {
            return mgr.read_stats(path);
        }
        ResourceUsage::default()
    }

    /// Read the OOM kill count from the agent's cgroup.
    ///
    /// Must be called before `cleanup()` which destroys the cgroup.
    /// Returns 0 if cgroups are unavailable.
    pub fn oom_count(&self) -> u32 {
        #[cfg(target_os = "linux")]
        if let (Some(mgr), Some(path)) = (&self.cgroup_mgr, &self.cgroup_path) {
            return mgr.read_oom_events(path);
        }
        0
    }

    /// Clean up the sandbox temp directory and cgroup.
    ///
    /// Must only be called after `wait()` returns.
    pub fn cleanup(self) {
        #[allow(unused_mut)]
        let mut cgroup_destroyed = false;
        #[cfg(target_os = "linux")]
        if let (Some(mgr), Some(path)) = (&self.cgroup_mgr, &self.cgroup_path) {
            cgroup_destroyed = mgr.destroy(path).is_ok();
        }

        #[cfg(windows)]
        let mut dacls_restored = true;
        #[cfg(windows)]
        let mut container_deleted = false;
        #[cfg(windows)]
        {
            for saved in &self.saved_dacls {
                if let Err(e) = crate::platform::windows::restore_dacl(saved) {
                    log::warn!("failed to restore DACL: {e}");
                    dacls_restored = false;
                }
            }
            if let Some(ref name) = self.container_name {
                container_deleted = crate::platform::windows::delete_app_container(name).is_ok();
            }
        }

        let tmpdir_removed = if self.tmp_dir.exists() {
            std::fs::remove_dir_all(&self.tmp_dir).is_ok()
        } else {
            true
        };

        if let Some(ref ctx) = self.audit_ctx {
            if let Err(e) = ctx.emit(AuditEvent::SandboxCleanup {
                timestamp: ctx.timestamp(),
                cgroup_destroyed,
                tmpdir_removed,
                #[cfg(windows)]
                dacls_restored: Some(dacls_restored),
                #[cfg(not(windows))]
                dacls_restored: None,
                #[cfg(windows)]
                container_deleted: Some(container_deleted),
                #[cfg(not(windows))]
                container_deleted: None,
            }) {
                log::error!("audit emit failed: {e}");
            }
        }
    }
}
