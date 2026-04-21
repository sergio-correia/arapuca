//! Sandboxed process lifecycle.
//!
//! Represents a running sandboxed subprocess with methods for waiting,
//! reading resource usage, and cleanup.

use std::path::PathBuf;

use crate::ResourceUsage;

/// A running sandboxed subprocess.
pub struct Process {
    /// The child process handle.
    pub(crate) child: std::process::Child,
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
    #[allow(dead_code)] // read via Drop — OwnedHandle::drop closes the handle
    pub(crate) job_handle: Option<std::os::windows::io::OwnedHandle>,
}

impl Process {
    /// Get the PID of the sandboxed process.
    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    /// Wait for the process to exit and return the exit status.
    pub fn wait(&mut self) -> crate::Result<std::process::ExitStatus> {
        self.child
            .wait()
            .map_err(|e| crate::Error::Process(format!("wait: {e}")))
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
        #[cfg(target_os = "linux")]
        if let (Some(mgr), Some(path)) = (&self.cgroup_mgr, &self.cgroup_path) {
            let _ = mgr.destroy(path);
        }
        // On Windows, dropping job_handle closes it. Since the child
        // has already exited (wait() returned), this is a no-op. If
        // the parent crashes before cleanup(), the Drop still fires,
        // triggering kill-on-close as a safety net.
        if self.tmp_dir.exists() {
            let _ = std::fs::remove_dir_all(&self.tmp_dir);
        }
    }
}
