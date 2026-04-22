//! Sandboxed process lifecycle.
//!
//! Represents a running sandboxed subprocess with methods for waiting,
//! reading resource usage, and cleanup.

use std::path::PathBuf;

use crate::ResourceUsage;

/// A running sandboxed subprocess.
pub struct Process {
    /// The child process handle (Unix platforms).
    #[cfg(not(windows))]
    pub(crate) child: std::process::Child,
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
}

impl Process {
    /// Get the PID of the sandboxed process.
    #[cfg(not(windows))]
    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    /// Get the PID of the sandboxed process.
    #[cfg(windows)]
    pub fn pid(&self) -> u32 {
        self.process_id
    }

    /// Wait for the process to exit and return the exit status.
    #[cfg(not(windows))]
    pub fn wait(&mut self) -> crate::Result<std::process::ExitStatus> {
        self.child
            .wait()
            .map_err(|e| crate::Error::Process(format!("wait: {e}")))
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

        Ok(std::process::ExitStatus::from_raw(exit_code))
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
        if self.tmp_dir.exists() {
            let _ = std::fs::remove_dir_all(&self.tmp_dir);
        }
    }
}
