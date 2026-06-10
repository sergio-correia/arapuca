//! Sandboxed process lifecycle.
//!
//! Represents a running sandboxed subprocess with methods for waiting,
//! reading resource usage, and cleanup.

use std::path::PathBuf;

#[cfg(unix)]
use std::os::unix::io::AsFd;

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
    /// DNS audit pipe read end. Read in wait() after child exits.
    #[cfg(target_os = "linux")]
    pub(crate) dns_audit_pipe: Option<std::os::unix::io::RawFd>,
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
    /// Passt network proxy handle (micro-VM only). Kept alive for
    /// the VM's lifetime; killed on cleanup/drop.
    #[cfg(all(target_os = "linux", feature = "microvm"))]
    pub(crate) passt: Option<crate::platform::microvm_net::PasstHandle>,
    /// PTY master FD (parent side). Present when `Config::tty` was set.
    /// The caller should proxy I/O on this FD via `pty_master()`.
    /// Closed automatically on drop.
    #[cfg(unix)]
    pub(crate) pty_master: Option<std::os::unix::io::OwnedFd>,
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

    /// Path to the process's temporary directory.
    pub fn tmp_dir(&self) -> &std::path::Path {
        &self.tmp_dir
    }

    /// Returns the PTY master FD, if TTY mode was requested.
    ///
    /// The returned `BorrowedFd` is lifetime-bound to this `Process`,
    /// preventing use-after-close.
    #[cfg(unix)]
    pub fn pty_master(&self) -> Option<std::os::unix::io::BorrowedFd<'_>> {
        self.pty_master.as_ref().map(|fd| fd.as_fd())
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
                // Mark as reaped so Drop's *pid > 0 guard skips it,
                // preventing SIGKILL to a recycled PID.
                *child_pid = 0;
                std::process::ExitStatus::from_raw(wstatus)
            }
        };

        // Read DNS audit pipe before emitting ProcessExited, so
        // NetworkBlocked events appear in the event stream before
        // the exit event.
        self.read_dns_audit_pipe(pid);

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

    /// Read DNS audit events from the bridge child's pipe and emit
    /// `NetworkBlocked` events via the audit context.
    #[cfg(target_os = "linux")]
    #[cfg_attr(not(feature = "serde"), allow(unused_variables))]
    fn read_dns_audit_pipe(&mut self, pid: u32) {
        let fd = match self.dns_audit_pipe.take() {
            Some(fd) => fd,
            None => return,
        };

        // Poll with a 1-second timeout — the bridge should be dead
        // (pdeathsig) by now, but SIGKILL delivery is asynchronous.
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let poll_ret = loop {
            let ret = unsafe { libc::poll(&mut pfd, 1, 1000) };
            if ret >= 0 || std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
                break ret;
            }
        };
        if poll_ret == 0 {
            log::warn!("DNS audit pipe: timeout waiting for EOF (bridge may still be alive)");
            unsafe { libc::close(fd) };
            return;
        }

        // Read all available data. Set O_NONBLOCK so we never block
        // waiting for the bridge child to die (SIGKILL is asynchronous).
        unsafe {
            let flags = libc::fcntl(fd, libc::F_GETFL);
            if flags >= 0 {
                libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
            }
        }
        let mut data = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
            if n < 0 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                if err.raw_os_error() == Some(libc::EAGAIN) {
                    let mut pfd = libc::pollfd {
                        fd,
                        events: libc::POLLIN,
                        revents: 0,
                    };
                    let ret = unsafe { libc::poll(&mut pfd, 1, 1000) };
                    if ret <= 0 {
                        break;
                    }
                    continue;
                }
                break;
            }
            if n == 0 {
                break;
            }
            data.extend_from_slice(&buf[..n as usize]);
        }
        unsafe { libc::close(fd) };

        #[cfg(not(feature = "serde"))]
        if !data.is_empty() {
            log::warn!(
                "DNS audit: {} bytes discarded (compile with 'serde' feature to emit events)",
                data.len()
            );
        }

        #[cfg(feature = "serde")]
        if !data.is_empty() {
            let ctx = match self.audit_ctx {
                Some(ref ctx) => ctx,
                None => return,
            };
            let text = String::from_utf8_lossy(&data);
            for line in text.lines() {
                if line.is_empty() {
                    continue;
                }
                #[derive(serde::Deserialize)]
                struct DnsAuditLine {
                    domain: String,
                    qtype: String,
                }
                match serde_json::from_str::<DnsAuditLine>(line) {
                    Ok(entry) => {
                        if let Err(e) = ctx.emit(AuditEvent::NetworkBlocked {
                            timestamp: ctx.timestamp(),
                            pid,
                            destination: entry.domain,
                            protocol: "dns".into(),
                            detail: Some(entry.qtype),
                        }) {
                            log::error!("audit emit failed: {e}");
                        }
                    }
                    Err(e) => {
                        log::debug!("DNS audit: skipping malformed line: {e}");
                    }
                }
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn read_dns_audit_pipe(&mut self, _pid: u32) {}

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
    /// Must only be called after `wait()` returns. Uses `take()` on
    /// cgroup/Windows fields so Drop sees None and does not double-
    /// cleanup. For tmpdir, Drop uses an `exists()` guard instead
    /// (tmpdir stays PathBuf to preserve the public API).
    #[allow(unused_mut)]
    pub fn cleanup(mut self) {
        #[allow(unused_mut)]
        let mut cgroup_destroyed = false;
        #[cfg(target_os = "linux")]
        {
            let mgr = self.cgroup_mgr.take();
            let path = self.cgroup_path.take();
            if let (Some(mgr), Some(path)) = (&mgr, &path) {
                cgroup_destroyed = mgr.destroy(path).is_ok();
            }
        }

        #[cfg(windows)]
        let mut dacls_restored = true;
        #[cfg(windows)]
        let mut container_deleted = false;
        #[cfg(windows)]
        {
            let saved_dacls = std::mem::take(&mut self.saved_dacls);
            for saved in &saved_dacls {
                if let Err(e) = crate::platform::windows::restore_dacl(saved) {
                    log::warn!("failed to restore DACL: {e}");
                    dacls_restored = false;
                }
            }
            if let Some(name) = self.container_name.take() {
                container_deleted = crate::platform::windows::delete_app_container(&name).is_ok();
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

impl Drop for Process {
    fn drop(&mut self) {
        // Kill the child process first to ensure resources can be
        // reclaimed. Without this, cgroups can't be destroyed while
        // occupied, and a live process would run unsupervised after
        // its containment is removed.
        #[cfg(not(windows))]
        match &mut self.child {
            ChildHandle::Managed(c) => {
                let _ = c.kill();
                let _ = c.wait();
            }
            ChildHandle::Forked(pid) if *pid > 0 => {
                // SAFETY: kill and waitpid on a valid PID.
                unsafe {
                    libc::kill(*pid as libc::pid_t, libc::SIGKILL);
                    libc::waitpid(*pid as libc::pid_t, std::ptr::null_mut(), 0);
                }
            }
            _ => {}
        }

        #[cfg(target_os = "linux")]
        if let Some(fd) = self.dns_audit_pipe.take() {
            unsafe { libc::close(fd) };
        }

        #[cfg(target_os = "linux")]
        if let (Some(mgr), Some(path)) = (&self.cgroup_mgr, &self.cgroup_path) {
            let _ = mgr.destroy(path);
        }

        #[cfg(windows)]
        {
            for saved in &self.saved_dacls {
                let _ = crate::platform::windows::restore_dacl(saved);
            }
            if let Some(ref name) = self.container_name {
                let _ = crate::platform::windows::delete_app_container(name);
            }
        }

        if self.tmp_dir.exists() {
            let _ = std::fs::remove_dir_all(&self.tmp_dir);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(windows))]
    #[test]
    fn process_drop_cleans_tmpdir() {
        let dir = crate::env::make_tmp_dir("drop-test").unwrap();
        assert!(dir.exists());
        {
            let child = std::process::Command::new("true")
                .spawn()
                .expect("failed to spawn true");
            let _process = Process {
                child: ChildHandle::Managed(child),
                tmp_dir: dir.clone(),
                #[cfg(target_os = "linux")]
                cgroup_path: None,
                #[cfg(target_os = "linux")]
                cgroup_mgr: None,
                #[cfg(target_os = "linux")]
                dns_audit_pipe: None,
                #[cfg(all(target_os = "linux", feature = "microvm"))]
                passt: None,
                pty_master: None,
                audit_ctx: None,
                final_stats: None,
            };
        }
        assert!(!dir.exists(), "Drop should have removed the tmpdir");
    }

    #[cfg(all(target_os = "linux", feature = "serde"))]
    #[test]
    fn dns_audit_pipe_emits_network_blocked() {
        use std::sync::{Arc, Mutex};

        struct VecSink(Mutex<Vec<crate::audit::AuditEvent>>);
        impl crate::audit::AuditSink for VecSink {
            fn emit(&self, event: crate::audit::AuditEvent) {
                self.0.lock().unwrap().push(event);
            }
        }

        let mut pipe_fds = [0i32; 2];
        assert_eq!(
            unsafe { libc::pipe2(pipe_fds.as_mut_ptr(), libc::O_CLOEXEC) },
            0
        );
        let pipe_read = pipe_fds[0];
        let pipe_write = pipe_fds[1];

        let ndjson = b"{\"domain\":\"evil.example.com\",\"qtype\":\"A\"}\n\
                       {\"domain\":\"bad.test\",\"qtype\":\"AAAA\"}\n";
        unsafe {
            libc::write(pipe_write, ndjson.as_ptr().cast(), ndjson.len());
            libc::close(pipe_write);
        }

        let vec_sink = Arc::new(VecSink(Mutex::new(Vec::new())));
        let sink: Arc<dyn crate::audit::AuditSink> = Arc::clone(&vec_sink) as _;
        let ctx = crate::audit::AuditContext::new(sink, crate::audit::AuditVerbosity::Standard);

        let dir = crate::env::make_tmp_dir("dns-audit-test").unwrap();
        let child = std::process::Command::new("true")
            .spawn()
            .expect("failed to spawn true");
        let mut process = Process {
            child: ChildHandle::Managed(child),
            tmp_dir: dir,
            cgroup_path: None,
            cgroup_mgr: None,
            dns_audit_pipe: Some(pipe_read),
            #[cfg(target_os = "macos")]
            launch_timestamp: None,
            #[cfg(all(target_os = "linux", feature = "microvm"))]
            passt: None,
            pty_master: None,
            audit_ctx: Some(ctx),
            final_stats: None,
        };

        process.read_dns_audit_pipe(42);

        let captured = vec_sink.0.lock().unwrap();
        let blocked: Vec<_> = captured
            .iter()
            .filter(|e| matches!(e, crate::audit::AuditEvent::NetworkBlocked { .. }))
            .collect();
        assert_eq!(blocked.len(), 2, "should emit 2 NetworkBlocked events");

        if let crate::audit::AuditEvent::NetworkBlocked {
            destination,
            protocol,
            detail,
            ..
        } = &blocked[0]
        {
            assert_eq!(destination, "evil.example.com");
            assert_eq!(protocol, "dns");
            assert_eq!(detail.as_deref(), Some("A"));
        } else {
            panic!("expected NetworkBlocked");
        }

        if let crate::audit::AuditEvent::NetworkBlocked {
            destination,
            detail,
            ..
        } = &blocked[1]
        {
            assert_eq!(destination, "bad.test");
            assert_eq!(detail.as_deref(), Some("AAAA"));
        } else {
            panic!("expected NetworkBlocked");
        }
    }
}
