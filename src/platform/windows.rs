//! Windows sandbox implementation.
//!
//! Provides process isolation via Job Objects (resource limits, UI
//! restrictions, kill-on-close) with environment hardening.
//!
//! Current limitations (documented as known gaps):
//! - Spawn-to-assign race: child runs briefly without Job Object
//!   limits between spawn() and AssignProcessToJobObject(). Phase 2
//!   will use CREATE_SUSPENDED + ResumeThread or
//!   PROC_THREAD_ATTRIBUTE_JOB_LIST for atomic assignment.
//! - No restricted token (child inherits parent's token)
//! - No integrity level reduction
//! - No process mitigation policies (requires STARTUPINFOEXW)
//! - No handle inheritance control (no PROC_THREAD_ATTRIBUTE_HANDLE_LIST)
//! - No desktop/window station isolation
//! - No filesystem isolation (requires AppContainer)
//! - No network isolation (requires AppContainer)
//! - No file size limits (no Windows per-process equivalent)
//!
//! These will be addressed in follow-up commits. Even without them,
//! the Job Object provides hard resource limits, UI restrictions to
//! prevent shatter attacks, and kill-on-close for parent-death cleanup.

#[cfg(not(target_pointer_width = "64"))]
compile_error!("arapuca requires 64-bit Windows");

use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::os::windows::process::CommandExt;
use std::path::Path;
use std::process::Command;

use windows_sys::Win32::Foundation::{HANDLE, HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_CPU_RATE_CONTROL_ENABLE,
    JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP, JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
    JOB_OBJECT_LIMIT_JOB_MEMORY, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOB_OBJECT_UILIMIT_DESKTOP,
    JOB_OBJECT_UILIMIT_DISPLAYSETTINGS, JOB_OBJECT_UILIMIT_EXITWINDOWS,
    JOB_OBJECT_UILIMIT_GLOBALATOMS, JOB_OBJECT_UILIMIT_HANDLES, JOB_OBJECT_UILIMIT_READCLIPBOARD,
    JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS, JOB_OBJECT_UILIMIT_WRITECLIPBOARD,
    JOBOBJECT_BASIC_UI_RESTRICTIONS, JOBOBJECT_CPU_RATE_CONTROL_INFORMATION,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectBasicUIRestrictions,
    JobObjectCpuRateControlInformation, JobObjectExtendedLimitInformation, SetInformationJobObject,
};
use windows_sys::Win32::System::Threading::CREATE_NO_WINDOW;

use crate::platform::Sandbox;
use crate::{Config, Error, process::Process};

/// Windows sandbox implementation.
pub struct Windows;

impl Windows {
    pub fn new() -> crate::Result<Self> {
        Ok(Windows)
    }
}

impl Sandbox for Windows {
    fn launch(&self, cfg: &Config, cmd: &str, args: &[&str]) -> crate::Result<Process> {
        crate::sanitize_task_id(&cfg.task_id)?;

        let tmp_dir = crate::env::make_tmp_dir(&cfg.task_id)?;

        let job_handle = create_job_object(&cfg.profile).inspect_err(|_| {
            let _ = std::fs::remove_dir_all(&tmp_dir);
        })?;

        let mut command = Command::new(cmd);
        command.args(args);
        command.creation_flags(CREATE_NO_WINDOW);

        if let Some(ref work_dir) = cfg.work_dir {
            command.current_dir(work_dir);
        }

        let env_vars = build_env(cfg, &tmp_dir);
        command.env_clear();
        for (k, v) in &env_vars {
            command.env(k, v);
        }

        // KNOWN GAP: the child starts running immediately. There is a
        // brief race window before AssignProcessToJobObject where the
        // child runs without resource limits. std::process::Command
        // does not expose the thread handle needed for CREATE_SUSPENDED
        // + ResumeThread. Phase 2 will switch to raw CreateProcessW.
        let child = command.spawn().map_err(|e| {
            let _ = std::fs::remove_dir_all(&tmp_dir);
            Error::Process(format!("start process: {e}"))
        })?;

        // SAFETY: Child's raw handle is a valid process HANDLE from
        // CreateProcessW. AssignProcessToJobObject requires
        // PROCESS_SET_QUOTA | PROCESS_TERMINATE access, which the
        // creator process has by default.
        let ret = unsafe {
            AssignProcessToJobObject(
                job_handle.as_raw_handle() as HANDLE,
                child.as_raw_handle() as HANDLE,
            )
        };
        if ret == 0 {
            let err = std::io::Error::last_os_error();
            // Fail-closed: kill the child — it must not run without
            // resource limits. On Windows, Child::drop only closes the
            // handle; it does not terminate the process.
            let mut child = child;
            let _ = child.kill();
            let _ = child.wait();
            let _ = std::fs::remove_dir_all(&tmp_dir);
            return Err(Error::Process(format!(
                "assign process to job object: {err}"
            )));
        }

        Ok(Process {
            child,
            tmp_dir,
            job_handle: Some(job_handle),
        })
    }

    fn available(&self) -> crate::Result<()> {
        log::warn!(
            "Windows sandbox has degraded security: no restricted token, \
             no filesystem/network isolation, spawn-to-assign race window. \
             See platform/windows.rs module docs for full gap list."
        );
        Ok(())
    }

    fn netns_available(&self) -> bool {
        false
    }

    fn cgroups_available(&self) -> bool {
        false
    }
}

fn create_job_object(profile: &crate::Profile) -> crate::Result<OwnedHandle> {
    // SAFETY: CreateJobObjectW with NULL security attributes and name
    // creates an anonymous Job Object.
    let raw = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
    if raw == INVALID_HANDLE_VALUE || raw == 0 as HANDLE {
        return Err(Error::Process(format!(
            "CreateJobObjectW: {}",
            std::io::Error::last_os_error()
        )));
    }
    // SAFETY: raw is a valid handle we own (verified above).
    let handle = unsafe { OwnedHandle::from_raw_handle(raw) };

    // Make the handle non-inheritable so the child can't hold it open
    // (which would defeat kill-on-close). Fail-closed if this fails.
    // SAFETY: handle is a valid Job Object handle.
    let ret = unsafe {
        windows_sys::Win32::Foundation::SetHandleInformation(
            handle.as_raw_handle() as HANDLE,
            HANDLE_FLAG_INHERIT,
            0,
        )
    };
    if ret == 0 {
        return Err(Error::Process(format!(
            "SetHandleInformation(non-inheritable): {}",
            std::io::Error::last_os_error()
        )));
    }

    set_job_limits(&handle, profile)?;
    set_job_ui_restrictions(&handle)?;

    Ok(handle)
}

fn set_job_limits(handle: &OwnedHandle, profile: &crate::Profile) -> crate::Result<()> {
    let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };

    info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;

    if profile.max_memory_mb > 0 {
        info.JobMemoryLimit = (profile.max_memory_mb * 1024 * 1024) as usize;
        info.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_JOB_MEMORY;
    }

    if profile.max_pids > 0 {
        info.BasicLimitInformation.ActiveProcessLimit = profile.max_pids;
        info.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
    }

    // SAFETY: handle is a valid Job Object, info is a valid struct.
    let ret = unsafe {
        SetInformationJobObject(
            handle.as_raw_handle() as HANDLE,
            JobObjectExtendedLimitInformation,
            (&raw const info).cast(),
            std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )
    };
    if ret == 0 {
        return Err(Error::Process(format!(
            "SetInformationJobObject(ExtendedLimit): {}",
            std::io::Error::last_os_error()
        )));
    }

    if profile.max_cpu_pct > 0 {
        set_job_cpu_limit(handle, profile.max_cpu_pct)?;
    }

    Ok(())
}

fn set_job_cpu_limit(handle: &OwnedHandle, cpu_pct: u32) -> crate::Result<()> {
    let mut info: JOBOBJECT_CPU_RATE_CONTROL_INFORMATION = unsafe { std::mem::zeroed() };
    info.ControlFlags = JOB_OBJECT_CPU_RATE_CONTROL_ENABLE | JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP;
    // CpuRate is in hundredths of a percent of total system CPU (1-10000).
    // Linux cgroups use per-core percentage (200 = 2 cores), so we divide
    // by core count to translate. Falls back to 1 core if unavailable,
    // which errs on the side of more restrictive.
    let num_cpus = std::thread::available_parallelism()
        .map(|n| n.get() as u64)
        .unwrap_or(1);
    let rate = (u64::from(cpu_pct) * 100 / num_cpus).clamp(1, 10000) as u32;
    info.Anonymous.CpuRate = rate;

    // SAFETY: handle is a valid Job Object, info is a valid struct.
    let ret = unsafe {
        SetInformationJobObject(
            handle.as_raw_handle() as HANDLE,
            JobObjectCpuRateControlInformation,
            (&raw const info).cast(),
            std::mem::size_of::<JOBOBJECT_CPU_RATE_CONTROL_INFORMATION>() as u32,
        )
    };
    if ret == 0 {
        return Err(Error::Process(format!(
            "SetInformationJobObject(CpuRate): {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

fn set_job_ui_restrictions(handle: &OwnedHandle) -> crate::Result<()> {
    let info = JOBOBJECT_BASIC_UI_RESTRICTIONS {
        UIRestrictionsClass: JOB_OBJECT_UILIMIT_HANDLES
            | JOB_OBJECT_UILIMIT_READCLIPBOARD
            | JOB_OBJECT_UILIMIT_WRITECLIPBOARD
            | JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS
            | JOB_OBJECT_UILIMIT_DISPLAYSETTINGS
            | JOB_OBJECT_UILIMIT_GLOBALATOMS
            | JOB_OBJECT_UILIMIT_DESKTOP
            | JOB_OBJECT_UILIMIT_EXITWINDOWS,
    };

    // SAFETY: handle is a valid Job Object, info is a valid struct.
    let ret = unsafe {
        SetInformationJobObject(
            handle.as_raw_handle() as HANDLE,
            JobObjectBasicUIRestrictions,
            (&raw const info).cast(),
            std::mem::size_of::<JOBOBJECT_BASIC_UI_RESTRICTIONS>() as u32,
        )
    };
    if ret == 0 {
        return Err(Error::Process(format!(
            "SetInformationJobObject(UIRestrictions): {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

fn build_env(cfg: &Config, tmp_dir: &Path) -> Vec<(String, String)> {
    // Start with filtered caller vars, then override with safe defaults.
    // Command::env uses last-write-wins, so safe defaults must come last
    // to prevent caller-supplied PATH/SystemRoot/etc. from taking effect.
    let mut env: Vec<(String, String)> = crate::env::filter_caller_env(&cfg.env);

    if let Some(ref proxy) = cfg.network_proxy_socket {
        env.push((
            "AGENT_NETWORK_PROXY".into(),
            proxy.to_string_lossy().into_owned(),
        ));
    }

    let system_root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());

    env.push(("USERPROFILE".into(), tmp_dir.to_string_lossy().into_owned()));
    env.push(("TEMP".into(), tmp_dir.to_string_lossy().into_owned()));
    env.push(("TMP".into(), tmp_dir.to_string_lossy().into_owned()));
    env.push((
        "PATH".into(),
        format!(r"{system_root}\system32;{system_root}"),
    ));
    env.push(("SystemRoot".into(), system_root));
    env.push(("LANG".into(), "C.UTF-8".into()));

    env
}
