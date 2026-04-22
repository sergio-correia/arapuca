//! Windows sandbox implementation.
//!
//! Provides process isolation via Job Objects (resource limits, UI
//! restrictions, kill-on-close), process creation via `CreateProcessW`
//! with `PROC_THREAD_ATTRIBUTE_JOB_LIST` for atomic Job assignment,
//! and environment hardening.
//!
//! Current limitations (documented as known gaps):
//! - No restricted token (child inherits parent's token)
//! - No integrity level reduction
//! - No process mitigation policies
//! - No desktop/window station isolation
//! - No filesystem isolation (requires AppContainer)
//! - No network isolation (requires AppContainer)
//! - No file size limits (no Windows per-process equivalent)

#[cfg(not(target_pointer_width = "64"))]
compile_error!("arapuca requires 64-bit Windows");

use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::Path;

use windows_sys::Win32::Foundation::{
    CloseHandle, DUPLICATE_SAME_ACCESS, DuplicateHandle, HANDLE, HANDLE_FLAG_INHERIT,
    INVALID_HANDLE_VALUE, TRUE,
};
use windows_sys::Win32::System::Console::{
    GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
};
use windows_sys::Win32::System::JobObjects::{
    CreateJobObjectW, JOB_OBJECT_CPU_RATE_CONTROL_ENABLE, JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP,
    JOB_OBJECT_LIMIT_ACTIVE_PROCESS, JOB_OBJECT_LIMIT_JOB_MEMORY,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOB_OBJECT_UILIMIT_DESKTOP,
    JOB_OBJECT_UILIMIT_DISPLAYSETTINGS, JOB_OBJECT_UILIMIT_EXITWINDOWS,
    JOB_OBJECT_UILIMIT_GLOBALATOMS, JOB_OBJECT_UILIMIT_HANDLES, JOB_OBJECT_UILIMIT_READCLIPBOARD,
    JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS, JOB_OBJECT_UILIMIT_WRITECLIPBOARD,
    JOBOBJECT_BASIC_UI_RESTRICTIONS, JOBOBJECT_CPU_RATE_CONTROL_INFORMATION,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectBasicUIRestrictions,
    JobObjectCpuRateControlInformation, JobObjectExtendedLimitInformation, SetInformationJobObject,
};
use windows_sys::Win32::System::Threading::{
    CREATE_NO_WINDOW, CREATE_UNICODE_ENVIRONMENT, CreateProcessW, DeleteProcThreadAttributeList,
    EXTENDED_STARTUPINFO_PRESENT, GetCurrentProcess, InitializeProcThreadAttributeList,
    PROCESS_INFORMATION, STARTF_USESTDHANDLES, STARTUPINFOEXW, UpdateProcThreadAttribute,
};

use crate::platform::Sandbox;
use crate::{Config, Error, process::Process};

const PROC_THREAD_ATTRIBUTE_JOB_LIST: usize = 0x0002_000D;
const PROC_THREAD_ATTRIBUTE_HANDLE_LIST: usize = 0x0002_0002;

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

        let env_vars = build_env(cfg, &tmp_dir);
        let env_block = encode_env_block(&env_vars);
        let mut cmdline = quote_args(cmd, args);

        let work_dir: Option<Vec<u16>> = cfg.work_dir.as_ref().map(|p| {
            p.as_os_str()
                .encode_wide()
                .chain(std::iter::once(0))
                .collect()
        });

        // Duplicate parent's stdio handles as inheritable copies for the
        // child. Only these handles appear in HANDLE_LIST — all other
        // handles in the parent are NOT inherited.
        let stdio_handles = duplicate_stdio().inspect_err(|_| {
            let _ = std::fs::remove_dir_all(&tmp_dir);
        })?;

        let mut handle_list = Vec::new();
        for h in &stdio_handles {
            handle_list.push(h.as_raw_handle() as HANDLE);
        }

        let job_raw = job_handle.as_raw_handle() as HANDLE;
        let mut attr_list = AttributeList::new(2).inspect_err(|_| {
            let _ = std::fs::remove_dir_all(&tmp_dir);
        })?;
        attr_list.add_job_list(&job_raw).inspect_err(|_| {
            let _ = std::fs::remove_dir_all(&tmp_dir);
        })?;
        attr_list
            .add_handle_list(&mut handle_list)
            .inspect_err(|_| {
                let _ = std::fs::remove_dir_all(&tmp_dir);
            })?;

        let mut si: STARTUPINFOEXW = unsafe { std::mem::zeroed() };
        si.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
        if handle_list.len() >= 3 {
            si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
            si.StartupInfo.hStdInput = handle_list[0];
            si.StartupInfo.hStdOutput = handle_list[1];
            si.StartupInfo.hStdError = handle_list[2];
        }
        si.lpAttributeList = attr_list.as_ptr();

        let inherit_handles = if handle_list.is_empty() { 0 } else { TRUE };

        let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

        // SAFETY: All pointers are valid. cmdline is a mutable
        // null-terminated UTF-16 buffer. env_block is a valid
        // double-null-terminated UTF-16 environment block.
        // bInheritHandles is TRUE only when HANDLE_LIST is populated,
        // restricting inheritance to explicit stdio handles. When no
        // handles exist (detached/service), FALSE prevents leaking all
        // inheritable handles to the child.
        let ret = unsafe {
            CreateProcessW(
                std::ptr::null(),
                cmdline.as_mut_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                inherit_handles,
                CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT,
                env_block.as_ptr().cast(),
                work_dir.as_ref().map_or(std::ptr::null(), |v| v.as_ptr()),
                &raw mut si.StartupInfo,
                &mut pi,
            )
        };

        drop(attr_list);

        if ret == 0 {
            let err = std::io::Error::last_os_error();
            let _ = std::fs::remove_dir_all(&tmp_dir);
            return Err(Error::Process(format!("CreateProcessW: {err}")));
        }

        // SAFETY: hThread is valid from successful CreateProcessW.
        unsafe { CloseHandle(pi.hThread) };

        // SAFETY: hProcess is valid from successful CreateProcessW.
        let process_handle =
            unsafe { OwnedHandle::from_raw_handle(pi.hProcess as *mut std::ffi::c_void) };

        Ok(Process {
            process_handle,
            process_id: pi.dwProcessId,
            tmp_dir,
            job_handle: Some(job_handle),
        })
    }

    fn available(&self) -> crate::Result<()> {
        log::warn!(
            "Windows sandbox has degraded security: no restricted token, \
             no filesystem/network isolation, no mitigation policies. \
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

// ─── Stdio handle duplication ──────────────────────────────────────

fn duplicate_stdio() -> crate::Result<Vec<OwnedHandle>> {
    let std_handles = [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE];
    let mut result = Vec::with_capacity(3);

    for &id in &std_handles {
        let h = unsafe { GetStdHandle(id) };
        if h == INVALID_HANDLE_VALUE || h == 0 as HANDLE {
            continue;
        }
        let dup = duplicate_as_inheritable(h)?;
        result.push(dup);
    }
    Ok(result)
}

fn duplicate_as_inheritable(handle: HANDLE) -> crate::Result<OwnedHandle> {
    let current = unsafe { GetCurrentProcess() };
    let mut dup: HANDLE = std::ptr::null_mut();
    // SAFETY: current process and handle are valid. The duplicated
    // handle is inheritable (bInheritHandle=TRUE) with same access.
    let ret = unsafe {
        DuplicateHandle(
            current,
            handle,
            current,
            &mut dup,
            0,
            TRUE,
            DUPLICATE_SAME_ACCESS,
        )
    };
    if ret == 0 {
        return Err(Error::Process(format!(
            "DuplicateHandle: {}",
            std::io::Error::last_os_error()
        )));
    }
    // SAFETY: dup is a valid handle from successful DuplicateHandle.
    Ok(unsafe { OwnedHandle::from_raw_handle(dup as *mut std::ffi::c_void) })
}

// ─── Attribute list RAII wrapper ───────────────────────────────────

struct AttributeList {
    buffer: Vec<u8>,
}

impl AttributeList {
    fn new(count: u32) -> crate::Result<Self> {
        let mut size: usize = 0;
        // SAFETY: First call with null determines required buffer size.
        unsafe {
            InitializeProcThreadAttributeList(std::ptr::null_mut(), count, 0, &mut size);
        }
        if size == 0 {
            return Err(Error::Process(
                "InitializeProcThreadAttributeList: size is 0".into(),
            ));
        }
        let mut buffer = vec![0u8; size];
        // SAFETY: buffer is large enough (size returned by first call).
        let ret = unsafe {
            InitializeProcThreadAttributeList(buffer.as_mut_ptr().cast(), count, 0, &mut size)
        };
        if ret == 0 {
            return Err(Error::Process(format!(
                "InitializeProcThreadAttributeList: {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(Self { buffer })
    }

    fn as_ptr(&mut self) -> *mut std::ffi::c_void {
        self.buffer.as_mut_ptr().cast()
    }

    fn add_job_list(&mut self, job: &HANDLE) -> crate::Result<()> {
        // SAFETY: self.buffer is a valid initialized attribute list.
        // job points to a valid HANDLE that outlives the attribute list.
        let ret = unsafe {
            UpdateProcThreadAttribute(
                self.as_ptr(),
                0,
                PROC_THREAD_ATTRIBUTE_JOB_LIST,
                (job as *const HANDLE).cast(),
                std::mem::size_of::<HANDLE>(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if ret == 0 {
            return Err(Error::Process(format!(
                "UpdateProcThreadAttribute(JOB_LIST): {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(())
    }

    fn add_handle_list(&mut self, handles: &mut [HANDLE]) -> crate::Result<()> {
        if handles.is_empty() {
            return Ok(());
        }
        // SAFETY: handles is a valid array that outlives the attribute list.
        let ret = unsafe {
            UpdateProcThreadAttribute(
                self.as_ptr(),
                0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                handles.as_mut_ptr().cast(),
                handles.len() * std::mem::size_of::<HANDLE>(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if ret == 0 {
            return Err(Error::Process(format!(
                "UpdateProcThreadAttribute(HANDLE_LIST): {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(())
    }
}

impl Drop for AttributeList {
    fn drop(&mut self) {
        // SAFETY: buffer was successfully initialized.
        unsafe { DeleteProcThreadAttributeList(self.as_ptr()) };
    }
}

// ─── Job Object ────────────────────────────────────────────────────

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

// ─── Environment ───────────────────────────────────────────────────

fn build_env(cfg: &Config, tmp_dir: &Path) -> Vec<(String, String)> {
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

// ─── Utilities ─────────────────────────────────────────────────────

/// Build a Windows command line from a command and arguments.
///
/// Implements `CommandLineToArgvW`-compatible quoting (MSVC C runtime
/// rules). Arguments containing spaces, tabs, or quotes are wrapped
/// in double quotes with proper backslash escaping.
///
/// Returns a null-terminated mutable UTF-16 buffer — `CreateProcessW`
/// may modify `lpCommandLine` in-place.
pub(crate) fn quote_args(cmd: &str, args: &[&str]) -> Vec<u16> {
    use std::ffi::OsStr;

    let mut cmdline = String::new();
    quote_arg(cmd, &mut cmdline);
    for arg in args {
        cmdline.push(' ');
        quote_arg(arg, &mut cmdline);
    }
    OsStr::new(&cmdline)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn quote_arg(arg: &str, out: &mut String) {
    if arg.is_empty() {
        out.push_str("\"\"");
        return;
    }
    let needs_quoting = arg.bytes().any(|b| b == b' ' || b == b'\t' || b == b'"');
    if !needs_quoting {
        out.push_str(arg);
        return;
    }
    out.push('"');
    let mut backslashes: usize = 0;
    for c in arg.chars() {
        match c {
            '\\' => backslashes += 1,
            '"' => {
                for _ in 0..backslashes {
                    out.push('\\');
                }
                backslashes = 0;
                out.push('\\');
                out.push('"');
            }
            _ => {
                for _ in 0..backslashes {
                    out.push('\\');
                }
                backslashes = 0;
                out.push(c);
            }
        }
    }
    for _ in 0..backslashes {
        out.push('\\');
    }
    out.push('"');
}

/// Encode environment variables into a Windows environment block.
///
/// The block is UTF-16 encoded, sorted by key (case-insensitive),
/// with each entry as `KEY=VALUE\0` and terminated by an extra `\0`.
/// Required for `CreateProcessW` with `CREATE_UNICODE_ENVIRONMENT`.
pub(crate) fn encode_env_block(vars: &[(String, String)]) -> Vec<u16> {
    use std::ffi::OsStr;

    let mut sorted: Vec<&(String, String)> = vars.iter().collect();
    sorted.sort_by(|a, b| a.0.to_ascii_uppercase().cmp(&b.0.to_ascii_uppercase()));

    let mut block = Vec::new();
    for (k, v) in &sorted {
        let entry = format!("{k}={v}");
        block.extend(OsStr::new(&entry).encode_wide());
        block.push(0);
    }
    block.push(0);
    block
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quote_simple() {
        let result = quote_args("cmd", &["arg1", "arg2"]);
        let s: String = result
            .iter()
            .take_while(|&&c| c != 0)
            .map(|&c| c as u8 as char)
            .collect();
        assert_eq!(s, "cmd arg1 arg2");
    }

    #[test]
    fn quote_spaces() {
        let result = quote_args("my program", &["hello world", "simple"]);
        let s: String = result
            .iter()
            .take_while(|&&c| c != 0)
            .map(|&c| c as u8 as char)
            .collect();
        assert_eq!(s, r#""my program" "hello world" simple"#);
    }

    #[test]
    fn quote_embedded_quotes() {
        let result = quote_args("cmd", &[r#"say "hello""#]);
        let s: String = result
            .iter()
            .take_while(|&&c| c != 0)
            .map(|&c| c as u8 as char)
            .collect();
        assert_eq!(s, r#"cmd "say \"hello\"""#);
    }

    #[test]
    fn quote_backslash_before_quote() {
        let result = quote_args("cmd", &[r#"path\"#]);
        let s: String = result
            .iter()
            .take_while(|&&c| c != 0)
            .map(|&c| c as u8 as char)
            .collect();
        assert_eq!(s, r"cmd path\");
    }

    #[test]
    fn quote_backslash_before_quote_with_space() {
        let result = quote_args("cmd", &[r#"c:\my dir\"#]);
        let s: String = result
            .iter()
            .take_while(|&&c| c != 0)
            .map(|&c| c as u8 as char)
            .collect();
        assert_eq!(s, r#"cmd "c:\my dir\\""#);
    }

    #[test]
    fn quote_windows_path_with_spaces() {
        let result = quote_args("cmd", &[r"C:\Program Files\app"]);
        let s: String = result
            .iter()
            .take_while(|&&c| c != 0)
            .map(|&c| c as u8 as char)
            .collect();
        assert_eq!(s, r#"cmd "C:\Program Files\app""#);
    }

    #[test]
    fn quote_empty_arg() {
        let result = quote_args("cmd", &[""]);
        let s: String = result
            .iter()
            .take_while(|&&c| c != 0)
            .map(|&c| c as u8 as char)
            .collect();
        assert_eq!(s, r#"cmd """#);
    }

    #[test]
    fn quote_null_terminated() {
        let result = quote_args("cmd", &[]);
        assert_eq!(*result.last().unwrap(), 0u16);
    }

    #[test]
    fn env_block_sorted() {
        let vars = vec![
            ("ZEBRA".into(), "1".into()),
            ("ALPHA".into(), "2".into()),
            ("middle".into(), "3".into()),
        ];
        let block = encode_env_block(&vars);
        let decoded: String = block
            .iter()
            .map(|&c| if c == 0 { '\n' } else { c as u8 as char })
            .collect();
        assert!(decoded.starts_with("ALPHA=2\n"));
        assert!(decoded.contains("middle=3\n"));
        assert!(decoded.contains("ZEBRA=1\n"));
        assert!(decoded.ends_with("\n\n"));
    }

    #[test]
    fn env_block_case_insensitive_sort() {
        let vars = vec![
            ("path".into(), "1".into()),
            ("PATH".into(), "2".into()),
            ("Path".into(), "3".into()),
        ];
        let block = encode_env_block(&vars);
        let decoded: String = block
            .iter()
            .map(|&c| if c == 0 { '\n' } else { c as u8 as char })
            .collect();
        assert!(decoded.starts_with("path=1\n"));
    }

    #[test]
    fn env_block_double_null_terminated() {
        let vars = vec![("A".into(), "1".into())];
        let block = encode_env_block(&vars);
        let len = block.len();
        assert_eq!(block[len - 1], 0);
        assert_eq!(block[len - 2], 0);
    }

    #[test]
    fn env_block_empty() {
        let block = encode_env_block(&[]);
        assert_eq!(block, vec![0u16]);
    }
}
