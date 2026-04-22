//! Windows sandbox implementation.
//!
//! Provides process isolation via Job Objects (resource limits, UI
//! restrictions, kill-on-close), process creation via `CreateProcessW`
//! with `PROC_THREAD_ATTRIBUTE_JOB_LIST` for atomic Job assignment,
//! and environment hardening.
//!
//! Current limitations (documented as known gaps):
//! - No desktop/window station isolation
//! - No filesystem isolation (requires AppContainer)
//! - No network isolation (requires AppContainer)
//! - No file size limits (no Windows per-process equivalent)

#[cfg(not(target_pointer_width = "64"))]
compile_error!("arapuca requires 64-bit Windows");

use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::{Path, PathBuf};

use windows_sys::Win32::Foundation::{
    CloseHandle, DUPLICATE_SAME_ACCESS, DuplicateHandle, HANDLE, HANDLE_FLAG_INHERIT,
    INVALID_HANDLE_VALUE, LocalFree, TRUE,
};
use windows_sys::Win32::Security::Authorization::{
    EXPLICIT_ACCESS_W, GetNamedSecurityInfoW, SE_FILE_OBJECT, SET_ACCESS, SetEntriesInAclW,
    SetNamedSecurityInfoW, TRUSTEE_IS_SID, TRUSTEE_W,
};
use windows_sys::Win32::Security::{
    CreateRestrictedToken, DISABLE_MAX_PRIVILEGE, SetTokenInformation, TOKEN_ACCESS_MASK,
    TOKEN_ADJUST_DEFAULT, TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE, TOKEN_MANDATORY_LABEL,
    TOKEN_QUERY, TokenIntegrityLevel,
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
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
use windows_sys::Win32::System::Threading::{
    CREATE_NO_WINDOW, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessW,
    DeleteProcThreadAttributeList, EXTENDED_STARTUPINFO_PRESENT, GetCurrentProcess,
    InitializeProcThreadAttributeList, OpenProcessToken, PROCESS_INFORMATION, ResumeThread,
    STARTF_USESTDHANDLES, STARTUPINFOEXW, TerminateProcess, UpdateProcThreadAttribute,
};

use crate::platform::Sandbox;
use crate::{Config, Error, process::Process};

const PROC_THREAD_ATTRIBUTE_JOB_LIST: usize = 0x0002_000D;
const PROC_THREAD_ATTRIBUTE_HANDLE_LIST: usize = 0x0002_0002;
const PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY: usize = 0x0002_0007;

// QWORD 1 of PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY.
// ACG (1 << 36, prohibit dynamic code) is deliberately omitted: it
// breaks JIT runtimes (Python, Node, Java, .NET). Add as opt-in via
// a Profile flag if needed for compiled-binary-only workloads.
const MITIGATION_POLICY: u64 = 0x01           // DEP enable
    | 0x02                                     // DEP ATL thunk enable
    | (1 << 8)                                 // mandatory ASLR
    | (1 << 12)                                // heap terminate on corruption
    | (1 << 16)                                // bottom-up ASLR
    | (1 << 20)                                // high-entropy ASLR (x64)
    | (1 << 24)                                // strict handle checks
    | (1 << 28)                                // Win32k syscall disable
    | (1 << 32)                                // extension point disable
    | (1 << 52)                                // image load no remote
    | (1 << 56); // image load no low label

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
        let mut policy = [MITIGATION_POLICY, 0u64];
        let mut attr_list = AttributeList::new(3).inspect_err(|_| {
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
        attr_list
            .add_mitigation_policy(&mut policy)
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

        // Create restricted token before spawning the process.
        let restricted_token = create_restricted_token().inspect_err(|_| {
            let _ = std::fs::remove_dir_all(&tmp_dir);
        })?;

        // Resolve NtSetInformationProcess before creating the child to
        // avoid leaving a suspended zombie if resolution fails.
        let nt_set_info = resolve_nt_set_information_process().inspect_err(|_| {
            let _ = std::fs::remove_dir_all(&tmp_dir);
        })?;

        // SAFETY: All pointers are valid. cmdline is a mutable
        // null-terminated UTF-16 buffer. env_block is a valid
        // double-null-terminated UTF-16 environment block.
        // bInheritHandles is TRUE only when HANDLE_LIST is populated,
        // restricting inheritance to explicit stdio handles. When no
        // handles exist (detached/service), FALSE prevents leaking all
        // inheritable handles to the child.
        // CREATE_SUSPENDED: process is created suspended so we can swap
        // the token before it runs any code.
        let ret = unsafe {
            CreateProcessW(
                std::ptr::null(),
                cmdline.as_mut_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                inherit_handles,
                CREATE_NO_WINDOW
                    | CREATE_SUSPENDED
                    | EXTENDED_STARTUPINFO_PRESENT
                    | CREATE_UNICODE_ENVIRONMENT,
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

        // Apply restricted token to the suspended process.
        if let Err(e) =
            apply_restricted_token(nt_set_info, pi.hProcess, pi.hThread, &restricted_token)
        {
            // Fail-closed: kill the suspended child.
            unsafe {
                TerminateProcess(pi.hProcess, 1);
                CloseHandle(pi.hThread);
                CloseHandle(pi.hProcess);
            }
            let _ = std::fs::remove_dir_all(&tmp_dir);
            return Err(e);
        }

        // Resume the thread now that the token is applied.
        let resume_ret = unsafe { ResumeThread(pi.hThread) };
        if resume_ret == u32::MAX {
            let err = std::io::Error::last_os_error();
            unsafe {
                TerminateProcess(pi.hProcess, 1);
                CloseHandle(pi.hThread);
                CloseHandle(pi.hProcess);
            }
            let _ = std::fs::remove_dir_all(&tmp_dir);
            return Err(Error::Process(format!("ResumeThread: {err}")));
        }

        // SAFETY: hThread is valid from successful CreateProcessW.
        unsafe { CloseHandle(pi.hThread) };

        // SAFETY: hProcess is valid from successful CreateProcessW.
        let process_handle = unsafe { OwnedHandle::from_raw_handle(pi.hProcess) };

        Ok(Process {
            process_handle,
            process_id: pi.dwProcessId,
            tmp_dir,
            job_handle: Some(job_handle),
            container_name: None,
            saved_dacls: Vec::new(),
        })
    }

    fn available(&self) -> crate::Result<()> {
        log::warn!(
            "Windows sandbox: no filesystem/network isolation without \
             AppContainer. See platform/windows.rs module docs for gaps."
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
    Ok(unsafe { OwnedHandle::from_raw_handle(dup) })
}

// ─── Restricted token ──────────────────────────────────────────────

fn create_restricted_token() -> crate::Result<OwnedHandle> {
    let mut token: HANDLE = std::ptr::null_mut();
    // SAFETY: GetCurrentProcess is always valid. token is a valid out pointer.
    let ret = unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            (TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ADJUST_DEFAULT | TOKEN_ASSIGN_PRIMARY)
                as TOKEN_ACCESS_MASK,
            &mut token,
        )
    };
    if ret == 0 {
        return Err(Error::Process(format!(
            "OpenProcessToken: {}",
            std::io::Error::last_os_error()
        )));
    }
    let token = unsafe { OwnedHandle::from_raw_handle(token) };

    let mut restricted: HANDLE = std::ptr::null_mut();
    // SAFETY: token is valid. DISABLE_MAX_PRIVILEGE strips all privileges.
    // No deny-only SIDs or restricting SIDs for now — those require
    // enumerating the token's groups which is complex. The privilege
    // stripping + Low IL provide meaningful privilege reduction.
    let ret = unsafe {
        CreateRestrictedToken(
            token.as_raw_handle() as HANDLE,
            DISABLE_MAX_PRIVILEGE,
            0,
            std::ptr::null(),
            0,
            std::ptr::null(),
            0,
            std::ptr::null(),
            &mut restricted,
        )
    };
    if ret == 0 {
        return Err(Error::Process(format!(
            "CreateRestrictedToken: {}",
            std::io::Error::last_os_error()
        )));
    }
    let restricted = unsafe { OwnedHandle::from_raw_handle(restricted) };

    // Lower integrity to Low (S-1-16-4096).
    set_token_integrity_low(&restricted)?;

    Ok(restricted)
}

fn set_token_integrity_low(token: &OwnedHandle) -> crate::Result<()> {
    // S-1-16-4096 (Low Mandatory Level)
    #[repr(C)]
    struct SidBuffer {
        revision: u8,
        sub_authority_count: u8,
        identifier_authority: [u8; 6],
        sub_authority: [u32; 1],
    }

    let low_sid = SidBuffer {
        revision: 1,
        sub_authority_count: 1,
        identifier_authority: [0, 0, 0, 0, 0, 16], // SECURITY_MANDATORY_LABEL_AUTHORITY
        sub_authority: [4096],                     // SECURITY_MANDATORY_LOW_RID
    };

    let label = TOKEN_MANDATORY_LABEL {
        Label: windows_sys::Win32::Security::SID_AND_ATTRIBUTES {
            Sid: (&raw const low_sid).cast::<std::ffi::c_void>() as *mut _,
            Attributes: 0x00000020, // SE_GROUP_INTEGRITY
        },
    };

    // SAFETY: token is valid, label is a valid TOKEN_MANDATORY_LABEL.
    let ret = unsafe {
        SetTokenInformation(
            token.as_raw_handle() as HANDLE,
            TokenIntegrityLevel,
            (&raw const label).cast(),
            std::mem::size_of::<TOKEN_MANDATORY_LABEL>() as u32,
        )
    };
    if ret == 0 {
        return Err(Error::Process(format!(
            "SetTokenInformation(IntegrityLevel): {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

type NtSetInformationProcessFn = unsafe extern "system" fn(
    process_handle: HANDLE,
    process_information_class: u32,
    process_information: *const std::ffi::c_void,
    process_information_length: u32,
) -> i32;

fn resolve_nt_set_information_process() -> crate::Result<NtSetInformationProcessFn> {
    let ntdll: Vec<u16> = "ntdll.dll\0".encode_utf16().collect();
    let func_name = b"NtSetInformationProcess\0";

    // SAFETY: ntdll.dll is always loaded in every Windows process.
    let module = unsafe { GetModuleHandleW(ntdll.as_ptr()) };
    if module.is_null() {
        return Err(Error::Process("GetModuleHandleW(ntdll.dll) failed".into()));
    }
    // SAFETY: module is valid, func_name is null-terminated.
    let proc = unsafe { GetProcAddress(module, func_name.as_ptr().cast()) };
    let Some(proc) = proc else {
        return Err(Error::Process(
            "NtSetInformationProcess not found in ntdll.dll".into(),
        ));
    };
    // SAFETY: proc is a valid function pointer from GetProcAddress.
    Ok(unsafe {
        std::mem::transmute::<unsafe extern "system" fn() -> isize, NtSetInformationProcessFn>(proc)
    })
}

fn apply_restricted_token(
    nt_set_info: NtSetInformationProcessFn,
    process: HANDLE,
    thread: HANDLE,
    token: &OwnedHandle,
) -> crate::Result<()> {
    // ProcessAccessToken = 9
    const PROCESS_ACCESS_TOKEN: u32 = 9;

    #[repr(C)]
    struct ProcessAccessTokenInfo {
        token: HANDLE,
        thread: HANDLE,
    }

    let info = ProcessAccessTokenInfo {
        token: token.as_raw_handle() as HANDLE,
        thread,
    };

    // SAFETY: process is a valid suspended process handle. token and
    // thread are valid handles. The process has zero started threads.
    let status = unsafe {
        nt_set_info(
            process,
            PROCESS_ACCESS_TOKEN,
            (&raw const info).cast(),
            std::mem::size_of::<ProcessAccessTokenInfo>() as u32,
        )
    };
    if status != 0 {
        return Err(Error::Process(format!(
            "NtSetInformationProcess(ProcessAccessToken): NTSTATUS 0x{status:08X}"
        )));
    }
    Ok(())
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
                std::mem::size_of_val(handles),
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

    fn add_mitigation_policy(&mut self, policy: &mut [u64; 2]) -> crate::Result<()> {
        // SAFETY: policy is a valid [u64; 2] that outlives the attribute list.
        let ret = unsafe {
            UpdateProcThreadAttribute(
                self.as_ptr(),
                0,
                PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
                policy.as_mut_ptr().cast(),
                std::mem::size_of::<[u64; 2]>(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if ret == 0 {
            return Err(Error::Process(format!(
                "UpdateProcThreadAttribute(MITIGATION_POLICY): {}",
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
    sorted.sort_by_key(|a| a.0.to_ascii_uppercase());

    let mut block = Vec::new();
    for (k, v) in &sorted {
        let entry = format!("{k}={v}");
        block.extend(OsStr::new(&entry).encode_wide());
        block.push(0);
    }
    block.push(0);
    block
}

// ─── DACL save/restore ─────────────────────────────────────────────

const DACL_SECURITY_INFORMATION: u32 = 4;
const PROTECTED_DACL_SECURITY_INFORMATION: u32 = 0x8000_0000;

/// Saved DACL state for a path — used to restore the original
/// security descriptor after the sandbox exits.
pub struct SavedDacl {
    path: PathBuf,
    sd: *mut std::ffi::c_void,
}

// SAFETY: SavedDacl holds a system-allocated security descriptor
// pointer accessed only for restoration (single-threaded). Not Sync
// because concurrent reads of the raw pointer would be unsafe.
unsafe impl Send for SavedDacl {}

impl Drop for SavedDacl {
    fn drop(&mut self) {
        if !self.sd.is_null() {
            // SAFETY: sd was allocated by GetNamedSecurityInfoW.
            unsafe { LocalFree(self.sd) };
        }
    }
}

/// Save the current DACL of a path for later restoration.
#[allow(dead_code)]
pub fn save_dacl(path: &Path) -> crate::Result<SavedDacl> {
    let wide_path: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let mut sd: *mut std::ffi::c_void = std::ptr::null_mut();

    // SAFETY: wide_path is null-terminated. sd is a valid out pointer.
    // GetNamedSecurityInfoW allocates the security descriptor; caller
    // must free with LocalFree.
    let err = unsafe {
        GetNamedSecurityInfoW(
            wide_path.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut sd,
        )
    };
    if err != 0 {
        return Err(Error::Process(format!(
            "GetNamedSecurityInfoW({}): error {err}",
            path.display()
        )));
    }

    Ok(SavedDacl {
        path: path.to_path_buf(),
        sd,
    })
}

/// Restore a previously saved DACL to its path.
pub fn restore_dacl(saved: &SavedDacl) -> crate::Result<()> {
    if saved.sd.is_null() {
        return Ok(());
    }

    let wide_path: Vec<u16> = saved
        .path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    // Extract the DACL from the saved security descriptor.
    let mut dacl: *mut std::ffi::c_void = std::ptr::null_mut();
    let mut dacl_present: i32 = 0;
    let mut dacl_defaulted: i32 = 0;

    // SAFETY: saved.sd is a valid security descriptor from
    // GetNamedSecurityInfoW.
    let ret = unsafe {
        windows_sys::Win32::Security::GetSecurityDescriptorDacl(
            saved.sd,
            &mut dacl_present,
            &mut dacl as *mut *mut _ as *mut *mut _,
            &mut dacl_defaulted,
        )
    };
    if ret == 0 {
        return Err(Error::Process(format!(
            "GetSecurityDescriptorDacl({}): {}",
            saved.path.display(),
            std::io::Error::last_os_error()
        )));
    }

    let dacl_ptr = if dacl_present != 0 {
        dacl as *const _
    } else {
        std::ptr::null()
    };

    // SAFETY: wide_path is null-terminated, dacl_ptr is valid or null.
    let err = unsafe {
        SetNamedSecurityInfoW(
            wide_path.as_ptr() as *mut _,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            dacl_ptr,
            std::ptr::null(),
        )
    };
    if err != 0 {
        return Err(Error::Process(format!(
            "SetNamedSecurityInfoW restore({}): error {err}",
            saved.path.display()
        )));
    }

    Ok(())
}

/// Grant an AppContainer SID access to a path by adding an ACE.
///
/// # Safety requirements on `sid`
/// - Must be a valid, non-null pointer to a Windows SID structure
/// - Must remain valid for the duration of this call
#[allow(dead_code)]
pub fn grant_path_access(
    path: &Path,
    sid: *mut std::ffi::c_void,
    access_mask: u32,
    inherit: bool,
) -> crate::Result<()> {
    let wide_path: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let inherit_flags: u32 = if inherit {
        1 | 2 // CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE
    } else {
        0
    };

    let mut ea: EXPLICIT_ACCESS_W = unsafe { std::mem::zeroed() };
    ea.grfAccessPermissions = access_mask;
    ea.grfAccessMode = SET_ACCESS;
    ea.grfInheritance = inherit_flags;
    ea.Trustee = unsafe { std::mem::zeroed::<TRUSTEE_W>() };
    ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea.Trustee.TrusteeType = 0; // TRUSTEE_IS_UNKNOWN — AppContainer SIDs are dynamic
    ea.Trustee.ptstrName = sid as *mut u16;

    // Get existing DACL.
    let mut existing_dacl: *mut std::ffi::c_void = std::ptr::null_mut();
    let mut sd: *mut std::ffi::c_void = std::ptr::null_mut();

    let err = unsafe {
        GetNamedSecurityInfoW(
            wide_path.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut existing_dacl as *mut *mut _ as *mut *mut _,
            std::ptr::null_mut(),
            &mut sd,
        )
    };
    if err != 0 {
        return Err(Error::Process(format!(
            "GetNamedSecurityInfoW({}): error {err}",
            path.display()
        )));
    }

    // Merge new ACE with existing DACL.
    let mut new_dacl: *mut std::ffi::c_void = std::ptr::null_mut();
    let err = unsafe {
        SetEntriesInAclW(
            1,
            &ea,
            existing_dacl as *mut _,
            &mut new_dacl as *mut *mut _ as *mut *mut _,
        )
    };

    if !sd.is_null() {
        unsafe { LocalFree(sd) };
    }

    if err != 0 {
        return Err(Error::Process(format!(
            "SetEntriesInAclW({}): error {err}",
            path.display()
        )));
    }

    // Apply the new DACL.
    let err = unsafe {
        SetNamedSecurityInfoW(
            wide_path.as_ptr() as *mut _,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            new_dacl as *const _,
            std::ptr::null(),
        )
    };

    if !new_dacl.is_null() {
        unsafe { LocalFree(new_dacl) };
    }

    if err != 0 {
        return Err(Error::Process(format!(
            "SetNamedSecurityInfoW grant({}): error {err}",
            path.display()
        )));
    }

    Ok(())
}

/// Delete an AppContainer profile by name.
pub fn delete_app_container(name: &str) -> crate::Result<()> {
    let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();

    // SAFETY: wide is a valid null-terminated UTF-16 string.
    let hr = unsafe {
        windows_sys::Win32::Security::Isolation::DeleteAppContainerProfile(wide.as_ptr())
    };
    if hr != 0 {
        return Err(Error::Process(format!(
            "DeleteAppContainerProfile({name}): HRESULT 0x{hr:08X}"
        )));
    }
    Ok(())
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
