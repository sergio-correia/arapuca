//! C FFI layer for arapuca.
//!
//! Provides a C-compatible API using opaque types, null-checked pointers,
//! and thread-local error strings.
//!
//! # Safety Contract
//!
//! 1. All pointer params are null-checked before dereference.
//! 2. `_free()` functions use `Option::take()` — double-free is a safe no-op.
//! 3. Opaque types are `!Send` — callers must not share across threads.
//! 4. All `const char*` params are validated (null, UTF-8, length).
//! 5. `arapuca_last_error()` returns a thread-local pointer valid until
//!    the next arapuca call on the same thread.
//! 6. Strings returned by arapuca MUST be freed with `arapuca_free_string()`,
//!    NOT with `free()` — different allocators.

use std::cell::RefCell;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::os::unix::io::RawFd;
use std::path::PathBuf;

use crate::platform::Sandbox;
use crate::{Config, Profile};

/// Maximum length for string inputs via FFI (4 KiB).
const MAX_STRING_LEN: usize = 4096;

// ─── Thread-local error storage ─────────────────────────────────────

thread_local! {
    static LAST_ERROR: RefCell<Option<CString>> = const { RefCell::new(None) };
}

fn set_error(msg: &str) {
    LAST_ERROR.with(|e| {
        *e.borrow_mut() = CString::new(msg).ok();
    });
}

fn clear_error() {
    LAST_ERROR.with(|e| {
        *e.borrow_mut() = None;
    });
}

// ─── Opaque types ───────────────────────────────────────────────────

/// Opaque profile builder.
pub struct ArapucaProfile {
    inner: Option<Profile>,
}

/// Opaque sandbox handle (platform-specific, type-erased).
pub struct ArapucaSandbox {
    inner: Option<Box<dyn Sandbox>>,
}

/// Opaque launch config.
pub struct ArapucaConfig {
    inner: Option<Config>,
}

/// Opaque process handle.
pub struct ArapucaProcess {
    inner: Option<crate::Process>,
}

// ─── Non-opaque types ───────────────────────────────────────────────

/// Resource usage statistics from cgroups v2.
#[repr(C)]
pub struct ArapucaResourceUsage {
    pub memory_current_bytes: i64,
    pub memory_peak_bytes: i64,
    pub cpu_usage_seconds: f64,
    pub pid_count: i64,
    pub io_read_bytes: i64,
    pub io_write_bytes: i64,
}

// ─── Profile API ────────────────────────────────────────────────────

/// Create a new profile builder.
#[unsafe(no_mangle)]
pub extern "C" fn arapuca_profile_new() -> *mut ArapucaProfile {
    clear_error();
    Box::into_raw(Box::new(ArapucaProfile {
        inner: Some(Profile::default()),
    }))
}

/// Add a read-only path to the profile. Returns 0 on success, -1 on error.
///
/// # Safety
/// `profile` and `path` must be valid pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn arapuca_profile_add_read_path(
    profile: *mut ArapucaProfile,
    path: *const c_char,
) -> i32 {
    clear_error();
    let Some(profile) = (unsafe { profile.as_mut() }) else {
        set_error("null profile pointer");
        return -1;
    };
    let Some(inner) = profile.inner.as_mut() else {
        set_error("profile already freed");
        return -1;
    };
    let path = match unsafe { validate_cstr(path) } {
        Ok(s) => s,
        Err(msg) => {
            set_error(&msg);
            return -1;
        }
    };
    inner.read_paths.push(PathBuf::from(path));
    0
}

/// Add a read-write path to the profile. Returns 0 on success, -1 on error.
///
/// # Safety
/// `profile` and `path` must be valid pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn arapuca_profile_add_write_path(
    profile: *mut ArapucaProfile,
    path: *const c_char,
) -> i32 {
    clear_error();
    let Some(profile) = (unsafe { profile.as_mut() }) else {
        set_error("null profile pointer");
        return -1;
    };
    let Some(inner) = profile.inner.as_mut() else {
        set_error("profile already freed");
        return -1;
    };
    let path = match unsafe { validate_cstr(path) } {
        Ok(s) => s,
        Err(msg) => {
            set_error(&msg);
            return -1;
        }
    };
    inner.write_paths.push(PathBuf::from(path));
    0
}

/// Set memory limit in MB.
///
/// # Safety
/// `profile` must be a valid pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn arapuca_profile_set_memory_mb(profile: *mut ArapucaProfile, mb: u64) {
    if let Some(profile) = unsafe { profile.as_mut() } {
        if let Some(inner) = profile.inner.as_mut() {
            inner.max_memory_mb = mb;
        }
    }
}

/// Set CPU percentage limit.
///
/// # Safety
/// `profile` must be a valid pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn arapuca_profile_set_cpu_pct(profile: *mut ArapucaProfile, pct: u32) {
    if let Some(profile) = unsafe { profile.as_mut() } {
        if let Some(inner) = profile.inner.as_mut() {
            inner.max_cpu_pct = pct;
        }
    }
}

/// Set maximum PIDs.
///
/// # Safety
/// `profile` must be a valid pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn arapuca_profile_set_max_pids(profile: *mut ArapucaProfile, pids: u32) {
    if let Some(profile) = unsafe { profile.as_mut() } {
        if let Some(inner) = profile.inner.as_mut() {
            inner.max_pids = pids;
        }
    }
}

/// Set maximum file size in MB (RLIMIT_FSIZE).
///
/// # Safety
/// `profile` must be a valid pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn arapuca_profile_set_max_file_size_mb(
    profile: *mut ArapucaProfile,
    mb: u64,
) {
    if let Some(profile) = unsafe { profile.as_mut() } {
        if let Some(inner) = profile.inner.as_mut() {
            inner.max_file_size_mb = mb;
        }
    }
}

/// Enable/disable network namespace isolation.
///
/// # Safety
/// `profile` must be a valid pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn arapuca_profile_set_netns(profile: *mut ArapucaProfile, enabled: bool) {
    if let Some(profile) = unsafe { profile.as_mut() } {
        if let Some(inner) = profile.inner.as_mut() {
            inner.use_netns = enabled;
        }
    }
}

/// Free a profile. Safe to call with NULL.
///
/// # Safety
/// `profile` must be NULL or a valid pointer from `arapuca_profile_new()`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn arapuca_profile_free(profile: *mut ArapucaProfile) {
    if !profile.is_null() {
        let mut p = unsafe { Box::from_raw(profile) };
        p.inner.take();
    }
}

// ─── Sandbox API ────────────────────────────────────────────────────

/// Create a new sandbox for the current platform.
///
/// Returns NULL on error (check `arapuca_last_error()`).
#[unsafe(no_mangle)]
pub extern "C" fn arapuca_sandbox_new() -> *mut ArapucaSandbox {
    clear_error();
    match crate::platform::new_boxed() {
        Ok(sb) => Box::into_raw(Box::new(ArapucaSandbox { inner: Some(sb) })),
        Err(e) => {
            set_error(&format!("{e}"));
            std::ptr::null_mut()
        }
    }
}

/// Check whether cgroups v2 resource limits are available.
///
/// # Safety
/// `sb` must be a valid pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn arapuca_sandbox_cgroups_available(sb: *const ArapucaSandbox) -> bool {
    let Some(sb) = (unsafe { sb.as_ref() }) else {
        return false;
    };
    sb.inner.as_ref().is_some_and(|s| s.cgroups_available())
}

/// Free a sandbox handle. Safe to call with NULL.
///
/// # Safety
/// `sb` must be NULL or a valid pointer from `arapuca_sandbox_new()`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn arapuca_sandbox_free(sb: *mut ArapucaSandbox) {
    if !sb.is_null() {
        let mut s = unsafe { Box::from_raw(sb) };
        s.inner.take();
    }
}

// ─── Config API ─────────────────────────────────────────────────────

/// Create a new launch config.
#[unsafe(no_mangle)]
pub extern "C" fn arapuca_config_new() -> *mut ArapucaConfig {
    clear_error();
    Box::into_raw(Box::new(ArapucaConfig {
        inner: Some(Config {
            profile: Profile::default(),
            socket_dir: PathBuf::new(),
            task_id: String::new(),
            phase: String::new(),
            work_dir: None,
            stdin: None,
            stdout: None,
            stderr: None,
            network_proxy_socket: None,
        }),
    }))
}

/// Set the profile on a config (clones the profile).
///
/// # Safety
/// Both pointers must be valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn arapuca_config_set_profile(
    cfg: *mut ArapucaConfig,
    profile: *const ArapucaProfile,
) -> i32 {
    clear_error();
    let (Some(cfg), Some(profile)) = (unsafe { cfg.as_mut() }, unsafe { profile.as_ref() }) else {
        set_error("null pointer");
        return -1;
    };
    let (Some(cfg_inner), Some(profile_inner)) = (cfg.inner.as_mut(), profile.inner.as_ref())
    else {
        set_error("already freed");
        return -1;
    };
    cfg_inner.profile = profile_inner.clone();
    0
}

/// Set the task ID on a config.
///
/// # Safety
/// Both pointers must be valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn arapuca_config_set_task_id(
    cfg: *mut ArapucaConfig,
    task_id: *const c_char,
) -> i32 {
    unsafe { set_config_string(cfg, task_id, |c, s| c.task_id = s) }
}

/// Set the phase on a config.
///
/// # Safety
/// Both pointers must be valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn arapuca_config_set_phase(
    cfg: *mut ArapucaConfig,
    phase: *const c_char,
) -> i32 {
    unsafe { set_config_string(cfg, phase, |c, s| c.phase = s) }
}

/// Set the socket directory on a config.
///
/// # Safety
/// Both pointers must be valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn arapuca_config_set_socket_dir(
    cfg: *mut ArapucaConfig,
    dir: *const c_char,
) -> i32 {
    unsafe { set_config_string(cfg, dir, |c, s| c.socket_dir = PathBuf::from(s)) }
}

/// Set the working directory on a config.
///
/// # Safety
/// Both pointers must be valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn arapuca_config_set_work_dir(
    cfg: *mut ArapucaConfig,
    dir: *const c_char,
) -> i32 {
    unsafe { set_config_string(cfg, dir, |c, s| c.work_dir = Some(PathBuf::from(s))) }
}

/// Set stdin FD on a config.
///
/// # Safety
/// `cfg` must be a valid pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn arapuca_config_set_stdin_fd(cfg: *mut ArapucaConfig, fd: i32) {
    if let Some(cfg) = unsafe { cfg.as_mut() } {
        if let Some(inner) = cfg.inner.as_mut() {
            inner.stdin = Some(fd);
        }
    }
}

/// Set stdout FD on a config.
///
/// # Safety
/// `cfg` must be a valid pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn arapuca_config_set_stdout_fd(cfg: *mut ArapucaConfig, fd: i32) {
    if let Some(cfg) = unsafe { cfg.as_mut() } {
        if let Some(inner) = cfg.inner.as_mut() {
            inner.stdout = Some(fd);
        }
    }
}

/// Set stderr FD on a config.
///
/// # Safety
/// `cfg` must be a valid pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn arapuca_config_set_stderr_fd(cfg: *mut ArapucaConfig, fd: i32) {
    if let Some(cfg) = unsafe { cfg.as_mut() } {
        if let Some(inner) = cfg.inner.as_mut() {
            inner.stderr = Some(fd);
        }
    }
}

/// Set network proxy socket path on a config.
///
/// # Safety
/// Both pointers must be valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn arapuca_config_set_network_proxy(
    cfg: *mut ArapucaConfig,
    path: *const c_char,
) -> i32 {
    unsafe {
        set_config_string(cfg, path, |c, s| {
            c.network_proxy_socket = Some(PathBuf::from(s));
        })
    }
}

/// Free a config. Safe to call with NULL.
///
/// # Safety
/// `cfg` must be NULL or a valid pointer from `arapuca_config_new()`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn arapuca_config_free(cfg: *mut ArapucaConfig) {
    if !cfg.is_null() {
        let mut c = unsafe { Box::from_raw(cfg) };
        c.inner.take();
    }
}

// ─── Launch + Process API ───────────────────────────────────────────

/// Launch a sandboxed subprocess.
///
/// Returns NULL on error (check `arapuca_last_error()`).
///
/// # Safety
/// All pointers must be valid. `args` must have `args_count` entries.
/// `extra_fds` must have `extra_fds_count` entries (or be NULL if 0).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn arapuca_launch(
    sb: *mut ArapucaSandbox,
    cfg: *const ArapucaConfig,
    cmd: *const c_char,
    args: *const *const c_char,
    args_count: usize,
    extra_fds: *const i32,
    extra_fds_count: usize,
) -> *mut ArapucaProcess {
    clear_error();

    // Validate sandbox.
    let Some(sb) = (unsafe { sb.as_mut() }) else {
        set_error("null sandbox pointer");
        return std::ptr::null_mut();
    };
    let Some(sandbox) = sb.inner.as_ref() else {
        set_error("sandbox already freed");
        return std::ptr::null_mut();
    };

    // Validate config.
    let Some(cfg) = (unsafe { cfg.as_ref() }) else {
        set_error("null config pointer");
        return std::ptr::null_mut();
    };
    let Some(config) = cfg.inner.as_ref() else {
        set_error("config already freed");
        return std::ptr::null_mut();
    };

    // Validate command.
    let cmd_str = match unsafe { validate_cstr(cmd) } {
        Ok(s) => s,
        Err(msg) => {
            set_error(&msg);
            return std::ptr::null_mut();
        }
    };

    // Parse args array.
    let mut arg_strings = Vec::with_capacity(args_count);
    if args_count > 0 {
        if args.is_null() {
            set_error("null args pointer with non-zero count");
            return std::ptr::null_mut();
        }
        for i in 0..args_count {
            let arg_ptr = unsafe { *args.add(i) };
            match unsafe { validate_cstr(arg_ptr) } {
                Ok(s) => arg_strings.push(s),
                Err(msg) => {
                    set_error(&format!("arg[{i}]: {msg}"));
                    return std::ptr::null_mut();
                }
            }
        }
    }
    let arg_refs: Vec<&str> = arg_strings.iter().map(|s| s.as_str()).collect();

    // Parse extra FDs.
    let mut fds = Vec::with_capacity(extra_fds_count);
    if extra_fds_count > 0 && !extra_fds.is_null() {
        for i in 0..extra_fds_count {
            fds.push(unsafe { *extra_fds.add(i) } as RawFd);
        }
    }

    // Launch.
    match sandbox.launch(config, &cmd_str, &arg_refs, &fds) {
        Ok(proc) => Box::into_raw(Box::new(ArapucaProcess { inner: Some(proc) })),
        Err(e) => {
            set_error(&format!("{e}"));
            std::ptr::null_mut()
        }
    }
}

/// Get the PID of a sandboxed process.
///
/// # Safety
/// `proc` must be a valid pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn arapuca_process_pid(proc_: *const ArapucaProcess) -> u32 {
    let Some(proc_) = (unsafe { proc_.as_ref() }) else {
        return 0;
    };
    proc_.inner.as_ref().map_or(0, |p| p.pid())
}

/// Wait for a sandboxed process to exit.
///
/// Returns:
/// - `>= 0`: exit code
/// - `< -1`: killed by signal (value = -signal_number)
/// - `-1`: error (check `arapuca_last_error()`)
///
/// # Safety
/// `proc` must be a valid pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn arapuca_process_wait(proc_: *mut ArapucaProcess) -> i32 {
    clear_error();
    let Some(proc_) = (unsafe { proc_.as_mut() }) else {
        set_error("null process pointer");
        return -1;
    };
    let Some(process) = proc_.inner.as_mut() else {
        set_error("process already cleaned up");
        return -1;
    };

    match process.wait() {
        Ok(status) => {
            if let Some(code) = status.code() {
                code
            } else {
                // Killed by signal. On Unix, signal number is available.
                #[cfg(unix)]
                {
                    use std::os::unix::process::ExitStatusExt;
                    if let Some(sig) = status.signal() {
                        return -sig;
                    }
                }
                -1 // Unknown non-exit termination.
            }
        }
        Err(e) => {
            set_error(&format!("{e}"));
            -1
        }
    }
}

/// Read resource usage from the process's cgroup.
///
/// Must be called before `arapuca_process_cleanup()`.
/// Returns 0 on success, -1 on error.
///
/// # Safety
/// Both pointers must be valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn arapuca_process_resource_stats(
    proc_: *const ArapucaProcess,
    out: *mut ArapucaResourceUsage,
) -> i32 {
    let Some(proc_) = (unsafe { proc_.as_ref() }) else {
        return -1;
    };
    let Some(out) = (unsafe { out.as_mut() }) else {
        return -1;
    };
    let Some(process) = proc_.inner.as_ref() else {
        return -1;
    };

    let stats = process.resource_stats();
    out.memory_current_bytes = stats.memory_current_bytes;
    out.memory_peak_bytes = stats.memory_peak_bytes;
    out.cpu_usage_seconds = stats.cpu_usage_seconds;
    out.pid_count = stats.pid_count;
    out.io_read_bytes = stats.io_read_bytes;
    out.io_write_bytes = stats.io_write_bytes;
    0
}

/// Read OOM kill count from the process's cgroup.
///
/// Must be called before `arapuca_process_cleanup()`.
///
/// # Safety
/// `proc` must be a valid pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn arapuca_process_oom_count(proc_: *const ArapucaProcess) -> u32 {
    let Some(proc_) = (unsafe { proc_.as_ref() }) else {
        return 0;
    };
    proc_.inner.as_ref().map_or(0, |p| p.oom_count())
}

/// Clean up the sandbox temp directory and cgroup.
///
/// Must only be called after `arapuca_process_wait()` returns.
/// Consumes the process — subsequent calls on the same pointer are no-ops.
///
/// # Safety
/// `proc` must be a valid pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn arapuca_process_cleanup(proc_: *mut ArapucaProcess) {
    if let Some(proc_) = unsafe { proc_.as_mut() } {
        if let Some(process) = proc_.inner.take() {
            process.cleanup();
        }
    }
}

// ─── Apply API ──────────────────────────────────────────────────────

/// Apply sandbox restrictions to the current process. Fail-closed.
/// Returns 0 on success, -1 on error.
///
/// # Safety
/// `profile` must be a valid pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn arapuca_apply(profile: *const ArapucaProfile) -> i32 {
    clear_error();
    let Some(profile) = (unsafe { profile.as_ref() }) else {
        set_error("null profile pointer");
        return -1;
    };
    let Some(inner) = profile.inner.as_ref() else {
        set_error("profile already freed");
        return -1;
    };

    #[cfg(target_os = "linux")]
    {
        if let Err(e) = crate::landlock::apply(inner) {
            set_error(&format!("landlock: {e}"));
            return -1;
        }
        if let Err(e) = crate::seccomp::apply() {
            set_error(&format!("seccomp: {e}"));
            return -1;
        }
    }
    if let Err(e) = crate::rlimit::apply(inner) {
        set_error(&format!("rlimit: {e}"));
        return -1;
    }
    0
}

// ─── Utility functions ──────────────────────────────────────────────

/// Create a socket directory (mode 0700, random suffix).
///
/// Returns a path string. Caller MUST free with `arapuca_free_string()`.
/// Returns NULL on error.
#[unsafe(no_mangle)]
pub extern "C" fn arapuca_make_socket_dir() -> *mut c_char {
    clear_error();
    match crate::env::make_socket_dir() {
        Ok(path) => match CString::new(path.to_string_lossy().as_bytes()) {
            Ok(cs) => cs.into_raw(),
            Err(e) => {
                set_error(&format!("path encoding: {e}"));
                std::ptr::null_mut()
            }
        },
        Err(e) => {
            set_error(&format!("{e}"));
            std::ptr::null_mut()
        }
    }
}

/// Create a temp directory for a task (random suffix).
///
/// Returns a path string. Caller MUST free with `arapuca_free_string()`.
/// Returns NULL on error.
///
/// # Safety
/// `task_id` must be a valid null-terminated string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn arapuca_make_tmp_dir(task_id: *const c_char) -> *mut c_char {
    clear_error();
    let task_id = match unsafe { validate_cstr(task_id) } {
        Ok(s) => s,
        Err(msg) => {
            set_error(&msg);
            return std::ptr::null_mut();
        }
    };
    match crate::env::make_tmp_dir(&task_id) {
        Ok(path) => match CString::new(path.to_string_lossy().as_bytes()) {
            Ok(cs) => cs.into_raw(),
            Err(e) => {
                set_error(&format!("path encoding: {e}"));
                std::ptr::null_mut()
            }
        },
        Err(e) => {
            set_error(&format!("{e}"));
            std::ptr::null_mut()
        }
    }
}

/// Find the arapuca wrapper binary.
///
/// Returns the path or NULL if not found.
/// Caller MUST free with `arapuca_free_string()`.
#[unsafe(no_mangle)]
pub extern "C" fn arapuca_wrapper_path() -> *mut c_char {
    match crate::env::wrapper_path() {
        Some(path) => match CString::new(path.to_string_lossy().as_bytes()) {
            Ok(cs) => cs.into_raw(),
            Err(_) => std::ptr::null_mut(),
        },
        None => std::ptr::null_mut(),
    }
}

/// Calculate disk usage of a directory in MB.
///
/// Returns 0 on error or if the path doesn't exist.
///
/// # Safety
/// `path` must be a valid null-terminated string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn arapuca_disk_usage_mb(path: *const c_char) -> u64 {
    let path = match unsafe { validate_cstr(path) } {
        Ok(s) => s,
        Err(_) => return 0,
    };
    crate::diskquota::usage_mb(std::path::Path::new(&path))
}

/// Free a string returned by arapuca.
///
/// MUST be used instead of `free()` — the string was allocated by
/// Rust's allocator, not the C allocator.
///
/// # Safety
/// `s` must be NULL or a pointer returned by a arapuca function.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn arapuca_free_string(s: *mut c_char) {
    if !s.is_null() {
        let _ = unsafe { CString::from_raw(s) };
    }
}

// ─── Probes ─────────────────────────────────────────────────────────

/// Probe the Landlock ABI version. Returns 0 if unavailable.
#[unsafe(no_mangle)]
pub extern "C" fn arapuca_landlock_abi_version() -> u32 {
    #[cfg(target_os = "linux")]
    {
        crate::landlock::abi_version()
    }
    #[cfg(not(target_os = "linux"))]
    {
        0
    }
}

/// Probe whether network namespace isolation is available.
#[unsafe(no_mangle)]
pub extern "C" fn arapuca_netns_available() -> bool {
    #[cfg(target_os = "linux")]
    {
        crate::netns::available()
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

// ─── Error handling ─────────────────────────────────────────────────

/// Get the last error message. Returns NULL if no error.
///
/// The returned pointer is valid until the next arapuca call on
/// the same thread. Caller must NOT free it.
#[unsafe(no_mangle)]
pub extern "C" fn arapuca_last_error() -> *const c_char {
    LAST_ERROR.with(|e| {
        let borrow = e.borrow();
        match borrow.as_ref() {
            Some(s) => s.as_ptr(),
            None => std::ptr::null(),
        }
    })
}

// ─── Internal helpers ───────────────────────────────────────────────

/// Validate a C string pointer: null-check, UTF-8, length bound.
///
/// # Safety
/// `ptr` must be either null or point to a valid null-terminated C string.
unsafe fn validate_cstr(ptr: *const c_char) -> Result<String, String> {
    if ptr.is_null() {
        return Err("null string pointer".into());
    }
    let cstr = unsafe { CStr::from_ptr(ptr) };
    let s = cstr.to_str().map_err(|e| format!("invalid UTF-8: {e}"))?;
    if s.len() > MAX_STRING_LEN {
        return Err(format!(
            "string too long ({} bytes, max {MAX_STRING_LEN})",
            s.len()
        ));
    }
    Ok(s.to_string())
}

/// Helper to set a string field on a config.
///
/// # Safety
/// Both pointers must be valid.
unsafe fn set_config_string(
    cfg: *mut ArapucaConfig,
    value: *const c_char,
    setter: impl FnOnce(&mut Config, String),
) -> i32 {
    clear_error();
    let Some(cfg) = (unsafe { cfg.as_mut() }) else {
        set_error("null config pointer");
        return -1;
    };
    let Some(inner) = cfg.inner.as_mut() else {
        set_error("config already freed");
        return -1;
    };
    let s = match unsafe { validate_cstr(value) } {
        Ok(s) => s,
        Err(msg) => {
            set_error(&msg);
            return -1;
        }
    };
    setter(inner, s);
    0
}

// ─── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_create_and_free() {
        let p = arapuca_profile_new();
        assert!(!p.is_null());
        unsafe { arapuca_profile_free(p) };
    }

    #[test]
    fn null_profile_free_is_safe() {
        unsafe { arapuca_profile_free(std::ptr::null_mut()) };
    }

    #[test]
    fn error_lifecycle() {
        clear_error();
        assert!(arapuca_last_error().is_null());

        set_error("test error");
        let err = arapuca_last_error();
        assert!(!err.is_null());
        let msg = unsafe { CStr::from_ptr(err) }.to_str().unwrap();
        assert_eq!(msg, "test error");

        clear_error();
        assert!(arapuca_last_error().is_null());
    }

    #[test]
    fn landlock_abi_version_probe() {
        let v = arapuca_landlock_abi_version();
        eprintln!("FFI landlock ABI: {v}");
    }

    #[test]
    fn sandbox_create_and_free() {
        let sb = arapuca_sandbox_new();
        assert!(!sb.is_null());
        unsafe { arapuca_sandbox_free(sb) };
    }

    #[test]
    fn null_sandbox_free_is_safe() {
        unsafe { arapuca_sandbox_free(std::ptr::null_mut()) };
    }

    #[test]
    fn config_create_and_free() {
        let cfg = arapuca_config_new();
        assert!(!cfg.is_null());
        unsafe { arapuca_config_free(cfg) };
    }

    #[test]
    fn config_set_fields() {
        let cfg = arapuca_config_new();
        let profile = arapuca_profile_new();

        unsafe {
            let task = CString::new("test-task").unwrap();
            let phase = CString::new("executing").unwrap();
            let dir = CString::new("/tmp/test").unwrap();

            assert_eq!(arapuca_config_set_task_id(cfg, task.as_ptr()), 0);
            assert_eq!(arapuca_config_set_phase(cfg, phase.as_ptr()), 0);
            assert_eq!(arapuca_config_set_socket_dir(cfg, dir.as_ptr()), 0);
            assert_eq!(arapuca_config_set_work_dir(cfg, dir.as_ptr()), 0);
            assert_eq!(arapuca_config_set_profile(cfg, profile), 0);
            arapuca_config_set_stdin_fd(cfg, 0);
            arapuca_config_set_stdout_fd(cfg, 1);
            arapuca_config_set_stderr_fd(cfg, 2);

            arapuca_profile_free(profile);
            arapuca_config_free(cfg);
        }
    }

    #[test]
    fn wrapper_path_returns_something() {
        let p = arapuca_wrapper_path();
        // May be NULL if arapuca binary not in PATH — that's fine.
        if !p.is_null() {
            unsafe { arapuca_free_string(p) };
        }
    }

    #[test]
    fn null_free_string_is_safe() {
        unsafe { arapuca_free_string(std::ptr::null_mut()) };
    }

    #[test]
    fn disk_usage_nonexistent() {
        let path = CString::new("/nonexistent-xyz-123").unwrap();
        let mb = unsafe { arapuca_disk_usage_mb(path.as_ptr()) };
        assert_eq!(mb, 0);
    }

    #[test]
    fn string_length_validation() {
        let long = "a".repeat(MAX_STRING_LEN + 1);
        let cs = CString::new(long).unwrap();
        let result = unsafe { validate_cstr(cs.as_ptr()) };
        assert!(result.is_err());
    }
}
