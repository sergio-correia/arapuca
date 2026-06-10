//! Selfexec mode: allows a Go binary (via go-arapuca) to act as its
//! own Landlock/seccomp trampoline, eliminating the need for a
//! separate `arapuca` wrapper binary.
//!
//! # Architecture
//!
//! A cgo `__attribute__((constructor))` checks `ARAPUCA_WRAPPER=1`
//! AND `argv[1] == "--"` on the C side using `getenv()` and
//! `__libc_argc`/`__libc_argv`. Only when both match does it call
//! into Rust via `arapuca_handle_selfexec_if_wrapper(argc, argv)`.
//!
//! This function applies Landlock, seccomp, and rlimits, then
//! `execve`-s into the handler. It never returns.
//!
//! # Constructor context constraints
//!
//! This code runs before Go's runtime starts. All error exits use
//! `libc::_exit()` (never `std::process::exit()`). Argv comes from
//! C pointers (not `std::env::args_os()` which has init_array
//! ordering issues). Edition 2024 automatically catches unwinds
//! at `extern "C"` boundaries.

use std::sync::atomic::{AtomicBool, Ordering};

static USE_SELFEXEC: AtomicBool = AtomicBool::new(false);

pub fn enable_selfexec_mode() {
    USE_SELFEXEC.store(true, Ordering::Release);
}

pub fn selfexec_enabled() -> bool {
    USE_SELFEXEC.load(Ordering::Acquire)
}

// ─── Linux-only trampoline implementation ───────────────────────────

#[cfg(target_os = "linux")]
use std::ffi::{CStr, CString, OsStr};
#[cfg(target_os = "linux")]
use std::path::PathBuf;

/// Entry point called from the C constructor in go-arapuca.
/// The C side has already verified ARAPUCA_WRAPPER=1 AND argv[1]=="--".
/// argc/argv are passed from C (__libc_argc/__libc_argv) to avoid
/// dependency on Rust's std::env::args_os() .init_array ordering.
///
/// This function never returns — it applies sandbox restrictions
/// and exec-s into the target command, or _exit-s on failure.
#[cfg(target_os = "linux")]
#[unsafe(no_mangle)]
pub extern "C" fn arapuca_handle_selfexec_if_wrapper(
    argc: libc::c_int,
    argv: *const *const libc::c_char,
) {
    run_wrapper_path(argc, argv);
    // run_wrapper_path is -> ! so this is unreachable, but the
    // return type here is () for FFI compatibility.
}

/// Adapted extraction of the internal wrapper path from
/// bin/arapuca.rs. All error exits use _exit(1). Allocating Rust
/// stdlib calls (canonicalize, PathBuf) are acceptable here because
/// glibc initializes the allocator before .init_array processing
/// and panic="abort" prevents UB.
#[cfg(target_os = "linux")]
fn run_wrapper_path(argc: libc::c_int, argv: *const *const libc::c_char) -> ! {
    use crate::wrapper::{audit_layer, which, write_stderr};
    // ── Parse argv from C pointers ───────────────────────────────
    // argv[0] = binary, argv[1] = "--" (verified by C guard),
    // argv[2..] = command and args.
    if argc < 3 {
        write_stderr("arapuca: selfexec: missing command after --\n");
        unsafe { libc::_exit(1) };
    }

    let mut args: Vec<String> = Vec::with_capacity(argc as usize);
    for i in 0..argc {
        let ptr = unsafe { *argv.add(i as usize) };
        if ptr.is_null() {
            break;
        }
        let cstr = unsafe { CStr::from_ptr(ptr) };
        match cstr.to_str() {
            Ok(s) => args.push(s.to_string()),
            Err(_) => {
                write_stderr("arapuca: selfexec: invalid UTF-8 in argv\n");
                unsafe { libc::_exit(1) };
            }
        }
    }

    if args.len() < 3 {
        write_stderr("arapuca: selfexec: missing command after --\n");
        unsafe { libc::_exit(1) };
    }

    let cmd = &args[2];
    let cmd_args = &args[2..];

    // ── Defense-in-depth sentinel check ───────────────────────────
    // C side already verified, but replicate for safety.
    if std::env::var_os("ARAPUCA_WRAPPER").as_deref() != Some(OsStr::new("1")) {
        write_stderr("arapuca: selfexec: ARAPUCA_WRAPPER not set\n");
        unsafe { libc::_exit(1) };
    }

    // ── Audit FD ─────────────────────────────────────────────────
    let audit_fd: Option<i32> =
        std::env::var_os("ARAPUCA_AUDIT_FD").and_then(|v| v.to_str().and_then(|s| s.parse().ok()));

    // ── Resolve command path before Landlock ─────────────────────
    let cmd = if std::fs::metadata(cmd).is_ok() {
        std::fs::canonicalize(cmd)
            .unwrap_or_else(|_| PathBuf::from(cmd))
            .to_string_lossy()
            .into_owned()
    } else {
        match which(cmd) {
            Some(path) => path.to_string_lossy().into_owned(),
            None => {
                write_stderr(&format!("arapuca: selfexec: command not found: {cmd}\n"));
                unsafe { libc::_exit(1) };
            }
        }
    };

    // ── Save parent PID for race check ───────────────────────────
    let parent_pid = unsafe { libc::getppid() };

    // ── setsid ───────────────────────────────────────────────────
    // In selfexec mode, pre_exec already called setsid(), so this
    // returns EPERM. A successful setsid() clears PR_SET_PDEATHSIG;
    // EPERM does NOT clear it. The call is retained as
    // defense-in-depth in case this function is ever called without
    // a prior setsid.
    {
        let ret = unsafe { libc::setsid() };
        if ret == -1 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::EPERM) {
                write_stderr(&format!("arapuca: selfexec: setsid: {err}\n"));
                unsafe { libc::_exit(1) };
            }
        }
    }

    // ── PR_SET_PDEATHSIG — immediately after setsid ──────────────
    {
        let ret = unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) };
        if ret != 0 {
            write_stderr(&format!(
                "arapuca: selfexec: pdeathsig: {} (non-fatal)\n",
                std::io::Error::last_os_error()
            ));
        }
    }

    // ── getppid() race check ─────────────────────────────────────
    // Defense-in-depth: verify parent is still alive. In selfexec
    // mode, setsid() returns EPERM (session leader from pre_exec),
    // so pdeathsig was never cleared. This check guards against
    // hypothetical future changes or direct invocations where
    // setsid() might succeed.
    if unsafe { libc::getppid() } != parent_pid {
        unsafe { libc::_exit(1) };
    }

    audit_layer(audit_fd, "Pdeathsig", true, None);

    // ── PR_SET_NO_NEW_PRIVS ──────────────────────────────────────
    #[cfg(target_os = "linux")]
    {
        let ret = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1i64, 0i64, 0i64, 0i64) };
        if ret != 0 {
            write_stderr(&format!(
                "arapuca: selfexec: PR_SET_NO_NEW_PRIVS: {}\n",
                std::io::Error::last_os_error()
            ));
            unsafe { libc::_exit(1) };
        }
    }

    // ── Landlock ─────────────────────────────────────────────────
    #[cfg(target_os = "linux")]
    {
        let read_paths = env_paths_os("ARAPUCA_READ_PATHS");
        let write_paths = env_paths_os("ARAPUCA_WRITE_PATHS");

        let profile = crate::Profile {
            read_paths,
            write_paths,
            ..Default::default()
        };

        // Bind-mount resolv.conf when DNS capture is active.
        if std::env::var("ARAPUCA_DNS_AUDIT_FD").is_ok() {
            let ok = crate::wrapper::override_resolv_conf();
            audit_layer(audit_fd, "ResolvConfOverride", ok, None);
        }

        if let Err(e) = crate::landlock::apply(&profile) {
            audit_layer(audit_fd, "Landlock", false, Some(&e.to_string()));
            write_stderr(&format!("arapuca: selfexec: landlock: {e}\n"));
            unsafe { libc::_exit(1) };
        }
        audit_layer(audit_fd, "Landlock", true, None);
    }

    // ── Proxy bridge ──────────────────────────────────────────────
    // Fork a TCP-to-UDS relay child before seccomp is applied.
    match crate::bridge::parse_bridge_env() {
        Ok(Some((port, uds_path))) => {
            let dns_audit_fd = std::env::var("ARAPUCA_DNS_AUDIT_FD")
                .ok()
                .and_then(|s| s.parse::<i32>().ok())
                .filter(|&fd| fd >= 0);
            match crate::bridge::fork_bridge(port, Some(&uds_path), dns_audit_fd) {
                Ok(bridge_port) => {
                    let proxy = format!("http://127.0.0.1:{bridge_port}");
                    // SAFETY: single-threaded (Go runtime not started).
                    unsafe {
                        std::env::set_var("HTTP_PROXY", &proxy);
                        std::env::set_var("HTTPS_PROXY", &proxy);
                        std::env::set_var("http_proxy", &proxy);
                        std::env::set_var("https_proxy", &proxy);
                    }
                    audit_layer(audit_fd, "ProxyBridge", true, None);
                }
                Err(e) => {
                    audit_layer(audit_fd, "ProxyBridge", false, Some(&e.to_string()));
                    write_stderr(&format!("arapuca: selfexec: bridge: {e}\n"));
                    unsafe { libc::_exit(1) };
                }
            }
        }
        Ok(None) => {
            let dns_audit_fd = std::env::var("ARAPUCA_DNS_AUDIT_FD")
                .ok()
                .and_then(|s| s.parse::<i32>().ok())
                .filter(|&fd| fd >= 0);
            if let Some(dns_fd) = dns_audit_fd {
                match crate::bridge::fork_bridge(0, None, Some(dns_fd)) {
                    Ok(_) => {
                        audit_layer(audit_fd, "DnsCapture", true, None);
                    }
                    Err(e) => {
                        audit_layer(audit_fd, "DnsCapture", false, Some(&e.to_string()));
                        write_stderr(&format!("arapuca: selfexec: dns bridge: {e}\n"));
                        unsafe { libc::_exit(1) };
                    }
                }
            }
        }
        Err(e) => {
            write_stderr(&format!("arapuca: selfexec: bridge env: {e}\n"));
            unsafe { libc::_exit(1) };
        }
    }

    // ── Seccomp ──────────────────────────────────────────────────
    #[cfg(seccomp_supported)]
    {
        let seccomp_profile = match std::env::var_os("ARAPUCA_SECCOMP_PROFILE").as_deref() {
            Some(v) if v == OsStr::new("baseline") => crate::SeccompProfile::Baseline,
            _ => crate::SeccompProfile::Strict,
        };
        if let Err(e) = crate::seccomp::apply(&seccomp_profile) {
            audit_layer(audit_fd, "Seccomp", false, Some(&e.to_string()));
            write_stderr(&format!("arapuca: selfexec: seccomp: {e}\n"));
            unsafe { libc::_exit(1) };
        }
        audit_layer(audit_fd, "Seccomp", true, None);
    }
    #[cfg(not(seccomp_supported))]
    {
        audit_layer(
            audit_fd,
            "Seccomp",
            false,
            Some("not supported on this architecture"),
        );
    }

    // ── Rlimits ──────────────────────────────────────────────────
    #[cfg(unix)]
    if let Err(e) = crate::rlimit::apply_from_env() {
        audit_layer(audit_fd, "Rlimit", false, Some(&e.to_string()));
        write_stderr(&format!("arapuca: selfexec: rlimit: {e}\n"));
        unsafe { libc::_exit(1) };
    }
    #[cfg(unix)]
    audit_layer(audit_fd, "Rlimit", true, None);

    // ── Close audit FDs before exec ──────────────────────────────
    // MUST happen before execve — the parent's pipe readers block on
    // read() until all write-end holders close the FD.
    if let Some(fd) = audit_fd {
        unsafe { libc::close(fd) };
    }
    if let Some(fd) = std::env::var("ARAPUCA_DNS_AUDIT_FD")
        .ok()
        .and_then(|s| s.parse::<i32>().ok())
    {
        unsafe { libc::close(fd) };
    }

    // ── Strip ARAPUCA_* from env ─────────────────────────────────
    let env: Vec<(CString, CString)> = std::env::vars()
        .filter(|(k, _)| !k.starts_with("ARAPUCA_"))
        .map(|(k, v)| {
            let k = CString::new(k).unwrap_or_else(|_| {
                write_stderr("arapuca: selfexec: null byte in env key\n");
                unsafe { libc::_exit(1) };
            });
            let v = CString::new(v).unwrap_or_else(|_| {
                write_stderr("arapuca: selfexec: null byte in env value\n");
                unsafe { libc::_exit(1) };
            });
            (k, v)
        })
        .collect();

    // ── Build exec arguments ─────────────────────────────────────
    let c_cmd = match CString::new(cmd.as_str()) {
        Ok(c) => c,
        Err(_) => {
            write_stderr(&format!("arapuca: selfexec: invalid command: {cmd}\n"));
            unsafe { libc::_exit(1) };
        }
    };

    let c_args: Vec<CString> = cmd_args
        .iter()
        .map(|a| {
            CString::new(a.as_str()).unwrap_or_else(|_| {
                write_stderr("arapuca: selfexec: null byte in argument\n");
                unsafe { libc::_exit(1) };
            })
        })
        .collect();

    // ── execve ───────────────────────────────────────────────────
    unsafe {
        let argv_ptrs: Vec<*const libc::c_char> = c_args
            .iter()
            .map(|a| a.as_ptr())
            .chain(std::iter::once(std::ptr::null()))
            .collect();

        let envp: Vec<*const libc::c_char> = env
            .iter()
            .map(|(k, v)| {
                let kv = format!("{}={}", k.to_string_lossy(), v.to_string_lossy());
                CString::new(kv)
                    .unwrap_or_else(|_| {
                        write_stderr("arapuca: selfexec: null byte in env var\n");
                        libc::_exit(1);
                    })
                    .into_raw() as *const libc::c_char
            })
            .chain(std::iter::once(std::ptr::null()))
            .collect();

        libc::execve(c_cmd.as_ptr(), argv_ptrs.as_ptr(), envp.as_ptr());
        write_stderr(&format!(
            "arapuca: selfexec: exec {}: {}\n",
            cmd,
            std::io::Error::last_os_error()
        ));
        libc::_exit(1);
    }
}

// ─── Helpers ─────────────────────────────────────────────────────

/// Read colon-separated paths from an env var using var_os().
#[cfg(target_os = "linux")]
fn env_paths_os(name: &str) -> Vec<PathBuf> {
    use crate::wrapper::write_stderr;
    match std::env::var_os(name) {
        Some(v) => match v.to_str() {
            Some(s) => crate::env::parse_paths(s),
            None => {
                write_stderr(&format!("arapuca: selfexec: {name} is not valid UTF-8\n"));
                unsafe { libc::_exit(1) };
            }
        },
        None => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enable_then_enabled() {
        enable_selfexec_mode();
        assert!(selfexec_enabled());
    }
}
