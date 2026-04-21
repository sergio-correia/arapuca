//! Arapuca CLI binary.
//!
//! Applies sandbox restrictions to the current process, then exec()s
//! the target command. This is a drop-in replacement for agent-sandbox.
//!
//! Configuration via environment variables:
//!
//!   ARAPUCA_READ_PATHS:   colon-separated readable paths
//!   ARAPUCA_WRITE_PATHS:  colon-separated writable paths
//!   ARAPUCA_RLIMIT_AS:    max virtual memory in bytes (0 = no limit)
//!   ARAPUCA_RLIMIT_NPROC: max processes (0 = no limit)
//!   ARAPUCA_RLIMIT_CPU:   max CPU seconds (0 = no limit)
//!   ARAPUCA_RLIMIT_FSIZE: max file size in bytes (0 = no limit)
//!
//! Usage: arapuca -- command [args...]

use std::ffi::CString;
use std::path::PathBuf;

fn main() {
    // Find -- separator.
    let args: Vec<String> = std::env::args().collect();
    let sep_idx = args.iter().position(|a| a == "--");
    let cmd_idx = match sep_idx {
        Some(i) if i + 1 < args.len() => i + 1,
        _ => {
            eprintln!("arapuca: usage: arapuca -- command [args...]");
            std::process::exit(1);
        }
    };

    let cmd = &args[cmd_idx];
    let cmd_args = &args[cmd_idx..];

    // Validate command exists before applying restrictions (Landlock
    // would block the stat after apply).
    if std::fs::metadata(cmd).is_err() {
        // Try PATH lookup.
        if which(cmd).is_none() {
            eprintln!("arapuca: command not found: {cmd}");
            std::process::exit(1);
        }
    }

    // Apply sandbox restrictions. Fail-closed: exit non-zero if any
    // step fails. The subprocess never runs unsandboxed.

    // 1. Landlock filesystem restrictions (Linux only).
    // 2. Seccomp BPF syscall filter (Linux only).
    #[cfg(target_os = "linux")]
    {
        let read_paths = env_paths("ARAPUCA_READ_PATHS");
        let write_paths = env_paths("ARAPUCA_WRITE_PATHS");

        let profile = arapuca::Profile {
            read_paths,
            write_paths,
            ..Default::default()
        };

        if let Err(e) = arapuca::landlock::apply(&profile) {
            eprintln!("arapuca: landlock: {e}");
            std::process::exit(1);
        }
        if let Err(e) = arapuca::seccomp::apply() {
            eprintln!("arapuca: seccomp: {e}");
            std::process::exit(1);
        }
    }

    // 3. Resource limits from env vars (Unix only).
    #[cfg(unix)]
    if let Err(e) = arapuca::rlimit::apply_from_env() {
        eprintln!("arapuca: rlimit: {e}");
        std::process::exit(1);
    }

    // 4. Pdeathsig — kill subprocess if parent dies (Linux only).
    #[cfg(target_os = "linux")]
    {
        // SAFETY: prctl with PR_SET_PDEATHSIG is a simple setter, no
        // pointer arguments. Affects only the calling thread.
        let ret = unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) };
        if ret != 0 {
            eprintln!(
                "arapuca: pdeathsig: {} (non-fatal)",
                std::io::Error::last_os_error()
            );
        }
    }

    // Strip ARAPUCA_* env vars so the agent can't inspect its own
    // sandbox configuration. Non-ARAPUCA env vars (e.g., agent-facing
    // proxy socket config) are preserved.
    let env: Vec<(CString, CString)> = std::env::vars()
        .filter(|(k, _)| !k.starts_with("ARAPUCA_"))
        .filter_map(|(k, v)| {
            let k = CString::new(k).ok()?;
            let v = CString::new(v).ok()?;
            Some((k, v))
        })
        .collect();

    // Build the exec arguments.
    let c_cmd = CString::new(cmd.as_str()).unwrap_or_else(|_| {
        eprintln!("arapuca: invalid command: {cmd}");
        std::process::exit(1);
    });

    let c_args: Vec<CString> = cmd_args
        .iter()
        .filter_map(|a| CString::new(a.as_str()).ok())
        .collect();

    // Exec the target command (Unix: replaces process, Windows: spawn-and-wait).
    #[cfg(unix)]
    {
        // SAFETY: All CStrings are valid, null-terminated, and live until
        // execve replaces the process image.
        unsafe {
            let argv: Vec<*const libc::c_char> = c_args
                .iter()
                .map(|a| a.as_ptr())
                .chain(std::iter::once(std::ptr::null()))
                .collect();

            let envp: Vec<*const libc::c_char> = env
                .iter()
                .map(|(k, v)| {
                    // Leak a "key=value" CString for the envp array.
                    // This is fine because execve replaces the process.
                    let kv = format!("{}={}", k.to_string_lossy(), v.to_string_lossy());
                    CString::new(kv).unwrap().into_raw() as *const libc::c_char
                })
                .chain(std::iter::once(std::ptr::null()))
                .collect();

            let ret = libc::execve(c_cmd.as_ptr(), argv.as_ptr(), envp.as_ptr());
            if ret == -1 {
                eprintln!("arapuca: exec {}: {}", cmd, std::io::Error::last_os_error());
                std::process::exit(1);
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (c_cmd, c_args, env);
        eprintln!("arapuca: binary not yet supported on this platform");
        std::process::exit(1);
    }
}

/// Parse colon-separated paths from an environment variable.
#[cfg(target_os = "linux")]
fn env_paths(name: &str) -> Vec<PathBuf> {
    match std::env::var(name) {
        Ok(v) => arapuca::env::parse_paths(&v),
        Err(_) => Vec::new(),
    }
}

/// Simple PATH lookup for a command name.
fn which(cmd: &str) -> Option<PathBuf> {
    let path_var = std::env::var("PATH").ok()?;
    for dir in path_var.split(':') {
        let candidate = PathBuf::from(dir).join(cmd);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}
