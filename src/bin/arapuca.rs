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
    // Audit FD: if set, write JSON status lines as each layer is applied.
    // The library creates a pipe and passes the write end via this env var.
    // Closed before execve so the target command cannot write to it.
    let audit_fd: Option<i32> = std::env::var("ARAPUCA_AUDIT_FD")
        .ok()
        .and_then(|s| s.parse().ok());

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
            audit_layer(audit_fd, "Landlock", false, Some(&e.to_string()));
            eprintln!("arapuca: landlock: {e}");
            std::process::exit(1);
        }
        audit_layer(audit_fd, "Landlock", true, None);

        if let Err(e) = arapuca::seccomp::apply() {
            audit_layer(audit_fd, "Seccomp", false, Some(&e.to_string()));
            eprintln!("arapuca: seccomp: {e}");
            std::process::exit(1);
        }
        audit_layer(audit_fd, "Seccomp", true, None);
    }

    // 3. Resource limits from env vars (Unix only).
    #[cfg(unix)]
    if let Err(e) = arapuca::rlimit::apply_from_env() {
        audit_layer(audit_fd, "Rlimit", false, Some(&e.to_string()));
        eprintln!("arapuca: rlimit: {e}");
        std::process::exit(1);
    }
    #[cfg(unix)]
    audit_layer(audit_fd, "Rlimit", true, None);

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
        audit_layer(audit_fd, "Pdeathsig", true, None);
    }

    // Close audit FD before exec — the target command must not inherit it.
    #[cfg(unix)]
    if let Some(fd) = audit_fd {
        // SAFETY: fd is a valid file descriptor from ARAPUCA_AUDIT_FD.
        unsafe { libc::close(fd) };
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

/// Write an audit status line to the audit FD (if set).
///
/// Writes newline-delimited JSON. Errors are silently ignored — audit
/// is observability, not a security gate.
#[cfg(unix)]
fn audit_layer(fd: Option<i32>, layer: &str, ok: bool, error: Option<&str>) {
    let Some(fd) = fd else { return };
    let status = if ok { "applied" } else { "failed" };
    let json = if let Some(err) = error {
        let escaped = json_escape(err);
        format!(r#"{{"layer":"{layer}","status":"{status}","error":"{escaped}"}}"#)
    } else {
        format!(r#"{{"layer":"{layer}","status":"{status}"}}"#)
    };
    let line = format!("{json}\n");
    // SAFETY: fd is a valid descriptor from ARAPUCA_AUDIT_FD, buf/len valid.
    let _ = unsafe { libc::write(fd, line.as_ptr().cast::<libc::c_void>(), line.len()) };
}

/// Escape a string for JSON (RFC 8259): backslash, double-quote,
/// and all control characters below U+0020.
#[cfg(unix)]
fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if c < '\u{0020}' => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
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
