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
#[cfg(target_os = "linux")]
use std::net::TcpListener;
use std::path::PathBuf;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    // Dispatch subcommands before the sandbox path.
    if args.get(1).is_some_and(|a| a == "image") {
        image_subcommand(&args[2..]);
        return;
    }

    // Audit FD: if set, write JSON status lines as each layer is applied.
    // The library creates a pipe and passes the write end via this env var.
    // Closed before execve so the target command cannot write to it.
    #[cfg(unix)]
    let audit_fd: Option<i32> = std::env::var("ARAPUCA_AUDIT_FD")
        .ok()
        .and_then(|s| s.parse().ok());

    // Find -- separator.
    let sep_idx = args.iter().position(|a| a == "--");
    let cmd_idx = match sep_idx {
        Some(i) if i + 1 < args.len() => i + 1,
        _ => {
            eprintln!("arapuca: usage: arapuca [image pull|list|rm] | [-- command ...]");
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

        // Bridge: fork a TCP-to-UDS relay before seccomp is applied.
        // Activated when ARAPUCA_PROXY_BRIDGE=<port>:<uds_path> is set.
        if let Some(bridge_port) = fork_bridge(audit_fd) {
            let proxy = format!("http://127.0.0.1:{bridge_port}");
            // SAFETY: single-threaded at this point (between
            // Landlock apply and seccomp apply, no threads spawned).
            unsafe {
                std::env::set_var("HTTP_PROXY", &proxy);
                std::env::set_var("HTTPS_PROXY", &proxy);
                std::env::set_var("http_proxy", &proxy);
                std::env::set_var("https_proxy", &proxy);
            }
        }

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

// ─── Image subcommands ─────────────────────────────────────────

fn image_subcommand(args: &[String]) {
    let subcmd = args.first().map(|s| s.as_str());
    match subcmd {
        Some("pull") => image_pull(&args[1..]),
        Some("list") => image_list(),
        Some("rm") => image_rm(&args[1..]),
        _ => {
            eprintln!("usage: arapuca image <pull|list|rm>");
            eprintln!();
            eprintln!("  pull <distro>:<version>   download and cache an image");
            eprintln!("  list                      show cached images");
            eprintln!("  rm <distro>:<version>     remove a cached image");
            std::process::exit(1);
        }
    }
}

#[cfg(feature = "microvm")]
fn image_pull(args: &[String]) {
    let spec = match args.first() {
        Some(s) => s,
        None => {
            eprintln!("usage: arapuca image pull <distro>:<version>");
            std::process::exit(1);
        }
    };

    let (distro, version) = match spec.split_once(':') {
        Some((d, v)) if !d.is_empty() && !v.is_empty() => (d, v),
        _ => {
            eprintln!("invalid image specifier: {spec} (expected distro:version)");
            std::process::exit(1);
        }
    };

    let source = arapuca::ImageSource::Distro {
        name: distro.into(),
        version: version.into(),
    };

    match arapuca::images::resolve(&source) {
        Ok(cached) => {
            println!("{}", cached.path.display());
        }
        Err(e) => {
            eprintln!("arapuca: image pull failed: {e}");
            std::process::exit(1);
        }
    }
}

#[cfg(not(feature = "microvm"))]
fn image_pull(_args: &[String]) {
    eprintln!("arapuca: image pull requires the 'microvm' feature");
    eprintln!("rebuild with: cargo build --features microvm");
    std::process::exit(1);
}

fn image_list() {
    match arapuca::images::cache::list() {
        Ok(images) => {
            if images.is_empty() {
                println!("no cached images");
                return;
            }
            for (name, cached) in &images {
                let size = std::fs::metadata(&cached.path)
                    .map(|m| m.len() / (1024 * 1024))
                    .unwrap_or(0);
                println!(
                    "{name}  {size}MB  root={} fs={}",
                    cached.metadata.root_device, cached.metadata.fstype,
                );
            }
        }
        Err(e) => {
            eprintln!("arapuca: image list failed: {e}");
            std::process::exit(1);
        }
    }
}

fn image_rm(args: &[String]) {
    let spec = match args.first() {
        Some(s) => s,
        None => {
            eprintln!("usage: arapuca image rm <name>");
            std::process::exit(1);
        }
    };

    // Accept both "distro:version" and cache name formats.
    let cache_name = if let Some((distro, version)) = spec.split_once(':') {
        if distro.is_empty() || version.is_empty() {
            eprintln!("invalid image specifier: {spec} (expected distro:version)");
            std::process::exit(1);
        }
        let arch = std::env::consts::ARCH;
        format!("{distro}-{version}-{arch}")
    } else {
        spec.clone()
    };

    match arapuca::images::cache::remove(&cache_name) {
        Ok(true) => println!("removed {cache_name}"),
        Ok(false) => {
            eprintln!("image not found: {cache_name}");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("arapuca: image rm failed: {e}");
            std::process::exit(1);
        }
    }
}

/// Parse ARAPUCA_PROXY_BRIDGE, fork a bridge child, and return the
/// port number on success. Returns None if the env var is not set.
/// Exits the process on error (fail-closed).
///
/// The bridge child: brings up loopback, binds TCP, applies its own
/// seccomp, signals readiness, then enters the accept/relay loop.
/// The parent waits for readiness (5s timeout) and returns.
#[cfg(target_os = "linux")]
fn fork_bridge(audit_fd: Option<i32>) -> Option<u16> {
    let bridge_var = std::env::var("ARAPUCA_PROXY_BRIDGE").ok()?;

    let (port_str, uds_path) = match bridge_var.split_once(':') {
        Some((p, u)) if !u.is_empty() => (p, u),
        _ => {
            eprintln!("arapuca: invalid ARAPUCA_PROXY_BRIDGE format (expected port:path)");
            std::process::exit(1);
        }
    };

    let port: u16 = match port_str.parse() {
        Ok(0) => {
            eprintln!("arapuca: bridge port must be non-zero");
            std::process::exit(1);
        }
        Ok(p) => p,
        Err(_) => {
            eprintln!("arapuca: invalid bridge port: {port_str}");
            std::process::exit(1);
        }
    };

    let uds_path = PathBuf::from(uds_path);

    // Invariant: seccomp must not be applied yet. The bridge child
    // needs to create sockets and bind before its own seccomp is
    // installed.
    // SAFETY: PR_GET_SECCOMP is a simple query, no pointer args.
    let seccomp_mode = unsafe { libc::prctl(libc::PR_GET_SECCOMP) };
    if seccomp_mode != 0 {
        eprintln!("arapuca: bridge: seccomp already applied (invariant violation)");
        std::process::exit(1);
    }

    // Bring up loopback inside the network namespace.
    if let Err(e) = arapuca::bridge::loopback_up() {
        eprintln!("arapuca: bridge: loopback: {e}");
        std::process::exit(1);
    }

    // Bind the TCP listener before forking so the child only needs
    // accept (not bind/listen) after its seccomp is applied.
    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
    let listener = match TcpListener::bind(addr) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("arapuca: bridge: bind {addr}: {e}");
            std::process::exit(1);
        }
    };

    // Create readiness pipe.
    let mut pipe_fds = [0i32; 2];
    // SAFETY: pipe2 with valid array and O_CLOEXEC flag.
    let ret = unsafe { libc::pipe2(pipe_fds.as_mut_ptr(), libc::O_CLOEXEC) };
    if ret != 0 {
        eprintln!("arapuca: bridge: pipe: {}", std::io::Error::last_os_error());
        std::process::exit(1);
    }
    let pipe_read = pipe_fds[0];
    let pipe_write = pipe_fds[1];

    // Save PID for the pdeathsig race check in the child.
    // SAFETY: getpid is always safe.
    let parent_pid = unsafe { libc::getpid() };

    // SAFETY: single-threaded at this point, fork is safe.
    let child_pid = unsafe { libc::fork() };

    if child_pid < 0 {
        eprintln!("arapuca: bridge: fork: {}", std::io::Error::last_os_error());
        std::process::exit(1);
    }

    use std::os::fd::AsRawFd;
    let listener_fd = listener.as_raw_fd();

    if child_pid == 0 {
        // ── Bridge child ──────────────────────────────────────

        // Close pipe read end.
        // SAFETY: pipe_read is a valid fd from pipe2.
        unsafe { libc::close(pipe_read) };

        // Close all FDs >= 3 except pipe_write and listener_fd.
        // SAFETY: close_range is available on Linux 5.9+ (within
        // our Landlock 5.13+ kernel floor).
        unsafe {
            let mut keep = [pipe_write, listener_fd];
            keep.sort();
            let mut start = 3i32;
            for &fd in &keep {
                if fd > start {
                    libc::syscall(libc::SYS_close_range, start as u32, (fd - 1) as u32, 0u32);
                }
                start = fd + 1;
            }
            libc::syscall(libc::SYS_close_range, start as u32, u32::MAX, 0u32);
        }

        // SAFETY: prctl with PR_SET_PDEATHSIG is a simple setter.
        unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) };

        // Race check: if the parent died between fork and prctl,
        // getppid will no longer match parent_pid.
        // SAFETY: getppid is always safe.
        if unsafe { libc::getppid() } != parent_pid {
            unsafe { libc::_exit(1) };
        }

        // SAFETY: prctl with PR_SET_DUMPABLE is a simple setter.
        // Prevents /proc/<pid>/mem access from the agent.
        unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0) };

        // Apply the bridge's own seccomp filter. The listener is
        // already bound, so bind/listen are not needed.
        if let Err(e) = arapuca::bridge::apply_bridge_seccomp() {
            eprintln!("arapuca: bridge: seccomp: {e}");
            unsafe { libc::_exit(1) };
        }

        // Enter the accept/relay loop. This never returns normally
        // — the bridge runs until killed by pdeathsig.
        if let Err(e) = arapuca::bridge::listen_and_relay(listener, &uds_path, pipe_write) {
            eprintln!("arapuca: bridge: relay: {e}");
        }
        unsafe { libc::_exit(0) };
    }

    // ── Parent ────────────────────────────────────────────────

    // The parent does not need the listener — the child owns it.
    let actual_port = listener.local_addr().expect("bound listener").port();
    drop(listener);

    // Close pipe write end.
    // SAFETY: pipe_write is a valid fd from pipe2.
    unsafe { libc::close(pipe_write) };

    // Wait for bridge readiness (5s timeout), retrying on EINTR.
    let mut pfd = libc::pollfd {
        fd: pipe_read,
        events: libc::POLLIN,
        revents: 0,
    };
    let poll_ret = loop {
        // SAFETY: pfd is a valid stack-local pollfd, timeout in ms.
        let ret = unsafe { libc::poll(&mut pfd, 1, 5000) };
        if ret >= 0 || std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            break ret;
        }
    };

    if poll_ret == 0 {
        eprintln!("arapuca: bridge: readiness timeout (5s)");
        // SAFETY: child_pid is a valid PID from fork.
        unsafe { libc::kill(child_pid, libc::SIGKILL) };
        std::process::exit(1);
    }
    if poll_ret < 0 {
        eprintln!("arapuca: bridge: poll: {}", std::io::Error::last_os_error());
        // SAFETY: child_pid is a valid PID from fork.
        unsafe { libc::kill(child_pid, libc::SIGKILL) };
        std::process::exit(1);
    }

    // Read the readiness byte, retrying on EINTR.
    let mut buf = [0u8; 1];
    let n = loop {
        // SAFETY: pipe_read is valid, buf is stack-local.
        let ret =
            unsafe { libc::read(pipe_read, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if ret >= 0 || std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            break ret;
        }
    };
    // SAFETY: done with pipe_read.
    unsafe { libc::close(pipe_read) };

    if n != 1 {
        eprintln!("arapuca: bridge: readiness signal failed");
        // SAFETY: child_pid is a valid PID from fork.
        unsafe { libc::kill(child_pid, libc::SIGKILL) };
        std::process::exit(1);
    }

    audit_layer(audit_fd, "ProxyBridge", true, None);
    Some(actual_port)
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
