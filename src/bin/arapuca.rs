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
    #[cfg(feature = "microvm")]
    if args.get(1).is_some_and(|a| a == "vm") {
        vm_subcommand(&args[2..]);
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
        #[cfg(feature = "microvm")]
        Some("setup") => image_setup(&args[1..]),
        _ => {
            eprintln!("usage: arapuca image <pull|list|rm|setup>");
            eprintln!();
            eprintln!("  pull <distro>:<version>      download and cache an image");
            eprintln!("  list                         show cached images");
            eprintln!("  rm <distro>:<version>        remove a cached image");
            eprintln!("  setup <distro:ver> [flags]   create a setup layer");
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
                let indent = if name.contains(".setup-") { "  " } else { "" };
                println!(
                    "{indent}{name}  {size}MB  root={} fs={}",
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

// ─── Image setup ──────────────────────────────────────────────

#[cfg(feature = "microvm")]
fn image_setup(args: &[String]) {
    use arapuca::platform::{MicroVm, Sandbox};

    let mut image_spec = None;
    let mut run_cmd = None;
    let mut script_path = None;
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--run" => {
                i += 1;
                run_cmd = Some(args.get(i).cloned().unwrap_or_default());
            }
            "--script" => {
                i += 1;
                script_path = Some(args.get(i).cloned().unwrap_or_default());
            }
            s if !s.starts_with('-') && image_spec.is_none() => {
                image_spec = Some(s.to_string());
            }
            _ => {
                eprintln!("unknown flag: {}", args[i]);
                std::process::exit(1);
            }
        }
        i += 1;
    }

    let spec = match image_spec {
        Some(s) => s,
        None => {
            eprintln!(
                "usage: arapuca image setup <distro:version> --run '<cmd>' | --script <path>"
            );
            std::process::exit(1);
        }
    };

    let script = match (run_cmd, script_path) {
        (Some(cmd), None) => cmd,
        (None, Some(path)) => match std::fs::read_to_string(&path) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("arapuca: cannot read script {path}: {e}");
                std::process::exit(1);
            }
        },
        (Some(_), Some(_)) => {
            eprintln!("arapuca: --run and --script are mutually exclusive");
            std::process::exit(1);
        }
        (None, None) => {
            eprintln!(
                "usage: arapuca image setup <distro:version> --run '<cmd>' | --script <path>"
            );
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

    let image_source = arapuca::ImageSource::Distro {
        name: distro.into(),
        version: version.into(),
    };

    // Resolve the base image (pull if needed).
    let cached = match arapuca::images::resolve(&image_source) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("arapuca: image resolve failed: {e}");
            std::process::exit(1);
        }
    };

    let arch = std::env::consts::ARCH;
    let base_name = format!("{distro}-{version}-{arch}");
    let base_sha256 = cached.metadata.sha256.as_deref();

    // Check if a setup layer already exists.
    match arapuca::images::setup::lookup(&base_name, &script, base_sha256) {
        Ok(Some(layer)) => {
            println!("{}", layer.path.display());
            eprintln!("setup layer already exists");
            return;
        }
        Ok(None) => {}
        Err(e) => {
            eprintln!("arapuca: setup lookup failed: {e}");
            std::process::exit(1);
        }
    }

    // Build a minimal config: no host mounts, networking enabled.
    let profile = arapuca::Profile {
        isolation: arapuca::Isolation::MicroVm(arapuca::MicroVmConfig {
            image: image_source.clone(),
            cpus: 2,
            mem_mb: 2048,
            write_files: Vec::new(),
        }),
        use_netns: false,
        ..Default::default()
    };

    let config = arapuca::Config {
        profile,
        socket_dir: std::env::temp_dir(),
        task_id: format!("setup-{distro}-{version}"),
        phase: "image-setup".into(),
        work_dir: None,
        #[cfg(unix)]
        stdin: None,
        #[cfg(unix)]
        stdout: None,
        #[cfg(unix)]
        stderr: None,
        #[cfg(unix)]
        extra_fds: Vec::new(),
        network_proxy_socket: None,
        env: Vec::new(),
        audit_sink: None,
        audit_verbosity: arapuca::audit::AuditVerbosity::Standard,
        audit_principal: None,
        audit_correlation_id: None,
    };

    eprintln!("running setup VM...");

    let sandbox = MicroVm::new().unwrap_or_else(|e| {
        eprintln!("arapuca: microvm: {e}");
        std::process::exit(125);
    });

    // Launch setup VM with the setup script as the command.
    let mut process = match sandbox.launch(&config, "/bin/sh", &["-c", &script]) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("arapuca: setup VM launch failed: {e}");
            std::process::exit(125);
        }
    };

    let status = match process.wait() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("arapuca: setup VM wait failed: {e}");
            std::process::exit(125);
        }
    };

    let exit_code = status.code().unwrap_or(1);

    // Save the overlay path before cleanup destroys the temp dir.
    let vm_overlay = process.tmp_dir().join("vm").join("disk.qcow2");

    if exit_code != 0 {
        process.cleanup();
        eprintln!("arapuca: setup command failed (exit {exit_code})");
        eprintln!("no setup layer was created");
        std::process::exit(exit_code);
    }

    // Success — cache the overlay as a setup layer.
    let result = arapuca::images::setup::store(
        &base_name,
        &script,
        &vm_overlay,
        &cached.metadata,
        base_sha256,
    );
    process.cleanup();

    match result {
        Ok(layer) => {
            eprintln!("setup layer created");
            println!("{}", layer.path.display());
        }
        Err(e) => {
            eprintln!("arapuca: failed to cache setup layer: {e}");
            std::process::exit(1);
        }
    }
}

// ─── VM subcommands ────────────────────────────────────────────

#[cfg(feature = "microvm")]
fn vm_subcommand(args: &[String]) {
    match args.first().map(|s| s.as_str()) {
        Some("run") => vm_run(&args[1..]),
        Some("start") => vm_start(&args[1..]),
        Some("exec") => vm_exec(&args[1..]),
        Some("list") | Some("ls") => vm_list(),
        _ => {
            eprintln!("usage: arapuca vm <command>");
            eprintln!();
            eprintln!("commands:");
            eprintln!("  run [flags] -- command [args...]   run a command in an ephemeral VM");
            eprintln!("  start [flags]                      start a persistent VM");
            eprintln!("  exec <name> [flags] -- cmd [args]  exec in a running VM");
            eprintln!("  list                               list VMs");
            std::process::exit(1);
        }
    }
}

#[cfg(feature = "microvm")]
fn vm_start(args: &[String]) {
    let mut image: Option<String> = None;
    let mut name: Option<String> = None;
    let mut cpus: u32 = 2;
    let mut mem_mb: u32 = 2048;
    let mut net = false;
    let mut volumes: Vec<arapuca::vm::VolumeSpec> = Vec::new();
    let mut max_lifetime: Option<u64> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--image" => {
                i += 1;
                image = Some(
                    args.get(i)
                        .unwrap_or_else(|| {
                            eprintln!("--image requires a value");
                            std::process::exit(125);
                        })
                        .clone(),
                );
            }
            "--name" => {
                i += 1;
                name = Some(
                    args.get(i)
                        .unwrap_or_else(|| {
                            eprintln!("--name requires a value");
                            std::process::exit(125);
                        })
                        .clone(),
                );
            }
            "--cpus" => {
                i += 1;
                cpus = args.get(i).and_then(|s| s.parse().ok()).unwrap_or_else(|| {
                    eprintln!("--cpus requires a positive integer");
                    std::process::exit(125);
                });
                if cpus == 0 {
                    eprintln!("--cpus must be > 0");
                    std::process::exit(125);
                }
            }
            "--mem" => {
                i += 1;
                mem_mb = args.get(i).and_then(|s| s.parse().ok()).unwrap_or_else(|| {
                    eprintln!("--mem requires a positive integer");
                    std::process::exit(125);
                });
                if mem_mb == 0 {
                    eprintln!("--mem must be > 0");
                    std::process::exit(125);
                }
            }
            "--net" => {
                net = true;
            }
            "-v" | "--volume" => {
                i += 1;
                let spec = args.get(i).unwrap_or_else(|| {
                    eprintln!("-v requires host:guest[:opts]");
                    std::process::exit(125);
                });
                let parts: Vec<&str> = spec.splitn(3, ':').collect();
                if parts.len() < 2 || parts[0].is_empty() || parts[1].is_empty() {
                    eprintln!("invalid volume: {spec} (expected host:guest[:opts])");
                    std::process::exit(125);
                }
                let opts = parts.get(2).unwrap_or(&"").to_lowercase();
                volumes.push(arapuca::vm::VolumeSpec {
                    host: parts[0].to_string(),
                    guest: parts[1].to_string(),
                    read_only: opts.contains("ro"),
                });
            }
            "--max-lifetime" => {
                i += 1;
                max_lifetime =
                    Some(args.get(i).and_then(|s| s.parse().ok()).unwrap_or_else(|| {
                        eprintln!("--max-lifetime requires a positive integer");
                        std::process::exit(125);
                    }));
            }
            other => {
                eprintln!("unknown flag: {other}");
                eprintln!("run 'arapuca vm start --help' for usage");
                std::process::exit(125);
            }
        }
        i += 1;
    }

    // --image is required on first start, optional on restart.
    let vm_name = name.unwrap_or_else(|| {
        let mut buf = [0u8; 8];
        // SAFETY: getrandom with valid buffer and no flags.
        unsafe { libc::getrandom(buf.as_mut_ptr().cast(), buf.len(), 0) };
        format!(
            "vm-{}",
            buf.iter().map(|b| format!("{b:02x}")).collect::<String>()
        )
    });

    // Check if this is a restart (VM dir exists but not running).
    let is_restart = arapuca::vm::state::vm_dir(&vm_name)
        .map(|d| d.exists())
        .unwrap_or(false);

    let image_source = if let Some(img) = &image {
        parse_image_source(img)
    } else if is_restart {
        match arapuca::vm::state::VmConfig::load(&vm_name) {
            Ok(cfg) => parse_image_source(&cfg.image),
            Err(e) => {
                eprintln!("arapuca: cannot load VM config: {e}");
                std::process::exit(125);
            }
        }
    } else {
        eprintln!("--image is required for new VMs");
        std::process::exit(125);
    };

    // Default max-lifetime: 24 hours.
    let max_lifetime = max_lifetime.or(Some(86400));

    let opts = arapuca::vm::StartOpts {
        name: vm_name,
        image: image_source,
        cpus,
        mem_mb,
        net,
        volumes,
        max_lifetime,
    };

    match arapuca::vm::start(&opts) {
        Ok(result) => {
            println!("{} {}", result.name, result.pid);
        }
        Err(e) => {
            eprintln!("arapuca: vm start failed: {e}");
            std::process::exit(125);
        }
    }
}

#[cfg(feature = "microvm")]
fn vm_list() {
    match arapuca::vm::state::list_vms() {
        Ok(vms) => {
            if vms.is_empty() {
                println!("no VMs");
                return;
            }
            for vm in &vms {
                let status = if vm.running { "running" } else { "stopped" };
                let pid = vm.pid.map(|p| p.to_string()).unwrap_or_default();
                let size_mb = vm.overlay_size_bytes / (1024 * 1024);
                println!(
                    "{:<20} {:<10} {:<8} {:<10} {}MB",
                    vm.name, status, pid, vm.image, size_mb
                );
            }
        }
        Err(e) => {
            eprintln!("arapuca: vm list failed: {e}");
            std::process::exit(1);
        }
    }
}

#[cfg(feature = "microvm")]
fn vm_exec(args: &[String]) {
    let vm_name = match args.first() {
        Some(name) if !name.starts_with('-') => name.clone(),
        _ => {
            eprintln!("usage: arapuca vm exec <name> [--env K=V] [--user U] -- cmd [args]");
            std::process::exit(125);
        }
    };

    let rest = &args[1..];
    let mut env_vars: Vec<String> = Vec::new();
    let mut user = "root".to_string();

    let sep_pos = rest.iter().position(|a| a == "--");
    let flag_args = match sep_pos {
        Some(pos) => &rest[..pos],
        None => rest,
    };
    let cmd_args: &[String] = match sep_pos {
        Some(pos) if pos + 1 < rest.len() => &rest[pos + 1..],
        _ => {
            eprintln!("usage: arapuca vm exec <name> [flags] -- command [args...]");
            std::process::exit(125);
        }
    };

    let mut i = 0;
    while i < flag_args.len() {
        match flag_args[i].as_str() {
            "--env" => {
                i += 1;
                let kv = flag_args.get(i).unwrap_or_else(|| {
                    eprintln!("--env requires KEY=VALUE");
                    std::process::exit(125);
                });
                env_vars.push(kv.clone());
            }
            "--user" => {
                i += 1;
                user = flag_args
                    .get(i)
                    .unwrap_or_else(|| {
                        eprintln!("--user requires a value");
                        std::process::exit(125);
                    })
                    .clone();
            }
            other => {
                eprintln!("unknown flag: {other}");
                std::process::exit(125);
            }
        }
        i += 1;
    }

    if !arapuca::vm::state::is_running(&vm_name).unwrap_or(false) {
        eprintln!("arapuca: VM '{vm_name}' is not running");
        std::process::exit(1);
    }

    let config = match arapuca::vm::state::VmConfig::load(&vm_name) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("arapuca: cannot load VM config: {e}");
            std::process::exit(1);
        }
    };

    let sock_path = match arapuca::vm::state::agent_sock_path(&vm_name) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("arapuca: {e}");
            std::process::exit(1);
        }
    };

    // Filter dangerous env vars before sending to the agent.
    // Both caller env and explicit --env values are filtered.
    let caller_env: Vec<(String, String)> = std::env::vars().collect();
    let filtered = arapuca::env::filter_caller_env(&caller_env);
    let explicit_env: Vec<(String, String)> = env_vars
        .iter()
        .filter_map(|kv| {
            let (k, v) = kv.split_once('=')?;
            Some((k.to_string(), v.to_string()))
        })
        .collect();
    let filtered_explicit = arapuca::env::filter_caller_env(&explicit_env);
    let filtered_env: Vec<String> = filtered
        .passed
        .into_iter()
        .chain(filtered_explicit.passed)
        .map(|(k, v)| format!("{k}={v}"))
        .collect();

    let cmd = cmd_args[0].as_str();
    let cmd_rest: Vec<String> = cmd_args[1..].to_vec();

    let exit_code = match arapuca::vm::exec::exec(
        &sock_path,
        &config.nonce,
        cmd,
        &cmd_rest,
        &filtered_env,
        &user,
    ) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("arapuca: vm exec failed: {e}");
            125
        }
    };

    std::process::exit(exit_code);
}

#[cfg(feature = "microvm")]
fn parse_image_source(spec: &str) -> arapuca::ImageSource {
    if spec.contains('/') || spec.ends_with(".qcow2") || spec.ends_with(".raw") {
        arapuca::ImageSource::Path(PathBuf::from(spec))
    } else if let Some((distro, version)) = spec.split_once(':') {
        if distro.is_empty() || version.is_empty() {
            eprintln!("invalid image: {spec} (expected distro:version or path)");
            std::process::exit(125);
        }
        arapuca::ImageSource::Distro {
            name: distro.to_string(),
            version: version.to_string(),
        }
    } else {
        eprintln!("invalid image: {spec} (expected distro:version or path)");
        std::process::exit(125);
    }
}

#[cfg(feature = "microvm")]
fn vm_run(args: &[String]) {
    use arapuca::platform::{MicroVm, Sandbox};

    let mut image: Option<String> = None;
    let mut cpus: u32 = 2;
    let mut mem_mb: u32 = 2048;
    let mut volumes: Vec<(String, String, String)> = Vec::new(); // host, guest, opts
    let mut net = false;
    let mut env: Vec<(String, String)> = Vec::new();
    let mut write_files: Vec<(String, String)> = Vec::new(); // host, guest
    let mut timeout: Option<u64> = None;
    let mut task_id: Option<String> = None;

    // Find -- separator.
    let sep_pos = args.iter().position(|a| a == "--");
    let flag_args = match sep_pos {
        Some(pos) => &args[..pos],
        None => args,
    };
    let cmd_args: &[String] = match sep_pos {
        Some(pos) if pos + 1 < args.len() => &args[pos + 1..],
        _ => &[],
    };

    // Parse flags.
    let mut i = 0;
    while i < flag_args.len() {
        match flag_args[i].as_str() {
            "--image" => {
                i += 1;
                image = Some(
                    flag_args
                        .get(i)
                        .unwrap_or_else(|| {
                            eprintln!("--image requires a value");
                            std::process::exit(125);
                        })
                        .clone(),
                );
            }
            "--cpus" => {
                i += 1;
                cpus = flag_args
                    .get(i)
                    .and_then(|s| s.parse().ok())
                    .unwrap_or_else(|| {
                        eprintln!("--cpus requires a positive integer");
                        std::process::exit(125);
                    });
                if cpus == 0 {
                    eprintln!("--cpus must be > 0");
                    std::process::exit(125);
                }
            }
            "--mem" => {
                i += 1;
                mem_mb = flag_args
                    .get(i)
                    .and_then(|s| s.parse().ok())
                    .unwrap_or_else(|| {
                        eprintln!("--mem requires a positive integer");
                        std::process::exit(125);
                    });
                if mem_mb == 0 {
                    eprintln!("--mem must be > 0");
                    std::process::exit(125);
                }
            }
            "-v" | "--volume" => {
                i += 1;
                let spec = flag_args.get(i).unwrap_or_else(|| {
                    eprintln!("-v requires host:guest[:opts]");
                    std::process::exit(125);
                });
                let parts: Vec<&str> = spec.splitn(3, ':').collect();
                if parts.len() < 2 || parts[0].is_empty() || parts[1].is_empty() {
                    eprintln!("invalid volume: {spec} (expected host:guest[:opts])");
                    std::process::exit(125);
                }
                volumes.push((
                    parts[0].to_string(),
                    parts[1].to_string(),
                    parts.get(2).unwrap_or(&"").to_string(),
                ));
            }
            "--net" => {
                net = true;
            }
            "--env" => {
                i += 1;
                let kv = flag_args.get(i).unwrap_or_else(|| {
                    eprintln!("--env requires KEY=VALUE");
                    std::process::exit(125);
                });
                if let Some((k, v)) = kv.split_once('=') {
                    env.push((k.to_string(), v.to_string()));
                } else {
                    eprintln!("invalid --env: {kv} (expected KEY=VALUE)");
                    std::process::exit(125);
                }
            }
            "--write-file" => {
                i += 1;
                let spec = flag_args.get(i).unwrap_or_else(|| {
                    eprintln!("--write-file requires host_path:guest_path");
                    std::process::exit(125);
                });
                if let Some((host, guest)) = spec.split_once(':') {
                    if host.is_empty() || guest.is_empty() {
                        eprintln!("invalid --write-file: {spec}");
                        std::process::exit(125);
                    }
                    // Validate host file.
                    let meta = match std::fs::metadata(host) {
                        Ok(m) => m,
                        Err(e) => {
                            eprintln!("--write-file: {host}: {e}");
                            std::process::exit(125);
                        }
                    };
                    if !meta.is_file() {
                        eprintln!("--write-file: {host}: not a regular file");
                        std::process::exit(125);
                    }
                    if meta.len() > 1024 * 1024 {
                        eprintln!("--write-file: {host}: file too large (max 1MB)");
                        std::process::exit(125);
                    }
                    if !guest.starts_with('/') {
                        eprintln!("--write-file: guest path must be absolute: {guest}");
                        std::process::exit(125);
                    }
                    write_files.push((host.to_string(), guest.to_string()));
                } else {
                    eprintln!("invalid --write-file: {spec} (expected host:guest)");
                    std::process::exit(125);
                }
            }
            "--timeout" => {
                i += 1;
                let secs: u64 = flag_args
                    .get(i)
                    .and_then(|s| s.parse().ok())
                    .unwrap_or_else(|| {
                        eprintln!("--timeout requires a positive integer (seconds)");
                        std::process::exit(125);
                    });
                if secs == 0 {
                    eprintln!("--timeout must be > 0");
                    std::process::exit(125);
                }
                timeout = Some(secs);
            }
            "--task-id" => {
                i += 1;
                task_id = Some(
                    flag_args
                        .get(i)
                        .unwrap_or_else(|| {
                            eprintln!("--task-id requires a value");
                            std::process::exit(125);
                        })
                        .clone(),
                );
            }
            other => {
                eprintln!("unknown flag: {other}");
                eprintln!("run 'arapuca vm' for usage");
                std::process::exit(125);
            }
        }
        i += 1;
    }

    let image = image.unwrap_or_else(|| {
        eprintln!("--image is required");
        std::process::exit(125);
    });

    // Parse image specifier.
    let image_source =
        if image.contains('/') || image.ends_with(".qcow2") || image.ends_with(".raw") {
            arapuca::ImageSource::Path(PathBuf::from(&image))
        } else if let Some((distro, version)) = image.split_once(':') {
            if distro.is_empty() || version.is_empty() {
                eprintln!("invalid image: {image} (expected distro:version or path)");
                std::process::exit(125);
            }
            arapuca::ImageSource::Distro {
                name: distro.to_string(),
                version: version.to_string(),
            }
        } else {
            eprintln!("invalid image: {image} (expected distro:version or path)");
            std::process::exit(125);
        };

    // Build profile.
    let mut read_paths = Vec::new();
    let mut write_paths = Vec::new();

    for (host, _guest, opts) in &volumes {
        let opts_lower = opts.to_lowercase();

        // SELinux relabeling.
        #[cfg(target_os = "linux")]
        if opts.contains('z') || opts.contains('Z') {
            apply_selinux_label(host);
        }

        if opts_lower.contains("ro") {
            read_paths.push(PathBuf::from(host));
        } else {
            write_paths.push(PathBuf::from(host));
        }
    }

    let task = task_id.unwrap_or_else(|| format!("vm-{}", std::process::id()));

    // Read host files and build GuestFile entries.
    let guest_files: Vec<arapuca::GuestFile> = write_files
        .iter()
        .map(|(host, guest)| {
            let content = match std::fs::read_to_string(host) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("arapuca: cannot read {host}: {e}");
                    std::process::exit(125);
                }
            };
            arapuca::GuestFile {
                path: guest.clone(),
                content,
                permissions: None,
            }
        })
        .collect();

    let profile = arapuca::Profile {
        isolation: arapuca::Isolation::MicroVm(arapuca::MicroVmConfig {
            image: image_source,
            cpus,
            mem_mb,
            write_files: guest_files,
        }),
        read_paths,
        write_paths,
        use_netns: !net,
        ..Default::default()
    };

    let config = arapuca::Config {
        profile,
        socket_dir: std::env::temp_dir(),
        task_id: task,
        phase: "vm-run".into(),
        work_dir: None,
        #[cfg(unix)]
        stdin: None,
        #[cfg(unix)]
        stdout: None,
        #[cfg(unix)]
        stderr: None,
        #[cfg(unix)]
        extra_fds: Vec::new(),
        network_proxy_socket: None,
        env,
        audit_sink: None,
        audit_verbosity: arapuca::audit::AuditVerbosity::Standard,
        audit_principal: None,
        audit_correlation_id: None,
    };

    // Build the command string.
    let cmd = cmd_args.first().map(|s| s.as_str()).unwrap_or("");
    let cmd_rest: Vec<&str> = cmd_args.iter().skip(1).map(|s| s.as_str()).collect();

    // Launch.
    let sandbox = MicroVm::new().unwrap_or_else(|e| {
        eprintln!("arapuca: microvm: {e}");
        std::process::exit(125);
    });

    if let Err(e) = sandbox.available() {
        eprintln!("arapuca: microvm not available: {e}");
        std::process::exit(125);
    }

    let mut process = match sandbox.launch(&config, cmd, &cmd_rest) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("arapuca: vm launch failed: {e}");
            std::process::exit(125);
        }
    };

    // Forward SIGINT/SIGTERM to the VM child for graceful shutdown.
    install_signal_forwarder(process.pid() as i32);

    // Wait with optional timeout. The done flag prevents the
    // timer thread from killing a recycled PID after the VM exits.
    let done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));

    if let Some(secs) = timeout {
        let pid = process.pid();
        let done_clone = std::sync::Arc::clone(&done);
        std::thread::spawn(move || {
            use std::sync::atomic::Ordering;
            std::thread::sleep(std::time::Duration::from_secs(secs));
            if done_clone.load(Ordering::Acquire) {
                return;
            }
            eprintln!("arapuca: timeout ({secs}s), killing VM");
            // SAFETY: pid is valid and not yet recycled (done is false).
            unsafe { libc::kill(pid as i32, libc::SIGTERM) };
            std::thread::sleep(std::time::Duration::from_secs(5));
            if done_clone.load(Ordering::Acquire) {
                return;
            }
            unsafe { libc::kill(pid as i32, libc::SIGKILL) };
        });
    }

    let status = process.wait();
    done.store(true, std::sync::atomic::Ordering::Release);
    VM_PID.store(0, std::sync::atomic::Ordering::Release);

    let exit_code = match status {
        Ok(s) => {
            if let Some(code) = s.code() {
                code
            } else {
                #[cfg(unix)]
                {
                    use std::os::unix::process::ExitStatusExt;
                    128 + s.signal().unwrap_or(9)
                }
                #[cfg(not(unix))]
                {
                    137
                }
            }
        }
        Err(e) => {
            eprintln!("arapuca: wait failed: {e}");
            125
        }
    };

    process.cleanup();
    std::process::exit(exit_code);
}

#[cfg(all(feature = "microvm", unix))]
static VM_PID: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);

/// Install signal handlers that forward SIGINT/SIGTERM to the VM
/// child process. First signal sends SIGTERM for graceful shutdown;
/// second signal sends SIGKILL.
#[cfg(all(feature = "microvm", unix))]
fn install_signal_forwarder(child_pid: i32) {
    use std::sync::atomic::{AtomicI32, Ordering};

    static SIGNAL_COUNT: AtomicI32 = AtomicI32::new(0);

    VM_PID.store(child_pid, Ordering::Release);

    extern "C" fn handler(_sig: libc::c_int) {
        let pid = VM_PID.load(Ordering::Acquire);
        if pid <= 0 {
            return;
        }
        let count = SIGNAL_COUNT.fetch_add(1, Ordering::AcqRel);
        if count == 0 {
            // First signal: SIGTERM for graceful shutdown.
            // SAFETY: pid is a valid child PID, SIGTERM is safe.
            unsafe { libc::kill(pid, libc::SIGTERM) };
        } else {
            // Second signal: SIGKILL.
            // SAFETY: pid is a valid child PID.
            unsafe { libc::kill(pid, libc::SIGKILL) };
        }
    }

    // Use sigaction instead of signal to avoid handler-reset-on-
    // delivery (System V semantics). sigaction keeps the handler
    // installed across invocations.
    // SAFETY: handler is async-signal-safe (only atomics + kill).
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        let handler_ptr: extern "C" fn(libc::c_int) = handler;
        sa.sa_sigaction = handler_ptr as usize;
        sa.sa_flags = libc::SA_RESTART;
        libc::sigaction(libc::SIGINT, &sa, std::ptr::null_mut());
        libc::sigaction(libc::SIGTERM, &sa, std::ptr::null_mut());
    }
}

#[cfg(all(feature = "microvm", target_os = "linux"))]
fn apply_selinux_label(path: &str) {
    // Reject dangerous paths that should never be relabeled.
    let canonical = match std::fs::canonicalize(path) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("warning: cannot resolve {path} for SELinux relabel: {e}");
            return;
        }
    };
    let canon_str = canonical.to_string_lossy();
    let dangerous = [
        "/", "/etc", "/usr", "/var", "/bin", "/sbin", "/lib", "/lib64", "/boot", "/dev", "/proc",
        "/sys", "/run", "/tmp",
    ];
    if dangerous
        .iter()
        .any(|d| canon_str == *d || canon_str.starts_with(&format!("{d}/")))
    {
        eprintln!("warning: refusing to relabel {path} (system directory)");
        return;
    }

    let enforcing = std::fs::read_to_string("/sys/fs/selinux/enforce")
        .map(|s| s.trim() == "1")
        .unwrap_or(false);

    if !enforcing {
        return;
    }

    // Use the canonicalized path to prevent TOCTOU symlink swaps.
    let status = std::process::Command::new("chcon")
        .args(["-R", "-t", "svirt_sandbox_file_t", &*canon_str])
        .status();

    match status {
        Ok(s) if s.success() => {}
        Ok(s) => eprintln!(
            "warning: chcon failed on {path} (exit {})",
            s.code().unwrap_or(-1)
        ),
        Err(e) => eprintln!("warning: chcon not available: {e}"),
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
