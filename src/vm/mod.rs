//! Persistent VM lifecycle management.
//!
//! Provides the infrastructure for long-running VMs with interactive
//! access via vsock-based host↔guest communication.

pub mod daemon;
pub mod exec;
pub mod protocol;
pub mod state;

#[cfg(feature = "microvm")]
use std::path::{Path, PathBuf};

/// Start a persistent VM.
///
/// Creates (or reuses) a VM directory, resolves the image, creates
/// a COW overlay, daemonizes, and launches the VM with the guest
/// agent listening on vsock. Returns the VM name and daemon PID.
#[cfg(feature = "microvm")]
pub fn start(opts: &StartOpts) -> crate::Result<StartResult> {
    use crate::MicroVmConfig;
    use crate::platform::microvm::{PersistentVmOpts, exec_vm};

    let name = &opts.name;
    crate::sanitize_task_id(name)?;

    let restarting = state::is_running(name).unwrap_or(false);
    if restarting {
        return Err(crate::Error::MicroVm(format!(
            "VM '{name}' is already running"
        )));
    }

    let allow_existing = state::vm_dir(name).map(|d| d.exists()).unwrap_or(false);
    let vm_dir = state::create_vm_dir(name, allow_existing)?;

    // Resolve image.
    let cached = crate::images::resolve(&opts.image, &Default::default())?;

    // Create or reuse the persistent overlay.
    let overlay_path = vm_dir.join("disk.qcow2");
    if !overlay_path.exists() {
        crate::images::overlay::create_overlay(&cached.path, &vm_dir)?;
    }

    // Generate fresh nonce for this session.
    let nonce = state::generate_nonce()?;

    // Acquire lockfile BEFORE writing vm.json (prevents TOCTOU).
    let lock_fd = state::acquire_lock(name)?;

    // Find agent binary adjacent to the current executable.
    let agent_bin_dir = find_agent_dir()?;

    // Start networking if requested.
    let passt = if opts.net {
        match crate::platform::microvm_net::start_passt() {
            Ok(handle) => Some(handle),
            Err(e) => {
                log::warn!("passt not available, VM will have no network: {e}");
                None
            }
        }
    } else {
        None
    };

    let passt_pid = passt.as_ref().map(|p| p.child.id());

    // Save VM config (after lock, with nonce and passt PID).
    let vm_config = state::VmConfig {
        image: format_image_source(&opts.image),
        cpus: opts.cpus,
        mem_mb: opts.mem_mb,
        net: opts.net,
        volumes: opts
            .volumes
            .iter()
            .map(|v| state::VolumeMount {
                host: v.host.clone(),
                guest: v.guest.clone(),
                read_only: v.read_only,
            })
            .collect(),
        nonce,
        passt_pid,
        max_lifetime: opts.max_lifetime,
    };
    vm_config.save(name)?;

    // Generate cloud-init datasource.
    let ci_cfg = crate::images::cloudinit::CloudInitConfig {
        hostname: name,
        user: "agent",
        virtiofs_mounts: Vec::new(),
        write_files: Vec::new(),
        runcmd: None,
    };
    let tmp_dir = crate::env::make_tmp_dir(name)?;
    let ci_dir = crate::images::cloudinit::generate_datasource(&ci_cfg, &tmp_dir)?;

    // Prepare data for the daemon.
    let net_fd = passt.as_ref().map(|p| p.parent_fd);
    let net_ips = passt.as_ref().map(|p| {
        (
            p.net_info.guest_ip.clone(),
            p.net_info.router_ip.clone(),
            p.net_info.dns_servers.clone(),
        )
    });
    let agent_sock = state::agent_sock_path(name)?;

    // Remove stale socket from a previous crashed run.
    let _ = std::fs::remove_file(&agent_sock);

    let log_path = state::vm_log_path(name)?;
    let vm_cfg = MicroVmConfig {
        image: opts.image.clone(),
        cpus: opts.cpus,
        mem_mb: opts.mem_mb,
        write_files: Vec::new(),
    };

    // Build the list of FDs to keep across daemonization.
    let mut keep_fds = vec![lock_fd];
    if let Some(fd) = net_fd {
        keep_fds.push(fd);
    }

    // Daemonize: parent returns with daemon PID, daemon continues.
    let result = daemon::daemonize(&log_path, &keep_fds)
        .map_err(|e| crate::Error::MicroVm(format!("daemonize: {e}")))?;

    match result {
        daemon::DaemonResult::Parent { daemon_pid } => {
            // Don't drop passt in the parent — the daemon owns it.
            if let Some(p) = passt {
                std::mem::forget(p);
            }

            // Poll for agent readiness.
            let ready = poll_agent_ready(&agent_sock, &nonce, 30);
            if !ready {
                eprintln!("warning: agent did not become ready within 30s");
            }

            // Clean up the parent's copy of the cidata tmp dir.
            let _ = std::fs::remove_dir_all(&tmp_dir);

            Ok(StartResult {
                name: name.clone(),
                pid: daemon_pid,
            })
        }
        daemon::DaemonResult::Daemon => {
            // ── Daemon process ────────────────────────────────
            // Update lockfile with the daemon's actual PID (the
            // double-fork gave us a new PID).
            let _ = state::update_lock_pid(lock_fd);

            let persistent_opts = PersistentVmOpts {
                agent_bin_dir: &agent_bin_dir,
                agent_sock_path: &agent_sock,
                nonce: &nonce,
                max_lifetime: opts.max_lifetime,
            };

            // exec_vm never returns — it replaces the process.
            exec_vm(
                &vm_cfg,
                &overlay_path,
                &ci_dir,
                &cached.metadata,
                &[],
                &[],
                "",
                &[],
                net_fd,
                net_ips.as_ref(),
                Some(&persistent_opts),
            )
        }
    }
}

/// Options for `vm start`.
#[cfg(feature = "microvm")]
pub struct StartOpts {
    pub name: String,
    pub image: crate::ImageSource,
    pub cpus: u32,
    pub mem_mb: u32,
    pub net: bool,
    pub volumes: Vec<VolumeSpec>,
    pub max_lifetime: Option<u64>,
}

/// Volume mount specification.
#[cfg(feature = "microvm")]
pub struct VolumeSpec {
    pub host: String,
    pub guest: String,
    pub read_only: bool,
}

/// Result of a successful `vm start`.
#[cfg(feature = "microvm")]
pub struct StartResult {
    pub name: String,
    pub pid: u32,
}

/// Find the directory containing the agent binary.
///
/// Looks for `arapuca-agent` next to the current executable.
#[cfg(feature = "microvm")]
fn find_agent_dir() -> crate::Result<PathBuf> {
    let exe =
        std::env::current_exe().map_err(|e| crate::Error::MicroVm(format!("current_exe: {e}")))?;
    let dir = exe
        .parent()
        .ok_or_else(|| crate::Error::MicroVm("cannot determine executable directory".into()))?;
    let agent_path = dir.join("arapuca-agent");
    if !agent_path.exists() {
        return Err(crate::Error::MicroVm(format!(
            "agent binary not found: {}",
            agent_path.display()
        )));
    }
    Ok(dir.to_path_buf())
}

/// Format an ImageSource as a string for vm.json.
#[cfg(feature = "microvm")]
fn format_image_source(source: &crate::ImageSource) -> String {
    match source {
        crate::ImageSource::Distro { name, version } => format!("{name}:{version}"),
        crate::ImageSource::Path(p) => p.to_string_lossy().to_string(),
    }
}

/// Poll the agent socket until it responds to PING with PONG.
#[cfg(feature = "microvm")]
fn poll_agent_ready(
    sock_path: &Path,
    nonce: &[u8; protocol::NONCE_SIZE],
    timeout_secs: u64,
) -> bool {
    use std::os::unix::net::UnixStream;
    use std::time::{Duration, Instant};

    let deadline = Instant::now() + Duration::from_secs(timeout_secs);

    while Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(200));

        let mut stream = match UnixStream::connect(sock_path) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));

        if protocol::write_nonce(&mut stream, nonce).is_err() {
            continue;
        }

        match protocol::read_control(&mut stream) {
            Ok(protocol::ControlMessage::Hello { .. }) => {}
            _ => continue,
        }

        if protocol::write_control(&mut stream, &protocol::ControlMessage::Ping).is_err() {
            continue;
        }

        match protocol::read_control(&mut stream) {
            Ok(protocol::ControlMessage::Pong) => return true,
            _ => continue,
        }
    }

    false
}
