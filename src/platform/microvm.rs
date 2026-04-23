//! Micro-VM sandbox implementation.
//!
//! Uses libkrun to launch sandboxed subprocesses inside lightweight
//! virtual machines. The VM provides hardware-enforced isolation
//! (separate kernel, separate address space) via KVM.

use std::ffi::CString;
use std::path::PathBuf;
use std::sync::Arc;

use crate::audit::{
    AuditContext, AuditEvent, AuditVerbosity, LayerDetail, SCHEMA_VERSION, SandboxLayer,
    SkipReason, sanitize_audit_string,
};
use crate::platform::Sandbox;
use crate::{Config, Error, Isolation, MicroVmConfig, Process};

/// Micro-VM sandbox implementation.
pub struct MicroVm;

impl MicroVm {
    pub fn new() -> crate::Result<Self> {
        Ok(Self)
    }
}

impl Sandbox for MicroVm {
    fn launch(&self, cfg: &Config, cmd: &str, args: &[&str]) -> crate::Result<Process> {
        let vm_cfg = match &cfg.profile.isolation {
            Isolation::MicroVm(c) => c,
            _ => {
                return Err(Error::MicroVm(
                    "MicroVm sandbox requires Isolation::MicroVm profile".into(),
                ));
            }
        };

        crate::sanitize_task_id(&cfg.task_id)?;

        let tmp_dir = crate::env::make_tmp_dir(&cfg.task_id)?;

        let audit_ctx = cfg
            .audit_sink
            .as_ref()
            .map(|sink| AuditContext::new(Arc::clone(sink), cfg.audit_verbosity.clone()));

        // Emit SandboxInit.
        if let Some(ref ctx) = audit_ctx {
            let args_field = match ctx.verbosity() {
                AuditVerbosity::Verbose => {
                    Some(args.iter().map(|a| sanitize_audit_string(a)).collect())
                }
                _ => None,
            };
            ctx.emit(AuditEvent::SandboxInit {
                timestamp: ctx.timestamp(),
                wall_clock_epoch_ns: ctx.wall_clock_epoch_ns(),
                schema_version: SCHEMA_VERSION,
                task_id: sanitize_audit_string(&cfg.task_id),
                phase: sanitize_audit_string(&cfg.phase),
                command: sanitize_audit_string(cmd),
                arg_count: args.len(),
                args: args_field,
                principal: cfg.audit_principal.as_deref().map(sanitize_audit_string),
                correlation_id: cfg
                    .audit_correlation_id
                    .as_deref()
                    .map(sanitize_audit_string),
            })?;
        }

        // Resolve the image.
        let image_source =
            cfg.profile.isolation.image_source().ok_or_else(|| {
                Error::MicroVm("MicroVm isolation requires an image source".into())
            })?;
        let cached = crate::images::resolve(image_source)?;

        // Create COW overlay so the template stays immutable.
        let overlay_dir = tmp_dir.join("vm");
        let overlay_path = crate::images::overlay::create_overlay(&cached.path, &overlay_dir)?;

        // Generate cloud-init datasource.
        let mut virtiofs_mounts = Vec::new();
        for (i, path) in cfg.profile.read_paths.iter().enumerate() {
            virtiofs_mounts.push((format!("ro{i}"), path.to_string_lossy().to_string(), "ro"));
        }
        for (i, path) in cfg.profile.write_paths.iter().enumerate() {
            virtiofs_mounts.push((
                format!("rw{i}"),
                path.to_string_lossy().to_string(),
                "defaults",
            ));
        }

        let mount_refs: Vec<(&str, &str, &str)> = virtiofs_mounts
            .iter()
            .map(|(t, m, o)| (t.as_str(), m.as_str(), *o))
            .collect();

        let runcmd = if !cmd.is_empty() && cmd != "/sbin/init" {
            let full_cmd = if args.is_empty() {
                cmd.to_string()
            } else {
                format!("{cmd} {}", args.join(" "))
            };
            Some(vec![full_cmd])
        } else {
            None
        };
        let runcmd_refs: Option<Vec<&str>> = runcmd
            .as_ref()
            .map(|v| v.iter().map(|s| s.as_str()).collect());

        let ci_cfg = crate::images::cloudinit::CloudInitConfig {
            hostname: &cfg.task_id,
            user: "agent",
            virtiofs_mounts: mount_refs,
            write_files: vec![],
            runcmd: runcmd_refs,
        };

        let ci_dir = crate::images::cloudinit::generate_datasource(&ci_cfg, &tmp_dir)?;

        // Emit audit events.
        let mut applied_layers = Vec::new();
        let mut skipped_layers = Vec::new();

        if let Some(ref ctx) = audit_ctx {
            ctx.emit(AuditEvent::LayerApplied {
                timestamp: ctx.timestamp(),
                layer: SandboxLayer::MicroVm,
                detail: Some(LayerDetail::MicroVm {
                    image_path: cached.path.to_string_lossy().into_owned(),
                    cpus: vm_cfg.cpus,
                    mem_mb: vm_cfg.mem_mb,
                }),
            })?;
        }
        applied_layers.push(SandboxLayer::MicroVm);

        // Skip all process-level layers — superseded by VM isolation.
        for layer in [
            SandboxLayer::Landlock,
            SandboxLayer::Seccomp,
            SandboxLayer::Cgroup,
            SandboxLayer::NetworkNamespace,
            SandboxLayer::Rlimit,
            SandboxLayer::NoNewPrivs,
            SandboxLayer::Setsid,
            SandboxLayer::Pdeathsig,
            SandboxLayer::FdSanitization,
        ] {
            if let Some(ref ctx) = audit_ctx {
                ctx.emit(AuditEvent::LayerSkipped {
                    timestamp: ctx.timestamp(),
                    layer: layer.clone(),
                    reason: SkipReason::PlatformUnsupported,
                })?;
            }
            skipped_layers.push(layer);
        }

        if let Some(ref ctx) = audit_ctx {
            ctx.emit(AuditEvent::SandboxReady {
                timestamp: ctx.timestamp(),
                applied_layers: applied_layers.clone(),
                skipped_layers: skipped_layers.clone(),
            })?;
        }

        // Start networking if allowed (use_netns=false means allow network).
        let passt = if !cfg.profile.use_netns {
            match super::microvm_net::start_passt() {
                Ok(handle) => Some(handle),
                Err(e) => {
                    log::warn!("passt not available, VM will have no network: {e}");
                    None
                }
            }
        } else {
            None
        };

        let net_fd = passt.as_ref().map(|p| p.parent_fd);

        // Fork and launch the VM in the child.
        let mut process = launch_vm(
            vm_cfg,
            &overlay_path,
            &ci_dir,
            &cached.metadata,
            &cfg.profile.read_paths,
            &cfg.profile.write_paths,
            &cfg.env,
            net_fd,
            &tmp_dir,
            audit_ctx,
        )?;

        // Store passt in the Process for deterministic cleanup.
        process.passt = passt;

        Ok(process)
    }

    fn available(&self) -> crate::Result<()> {
        // Check /dev/kvm exists and is accessible.
        std::fs::File::open("/dev/kvm").map_err(|e| {
            Error::MicroVm(format!(
                "/dev/kvm: {e} (KVM not available or no permission)"
            ))
        })?;
        // Check qemu-img is available.
        std::process::Command::new("qemu-img")
            .arg("--version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map_err(|e| Error::MicroVm(format!("qemu-img not found: {e}")))?;
        Ok(())
    }

    fn netns_available(&self) -> bool {
        true
    }

    fn cgroups_available(&self) -> bool {
        false
    }
}

#[allow(clippy::too_many_arguments)]
fn launch_vm(
    vm_cfg: &MicroVmConfig,
    overlay_path: &std::path::Path,
    ci_dir: &std::path::Path,
    meta: &crate::images::ImageMetadata,
    read_paths: &[PathBuf],
    write_paths: &[PathBuf],
    env: &[(String, String)],
    net_fd: Option<i32>,
    tmp_dir: &std::path::Path,
    audit_ctx: Option<AuditContext>,
) -> crate::Result<Process> {
    // SAFETY: single-threaded at this point.
    let child_pid = unsafe { libc::fork() };

    if child_pid < 0 {
        return Err(Error::MicroVm(format!(
            "fork: {}",
            std::io::Error::last_os_error()
        )));
    }

    if child_pid == 0 {
        // ── VM child ──────────────────────────────────────────
        exec_vm(
            vm_cfg,
            overlay_path,
            ci_dir,
            meta,
            read_paths,
            write_paths,
            env,
            net_fd,
        );
    }

    // ── Parent ────────────────────────────────────────────────
    if let Some(ref ctx) = audit_ctx {
        let _ = ctx.emit(AuditEvent::ProcessStarted {
            timestamp: ctx.timestamp(),
            pid: child_pid as u32,
        });
    }

    Ok(Process {
        child: crate::process::ChildHandle::Forked(child_pid as u32),
        tmp_dir: tmp_dir.to_path_buf(),
        #[cfg(target_os = "linux")]
        cgroup_path: None,
        #[cfg(target_os = "linux")]
        cgroup_mgr: None,
        passt: None,
        audit_ctx,
        final_stats: None,
    })
}

/// Execute the VM in the current process (called from the forked child).
/// This function never returns — it replaces the process with the VM.
#[allow(clippy::too_many_arguments)]
fn exec_vm(
    vm_cfg: &MicroVmConfig,
    overlay_path: &std::path::Path,
    ci_dir: &std::path::Path,
    meta: &crate::images::ImageMetadata,
    read_paths: &[PathBuf],
    write_paths: &[PathBuf],
    env: &[(String, String)],
    net_fd: Option<i32>,
) -> ! {
    if let Err(e) = exec_vm_inner(
        vm_cfg,
        overlay_path,
        ci_dir,
        meta,
        read_paths,
        write_paths,
        env,
        net_fd,
    ) {
        eprintln!("arapuca: microvm: {e}");
    }
    // SAFETY: we are in the forked child.
    unsafe { libc::_exit(1) }
}

#[allow(clippy::too_many_arguments)]
fn exec_vm_inner(
    vm_cfg: &MicroVmConfig,
    overlay_path: &std::path::Path,
    ci_dir: &std::path::Path,
    meta: &crate::images::ImageMetadata,
    read_paths: &[PathBuf],
    write_paths: &[PathBuf],
    env: &[(String, String)],
    net_fd: Option<i32>,
) -> crate::Result<()> {
    // SAFETY: all krun_sys calls operate on a context ID and take
    // C strings. The context is process-local (this is the forked
    // child). Return values are checked.

    let ctx_raw = unsafe { krun_sys::krun_create_ctx() };
    if ctx_raw < 0 {
        return Err(Error::MicroVm(format!(
            "krun_create_ctx failed (ret={ctx_raw})"
        )));
    }
    let ctx = ctx_raw as u32;

    let cpus = vm_cfg.cpus.min(255) as u8;
    let ret = unsafe { krun_sys::krun_set_vm_config(ctx, cpus, vm_cfg.mem_mb) };
    if ret < 0 {
        return Err(Error::MicroVm("krun_set_vm_config failed".into()));
    }

    use std::os::unix::ffi::OsStrExt;

    // Add the overlay disk.
    let disk_path = CString::new(overlay_path.as_os_str().as_bytes())
        .map_err(|_| Error::MicroVm("invalid disk path".into()))?;
    let disk_label = CString::new("root").unwrap();

    let ret = unsafe {
        krun_sys::krun_add_disk2(
            ctx,
            disk_label.as_ptr(),
            disk_path.as_ptr(),
            krun_sys::KRUN_DISK_FORMAT_QCOW2,
            false,
        )
    };
    if ret < 0 {
        return Err(Error::MicroVm("krun_add_disk2 failed".into()));
    }

    // Set root disk remount.
    let device = CString::new(meta.root_device.as_bytes())
        .map_err(|_| Error::MicroVm("invalid root_device".into()))?;
    let fstype = CString::new(meta.fstype.as_bytes())
        .map_err(|_| Error::MicroVm("invalid fstype".into()))?;

    let ret = unsafe {
        krun_sys::krun_set_root_disk_remount(
            ctx,
            device.as_ptr(),
            fstype.as_ptr(),
            std::ptr::null(),
        )
    };
    if ret < 0 {
        return Err(Error::MicroVm("krun_set_root_disk_remount failed".into()));
    }

    // Add cloud-init datasource as a virtio-fs share.
    let ci_tag = CString::new("cidata").unwrap();
    let ci_path = CString::new(ci_dir.as_os_str().as_bytes())
        .map_err(|_| Error::MicroVm("invalid cloud-init path".into()))?;

    let ret = unsafe { krun_sys::krun_add_virtiofs(ctx, ci_tag.as_ptr(), ci_path.as_ptr()) };
    if ret < 0 {
        return Err(Error::MicroVm("krun_add_virtiofs (cidata) failed".into()));
    }

    // Add read-only paths as virtio-fs shares.
    for (i, path) in read_paths.iter().enumerate() {
        let tag = CString::new(format!("ro{i}")).unwrap();
        let host = CString::new(path.as_os_str().as_bytes())
            .map_err(|_| Error::MicroVm(format!("invalid read path: {}", path.display())))?;
        let ret = unsafe { krun_sys::krun_add_virtiofs(ctx, tag.as_ptr(), host.as_ptr()) };
        if ret < 0 {
            return Err(Error::MicroVm(format!("krun_add_virtiofs (ro{i}) failed")));
        }
    }

    // Add read-write paths as virtio-fs shares.
    for (i, path) in write_paths.iter().enumerate() {
        let tag = CString::new(format!("rw{i}")).unwrap();
        let host = CString::new(path.as_os_str().as_bytes())
            .map_err(|_| Error::MicroVm(format!("invalid write path: {}", path.display())))?;
        let ret = unsafe { krun_sys::krun_add_virtiofs(ctx, tag.as_ptr(), host.as_ptr()) };
        if ret < 0 {
            return Err(Error::MicroVm(format!("krun_add_virtiofs (rw{i}) failed")));
        }
    }

    // Configure networking if a passt FD was provided.
    if let Some(fd) = net_fd {
        let mut mac = super::microvm_net::random_mac();
        let ret = unsafe {
            krun_sys::krun_add_net_unixstream(
                ctx,
                std::ptr::null(),
                fd,
                mac.as_mut_ptr(),
                krun_sys::COMPAT_NET_FEATURES,
                0,
            )
        };
        if ret < 0 {
            return Err(Error::MicroVm("krun_add_net_unixstream failed".into()));
        }
    }

    // Set the executable and environment.
    let c_cmd = CString::new(meta.init.as_bytes())
        .map_err(|_| Error::MicroVm("invalid init path".into()))?;

    let mut c_env: Vec<CString> = Vec::new();
    c_env.push(CString::new("HOME=/home/agent").unwrap());
    c_env.push(
        CString::new("PATH=/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin").unwrap(),
    );
    for (k, v) in env {
        if let Ok(kv) = CString::new(format!("{k}={v}")) {
            c_env.push(kv);
        }
    }

    let mut envp: Vec<*const libc::c_char> = c_env.iter().map(|s| s.as_ptr()).collect();
    envp.push(std::ptr::null());

    // No argv needed for /sbin/init.
    let argv: Vec<*const libc::c_char> = vec![std::ptr::null()];

    let ret = unsafe { krun_sys::krun_set_exec(ctx, c_cmd.as_ptr(), argv.as_ptr(), envp.as_ptr()) };
    if ret < 0 {
        return Err(Error::MicroVm("krun_set_exec failed".into()));
    }

    // Start the VM. This replaces the current process.
    let ret = unsafe { krun_sys::krun_start_enter(ctx) };
    // If we get here, start_enter failed.
    Err(Error::MicroVm(format!(
        "krun_start_enter failed (ret={ret})"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn microvm_available_check() {
        let vm = MicroVm::new().unwrap();
        let result = vm.available();
        match &result {
            Ok(()) => eprintln!("microvm: available (KVM + qemu-img)"),
            Err(e) => eprintln!("microvm: not available: {e}"),
        }
    }
}
