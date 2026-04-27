//! VM state tracking: directories, lockfiles, and persistent config.
//!
//! Each VM gets a directory at `$XDG_DATA_HOME/arapuca/vms/<name>/`
//! containing its lockfile, config, agent socket, and disk overlay.

use std::fs;
use std::io::{self, Write};
use std::os::fd::RawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;

use crate::vm::protocol::{self, NONCE_SIZE};

/// Persistent VM configuration stored as `vm.json`.
///
/// Does NOT persist env vars (security: secrets not written to disk).
#[derive(Debug, Clone)]
pub struct VmConfig {
    pub image: String,
    pub cpus: u32,
    pub mem_mb: u32,
    pub net: bool,
    pub volumes: Vec<VolumeMount>,
    pub nonce: [u8; NONCE_SIZE],
    pub passt_pid: Option<u32>,
    pub max_lifetime: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct VolumeMount {
    pub host: String,
    pub guest: String,
    pub read_only: bool,
}

/// Well-known files inside a VM directory.
const VM_JSON: &str = "vm.json";
const VM_LOCK: &str = "vm.lock";
const DISK_QCOW2: &str = "disk.qcow2";
pub const AGENT_SOCK: &str = "agent.sock";
const VM_LOG: &str = "vm.log";

/// Root directory for all VM state.
pub fn vms_dir() -> io::Result<PathBuf> {
    let base = data_home()?;
    Ok(base.join("arapuca").join("vms"))
}

/// Directory for a specific VM.
///
/// Validates the name to prevent path traversal — rejects names
/// containing `/`, `\`, `..`, or characters outside `[a-zA-Z0-9-]`.
pub fn vm_dir(name: &str) -> io::Result<PathBuf> {
    crate::sanitize_task_id(name).map_err(|e| {
        io::Error::new(io::ErrorKind::InvalidInput, format!("invalid VM name: {e}"))
    })?;
    Ok(vms_dir()?.join(name))
}

/// Create the VM directory (mode 0700). Fails if it already exists
/// unless `allow_existing` is true (for restart).
pub fn create_vm_dir(name: &str, allow_existing: bool) -> io::Result<PathBuf> {
    let parent = vms_dir()?;
    fs::create_dir_all(&parent)?;
    let dir = parent.join(name);
    match fs::create_dir(&dir) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists && allow_existing => {}
        Err(e) => return Err(e),
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
    }
    Ok(dir)
}

/// Path to the VM overlay disk.
pub fn overlay_path(name: &str) -> io::Result<PathBuf> {
    Ok(vm_dir(name)?.join(DISK_QCOW2))
}

/// Path to the agent Unix socket.
pub fn agent_sock_path(name: &str) -> io::Result<PathBuf> {
    Ok(vm_dir(name)?.join(AGENT_SOCK))
}

/// Path to the VM log file.
pub fn vm_log_path(name: &str) -> io::Result<PathBuf> {
    Ok(vm_dir(name)?.join(VM_LOG))
}

// ─── Lockfile ─────────────────────────────────────────────────

/// Acquire the VM lockfile (flock). Returns the held FD.
///
/// Uses `O_CREAT | O_NOFOLLOW` to prevent symlink attacks.
/// The lock is held for the VM's lifetime; the kernel releases
/// it if the process crashes.
pub fn acquire_lock(name: &str) -> io::Result<RawFd> {
    let path = vm_dir(name)?.join(VM_LOCK);

    let fd = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)?;

    use std::os::fd::IntoRawFd;
    let raw_fd = fd.into_raw_fd();

    // SAFETY: raw_fd is valid, LOCK_EX|LOCK_NB for non-blocking.
    let ret = unsafe { libc::flock(raw_fd, libc::LOCK_EX | libc::LOCK_NB) };
    if ret != 0 {
        // SAFETY: close the fd we own on failure.
        unsafe { libc::close(raw_fd) };
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!("VM '{name}' is already running"),
        ));
    }

    // Write PID as metadata.
    use std::os::fd::FromRawFd;
    // SAFETY: raw_fd is valid and we are the sole owner (into_raw_fd
    // consumed the original File).
    let mut lock_file = unsafe { fs::File::from_raw_fd(raw_fd) };
    lock_file.set_len(0)?;
    write!(lock_file, "{}", std::process::id())?;
    lock_file.flush()?;

    // Prevent File::drop from closing the fd — the caller owns it.
    std::mem::forget(lock_file);

    Ok(raw_fd)
}

/// Update the PID metadata in a held lockfile.
///
/// Called from the daemon (grandchild) after double-fork, since
/// the daemon has a different PID than the parent that acquired
/// the lock.
pub fn update_lock_pid(lock_fd: RawFd) -> io::Result<()> {
    use std::os::fd::FromRawFd;
    let mut lock_file = unsafe { fs::File::from_raw_fd(lock_fd) };
    lock_file.set_len(0)?;
    write!(lock_file, "{}", std::process::id())?;
    lock_file.flush()?;
    std::mem::forget(lock_file);
    Ok(())
}

/// Check if a VM is running by probing its lockfile.
///
/// Returns `true` if the lockfile exists and is held (flock fails
/// with EWOULDBLOCK).
pub fn is_running(name: &str) -> io::Result<bool> {
    let path = match vm_dir(name) {
        Ok(d) => d.join(VM_LOCK),
        Err(_) => return Ok(false),
    };
    if !path.exists() {
        return Ok(false);
    }

    let fd = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)
    {
        Ok(f) => f,
        Err(_) => return Ok(false),
    };

    use std::os::fd::AsRawFd;
    // SAFETY: valid fd, non-blocking exclusive flock.
    let ret = unsafe { libc::flock(fd.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if ret == 0 {
        // We got the lock → VM is NOT running. Release it.
        // SAFETY: valid fd.
        unsafe { libc::flock(fd.as_raw_fd(), libc::LOCK_UN) };
        Ok(false)
    } else {
        // flock failed → lock is held → VM IS running.
        Ok(true)
    }
}

/// Read the PID from the lockfile (supplementary metadata for display).
pub fn read_lock_pid(name: &str) -> io::Result<Option<u32>> {
    let path = vm_dir(name)?.join(VM_LOCK);
    match fs::read_to_string(&path) {
        Ok(s) => Ok(s.trim().parse().ok()),
        Err(_) => Ok(None),
    }
}

// ─── Nonce ────────────────────────────────────────────────────

/// Generate a cryptographically random 256-bit nonce.
pub fn generate_nonce() -> io::Result<[u8; NONCE_SIZE]> {
    let mut nonce = [0u8; NONCE_SIZE];
    // SAFETY: getrandom with valid buffer and no flags.
    let ret = unsafe { libc::getrandom(nonce.as_mut_ptr().cast(), NONCE_SIZE, 0) };
    if ret != NONCE_SIZE as isize {
        return Err(io::Error::other("getrandom failed to fill nonce"));
    }
    Ok(nonce)
}

// ─── vm.json ──────────────────────────────────────────────────

impl VmConfig {
    /// Write config to `vm.json` atomically (tmp+fsync+rename).
    pub fn save(&self, name: &str) -> io::Result<()> {
        let dir = vm_dir(name)?;
        let target = dir.join(VM_JSON);
        let tmp = dir.join(".vm.json.tmp");

        let json = self.to_json();
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&tmp)?;
        f.write_all(json.as_bytes())?;
        f.sync_all()?;
        fs::rename(&tmp, &target)?;
        Ok(())
    }

    /// Load config from `vm.json`.
    pub fn load(name: &str) -> io::Result<Self> {
        let path = vm_dir(name)?.join(VM_JSON);
        let json = fs::read_to_string(&path)?;
        Self::from_json(&json)
    }

    fn to_json(&self) -> String {
        let mut out = String::with_capacity(512);
        out.push('{');
        out.push_str("\"image\":");
        protocol::json_encode_string(&self.image, &mut out);
        out.push_str(&format!(",\"cpus\":{}", self.cpus));
        out.push_str(&format!(",\"mem_mb\":{}", self.mem_mb));
        out.push_str(&format!(",\"net\":{}", self.net));

        out.push_str(",\"volumes\":[");
        for (i, v) in self.volumes.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push_str("{\"host\":");
            protocol::json_encode_string(&v.host, &mut out);
            out.push_str(",\"guest\":");
            protocol::json_encode_string(&v.guest, &mut out);
            out.push_str(&format!(",\"read_only\":{}}}", v.read_only));
        }
        out.push(']');

        out.push_str(",\"nonce\":\"");
        for b in &self.nonce {
            out.push_str(&format!("{b:02x}"));
        }
        out.push('"');

        if let Some(pid) = self.passt_pid {
            out.push_str(&format!(",\"passt_pid\":{pid}"));
        }
        if let Some(lt) = self.max_lifetime {
            out.push_str(&format!(",\"max_lifetime\":{lt}"));
        }

        out.push('}');
        out
    }

    fn from_json(json: &str) -> io::Result<Self> {
        let mut p = protocol::JsonParser::new(json);
        p.skip_ws();
        p.expect_byte(b'{')?;

        let mut image = None;
        let mut cpus = None;
        let mut mem_mb = None;
        let mut net = None;
        let mut nonce = None;
        let mut passt_pid = None;
        let mut max_lifetime = None;
        let mut volumes = Vec::new();
        let mut first = true;

        loop {
            p.skip_ws();
            if p.peek() == Some(b'}') {
                p.advance();
                break;
            }
            if !first {
                p.expect_byte(b',')?;
            }
            first = false;

            p.skip_ws();
            let key = p.parse_string()?;
            p.skip_ws();
            p.expect_byte(b':')?;
            p.skip_ws();

            match key.as_str() {
                "image" => image = Some(p.parse_string()?),
                "cpus" => cpus = Some(p.parse_u64()? as u32),
                "mem_mb" => mem_mb = Some(p.parse_u64()? as u32),
                "net" => net = Some(p.parse_bool()?),
                "nonce" => {
                    let hex = p.parse_string()?;
                    nonce = Some(parse_nonce_hex(&hex).ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidData, "invalid nonce hex")
                    })?);
                }
                "passt_pid" => passt_pid = Some(p.parse_u64()? as u32),
                "max_lifetime" => max_lifetime = Some(p.parse_u64()?),
                "volumes" => {
                    p.expect_byte(b'[')?;
                    p.skip_ws();
                    if p.peek() != Some(b']') {
                        loop {
                            volumes.push(parse_volume_mount(&mut p)?);
                            p.skip_ws();
                            match p.peek() {
                                Some(b',') => p.advance(),
                                Some(b']') => break,
                                _ => {
                                    return Err(io::Error::new(
                                        io::ErrorKind::InvalidData,
                                        "expected ',' or ']' in volumes",
                                    ));
                                }
                            }
                        }
                    }
                    p.advance(); // ']'
                }
                _ => p.skip_value()?,
            }
        }

        Ok(VmConfig {
            image: image
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing 'image'"))?,
            cpus: cpus
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing 'cpus'"))?,
            mem_mb: mem_mb
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing 'mem_mb'"))?,
            net: net.unwrap_or(false),
            nonce: nonce
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing 'nonce'"))?,
            passt_pid,
            max_lifetime,
            volumes,
        })
    }
}

// ─── VM listing ───────────────────────────────────────────────

/// Information about a VM for display.
#[derive(Debug)]
pub struct VmInfo {
    pub name: String,
    pub running: bool,
    pub pid: Option<u32>,
    pub image: String,
    pub overlay_size_bytes: u64,
}

/// List all VMs.
pub fn list_vms() -> io::Result<Vec<VmInfo>> {
    let dir = vms_dir()?;
    if !dir.exists() {
        return Ok(Vec::new());
    }

    let mut vms = Vec::new();
    for entry in fs::read_dir(&dir)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().to_string();
        let running = is_running(&name).unwrap_or(false);
        let pid = if running {
            read_lock_pid(&name).ok().flatten()
        } else {
            None
        };
        let image = VmConfig::load(&name).map(|c| c.image).unwrap_or_default();
        let overlay_size_bytes = vm_dir(&name)
            .ok()
            .and_then(|d| fs::metadata(d.join(DISK_QCOW2)).ok())
            .map(|m| m.len())
            .unwrap_or(0);

        vms.push(VmInfo {
            name,
            running,
            pid,
            image,
            overlay_size_bytes,
        });
    }

    vms.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(vms)
}

/// Remove a stopped VM's directory.
pub fn remove_vm(name: &str) -> io::Result<()> {
    if is_running(name)? {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("VM '{name}' is still running"),
        ));
    }
    let dir = vm_dir(name)?;
    if dir.exists() {
        fs::remove_dir_all(&dir)?;
    }
    Ok(())
}

/// Remove stale state from crashed VMs.
pub fn prune_stale() -> io::Result<Vec<String>> {
    let dir = vms_dir()?;
    if !dir.exists() {
        return Ok(Vec::new());
    }

    let mut pruned = Vec::new();
    for entry in fs::read_dir(&dir)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().to_string();
        if !is_running(&name)? {
            // Kill orphaned passt if present.
            if let Ok(cfg) = VmConfig::load(&name) {
                if let Some(pid) = cfg.passt_pid {
                    kill_passt_if_valid(pid);
                }
            }
            // Clean up stale socket.
            let sock = entry.path().join(AGENT_SOCK);
            let _ = fs::remove_file(&sock);
            // Remove stale lockfile content.
            let lock = entry.path().join(VM_LOCK);
            if lock.exists() {
                let _ = fs::write(&lock, "");
            }
            pruned.push(name);
        }
    }
    Ok(pruned)
}

/// Verify /proc/<pid>/comm is "passt" before killing.
fn kill_passt_if_valid(pid: u32) {
    let comm_path = format!("/proc/{pid}/comm");
    if let Ok(comm) = fs::read_to_string(&comm_path) {
        if comm.trim() == "passt" {
            // SAFETY: pid verified as passt process via /proc/comm.
            unsafe { libc::kill(pid as i32, libc::SIGKILL) };
        }
    }
}

// ─── JSON helpers ─────────────────────────────────────────────

fn parse_volume_mount(p: &mut protocol::JsonParser<'_>) -> io::Result<VolumeMount> {
    p.skip_ws();
    p.expect_byte(b'{')?;

    let mut host = None;
    let mut guest = None;
    let mut read_only = None;
    let mut first = true;

    loop {
        p.skip_ws();
        if p.peek() == Some(b'}') {
            p.advance();
            break;
        }
        if !first {
            p.expect_byte(b',')?;
        }
        first = false;

        p.skip_ws();
        let key = p.parse_string()?;
        p.skip_ws();
        p.expect_byte(b':')?;
        p.skip_ws();

        match key.as_str() {
            "host" => host = Some(p.parse_string()?),
            "guest" => guest = Some(p.parse_string()?),
            "read_only" => read_only = Some(p.parse_bool()?),
            _ => p.skip_value()?,
        }
    }

    Ok(VolumeMount {
        host: host.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing 'host'"))?,
        guest: guest
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing 'guest'"))?,
        read_only: read_only.unwrap_or(false),
    })
}

fn parse_nonce_hex(hex: &str) -> Option<[u8; NONCE_SIZE]> {
    if hex.len() != NONCE_SIZE * 2 {
        return None;
    }
    let mut nonce = [0u8; NONCE_SIZE];
    for i in 0..NONCE_SIZE {
        nonce[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(nonce)
}

fn data_home() -> io::Result<PathBuf> {
    if let Ok(xdg) = std::env::var("XDG_DATA_HOME") {
        if !xdg.is_empty() {
            return Ok(PathBuf::from(xdg));
        }
    }
    match std::env::var("HOME") {
        Ok(home) if !home.is_empty() => Ok(PathBuf::from(home).join(".local").join("share")),
        _ => Err(io::Error::new(
            io::ErrorKind::NotFound,
            "neither XDG_DATA_HOME nor HOME is set",
        )),
    }
}

// ─── Tests ────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vm_config_roundtrip() {
        let nonce = [0xABu8; NONCE_SIZE];
        let cfg = VmConfig {
            image: "fedora:42".to_string(),
            cpus: 4,
            mem_mb: 4096,
            net: true,
            volumes: vec![
                VolumeMount {
                    host: "/home/user/data".to_string(),
                    guest: "/data".to_string(),
                    read_only: false,
                },
                VolumeMount {
                    host: "/etc/config".to_string(),
                    guest: "/config".to_string(),
                    read_only: true,
                },
            ],
            nonce,
            passt_pid: Some(12345),
            max_lifetime: Some(86400),
        };
        let json = cfg.to_json();
        let parsed = VmConfig::from_json(&json).unwrap();
        assert_eq!(parsed.image, cfg.image);
        assert_eq!(parsed.cpus, cfg.cpus);
        assert_eq!(parsed.mem_mb, cfg.mem_mb);
        assert_eq!(parsed.net, cfg.net);
        assert_eq!(parsed.nonce, cfg.nonce);
        assert_eq!(parsed.passt_pid, cfg.passt_pid);
        assert_eq!(parsed.max_lifetime, cfg.max_lifetime);
        assert_eq!(parsed.volumes.len(), 2);
        assert_eq!(parsed.volumes[0].host, "/home/user/data");
        assert!(parsed.volumes[1].read_only);
    }

    #[test]
    fn vm_config_minimal() {
        let cfg = VmConfig {
            image: "fedora:42".to_string(),
            cpus: 2,
            mem_mb: 2048,
            net: false,
            volumes: vec![],
            nonce: [0; NONCE_SIZE],
            passt_pid: None,
            max_lifetime: None,
        };
        let json = cfg.to_json();
        let parsed = VmConfig::from_json(&json).unwrap();
        assert_eq!(parsed.image, "fedora:42");
        assert!(!parsed.net);
        assert!(parsed.volumes.is_empty());
        assert!(parsed.passt_pid.is_none());
        assert!(parsed.max_lifetime.is_none());
    }

    #[test]
    fn nonce_hex_roundtrip() {
        let nonce = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB,
            0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67,
            0x89, 0xAB, 0xCD, 0xEF,
        ];
        let hex: String = nonce.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(parse_nonce_hex(&hex).unwrap(), nonce);
    }

    #[test]
    fn nonce_hex_invalid_length() {
        assert!(parse_nonce_hex("abcd").is_none());
    }

    #[test]
    fn generate_nonce_fills_bytes() {
        let nonce = generate_nonce().unwrap();
        assert_ne!(nonce, [0u8; NONCE_SIZE]);
    }

    #[test]
    fn vm_config_special_chars_in_image() {
        let cfg = VmConfig {
            image: r#"test","nonce":"0000fake"#.to_string(),
            cpus: 2,
            mem_mb: 2048,
            net: false,
            volumes: vec![],
            nonce: [0xAB; NONCE_SIZE],
            passt_pid: None,
            max_lifetime: None,
        };
        let json = cfg.to_json();
        let parsed = VmConfig::from_json(&json).unwrap();
        assert_eq!(parsed.image, cfg.image);
        assert_eq!(parsed.nonce, [0xAB; NONCE_SIZE]);
    }

    #[test]
    fn vm_config_unknown_fields_skipped() {
        let json = r#"{"image":"fedora:42","cpus":2,"mem_mb":2048,"net":false,"extra":"ignored","volumes":[],"nonce":"0000000000000000000000000000000000000000000000000000000000000000"}"#;
        let parsed = VmConfig::from_json(json).unwrap();
        assert_eq!(parsed.image, "fedora:42");
    }
}
