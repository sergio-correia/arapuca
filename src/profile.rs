#[cfg(unix)]
use std::os::unix::io::RawFd;
use std::path::PathBuf;
use std::sync::Arc;

use crate::audit::{AuditSink, AuditVerbosity};

/// Isolation level for a sandboxed process.
#[derive(Debug, Clone, Default)]
pub enum Isolation {
    /// Process-level sandbox (Landlock, seccomp, cgroups, netns).
    #[default]
    Process,
    /// Micro-VM sandbox (libkrun). Strongest isolation — the
    /// subprocess runs inside a lightweight virtual machine with
    /// its own kernel. Requires the `microvm` feature.
    MicroVm(MicroVmConfig),
}

impl Isolation {
    /// Returns the image source if this is a MicroVm isolation.
    pub fn image_source(&self) -> Option<&ImageSource> {
        match self {
            Self::MicroVm(cfg) => Some(&cfg.image),
            Self::Process => None,
        }
    }
}

/// Configuration for micro-VM isolation.
///
/// No `Default` — the caller must explicitly choose the image,
/// CPU count, and memory allocation.
#[derive(Debug, Clone)]
pub struct MicroVmConfig {
    /// Image to boot.
    pub image: ImageSource,
    /// Number of vCPUs.
    pub cpus: u32,
    /// RAM in MB.
    pub mem_mb: u32,
    /// Files to inject into the guest via cloud-init write_files.
    /// Each entry: (guest_path, content, optional permissions).
    pub write_files: Vec<GuestFile>,
}

/// A file to inject into a micro-VM guest.
#[derive(Debug, Clone)]
pub struct GuestFile {
    /// Absolute path in the guest.
    pub path: String,
    /// File content.
    pub content: String,
    /// File permissions (e.g., "0644"). Defaults to "0644" if None.
    pub permissions: Option<String>,
}

/// Source for a micro-VM root filesystem image.
#[derive(Debug, Clone)]
pub enum ImageSource {
    /// Absolute path to a qcow2 file.
    Path(PathBuf),
    /// Distro specifier resolved via built-in or external providers.
    Distro { name: String, version: String },
}

/// Seccomp filter profile for the sandbox.
///
/// Controls the restrictiveness of the syscall filter applied to the
/// sandboxed process. The filter is applied by the arapuca wrapper
/// binary after Landlock and before execve.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum SeccompProfile {
    /// Blocks AF_INET/AF_INET6 sockets, symlink, memfd_create,
    /// io_uring, pidfd, and other syscalls. Designed for untrusted
    /// code (scripts, build tools, agents).
    #[default]
    Strict,
    /// Blocks only sandbox-escape syscalls (ptrace, mount, namespace
    /// ops, kernel modules, bpf). Everything else is allowed.
    /// Designed for trusted-but-isolated applications (Claude Code,
    /// compilers) that need network sockets, memfd, io_uring, etc.
    /// Relies on Landlock + netns for the actual confinement.
    Baseline,
}

impl SeccompProfile {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Strict => "strict",
            Self::Baseline => "baseline",
        }
    }
}

/// Filesystem and resource restrictions for a sandboxed process.
#[derive(Debug, Clone, Default)]
pub struct Profile {
    /// Isolation level. Defaults to process-level sandbox.
    pub isolation: Isolation,
    /// Allowed read-only paths (canonicalized).
    pub read_paths: Vec<PathBuf>,
    /// Allowed read-write paths (canonicalized).
    pub write_paths: Vec<PathBuf>,
    /// Memory limit in MB (0 = no limit). Enforced via cgroups v2
    /// `memory.max` on Linux and RSS polling on macOS. u64 to
    /// support >4GB.
    pub max_memory_mb: u64,
    /// CPU percentage limit (0 = no limit; 200 = 2 cores).
    pub max_cpu_pct: u32,
    /// Maximum number of processes (0 = no limit). Enforced via
    /// cgroups v2 `pids.max` on Linux.
    pub max_pids: u32,
    /// Maximum file size in MB via RLIMIT_FSIZE (0 = no limit).
    pub max_file_size_mb: u64,
    /// Maximum open file descriptors via RLIMIT_NOFILE (0 = no limit).
    pub max_open_files: u64,
    /// Whether execve is permitted (for git, test runners, etc.).
    pub allow_exec: bool,
    /// Use CLONE_NEWNET for network namespace isolation (Linux only).
    pub use_netns: bool,
    /// Seccomp filter profile. Defaults to Strict.
    pub seccomp_profile: SeccompProfile,
}

/// Full configuration for launching a sandboxed process.
#[derive(Clone)]
pub struct Config {
    /// Security restrictions to apply.
    pub profile: Profile,
    /// Per-agent socket directory (created via tempdir, mode 0700).
    pub socket_dir: PathBuf,
    /// Task identifier. Validated: ^[a-zA-Z0-9-]+$, max 128 chars.
    pub task_id: String,
    /// Current phase (opaque to arapuca — passed through to caller).
    pub phase: String,
    /// Working directory for the subprocess (None = inherit).
    pub work_dir: Option<PathBuf>,
    /// Redirect subprocess stdin from this FD (None = inherit).
    #[cfg(unix)]
    pub stdin: Option<RawFd>,
    /// Redirect subprocess stdout to this FD (None = inherit).
    #[cfg(unix)]
    pub stdout: Option<RawFd>,
    /// Redirect subprocess stderr to this FD (None = inherit).
    #[cfg(unix)]
    pub stderr: Option<RawFd>,
    /// Additional FDs to inherit to the subprocess.
    #[cfg(unix)]
    pub extra_fds: Vec<RawFd>,
    /// Allocate a PTY pair and attach the slave as the child's
    /// controlling terminal. Incompatible with stdin/stdout/stderr
    /// redirection.
    #[cfg(unix)]
    pub tty: bool,
    /// Path to the network proxy Unix socket. When set, the subprocess
    /// receives an env var pointing to this socket. Uses a non-ARAPUCA
    /// prefix so it is not stripped by the binary.
    pub network_proxy_socket: Option<PathBuf>,
    /// Caller-supplied environment variables for the subprocess.
    /// Filtered by the platform launcher before use: ARAPUCA_*,
    /// LD_*, DYLD_*, and other dangerous names are silently dropped.
    /// If the same key is added multiple times, the last value wins.
    pub env: Vec<(String, String)>,
    /// Optional audit event sink. When None, no events are emitted
    /// and zero audit overhead is incurred.
    pub audit_sink: Option<Arc<dyn AuditSink>>,
    /// Controls how much detail audit events include.
    pub audit_verbosity: AuditVerbosity,
    /// Caller-supplied principal identity for audit records.
    pub audit_principal: Option<String>,
    /// Caller-supplied correlation ID for distributed tracing.
    pub audit_correlation_id: Option<String>,
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut s = f.debug_struct("Config");
        s.field("profile", &self.profile)
            .field("socket_dir", &self.socket_dir)
            .field("task_id", &self.task_id)
            .field("phase", &self.phase)
            .field("work_dir", &self.work_dir);
        #[cfg(unix)]
        {
            s.field("stdin", &self.stdin)
                .field("stdout", &self.stdout)
                .field("stderr", &self.stderr)
                .field("extra_fds", &self.extra_fds)
                .field("tty", &self.tty);
        }
        s.field("network_proxy_socket", &self.network_proxy_socket)
            .field("env", &format!("[{} vars]", self.env.len()))
            .field(
                "audit_sink",
                if self.audit_sink.is_some() {
                    &"Some(<AuditSink>)"
                } else {
                    &"None"
                },
            )
            .field("audit_verbosity", &self.audit_verbosity)
            .field("audit_principal", &self.audit_principal)
            .field("audit_correlation_id", &self.audit_correlation_id)
            .finish()
    }
}

/// Resource usage statistics from cgroups v2.
///
/// All fields are best-effort — they return zero if the corresponding
/// cgroup controller is unavailable or the stat file is unreadable.
#[derive(Debug, Clone, Default)]
pub struct ResourceUsage {
    /// Current memory usage in bytes.
    pub memory_current_bytes: i64,
    /// Peak memory usage in bytes (kernel 5.19+).
    pub memory_peak_bytes: i64,
    /// Total CPU time consumed in seconds.
    pub cpu_usage_seconds: f64,
    /// Number of processes in the cgroup.
    pub pid_count: i64,
    /// Total I/O bytes read (summed across all devices).
    pub io_read_bytes: i64,
    /// Total I/O bytes written (summed across all devices).
    pub io_write_bytes: i64,
}
