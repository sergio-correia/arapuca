use std::os::unix::io::RawFd;
use std::path::PathBuf;

/// Filesystem and resource restrictions for a sandboxed process.
#[derive(Debug, Clone, Default)]
pub struct Profile {
    /// Allowed read-only paths (canonicalized).
    pub read_paths: Vec<PathBuf>,
    /// Allowed read-write paths (canonicalized).
    pub write_paths: Vec<PathBuf>,
    /// Memory limit in MB (0 = no limit). u64 to support >4GB.
    pub max_memory_mb: u64,
    /// CPU percentage limit (0 = no limit; 200 = 2 cores).
    pub max_cpu_pct: u32,
    /// Maximum number of processes (0 = no limit).
    pub max_pids: u32,
    /// Maximum file size in MB via RLIMIT_FSIZE (0 = no limit).
    pub max_file_size_mb: u64,
    /// Whether execve is permitted (for git, test runners, etc.).
    pub allow_exec: bool,
    /// Use CLONE_NEWNET for network namespace isolation (Linux only).
    pub use_netns: bool,
}

/// Full configuration for launching a sandboxed process.
#[derive(Debug, Clone)]
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
    pub stdin: Option<RawFd>,
    /// Redirect subprocess stdout to this FD (None = inherit).
    pub stdout: Option<RawFd>,
    /// Redirect subprocess stderr to this FD (None = inherit).
    pub stderr: Option<RawFd>,
    /// Path to the network proxy Unix socket. When set, the subprocess
    /// receives an env var pointing to this socket. Uses a non-ARAPUCA
    /// prefix so it is not stripped by the binary.
    pub network_proxy_socket: Option<PathBuf>,
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
