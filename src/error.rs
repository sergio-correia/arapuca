/// Errors returned by arapuca operations.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Landlock setup failed.
    #[error("landlock: {0}")]
    Landlock(String),

    /// Seccomp filter installation failed.
    #[error("seccomp: {0}")]
    Seccomp(String),

    /// Resource limit (rlimit) operation failed.
    #[error("rlimit: {0}")]
    Rlimit(String),

    /// Network namespace operation failed.
    #[error("netns: {0}")]
    Netns(String),

    /// Cgroup operation failed (hard failure — cannot proceed).
    #[error("cgroup: {0}")]
    Cgroup(String),

    /// Cgroup controller not delegated (soft failure — caller decides
    /// degradation policy).
    #[error("cgroup controller not delegated: {0}")]
    CgroupDegraded(String),

    /// Micro-VM operation failed.
    #[error("microvm: {0}")]
    MicroVm(String),

    /// Process launch or lifecycle error.
    #[error("process: {0}")]
    Process(String),

    /// Input validation error (bad task ID, invalid path, etc.).
    #[error("validation: {0}")]
    Validation(String),

    /// System call failed.
    #[error("syscall {name}: {source}")]
    Syscall {
        name: &'static str,
        source: std::io::Error,
    },

    /// I/O error.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}
