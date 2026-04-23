//! Arapuca — Linux process sandbox.
//!
//! Provides Landlock filesystem restrictions, seccomp BPF syscall filtering,
//! cgroups v2 resource limits, network namespace isolation, and process
//! lifecycle management. Available as both a Rust library (with C FFI) and
//! a CLI binary.
//!
//! The sandbox is a mandatory security boundary — even a fully compromised
//! subprocess is contained by OS-enforced restrictions.

#![deny(unsafe_op_in_unsafe_fn)]

pub mod audit;
#[cfg(target_os = "linux")]
pub mod bridge;
#[cfg(target_os = "linux")]
pub mod cgroup;
pub mod diskquota;
pub mod env;
mod error;
pub mod ffi;
pub mod images;
#[cfg(target_os = "linux")]
pub mod landlock;
#[cfg(target_os = "linux")]
pub mod netns;
pub mod platform;
mod process;
mod profile;
#[cfg(unix)]
pub mod rlimit;
#[cfg(target_os = "linux")]
pub mod seccomp;
mod validate;

pub use process::Process;

pub use error::Error;
pub use profile::{
    Config, GuestFile, ImageSource, Isolation, MicroVmConfig, Profile, ResourceUsage,
};
pub use validate::{reject_cgroup_paths, sanitize_task_id};

/// Result type for arapuca operations.
pub type Result<T> = std::result::Result<T, Error>;
