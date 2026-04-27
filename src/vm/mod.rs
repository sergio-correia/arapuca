//! Persistent VM lifecycle management.
//!
//! Provides the infrastructure for long-running VMs with interactive
//! access via vsock-based host↔guest communication.

pub mod daemon;
pub mod protocol;
pub mod state;
