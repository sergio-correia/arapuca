//! Windows sandbox implementation (stub).
//!
//! Will provide Job Objects, restricted tokens, integrity level reduction,
//! process mitigation policies, and desktop/window station isolation.
//! Full implementation is tracked in the Windows sandboxing plan.

use crate::platform::Sandbox;
use crate::{Config, Error, process::Process};

/// Windows sandbox implementation.
pub struct Windows;

impl Windows {
    pub fn new() -> crate::Result<Self> {
        Ok(Windows)
    }
}

impl Sandbox for Windows {
    fn launch(&self, _cfg: &Config, _cmd: &str, _args: &[&str]) -> crate::Result<Process> {
        Err(Error::Process("Windows sandbox not yet implemented".into()))
    }

    fn available(&self) -> crate::Result<()> {
        Err(Error::Process("Windows sandbox not yet implemented".into()))
    }

    fn netns_available(&self) -> bool {
        false
    }

    fn cgroups_available(&self) -> bool {
        false
    }
}
