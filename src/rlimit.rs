//! POSIX resource limits (rlimits).
//!
//! Sets hard resource limits on the sandboxed process:
//! - RLIMIT_CPU: CPU time in seconds
//! - RLIMIT_FSIZE: maximum file size
//! - RLIMIT_NOFILE: maximum open file descriptors
//!
//! Memory and PID limits are enforced via cgroups v2 (`memory.max`,
//! `pids.max`), not RLIMIT_AS/RLIMIT_NPROC. Both rlimits are
//! system-wide per-UID counters, not per-sandbox: RLIMIT_AS breaks
//! Go/JVM/.NET runtimes, and RLIMIT_NPROC counts all processes
//! under the UID, causing `clone()` EAGAIN when the system already
//! has more processes than the limit. Explicit opt-in via
//! `ARAPUCA_RLIMIT_AS` and `ARAPUCA_RLIMIT_NPROC` env vars is
//! still available in `apply_from_env()`.

use crate::{Error, Profile};

/// Apply resource limits from the profile to the current process.
///
/// Sets RLIMIT_CORE=0 unconditionally (prevents core dumps from
/// leaking secrets), plus RLIMIT_FSIZE and RLIMIT_NOFILE when
/// configured. Memory and PID limits are enforced via
/// cgroups v2 (`memory.max`, `pids.max`), not RLIMIT_AS/RLIMIT_NPROC.
/// Both are system-wide per-UID limits that break sandboxed workloads:
/// RLIMIT_AS kills Go/JVM/.NET at startup, and RLIMIT_NPROC fails
/// `clone()` when the UID already has more processes than the limit.
///
/// Each limit is set as both soft and hard (identical values), meaning
/// the process cannot raise them. Limits of 0 mean "no limit" and are
/// skipped.
///
/// # Errors
///
/// Returns an error if any `prlimit64` call fails.
#[must_use = "rlimit errors must be handled"]
pub fn apply(profile: &Profile) -> crate::Result<()> {
    set_rlimit(libc::RLIMIT_CORE, 0, "RLIMIT_CORE")?;
    if profile.max_file_size_mb > 0 {
        let bytes = profile
            .max_file_size_mb
            .checked_mul(1024 * 1024)
            .ok_or_else(|| Error::Rlimit("max_file_size_mb overflow".into()))?;
        set_rlimit(libc::RLIMIT_FSIZE, bytes, "RLIMIT_FSIZE")?;
    }
    if profile.max_open_files > 0 {
        set_rlimit(libc::RLIMIT_NOFILE, profile.max_open_files, "RLIMIT_NOFILE")?;
    }
    Ok(())
}

/// Apply resource limits parsed from environment variables.
///
/// Used by the binary. Reads `ARAPUCA_RLIMIT_AS`, `ARAPUCA_RLIMIT_NPROC`,
/// `ARAPUCA_RLIMIT_CPU`, `ARAPUCA_RLIMIT_FSIZE`, and `ARAPUCA_RLIMIT_NOFILE`
/// from the environment.
pub fn apply_from_env() -> crate::Result<()> {
    set_rlimit(libc::RLIMIT_CORE, 0, "RLIMIT_CORE")?;
    if let Some(v) = parse_env_u64("ARAPUCA_RLIMIT_AS")? {
        set_rlimit(libc::RLIMIT_AS, v, "RLIMIT_AS")?;
    }
    if let Some(v) = parse_env_u64("ARAPUCA_RLIMIT_NPROC")? {
        set_rlimit(libc::RLIMIT_NPROC, v, "RLIMIT_NPROC")?;
    }
    if let Some(v) = parse_env_u64("ARAPUCA_RLIMIT_CPU")? {
        set_rlimit(libc::RLIMIT_CPU, v, "RLIMIT_CPU")?;
    }
    if let Some(v) = parse_env_u64("ARAPUCA_RLIMIT_FSIZE")? {
        set_rlimit(libc::RLIMIT_FSIZE, v, "RLIMIT_FSIZE")?;
    }
    if let Some(v) = parse_env_u64("ARAPUCA_RLIMIT_NOFILE")? {
        set_rlimit(libc::RLIMIT_NOFILE, v, "RLIMIT_NOFILE")?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn set_rlimit(resource: libc::__rlimit_resource_t, value: u64, name: &str) -> crate::Result<()> {
    let rlim = libc::rlimit64 {
        rlim_cur: value,
        rlim_max: value,
    };
    // SAFETY: prlimit64 with pid=0 targets the calling process.
    // The rlimit struct is valid and on the stack.
    let ret = unsafe { libc::prlimit64(0, resource, &rlim, std::ptr::null_mut()) };
    if ret != 0 {
        return Err(Error::Rlimit(format!(
            "{name}: {}",
            std::io::Error::last_os_error()
        )));
    }
    log::debug!("rlimit: {name} = {value}");
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn set_rlimit(resource: libc::c_int, value: u64, name: &str) -> crate::Result<()> {
    let rlim = libc::rlimit {
        rlim_cur: value as libc::rlim_t,
        rlim_max: value as libc::rlim_t,
    };
    // SAFETY: setrlimit with valid resource and rlimit struct.
    let ret = unsafe { libc::setrlimit(resource, &rlim) };
    if ret != 0 {
        return Err(Error::Rlimit(format!(
            "{name}: {}",
            std::io::Error::last_os_error()
        )));
    }
    log::debug!("rlimit: {name} = {value}");
    Ok(())
}

fn parse_env_u64(name: &str) -> crate::Result<Option<u64>> {
    match std::env::var(name) {
        Ok(v) if !v.is_empty() => {
            let n = v
                .parse::<u64>()
                .map_err(|e| Error::Rlimit(format!("parse {name}: {e}")))?;
            if n > 0 { Ok(Some(n)) } else { Ok(None) }
        }
        _ => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_limits_are_skipped() {
        let profile = Profile::default();
        assert!(apply(&profile).is_ok());
    }

    #[test]
    fn parse_env_missing() {
        assert!(parse_env_u64("ARAPUCA_TEST_NONEXISTENT").unwrap().is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn apply_does_not_set_rlimit_as_or_nproc() {
        let read_rlimit = |resource| {
            let mut rlim: libc::rlimit64 = unsafe { std::mem::zeroed() };
            // SAFETY: prlimit64 with pid=0 reads the current process limit.
            unsafe { libc::prlimit64(0, resource, std::ptr::null(), &mut rlim) };
            rlim.rlim_cur
        };

        let as_before = read_rlimit(libc::RLIMIT_AS);
        let nproc_before = read_rlimit(libc::RLIMIT_NPROC);

        let profile = Profile {
            max_memory_mb: 256,
            max_pids: 32,
            ..Default::default()
        };
        apply(&profile).unwrap();

        let as_after = read_rlimit(libc::RLIMIT_AS);
        let nproc_after = read_rlimit(libc::RLIMIT_NPROC);

        assert_eq!(as_before, as_after, "apply() must not modify RLIMIT_AS");
        assert_eq!(
            nproc_before, nproc_after,
            "apply() must not modify RLIMIT_NPROC"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn apply_sets_rlimit_core_to_zero() {
        let profile = Profile::default();
        apply(&profile).unwrap();

        let mut rlim: libc::rlimit64 = unsafe { std::mem::zeroed() };
        // SAFETY: prlimit64 with pid=0 reads the current process limit.
        unsafe { libc::prlimit64(0, libc::RLIMIT_CORE, std::ptr::null(), &mut rlim) };
        assert_eq!(rlim.rlim_cur, 0, "apply() must set RLIMIT_CORE soft to 0");
        assert_eq!(rlim.rlim_max, 0, "apply() must set RLIMIT_CORE hard to 0");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn apply_from_env_honors_explicit_rlimit_as() {
        // SAFETY: test-only env manipulation, no concurrent threads
        // reading this variable.
        unsafe { std::env::set_var("ARAPUCA_RLIMIT_AS", "17179869184") };
        let result = apply_from_env();
        unsafe { std::env::remove_var("ARAPUCA_RLIMIT_AS") };
        assert!(result.is_ok(), "explicit ARAPUCA_RLIMIT_AS must be honored");
    }
}
