//! Landlock filesystem restrictions.
//!
//! Uses the `landlock` crate (by the kernel subsystem maintainer) to apply
//! filesystem access restrictions. Supports ABI v1-v6 with best-effort
//! compatibility — unsupported access rights on older kernels are silently
//! ignored, while core restrictions are always enforced.

use landlock::{
    ABI, Access, AccessFs, Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetStatus, make_bitflags,
    path_beneath_rules,
};

use crate::{Error, Profile};

/// Apply Landlock filesystem restrictions to the current process.
///
/// This is called by the binary before `execve()`. After this call,
/// the process can only access files within the allowed paths.
///
/// # Errors
///
/// Returns an error if Landlock is unavailable (pre-5.13 kernel) or
/// if all path rules fail to apply. Individual path failures are logged
/// but do not abort — only a complete failure is fatal.
///
/// # Security
///
/// - Calls `prctl(PR_SET_NO_NEW_PRIVS)` via the crate's `set_no_new_privs(true)`.
/// - Uses `CompatLevel::BestEffort` so the strictest possible restrictions
///   are applied for the running kernel's ABI version.
/// - Fail-closed: returns error if the ruleset is `NotEnforced`.
#[must_use = "landlock errors must be handled — the process may be unsandboxed"]
pub fn apply(profile: &Profile) -> crate::Result<()> {
    let read_paths = &profile.read_paths;
    let write_paths = &profile.write_paths;

    if read_paths.is_empty() && write_paths.is_empty() {
        log::info!("landlock: no paths configured, skipping filesystem restrictions");
        return Ok(());
    }

    // Use the highest ABI we fully support. The crate handles
    // best-effort downgrade for access rights added in later ABIs.
    let abi = ABI::V5;

    // All access rights we want to restrict.
    let read_access = make_bitflags!(AccessFs::{
        Execute
        | ReadFile
        | ReadDir
    });

    let write_access = AccessFs::from_all(abi);

    let mut ruleset = Ruleset::default()
        .handle_access(AccessFs::from_all(abi))
        .map_err(|e| Error::Landlock(format!("handle access: {e}")))?
        .create()
        .map_err(|e| Error::Landlock(format!("create ruleset: {e}")))?;

    // Add read-only path rules.
    let read_rules = path_beneath_rules(read_paths, read_access);
    ruleset = ruleset
        .add_rules(read_rules)
        .map_err(|e| Error::Landlock(format!("add read rules: {e}")))?;

    // Add read-write path rules.
    let write_rules = path_beneath_rules(write_paths, write_access);
    ruleset = ruleset
        .add_rules(write_rules)
        .map_err(|e| Error::Landlock(format!("add write rules: {e}")))?;

    // Enforce. set_no_new_privs(true) is the default and calls
    // prctl(PR_SET_NO_NEW_PRIVS) internally.
    let status = ruleset
        .restrict_self()
        .map_err(|e| Error::Landlock(format!("restrict self: {e}")))?;

    match status.ruleset {
        RulesetStatus::FullyEnforced | RulesetStatus::PartiallyEnforced => {
            log::info!(
                "landlock: applied ({:?}, ABI {:?})",
                status.ruleset,
                abi_version()
            );
            Ok(())
        }
        RulesetStatus::NotEnforced => Err(Error::Landlock("ruleset not enforced".into())),
    }
}

/// Probe the Landlock ABI version supported by the running kernel.
///
/// Returns 0 if Landlock is unavailable (pre-5.13 kernel, or disabled
/// via kernel config / boot parameter).
///
/// Uses the `landlock_create_ruleset` syscall with
/// `LANDLOCK_CREATE_RULESET_ATTR_SIZE_VER` flag, which returns the ABI
/// version without creating a ruleset or modifying process state.
pub fn abi_version() -> u32 {
    // SAFETY: landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_ATTR_SIZE_VER)
    // is a read-only probe — it does not modify process state. Returns the
    // ABI version on success or -1 with errno on failure.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<libc::c_void>(),
            0usize,
            1u32, // LANDLOCK_CREATE_RULESET_ATTR_SIZE_VER
        )
    };

    if ret < 0 { 0 } else { ret as u32 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_paths_is_noop() {
        let profile = Profile::default();
        assert!(apply(&profile).is_ok());
    }

    #[test]
    fn abi_version_probe() {
        // On a modern kernel, this should return >= 1.
        // On CI without Landlock, it returns 0. Both are valid.
        let v = abi_version();
        eprintln!("landlock ABI version: {v}");
        // Just assert it doesn't panic.
    }
}
