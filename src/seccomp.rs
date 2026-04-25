//! Seccomp BPF syscall filtering.
//!
//! Uses the `seccompiler` crate (from AWS Firecracker) to construct and
//! install BPF filters that restrict which syscalls a sandboxed process
//! can make.
//!
//! Two tiers of response:
//! - **Tier 1 (KILL_PROCESS)**: Syscalls with no legitimate agent use
//!   (ptrace, mount, namespace manipulation, kernel modules, etc.).
//! - **Tier 2 (EPERM)**: Syscalls that may be probed by libraries
//!   (symlink, link, network sockets, perf_event_open, etc.).

use std::collections::HashMap;

use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
    SeccompRule, TargetArch,
};

use crate::Error;

/// Apply the seccomp BPF filter to the current process.
///
/// This calls `prctl(PR_SET_NO_NEW_PRIVS)` and then installs the filter.
/// After this call, the process is restricted to allowed syscalls. The
/// filter is inherited across `fork()` and `execve()`.
///
/// # Errors
///
/// Returns an error if filter construction or installation fails.
/// This is fail-closed — an error means the process is NOT filtered.
#[must_use = "seccomp errors must be handled — the process may be unfiltered"]
pub fn apply() -> crate::Result<()> {
    let filter = build_filter()?;
    seccompiler::apply_filter(&filter).map_err(|e| Error::Seccomp(format!("{e}")))?;
    log::info!("seccomp: filter applied");
    Ok(())
}

/// Build the seccomp BPF filter program.
///
/// The filter uses a default-allow policy with explicit deny rules.
/// This matches the Go implementation's approach: block dangerous
/// syscalls, allow everything else.
fn build_filter() -> crate::Result<BpfProgram> {
    let arch = target_arch()?;

    // Collect all rules: syscall -> (action, conditions).
    let mut rules: HashMap<i64, Vec<SeccompRule>> = HashMap::new();

    // --- Tier 1: KILL_PROCESS ---
    let tier1_syscalls = tier1_kill_syscalls();
    for nr in tier1_syscalls {
        // Empty rule vector = match unconditionally.
        rules.insert(nr, vec![]);
    }

    // --- Tier 2: EPERM ---
    // These are handled by a separate filter since seccompiler only
    // supports one match action per filter. We install two filters:
    // first the EPERM filter (checked last by kernel), then the KILL
    // filter (checked first by kernel). Seccomp filters stack — the
    // most restrictive action wins.

    // Build and install the Tier 1 (KILL) filter.
    let kill_filter = SeccompFilter::new(
        rules.into_iter().collect(),
        SeccompAction::Allow,
        SeccompAction::KillProcess,
        arch,
    )
    .map_err(|e| Error::Seccomp(format!("build kill filter: {e}")))?;

    let kill_prog: BpfProgram =
        kill_filter
            .try_into()
            .map_err(|e: seccompiler::BackendError| {
                Error::Seccomp(format!("compile kill filter: {e}"))
            })?;

    // Install KILL filter first (will be checked first by kernel due
    // to seccomp filter stacking — last installed is checked first).
    // Actually, we need to install the EPERM filter first so KILL
    // takes priority (last installed = checked first).

    // Build Tier 2 (EPERM) filter.
    let mut eperm_rules: HashMap<i64, Vec<SeccompRule>> = HashMap::new();
    for nr in tier2_eperm_syscalls() {
        eperm_rules.insert(nr, vec![]);
    }

    // Socket domain filtering: block AF_INET and AF_INET6.
    // socket(domain, type, protocol) — domain is arg0.
    let socket_inet = SeccompRule::new(vec![
        SeccompCondition::new(
            0,
            SeccompCmpArgLen::Dword,
            SeccompCmpOp::Eq,
            libc::AF_INET as u64,
        )
        .map_err(|e| Error::Seccomp(format!("socket AF_INET condition: {e}")))?,
    ])
    .map_err(|e| Error::Seccomp(format!("socket AF_INET rule: {e}")))?;

    let socket_inet6 = SeccompRule::new(vec![
        SeccompCondition::new(
            0,
            SeccompCmpArgLen::Dword,
            SeccompCmpOp::Eq,
            libc::AF_INET6 as u64,
        )
        .map_err(|e| Error::Seccomp(format!("socket AF_INET6 condition: {e}")))?,
    ])
    .map_err(|e| Error::Seccomp(format!("socket AF_INET6 rule: {e}")))?;

    eperm_rules.insert(libc::SYS_socket, vec![socket_inet, socket_inet6]);

    // prctl argument filtering: block PR_SET_PDEATHSIG=0 and PR_SET_DUMPABLE=1.
    let prctl_disable_pdeathsig = SeccompRule::new(vec![
        SeccompCondition::new(
            0,
            SeccompCmpArgLen::Dword,
            SeccompCmpOp::Eq,
            libc::PR_SET_PDEATHSIG as u64,
        )
        .map_err(|e| Error::Seccomp(format!("prctl condition: {e}")))?,
        SeccompCondition::new(1, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, 0u64)
            .map_err(|e| Error::Seccomp(format!("prctl arg condition: {e}")))?,
    ])
    .map_err(|e| Error::Seccomp(format!("prctl rule: {e}")))?;

    let prctl_set_dumpable = SeccompRule::new(vec![
        SeccompCondition::new(
            0,
            SeccompCmpArgLen::Dword,
            SeccompCmpOp::Eq,
            libc::PR_SET_DUMPABLE as u64,
        )
        .map_err(|e| Error::Seccomp(format!("prctl condition: {e}")))?,
        SeccompCondition::new(1, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, 1u64)
            .map_err(|e| Error::Seccomp(format!("prctl arg condition: {e}")))?,
    ])
    .map_err(|e| Error::Seccomp(format!("prctl rule: {e}")))?;

    eperm_rules.insert(
        libc::SYS_prctl,
        vec![prctl_disable_pdeathsig, prctl_set_dumpable],
    );

    // Block execveat with AT_EMPTY_PATH (fileless execution).
    // execveat(fd, "", ..., flags) — flags is arg4.
    let execveat_empty_path = SeccompRule::new(vec![
        SeccompCondition::new(
            4,
            SeccompCmpArgLen::Dword,
            SeccompCmpOp::MaskedEq(libc::AT_EMPTY_PATH as u64),
            libc::AT_EMPTY_PATH as u64,
        )
        .map_err(|e| Error::Seccomp(format!("execveat condition: {e}")))?,
    ])
    .map_err(|e| Error::Seccomp(format!("execveat rule: {e}")))?;

    eperm_rules.insert(libc::SYS_execveat, vec![execveat_empty_path]);

    // NOTE: we do NOT block seccomp(SET_MODE_FILTER) because seccomp
    // filters stack — new filters can only be more restrictive (kernel
    // takes the most restrictive action across all filters). Blocking it
    // would also prevent our own two-phase filter installation since the
    // EPERM filter is installed before the KILL filter.

    let eperm_filter = SeccompFilter::new(
        eperm_rules.into_iter().collect(),
        SeccompAction::Allow,
        SeccompAction::Errno(libc::EPERM as u32),
        arch,
    )
    .map_err(|e| Error::Seccomp(format!("build eperm filter: {e}")))?;

    let eperm_prog: BpfProgram =
        eperm_filter
            .try_into()
            .map_err(|e: seccompiler::BackendError| {
                Error::Seccomp(format!("compile eperm filter: {e}"))
            })?;

    // Install EPERM filter first. Seccomp filter stacking: last
    // installed is checked first. Since KILL is more restrictive than
    // EPERM, and the kernel takes the most restrictive action across
    // all filters, the ordering doesn't actually matter for
    // correctness. But we install EPERM first so the KILL filter's
    // PR_SET_NO_NEW_PRIVS call covers both.
    seccompiler::apply_filter(&eperm_prog)
        .map_err(|e| Error::Seccomp(format!("install eperm filter: {e}")))?;

    Ok(kill_prog)
}

/// Tier 1 syscalls: KILL_PROCESS on match.
/// No legitimate use by sandboxed agents.
fn tier1_kill_syscalls() -> Vec<i64> {
    vec![
        libc::SYS_ptrace,
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_reboot,
        libc::SYS_kexec_load,
        libc::SYS_kexec_file_load,
        libc::SYS_pivot_root,
        libc::SYS_chroot,
        libc::SYS_init_module,
        libc::SYS_finit_module,
        libc::SYS_delete_module,
        libc::SYS_unshare,
        libc::SYS_setns,
        libc::SYS_personality,
        libc::SYS_memfd_create,
        libc::SYS_process_vm_readv,
        libc::SYS_process_vm_writev,
        libc::SYS_userfaultfd,
        libc::SYS_kcmp,
        libc::SYS_clone3,
        libc::SYS_io_uring_setup,
        libc::SYS_io_uring_enter,
        libc::SYS_io_uring_register,
        libc::SYS_bpf,
        libc::SYS_mount_setattr,
        libc::SYS_move_mount,
        libc::SYS_open_tree,
        libc::SYS_fsopen,
        libc::SYS_fsconfig,
        libc::SYS_fsmount,
        libc::SYS_fspick,
        libc::SYS_pidfd_open,
        libc::SYS_pidfd_getfd,
        libc::SYS_pidfd_send_signal,
    ]
}

/// Tier 2 syscalls: EPERM on match (unconditional).
/// May be probed by libraries; returning EPERM is less disruptive
/// than killing the process.
fn tier2_eperm_syscalls() -> Vec<i64> {
    vec![
        libc::SYS_symlink,
        libc::SYS_symlinkat,
        libc::SYS_link,
        libc::SYS_linkat,
        libc::SYS_perf_event_open,
    ]
}

/// Summary of the seccomp filter policy for audit reporting.
pub(crate) struct SeccompSummary {
    pub tier1_kill_count: usize,
    pub tier2_eperm_count: usize,
    pub socket_filter: bool,
    pub prctl_filter: bool,
}

// NOTE: socket_filter and prctl_filter are hardcoded to match
// build_filter(). Update these if those filters become conditional.
pub(crate) fn summary() -> SeccompSummary {
    SeccompSummary {
        tier1_kill_count: tier1_kill_syscalls().len(),
        tier2_eperm_count: tier2_eperm_syscalls().len(),
        socket_filter: true,
        prctl_filter: true,
    }
}

/// Determine the target architecture for seccompiler.
pub(crate) fn target_arch() -> crate::Result<TargetArch> {
    #[cfg(target_arch = "x86_64")]
    {
        Ok(TargetArch::x86_64)
    }
    #[cfg(target_arch = "aarch64")]
    {
        Ok(TargetArch::aarch64)
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        Err(Error::Seccomp(format!(
            "unsupported architecture: {}",
            std::env::consts::ARCH
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tier1_syscalls_not_empty() {
        assert!(!tier1_kill_syscalls().is_empty());
    }

    #[test]
    fn tier2_syscalls_not_empty() {
        assert!(!tier2_eperm_syscalls().is_empty());
    }

    #[test]
    fn target_arch_resolves() {
        assert!(target_arch().is_ok());
    }

    #[test]
    fn filter_builds() {
        // Verify the filter compiles without error.
        // We don't apply it here because that would restrict this test process.
        assert!(build_filter().is_ok());
    }

    /// Fork a child, apply the seccomp filter, run `test_fn`, and
    /// check the exit status. Returns (exited_normally, exit_code_or_signal).
    fn run_in_filtered_child(test_fn: fn()) -> (bool, i32) {
        // SAFETY: fork is safe here — single-threaded test process.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed");

        if pid == 0 {
            // Child: apply filter and run the test.
            if let Err(e) = apply() {
                eprintln!("seccomp apply failed: {e}");
                unsafe { libc::_exit(99) };
            }
            test_fn();
            unsafe { libc::_exit(0) };
        }

        // Parent: wait for child and inspect status.
        let mut wstatus: libc::c_int = 0;
        // SAFETY: pid is valid from fork.
        let ret = unsafe { libc::waitpid(pid, &mut wstatus, 0) };
        assert!(ret > 0, "waitpid failed");

        if libc::WIFEXITED(wstatus) {
            (true, libc::WEXITSTATUS(wstatus))
        } else if libc::WIFSIGNALED(wstatus) {
            (false, libc::WTERMSIG(wstatus))
        } else {
            panic!("unexpected wait status: {wstatus}");
        }
    }

    #[test]
    fn tier1_pidfd_open_kills() {
        let (exited, sig) = run_in_filtered_child(|| {
            // SAFETY: syscall with valid args.
            unsafe { libc::syscall(libc::SYS_pidfd_open, libc::getpid(), 0) };
        });
        assert!(!exited, "child should be killed, not exit normally");
        assert_eq!(sig, libc::SIGSYS, "expected SIGSYS from seccomp KILL");
    }

    #[test]
    fn tier1_fspick_kills() {
        let (exited, sig) = run_in_filtered_child(|| {
            let path = b"/\0".as_ptr();
            // SAFETY: syscall with valid args.
            unsafe { libc::syscall(libc::SYS_fspick, libc::AT_FDCWD, path, 0) };
        });
        assert!(!exited, "child should be killed, not exit normally");
        assert_eq!(sig, libc::SIGSYS, "expected SIGSYS from seccomp KILL");
    }

    #[test]
    fn tier2_execveat_empty_path_eperm() {
        let (exited, code) = run_in_filtered_child(|| {
            let empty = b"\0".as_ptr();
            // SAFETY: syscall with AT_EMPTY_PATH flag.
            let ret = unsafe {
                libc::syscall(
                    libc::SYS_execveat,
                    -1i32,
                    empty,
                    std::ptr::null::<*const libc::c_char>(),
                    std::ptr::null::<*const libc::c_char>(),
                    libc::AT_EMPTY_PATH,
                )
            };
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            if ret < 0 && errno == libc::EPERM {
                unsafe { libc::_exit(42) };
            }
            unsafe { libc::_exit(1) };
        });
        assert!(exited, "child should exit normally");
        assert_eq!(code, 42, "expected EPERM (exit 42)");
    }

    #[test]
    fn tier2_socket_inet_eperm() {
        let (exited, code) = run_in_filtered_child(|| {
            let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
            if fd < 0 {
                let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
                if errno == libc::EPERM {
                    unsafe { libc::_exit(42) };
                }
            }
            unsafe { libc::_exit(1) };
        });
        assert!(exited, "child should exit normally");
        assert_eq!(code, 42, "expected EPERM (exit 42)");
    }

    #[test]
    fn tier2_socket_unix_allowed() {
        let (exited, code) = run_in_filtered_child(|| {
            let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
            if fd >= 0 {
                unsafe {
                    libc::close(fd);
                    libc::_exit(42);
                }
            }
            unsafe { libc::_exit(1) };
        });
        assert!(exited, "child should exit normally");
        assert_eq!(code, 42, "AF_UNIX socket should be allowed");
    }
}
