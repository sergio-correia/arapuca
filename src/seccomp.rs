//! Seccomp BPF syscall filtering.
//!
//! Uses the `seccompiler` crate (from AWS Firecracker) to construct and
//! install BPF filters that restrict which syscalls a sandboxed process
//! can make.
//!
//! Three tiers of response:
//! - **Tier 1 (KILL_PROCESS)**: Syscalls with no legitimate agent use
//!   (ptrace, mount, namespace manipulation, kernel modules, etc.).
//! - **Tier 2 (EPERM)**: Syscalls that may be probed by libraries
//!   (symlink, link, network sockets, clone with namespace flags, etc.).
//! - **Tier 3 (ENOSYS)**: `clone3` — forces runtime fallback to `clone`
//!   where namespace flags can be inspected via arg0.

use std::collections::HashMap;

use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
    SeccompRule, TargetArch,
};

use crate::Error;

/// Apply the seccomp BPF filter to the current process.
///
/// The filter restrictiveness depends on the profile:
/// - **Strict**: blocks AF_INET, symlink, memfd_create, io_uring, etc.
/// - **Baseline**: blocks only escape-critical syscalls (ptrace, mount,
///   namespace ops, kernel modules). Everything else allowed.
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
pub fn apply(profile: &crate::SeccompProfile) -> crate::Result<()> {
    match profile {
        crate::SeccompProfile::Strict => {
            let filter = build_filter()?;
            seccompiler::apply_filter(&filter).map_err(|e| Error::Seccomp(format!("{e}")))?;
            log::info!("seccomp: strict filter applied");
        }
        crate::SeccompProfile::Baseline => {
            let filter = build_baseline_filter()?;
            seccompiler::apply_filter(&filter).map_err(|e| Error::Seccomp(format!("{e}")))?;
            log::info!("seccomp: baseline filter applied");
        }
    }
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

    // prctl argument filtering: block all PR_SET_PDEATHSIG (any signal
    // value) and all non-zero PR_SET_DUMPABLE (including SUID_DUMP_ROOT=2).
    let prctl_block_pdeathsig = SeccompRule::new(vec![
        SeccompCondition::new(
            0,
            SeccompCmpArgLen::Dword,
            SeccompCmpOp::Eq,
            libc::PR_SET_PDEATHSIG as u64,
        )
        .map_err(|e| Error::Seccomp(format!("prctl condition: {e}")))?,
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
        SeccompCondition::new(1, SeccompCmpArgLen::Dword, SeccompCmpOp::Ne, 0u64)
            .map_err(|e| Error::Seccomp(format!("prctl arg condition: {e}")))?,
    ])
    .map_err(|e| Error::Seccomp(format!("prctl rule: {e}")))?;

    eperm_rules.insert(
        libc::SYS_prctl,
        vec![prctl_block_pdeathsig, prctl_set_dumpable],
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

    // Block ioctl(fd, TIOCSTI, ...) — terminal input injection.
    // On kernels < 6.2, a sandboxed process can inject keystrokes
    // into the parent's terminal via TIOCSTI on inherited FD 0.
    let ioctl_tiocsti = SeccompRule::new(vec![
        SeccompCondition::new(
            1,
            SeccompCmpArgLen::Dword,
            SeccompCmpOp::Eq,
            0x5412u64, // TIOCSTI
        )
        .map_err(|e| Error::Seccomp(format!("ioctl TIOCSTI condition: {e}")))?,
    ])
    .map_err(|e| Error::Seccomp(format!("ioctl TIOCSTI rule: {e}")))?;

    eperm_rules.insert(libc::SYS_ioctl, vec![ioctl_tiocsti]);

    // Block kill() with pid <= 0 (broadcast/group signals).
    // pid <= 0 covers kill(-1, sig) (all processes), kill(0, sig)
    // (process group), and kill(-pgid, sig) (specific group).
    // Safe for positive PIDs: Linux pid_max <= 4194304 (0x400000),
    // so no legitimate positive PID has bit 31 set.
    let kill_zero = SeccompRule::new(vec![
        SeccompCondition::new(0, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, 0u64)
            .map_err(|e| Error::Seccomp(format!("kill zero condition: {e}")))?,
    ])
    .map_err(|e| Error::Seccomp(format!("kill zero rule: {e}")))?;
    let kill_negative = SeccompRule::new(vec![
        SeccompCondition::new(
            0,
            SeccompCmpArgLen::Dword,
            SeccompCmpOp::MaskedEq(0x80000000),
            0x80000000,
        )
        .map_err(|e| Error::Seccomp(format!("kill negative condition: {e}")))?,
    ])
    .map_err(|e| Error::Seccomp(format!("kill negative rule: {e}")))?;
    eperm_rules.insert(libc::SYS_kill, vec![kill_zero, kill_negative]);

    // Block tkill unconditionally (deprecated, superseded by tgkill).
    eperm_rules.insert(libc::SYS_tkill, vec![]);

    // Block clone(2) with any CLONE_NEW* namespace flag. One rule per
    // flag — seccompiler OR's multiple rules for the same syscall.
    // Uses Qword (64-bit) to match the unsigned long flags argument.
    let clone_ns_flags: &[(i64, &str)] = &[
        (0x0002_0000, "CLONE_NEWNS"),
        (0x0200_0000, "CLONE_NEWCGROUP"),
        (0x0400_0000, "CLONE_NEWUTS"),
        (0x0800_0000, "CLONE_NEWIPC"),
        (0x1000_0000, "CLONE_NEWUSER"),
        (0x2000_0000, "CLONE_NEWPID"),
        (0x4000_0000, "CLONE_NEWNET"),
        (0x0000_0080, "CLONE_NEWTIME"),
    ];

    let mut clone_rules = Vec::new();
    for &(flag, name) in clone_ns_flags {
        let rule = SeccompRule::new(vec![
            SeccompCondition::new(
                0,
                SeccompCmpArgLen::Qword,
                SeccompCmpOp::MaskedEq(flag as u64),
                flag as u64,
            )
            .map_err(|e| Error::Seccomp(format!("clone {name} condition: {e}")))?,
        ])
        .map_err(|e| Error::Seccomp(format!("clone {name} rule: {e}")))?;
        clone_rules.push(rule);
    }
    eperm_rules.insert(libc::SYS_clone, clone_rules);

    // NOTE: we do NOT block seccomp(SET_MODE_FILTER) because seccomp
    // filters stack — new filters can only be more restrictive (kernel
    // takes the most restrictive action across all filters). Blocking it
    // would also prevent our three-phase filter installation.

    // --- ENOSYS filter for clone3 ---
    // Return ENOSYS so Go/glibc fall back to clone(2), where we CAN
    // inspect flags via arg0. This is the Chromium/Firefox approach.
    // We cannot filter clone3 flags because they're inside a struct
    // behind a pointer, not a direct syscall argument.
    let mut enosys_rules: HashMap<i64, Vec<SeccompRule>> = HashMap::new();
    enosys_rules.insert(libc::SYS_clone3, vec![]);

    let enosys_filter = SeccompFilter::new(
        enosys_rules.into_iter().collect(),
        SeccompAction::Allow,
        SeccompAction::Errno(libc::ENOSYS as u32),
        arch,
    )
    .map_err(|e| Error::Seccomp(format!("build enosys filter: {e}")))?;

    let enosys_prog: BpfProgram =
        enosys_filter
            .try_into()
            .map_err(|e: seccompiler::BackendError| {
                Error::Seccomp(format!("compile enosys filter: {e}"))
            })?;

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

    // Install order: ENOSYS → EPERM → KILL (last installed checked
    // first by kernel). The kernel takes the most restrictive action
    // across all filters: KILL > ERRNO > ALLOW. The ENOSYS and EPERM
    // filters target different syscalls (no overlap), so the equal
    // precedence of ERRNO values is not a concern.
    seccompiler::apply_filter(&enosys_prog)
        .map_err(|e| Error::Seccomp(format!("install enosys filter: {e}")))?;
    seccompiler::apply_filter(&eperm_prog)
        .map_err(|e| Error::Seccomp(format!("install eperm filter: {e}")))?;

    Ok(kill_prog)
}

// LSM syscalls (kernel 6.8+, generic table — same NR on x86_64/aarch64).
// Not yet in the libc crate for these architectures.
// TODO: replace with libc::SYS_lsm_* when the libc crate adds them.
// Reference: include/uapi/asm-generic/unistd.h
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
const SYS_LSM_GET_SELF_ATTR: i64 = 459;
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
const SYS_LSM_SET_SELF_ATTR: i64 = 460;
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
const SYS_LSM_LIST_MODULES: i64 = 461;

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
        libc::SYS_process_madvise,
        libc::SYS_memfd_secret,
        libc::SYS_landlock_create_ruleset,
        libc::SYS_landlock_add_rule,
        libc::SYS_landlock_restrict_self,
        libc::SYS_quotactl,
        libc::SYS_quotactl_fd,
        libc::SYS_swapon,
        libc::SYS_swapoff,
        libc::SYS_acct,
        libc::SYS_add_key,
        libc::SYS_request_key,
        libc::SYS_keyctl,
        SYS_LSM_GET_SELF_ATTR,
        SYS_LSM_SET_SELF_ATTR,
        SYS_LSM_LIST_MODULES,
    ]
}

/// Tier 2 syscalls: EPERM on match (unconditional).
/// May be probed by libraries; returning EPERM is less disruptive
/// than killing the process.
fn tier2_eperm_syscalls() -> Vec<i64> {
    #[allow(unused_mut)]
    let mut v = vec![
        libc::SYS_symlinkat,
        libc::SYS_linkat,
        libc::SYS_perf_event_open,
    ];
    #[cfg(target_arch = "x86_64")]
    {
        v.push(libc::SYS_symlink);
        v.push(libc::SYS_link);
    }
    v
}

/// Summary of the seccomp filter policy for audit reporting.
pub(crate) struct SeccompSummary {
    pub tier1_kill_count: usize,
    /// Count of unconditional EPERM syscalls only (symlinkat, linkat, etc.).
    /// Does not include argument-filtered rules (socket domain check,
    /// prctl argument check, execveat AT_EMPTY_PATH check, clone namespace
    /// flags check) — those are reported as separate bool flags below.
    pub tier2_eperm_count: usize,
    pub socket_filter: bool,
    pub prctl_filter: bool,
    pub clone_ns_filter: bool,
    pub clone3_enosys: bool,
    pub execveat_filter: bool,
    pub kill_filter: bool,
}

pub(crate) fn summary(profile: &crate::SeccompProfile) -> SeccompSummary {
    match profile {
        crate::SeccompProfile::Strict => SeccompSummary {
            tier1_kill_count: tier1_kill_syscalls().len(),
            tier2_eperm_count: tier2_eperm_syscalls().len(),
            socket_filter: true,
            prctl_filter: true,
            clone_ns_filter: true,
            clone3_enosys: true,
            execveat_filter: true,
            kill_filter: true,
        },
        crate::SeccompProfile::Baseline => SeccompSummary {
            tier1_kill_count: baseline_kill_syscalls().len(),
            tier2_eperm_count: 2, // tkill + perf_event_open
            socket_filter: false,
            prctl_filter: true,
            clone_ns_filter: true,
            clone3_enosys: true,
            execveat_filter: true,
            kill_filter: true,
        },
    }
}

/// Syscalls unconditionally blocked in the baseline profile.
fn baseline_kill_syscalls() -> Vec<i64> {
    vec![
        libc::SYS_ptrace,
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_pivot_root,
        libc::SYS_chroot,
        libc::SYS_mount_setattr,
        libc::SYS_move_mount,
        libc::SYS_open_tree,
        libc::SYS_fsopen,
        libc::SYS_fsconfig,
        libc::SYS_fsmount,
        libc::SYS_fspick,
        libc::SYS_unshare,
        libc::SYS_setns,
        libc::SYS_personality,
        libc::SYS_init_module,
        libc::SYS_finit_module,
        libc::SYS_delete_module,
        libc::SYS_kexec_load,
        libc::SYS_kexec_file_load,
        libc::SYS_reboot,
        libc::SYS_bpf,
        libc::SYS_process_vm_readv,
        libc::SYS_process_vm_writev,
        libc::SYS_landlock_create_ruleset,
        libc::SYS_landlock_add_rule,
        libc::SYS_landlock_restrict_self,
        libc::SYS_userfaultfd,
        SYS_LSM_SET_SELF_ATTR,
        libc::SYS_io_uring_setup,
        libc::SYS_io_uring_enter,
        libc::SYS_io_uring_register,
        libc::SYS_memfd_create,
        libc::SYS_pidfd_send_signal,
    ]
}

/// Build the baseline seccomp filter (default-allow, explicit deny).
///
/// Blocks escape-critical syscalls unconditionally, plus clone() with
/// namespace flags and clone3 (returns ENOSYS to force fallback to
/// clone where flags can be inspected).
fn build_baseline_filter() -> crate::Result<BpfProgram> {
    let arch = target_arch()?;

    let mut deny: HashMap<i64, Vec<SeccompRule>> = HashMap::new();
    for nr in baseline_kill_syscalls() {
        deny.insert(nr, vec![]);
    }

    let filter = SeccompFilter::new(
        deny.into_iter().collect(),
        SeccompAction::Allow,
        SeccompAction::KillProcess,
        arch,
    )
    .map_err(|e| Error::Seccomp(format!("build baseline filter: {e}")))?;

    let main_prog: BpfProgram = filter
        .try_into()
        .map_err(|e: seccompiler::BackendError| Error::Seccomp(format!("compile baseline: {e}")))?;

    // Stacked filter: block clone with namespace flags.
    // Default action = Allow (non-clone syscalls pass through).
    // Match action = KillProcess (clone with ns flags is killed).
    // We insert clone with a condition that matches when ANY
    // CLONE_NEW* flag is set. MaskedEq(CLONE_NEW_FLAGS, 0) matches
    // when no ns flags → we want the inverse.
    //
    // Approach: use a default-KillProcess filter that ALLOWS clone
    // only when no namespace flags are set. Other syscalls get
    // Allow (they're in the map with empty rules). clone without
    // ns flags also gets Allow. clone WITH ns flags falls through
    // to mismatch (KillProcess).
    //
    // Actually the simplest approach: use an EPERM filter for clone
    // with ns flags, matching the strict mode pattern.
    let mut clone_deny: HashMap<i64, Vec<SeccompRule>> = HashMap::new();

    // clone: kill if any CLONE_NEW* flag is present.
    // MaskedEq(mask, mask) matches when ALL bits in mask are set.
    // But we want to match when ANY bit is set. BPF can't do OR
    // directly. The strict mode uses 8 separate conditions ANDed
    // in one rule — that would match only when ALL 8 flags are set.
    //
    // Looking at the strict mode code: it uses
    // MaskedEq(CLONE_NEWNS, CLONE_NEWNS) for each flag in separate
    // rules. Multiple rules in the Vec are ORed — if ANY rule
    // matches, the action fires. So we need one rule per flag.
    let ns_flags = [
        libc::CLONE_NEWNS as u64,
        libc::CLONE_NEWCGROUP as u64,
        libc::CLONE_NEWUTS as u64,
        libc::CLONE_NEWIPC as u64,
        libc::CLONE_NEWUSER as u64,
        libc::CLONE_NEWPID as u64,
        libc::CLONE_NEWNET as u64,
        0x0000_0080, // CLONE_NEWTIME (Linux 5.6+, not yet in libc crate)
    ];
    let mut clone_rules = Vec::new();
    for flag in ns_flags {
        clone_rules.push(
            SeccompRule::new(vec![
                SeccompCondition::new(
                    0,
                    SeccompCmpArgLen::Qword,
                    SeccompCmpOp::MaskedEq(flag),
                    flag,
                )
                .map_err(|e| Error::Seccomp(format!("clone flag condition: {e}")))?,
            ])
            .map_err(|e| Error::Seccomp(format!("clone flag rule: {e}")))?,
        );
    }
    clone_deny.insert(libc::SYS_clone, clone_rules);

    // clone3 is handled by a separate ENOSYS stacked filter below.
    // Do NOT add it to the deny map — KillProcess would override
    // the ENOSYS (seccomp takes the most restrictive action).

    let clone_filter = SeccompFilter::new(
        clone_deny.into_iter().collect(),
        SeccompAction::Allow,
        SeccompAction::Errno(libc::EPERM as u32),
        arch,
    )
    .map_err(|e| Error::Seccomp(format!("build baseline clone filter: {e}")))?;

    let clone_prog: BpfProgram =
        clone_filter
            .try_into()
            .map_err(|e: seccompiler::BackendError| {
                Error::Seccomp(format!("compile baseline clone filter: {e}"))
            })?;

    // clone3 ENOSYS filter (same pattern as strict mode).
    let mut clone3_enosys: HashMap<i64, Vec<SeccompRule>> = HashMap::new();
    clone3_enosys.insert(libc::SYS_clone3, vec![]);
    let clone3_filter = SeccompFilter::new(
        clone3_enosys.into_iter().collect(),
        SeccompAction::Allow,
        SeccompAction::Errno(libc::ENOSYS as u32),
        arch,
    )
    .map_err(|e| Error::Seccomp(format!("build baseline clone3 enosys: {e}")))?;
    let clone3_prog: BpfProgram =
        clone3_filter
            .try_into()
            .map_err(|e: seccompiler::BackendError| {
                Error::Seccomp(format!("compile baseline clone3 enosys: {e}"))
            })?;

    // Install stacked filters: ENOSYS first, then clone deny, then main.
    // Last installed is checked first; most restrictive action wins.
    seccompiler::apply_filter(&clone3_prog)
        .map_err(|e| Error::Seccomp(format!("install baseline clone3 enosys: {e}")))?;
    seccompiler::apply_filter(&clone_prog)
        .map_err(|e| Error::Seccomp(format!("install baseline clone filter: {e}")))?;

    // Consolidated EPERM filter for all argument-filtered rules.
    // A single stacked filter reduces BPF evaluation overhead.
    let mut eperm_rules: HashMap<i64, Vec<SeccompRule>> = HashMap::new();

    // prctl(PR_SET_PDEATHSIG, *) and prctl(PR_SET_DUMPABLE, non-zero)
    let baseline_prctl_pdeathsig = SeccompRule::new(vec![
        SeccompCondition::new(
            0,
            SeccompCmpArgLen::Dword,
            SeccompCmpOp::Eq,
            libc::PR_SET_PDEATHSIG as u64,
        )
        .map_err(|e| Error::Seccomp(format!("baseline prctl condition: {e}")))?,
    ])
    .map_err(|e| Error::Seccomp(format!("baseline prctl rule: {e}")))?;
    let baseline_prctl_dumpable = SeccompRule::new(vec![
        SeccompCondition::new(
            0,
            SeccompCmpArgLen::Dword,
            SeccompCmpOp::Eq,
            libc::PR_SET_DUMPABLE as u64,
        )
        .map_err(|e| Error::Seccomp(format!("baseline prctl condition: {e}")))?,
        SeccompCondition::new(1, SeccompCmpArgLen::Dword, SeccompCmpOp::Ne, 0u64)
            .map_err(|e| Error::Seccomp(format!("baseline prctl arg condition: {e}")))?,
    ])
    .map_err(|e| Error::Seccomp(format!("baseline prctl rule: {e}")))?;
    eperm_rules.insert(
        libc::SYS_prctl,
        vec![baseline_prctl_pdeathsig, baseline_prctl_dumpable],
    );

    // execveat with AT_EMPTY_PATH (fileless execution)
    eperm_rules.insert(
        libc::SYS_execveat,
        vec![
            SeccompRule::new(vec![
                SeccompCondition::new(
                    4,
                    SeccompCmpArgLen::Dword,
                    SeccompCmpOp::MaskedEq(libc::AT_EMPTY_PATH as u64),
                    libc::AT_EMPTY_PATH as u64,
                )
                .map_err(|e| Error::Seccomp(format!("baseline execveat condition: {e}")))?,
            ])
            .map_err(|e| Error::Seccomp(format!("baseline execveat rule: {e}")))?,
        ],
    );

    // ioctl(TIOCSTI) — terminal input injection
    eperm_rules.insert(
        libc::SYS_ioctl,
        vec![
            SeccompRule::new(vec![
                SeccompCondition::new(1, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, 0x5412u64)
                    .map_err(|e| Error::Seccomp(format!("baseline ioctl condition: {e}")))?,
            ])
            .map_err(|e| Error::Seccomp(format!("baseline ioctl rule: {e}")))?,
        ],
    );

    // kill(pid <= 0) — broadcast/group signals
    let kill_zero = SeccompRule::new(vec![
        SeccompCondition::new(0, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, 0u64)
            .map_err(|e| Error::Seccomp(format!("baseline kill zero condition: {e}")))?,
    ])
    .map_err(|e| Error::Seccomp(format!("baseline kill zero rule: {e}")))?;
    let kill_negative = SeccompRule::new(vec![
        SeccompCondition::new(
            0,
            SeccompCmpArgLen::Dword,
            SeccompCmpOp::MaskedEq(0x80000000),
            0x80000000,
        )
        .map_err(|e| Error::Seccomp(format!("baseline kill negative condition: {e}")))?,
    ])
    .map_err(|e| Error::Seccomp(format!("baseline kill negative rule: {e}")))?;
    eperm_rules.insert(libc::SYS_kill, vec![kill_zero, kill_negative]);

    // tkill — deprecated, block unconditionally
    eperm_rules.insert(libc::SYS_tkill, vec![]);

    // perf_event_open — may be probed by profiling libraries
    eperm_rules.insert(libc::SYS_perf_event_open, vec![]);

    let eperm_filter = SeccompFilter::new(
        eperm_rules.into_iter().collect(),
        SeccompAction::Allow,
        SeccompAction::Errno(libc::EPERM as u32),
        arch,
    )
    .map_err(|e| Error::Seccomp(format!("build baseline eperm filter: {e}")))?;
    let eperm_prog: BpfProgram =
        eperm_filter
            .try_into()
            .map_err(|e: seccompiler::BackendError| {
                Error::Seccomp(format!("compile baseline eperm filter: {e}"))
            })?;
    seccompiler::apply_filter(&eperm_prog)
        .map_err(|e| Error::Seccomp(format!("install baseline eperm filter: {e}")))?;

    Ok(main_prog)
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
    fn tier1_count_is_exact() {
        assert_eq!(
            tier1_kill_syscalls().len(),
            49,
            "tier1 count changed — update this assertion if intentional"
        );
    }

    #[test]
    fn tier2_count_is_exact() {
        #[cfg(target_arch = "x86_64")]
        let expected = 5;
        #[cfg(target_arch = "aarch64")]
        let expected = 3;
        assert_eq!(
            tier2_eperm_syscalls().len(),
            expected,
            "tier2 count changed — update this assertion if intentional"
        );
    }

    #[test]
    fn tier1_no_duplicates() {
        let syscalls = tier1_kill_syscalls();
        let mut seen = std::collections::HashSet::new();
        for nr in &syscalls {
            assert!(seen.insert(nr), "duplicate tier1 syscall: {nr}");
        }
    }

    #[test]
    fn tier2_no_duplicates() {
        let syscalls = tier2_eperm_syscalls();
        let mut seen = std::collections::HashSet::new();
        for nr in &syscalls {
            assert!(seen.insert(nr), "duplicate tier2 syscall: {nr}");
        }
    }

    #[test]
    fn no_tier_overlap() {
        let t1: std::collections::HashSet<i64> = tier1_kill_syscalls().into_iter().collect();
        let t2: std::collections::HashSet<i64> = tier2_eperm_syscalls().into_iter().collect();
        let overlap: Vec<_> = t1.intersection(&t2).collect();
        assert!(overlap.is_empty(), "syscalls in both tiers: {overlap:?}");
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
            if let Err(e) = apply(&crate::SeccompProfile::Strict) {
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

    #[test]
    fn tier1_unshare_kills() {
        let (exited, sig) = run_in_filtered_child(|| {
            // SAFETY: unshare with 0 flags is harmless but triggers the filter.
            unsafe { libc::unshare(0) };
        });
        assert!(!exited, "unshare should be killed");
        assert_eq!(sig, libc::SIGSYS, "expected SIGSYS from seccomp KILL");
    }

    #[test]
    fn tier1_setns_kills() {
        let (exited, sig) = run_in_filtered_child(|| {
            // SAFETY: setns with invalid fd is harmless but triggers the filter.
            unsafe { libc::syscall(libc::SYS_setns, -1i32, 0i32) };
        });
        assert!(!exited, "setns should be killed");
        assert_eq!(sig, libc::SIGSYS, "expected SIGSYS from seccomp KILL");
    }

    #[test]
    fn clone3_returns_enosys() {
        let (exited, code) = run_in_filtered_child(|| {
            // SAFETY: clone3 with NULL args returns EFAULT normally,
            // but our filter intercepts before the kernel checks args.
            let ret = unsafe { libc::syscall(libc::SYS_clone3, std::ptr::null::<u8>(), 0usize) };
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            if ret < 0 && errno == libc::ENOSYS {
                unsafe { libc::_exit(42) };
            }
            unsafe { libc::_exit(1) };
        });
        assert!(exited, "clone3 should return ENOSYS, not kill");
        assert_eq!(code, 42, "expected ENOSYS (exit 42)");
    }

    #[test]
    fn clone_thread_still_allowed() {
        let (exited, code) = run_in_filtered_child(|| {
            const STACK_SIZE: usize = 64 * 1024;
            let stack = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    STACK_SIZE,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_STACK,
                    -1,
                    0,
                )
            };
            if stack == libc::MAP_FAILED {
                unsafe { libc::_exit(2) };
            }
            let stack_top = unsafe { (stack as *mut u8).add(STACK_SIZE) };

            // CLONE_THREAD requires CLONE_SIGHAND which requires CLONE_VM.
            const FLAGS: libc::c_ulong = (libc::CLONE_THREAD
                | libc::CLONE_SIGHAND
                | libc::CLONE_VM
                | libc::CLONE_FS
                | libc::CLONE_FILES) as libc::c_ulong;

            // SAFETY: valid stack, thread immediately exits.
            extern "C" fn thread_fn(_arg: *mut libc::c_void) -> libc::c_int {
                0
            }

            let ret = unsafe {
                libc::clone(
                    thread_fn,
                    stack_top.cast(),
                    FLAGS as i32,
                    std::ptr::null_mut(),
                )
            };
            if ret > 0 {
                unsafe { libc::_exit(42) };
            }
            unsafe { libc::_exit(1) };
        });
        assert!(exited, "clone(CLONE_THREAD) should not be killed");
        assert_eq!(code, 42, "thread creation should succeed");
    }

    #[test]
    fn clone_newuser_blocked() {
        let (exited, code) = run_in_filtered_child(|| {
            // SAFETY: clone with CLONE_NEWUSER and SIGCHLD, NULL stack
            // (kernel allocates). Will fail anyway but we just check the errno.
            let ret = unsafe {
                libc::syscall(
                    libc::SYS_clone,
                    libc::CLONE_NEWUSER | libc::SIGCHLD,
                    std::ptr::null::<u8>(),
                    std::ptr::null::<u8>(),
                    std::ptr::null::<u8>(),
                    0usize,
                )
            };
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            if ret < 0 && errno == libc::EPERM {
                unsafe { libc::_exit(42) };
            }
            unsafe { libc::_exit(1) };
        });
        assert!(exited, "clone(CLONE_NEWUSER) should return EPERM, not kill");
        assert_eq!(code, 42, "expected EPERM (exit 42)");
    }

    #[test]
    fn clone_newnet_blocked() {
        let (exited, code) = run_in_filtered_child(|| {
            let ret = unsafe {
                libc::syscall(
                    libc::SYS_clone,
                    libc::CLONE_NEWNET | libc::SIGCHLD,
                    std::ptr::null::<u8>(),
                    std::ptr::null::<u8>(),
                    std::ptr::null::<u8>(),
                    0usize,
                )
            };
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            if ret < 0 && errno == libc::EPERM {
                unsafe { libc::_exit(42) };
            }
            unsafe { libc::_exit(1) };
        });
        assert!(exited, "clone(CLONE_NEWNET) should return EPERM, not kill");
        assert_eq!(code, 42, "expected EPERM (exit 42)");
    }

    #[test]
    fn clone_combined_ns_thread_blocked() {
        let (exited, code) = run_in_filtered_child(|| {
            // Namespace flag takes precedence even combined with CLONE_THREAD.
            let ret = unsafe {
                libc::syscall(
                    libc::SYS_clone,
                    libc::CLONE_THREAD | libc::CLONE_NEWUSER | libc::SIGCHLD,
                    std::ptr::null::<u8>(),
                    std::ptr::null::<u8>(),
                    std::ptr::null::<u8>(),
                    0usize,
                )
            };
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            if ret < 0 && errno == libc::EPERM {
                unsafe { libc::_exit(42) };
            }
            unsafe { libc::_exit(1) };
        });
        assert!(
            exited,
            "clone(CLONE_THREAD|CLONE_NEWUSER) should return EPERM"
        );
        assert_eq!(code, 42, "namespace flag should override thread flag");
    }

    #[test]
    fn execveat_without_empty_path_allowed() {
        let (exited, code) = run_in_filtered_child(|| {
            // execveat with flags=0 (no AT_EMPTY_PATH) should NOT be
            // blocked by seccomp. The null path causes EFAULT, not EPERM.
            let ret = unsafe {
                libc::syscall(
                    libc::SYS_execveat,
                    libc::AT_FDCWD,
                    std::ptr::null::<libc::c_char>(),
                    std::ptr::null::<*const libc::c_char>(),
                    std::ptr::null::<*const libc::c_char>(),
                    0i32,
                )
            };
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            if ret < 0 && errno != libc::EPERM {
                unsafe { libc::_exit(42) };
            }
            unsafe { libc::_exit(1) };
        });
        assert!(exited, "child should exit normally");
        assert_eq!(
            code, 42,
            "execveat without AT_EMPTY_PATH should not be blocked"
        );
    }

    #[test]
    fn execveat_combined_flags_with_empty_path_blocked() {
        let (exited, code) = run_in_filtered_child(|| {
            // execveat with AT_EMPTY_PATH combined with other flags
            // should still be blocked by the MaskedEq filter.
            let ret = unsafe {
                libc::syscall(
                    libc::SYS_execveat,
                    -1i32,
                    b"\0".as_ptr(),
                    std::ptr::null::<*const libc::c_char>(),
                    std::ptr::null::<*const libc::c_char>(),
                    libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW,
                )
            };
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            if ret < 0 && errno == libc::EPERM {
                unsafe { libc::_exit(42) };
            }
            unsafe { libc::_exit(1) };
        });
        assert!(exited, "child should exit normally");
        assert_eq!(
            code, 42,
            "AT_EMPTY_PATH|AT_SYMLINK_NOFOLLOW should be blocked"
        );
    }

    #[test]
    fn tier1_quotactl_kills() {
        let (exited, sig) = run_in_filtered_child(|| {
            // SAFETY: quotactl with invalid args — triggers filter before kernel checks.
            unsafe { libc::syscall(libc::SYS_quotactl, 0i32, std::ptr::null::<u8>(), 0i32, 0u64) };
        });
        assert!(!exited, "quotactl should be killed");
        assert_eq!(sig, libc::SIGSYS, "expected SIGSYS from seccomp KILL");
    }

    #[test]
    fn tier1_lsm_set_self_attr_kills() {
        let (exited, sig) = run_in_filtered_child(|| {
            // SAFETY: raw syscall with invalid args — filter kills before kernel processes.
            unsafe { libc::syscall(SYS_LSM_SET_SELF_ATTR, 0u64, 0u64, 0u64, 0u64) };
        });
        assert!(!exited, "lsm_set_self_attr should be killed");
        assert_eq!(sig, libc::SIGSYS, "expected SIGSYS from seccomp KILL");
    }

    #[test]
    fn tier1_lsm_get_self_attr_kills() {
        let (exited, sig) = run_in_filtered_child(|| {
            // SAFETY: raw syscall with invalid args — filter kills before kernel processes.
            unsafe { libc::syscall(SYS_LSM_GET_SELF_ATTR, 0u64, 0u64, 0u64, 0u64) };
        });
        assert!(!exited, "lsm_get_self_attr should be killed");
        assert_eq!(sig, libc::SIGSYS, "expected SIGSYS from seccomp KILL");
    }

    #[test]
    fn tier1_lsm_list_modules_kills() {
        let (exited, sig) = run_in_filtered_child(|| {
            // SAFETY: raw syscall with invalid args — filter kills before kernel processes.
            // x86_64/aarch64: __NR_lsm_list_modules = 461
            unsafe { libc::syscall(SYS_LSM_LIST_MODULES, 0u64, 0u64, 0u64) };
        });
        assert!(!exited, "lsm_list_modules should be killed");
        assert_eq!(sig, libc::SIGSYS, "expected SIGSYS from seccomp KILL");
    }

    #[test]
    fn prctl_pdeathsig_zero_blocked() {
        let (exited, code) = run_in_filtered_child(|| {
            let ret = unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, 0) };
            if ret == -1 {
                let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
                if errno == libc::EPERM {
                    unsafe { libc::_exit(42) };
                }
            }
            unsafe { libc::_exit(1) };
        });
        assert!(exited, "child should exit normally");
        assert_eq!(code, 42, "PR_SET_PDEATHSIG=0 should return EPERM");
    }

    #[test]
    fn prctl_set_dumpable_blocked() {
        let (exited, code) = run_in_filtered_child(|| {
            let ret = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 1) };
            if ret == -1 {
                let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
                if errno == libc::EPERM {
                    unsafe { libc::_exit(42) };
                }
            }
            unsafe { libc::_exit(1) };
        });
        assert!(exited, "child should exit normally");
        assert_eq!(code, 42, "PR_SET_DUMPABLE=1 should return EPERM");
    }

    #[test]
    fn prctl_pdeathsig_sigkill_blocked() {
        let (exited, code) = run_in_filtered_child(|| {
            let ret = unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) };
            if ret == -1 {
                let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
                if errno == libc::EPERM {
                    unsafe { libc::_exit(42) };
                }
            }
            unsafe { libc::_exit(1) };
        });
        assert!(exited, "child should exit normally");
        assert_eq!(code, 42, "PR_SET_PDEATHSIG=SIGKILL should return EPERM");
    }

    #[test]
    fn prctl_pdeathsig_sigcont_blocked() {
        let (exited, code) = run_in_filtered_child(|| {
            let ret = unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGCONT) };
            if ret == -1 {
                let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
                if errno == libc::EPERM {
                    unsafe { libc::_exit(42) };
                }
            }
            unsafe { libc::_exit(1) };
        });
        assert!(exited, "child should exit normally");
        assert_eq!(code, 42, "PR_SET_PDEATHSIG=SIGCONT should return EPERM");
    }

    #[test]
    fn prctl_set_dumpable_two_blocked() {
        let (exited, code) = run_in_filtered_child(|| {
            let ret = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 2) };
            if ret == -1 {
                let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
                if errno == libc::EPERM {
                    unsafe { libc::_exit(42) };
                }
            }
            unsafe { libc::_exit(1) };
        });
        assert!(exited, "child should exit normally");
        assert_eq!(code, 42, "PR_SET_DUMPABLE=2 should return EPERM");
    }

    #[test]
    fn prctl_set_dumpable_zero_allowed() {
        let (exited, code) = run_in_filtered_child(|| {
            let ret = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0) };
            if ret == 0 {
                unsafe { libc::_exit(42) };
            }
            unsafe { libc::_exit(1) };
        });
        assert!(exited, "child should exit normally");
        assert_eq!(code, 42, "PR_SET_DUMPABLE=0 should succeed");
    }

    #[test]
    fn tier2_socket_inet6_eperm() {
        let (exited, code) = run_in_filtered_child(|| {
            let fd = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_STREAM, 0) };
            if fd < 0 {
                let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
                if errno == libc::EPERM {
                    unsafe { libc::_exit(42) };
                }
            }
            unsafe { libc::_exit(1) };
        });
        assert!(exited, "child should exit normally");
        assert_eq!(code, 42, "AF_INET6 socket should return EPERM");
    }

    fn run_in_baseline_child(test_fn: fn()) -> (bool, i32) {
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed");

        if pid == 0 {
            if let Err(e) = apply(&crate::SeccompProfile::Baseline) {
                eprintln!("seccomp baseline apply failed: {e}");
                unsafe { libc::_exit(99) };
            }
            test_fn();
            unsafe { libc::_exit(0) };
        }

        let mut wstatus: libc::c_int = 0;
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
    fn baseline_prctl_pdeathsig_blocked() {
        let (exited, code) = run_in_baseline_child(|| {
            let ret = unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, 0) };
            if ret == -1 {
                let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
                if errno == libc::EPERM {
                    unsafe { libc::_exit(42) };
                }
            }
            unsafe { libc::_exit(1) };
        });
        assert!(exited, "child should exit normally");
        assert_eq!(code, 42, "baseline: PR_SET_PDEATHSIG should return EPERM");
    }

    #[test]
    fn baseline_prctl_set_name_allowed() {
        let (exited, code) = run_in_baseline_child(|| {
            let name = std::ffi::CString::new("test").unwrap();
            let ret = unsafe { libc::prctl(libc::PR_SET_NAME, name.as_ptr()) };
            if ret == 0 {
                unsafe { libc::_exit(42) };
            }
            unsafe { libc::_exit(1) };
        });
        assert!(exited, "child should exit normally");
        assert_eq!(code, 42, "baseline: PR_SET_NAME should succeed");
    }
}
