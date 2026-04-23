//! Structured audit events for sandbox lifecycle.
//!
//! Provides machine-readable events recording what restrictions were applied,
//! what was allowed or denied, and what resources were consumed. Events are
//! emitted via a caller-supplied [`AuditSink`] trait object — the library
//! performs no I/O or serialization unless the caller opts in.

use std::sync::Arc;
use std::time::{Instant, SystemTime};

// ─── Timestamp ─────────────────────────────────────────────────────

/// Monotonic timestamp (nanoseconds since sandbox creation).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct AuditTimestamp(pub u64);

// ─── Event types ───────────────────────────────────────────────────

/// A single audit event emitted during sandbox lifecycle.
///
/// Events within a single sandbox lifecycle are emitted in causal order.
/// The monotonic [`AuditTimestamp`] provides total ordering.
#[derive(Debug, Clone)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(tag = "event_type"))]
pub enum AuditEvent {
    /// Sandbox creation started. Always the first event.
    ///
    /// `wall_clock_epoch_ns` anchors the monotonic timeline to wall-clock
    /// time for SIEM correlation. The consumer computes absolute time as
    /// `wall_clock_epoch_ns + timestamp.0`.
    #[non_exhaustive]
    SandboxInit {
        timestamp: AuditTimestamp,
        wall_clock_epoch_ns: u64,
        schema_version: u32,
        task_id: String,
        phase: String,
        command: String,
        arg_count: usize,
        /// Only populated when [`AuditVerbosity::Verbose`].
        args: Option<Vec<String>>,
        principal: Option<String>,
        correlation_id: Option<String>,
    },

    /// A sandbox layer was successfully applied.
    #[non_exhaustive]
    LayerApplied {
        timestamp: AuditTimestamp,
        layer: SandboxLayer,
        detail: Option<LayerDetail>,
    },

    /// A sandbox layer was skipped (degraded mode).
    #[non_exhaustive]
    LayerSkipped {
        timestamp: AuditTimestamp,
        layer: SandboxLayer,
        reason: SkipReason,
    },

    /// A sandbox layer failed to apply (fatal).
    #[non_exhaustive]
    LayerFailed {
        timestamp: AuditTimestamp,
        layer: SandboxLayer,
        error: String,
    },

    /// Environment variable filtering outcome.
    ///
    /// Key names are logged (the audit consumer already has full visibility
    /// into the environment). Values are NEVER logged.
    #[non_exhaustive]
    EnvPolicy {
        timestamp: AuditTimestamp,
        passed_keys: Vec<String>,
        dropped: Vec<DroppedEnvVar>,
    },

    /// Filesystem access policy summary.
    #[non_exhaustive]
    FilesystemPolicy {
        timestamp: AuditTimestamp,
        read_paths: Vec<String>,
        write_paths: Vec<String>,
    },

    /// Resource limits applied.
    #[non_exhaustive]
    ResourceLimits {
        timestamp: AuditTimestamp,
        memory_mb: u64,
        cpu_pct: u32,
        max_pids: u32,
        max_file_size_mb: u64,
        allow_exec: bool,
    },

    /// Network policy applied.
    #[non_exhaustive]
    NetworkPolicy {
        timestamp: AuditTimestamp,
        isolated: bool,
        proxy_socket: Option<String>,
    },

    /// Seccomp filter policy summary.
    #[non_exhaustive]
    SeccompPolicy {
        timestamp: AuditTimestamp,
        tier1_kill_count: usize,
        tier2_eperm_count: usize,
        socket_filter: bool,
        prctl_filter: bool,
        allow_exec: bool,
    },

    /// FD inheritance summary.
    #[non_exhaustive]
    FdInheritance {
        timestamp: AuditTimestamp,
        inherited_fds: Vec<i32>,
        stdin_redirected: bool,
        stdout_redirected: bool,
        stderr_redirected: bool,
    },

    /// All mandatory sandbox layers applied — the process is about to start.
    ///
    /// This is the primary event compliance systems should key on.
    /// Absence of this event after [`AuditEvent::SandboxInit`] means the
    /// setup was interrupted.
    #[non_exhaustive]
    SandboxReady {
        timestamp: AuditTimestamp,
        applied_layers: Vec<SandboxLayer>,
        skipped_layers: Vec<SandboxLayer>,
    },

    /// Subprocess launched successfully.
    #[non_exhaustive]
    ProcessStarted { timestamp: AuditTimestamp, pid: u32 },

    /// Subprocess exited.
    ///
    /// `exit_code`, `signal`, and `oom_kill_count` are influenced by the
    /// child process (kernel observations, not forgeable).
    #[non_exhaustive]
    ProcessExited {
        timestamp: AuditTimestamp,
        pid: u32,
        exit_code: Option<i32>,
        signal: Option<i32>,
        oom_kill_count: u32,
    },

    /// Resource usage at exit (from cgroups).
    #[non_exhaustive]
    ResourceUsage {
        timestamp: AuditTimestamp,
        memory_current_bytes: i64,
        memory_peak_bytes: i64,
        cpu_seconds: f64,
        pid_count: i64,
        io_read_bytes: i64,
        io_write_bytes: i64,
    },

    /// Sandbox cleanup completed.
    #[non_exhaustive]
    SandboxCleanup {
        timestamp: AuditTimestamp,
        cgroup_destroyed: bool,
        tmpdir_removed: bool,
        dacls_restored: Option<bool>,
        container_deleted: Option<bool>,
    },
}

/// Current schema version. Incremented only for breaking changes.
pub const SCHEMA_VERSION: u32 = 1;

// ─── Supporting types ──────────────────────────────────────────────

/// Sandbox isolation layers.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub enum SandboxLayer {
    Landlock,
    Seccomp,
    Cgroup,
    NetworkNamespace,
    Rlimit,
    Setsid,
    Pdeathsig,
    NoNewPrivs,
    EnvFilter,
    FdSanitization,
    // macOS
    Seatbelt,
    MemoryMonitor,
    ParentWatchdog,
    // Windows
    AppContainer,
    JobObject,
    RestrictedToken,
    IntegrityLevel,
    MitigationPolicy,
    DaclGrant,
}

/// Structured detail for a successfully applied layer.
#[derive(Debug, Clone)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub enum LayerDetail {
    Landlock {
        abi_version: u32,
        fully_enforced: bool,
    },
    Cgroup {
        path: String,
    },
    Other(String),
}

/// Reason a sandbox layer was skipped.
#[derive(Debug, Clone)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub enum SkipReason {
    NotAvailable,
    NotConfigured,
    PlatformUnsupported,
    ComponentMissing(String),
    PartialFailure(String),
}

/// Why an environment variable was dropped during filtering.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub enum DropReason {
    ArapucaPrefix,
    LauncherReserved,
    LdPrefix,
    DyldPrefix,
    DotnetPrefix,
    InterpreterInjection,
    ShellInjection,
    WindowsShimInjection,
}

/// An environment variable that was dropped during filtering.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct DroppedEnvVar {
    pub key: String,
    pub reason: DropReason,
}

/// Controls how much detail audit events include.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub enum AuditVerbosity {
    #[default]
    Standard,
    Verbose,
}

// ─── Sink trait ────────────────────────────────────────────────────

/// Receiver for audit events.
///
/// # Contract
///
/// - **Must not panic.** Panics are caught via `catch_unwind` and the
///   event is lost, but repeated panics degrade audit coverage.
/// - **Must not block.** `emit()` runs synchronously on the sandbox
///   creation thread. For I/O-bound sinks, buffer in memory and flush
///   asynchronously.
/// - **Must not call back into arapuca.** Reentrancy may deadlock.
///
/// Implementations using `Mutex` should handle poisoning gracefully
/// (e.g., `lock().unwrap_or_else(|e| e.into_inner())`).
pub trait AuditSink: Send + Sync {
    fn emit(&self, event: AuditEvent);

    /// If true, audit failure (emit panic) aborts the sandbox launch.
    ///
    /// Default: false (best-effort audit). A mandatory failure during
    /// cleanup may leave resources behind — the caller is responsible
    /// for handling the returned error.
    fn is_mandatory(&self) -> bool {
        false
    }
}

// ─── AuditContext ──────────────────────────────────────────────────

/// Internal helper that centralizes timestamp computation and
/// panic-safe event emission.
#[allow(dead_code)]
pub(crate) struct AuditContext {
    sink: Arc<dyn AuditSink>,
    epoch: Instant,
    wall_clock_epoch_ns: u64,
    verbosity: AuditVerbosity,
}

#[allow(dead_code)]
impl AuditContext {
    pub fn new(sink: Arc<dyn AuditSink>, verbosity: AuditVerbosity) -> Self {
        let epoch = Instant::now();
        let wall_clock_epoch_ns = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        Self {
            sink,
            epoch,
            wall_clock_epoch_ns,
            verbosity,
        }
    }

    pub fn timestamp(&self) -> AuditTimestamp {
        AuditTimestamp(self.epoch.elapsed().as_nanos() as u64)
    }

    pub fn wall_clock_epoch_ns(&self) -> u64 {
        self.wall_clock_epoch_ns
    }

    pub fn verbosity(&self) -> &AuditVerbosity {
        &self.verbosity
    }

    /// Emit an event, catching sink panics.
    ///
    /// Returns `Err` only when the sink panics AND `is_mandatory()`.
    // AssertUnwindSafe is safe here: `sink` is an Arc clone (separate
    // strong ref — the original is untouched on panic) and `event` is
    // moved into the closure (consumed, not shared).
    pub fn emit(&self, event: AuditEvent) -> crate::Result<()> {
        let sink = Arc::clone(&self.sink);
        let mandatory = self.sink.is_mandatory();
        let result =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || sink.emit(event)));
        if result.is_err() {
            log::warn!("audit sink panicked, event lost");
            if mandatory {
                return Err(crate::Error::Process(
                    "mandatory audit sink panicked".into(),
                ));
            }
        }
        Ok(())
    }
}

impl std::fmt::Debug for AuditContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditContext")
            .field("epoch", &self.epoch)
            .field("wall_clock_epoch_ns", &self.wall_clock_epoch_ns)
            .field("verbosity", &self.verbosity)
            .field("sink", &"<AuditSink>")
            .finish()
    }
}

// ─── Helpers ───────────────────────────────────────────────────────

/// Strip control characters and bidi overrides from a string before
/// it enters an audit event, preventing log injection attacks on
/// downstream consumers.
#[allow(dead_code)]
pub(crate) fn sanitize_audit_string(s: &str) -> String {
    s.chars()
        .filter(|c| {
            if c.is_control() && *c != '\n' {
                return false;
            }
            !matches!(
                *c,
                '\u{202A}'..='\u{202E}'
                    | '\u{2066}'..='\u{2069}'
                    | '\u{200E}'
                    | '\u{200F}'
            )
        })
        .collect()
}

// ─── Tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct VecSink(Mutex<Vec<AuditEvent>>);

    impl AuditSink for VecSink {
        fn emit(&self, event: AuditEvent) {
            self.0.lock().unwrap_or_else(|e| e.into_inner()).push(event);
        }
    }

    struct PanickingSink {
        mandatory: bool,
    }

    impl AuditSink for PanickingSink {
        fn emit(&self, _event: AuditEvent) {
            panic!("deliberate test panic");
        }

        fn is_mandatory(&self) -> bool {
            self.mandatory
        }
    }

    #[test]
    fn timestamp_ordering() {
        let a = AuditTimestamp(100);
        let b = AuditTimestamp(200);
        assert!(a < b);
        assert_eq!(a, AuditTimestamp(100));
    }

    #[test]
    fn context_timestamps_increase() {
        let sink = Arc::new(VecSink(Mutex::new(Vec::new())));
        let ctx = AuditContext::new(sink, AuditVerbosity::Standard);
        let t1 = ctx.timestamp();
        std::thread::sleep(std::time::Duration::from_millis(1));
        let t2 = ctx.timestamp();
        assert!(t2 > t1);
    }

    #[test]
    fn context_wall_clock_is_reasonable() {
        let sink = Arc::new(VecSink(Mutex::new(Vec::new())));
        let ctx = AuditContext::new(sink, AuditVerbosity::Standard);
        assert!(ctx.wall_clock_epoch_ns() > 1_700_000_000_000_000_000);
    }

    #[test]
    fn context_emit_delivers_event() {
        let vec_sink = Arc::new(VecSink(Mutex::new(Vec::new())));
        let sink: Arc<dyn AuditSink> = Arc::clone(&vec_sink) as Arc<dyn AuditSink>;
        let ctx = AuditContext::new(sink, AuditVerbosity::Standard);
        let event = AuditEvent::ProcessStarted {
            timestamp: ctx.timestamp(),
            pid: 42,
        };
        ctx.emit(event).unwrap();
        let events = vec_sink.0.lock().unwrap();
        assert_eq!(events.len(), 1);
    }

    #[test]
    fn context_catches_sink_panic() {
        let sink = Arc::new(PanickingSink { mandatory: false });
        let ctx = AuditContext::new(sink, AuditVerbosity::Standard);
        let event = AuditEvent::ProcessStarted {
            timestamp: ctx.timestamp(),
            pid: 1,
        };
        let result = ctx.emit(event);
        assert!(result.is_ok());
    }

    #[test]
    fn context_mandatory_sink_panic_returns_err() {
        let sink = Arc::new(PanickingSink { mandatory: true });
        let ctx = AuditContext::new(sink, AuditVerbosity::Standard);
        let event = AuditEvent::ProcessStarted {
            timestamp: ctx.timestamp(),
            pid: 1,
        };
        let result = ctx.emit(event);
        assert!(result.is_err());
    }

    #[test]
    fn sanitize_strips_control_chars() {
        assert_eq!(sanitize_audit_string("hello\x00world"), "helloworld");
        assert_eq!(sanitize_audit_string("tab\there"), "tabhere");
        assert_eq!(sanitize_audit_string("\x1b[31mred\x1b[0m"), "[31mred[0m");
    }

    #[test]
    fn sanitize_preserves_newlines() {
        assert_eq!(sanitize_audit_string("line1\nline2"), "line1\nline2");
    }

    #[test]
    fn sanitize_strips_bidi_overrides() {
        assert_eq!(sanitize_audit_string("a\u{202E}b\u{202C}c"), "abc");
        assert_eq!(sanitize_audit_string("x\u{2066}y\u{2069}z"), "xyz");
    }

    #[test]
    fn sanitize_preserves_normal_unicode() {
        assert_eq!(sanitize_audit_string("café ñ 日本語"), "café ñ 日本語");
    }

    #[test]
    fn verbosity_default_is_standard() {
        assert!(matches!(
            AuditVerbosity::default(),
            AuditVerbosity::Standard
        ));
    }

    #[test]
    fn drop_reason_variants_exist() {
        let reasons = [
            DropReason::ArapucaPrefix,
            DropReason::LauncherReserved,
            DropReason::LdPrefix,
            DropReason::DyldPrefix,
            DropReason::DotnetPrefix,
            DropReason::InterpreterInjection,
            DropReason::ShellInjection,
            DropReason::WindowsShimInjection,
        ];
        assert_eq!(reasons.len(), 8);
    }

    #[test]
    fn schema_version_is_one() {
        assert_eq!(SCHEMA_VERSION, 1);
    }
}
