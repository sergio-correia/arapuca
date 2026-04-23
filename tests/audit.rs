//! Audit event lifecycle integration tests.
//!
//! Launches a sandboxed subprocess with an audit sink and verifies
//! the complete event sequence from SandboxInit through SandboxCleanup.
#![cfg(target_os = "linux")]

use std::sync::{Arc, Mutex};

use arapuca::audit::{AuditEvent, AuditSink, AuditVerbosity, SandboxLayer};
use arapuca::platform::{Sandbox, new};
use arapuca::{Config, Profile};

struct VecSink(Mutex<Vec<AuditEvent>>);

impl AuditSink for VecSink {
    fn emit(&self, event: AuditEvent) {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).push(event);
    }
}

fn event_names(events: &[AuditEvent]) -> Vec<&'static str> {
    events
        .iter()
        .map(|e| match e {
            AuditEvent::SandboxInit { .. } => "SandboxInit",
            AuditEvent::LayerApplied { .. } => "LayerApplied",
            AuditEvent::LayerSkipped { .. } => "LayerSkipped",
            AuditEvent::LayerFailed { .. } => "LayerFailed",
            AuditEvent::EnvPolicy { .. } => "EnvPolicy",
            AuditEvent::FilesystemPolicy { .. } => "FilesystemPolicy",
            AuditEvent::ResourceLimits { .. } => "ResourceLimits",
            AuditEvent::NetworkPolicy { .. } => "NetworkPolicy",
            AuditEvent::SeccompPolicy { .. } => "SeccompPolicy",
            AuditEvent::FdInheritance { .. } => "FdInheritance",
            AuditEvent::SandboxReady { .. } => "SandboxReady",
            AuditEvent::ProcessStarted { .. } => "ProcessStarted",
            AuditEvent::ProcessExited { .. } => "ProcessExited",
            AuditEvent::ResourceUsage { .. } => "ResourceUsage",
            AuditEvent::SandboxCleanup { .. } => "SandboxCleanup",
            _ => "Unknown",
        })
        .collect()
}

fn basic_config(sink: Arc<dyn AuditSink>) -> Config {
    Config {
        profile: Profile::default(),
        socket_dir: std::path::PathBuf::new(),
        task_id: "audit-test".into(),
        phase: "test".into(),
        work_dir: None,
        stdin: None,
        stdout: None,
        stderr: None,
        extra_fds: Vec::new(),
        network_proxy_socket: None,
        env: Vec::new(),
        audit_sink: Some(sink),
        audit_verbosity: AuditVerbosity::Standard,
        audit_principal: Some("test-user".into()),
        audit_correlation_id: Some("corr-123".into()),
    }
}

#[test]
fn full_lifecycle_event_sequence() {
    let vec_sink = Arc::new(VecSink(Mutex::new(Vec::new())));
    let sink: Arc<dyn AuditSink> = Arc::clone(&vec_sink) as Arc<dyn AuditSink>;
    let cfg = basic_config(sink);

    let sb = new().unwrap();
    let mut proc = sb.launch(&cfg, "/bin/true", &[]).unwrap();
    let status = proc.wait().unwrap();
    assert!(status.success());
    proc.cleanup();

    let events = vec_sink.0.lock().unwrap();
    let names = event_names(&events);

    // First event must be SandboxInit.
    assert_eq!(names[0], "SandboxInit");

    // SandboxReady must appear before ProcessStarted.
    let ready_pos = names.iter().position(|n| *n == "SandboxReady").unwrap();
    let started_pos = names.iter().position(|n| *n == "ProcessStarted").unwrap();
    assert!(ready_pos < started_pos);

    // ProcessExited must appear after ProcessStarted.
    let exited_pos = names.iter().position(|n| *n == "ProcessExited").unwrap();
    assert!(exited_pos > started_pos);

    // ResourceUsage must appear after ProcessExited.
    let usage_pos = names.iter().position(|n| *n == "ResourceUsage").unwrap();
    assert!(usage_pos > exited_pos);

    // SandboxCleanup must be the last event.
    assert_eq!(*names.last().unwrap(), "SandboxCleanup");

    // No unknown event types (catches new variants silently absorbed by wildcard).
    assert!(
        !names.iter().any(|n| *n == "Unknown"),
        "unknown event type in sequence: {names:?}"
    );

    // Policy events must appear between SandboxInit and SandboxReady.
    for policy in [
        "EnvPolicy",
        "FilesystemPolicy",
        "ResourceLimits",
        "NetworkPolicy",
    ] {
        let pos = names.iter().position(|n| *n == policy).unwrap();
        assert!(
            pos > 0 && pos < ready_pos,
            "{policy} not between init and ready"
        );
    }
}

#[test]
fn sandbox_init_fields() {
    let vec_sink = Arc::new(VecSink(Mutex::new(Vec::new())));
    let sink: Arc<dyn AuditSink> = Arc::clone(&vec_sink) as Arc<dyn AuditSink>;
    let cfg = basic_config(sink);

    let sb = new().unwrap();
    let mut proc = sb.launch(&cfg, "/bin/true", &[]).unwrap();
    proc.wait().unwrap();
    proc.cleanup();

    let events = vec_sink.0.lock().unwrap();
    match &events[0] {
        AuditEvent::SandboxInit {
            wall_clock_epoch_ns,
            schema_version,
            task_id,
            phase,
            command,
            arg_count,
            args,
            principal,
            correlation_id,
            ..
        } => {
            assert!(*wall_clock_epoch_ns > 1_700_000_000_000_000_000);
            assert_eq!(*schema_version, 1);
            assert_eq!(task_id, "audit-test");
            assert_eq!(phase, "test");
            assert_eq!(command, "/bin/true");
            assert_eq!(*arg_count, 0);
            assert!(args.is_none());
            assert_eq!(principal.as_deref(), Some("test-user"));
            assert_eq!(correlation_id.as_deref(), Some("corr-123"));
        }
        _ => panic!("first event should be SandboxInit"),
    }
}

#[test]
fn verbose_mode_includes_args() {
    let vec_sink = Arc::new(VecSink(Mutex::new(Vec::new())));
    let sink: Arc<dyn AuditSink> = Arc::clone(&vec_sink) as Arc<dyn AuditSink>;
    let mut cfg = basic_config(sink);
    cfg.audit_verbosity = AuditVerbosity::Verbose;

    let sb = new().unwrap();
    let mut proc = sb.launch(&cfg, "/bin/true", &["arg1", "arg2"]).unwrap();
    proc.wait().unwrap();
    proc.cleanup();

    let events = vec_sink.0.lock().unwrap();
    match &events[0] {
        AuditEvent::SandboxInit {
            arg_count, args, ..
        } => {
            assert_eq!(*arg_count, 2);
            let args = args.as_ref().unwrap();
            assert_eq!(args, &["arg1", "arg2"]);
        }
        _ => panic!("first event should be SandboxInit"),
    }
}

#[test]
fn standard_mode_omits_args() {
    let vec_sink = Arc::new(VecSink(Mutex::new(Vec::new())));
    let sink: Arc<dyn AuditSink> = Arc::clone(&vec_sink) as Arc<dyn AuditSink>;
    let cfg = basic_config(sink);

    let sb = new().unwrap();
    let mut proc = sb.launch(&cfg, "/bin/true", &["redacted"]).unwrap();
    proc.wait().unwrap();
    proc.cleanup();

    let events = vec_sink.0.lock().unwrap();
    match &events[0] {
        AuditEvent::SandboxInit {
            arg_count, args, ..
        } => {
            assert_eq!(*arg_count, 1);
            assert!(args.is_none());
        }
        _ => panic!("first event should be SandboxInit"),
    }
}

#[test]
fn process_exited_captures_exit_code() {
    let vec_sink = Arc::new(VecSink(Mutex::new(Vec::new())));
    let sink: Arc<dyn AuditSink> = Arc::clone(&vec_sink) as Arc<dyn AuditSink>;
    let cfg = basic_config(sink);

    let sb = new().unwrap();
    let mut proc = sb.launch(&cfg, "/bin/false", &[]).unwrap();
    let status = proc.wait().unwrap();
    assert!(!status.success());
    proc.cleanup();

    let events = vec_sink.0.lock().unwrap();
    let exited = events
        .iter()
        .find(|e| matches!(e, AuditEvent::ProcessExited { .. }));
    match exited.unwrap() {
        AuditEvent::ProcessExited {
            exit_code, signal, ..
        } => {
            assert_eq!(*exit_code, Some(1));
            assert_eq!(*signal, None);
        }
        _ => unreachable!(),
    }
}

#[test]
fn sandbox_ready_lists_layers() {
    let vec_sink = Arc::new(VecSink(Mutex::new(Vec::new())));
    let sink: Arc<dyn AuditSink> = Arc::clone(&vec_sink) as Arc<dyn AuditSink>;
    let cfg = basic_config(sink);

    let sb = new().unwrap();
    let mut proc = sb.launch(&cfg, "/bin/true", &[]).unwrap();
    proc.wait().unwrap();
    proc.cleanup();

    let events = vec_sink.0.lock().unwrap();
    let ready = events
        .iter()
        .find(|e| matches!(e, AuditEvent::SandboxReady { .. }));
    match ready.unwrap() {
        AuditEvent::SandboxReady {
            applied_layers,
            skipped_layers,
            ..
        } => {
            // EnvFilter and pre_exec layers are always applied.
            assert!(applied_layers.contains(&SandboxLayer::EnvFilter));
            assert!(applied_layers.contains(&SandboxLayer::Setsid));
            assert!(applied_layers.contains(&SandboxLayer::Pdeathsig));
            assert!(applied_layers.contains(&SandboxLayer::FdSanitization));
            // Without paths configured, wrapper layers are skipped.
            assert!(skipped_layers.contains(&SandboxLayer::Landlock));
            assert!(skipped_layers.contains(&SandboxLayer::Seccomp));
        }
        _ => unreachable!(),
    }
}

#[test]
fn no_events_without_sink() {
    let cfg = Config {
        profile: Profile::default(),
        socket_dir: std::path::PathBuf::new(),
        task_id: "no-audit".into(),
        phase: "test".into(),
        work_dir: None,
        stdin: None,
        stdout: None,
        stderr: None,
        extra_fds: Vec::new(),
        network_proxy_socket: None,
        env: Vec::new(),
        audit_sink: None,
        audit_verbosity: AuditVerbosity::Standard,
        audit_principal: None,
        audit_correlation_id: None,
    };

    let sb = new().unwrap();
    let mut proc = sb.launch(&cfg, "/bin/true", &[]).unwrap();
    proc.wait().unwrap();
    proc.cleanup();
    // No panic, no events — zero overhead path works.
}

#[test]
fn env_filtering_audited() {
    let vec_sink = Arc::new(VecSink(Mutex::new(Vec::new())));
    let sink: Arc<dyn AuditSink> = Arc::clone(&vec_sink) as Arc<dyn AuditSink>;
    let mut cfg = basic_config(sink);
    cfg.env = vec![
        ("SAFE_VAR".into(), "ok".into()),
        ("LD_PRELOAD".into(), "/evil.so".into()),
    ];

    let sb = new().unwrap();
    let mut proc = sb.launch(&cfg, "/bin/true", &[]).unwrap();
    proc.wait().unwrap();
    proc.cleanup();

    let events = vec_sink.0.lock().unwrap();
    let env_event = events
        .iter()
        .find(|e| matches!(e, AuditEvent::EnvPolicy { .. }));
    match env_event.unwrap() {
        AuditEvent::EnvPolicy {
            passed_keys,
            dropped,
            ..
        } => {
            assert!(passed_keys.contains(&"SAFE_VAR".to_string()));
            assert!(!passed_keys.iter().any(|k| k == "LD_PRELOAD"));
            assert_eq!(dropped.len(), 1);
            assert_eq!(dropped[0].key, "LD_PRELOAD");
        }
        _ => unreachable!(),
    }
}
