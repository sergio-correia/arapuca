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
    let (read_paths, write_paths) = arapuca::env::default_sandbox_paths();
    Config {
        profile: Profile {
            read_paths,
            write_paths,
            ..Default::default()
        },
        socket_dir: std::path::PathBuf::new(),
        task_id: "audit-test".into(),
        phase: "test".into(),
        work_dir: None,
        stdin: None,
        stdout: None,
        stderr: None,
        extra_fds: Vec::new(),
        tty: false,
        network_proxy_socket: None,
        #[cfg(target_os = "linux")]
        allowed_hosts: Vec::new(),
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
        AuditEvent::SandboxReady { applied_layers, .. } => {
            // EnvFilter and pre_exec layers are always applied.
            assert!(applied_layers.contains(&SandboxLayer::EnvFilter));
            assert!(applied_layers.contains(&SandboxLayer::Setsid));
            assert!(applied_layers.contains(&SandboxLayer::Pdeathsig));
            assert!(applied_layers.contains(&SandboxLayer::FdSanitization));
            // With default paths configured, wrapper layers are applied.
            assert!(applied_layers.contains(&SandboxLayer::Landlock));
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
        tty: false,
        network_proxy_socket: None,
        #[cfg(target_os = "linux")]
        allowed_hosts: Vec::new(),
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

#[test]
fn signal_killed_process() {
    use std::os::unix::process::ExitStatusExt;

    let vec_sink = Arc::new(VecSink(Mutex::new(Vec::new())));
    let sink: Arc<dyn AuditSink> = Arc::clone(&vec_sink) as Arc<dyn AuditSink>;
    let cfg = basic_config(sink);

    let sb = new().unwrap();
    let mut proc = sb.launch(&cfg, "/bin/sleep", &["60"]).unwrap();

    let pid = proc.pid();
    // SAFETY: pid is a valid child PID.
    unsafe { libc::kill(pid as i32, libc::SIGKILL) };

    let status = proc.wait().unwrap();
    assert_eq!(status.signal(), Some(9));
    proc.cleanup();

    let events = vec_sink.0.lock().unwrap();
    let exited = events
        .iter()
        .find(|e| matches!(e, AuditEvent::ProcessExited { .. }));
    match exited.unwrap() {
        AuditEvent::ProcessExited {
            exit_code, signal, ..
        } => {
            assert_eq!(*exit_code, None);
            assert_eq!(*signal, Some(9));
        }
        _ => unreachable!(),
    }
}

#[test]
fn spawn_failure_for_nonexistent_binary() {
    let vec_sink = Arc::new(VecSink(Mutex::new(Vec::new())));
    let sink: Arc<dyn AuditSink> = Arc::clone(&vec_sink) as Arc<dyn AuditSink>;
    let cfg = basic_config(sink);

    let sb = new().unwrap();
    let result = sb.launch(&cfg, "/nonexistent-binary-xyz-12345", &[]);
    assert!(result.is_err());
}

#[test]
fn sandbox_ready_present_before_spawn_failure() {
    let vec_sink = Arc::new(VecSink(Mutex::new(Vec::new())));
    let sink: Arc<dyn AuditSink> = Arc::clone(&vec_sink) as Arc<dyn AuditSink>;
    let cfg = basic_config(sink);

    let sb = new().unwrap();
    let result = sb.launch(&cfg, "/nonexistent-binary-xyz-12345", &[]);
    assert!(result.is_err());

    let events = vec_sink.0.lock().unwrap();
    let names = event_names(&events);
    assert!(names.contains(&"SandboxReady"));
    assert!(!names.contains(&"ProcessStarted"));
}

#[test]
fn mandatory_sink_abort() {
    struct PanickingSink;
    impl AuditSink for PanickingSink {
        fn emit(&self, _event: AuditEvent) {
            panic!("mandatory sink panics");
        }
        fn is_mandatory(&self) -> bool {
            true
        }
    }

    let sink: Arc<dyn AuditSink> = Arc::new(PanickingSink);
    let cfg = Config {
        profile: Profile::default(),
        socket_dir: std::path::PathBuf::new(),
        task_id: "mandatory-test".into(),
        phase: "test".into(),
        work_dir: None,
        stdin: None,
        stdout: None,
        stderr: None,
        extra_fds: Vec::new(),
        tty: false,
        network_proxy_socket: None,
        #[cfg(target_os = "linux")]
        allowed_hosts: Vec::new(),
        env: Vec::new(),
        audit_sink: Some(sink),
        audit_verbosity: AuditVerbosity::Standard,
        audit_principal: None,
        audit_correlation_id: None,
    };

    let sb = new().unwrap();
    let result = sb.launch(&cfg, "/bin/true", &[]);
    assert!(
        result.is_err(),
        "mandatory panicking sink should cause launch failure"
    );
}

#[test]
fn env_enforcement_end_to_end() {
    let vec_sink = Arc::new(VecSink(Mutex::new(Vec::new())));
    let sink: Arc<dyn AuditSink> = Arc::clone(&vec_sink) as Arc<dyn AuditSink>;
    let mut cfg = basic_config(sink);

    let env_file = std::env::temp_dir().join(format!("arapuca-env-test-{}", std::process::id()));

    // Drop guard ensures cleanup even if assertions panic.
    struct FileGuard<'a>(&'a std::path::Path);
    impl Drop for FileGuard<'_> {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(self.0);
        }
    }
    let _guard = FileGuard(&env_file);

    let env_path = env_file.to_string_lossy().to_string();

    cfg.profile
        .write_paths
        .push(std::path::PathBuf::from("/tmp"));
    cfg.env = vec![
        ("SAFE_VAR".into(), "hello".into()),
        ("LD_PRELOAD".into(), "/evil.so".into()),
        ("PYTHONPATH".into(), "/inject".into()),
    ];

    let sb = new().unwrap();
    let mut proc = sb
        .launch(
            &cfg,
            "/bin/sh",
            &["-c", &format!("/usr/bin/env > '{env_path}'")],
        )
        .unwrap();
    let status = proc.wait().unwrap();
    assert!(status.success());
    proc.cleanup();

    let env_output = std::fs::read_to_string(&env_file).unwrap();

    assert!(
        env_output.lines().any(|l| l.starts_with("SAFE_VAR=")),
        "SAFE_VAR should be in child environment"
    );
    assert!(
        !env_output.lines().any(|l| l.starts_with("LD_PRELOAD=")),
        "LD_PRELOAD should be filtered from child environment"
    );
    assert!(
        !env_output.lines().any(|l| l.starts_with("PYTHONPATH=")),
        "PYTHONPATH should be filtered from child environment"
    );
}

#[test]
fn audit_sanitization_end_to_end() {
    let vec_sink = Arc::new(VecSink(Mutex::new(Vec::new())));
    let sink: Arc<dyn AuditSink> = Arc::clone(&vec_sink) as Arc<dyn AuditSink>;
    let mut cfg = basic_config(sink);
    cfg.audit_verbosity = AuditVerbosity::Verbose;

    // Pass args with bidi override and zero-width characters.
    let bidi_arg = "normal\u{202E}evil\u{202C}text";
    let zwsp_arg = "clean\u{200B}data";

    let sb = new().unwrap();
    let mut proc = sb.launch(&cfg, "/bin/true", &[bidi_arg, zwsp_arg]).unwrap();
    proc.wait().unwrap();
    proc.cleanup();

    let events = vec_sink.0.lock().unwrap();
    match &events[0] {
        AuditEvent::SandboxInit { args, .. } => {
            let args = args.as_ref().expect("Verbose mode should include args");
            // Bidi overrides and zero-width chars should be stripped.
            assert_ne!(
                args[0], bidi_arg,
                "unsanitized bidi string must not appear in audit"
            );
            assert_ne!(
                args[1], zwsp_arg,
                "unsanitized zero-width string must not appear in audit"
            );
            assert_eq!(args[0], "normaleviltext");
            assert_eq!(args[1], "cleandata");
        }
        _ => panic!("first event should be SandboxInit"),
    }
}
