//! Stdio pipe redirection tests.
//!
//! Exercises the same code path go-arapuca uses: create pipes, pass
//! FDs via Config.stdin/stdout/stderr, launch through the library API,
//! and verify data flows correctly through the pipes.
//!
//! These tests diagnose whether the library's FD wiring works for
//! callers that supply their own pipe FDs (as opposed to inheriting
//! the parent's stdio).
#![cfg(target_os = "linux")]

use std::io::{Read, Write};
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::path::PathBuf;

use arapuca::platform::{Sandbox, new};
use arapuca::{Config, Profile};

fn pipe_pair() -> (std::fs::File, std::fs::File) {
    let mut fds = [0i32; 2];
    let ret = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
    assert_eq!(ret, 0, "pipe2 failed");
    unsafe {
        (
            std::fs::File::from_raw_fd(fds[0]),
            std::fs::File::from_raw_fd(fds[1]),
        )
    }
}

fn base_config() -> Config {
    let (read_paths, write_paths) = arapuca::env::default_sandbox_paths();
    Config {
        profile: Profile {
            read_paths,
            write_paths,
            ..Default::default()
        },
        socket_dir: PathBuf::new(),
        task_id: "stdio-test".into(),
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
        audit_verbosity: arapuca::audit::AuditVerbosity::Standard,
        audit_principal: None,
        audit_correlation_id: None,
    }
}

/// Test 1: stdout capture from /bin/echo (no stdin needed).
/// If this fails, the basic stdout pipe wiring is broken.
#[test]
fn stdout_pipe_echo() {
    let (stdout_r, stdout_w) = pipe_pair();
    let (_stderr_r, stderr_w) = pipe_pair();

    let mut cfg = base_config();
    cfg.stdout = Some(stdout_w.as_raw_fd());
    cfg.stderr = Some(stderr_w.as_raw_fd());

    let sb = new().unwrap();
    let mut proc = sb.launch(&cfg, "/bin/echo", &["hello"]).unwrap();

    drop(stdout_w);
    drop(stderr_w);

    let mut stdout = String::new();
    stdout_r.take(4096).read_to_string(&mut stdout).unwrap();

    let status = proc.wait().unwrap();
    proc.cleanup();

    assert!(status.success(), "echo should exit 0");
    assert_eq!(stdout.trim(), "hello", "stdout should contain 'hello'");
}

/// Test 2: stdout capture WITH Landlock wrapper.
/// Same as test 1 but with ReadPaths set, forcing the wrapper binary.
#[test]
fn stdout_pipe_echo_with_wrapper() {
    let (stdout_r, stdout_w) = pipe_pair();
    let (_stderr_r, stderr_w) = pipe_pair();

    let mut cfg = base_config();
    cfg.stdout = Some(stdout_w.as_raw_fd());
    cfg.stderr = Some(stderr_w.as_raw_fd());
    cfg.profile.read_paths = vec![
        PathBuf::from("/usr"),
        PathBuf::from("/lib"),
        PathBuf::from("/lib64"),
        PathBuf::from("/bin"),
    ];

    let sb = new().unwrap();
    let mut proc = sb.launch(&cfg, "/bin/echo", &["hello"]).unwrap();

    drop(stdout_w);
    drop(stderr_w);

    let mut stdout = String::new();
    stdout_r.take(4096).read_to_string(&mut stdout).unwrap();

    let status = proc.wait().unwrap();
    proc.cleanup();

    assert!(
        status.success(),
        "echo should exit 0 (exit code {:?})",
        status.code()
    );
    assert_eq!(stdout.trim(), "hello", "stdout should contain 'hello'");
}

/// Test 3: stdin→stdout relay via /bin/cat.
/// Parent writes to stdin pipe, child relays to stdout pipe.
#[test]
fn stdin_stdout_relay_cat() {
    let (stdin_r, mut stdin_w) = pipe_pair();
    let (stdout_r, stdout_w) = pipe_pair();
    let (_stderr_r, stderr_w) = pipe_pair();

    let mut cfg = base_config();
    cfg.stdin = Some(stdin_r.as_raw_fd());
    cfg.stdout = Some(stdout_w.as_raw_fd());
    cfg.stderr = Some(stderr_w.as_raw_fd());

    let sb = new().unwrap();
    let mut proc = sb.launch(&cfg, "/bin/cat", &[]).unwrap();

    drop(stdin_r);
    drop(stdout_w);
    drop(stderr_w);

    stdin_w.write_all(b"relay-test\n").unwrap();
    drop(stdin_w);

    let mut stdout = String::new();
    stdout_r.take(4096).read_to_string(&mut stdout).unwrap();

    let status = proc.wait().unwrap();
    proc.cleanup();

    assert!(status.success(), "cat should exit 0");
    assert_eq!(stdout.trim(), "relay-test");
}

/// Test 4: stdin→stdout relay WITH Landlock wrapper.
/// Same as test 3 but through the wrapper binary.
#[test]
fn stdin_stdout_relay_cat_with_wrapper() {
    let (stdin_r, mut stdin_w) = pipe_pair();
    let (stdout_r, stdout_w) = pipe_pair();
    let (stderr_r, stderr_w) = pipe_pair();

    let mut cfg = base_config();
    cfg.stdin = Some(stdin_r.as_raw_fd());
    cfg.stdout = Some(stdout_w.as_raw_fd());
    cfg.stderr = Some(stderr_w.as_raw_fd());
    cfg.profile.read_paths = vec![
        PathBuf::from("/usr"),
        PathBuf::from("/lib"),
        PathBuf::from("/lib64"),
        PathBuf::from("/bin"),
    ];

    let sb = new().unwrap();
    let mut proc = sb.launch(&cfg, "/bin/cat", &[]).unwrap();

    drop(stdin_r);
    drop(stdout_w);
    drop(stderr_w);

    stdin_w.write_all(b"relay-test\n").unwrap();
    drop(stdin_w);

    let mut stdout = String::new();
    stdout_r.take(4096).read_to_string(&mut stdout).unwrap();

    let mut stderr = String::new();
    stderr_r.take(4096).read_to_string(&mut stderr).unwrap();

    let status = proc.wait().unwrap();
    proc.cleanup();

    assert!(status.success(), "cat should exit 0, stderr: {stderr}");
    assert_eq!(
        stdout.trim(),
        "relay-test",
        "cat should relay stdin→stdout, stderr: {stderr}"
    );
}

/// Test 5: stderr capture.
#[test]
fn stderr_pipe_capture() {
    let (_stdout_r, stdout_w) = pipe_pair();
    let (stderr_r, stderr_w) = pipe_pair();

    let mut cfg = base_config();
    cfg.stdout = Some(stdout_w.as_raw_fd());
    cfg.stderr = Some(stderr_w.as_raw_fd());

    let sb = new().unwrap();
    let mut proc = sb
        .launch(&cfg, "/bin/sh", &["-c", "echo errout >&2"])
        .unwrap();

    drop(stdout_w);
    drop(stderr_w);

    let mut stderr = String::new();
    stderr_r.take(4096).read_to_string(&mut stderr).unwrap();

    let status = proc.wait().unwrap();
    proc.cleanup();

    assert!(status.success());
    assert_eq!(stderr.trim(), "errout");
}

// ─── PTY validation tests ─────────────────────────────────────

#[test]
fn tty_rejects_stdin_redirect() {
    let (r, _w) = pipe_pair();
    let mut cfg = base_config();
    cfg.tty = true;
    cfg.stdin = Some(r.as_raw_fd());
    let sb = new().unwrap();
    let msg = sb
        .launch(&cfg, "/bin/true", &[])
        .err()
        .expect("launch should fail with tty + stdio redirect")
        .to_string();
    assert!(
        msg.contains("tty") && msg.contains("incompatible"),
        "expected tty incompatibility error: {msg}"
    );
}

#[test]
fn tty_rejects_stdout_redirect() {
    let (_r, w) = pipe_pair();
    let mut cfg = base_config();
    cfg.tty = true;
    cfg.stdout = Some(w.as_raw_fd());
    let sb = new().unwrap();
    let msg = sb
        .launch(&cfg, "/bin/true", &[])
        .err()
        .expect("launch should fail with tty + stdio redirect")
        .to_string();
    assert!(
        msg.contains("tty") && msg.contains("incompatible"),
        "expected tty incompatibility error: {msg}"
    );
}

#[test]
fn tty_rejects_stderr_redirect() {
    let (_r, w) = pipe_pair();
    let mut cfg = base_config();
    cfg.tty = true;
    cfg.stderr = Some(w.as_raw_fd());
    let sb = new().unwrap();
    let msg = sb
        .launch(&cfg, "/bin/true", &[])
        .err()
        .expect("launch should fail with tty + stdio redirect")
        .to_string();
    assert!(
        msg.contains("tty") && msg.contains("incompatible"),
        "expected tty incompatibility error: {msg}"
    );
}
