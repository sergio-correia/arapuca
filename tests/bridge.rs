//! Integration tests for the network namespace proxy bridge.
//!
//! These tests require `unshare --user --net` to work, which needs
//! unprivileged user namespace support. Skipped if unavailable.

#[cfg(target_os = "linux")]
mod linux {
    use std::io::{self, Read as _, Write as _};
    use std::net::{Shutdown, TcpStream};
    use std::process::Command;
    use std::time::Duration;

    fn netns_available() -> bool {
        Command::new("unshare")
            .args(["--user", "--net", "--map-current-user", "--", "/bin/true"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    }

    fn netns_root_available() -> bool {
        Command::new("unshare")
            .args(["--user", "--net", "--map-root-user", "--", "/bin/true"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    }

    /// Re-exec the current test binary inside a fresh user+network
    /// namespace with full capabilities (CAP_NET_ADMIN for loopback).
    /// The inner invocation sees `ARAPUCA_TEST_IN_NETNS=1` and runs
    /// the test body directly.
    fn reexec_in_netns(test_name: &str) {
        let exe = std::env::current_exe().expect("current_exe");
        let output = Command::new("unshare")
            .args(["--user", "--net", "--map-root-user", "--"])
            .arg(&exe)
            .args([test_name, "--exact", "--nocapture", "--test-threads=1"])
            .env("ARAPUCA_TEST_IN_NETNS", "1")
            .output()
            .expect("unshare failed to launch");

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success(),
            "inner test failed (exit {:?}):\nstdout: {stdout}\nstderr: {stderr}",
            output.status.code(),
        );
    }

    fn in_netns() -> bool {
        std::env::var("ARAPUCA_TEST_IN_NETNS").is_ok()
    }

    /// Start a UDS echo server that copies input back to the client.
    /// Returns the join handle (runs until the client disconnects).
    fn spawn_uds_echo(path: &std::path::Path) -> std::thread::JoinHandle<()> {
        let listener = std::os::unix::net::UnixListener::bind(path).unwrap();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let mut conn = match stream {
                    Ok(c) => c,
                    Err(_) => break,
                };
                let mut buf = [0u8; 1024];
                loop {
                    let n = match io::Read::read(&mut conn, &mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => n,
                    };
                    if conn.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
            }
        })
    }

    #[test]
    fn loopback_up_in_namespace() {
        if !netns_available() {
            eprintln!("skipping: unshare --user --net not available");
            return;
        }

        let output = Command::new("unshare")
            .args([
                "--user",
                "--net",
                "--map-current-user",
                "--",
                "cat",
                "/sys/class/net/lo/operstate",
            ])
            .output()
            .expect("unshare failed");

        let state = String::from_utf8_lossy(&output.stdout);
        let state = state.trim();
        assert!(
            state == "down" || state == "unknown",
            "lo should be down/unknown in a fresh netns, got: {state}"
        );
    }

    #[test]
    fn fork_bridge_starts_and_relays() {
        if in_netns() {
            fork_bridge_starts_and_relays_inner();
            return;
        }
        if !netns_root_available() {
            eprintln!("skipping: unshare --user --net --map-root-user not available");
            return;
        }
        reexec_in_netns("linux::fork_bridge_starts_and_relays");
    }

    fn fork_bridge_starts_and_relays_inner() {
        let dir = tempfile::tempdir().unwrap();
        let uds_path = dir.path().join("echo.sock");

        let _echo = spawn_uds_echo(&uds_path);

        let port = arapuca::bridge::fork_bridge(0, Some(&uds_path), None).unwrap();
        assert!(port > 0, "fork_bridge should return a valid port");

        let mut client = TcpStream::connect(("127.0.0.1", port)).unwrap();
        client.write_all(b"hello through bridge").unwrap();
        client.shutdown(Shutdown::Write).unwrap();

        let mut response = Vec::new();
        client.read_to_end(&mut response).unwrap();
        assert_eq!(response, b"hello through bridge");
    }

    #[test]
    fn fork_bridge_pdeathsig() {
        if in_netns() {
            fork_bridge_pdeathsig_inner();
            return;
        }
        if !netns_root_available() {
            eprintln!("skipping: unshare --user --net --map-root-user not available");
            return;
        }
        reexec_in_netns("linux::fork_bridge_pdeathsig");
    }

    fn fork_bridge_pdeathsig_inner() {
        let dir = tempfile::tempdir().unwrap();
        let uds_path = dir.path().join("echo.sock");

        let _echo = spawn_uds_echo(&uds_path);

        // Pipe for the child to report the bridge port.
        let mut pipe_fds = [0i32; 2];
        assert_eq!(
            unsafe { libc::pipe2(pipe_fds.as_mut_ptr(), libc::O_CLOEXEC) },
            0
        );
        let pipe_read = pipe_fds[0];
        let pipe_write = pipe_fds[1];

        let uds_for_child = uds_path.clone();
        let child_pid = unsafe { libc::fork() };
        assert!(child_pid >= 0, "fork failed");

        if child_pid == 0 {
            // Child: call fork_bridge, report port, then sleep.
            unsafe { libc::close(pipe_read) };
            let port = match arapuca::bridge::fork_bridge(0, Some(&uds_for_child), None) {
                Ok(p) => p,
                Err(_) => unsafe { libc::_exit(2) },
            };
            let port_bytes = port.to_ne_bytes();
            let _ = unsafe {
                libc::write(
                    pipe_write,
                    port_bytes.as_ptr() as *const libc::c_void,
                    port_bytes.len(),
                )
            };
            unsafe { libc::close(pipe_write) };
            loop {
                unsafe { libc::pause() };
            }
        }

        // Parent
        unsafe { libc::close(pipe_write) };

        let mut port_buf = [0u8; 2];
        let n = unsafe {
            libc::read(
                pipe_read,
                port_buf.as_mut_ptr() as *mut libc::c_void,
                port_buf.len(),
            )
        };
        unsafe { libc::close(pipe_read) };
        assert_eq!(n, 2, "child should report bridge port");
        let port = u16::from_ne_bytes(port_buf);

        // Verify relay works while child is alive.
        {
            let mut client = TcpStream::connect(("127.0.0.1", port)).unwrap();
            client.write_all(b"before kill").unwrap();
            client.shutdown(Shutdown::Write).unwrap();
            let mut resp = Vec::new();
            client.read_to_end(&mut resp).unwrap();
            assert_eq!(resp, b"before kill");
        }

        // Kill the child (parent of bridge). pdeathsig should
        // deliver SIGKILL to the bridge grandchild.
        unsafe { libc::kill(child_pid, libc::SIGKILL) };
        unsafe { libc::waitpid(child_pid, std::ptr::null_mut(), 0) };

        std::thread::sleep(Duration::from_millis(200));

        // Bridge grandchild should be dead — connection refused.
        let result = TcpStream::connect(("127.0.0.1", port));
        assert!(result.is_err(), "bridge should be dead after parent killed");
    }
}
