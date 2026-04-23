//! Micro-VM networking via passt.
//!
//! Provides userspace TCP/UDP networking for micro-VMs without
//! root privileges. Disabled by default — only started when
//! `use_netns` is false (meaning: allow network access).

use std::io;
use std::os::unix::io::IntoRawFd;
use std::process::{Child, Command, Stdio};

/// A running passt network proxy.
pub(crate) struct PasstHandle {
    /// The passt child process.
    pub child: Child,
    /// Parent end of the socket pair — passed to libkrun.
    pub parent_fd: i32,
    /// Guest IP address (parsed from passt DHCP output).
    #[allow(dead_code)]
    pub guest_ip: String,
    /// Router/gateway IP address.
    #[allow(dead_code)]
    pub router_ip: String,
}

impl Drop for PasstHandle {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        // SAFETY: parent_fd is a valid FD we own.
        unsafe { libc::close(self.parent_fd) };
    }
}

/// Start passt and return the handle.
///
/// Creates a Unix socket pair: one end goes to passt (via --fd),
/// the other is returned for libkrun via `krun_add_net_unixstream`.
///
/// # Errors
///
/// Returns an error if passt is not installed or fails to start.
pub(crate) fn start_passt() -> io::Result<PasstHandle> {
    let (parent_socket, child_socket) = std::os::unix::net::UnixStream::pair()?;

    // Transfer ownership of the FDs out of UnixStream.
    let child_fd = child_socket.into_raw_fd();

    // Parent FD needs CLOEXEC so it doesn't leak across exec.
    // into_raw_fd() transfers ownership — we must close the
    // original after duping it with CLOEXEC.
    let parent_raw = parent_socket.into_raw_fd();
    // SAFETY: parent_raw is a valid FD from into_raw_fd().
    let parent_fd = unsafe { libc::fcntl(parent_raw, libc::F_DUPFD_CLOEXEC, 0) };
    // SAFETY: close the original — we use the CLOEXEC dup.
    unsafe { libc::close(parent_raw) };
    if parent_fd < 0 {
        // SAFETY: child_fd is valid.
        unsafe { libc::close(child_fd) };
        return Err(io::Error::last_os_error());
    }

    let mut cmd = Command::new("passt");
    cmd.arg("--fd")
        .arg(child_fd.to_string())
        .arg("--foreground")
        .arg("-4")
        .stdout(Stdio::null())
        .stderr(Stdio::piped());

    let mut child = cmd.spawn().map_err(|e| {
        // SAFETY: both FDs are valid.
        unsafe {
            libc::close(parent_fd);
            libc::close(child_fd);
        }
        if e.kind() == io::ErrorKind::NotFound {
            io::Error::new(
                io::ErrorKind::NotFound,
                "passt not found in PATH (install passt for VM networking)",
            )
        } else {
            e
        }
    })?;

    // Close the child end in the parent — passt inherited it.
    // SAFETY: child_fd is valid.
    unsafe { libc::close(child_fd) };

    // Parse DHCP info from passt's stderr with a timeout.
    let (guest_ip, router_ip) = match child.stderr.take() {
        Some(stderr) => parse_dhcp_info(stderr),
        None => ("192.168.127.2".into(), "192.168.127.1".into()),
    };

    Ok(PasstHandle {
        child,
        parent_fd,
        guest_ip,
        router_ip,
    })
}

/// Generate a locally-administered MAC address from random bytes.
pub(crate) fn random_mac() -> [u8; 6] {
    let mut mac = [0u8; 6];
    // SAFETY: getrandom with valid buffer.
    let ret = unsafe { libc::getrandom(mac.as_mut_ptr().cast(), 6, 0) };
    if ret != 6 {
        // Fallback to a fixed MAC if getrandom fails.
        return [0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee];
    }
    // Set locally-administered bit, clear multicast bit.
    mac[0] = (mac[0] & 0xFE) | 0x02;
    mac
}

/// Parse guest and router IPs from passt's DHCP stderr output.
fn parse_dhcp_info(stderr: std::process::ChildStderr) -> (String, String) {
    use std::io::BufRead;

    let reader = std::io::BufReader::new(stderr);
    let mut guest_ip: Option<String> = None;
    let mut router_ip: Option<String> = None;
    let mut in_dhcp = false;

    // Bound by line count — passt's startup output is small.
    // If we don't find both IPs in 50 lines, fall back to defaults.
    for (i, line_result) in reader.lines().enumerate() {
        if i > 50 {
            break;
        }
        let line = match line_result {
            Ok(l) => l,
            Err(_) => break,
        };

        if line.contains("DHCP:") {
            in_dhcp = true;
        } else if in_dhcp {
            let trimmed = line.trim();
            if trimmed.starts_with("assign:") {
                if let Some(ip) = trimmed.split(':').nth(1) {
                    guest_ip = Some(ip.trim().to_string());
                }
            } else if trimmed.starts_with("router:") {
                if let Some(ip) = trimmed.split(':').nth(1) {
                    router_ip = Some(ip.trim().to_string());
                }
            }
            if guest_ip.is_some() && router_ip.is_some() {
                break;
            }
            if trimmed.is_empty() {
                in_dhcp = false;
            }
        }
    }

    (
        guest_ip.unwrap_or_else(|| "192.168.127.2".into()),
        router_ip.unwrap_or_else(|| "192.168.127.1".into()),
    )
}
