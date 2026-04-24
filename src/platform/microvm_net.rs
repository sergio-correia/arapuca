//! Micro-VM networking via passt.
//!
//! Provides userspace TCP/UDP networking for micro-VMs without
//! root privileges. Disabled by default — only started when
//! `use_netns` is false (meaning: allow network access).

use std::io;
use std::os::unix::io::IntoRawFd;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

/// Guest network configuration parsed from passt's DHCP output.
pub(crate) struct NetworkInfo {
    pub guest_ip: String,
    pub router_ip: String,
    pub dns_servers: Vec<String>,
}

/// A running passt network proxy.
pub(crate) struct PasstHandle {
    /// The passt child process.
    pub child: Child,
    /// Parent end of the socket pair — passed to libkrun.
    pub parent_fd: i32,
    /// Guest network info (IPs parsed from passt DHCP output).
    pub net_info: NetworkInfo,
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
        .arg("--no-map-gw")
        .stdout(Stdio::null())
        .stderr(Stdio::piped());

    // Clear CLOEXEC on child_fd in the child process so passt
    // inherits it across exec. Done via pre_exec (not parent-side
    // fcntl) to avoid leaking the FD if another thread forks
    // concurrently — important since arapuca is also a library.
    // SAFETY: fcntl is async-signal-safe; child_fd is valid.
    unsafe {
        cmd.pre_exec(move || {
            if libc::fcntl(child_fd, libc::F_SETFD, 0) < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }

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

    // Close the child end in the parent — passt inherited it
    // (CLOEXEC was cleared in pre_exec).
    // SAFETY: child_fd is valid.
    unsafe { libc::close(child_fd) };

    // Parse DHCP info from passt's stderr with a wall-clock timeout.
    let net_info = match child.stderr.take() {
        Some(stderr) => match parse_dhcp_info(stderr) {
            Ok(info) => info,
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                // SAFETY: parent_fd is valid.
                unsafe { libc::close(parent_fd) };
                return Err(e);
            }
        },
        None => {
            let _ = child.kill();
            let _ = child.wait();
            // SAFETY: parent_fd is valid.
            unsafe { libc::close(parent_fd) };
            return Err(io::Error::other("passt stderr not available"));
        }
    };

    Ok(PasstHandle {
        child,
        parent_fd,
        net_info,
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
///
/// Uses a wall-clock timeout to avoid blocking indefinitely if
/// passt hangs. Both IPs are validated as IPv4 addresses to
/// prevent injection when embedded in the guest init script.
fn parse_dhcp_info(stderr: std::process::ChildStderr) -> io::Result<NetworkInfo> {
    let (tx, rx) = mpsc::channel();

    std::thread::spawn(move || {
        let _ = tx.send(parse_dhcp_info_inner(stderr));
    });

    rx.recv_timeout(Duration::from_secs(5)).map_err(|_| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            "passt DHCP info not received within 5s",
        )
    })?
}

/// Blocking inner parser — runs in a dedicated thread.
///
/// Parses the DHCP section (assign/router) and DNS section
/// (nameserver IPs) from passt's stderr startup output.
fn parse_dhcp_info_inner(stderr: std::process::ChildStderr) -> io::Result<NetworkInfo> {
    use std::io::BufRead;
    use std::net::Ipv4Addr;

    let reader = io::BufReader::new(stderr);
    let mut guest_ip: Option<String> = None;
    let mut router_ip: Option<String> = None;
    let mut dns_servers: Vec<String> = Vec::new();
    let mut in_dhcp = false;
    let mut in_dns = false;
    let mut done_dhcp = false;
    let mut done_dns = false;

    for (i, line_result) in reader.lines().enumerate() {
        if i > 50 || (done_dhcp && done_dns) {
            break;
        }
        let line = match line_result {
            Ok(l) => l,
            Err(_) => break,
        };

        let trimmed = line.trim();

        if line.contains("DHCP:") {
            in_dhcp = true;
            in_dns = false;
            continue;
        }
        if line.contains("DNS:") {
            in_dns = true;
            in_dhcp = false;
            done_dhcp = guest_ip.is_some() && router_ip.is_some();
            continue;
        }

        // A non-indented line ends the current section.
        if !line.starts_with(' ') && !line.starts_with('\t') {
            if in_dhcp {
                done_dhcp = true;
            }
            if in_dns {
                done_dns = true;
            }
            in_dhcp = false;
            in_dns = false;
            continue;
        }

        if in_dhcp {
            if trimmed.starts_with("assign:") {
                if let Some(raw) = trimmed.split(':').nth(1) {
                    let ip: Ipv4Addr = raw.trim().parse().map_err(|_| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("invalid guest IP from passt: {}", raw.trim()),
                        )
                    })?;
                    guest_ip = Some(ip.to_string());
                }
            } else if trimmed.starts_with("router:") {
                if let Some(raw) = trimmed.split(':').nth(1) {
                    let ip: Ipv4Addr = raw.trim().parse().map_err(|_| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("invalid router IP from passt: {}", raw.trim()),
                        )
                    })?;
                    router_ip = Some(ip.to_string());
                }
            }
        } else if in_dns {
            if let Ok(ip) = trimmed.parse::<Ipv4Addr>() {
                dns_servers.push(ip.to_string());
            }
        }
    }

    match (guest_ip, router_ip) {
        (Some(g), Some(r)) => Ok(NetworkInfo {
            guest_ip: g,
            router_ip: r,
            dns_servers,
        }),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "passt did not provide both guest and router IPs",
        )),
    }
}
