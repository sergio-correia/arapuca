//! Network namespace proxy bridge.
//!
//! Provides loopback bring-up via raw netlink and TCP-to-UDS relay
//! for bridging network access inside an isolated network namespace.
//! Linux-only.

use std::io;
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

/// Bring up the loopback interface via raw netlink.
///
/// Opens an `AF_NETLINK`/`NETLINK_ROUTE` socket, sends an
/// `RTM_SETLINK` message to set `IFF_UP` on interface index 1 (lo).
///
/// # Preconditions
///
/// Assumes the loopback interface has index 1, which holds in a
/// freshly created network namespace.
///
/// # Errors
///
/// Returns an `io::Error` if the netlink socket cannot be created,
/// the message cannot be sent, or the kernel rejects the request
/// (e.g., insufficient privileges).
pub fn loopback_up() -> io::Result<()> {
    #[repr(C)]
    struct Ifinfomsg {
        ifi_family: u8,
        _pad: u8,
        ifi_type: libc::c_ushort,
        ifi_index: libc::c_int,
        ifi_flags: libc::c_uint,
        ifi_change: libc::c_uint,
    }

    #[repr(C)]
    struct Request {
        nlh: libc::nlmsghdr,
        ifi: Ifinfomsg,
    }

    // Response buffer with guaranteed alignment for nlmsghdr (4 bytes).
    #[repr(C)]
    struct Response {
        nlh: libc::nlmsghdr,
        errno: i32,
    }

    // SAFETY: socket() with constant arguments. The returned fd is
    // checked for errors before use.
    let raw_fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_ROUTE,
        )
    };
    if raw_fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: raw_fd is a valid, open file descriptor (checked above).
    let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };

    let msg_len = std::mem::size_of::<Request>() as u32;
    let req = Request {
        nlh: libc::nlmsghdr {
            nlmsg_len: msg_len,
            nlmsg_type: libc::RTM_SETLINK,
            nlmsg_flags: (libc::NLM_F_REQUEST | libc::NLM_F_ACK) as u16,
            nlmsg_seq: 1,
            nlmsg_pid: 0,
        },
        ifi: Ifinfomsg {
            ifi_family: libc::AF_UNSPEC as u8,
            _pad: 0,
            ifi_type: 0,
            ifi_index: 1,
            ifi_flags: libc::IFF_UP as u32,
            ifi_change: libc::IFF_UP as u32,
        },
    };

    // SAFETY: fd is valid (owned), req is a stack-local #[repr(C)]
    // struct, msg_len matches its size.
    let ret = unsafe {
        libc::send(
            fd.as_raw_fd(),
            &raw const req as *const libc::c_void,
            msg_len as usize,
            0,
        )
    };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }

    let mut resp = std::mem::MaybeUninit::<Response>::uninit();

    // SAFETY: fd is valid, resp is a stack-local buffer with correct
    // size and alignment for receiving a netlink error/ack response.
    let n = unsafe {
        libc::recv(
            fd.as_raw_fd(),
            resp.as_mut_ptr() as *mut libc::c_void,
            std::mem::size_of::<Response>(),
            0,
        )
    };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }

    let n = n as usize;
    if n < std::mem::size_of::<libc::nlmsghdr>() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "netlink response too short",
        ));
    }

    // SAFETY: n >= size_of::<nlmsghdr>(), and resp is properly
    // aligned (guaranteed by #[repr(C)] struct layout). The nlh
    // field is at offset 0.
    let resp = unsafe { resp.assume_init() };

    // With NLM_F_ACK, the kernel always replies with NLMSG_ERROR
    // (errno=0 for success). Any other type is unexpected.
    if resp.nlh.nlmsg_type != libc::NLMSG_ERROR as u16 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unexpected netlink response type: {}", resp.nlh.nlmsg_type),
        ));
    }

    if n < std::mem::size_of::<Response>() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "netlink error response too short",
        ));
    }

    // errno == 0 means ACK (success). The kernel returns negative
    // errno values in the error payload.
    if resp.errno != 0 {
        return Err(io::Error::from_raw_os_error(-resp.errno));
    }

    Ok(())
}

const MAX_CONNECTIONS: usize = 64;
const IDLE_TIMEOUT: Duration = Duration::from_secs(300);

/// Thread-creation flags required by glibc/musl for `pthread_create`.
const CLONE_THREAD_FLAGS: u64 = (libc::CLONE_VM
    | libc::CLONE_FS
    | libc::CLONE_FILES
    | libc::CLONE_SIGHAND
    | libc::CLONE_THREAD) as u64;

/// Apply a minimal default-deny seccomp filter for the bridge process.
///
/// Only syscalls needed for TCP accept, UDS connect, bidirectional
/// relay, and thread management are allowed. Everything else kills
/// the process. This prevents a compromised bridge from being used
/// as a seccomp-free pivot.
///
/// `clone` is restricted to require thread-creation flags (the flags
/// must be present, though BPF cannot prevent additional flags from
/// also being set — defense-in-depth, not a hard guarantee).
/// `clone3` returns `ENOSYS` to force glibc fallback to `clone`
/// (where the flag filter applies). `socket` is restricted to
/// `AF_UNIX` only — the TCP listener is already bound pre-seccomp.
/// `mprotect` denies `PROT_EXEC` to block code injection.
///
/// # Preconditions
///
/// The TCP listener must already be bound before calling this
/// function, since `bind` and `listen` are not in the allowlist.
///
/// # Errors
///
/// Returns an error if the filter cannot be built or installed.
pub fn apply_bridge_seccomp() -> crate::Result<()> {
    let (clone3_prog, main_prog) = build_bridge_filters()?;

    // Install clone3 ENOSYS filter first. Seccomp filter stacking:
    // last installed is checked first, and the kernel takes the
    // most restrictive action across all filters.
    seccompiler::apply_filter(&clone3_prog)
        .map_err(|e| crate::Error::Seccomp(format!("install clone3 filter: {e}")))?;

    seccompiler::apply_filter(&main_prog)
        .map_err(|e| crate::Error::Seccomp(format!("install bridge filter: {e}")))?;

    log::info!("bridge seccomp: filter applied");
    Ok(())
}

/// Build two BPF programs:
/// 1. clone3 → ENOSYS (forces glibc fallback to clone)
/// 2. main allowlist (everything else)
fn build_bridge_filters() -> crate::Result<(seccompiler::BpfProgram, seccompiler::BpfProgram)> {
    use seccompiler::{
        SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter, SeccompRule,
    };
    use std::collections::HashMap;

    let arch = crate::seccomp::target_arch()?;

    let mut allow: HashMap<i64, Vec<SeccompRule>> = HashMap::new();

    // I/O: accept, connect, relay, shutdown.
    for nr in [
        libc::SYS_accept4,
        libc::SYS_connect,
        libc::SYS_read,
        libc::SYS_write,
        libc::SYS_writev,
        libc::SYS_recvfrom,
        libc::SYS_sendto,
        libc::SYS_close,
        libc::SYS_shutdown,
        libc::SYS_poll,
        libc::SYS_ppoll,
        libc::SYS_epoll_wait,
        libc::SYS_epoll_ctl,
        libc::SYS_epoll_create1,
    ] {
        allow.insert(nr, vec![]);
    }

    // Thread management.
    for nr in [
        libc::SYS_futex,
        libc::SYS_set_robust_list,
        libc::SYS_sched_yield,
        libc::SYS_gettid,
        libc::SYS_getpid,
        libc::SYS_tgkill,
    ] {
        allow.insert(nr, vec![]);
    }

    // clone: require thread-creation flags to be present.
    let clone_rule = SeccompRule::new(vec![
        SeccompCondition::new(
            0,
            SeccompCmpArgLen::Qword,
            SeccompCmpOp::MaskedEq(CLONE_THREAD_FLAGS),
            CLONE_THREAD_FLAGS,
        )
        .map_err(|e| crate::Error::Seccomp(format!("clone condition: {e}")))?,
    ])
    .map_err(|e| crate::Error::Seccomp(format!("clone rule: {e}")))?;
    allow.insert(libc::SYS_clone, vec![clone_rule]);

    // clone3: must be in the main allowlist (→ Allow) so the
    // stacked clone3 filter's Errno(ENOSYS) wins via seccomp's
    // most-restrictive-action rule. Without this, the main
    // filter's KillProcess mismatch would override the ENOSYS.
    allow.insert(libc::SYS_clone3, vec![]);

    // Memory management.
    for nr in [
        libc::SYS_mmap,
        libc::SYS_munmap,
        libc::SYS_brk,
        libc::SYS_mremap,
        libc::SYS_madvise,
    ] {
        allow.insert(nr, vec![]);
    }

    // mprotect: deny PROT_EXEC (arg2 must NOT have bit 0x4 set).
    let mprotect_rule = SeccompRule::new(vec![
        SeccompCondition::new(
            2,
            SeccompCmpArgLen::Dword,
            SeccompCmpOp::MaskedEq(libc::PROT_EXEC as u64),
            0,
        )
        .map_err(|e| crate::Error::Seccomp(format!("mprotect condition: {e}")))?,
    ])
    .map_err(|e| crate::Error::Seccomp(format!("mprotect rule: {e}")))?;
    allow.insert(libc::SYS_mprotect, vec![mprotect_rule]);

    // Signals.
    for nr in [
        libc::SYS_rt_sigaction,
        libc::SYS_rt_sigprocmask,
        libc::SYS_rt_sigreturn,
        libc::SYS_sigaltstack,
    ] {
        allow.insert(nr, vec![]);
    }

    // Process lifecycle.
    for nr in [libc::SYS_exit, libc::SYS_exit_group] {
        allow.insert(nr, vec![]);
    }

    // socket: only AF_UNIX. The TCP listener is already bound
    // pre-seccomp; the bridge only needs AF_UNIX for connecting
    // to the UDS proxy. Blocking AF_INET/AF_INET6 prevents the
    // bridge from being used as a network pivot.
    let socket_unix_rule = SeccompRule::new(vec![
        SeccompCondition::new(
            0,
            SeccompCmpArgLen::Dword,
            SeccompCmpOp::Eq,
            libc::AF_UNIX as u64,
        )
        .map_err(|e| crate::Error::Seccomp(format!("socket condition: {e}")))?,
    ])
    .map_err(|e| crate::Error::Seccomp(format!("socket rule: {e}")))?;
    allow.insert(libc::SYS_socket, vec![socket_unix_rule]);

    // Misc (needed by glibc/Rust runtime).
    for nr in [
        libc::SYS_getrandom,
        libc::SYS_clock_gettime,
        libc::SYS_clock_nanosleep,
        libc::SYS_nanosleep,
        libc::SYS_setsockopt,
        libc::SYS_getsockopt,
        libc::SYS_fcntl,
        libc::SYS_prlimit64,
        libc::SYS_rseq,
    ] {
        allow.insert(nr, vec![]);
    }

    // clone3: return ENOSYS to force glibc fallback to clone
    // (where our flag filter applies). Allowing clone3 would let
    // the bridge create processes with arbitrary namespace flags,
    // since BPF cannot inspect the clone_args struct pointer.
    // glibc handles ENOSYS gracefully — it retries with clone.
    //
    // This is a separate filter because seccompiler only supports
    // one match action per filter. Seccomp filter stacking applies
    // the most restrictive action, so:
    //   - clone3 → ENOSYS (from this filter)
    //   - allowlisted syscalls → Allow (from the main filter)
    //   - everything else → KillProcess (from the main filter)
    let mut clone3_deny: HashMap<i64, Vec<SeccompRule>> = HashMap::new();
    clone3_deny.insert(libc::SYS_clone3, vec![]);

    let clone3_filter = SeccompFilter::new(
        clone3_deny.into_iter().collect(),
        SeccompAction::Allow,
        SeccompAction::Errno(libc::ENOSYS as u32),
        arch,
    )
    .map_err(|e| crate::Error::Seccomp(format!("build clone3 filter: {e}")))?;

    let clone3_prog: seccompiler::BpfProgram =
        clone3_filter
            .try_into()
            .map_err(|e: seccompiler::BackendError| {
                crate::Error::Seccomp(format!("compile clone3 filter: {e}"))
            })?;

    // Main allowlist filter.
    //   mismatch_action = KillProcess (unknown syscalls → kill)
    //   match_action    = Allow       (listed syscalls → allow)
    let filter = SeccompFilter::new(
        allow.into_iter().collect(),
        SeccompAction::KillProcess,
        SeccompAction::Allow,
        arch,
    )
    .map_err(|e| crate::Error::Seccomp(format!("build bridge filter: {e}")))?;

    let main_prog = filter.try_into().map_err(|e: seccompiler::BackendError| {
        crate::Error::Seccomp(format!("compile bridge filter: {e}"))
    })?;

    Ok((clone3_prog, main_prog))
}

/// Relay bytes bidirectionally between a TCP stream and a Unix
/// domain stream socket.
///
/// Sets `TCP_NODELAY` on the TCP stream. Spawns two threads (one
/// per direction). When `io::copy` returns on one direction,
/// shuts down the opposite stream's write half so the peer sees
/// EOF. Blocks until both directions complete.
///
/// # Errors
///
/// Returns an error if the UDS connection fails or relay setup fails.
pub fn relay(tcp: TcpStream, uds_path: &Path) -> io::Result<()> {
    tcp.set_nodelay(true)?;
    tcp.set_read_timeout(Some(IDLE_TIMEOUT))?;

    let uds = UnixStream::connect(uds_path)?;
    uds.set_read_timeout(Some(IDLE_TIMEOUT))?;

    let tcp_read = tcp;
    let uds_read = uds;
    let tcp_write = tcp_read.try_clone()?;
    let uds_write = uds_read.try_clone()?;

    let t1 = std::thread::spawn(move || {
        let mut src = &tcp_read;
        let mut dst = &uds_write;
        if let Err(e) = io::copy(&mut src, &mut dst) {
            log::debug!("relay tcp→uds: {e}");
        }
        let _ = uds_write.shutdown(Shutdown::Write);
    });

    let t2 = std::thread::spawn(move || {
        let mut src = &uds_read;
        let mut dst = &tcp_write;
        if let Err(e) = io::copy(&mut src, &mut dst) {
            log::debug!("relay uds→tcp: {e}");
        }
        let _ = tcp_write.shutdown(Shutdown::Write);
    });

    // JoinHandle has no timed join. The relay threads will terminate
    // once the streams are shut down (io::copy sees EOF or the read
    // timeout fires).
    let _ = t1.join();
    let _ = t2.join();

    Ok(())
}

/// Listen on TCP and relay each connection to a UDS.
///
/// Enforces [`MAX_CONNECTIONS`] concurrent connection limit. Sends
/// a single readiness byte on `ready_fd` once the listener is
/// bound. Runs until the process is killed (via pdeathsig).
///
/// # Errors
///
/// Returns an error if the listener cannot be bound or the
/// readiness signal cannot be sent.
/// # Safety
///
/// `ready_fd` must be a valid, open file descriptor for a pipe write
/// end that the caller owns. It will be closed after the readiness
/// byte is sent.
pub fn listen_and_relay(addr: SocketAddr, uds_path: &Path, ready_fd: RawFd) -> io::Result<()> {
    // SAFETY: caller guarantees ready_fd is a valid, owned pipe write end.
    let ready = unsafe { OwnedFd::from_raw_fd(ready_fd) };

    let listener = TcpListener::bind(addr)?;

    // Signal readiness to the parent.
    // SAFETY: ready is valid (owned), writing a single byte to a pipe.
    let written =
        unsafe { libc::write(ready.as_raw_fd(), [1u8].as_ptr() as *const libc::c_void, 1) };
    if written < 0 {
        return Err(io::Error::last_os_error());
    }
    drop(ready);

    let active = Arc::new(AtomicUsize::new(0));

    for stream in listener.incoming() {
        let tcp = match stream {
            Ok(s) => s,
            Err(e) => {
                log::debug!("bridge accept: {e}");
                std::thread::sleep(Duration::from_millis(50));
                continue;
            }
        };

        let prev = active.fetch_add(1, Ordering::AcqRel);
        if prev >= MAX_CONNECTIONS {
            active.fetch_sub(1, Ordering::Release);
            drop(tcp);
            continue;
        }

        let active = Arc::clone(&active);
        let path = uds_path.to_path_buf();

        std::thread::spawn(move || {
            let _ = relay(tcp, &path);
            active.fetch_sub(1, Ordering::Release);
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bridge_seccomp_filters_build() {
        let (clone3_prog, main_prog) = build_bridge_filters().unwrap();
        assert!(!clone3_prog.is_empty());
        assert!(!main_prog.is_empty());
    }

    #[test]
    fn loopback_up_smoke_test() {
        // Outside a netns, lo is already up. The call should
        // succeed (idempotent) or fail with EPERM if we lack
        // CAP_NET_ADMIN. Either outcome is valid — we verify
        // no panic or undefined behavior.
        let result = loopback_up();
        match &result {
            Ok(()) => eprintln!("loopback_up: ok (already up)"),
            Err(e) => eprintln!("loopback_up: {e} (expected in unprivileged context)"),
        }
    }

    #[test]
    fn relay_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("echo.sock");

        let listener = std::os::unix::net::UnixListener::bind(&sock_path).unwrap();

        let echo_handle = std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            let mut buf = [0u8; 256];
            loop {
                let n = match io::Read::read(&mut conn, &mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                if io::Write::write_all(&mut conn, &buf[..n]).is_err() {
                    break;
                }
            }
        });

        let tcp_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = tcp_listener.local_addr().unwrap();

        let relay_path = sock_path.clone();
        let relay_handle = std::thread::spawn(move || {
            let (stream, _) = tcp_listener.accept().unwrap();
            relay(stream, &relay_path).unwrap();
        });

        let mut client = TcpStream::connect(addr).unwrap();
        io::Write::write_all(&mut client, b"hello bridge").unwrap();
        client.shutdown(Shutdown::Write).unwrap();

        let mut response = Vec::new();
        io::Read::read_to_end(&mut client, &mut response).unwrap();

        assert_eq!(response, b"hello bridge");

        relay_handle.join().unwrap();
        echo_handle.join().unwrap();
    }

    #[test]
    fn connection_limit_enforced() {
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("slow.sock");

        let listener = std::os::unix::net::UnixListener::bind(&sock_path).unwrap();

        // UDS server that accepts connections but never sends data
        // (holds connections open until dropped).
        let _server_handle = std::thread::spawn(move || {
            let mut conns = Vec::new();
            for stream in listener.incoming() {
                match stream {
                    Ok(s) => conns.push(s),
                    Err(_) => break,
                }
            }
        });

        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let tcp_listener = TcpListener::bind(addr).unwrap();
        let bound_addr = tcp_listener.local_addr().unwrap();

        let active = Arc::new(AtomicUsize::new(0));
        let active_clone = Arc::clone(&active);
        let path = sock_path.clone();

        let accept_handle = std::thread::spawn(move || {
            for stream in tcp_listener.incoming() {
                let tcp = match stream {
                    Ok(s) => s,
                    Err(_) => break,
                };
                let prev = active_clone.fetch_add(1, Ordering::AcqRel);
                if prev >= 4 {
                    active_clone.fetch_sub(1, Ordering::Release);
                    drop(tcp);
                    continue;
                }
                let active = Arc::clone(&active_clone);
                let p = path.clone();
                std::thread::spawn(move || {
                    let _ = relay(tcp, &p);
                    active.fetch_sub(1, Ordering::Release);
                });
            }
        });

        // Open 4 connections (should all succeed).
        let mut clients: Vec<TcpStream> = (0..4)
            .map(|_| TcpStream::connect(bound_addr).unwrap())
            .collect();

        std::thread::sleep(Duration::from_millis(50));
        assert_eq!(active.load(Ordering::Acquire), 4);

        // 5th connection: accepted by TCP but dropped immediately
        // (RST sent to client).
        let extra = TcpStream::connect(bound_addr).unwrap();
        extra
            .set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let mut buf = [0u8; 1];
        let result = io::Read::read(&mut &extra, &mut buf);
        assert!(
            result.is_err() || result.unwrap() == 0,
            "5th connection should be rejected"
        );

        // Clean up: close all clients to unblock relay threads.
        for c in clients.drain(..) {
            drop(c);
        }
        drop(extra);

        // Give threads time to wind down, then drop the listener
        // to break the accept loop.
        std::thread::sleep(Duration::from_millis(100));
        drop(accept_handle);
    }
}
