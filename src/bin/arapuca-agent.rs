//! Guest agent for persistent VMs.
//!
//! Runs inside the VM, listens on vsock port 1024, handles exec
//! requests from the host via the binary framing protocol.
//! Started as a background process from the init script (NOT PID 1).

use std::ffi::CString;
use std::io::{self, Read, Write};
use std::os::fd::RawFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use arapuca::vm::protocol::{
    self, AGENT_VSOCK_PORT, ControlMessage, ExecRequest, IDLE_TIMEOUT_SECS, MAX_CONNECTIONS,
    MAX_SESSIONS, NONCE_SIZE, PROTOCOL_VERSION,
};

// ─── vsock ────────────────────────────────────────────────────

const AF_VSOCK: libc::c_int = 40;
const VMADDR_CID_ANY: u32 = u32::MAX;

#[repr(C)]
struct SockaddrVm {
    svm_family: libc::sa_family_t,
    svm_reserved1: u16,
    svm_port: u32,
    svm_cid: u32,
    svm_flags: u8,
    svm_zero: [u8; 3],
}

const _: () = assert!(std::mem::size_of::<SockaddrVm>() == 16);

// ─── capability structs ───────────────────────────────────────

#[repr(C)]
struct CapHeader {
    version: u32,
    pid: i32,
}

#[repr(C)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

const LINUX_CAPABILITY_VERSION_3: u32 = 0x20080522;
const CAP_SETGID: u32 = 6;
const CAP_SETUID: u32 = 7;

// ─── main ─────────────────────────────────────────────────────

fn main() {
    let nonce = read_nonce_file("/cidata/nonce");

    // SAFETY: prctl with PR_SET_CHILD_SUBREAPER is a simple setter.
    unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) };

    let listener_fd = create_vsock_listener(AGENT_VSOCK_PORT);

    drop_capabilities();

    if let Ok(content) = std::fs::read_to_string("/cidata/max_lifetime") {
        if let Ok(secs) = content.trim().parse::<libc::c_uint>() {
            if secs > 0 {
                install_alarm_handler();
                // SAFETY: alarm is always safe to call.
                unsafe { libc::alarm(secs) };
            }
        }
    }

    let active_conns = Arc::new(AtomicUsize::new(0));
    let active_sessions = Arc::new(AtomicUsize::new(0));

    loop {
        // SAFETY: listener_fd is a valid SOCK_CLOEXEC socket.
        let conn_fd = unsafe {
            libc::accept4(
                listener_fd,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                libc::SOCK_CLOEXEC,
            )
        };
        if conn_fd < 0 {
            let e = io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            eprintln!("agent: accept: {e}");
            continue;
        }

        if active_conns.load(Ordering::Acquire) >= MAX_CONNECTIONS {
            // SAFETY: conn_fd is a valid fd just returned by accept4.
            unsafe { libc::close(conn_fd) };
            continue;
        }

        active_conns.fetch_add(1, Ordering::AcqRel);
        let nonce_copy = nonce;
        let conns = Arc::clone(&active_conns);
        let sessions = Arc::clone(&active_sessions);

        std::thread::spawn(move || {
            handle_connection(conn_fd, &nonce_copy, &sessions);
            // SAFETY: conn_fd was opened by accept4 in this session.
            unsafe { libc::close(conn_fd) };
            conns.fetch_sub(1, Ordering::AcqRel);
        });
    }
}

// ─── setup helpers ────────────────────────────────────────────

fn read_nonce_file(path: &str) -> [u8; NONCE_SIZE] {
    let bytes = std::fs::read(path).unwrap_or_else(|e| {
        eprintln!("agent: cannot read {path}: {e}");
        std::process::exit(1);
    });
    if bytes.len() != NONCE_SIZE {
        eprintln!(
            "agent: invalid nonce size: {} (expected {NONCE_SIZE})",
            bytes.len()
        );
        std::process::exit(1);
    }
    let mut nonce = [0u8; NONCE_SIZE];
    nonce.copy_from_slice(&bytes);
    nonce
}

fn create_vsock_listener(port: u32) -> RawFd {
    // SAFETY: creating a vsock socket with SOCK_CLOEXEC.
    let fd = unsafe { libc::socket(AF_VSOCK, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        eprintln!("agent: socket(AF_VSOCK): {}", io::Error::last_os_error());
        std::process::exit(1);
    }

    let addr = SockaddrVm {
        svm_family: AF_VSOCK as libc::sa_family_t,
        svm_reserved1: 0,
        svm_port: port,
        svm_cid: VMADDR_CID_ANY,
        svm_flags: 0,
        svm_zero: [0; 3],
    };

    // SAFETY: fd is a valid vsock socket, addr is stack-local.
    let ret = unsafe {
        libc::bind(
            fd,
            &addr as *const _ as *const libc::sockaddr,
            std::mem::size_of::<SockaddrVm>() as libc::socklen_t,
        )
    };
    if ret < 0 {
        eprintln!(
            "agent: bind vsock port {port}: {}",
            io::Error::last_os_error()
        );
        std::process::exit(1);
    }

    // SAFETY: fd is a valid bound socket.
    let ret = unsafe { libc::listen(fd, 16) };
    if ret < 0 {
        eprintln!("agent: listen: {}", io::Error::last_os_error());
        std::process::exit(1);
    }

    fd
}

fn drop_capabilities() {
    // SAFETY: prctl calls are simple setters with integer arguments.
    unsafe {
        let ret = libc::prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_CLEAR_ALL,
            0,
            0,
            0,
        );
        if ret != 0 {
            eprintln!("agent: PR_CAP_AMBIENT_CLEAR_ALL failed");
            std::process::exit(1);
        }

        for cap in 0u64..64 {
            if cap != u64::from(CAP_SETGID) && cap != u64::from(CAP_SETUID) {
                let ret = libc::prctl(libc::PR_CAPBSET_DROP, cap, 0, 0, 0);
                // EINVAL = cap doesn't exist on this kernel (fine).
                if ret != 0 && *libc::__errno_location() != libc::EINVAL {
                    eprintln!("agent: PR_CAPBSET_DROP({cap}) failed");
                    std::process::exit(1);
                }
            }
        }
    }

    let mask: u32 = (1 << CAP_SETGID) | (1 << CAP_SETUID);
    let hdr = CapHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let data = [
        CapData {
            effective: mask,
            permitted: mask,
            inheritable: 0,
        },
        CapData {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        },
    ];
    // SAFETY: capset with well-formed v3 header and two-element data array.
    let ret = unsafe { libc::syscall(libc::SYS_capset, &hdr as *const _, data.as_ptr()) };
    if ret != 0 {
        eprintln!("agent: capset failed: {}", io::Error::last_os_error());
        std::process::exit(1);
    }
}

fn install_alarm_handler() {
    extern "C" fn alarm_handler(_sig: libc::c_int) {
        // SAFETY: kill(1, SIGKILL) is async-signal-safe.
        unsafe { libc::kill(1, libc::SIGKILL) };
    }
    // SAFETY: handler is async-signal-safe (only kill).
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = alarm_handler as *const () as usize;
        sa.sa_flags = 0;
        libc::sigaction(libc::SIGALRM, &sa, std::ptr::null_mut());
    }
}

// ─── connection handler ───────────────────────────────────────

fn handle_connection(fd: RawFd, nonce: &[u8; NONCE_SIZE], sessions: &AtomicUsize) {
    let mut stream = FdStream(fd);

    let client_nonce = match protocol::read_nonce(&mut stream) {
        Ok(n) => n,
        Err(_) => return,
    };
    if !protocol::nonce_eq(&client_nonce, nonce) {
        return;
    }

    let hello = ControlMessage::Hello {
        version: PROTOCOL_VERSION.to_string(),
    };
    if protocol::write_control(&mut stream, &hello).is_err() {
        return;
    }

    loop {
        set_recv_timeout(fd, IDLE_TIMEOUT_SECS);

        let msg = match protocol::read_control(&mut stream) {
            Ok(m) => m,
            Err(e) => {
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut {
                    return;
                }
                return;
            }
        };

        match msg {
            ControlMessage::Ping
                if protocol::write_control(&mut stream, &ControlMessage::Pong).is_err() =>
            {
                return;
            }
            ControlMessage::Ping => {}
            ControlMessage::Shutdown => {
                // SAFETY: kill PID 1 triggers kernel shutdown.
                unsafe { libc::kill(1, libc::SIGKILL) };
                return;
            }
            ControlMessage::Exec(req) => {
                if sessions.load(Ordering::Acquire) >= MAX_SESSIONS {
                    let _ = protocol::write_control(
                        &mut stream,
                        &ControlMessage::Status { exit_code: 126 },
                    );
                    continue;
                }
                sessions.fetch_add(1, Ordering::AcqRel);
                set_recv_timeout(fd, 0);

                let exit_code = handle_exec(fd, &req);
                sessions.fetch_sub(1, Ordering::AcqRel);

                if protocol::write_control(&mut stream, &ControlMessage::Status { exit_code })
                    .is_err()
                {
                    return;
                }
            }
            _ => {}
        }
    }
}

fn set_recv_timeout(fd: RawFd, secs: u64) {
    let tv = libc::timeval {
        tv_sec: secs as libc::time_t,
        tv_usec: 0,
    };
    // SAFETY: fd is a valid socket, tv is stack-local.
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &tv as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        );
    }
}

// ─── PATH resolution ──────────────────────────────────────────

/// Resolve a command name to an absolute path using the request's
/// PATH environment variable. Returns None if not found.
fn resolve_command(cmd: &str, env: &[String]) -> Option<String> {
    if cmd.contains('/') {
        return Some(cmd.to_string());
    }

    let path_val = env
        .iter()
        .find_map(|e| e.strip_prefix("PATH="))
        .unwrap_or("/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin");

    for dir in path_val.split(':') {
        if dir.is_empty() {
            continue;
        }
        let candidate = format!("{dir}/{cmd}");
        let c_path = match CString::new(candidate.as_str()) {
            Ok(c) => c,
            Err(_) => continue,
        };
        // SAFETY: c_path is a valid null-terminated string.
        if unsafe { libc::access(c_path.as_ptr(), libc::X_OK) } == 0 {
            return Some(candidate);
        }
    }
    None
}

// ─── exec handler ─────────────────────────────────────────────

fn handle_exec(conn_fd: RawFd, req: &ExecRequest) -> i32 {
    // Resolve user before fork (getpwnam_r is thread-safe but not
    // async-signal-safe, so it must happen pre-fork).
    let user_info = if req.user != "root" {
        match resolve_user(&req.user) {
            Some(info) => Some(info),
            None => {
                eprintln!("agent: user not found: {}", req.user);
                return 126;
            }
        }
    } else {
        None
    };

    // Resolve command via PATH before fork (allocations and
    // access() are not async-signal-safe).
    let resolved_cmd = resolve_command(&req.cmd, &req.env);
    let cmd_str = match &resolved_cmd {
        Some(path) => path.as_str(),
        None => {
            eprintln!("agent: command not found: {}", req.cmd);
            return 127;
        }
    };

    // Build ALL data structures before fork — allocations are not
    // async-signal-safe and can deadlock if another thread holds the
    // allocator lock at fork time.
    let c_cmd = match CString::new(cmd_str) {
        Ok(c) => c,
        Err(_) => return 126,
    };
    let mut c_argv: Vec<CString> = Vec::with_capacity(1 + req.args.len());
    c_argv.push(c_cmd.clone());
    for arg in &req.args {
        match CString::new(arg.as_str()) {
            Ok(c) => c_argv.push(c),
            Err(_) => return 126,
        }
    }
    let mut c_envp: Vec<CString> = Vec::with_capacity(req.env.len());
    for env_str in &req.env {
        if let Ok(c) = CString::new(env_str.as_str()) {
            c_envp.push(c);
        }
    }

    // Build pointer arrays pre-fork too.
    let argv_ptrs: Vec<*const libc::c_char> = c_argv
        .iter()
        .map(|a| a.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();
    let envp_ptrs: Vec<*const libc::c_char> = c_envp
        .iter()
        .map(|e| e.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();

    if req.tty {
        handle_exec_tty(
            conn_fd,
            req,
            &c_cmd,
            &argv_ptrs,
            &envp_ptrs,
            user_info.as_ref(),
        )
    } else {
        handle_exec_pipes(conn_fd, &c_cmd, &argv_ptrs, &envp_ptrs, user_info.as_ref())
    }
}

fn handle_exec_pipes(
    conn_fd: RawFd,
    c_cmd: &CString,
    argv_ptrs: &[*const libc::c_char],
    envp_ptrs: &[*const libc::c_char],
    user_info: Option<&UserInfo>,
) -> i32 {
    let mut stdin_pipe = [0i32; 2];
    let mut stdout_pipe = [0i32; 2];
    let mut stderr_pipe = [0i32; 2];

    // SAFETY: pipe2 with valid arrays and O_CLOEXEC flag.
    unsafe {
        if libc::pipe2(stdin_pipe.as_mut_ptr(), libc::O_CLOEXEC) != 0 {
            return 126;
        }
        if libc::pipe2(stdout_pipe.as_mut_ptr(), libc::O_CLOEXEC) != 0 {
            libc::close(stdin_pipe[0]);
            libc::close(stdin_pipe[1]);
            return 126;
        }
        if libc::pipe2(stderr_pipe.as_mut_ptr(), libc::O_CLOEXEC) != 0 {
            libc::close(stdin_pipe[0]);
            libc::close(stdin_pipe[1]);
            libc::close(stdout_pipe[0]);
            libc::close(stdout_pipe[1]);
            return 126;
        }
    }

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        unsafe {
            libc::close(stdin_pipe[0]);
            libc::close(stdin_pipe[1]);
            libc::close(stdout_pipe[0]);
            libc::close(stdout_pipe[1]);
            libc::close(stderr_pipe[0]);
            libc::close(stderr_pipe[1]);
        }
        return 126;
    }

    if pid == 0 {
        // ── Child (pipe mode) ─────────────────────────────
        unsafe {
            libc::dup2(stdin_pipe[0], 0);
            libc::dup2(stdout_pipe[1], 1);
            libc::dup2(stderr_pipe[1], 2);
            libc::close(stdin_pipe[0]);
            libc::close(stdin_pipe[1]);
            libc::close(stdout_pipe[0]);
            libc::close(stdout_pipe[1]);
            libc::close(stderr_pipe[0]);
            libc::close(stderr_pipe[1]);
            exec_child(c_cmd, argv_ptrs, envp_ptrs, user_info);
        }
    }

    unsafe {
        libc::close(stdin_pipe[0]);
        libc::close(stdout_pipe[1]);
        libc::close(stderr_pipe[1]);
    }

    let (exit_code, stdin_closed) =
        forward_io(conn_fd, stdin_pipe[1], stdout_pipe[0], stderr_pipe[0], pid);

    unsafe {
        if !stdin_closed {
            libc::close(stdin_pipe[1]);
        }
        libc::close(stdout_pipe[0]);
        libc::close(stderr_pipe[0]);
    }

    exit_code
}

fn handle_exec_tty(
    conn_fd: RawFd,
    req: &ExecRequest,
    c_cmd: &CString,
    argv_ptrs: &[*const libc::c_char],
    envp_ptrs: &[*const libc::c_char],
    user_info: Option<&UserInfo>,
) -> i32 {
    let mut master: libc::c_int = -1;
    let mut slave: libc::c_int = -1;

    // SAFETY: openpty with null name/termios/winsize.
    let ret = unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    if ret != 0 {
        return 126;
    }

    // SAFETY: set FD_CLOEXEC on master immediately.
    unsafe { libc::fcntl(master, libc::F_SETFD, libc::FD_CLOEXEC) };

    // Set initial window size if provided.
    if req.rows > 0 && req.cols > 0 {
        let ws: libc::winsize = libc::winsize {
            ws_row: req.rows,
            ws_col: req.cols,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        // SAFETY: master is a valid PTY fd, ws is stack-local.
        unsafe { libc::ioctl(master, libc::TIOCSWINSZ, &ws) };
    }

    // SAFETY: all pre-fork allocations complete.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        // Fork failed — close both PTY fds.
        unsafe {
            libc::close(master);
            libc::close(slave);
        }
        return 126;
    }

    if pid == 0 {
        // ── Child (TTY mode) ──────────────────────────────
        // All calls are async-signal-safe.
        unsafe {
            libc::close(master);
            libc::setsid();
            libc::ioctl(slave, libc::TIOCSCTTY, 0);
            libc::dup2(slave, 0);
            libc::dup2(slave, 1);
            libc::dup2(slave, 2);
            if slave > 2 {
                libc::close(slave);
            }
            exec_child(c_cmd, argv_ptrs, envp_ptrs, user_info);
        }
    }

    // ── Parent (TTY mode) ─────────────────────────────────
    // SAFETY: parent doesn't need the slave.
    unsafe { libc::close(slave) };

    let exit_code = forward_io_tty(conn_fd, master, pid);

    // SAFETY: close the master fd.
    unsafe { libc::close(master) };

    exit_code
}

/// Shared child exec logic (called after dup2, async-signal-safe only).
///
/// # Safety
/// Must only be called in the forked child after dup2 of stdio fds.
/// All calls must be async-signal-safe. Never returns.
unsafe fn exec_child(
    c_cmd: &CString,
    argv_ptrs: &[*const libc::c_char],
    envp_ptrs: &[*const libc::c_char],
    user_info: Option<&UserInfo>,
) -> ! {
    unsafe {
        for fd in 3..1024 {
            libc::close(fd);
        }

        if let Some(info) = user_info {
            if libc::setgroups(info.ngroups as libc::size_t, info.groups.as_ptr()) != 0 {
                libc::_exit(126);
            }
            if libc::setgid(info.gid) != 0 {
                libc::_exit(126);
            }
            if libc::setuid(info.uid) != 0 {
                libc::_exit(126);
            }
        }

        libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
        libc::execve(c_cmd.as_ptr(), argv_ptrs.as_ptr(), envp_ptrs.as_ptr());
        libc::_exit(127);
    }
}

struct UserInfo {
    uid: libc::uid_t,
    gid: libc::gid_t,
    groups: Vec<libc::gid_t>,
    ngroups: i32,
}

fn resolve_user(username: &str) -> Option<UserInfo> {
    let c_name = CString::new(username).ok()?;
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    let mut buf = vec![0u8; 4096];

    // SAFETY: getpwnam_r with properly sized buffer.
    let ret = unsafe {
        libc::getpwnam_r(
            c_name.as_ptr(),
            &mut pwd,
            buf.as_mut_ptr().cast::<libc::c_char>(),
            buf.len(),
            &mut result,
        )
    };
    if ret != 0 || result.is_null() {
        return None;
    }

    let uid = pwd.pw_uid;
    let gid = pwd.pw_gid;

    let mut ngroups: libc::c_int = 32;
    let mut groups = vec![0 as libc::gid_t; ngroups as usize];
    // SAFETY: getgrouplist with valid username and pre-sized buffer.
    let ret =
        unsafe { libc::getgrouplist(c_name.as_ptr(), gid, groups.as_mut_ptr(), &mut ngroups) };
    if ret < 0 {
        groups.resize(ngroups as usize, 0);
        unsafe { libc::getgrouplist(c_name.as_ptr(), gid, groups.as_mut_ptr(), &mut ngroups) };
    }
    groups.truncate(ngroups as usize);

    Some(UserInfo {
        uid,
        gid,
        groups,
        ngroups,
    })
}

// ─── I/O forwarding ───────────────────────────────────────────

/// Returns (exit_code, stdin_was_closed).
fn forward_io(
    conn_fd: RawFd,
    stdin_w: RawFd,
    stdout_r: RawFd,
    stderr_r: RawFd,
    child_pid: libc::pid_t,
) -> (i32, bool) {
    // Set child pipes to non-blocking.
    // SAFETY: F_SETFL with O_NONBLOCK on valid fds.
    unsafe {
        libc::fcntl(stdout_r, libc::F_SETFL, libc::O_NONBLOCK);
        libc::fcntl(stderr_r, libc::F_SETFL, libc::O_NONBLOCK);
    }

    let mut fds = [
        libc::pollfd {
            fd: conn_fd,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: stdout_r,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: stderr_r,
            events: libc::POLLIN,
            revents: 0,
        },
    ];

    let mut stdin_open = true;
    let mut stdout_done = false;
    let mut stderr_done = false;
    let mut child_exited = false;
    let mut wstatus = 0i32;

    loop {
        // SAFETY: poll with valid pollfd array and timeout.
        let ret = unsafe { libc::poll(fds.as_mut_ptr(), 3, 100) };
        if ret < 0 {
            let e = io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            break;
        }

        // Forward child stdout → vsock.
        if !stdout_done && (fds[1].revents & (libc::POLLIN | libc::POLLHUP) != 0) {
            stdout_done = !drain_pipe_to_conn(stdout_r, conn_fd, protocol::CHANNEL_STDOUT);
            if stdout_done {
                fds[1].fd = -1;
            }
        }

        // Forward child stderr → vsock.
        if !stderr_done && (fds[2].revents & (libc::POLLIN | libc::POLLHUP) != 0) {
            stderr_done = !drain_pipe_to_conn(stderr_r, conn_fd, protocol::CHANNEL_STDERR);
            if stderr_done {
                fds[2].fd = -1;
            }
        }

        // Read from vsock (stdin data or control).
        if fds[0].revents & libc::POLLIN != 0 {
            match protocol::read_frame(&mut FdStream(conn_fd)) {
                Ok((ch, payload)) => {
                    if ch == protocol::CHANNEL_STDIN && stdin_open {
                        if payload.is_empty() {
                            // SAFETY: closing our write end of stdin pipe.
                            unsafe { libc::close(stdin_w) };
                            stdin_open = false;
                        } else {
                            let _ = write_all_fd(stdin_w, &payload);
                        }
                    } else if ch == protocol::CHANNEL_CONTROL {
                        if let Ok(ControlMessage::Shutdown) = ControlMessage::parse(&payload) {
                            // SAFETY: kill PID 1 triggers kernel shutdown.
                            unsafe { libc::kill(1, libc::SIGKILL) };
                            return (137, !stdin_open);
                        }
                    }
                }
                Err(_) => {
                    // Client disconnected — kill child.
                    // SAFETY: child_pid is a valid PID from fork.
                    unsafe { libc::kill(child_pid, libc::SIGKILL) };
                    break;
                }
            }
        }

        if fds[0].revents & (libc::POLLHUP | libc::POLLERR) != 0 {
            // SAFETY: child_pid is a valid PID from fork.
            unsafe { libc::kill(child_pid, libc::SIGKILL) };
            break;
        }

        // Check child status (non-blocking).
        if !child_exited {
            // SAFETY: child_pid is valid, wstatus is stack-local.
            let ret = unsafe { libc::waitpid(child_pid, &mut wstatus, libc::WNOHANG) };
            if ret > 0 {
                child_exited = true;
            }
        }

        if child_exited && stdout_done && stderr_done {
            return (exit_code_from_wstatus(wstatus), !stdin_open);
        }
    }

    // Final waitpid if we broke out early.
    if !child_exited {
        // SAFETY: child_pid is valid.
        unsafe { libc::waitpid(child_pid, &mut wstatus, 0) };
    }
    (exit_code_from_wstatus(wstatus), !stdin_open)
}

/// TTY I/O forwarding: poll master fd + connection fd.
fn forward_io_tty(conn_fd: RawFd, master_fd: RawFd, child_pid: libc::pid_t) -> i32 {
    // SAFETY: set master to non-blocking.
    unsafe { libc::fcntl(master_fd, libc::F_SETFL, libc::O_NONBLOCK) };

    let mut fds = [
        libc::pollfd {
            fd: conn_fd,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: master_fd,
            events: libc::POLLIN,
            revents: 0,
        },
    ];

    let mut master_done = false;
    let mut child_exited = false;
    let mut wstatus = 0i32;
    let mut grace_deadline: Option<std::time::Instant> = None;

    loop {
        // SAFETY: poll with valid pollfd array.
        let ret = unsafe { libc::poll(fds.as_mut_ptr(), 2, 100) };
        if ret < 0 {
            let e = io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            break;
        }

        // Forward master output → CHANNEL_STDOUT.
        if !master_done && (fds[1].revents & (libc::POLLIN | libc::POLLHUP) != 0) {
            master_done = !drain_pipe_to_conn(master_fd, conn_fd, protocol::CHANNEL_STDOUT);
            if master_done {
                fds[1].fd = -1;
            }
        }

        // Read from connection (stdin data or control).
        if fds[0].revents & libc::POLLIN != 0 {
            match protocol::read_frame(&mut FdStream(conn_fd)) {
                Ok((ch, payload)) => {
                    if ch == protocol::CHANNEL_STDIN && !payload.is_empty() {
                        let _ = write_all_fd(master_fd, &payload);
                    }
                    // Ignore empty stdin frames in TTY mode (Ctrl-D
                    // is handled by the PTY line discipline).
                    if ch == protocol::CHANNEL_CONTROL {
                        if let Ok(msg) = ControlMessage::parse(&payload) {
                            match msg {
                                ControlMessage::Resize { rows, cols } if rows > 0 && cols > 0 => {
                                    let ws = libc::winsize {
                                        ws_row: rows,
                                        ws_col: cols,
                                        ws_xpixel: 0,
                                        ws_ypixel: 0,
                                    };
                                    // SAFETY: master_fd is a valid PTY.
                                    unsafe { libc::ioctl(master_fd, libc::TIOCSWINSZ, &ws) };
                                }
                                ControlMessage::Shutdown => {
                                    unsafe { libc::kill(1, libc::SIGKILL) };
                                    return 137;
                                }
                                _ => {}
                            }
                        }
                    }
                }
                Err(_) => {
                    unsafe { libc::kill(child_pid, libc::SIGKILL) };
                    break;
                }
            }
        }

        if fds[0].revents & (libc::POLLHUP | libc::POLLERR) != 0 {
            unsafe { libc::kill(child_pid, libc::SIGKILL) };
            break;
        }

        // Check child status.
        if !child_exited {
            let ret = unsafe { libc::waitpid(child_pid, &mut wstatus, libc::WNOHANG) };
            if ret > 0 {
                child_exited = true;
                grace_deadline =
                    Some(std::time::Instant::now() + std::time::Duration::from_secs(5));
            }
        }

        // After child exit: drain remaining master output, then return.
        // Grace period handles background jobs holding the slave open.
        if child_exited {
            if master_done {
                return exit_code_from_wstatus(wstatus);
            }
            if let Some(deadline) = grace_deadline {
                if std::time::Instant::now() >= deadline {
                    return exit_code_from_wstatus(wstatus);
                }
            }
        }
    }

    if !child_exited {
        unsafe { libc::waitpid(child_pid, &mut wstatus, 0) };
    }
    exit_code_from_wstatus(wstatus)
}

/// Drain available data from a non-blocking pipe and write as framed
/// data to the connection. Returns false when the pipe is at EOF.
fn drain_pipe_to_conn(pipe_fd: RawFd, conn_fd: RawFd, channel: u8) -> bool {
    let mut buf = [0u8; 65536];
    loop {
        // SAFETY: pipe_fd is valid, buf is stack-local.
        let n = unsafe { libc::read(pipe_fd, buf.as_mut_ptr().cast::<libc::c_void>(), buf.len()) };
        if n > 0 {
            let data = &buf[..n as usize];
            let mut stream = FdStream(conn_fd);
            if protocol::write_frame(&mut stream, channel, data).is_err() {
                return false;
            }
        } else if n == 0 {
            return false; // EOF
        } else {
            let e = io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::EAGAIN) || e.raw_os_error() == Some(libc::EWOULDBLOCK)
            {
                return true; // No more data right now
            }
            return false; // Error
        }
    }
}

fn write_all_fd(fd: RawFd, data: &[u8]) -> io::Result<()> {
    let mut written = 0;
    while written < data.len() {
        // SAFETY: fd is valid, data slice is valid.
        let n = unsafe {
            libc::write(
                fd,
                data[written..].as_ptr().cast::<libc::c_void>(),
                data.len() - written,
            )
        };
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(e);
        }
        written += n as usize;
    }
    Ok(())
}

fn exit_code_from_wstatus(wstatus: i32) -> i32 {
    if libc::WIFEXITED(wstatus) {
        libc::WEXITSTATUS(wstatus)
    } else if libc::WIFSIGNALED(wstatus) {
        128 + libc::WTERMSIG(wstatus)
    } else {
        1
    }
}

// ─── FD stream adapter ───────────────────────────────────────

/// Non-owning Read/Write wrapper around a raw file descriptor.
struct FdStream(RawFd);

impl Read for FdStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // SAFETY: self.0 is a valid fd, buf is a valid mutable slice.
        let n = unsafe { libc::read(self.0, buf.as_mut_ptr().cast::<libc::c_void>(), buf.len()) };
        if n < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(n as usize)
        }
    }
}

impl Write for FdStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // SAFETY: self.0 is a valid fd, buf is a valid slice.
        let n = unsafe { libc::write(self.0, buf.as_ptr().cast::<libc::c_void>(), buf.len()) };
        if n < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(n as usize)
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
