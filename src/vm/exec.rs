//! Host-side exec client for persistent VMs.
//!
//! Connects to the agent's Unix socket, authenticates with the nonce,
//! sends an EXEC request, and forwards stdin/stdout/stderr using
//! poll(2)-based multiplexing. In TTY mode, puts the terminal into
//! raw mode and forwards SIGWINCH as RESIZE control messages.

use std::io::{self, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::time::Duration;

use super::protocol::{self, ControlMessage, ExecRequest, NONCE_SIZE};

/// Execute a command in a running VM.
pub fn exec(
    sock_path: &Path,
    nonce: &[u8; NONCE_SIZE],
    cmd: &str,
    args: &[String],
    env: &[String],
    user: &str,
    tty: bool,
) -> io::Result<i32> {
    let mut stream = UnixStream::connect(sock_path)
        .map_err(|e| io::Error::new(e.kind(), format!("cannot connect to agent: {e}")))?;
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;

    protocol::write_nonce(&mut stream, nonce)?;

    match protocol::read_control(&mut stream) {
        Ok(ControlMessage::Hello { .. }) => {}
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unexpected response from agent (expected HELLO)",
            ));
        }
        Err(e) => {
            return Err(io::Error::new(
                e.kind(),
                format!("agent handshake failed: {e}"),
            ));
        }
    }

    let (rows, cols) = if tty { get_terminal_size() } else { (0, 0) };

    let req = ExecRequest {
        cmd: cmd.to_string(),
        args: args.to_vec(),
        env: env.to_vec(),
        user: user.to_string(),
        tty,
        rows,
        cols,
    };
    protocol::write_control(&mut stream, &ControlMessage::Exec(req))?;

    stream.set_read_timeout(None)?;

    forward_io(&mut stream, tty)
}

fn forward_io(stream: &mut UnixStream, tty: bool) -> io::Result<i32> {
    use std::os::fd::AsRawFd;

    let conn_fd = stream.as_raw_fd();
    let stdin_fd: i32 = 0;

    // SAFETY: F_GETFL on stdin.
    let saved_flags = unsafe { libc::fcntl(stdin_fd, libc::F_GETFL) };
    unsafe { libc::fcntl(stdin_fd, libc::F_SETFL, saved_flags | libc::O_NONBLOCK) };

    // Enter raw mode for TTY sessions.
    let _raw_guard = if tty {
        Some(RawModeGuard::enter(stdin_fd)?)
    } else {
        None
    };

    if tty {
        install_sigwinch_handler();
    }

    let result = forward_io_inner(stream, conn_fd, stdin_fd, tty);

    // RawModeGuard::drop restores terminal state.
    if saved_flags >= 0 {
        // SAFETY: restoring saved flags.
        unsafe { libc::fcntl(stdin_fd, libc::F_SETFL, saved_flags) };
    }

    result
}

fn forward_io_inner(
    stream: &mut UnixStream,
    conn_fd: i32,
    stdin_fd: i32,
    tty: bool,
) -> io::Result<i32> {
    let mut fds = [
        libc::pollfd {
            fd: conn_fd,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: stdin_fd,
            events: libc::POLLIN,
            revents: 0,
        },
    ];

    let mut stdin_closed = false;
    let mut buf = [0u8; 65536];

    loop {
        // SAFETY: poll with valid pollfd array.
        let ret = unsafe { libc::poll(fds.as_mut_ptr(), 2, 100) };
        if ret < 0 {
            let e = io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(e);
        }

        // Check for SIGWINCH (TTY mode only).
        if tty && SIGWINCH_RECEIVED.swap(false, Ordering::AcqRel) {
            let (rows, cols) = get_terminal_size();
            if rows > 0 && cols > 0 {
                let _ = protocol::write_control(stream, &ControlMessage::Resize { rows, cols });
            }
        }

        // Read from agent (stdout/stderr data or STATUS control).
        if fds[0].revents & libc::POLLIN != 0 {
            let (channel, payload) = protocol::read_frame(stream)?;
            match channel {
                protocol::CHANNEL_STDOUT => {
                    let stdout = io::stdout();
                    let mut out = stdout.lock();
                    out.write_all(&payload)?;
                    out.flush()?;
                }
                protocol::CHANNEL_STDERR => {
                    let stderr = io::stderr();
                    let mut err = stderr.lock();
                    err.write_all(&payload)?;
                    err.flush()?;
                }
                protocol::CHANNEL_CONTROL => {
                    let msg = ControlMessage::parse(&payload)?;
                    if let ControlMessage::Status { exit_code } = msg {
                        return Ok(exit_code);
                    }
                }
                _ => {}
            }
        }

        if fds[0].revents & (libc::POLLHUP | libc::POLLERR) != 0 {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "agent connection closed",
            ));
        }

        // Forward local stdin to agent.
        if !stdin_closed && (fds[1].revents & libc::POLLIN != 0) {
            // SAFETY: stdin_fd is valid, buf is stack-local.
            let n =
                unsafe { libc::read(stdin_fd, buf.as_mut_ptr().cast::<libc::c_void>(), buf.len()) };
            if n > 0 {
                protocol::write_frame(stream, protocol::CHANNEL_STDIN, &buf[..n as usize])?;
            } else if n == 0 && !tty {
                protocol::write_frame(stream, protocol::CHANNEL_STDIN, &[])?;
                stdin_closed = true;
                fds[1].fd = -1;
            }
        }

        if !stdin_closed && !tty && (fds[1].revents & libc::POLLHUP != 0) {
            protocol::write_frame(stream, protocol::CHANNEL_STDIN, &[])?;
            stdin_closed = true;
            fds[1].fd = -1;
        }
    }
}

// ─── Terminal helpers ─────────────────────────────────────────

fn get_terminal_size() -> (u16, u16) {
    let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
    // SAFETY: TIOCGWINSZ on stdin.
    let ret = unsafe { libc::ioctl(0, libc::TIOCGWINSZ, &mut ws) };
    if ret == 0 && ws.ws_row > 0 && ws.ws_col > 0 {
        (ws.ws_row, ws.ws_col)
    } else {
        (24, 80)
    }
}

// ─── Raw mode guard ───────────────────────────────────────────

// SAFETY: CLEANUP_TERMIOS is written once (before signal handler
// install) and read only from the signal handler (after the write).
// libc::termios is a plain C struct (Copy, no pointers). Access
// uses addr_of_mut! to avoid creating references to static mut
// (Rust 2024 edition compliance).
static mut CLEANUP_TERMIOS: libc::termios = unsafe { std::mem::zeroed() };
static CLEANUP_FD: AtomicI32 = AtomicI32::new(-1);

struct RawModeGuard {
    fd: i32,
    saved: libc::termios,
}

impl RawModeGuard {
    fn enter(fd: i32) -> io::Result<Self> {
        let mut saved: libc::termios = unsafe { std::mem::zeroed() };
        // SAFETY: tcgetattr on a valid fd.
        if unsafe { libc::tcgetattr(fd, &mut saved) } != 0 {
            return Err(io::Error::last_os_error());
        }

        // Store for signal handler cleanup (before handler install).
        // SAFETY: single-threaded at this point, written before
        // signal handlers are installed.
        unsafe { std::ptr::addr_of_mut!(CLEANUP_TERMIOS).write(saved) };
        CLEANUP_FD.store(fd, Ordering::Release);

        install_cleanup_signal_handlers();

        let mut raw = saved;
        // SAFETY: cfmakeraw modifies the termios struct in place.
        unsafe { libc::cfmakeraw(&mut raw) };
        // SAFETY: tcsetattr on a valid fd.
        if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &raw) } != 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(Self { fd, saved })
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        // SAFETY: restoring saved termios.
        unsafe { libc::tcsetattr(self.fd, libc::TCSANOW, &self.saved) };
        CLEANUP_FD.store(-1, Ordering::Release);
    }
}

fn install_cleanup_signal_handlers() {
    extern "C" fn cleanup_handler(sig: libc::c_int) {
        let fd = CLEANUP_FD.load(Ordering::Acquire);
        if fd >= 0 {
            // SAFETY: tcsetattr is async-signal-safe per POSIX.
            // CLEANUP_TERMIOS was written before this handler was
            // installed; the sigaction call provides a memory barrier.
            unsafe {
                libc::tcsetattr(fd, libc::TCSANOW, std::ptr::addr_of!(CLEANUP_TERMIOS));
            }
        }
        // Re-raise with default disposition for correct exit status.
        // SAFETY: signal + raise are async-signal-safe.
        unsafe {
            libc::signal(sig, libc::SIG_DFL);
            libc::raise(sig);
        }
    }

    // SAFETY: handler is async-signal-safe (tcsetattr, signal, raise).
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = cleanup_handler as *const () as usize;
        sa.sa_flags = 0;
        libc::sigaction(libc::SIGINT, &sa, std::ptr::null_mut());
        libc::sigaction(libc::SIGTERM, &sa, std::ptr::null_mut());
        libc::sigaction(libc::SIGQUIT, &sa, std::ptr::null_mut());
    }
}

// ─── SIGWINCH ─────────────────────────────────────────────────

static SIGWINCH_RECEIVED: AtomicBool = AtomicBool::new(false);

fn install_sigwinch_handler() {
    extern "C" fn handler(_sig: libc::c_int) {
        SIGWINCH_RECEIVED.store(true, Ordering::Release);
    }
    // SAFETY: handler only sets an AtomicBool — async-signal-safe.
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = handler as *const () as usize;
        sa.sa_flags = 0;
        libc::sigaction(libc::SIGWINCH, &sa, std::ptr::null_mut());
    }
}
