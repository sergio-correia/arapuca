//! Host-side exec client for persistent VMs.
//!
//! Connects to the agent's Unix socket, authenticates with the nonce,
//! sends an EXEC request, and forwards stdin/stdout/stderr using
//! poll(2)-based multiplexing.

use std::io::{self, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use super::protocol::{self, ControlMessage, ExecRequest, NONCE_SIZE};

/// Execute a command in a running VM.
///
/// Connects to the agent socket, authenticates, sends the command,
/// and forwards I/O until the command exits. Returns the exit code
/// reported by the agent.
pub fn exec(
    sock_path: &Path,
    nonce: &[u8; NONCE_SIZE],
    cmd: &str,
    args: &[String],
    env: &[String],
    user: &str,
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

    let req = ExecRequest {
        cmd: cmd.to_string(),
        args: args.to_vec(),
        env: env.to_vec(),
        user: user.to_string(),
    };
    protocol::write_control(&mut stream, &ControlMessage::Exec(req))?;

    stream.set_read_timeout(None)?;

    forward_io(&mut stream)
}

/// Forward stdin/stdout/stderr between the local terminal and the
/// agent connection until a STATUS message is received.
fn forward_io(stream: &mut UnixStream) -> io::Result<i32> {
    use std::os::fd::AsRawFd;

    let conn_fd = stream.as_raw_fd();
    let stdin_fd: i32 = 0;

    // Save and restore stdin flags to avoid leaving the terminal
    // in non-blocking mode after exec returns.
    // SAFETY: F_GETFL/F_SETFL on stdin fd.
    let saved_flags = unsafe { libc::fcntl(stdin_fd, libc::F_GETFL) };
    unsafe { libc::fcntl(stdin_fd, libc::F_SETFL, saved_flags | libc::O_NONBLOCK) };

    let result = forward_io_inner(stream, conn_fd, stdin_fd);

    // Restore original stdin flags.
    if saved_flags >= 0 {
        unsafe { libc::fcntl(stdin_fd, libc::F_SETFL, saved_flags) };
    }

    result
}

fn forward_io_inner(stream: &mut UnixStream, conn_fd: i32, stdin_fd: i32) -> io::Result<i32> {
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
            } else if n == 0 {
                protocol::write_frame(stream, protocol::CHANNEL_STDIN, &[])?;
                stdin_closed = true;
                fds[1].fd = -1;
            }
            // n < 0 with EAGAIN is normal for non-blocking reads.
        }

        if !stdin_closed && (fds[1].revents & libc::POLLHUP != 0) {
            protocol::write_frame(stream, protocol::CHANNEL_STDIN, &[])?;
            stdin_closed = true;
            fds[1].fd = -1;
        }
    }
}
