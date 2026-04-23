//! Network namespace proxy bridge.
//!
//! Provides loopback bring-up via raw netlink and TCP-to-UDS relay
//! for bridging network access inside an isolated network namespace.
//! Linux-only.

use std::io;
use std::os::fd::{FromRawFd, OwnedFd};

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

    use std::os::fd::AsRawFd;

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

#[cfg(test)]
mod tests {
    use super::*;

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
}
