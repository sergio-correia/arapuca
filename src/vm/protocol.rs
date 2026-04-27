//! Binary framing protocol for host↔guest communication via vsock.
//!
//! All messages use length-prefixed frames:
//! ```text
//! [channel: u8] [length: u32 BE] [payload: [u8; length]]
//! ```
//!
//! Channels: 0=stdin, 1=stdout, 2=stderr, 3=control.
//! Control messages use a line-oriented text format within frames.

use std::io::{self, Read, Write};

// ─── Constants ────────────────────────────────────────────────

/// Stdin channel (host → guest).
pub const CHANNEL_STDIN: u8 = 0;
/// Stdout channel (guest → host).
pub const CHANNEL_STDOUT: u8 = 1;
/// Stderr channel (guest → host).
pub const CHANNEL_STDERR: u8 = 2;
/// Control channel (bidirectional).
pub const CHANNEL_CONTROL: u8 = 3;

/// Frame header: 1 byte channel + 4 bytes length.
pub const FRAME_HEADER_SIZE: usize = 5;

/// Maximum control message payload (64 KiB).
pub const MAX_CONTROL_PAYLOAD: usize = 64 * 1024;
/// Maximum data frame payload (1 MiB).
pub const MAX_DATA_PAYLOAD: usize = 1024 * 1024;
/// Maximum EXEC JSON payload (64 KiB).
pub const MAX_EXEC_PAYLOAD: usize = 64 * 1024;

/// Protocol version sent in HELLO handshake.
pub const PROTOCOL_VERSION: &str = "arapuca-agent/1";
/// Nonce size for socket authentication (256-bit).
pub const NONCE_SIZE: usize = 32;
/// Default vsock port for the agent.
pub const AGENT_VSOCK_PORT: u32 = 1024;

/// Maximum concurrent connections per agent.
pub const MAX_CONNECTIONS: usize = 16;
/// Maximum concurrent exec sessions per agent.
pub const MAX_SESSIONS: usize = 32;
/// Maximum elements in a JSON string array (args, env).
pub const MAX_ARRAY_ELEMENTS: usize = 4096;
/// Idle connection timeout in seconds.
pub const IDLE_TIMEOUT_SECS: u64 = 30;

// ─── Frame I/O ────────────────────────────────────────────────

/// Write a framed message to `w`.
pub fn write_frame(w: &mut impl Write, channel: u8, payload: &[u8]) -> io::Result<()> {
    if channel > CHANNEL_CONTROL {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid channel: {channel}"),
        ));
    }
    let max = if channel == CHANNEL_CONTROL {
        MAX_CONTROL_PAYLOAD
    } else {
        MAX_DATA_PAYLOAD
    };
    if payload.len() > max {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("payload too large: {} > {max}", payload.len()),
        ));
    }
    let len = payload.len() as u32;
    let mut header = [0u8; FRAME_HEADER_SIZE];
    header[0] = channel;
    header[1..5].copy_from_slice(&len.to_be_bytes());
    w.write_all(&header)?;
    if !payload.is_empty() {
        w.write_all(payload)?;
    }
    Ok(())
}

/// Read a framed message from `r`.
pub fn read_frame(r: &mut impl Read) -> io::Result<(u8, Vec<u8>)> {
    let mut header = [0u8; FRAME_HEADER_SIZE];
    r.read_exact(&mut header)?;

    let channel = header[0];
    if channel > CHANNEL_CONTROL {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid channel: {channel}"),
        ));
    }

    let len = u32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize;
    let max = if channel == CHANNEL_CONTROL {
        MAX_CONTROL_PAYLOAD
    } else {
        MAX_DATA_PAYLOAD
    };
    if len > max {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("frame too large: {len} > {max}"),
        ));
    }

    let mut payload = vec![0u8; len];
    if len > 0 {
        r.read_exact(&mut payload)?;
    }
    Ok((channel, payload))
}

// ─── Nonce authentication ─────────────────────────────────────

/// Write a 256-bit nonce.
pub fn write_nonce(w: &mut impl Write, nonce: &[u8; NONCE_SIZE]) -> io::Result<()> {
    w.write_all(nonce)
}

/// Read a 256-bit nonce.
pub fn read_nonce(r: &mut impl Read) -> io::Result<[u8; NONCE_SIZE]> {
    let mut nonce = [0u8; NONCE_SIZE];
    r.read_exact(&mut nonce)?;
    Ok(nonce)
}

/// Constant-time comparison of two nonces.
pub fn nonce_eq(a: &[u8; NONCE_SIZE], b: &[u8; NONCE_SIZE]) -> bool {
    let mut diff = 0u8;
    for i in 0..NONCE_SIZE {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

// ─── Control messages ─────────────────────────────────────────

/// Control channel message.
#[derive(Debug, Clone, PartialEq)]
pub enum ControlMessage {
    /// Agent → host: protocol handshake.
    Hello { version: String },
    /// Host → agent: execute a command.
    Exec(ExecRequest),
    /// Agent → host: command exited.
    Status { exit_code: i32 },
    /// Host → agent: initiate graceful shutdown.
    Shutdown,
    /// Host → agent: readiness probe.
    Ping,
    /// Agent → host: readiness response.
    Pong,
    /// Host → agent: terminal window resize (TTY mode).
    Resize { rows: u16, cols: u16 },
}

/// Request to execute a command in the guest.
#[derive(Debug, Clone, PartialEq)]
pub struct ExecRequest {
    pub cmd: String,
    pub args: Vec<String>,
    pub env: Vec<String>,
    pub user: String,
    pub tty: bool,
    pub rows: u16,
    pub cols: u16,
}

impl ControlMessage {
    /// Serialize to wire format (text, newline-terminated).
    pub fn serialize(&self) -> Vec<u8> {
        match self {
            Self::Hello { version } => format!("HELLO {version}\n").into_bytes(),
            Self::Exec(req) => {
                let json = req.to_json();
                let mut buf = Vec::with_capacity(5 + json.len() + 1);
                buf.extend_from_slice(b"EXEC ");
                buf.extend_from_slice(json.as_bytes());
                buf.push(b'\n');
                buf
            }
            Self::Status { exit_code } => format!("STATUS {exit_code}\n").into_bytes(),
            Self::Shutdown => b"SHUTDOWN\n".to_vec(),
            Self::Ping => b"PING\n".to_vec(),
            Self::Pong => b"PONG\n".to_vec(),
            Self::Resize { rows, cols } => format!("RESIZE {rows} {cols}\n").into_bytes(),
        }
    }

    /// Parse from wire format.
    pub fn parse(payload: &[u8]) -> io::Result<Self> {
        let text = std::str::from_utf8(payload).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid UTF-8 in control message",
            )
        })?;
        let text = text.trim_end_matches('\n');

        if let Some(version) = text.strip_prefix("HELLO ") {
            Ok(Self::Hello {
                version: version.to_string(),
            })
        } else if let Some(json) = text.strip_prefix("EXEC ") {
            if json.len() > MAX_EXEC_PAYLOAD {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "EXEC payload exceeds 64 KiB limit",
                ));
            }
            Ok(Self::Exec(ExecRequest::from_json(json)?))
        } else if let Some(code_str) = text.strip_prefix("STATUS ") {
            let exit_code: i32 = code_str.parse().map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid STATUS exit code")
            })?;
            Ok(Self::Status { exit_code })
        } else if text == "SHUTDOWN" {
            Ok(Self::Shutdown)
        } else if text == "PING" {
            Ok(Self::Ping)
        } else if text == "PONG" {
            Ok(Self::Pong)
        } else if let Some(dims) = text.strip_prefix("RESIZE ") {
            let (rows_str, cols_str) = dims.split_once(' ').ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "RESIZE requires <rows> <cols>")
            })?;
            let rows: u16 = rows_str
                .parse()
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid RESIZE rows"))?;
            let cols: u16 = cols_str
                .parse()
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid RESIZE cols"))?;
            Ok(Self::Resize { rows, cols })
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unknown control message",
            ))
        }
    }
}

/// Write a control message as a framed message.
pub fn write_control(w: &mut impl Write, msg: &ControlMessage) -> io::Result<()> {
    let payload = msg.serialize();
    write_frame(w, CHANNEL_CONTROL, &payload)
}

/// Read a control message from a framed stream.
///
/// Returns an error if the next frame is not on the control channel.
pub fn read_control(r: &mut impl Read) -> io::Result<ControlMessage> {
    let (channel, payload) = read_frame(r)?;
    if channel != CHANNEL_CONTROL {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("expected control channel, got channel {channel}"),
        ));
    }
    ControlMessage::parse(&payload)
}

// ─── JSON serialization ──────────────────────────────────────

impl ExecRequest {
    fn to_json(&self) -> String {
        let mut out = String::with_capacity(128);
        out.push('{');
        out.push_str("\"cmd\":");
        json_encode_string(&self.cmd, &mut out);
        out.push_str(",\"args\":");
        json_encode_string_array(&self.args, &mut out);
        out.push_str(",\"env\":");
        json_encode_string_array(&self.env, &mut out);
        out.push_str(",\"user\":");
        json_encode_string(&self.user, &mut out);
        if self.tty {
            out.push_str(",\"tty\":true");
            if self.rows > 0 && self.cols > 0 {
                out.push_str(&format!(",\"rows\":{},\"cols\":{}", self.rows, self.cols));
            }
        }
        out.push('}');
        out
    }

    fn from_json(json: &str) -> io::Result<Self> {
        let mut p = JsonParser::new(json);
        p.skip_ws();
        p.expect_byte(b'{')?;

        let mut cmd = None;
        let mut args = None;
        let mut env = None;
        let mut user = None;
        let mut tty = None;
        let mut rows = None;
        let mut cols = None;
        let mut first = true;

        loop {
            p.skip_ws();
            if p.peek() == Some(b'}') {
                p.advance();
                break;
            }
            if !first {
                p.expect_byte(b',')?;
            }
            first = false;

            p.skip_ws();
            let key = p.parse_string()?;
            p.skip_ws();
            p.expect_byte(b':')?;
            p.skip_ws();

            match key.as_str() {
                "cmd" if cmd.is_none() => cmd = Some(p.parse_string()?),
                "args" if args.is_none() => args = Some(p.parse_string_array()?),
                "env" if env.is_none() => env = Some(p.parse_string_array()?),
                "user" if user.is_none() => user = Some(p.parse_string()?),
                "tty" if tty.is_none() => tty = Some(p.parse_bool()?),
                "rows" if rows.is_none() => rows = Some(p.parse_u16()?),
                "cols" if cols.is_none() => cols = Some(p.parse_u16()?),
                "cmd" | "args" | "env" | "user" | "tty" | "rows" | "cols" => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("duplicate field in EXEC: {key}"),
                    ));
                }
                _ => p.skip_value()?,
            }
        }

        Ok(Self {
            cmd: cmd.ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "missing 'cmd' in EXEC")
            })?,
            args: args.unwrap_or_default(),
            env: env.unwrap_or_default(),
            user: user.unwrap_or_else(|| "root".to_string()),
            tty: tty.unwrap_or(false),
            rows: rows.unwrap_or(0),
            cols: cols.unwrap_or(0),
        })
    }
}

pub(crate) fn json_encode_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = std::fmt::Write::write_fmt(out, format_args!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn json_encode_string_array(arr: &[String], out: &mut String) {
    out.push('[');
    for (i, s) in arr.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        json_encode_string(s, out);
    }
    out.push(']');
}

// ─── JSON parser ──────────────────────────────────────────────

pub(crate) struct JsonParser<'a> {
    input: &'a str,
    pos: usize,
}

impl<'a> JsonParser<'a> {
    pub(crate) fn new(input: &'a str) -> Self {
        Self { input, pos: 0 }
    }

    pub(crate) fn peek(&self) -> Option<u8> {
        self.input.as_bytes().get(self.pos).copied()
    }

    pub(crate) fn advance(&mut self) {
        self.pos += 1;
    }

    pub(crate) fn skip_ws(&mut self) {
        let bytes = self.input.as_bytes();
        while self.pos < bytes.len() && bytes[self.pos].is_ascii_whitespace() {
            self.pos += 1;
        }
    }

    pub(crate) fn expect_byte(&mut self, expected: u8) -> io::Result<()> {
        match self.peek() {
            Some(c) if c == expected => {
                self.advance();
                Ok(())
            }
            Some(c) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("expected '{}', got '{}'", expected as char, c as char),
            )),
            None => Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!("expected '{}'", expected as char),
            )),
        }
    }

    pub(crate) fn parse_string(&mut self) -> io::Result<String> {
        self.expect_byte(b'"')?;
        let mut s = String::new();
        let bytes = self.input.as_bytes();

        loop {
            if self.pos >= bytes.len() {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "unterminated string",
                ));
            }
            match bytes[self.pos] {
                b'"' => {
                    self.pos += 1;
                    return Ok(s);
                }
                b'\\' => {
                    self.pos += 1;
                    if self.pos >= bytes.len() {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "unterminated escape",
                        ));
                    }
                    match bytes[self.pos] {
                        b'"' => {
                            s.push('"');
                            self.pos += 1;
                        }
                        b'\\' => {
                            s.push('\\');
                            self.pos += 1;
                        }
                        b'/' => {
                            s.push('/');
                            self.pos += 1;
                        }
                        b'n' => {
                            s.push('\n');
                            self.pos += 1;
                        }
                        b'r' => {
                            s.push('\r');
                            self.pos += 1;
                        }
                        b't' => {
                            s.push('\t');
                            self.pos += 1;
                        }
                        b'b' => {
                            s.push('\u{08}');
                            self.pos += 1;
                        }
                        b'f' => {
                            s.push('\u{0C}');
                            self.pos += 1;
                        }
                        b'u' => {
                            self.pos += 1;
                            if self.pos + 4 > bytes.len() {
                                return Err(io::Error::new(
                                    io::ErrorKind::UnexpectedEof,
                                    "truncated \\u escape",
                                ));
                            }
                            let hex = &self.input[self.pos..self.pos + 4];
                            self.pos += 4;
                            let code = u32::from_str_radix(hex, 16).map_err(|_| {
                                io::Error::new(io::ErrorKind::InvalidData, "invalid \\u hex")
                            })?;
                            let c = char::from_u32(code).ok_or_else(|| {
                                io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    "invalid unicode codepoint",
                                )
                            })?;
                            s.push(c);
                        }
                        c => {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                format!("invalid escape: \\{}", c as char),
                            ));
                        }
                    }
                }
                c if c < 0x80 => {
                    s.push(c as char);
                    self.pos += 1;
                }
                _ => {
                    // Multi-byte UTF-8: extract the full character.
                    let ch = self.input[self.pos..].chars().next().ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidData, "invalid UTF-8 in string")
                    })?;
                    s.push(ch);
                    self.pos += ch.len_utf8();
                }
            }
        }
    }

    fn parse_string_array(&mut self) -> io::Result<Vec<String>> {
        self.expect_byte(b'[')?;
        let mut arr = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.advance();
            return Ok(arr);
        }
        loop {
            if arr.len() >= MAX_ARRAY_ELEMENTS {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "array exceeds element limit",
                ));
            }
            self.skip_ws();
            arr.push(self.parse_string()?);
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.advance(),
                Some(b']') => {
                    self.advance();
                    return Ok(arr);
                }
                Some(c) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("expected ',' or ']', got '{}'", c as char),
                    ));
                }
                None => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "unterminated array",
                    ));
                }
            }
        }
    }

    /// Parse a JSON number (unsigned integer).
    pub(crate) fn parse_u64(&mut self) -> io::Result<u64> {
        let bytes = self.input.as_bytes();
        let start = self.pos;
        while self.pos < bytes.len() && bytes[self.pos].is_ascii_digit() {
            self.pos += 1;
        }
        if self.pos == start {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "expected number",
            ));
        }
        self.input[start..self.pos]
            .parse()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid number"))
    }

    /// Parse a JSON number as u16 (rejects values > 65535).
    pub(crate) fn parse_u16(&mut self) -> io::Result<u16> {
        let val = self.parse_u64()?;
        u16::try_from(val)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "number exceeds u16 range"))
    }

    /// Parse a JSON boolean.
    pub(crate) fn parse_bool(&mut self) -> io::Result<bool> {
        if self.input[self.pos..].starts_with("true") {
            self.pos += 4;
            Ok(true)
        } else if self.input[self.pos..].starts_with("false") {
            self.pos += 5;
            Ok(false)
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "expected boolean",
            ))
        }
    }

    /// Skip a JSON value (string, number, boolean, array, or object).
    pub(crate) fn skip_value(&mut self) -> io::Result<()> {
        match self.peek() {
            Some(b'"') => {
                self.parse_string()?;
            }
            Some(b'[') => {
                self.advance();
                self.skip_ws();
                if self.peek() != Some(b']') {
                    loop {
                        self.skip_ws();
                        self.skip_value()?;
                        self.skip_ws();
                        match self.peek() {
                            Some(b',') => self.advance(),
                            Some(b']') => break,
                            _ => {
                                return Err(io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    "expected ',' or ']'",
                                ));
                            }
                        }
                    }
                }
                self.advance(); // ']'
            }
            Some(b'{') => {
                self.advance();
                self.skip_ws();
                if self.peek() != Some(b'}') {
                    loop {
                        self.skip_ws();
                        self.parse_string()?; // key
                        self.skip_ws();
                        self.expect_byte(b':')?;
                        self.skip_ws();
                        self.skip_value()?;
                        self.skip_ws();
                        match self.peek() {
                            Some(b',') => self.advance(),
                            Some(b'}') => break,
                            _ => {
                                return Err(io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    "expected ',' or '}'",
                                ));
                            }
                        }
                    }
                }
                self.advance(); // '}'
            }
            Some(b) if b == b't' || b == b'f' => {
                self.parse_bool()?;
            }
            Some(b) if b.is_ascii_digit() => {
                self.parse_u64()?;
            }
            Some(b'n') if self.input[self.pos..].starts_with("null") => {
                self.pos += 4;
            }
            _ => {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "expected value"));
            }
        }
        Ok(())
    }
}

// ─── Tests ────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    // ── Frame round-trips ─────────────────────────────────────

    #[test]
    fn frame_roundtrip_stdin() {
        let data = b"hello world";
        let mut buf = Vec::new();
        write_frame(&mut buf, CHANNEL_STDIN, data).unwrap();
        let (ch, payload) = read_frame(&mut Cursor::new(&buf)).unwrap();
        assert_eq!(ch, CHANNEL_STDIN);
        assert_eq!(payload, data);
    }

    #[test]
    fn frame_roundtrip_stdout() {
        let data = b"output data";
        let mut buf = Vec::new();
        write_frame(&mut buf, CHANNEL_STDOUT, data).unwrap();
        let (ch, payload) = read_frame(&mut Cursor::new(&buf)).unwrap();
        assert_eq!(ch, CHANNEL_STDOUT);
        assert_eq!(payload, data);
    }

    #[test]
    fn frame_roundtrip_stderr() {
        let data = b"error message";
        let mut buf = Vec::new();
        write_frame(&mut buf, CHANNEL_STDERR, data).unwrap();
        let (ch, payload) = read_frame(&mut Cursor::new(&buf)).unwrap();
        assert_eq!(ch, CHANNEL_STDERR);
        assert_eq!(payload, data);
    }

    #[test]
    fn frame_roundtrip_control() {
        let data = b"PING\n";
        let mut buf = Vec::new();
        write_frame(&mut buf, CHANNEL_CONTROL, data).unwrap();
        let (ch, payload) = read_frame(&mut Cursor::new(&buf)).unwrap();
        assert_eq!(ch, CHANNEL_CONTROL);
        assert_eq!(payload, data);
    }

    #[test]
    fn frame_empty_payload() {
        let mut buf = Vec::new();
        write_frame(&mut buf, CHANNEL_STDOUT, b"").unwrap();
        let (ch, payload) = read_frame(&mut Cursor::new(&buf)).unwrap();
        assert_eq!(ch, CHANNEL_STDOUT);
        assert!(payload.is_empty());
    }

    #[test]
    fn frame_write_rejects_invalid_channel() {
        let mut buf = Vec::new();
        let err = write_frame(&mut buf, 4, b"data").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn frame_read_rejects_invalid_channel() {
        let mut buf = vec![5u8, 0, 0, 0, 1, 0x41];
        let err = read_frame(&mut Cursor::new(&mut buf)).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn frame_write_rejects_oversized_control() {
        let data = vec![0u8; MAX_CONTROL_PAYLOAD + 1];
        let mut buf = Vec::new();
        let err = write_frame(&mut buf, CHANNEL_CONTROL, &data).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn frame_write_rejects_oversized_data() {
        let data = vec![0u8; MAX_DATA_PAYLOAD + 1];
        let mut buf = Vec::new();
        let err = write_frame(&mut buf, CHANNEL_STDOUT, &data).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn frame_read_rejects_oversized() {
        // Forge a header claiming a control frame larger than MAX_CONTROL_PAYLOAD.
        let len = (MAX_CONTROL_PAYLOAD as u32) + 1;
        let mut buf = vec![CHANNEL_CONTROL];
        buf.extend_from_slice(&len.to_be_bytes());
        let err = read_frame(&mut Cursor::new(&buf)).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn frame_write_max_control_payload() {
        let data = vec![0x42u8; MAX_CONTROL_PAYLOAD];
        let mut buf = Vec::new();
        write_frame(&mut buf, CHANNEL_CONTROL, &data).unwrap();
        let (ch, payload) = read_frame(&mut Cursor::new(&buf)).unwrap();
        assert_eq!(ch, CHANNEL_CONTROL);
        assert_eq!(payload.len(), MAX_CONTROL_PAYLOAD);
    }

    #[test]
    fn frame_header_format() {
        let mut buf = Vec::new();
        write_frame(&mut buf, CHANNEL_STDERR, &[1, 2, 3]).unwrap();
        assert_eq!(buf[0], CHANNEL_STDERR);
        assert_eq!(&buf[1..5], &[0, 0, 0, 3]); // big-endian length
        assert_eq!(&buf[5..], &[1, 2, 3]);
    }

    #[test]
    fn frame_multiple_sequential() {
        let mut buf = Vec::new();
        write_frame(&mut buf, CHANNEL_STDOUT, b"first").unwrap();
        write_frame(&mut buf, CHANNEL_STDERR, b"second").unwrap();
        write_frame(&mut buf, CHANNEL_CONTROL, b"PONG\n").unwrap();

        let mut cursor = Cursor::new(&buf);
        let (ch1, p1) = read_frame(&mut cursor).unwrap();
        let (ch2, p2) = read_frame(&mut cursor).unwrap();
        let (ch3, p3) = read_frame(&mut cursor).unwrap();

        assert_eq!((ch1, &p1[..]), (CHANNEL_STDOUT, &b"first"[..]));
        assert_eq!((ch2, &p2[..]), (CHANNEL_STDERR, &b"second"[..]));
        assert_eq!((ch3, &p3[..]), (CHANNEL_CONTROL, &b"PONG\n"[..]));
    }

    // ── Nonce ─────────────────────────────────────────────────

    #[test]
    fn nonce_roundtrip() {
        let nonce = [0xABu8; NONCE_SIZE];
        let mut buf = Vec::new();
        write_nonce(&mut buf, &nonce).unwrap();
        assert_eq!(buf.len(), NONCE_SIZE);
        let read_back = read_nonce(&mut Cursor::new(&buf)).unwrap();
        assert_eq!(read_back, nonce);
    }

    #[test]
    fn nonce_eq_matching() {
        let a = [0x42u8; NONCE_SIZE];
        let b = [0x42u8; NONCE_SIZE];
        assert!(nonce_eq(&a, &b));
    }

    #[test]
    fn nonce_eq_different() {
        let a = [0x42u8; NONCE_SIZE];
        let mut b = [0x42u8; NONCE_SIZE];
        b[31] = 0x43;
        assert!(!nonce_eq(&a, &b));
    }

    #[test]
    fn nonce_eq_all_zeros_vs_all_ones() {
        let a = [0x00u8; NONCE_SIZE];
        let b = [0xFFu8; NONCE_SIZE];
        assert!(!nonce_eq(&a, &b));
    }

    // ── Control messages ──────────────────────────────────────

    #[test]
    fn control_hello_roundtrip() {
        let msg = ControlMessage::Hello {
            version: PROTOCOL_VERSION.to_string(),
        };
        let serialized = msg.serialize();
        let parsed = ControlMessage::parse(&serialized).unwrap();
        assert_eq!(parsed, msg);
    }

    #[test]
    fn control_status_roundtrip() {
        for code in [0, 1, 127, -1, -15] {
            let msg = ControlMessage::Status { exit_code: code };
            let serialized = msg.serialize();
            let parsed = ControlMessage::parse(&serialized).unwrap();
            assert_eq!(parsed, msg);
        }
    }

    #[test]
    fn control_shutdown_roundtrip() {
        let msg = ControlMessage::Shutdown;
        let parsed = ControlMessage::parse(&msg.serialize()).unwrap();
        assert_eq!(parsed, msg);
    }

    #[test]
    fn control_ping_pong_roundtrip() {
        let ping = ControlMessage::Ping;
        let pong = ControlMessage::Pong;
        assert_eq!(ControlMessage::parse(&ping.serialize()).unwrap(), ping);
        assert_eq!(ControlMessage::parse(&pong.serialize()).unwrap(), pong);
    }

    #[test]
    fn control_resize_roundtrip() {
        let msg = ControlMessage::Resize { rows: 24, cols: 80 };
        let parsed = ControlMessage::parse(&msg.serialize()).unwrap();
        assert_eq!(parsed, msg);
    }

    #[test]
    fn control_exec_roundtrip() {
        let msg = ControlMessage::Exec(ExecRequest {
            cmd: "/bin/bash".to_string(),
            args: vec!["-l".to_string()],
            env: vec!["TERM=xterm".to_string(), "HOME=/root".to_string()],
            user: "root".to_string(),
            tty: false,
            rows: 0,
            cols: 0,
        });
        let serialized = msg.serialize();
        let parsed = ControlMessage::parse(&serialized).unwrap();
        assert_eq!(parsed, msg);
    }

    #[test]
    fn control_exec_empty_arrays() {
        let msg = ControlMessage::Exec(ExecRequest {
            cmd: "/usr/bin/id".to_string(),
            args: vec![],
            env: vec![],
            user: "nobody".to_string(),
            tty: false,
            rows: 0,
            cols: 0,
        });
        let parsed = ControlMessage::parse(&msg.serialize()).unwrap();
        assert_eq!(parsed, msg);
    }

    #[test]
    fn control_exec_special_chars() {
        let msg = ControlMessage::Exec(ExecRequest {
            cmd: "/bin/sh".to_string(),
            args: vec!["-c".to_string(), "echo \"hello\nworld\"".to_string()],
            env: vec!["MSG=it's a \"test\"".to_string()],
            user: "root".to_string(),
            tty: false,
            rows: 0,
            cols: 0,
        });
        let parsed = ControlMessage::parse(&msg.serialize()).unwrap();
        assert_eq!(parsed, msg);
    }

    #[test]
    fn control_exec_unicode() {
        let msg = ControlMessage::Exec(ExecRequest {
            cmd: "/bin/echo".to_string(),
            args: vec!["café".to_string(), "日本語".to_string()],
            env: vec![],
            user: "root".to_string(),
            tty: false,
            rows: 0,
            cols: 0,
        });
        let parsed = ControlMessage::parse(&msg.serialize()).unwrap();
        assert_eq!(parsed, msg);
    }

    #[test]
    fn control_exec_default_user() {
        let json = r#"{"cmd":"/bin/ls","args":[],"env":[]}"#;
        let req = ExecRequest::from_json(json).unwrap();
        assert_eq!(req.user, "root");
    }

    #[test]
    fn control_parse_unknown_message() {
        let err = ControlMessage::parse(b"UNKNOWN\n").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn control_parse_invalid_status() {
        let err = ControlMessage::parse(b"STATUS abc\n").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn control_parse_invalid_resize() {
        let err = ControlMessage::parse(b"RESIZE 24\n").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    // ── Framed control convenience ────────────────────────────

    #[test]
    fn write_read_control_roundtrip() {
        let msg = ControlMessage::Ping;
        let mut buf = Vec::new();
        write_control(&mut buf, &msg).unwrap();
        let parsed = read_control(&mut Cursor::new(&buf)).unwrap();
        assert_eq!(parsed, msg);
    }

    #[test]
    fn read_control_rejects_data_channel() {
        let mut buf = Vec::new();
        write_frame(&mut buf, CHANNEL_STDOUT, b"data").unwrap();
        let err = read_control(&mut Cursor::new(&buf)).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    // ── JSON encoding ─────────────────────────────────────────

    #[test]
    fn json_encode_simple_string() {
        let mut out = String::new();
        json_encode_string("hello", &mut out);
        assert_eq!(out, "\"hello\"");
    }

    #[test]
    fn json_encode_escapes() {
        let mut out = String::new();
        json_encode_string("a\"b\\c\nd\re\tf", &mut out);
        assert_eq!(out, r#""a\"b\\c\nd\re\tf""#);
    }

    #[test]
    fn json_encode_control_chars() {
        let mut out = String::new();
        json_encode_string("\x00\x1f", &mut out);
        assert_eq!(out, "\"\\u0000\\u001f\"");
    }

    #[test]
    fn json_roundtrip_backslash_in_path() {
        let req = ExecRequest {
            cmd: "/bin/echo".to_string(),
            args: vec!["C:\\Users\\test".to_string()],
            env: vec![],
            user: "root".to_string(),
            tty: false,
            rows: 0,
            cols: 0,
        };
        let json = req.to_json();
        let parsed = ExecRequest::from_json(&json).unwrap();
        assert_eq!(parsed, req);
    }

    #[test]
    fn json_parse_with_whitespace() {
        let json = r#"{ "cmd" : "/bin/ls" , "args" : [ "-la" ] , "env" : [ ] , "user" : "root" }"#;
        let req = ExecRequest::from_json(json).unwrap();
        assert_eq!(req.cmd, "/bin/ls");
        assert_eq!(req.args, vec!["-la"]);
        assert!(req.env.is_empty());
    }

    #[test]
    fn json_parse_unknown_field_skipped() {
        let json = r#"{"cmd":"/bin/ls","bogus":"val","args":[],"env":[]}"#;
        let req = ExecRequest::from_json(json).unwrap();
        assert_eq!(req.cmd, "/bin/ls");
    }

    #[test]
    fn json_parse_missing_cmd_rejected() {
        let json = r#"{"args":[],"env":[],"user":"root"}"#;
        let err = ExecRequest::from_json(json).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn json_parse_unicode_escape() {
        let json = r#"{"cmd":"/bin/echo","args":["AB"],"env":[],"user":"root"}"#;
        let req = ExecRequest::from_json(json).unwrap();
        assert_eq!(req.args, vec!["AB"]);
    }

    #[test]
    fn json_parse_backspace_formfeed_escapes() {
        let json = r#"{"cmd":"/bin/echo","args":["a\b\fc"],"env":[],"user":"root"}"#;
        let req = ExecRequest::from_json(json).unwrap();
        assert_eq!(req.args, vec!["a\u{08}\u{0C}c"]);
    }

    #[test]
    fn json_parse_duplicate_key_rejected() {
        let json = r#"{"cmd":"/bin/a","cmd":"/bin/b","args":[],"env":[],"user":"root"}"#;
        let err = ExecRequest::from_json(json).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn json_parse_duplicate_args_rejected() {
        let json = r#"{"cmd":"/bin/a","args":[],"args":[],"env":[],"user":"root"}"#;
        let err = ExecRequest::from_json(json).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    // ── TTY fields ────────────────────────────────────────────

    #[test]
    fn control_exec_tty_roundtrip() {
        let msg = ControlMessage::Exec(ExecRequest {
            cmd: "/bin/bash".to_string(),
            args: vec!["-l".to_string()],
            env: vec![],
            user: "root".to_string(),
            tty: true,
            rows: 24,
            cols: 80,
        });
        let parsed = ControlMessage::parse(&msg.serialize()).unwrap();
        assert_eq!(parsed, msg);
    }

    #[test]
    fn control_exec_tty_default_false() {
        let json = r#"{"cmd":"/bin/ls","args":[],"env":[]}"#;
        let req = ExecRequest::from_json(json).unwrap();
        assert!(!req.tty);
        assert_eq!(req.rows, 0);
        assert_eq!(req.cols, 0);
    }

    #[test]
    fn control_exec_tty_zero_dimensions() {
        let msg = ControlMessage::Exec(ExecRequest {
            cmd: "/bin/bash".to_string(),
            args: vec![],
            env: vec![],
            user: "root".to_string(),
            tty: true,
            rows: 0,
            cols: 0,
        });
        let parsed = ControlMessage::parse(&msg.serialize()).unwrap();
        assert_eq!(parsed, msg);
    }

    #[test]
    fn control_exec_non_tty_omits_tty_fields() {
        let req = ExecRequest {
            cmd: "/bin/ls".to_string(),
            args: vec![],
            env: vec![],
            user: "root".to_string(),
            tty: false,
            rows: 0,
            cols: 0,
        };
        let json = req.to_json();
        assert!(!json.contains("tty"));
        assert!(!json.contains("rows"));
        assert!(!json.contains("cols"));
    }
}
