//! Shared utilities for the wrapper execution path.
//!
//! Used by both the standalone `bin/arapuca` wrapper binary and the
//! selfexec trampoline (`selfexec.rs`). Extracted to avoid
//! duplication between the two paths.

use std::path::PathBuf;

/// Simple PATH lookup for a command name.
pub fn which(cmd: &str) -> Option<PathBuf> {
    let path_var = std::env::var_os("PATH")?;
    let path_str = path_var.to_str()?;
    for dir in path_str.split(':') {
        let candidate = PathBuf::from(dir).join(cmd);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// Write an audit status line to the audit FD (if set).
///
/// Writes newline-delimited JSON. Errors are silently ignored — audit
/// is observability, not a security gate.
#[cfg(unix)]
pub fn audit_layer(fd: Option<i32>, layer: &str, ok: bool, error: Option<&str>) {
    let Some(fd) = fd else { return };
    let status = if ok { "applied" } else { "failed" };
    let json = if let Some(err) = error {
        let escaped = json_escape(err);
        format!(r#"{{"layer":"{layer}","status":"{status}","error":"{escaped}"}}"#)
    } else {
        format!(r#"{{"layer":"{layer}","status":"{status}"}}"#)
    };
    let line = format!("{json}\n");
    // SAFETY: fd is a valid descriptor from ARAPUCA_AUDIT_FD, buf/len valid.
    let _ = unsafe { libc::write(fd, line.as_ptr().cast::<libc::c_void>(), line.len()) };
}

/// Escape a string for JSON (RFC 8259): backslash, double-quote,
/// and all control characters below U+0020.
pub fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if c < '\u{0020}' => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

/// Write a message to stderr using raw libc (async-signal-safe).
#[cfg(unix)]
pub fn write_stderr(msg: &str) {
    let _ = unsafe { libc::write(2, msg.as_ptr().cast::<libc::c_void>(), msg.len()) };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_escape_plain() {
        assert_eq!(json_escape("hello world"), "hello world");
    }

    #[test]
    fn json_escape_quotes_and_backslash() {
        assert_eq!(json_escape(r#"say "hi""#), r#"say \"hi\""#);
        assert_eq!(json_escape(r"back\slash"), r"back\\slash");
    }

    #[test]
    fn json_escape_control_characters() {
        assert_eq!(json_escape("tab\there"), "tab\\u0009here");
        assert_eq!(json_escape("new\nline"), "new\\u000aline");
        assert_eq!(json_escape("\x00null"), "\\u0000null");
        assert_eq!(json_escape("\x1f"), "\\u001f");
    }

    #[test]
    fn json_escape_mixed() {
        assert_eq!(
            json_escape("err: \"bad\\path\"\n"),
            "err: \\\"bad\\\\path\\\"\\u000a"
        );
    }

    #[test]
    fn json_escape_unicode_passthrough() {
        assert_eq!(json_escape("café ☕ 日本語"), "café ☕ 日本語");
    }

    #[test]
    fn json_escape_empty() {
        assert_eq!(json_escape(""), "");
    }

    #[cfg(unix)]
    #[test]
    fn which_finds_known_command() {
        assert!(which("sh").is_some());
    }

    #[test]
    fn which_returns_none_for_missing() {
        assert!(which("__nonexistent_binary_42__").is_none());
    }

    #[cfg(unix)]
    #[test]
    fn which_result_is_file() {
        if let Some(path) = which("sh") {
            assert!(path.is_file());
        }
    }
}
