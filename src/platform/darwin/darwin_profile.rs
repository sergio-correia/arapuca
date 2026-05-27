//! Seatbelt profile generation for macOS sandbox-exec.
//!
//! Generates `.sb` profile files in Apple's Seatbelt policy language.
//! The profile starts with `(deny default)` and explicitly allows only
//! the paths and operations the sandboxed process needs.
//!
//! Path validation prevents Seatbelt profile injection attacks — only a
//! strict character allowlist is accepted.

use std::fmt::Write;
use std::path::Path;

use crate::Error;

/// Data used to render a Seatbelt profile.
pub struct ProfileData {
    /// Paths the subprocess can read.
    pub read_paths: Vec<String>,
    /// Paths the subprocess can read and write.
    pub write_paths: Vec<String>,
    /// Paths the subprocess can execute (in addition to system defaults).
    pub exec_paths: Vec<String>,
    /// Path to the JSON-RPC control socket.
    pub control_socket: Option<String>,
    /// Path to the LLM proxy socket.
    pub llm_socket: Option<String>,
}

/// Validate that a path contains only safe characters for embedding in
/// a Seatbelt profile.
///
/// This prevents injection attacks where a crafted path could break out
/// of the `(subpath ...)` or `(literal ...)` expressions in the profile.
///
/// Allowed characters: `[a-zA-Z0-9/_. @-]`
pub fn validate_profile_path(path: &str) -> crate::Result<()> {
    if path.is_empty() {
        return Err(Error::Validation("empty path".into()));
    }
    for ch in path.chars() {
        if !matches!(ch, 'a'..='z' | 'A'..='Z' | '0'..='9' | '/' | '_' | '.' | ' ' | '-' | '@') {
            return Err(Error::Validation(format!(
                "invalid character in sandbox profile path: {:?}",
                ch
            )));
        }
    }
    Ok(())
}

/// Generate a Seatbelt `.sb` profile and write it to `dir/profile.sb`.
///
/// Returns the path to the generated profile file.
pub fn generate_profile(dir: &Path, data: &ProfileData) -> crate::Result<std::path::PathBuf> {
    // Validate all paths before generating the profile.
    for p in &data.read_paths {
        validate_profile_path(p)?;
    }
    for p in &data.write_paths {
        validate_profile_path(p)?;
    }
    for p in &data.exec_paths {
        validate_profile_path(p)?;
    }
    if let Some(ref s) = data.control_socket {
        validate_profile_path(s)?;
    }
    if let Some(ref s) = data.llm_socket {
        validate_profile_path(s)?;
    }

    let mut profile = String::with_capacity(4096);

    // Header: deny everything by default.
    writeln!(profile, "(version 1)").unwrap();
    writeln!(profile, "(deny default)").unwrap();
    writeln!(profile).unwrap();

    // Process operations.
    writeln!(profile, "; Process").unwrap();
    writeln!(profile, "(allow process-fork)").unwrap();
    writeln!(profile, "(allow signal (target self))").unwrap();
    writeln!(profile).unwrap();

    // Root directory: dyld needs to stat "/" during process bootstrap.
    // Without this, the process receives SIGABRT before main() runs.
    writeln!(profile, "; Root directory (dyld bootstrap)").unwrap();
    writeln!(profile, "(allow file-read* (literal \"/\"))").unwrap();
    writeln!(profile).unwrap();

    // Ancestor directories for path traversal. Seatbelt requires
    // explicit access to parent directories for realpath() resolution.
    // /private and /private/var are needed because /var, /etc, and /tmp
    // are symlinks into /private on macOS.
    // /etc is a symlink to /private/etc — it must be readable for
    // processes that open /etc/hosts, /etc/resolv.conf, etc.
    writeln!(profile, "; Ancestor directories for path traversal").unwrap();
    for ancestor in &["/opt", "/etc", "/private", "/private/var"] {
        writeln!(profile, "(allow file-read* (literal \"{ancestor}\"))").unwrap();
    }
    writeln!(profile).unwrap();

    // System read paths (always allowed).
    // Note: /System covers /System/Library and /System/Cryptexes (dyld
    // shared cache on macOS 13+).
    writeln!(profile, "; System read paths").unwrap();
    for sys_path in &[
        "/usr",
        "/bin",
        "/opt/homebrew",
        "/Library/Frameworks",
        "/System",
        "/dev",
        "/private/var/select",
    ] {
        writeln!(profile, "(allow file-read* (subpath \"{sys_path}\"))").unwrap();
    }
    writeln!(profile).unwrap();

    // Specific /etc files (not the whole directory).
    // macOS paths: /etc -> /private/etc, so use canonical paths.
    // Seatbelt resolves symlinks in access paths but stores profile
    // paths as-is, so /etc/hosts would NOT match an access to
    // /private/etc/hosts.
    writeln!(profile, "; Specific /etc files (canonical paths)").unwrap();
    for etc_file in &[
        "/private/etc/hosts",
        "/private/etc/resolv.conf",
        "/private/etc/localtime",
        "/private/etc/ssl/cert.pem",
    ] {
        writeln!(profile, "(allow file-read* (literal \"{etc_file}\"))").unwrap();
    }
    // Allow reading /etc/ssl directory for certificate lookup.
    writeln!(
        profile,
        "(allow file-read* (subpath \"/private/etc/ssl/certs\"))"
    )
    .unwrap();
    writeln!(profile).unwrap();

    // User read paths.
    if !data.read_paths.is_empty() {
        writeln!(profile, "; User read paths").unwrap();
        for p in &data.read_paths {
            writeln!(profile, "(allow file-read* (subpath \"{p}\"))").unwrap();
        }
        writeln!(profile).unwrap();
    }

    // User write paths.
    if !data.write_paths.is_empty() {
        writeln!(profile, "; User write paths").unwrap();
        for p in &data.write_paths {
            writeln!(profile, "(allow file-read* (subpath \"{p}\"))").unwrap();
            writeln!(profile, "(allow file-write* (subpath \"{p}\"))").unwrap();
        }
        writeln!(profile).unwrap();
    }

    // /dev/null write access.
    writeln!(profile, "; /dev/null write").unwrap();
    writeln!(profile, "(allow file-write* (literal \"/dev/null\"))").unwrap();
    writeln!(profile).unwrap();

    // Exec permissions: system paths + user exec paths + write paths
    // (uv creates virtualenvs in write paths that need to be executable).
    writeln!(profile, "; Exec").unwrap();
    writeln!(profile, "(allow process-exec (subpath \"/usr\"))").unwrap();
    writeln!(profile, "(allow process-exec (subpath \"/bin\"))").unwrap();
    writeln!(profile, "(allow process-exec (subpath \"/opt/homebrew\"))").unwrap();
    for p in &data.exec_paths {
        writeln!(profile, "(allow process-exec (subpath \"{p}\"))").unwrap();
    }
    // Write paths are also exec paths (virtualenvs).
    for p in &data.write_paths {
        writeln!(profile, "(allow process-exec (subpath \"{p}\"))").unwrap();
    }
    writeln!(profile).unwrap();

    // Network: deny all TCP/UDP (via deny default). Only allow Unix
    // domain sockets to specific paths.
    if data.control_socket.is_some() || data.llm_socket.is_some() {
        writeln!(profile, "; Unix sockets").unwrap();
        writeln!(profile, "(allow network-outbound (remote unix))").unwrap();
        if let Some(ref s) = data.control_socket {
            writeln!(profile, "(allow file-read* (literal \"{s}\"))").unwrap();
            writeln!(profile, "(allow file-write* (literal \"{s}\"))").unwrap();
        }
        if let Some(ref s) = data.llm_socket {
            writeln!(profile, "(allow file-read* (literal \"{s}\"))").unwrap();
            writeln!(profile, "(allow file-write* (literal \"{s}\"))").unwrap();
        }
        writeln!(profile).unwrap();
    }

    // Mach IPC (required for basic macOS operation).
    writeln!(profile, "; Mach IPC").unwrap();
    writeln!(
        profile,
        "(allow mach-lookup (global-name \"com.apple.system.logger\"))"
    )
    .unwrap();
    writeln!(
        profile,
        "(allow mach-lookup (global-name \"com.apple.system.opendirectoryd.libinfo\"))"
    )
    .unwrap();
    writeln!(
        profile,
        "(allow mach-lookup (global-name \"com.apple.system.notification_center\"))"
    )
    .unwrap();
    writeln!(profile).unwrap();

    // POSIX shared memory (read-only).
    writeln!(profile, "; POSIX shm").unwrap();
    writeln!(profile, "(allow ipc-posix-shm-read-data)").unwrap();
    writeln!(profile).unwrap();

    // Sysctl read.
    writeln!(profile, "; Sysctl").unwrap();
    writeln!(profile, "(allow sysctl-read)").unwrap();

    // Write profile to file.
    let profile_path = dir.join("profile.sb");
    std::fs::write(&profile_path, &profile)?;

    // Set permissions to 0400 (read-only for owner).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&profile_path, std::fs::Permissions::from_mode(0o400))?;
    }

    Ok(profile_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_profile_path_valid() {
        // Simple path.
        assert!(validate_profile_path("/usr/bin/python3").is_ok());
        // Homebrew path.
        assert!(validate_profile_path("/opt/homebrew/bin").is_ok());
        // Path with spaces.
        assert!(validate_profile_path("/Users/test user/dir").is_ok());
        // Underscore and dash.
        assert!(validate_profile_path("/tmp/my_dir-name").is_ok());
        // @ in Homebrew versioned paths.
        assert!(validate_profile_path("/opt/homebrew/opt/python@3.14/bin/python3.14").is_ok());
        // Dots.
        assert!(validate_profile_path("/usr/lib/libfoo.1.2.dylib").is_ok());
    }

    #[test]
    fn test_validate_profile_path_invalid() {
        // Empty.
        assert!(validate_profile_path("").is_err());
        // Double quote (profile injection).
        assert!(validate_profile_path("/tmp/foo\"bar").is_err());
        // Parentheses (Seatbelt syntax).
        assert!(validate_profile_path("/tmp/foo(bar)").is_err());
        // Semicolon.
        assert!(validate_profile_path("/tmp/foo;bar").is_err());
        // Backslash.
        assert!(validate_profile_path("/tmp/foo\\bar").is_err());
        // Newline.
        assert!(validate_profile_path("/tmp/foo\nbar").is_err());
        // Null byte.
        assert!(validate_profile_path("/tmp/foo\0bar").is_err());
        // Backtick.
        assert!(validate_profile_path("/tmp/foo`bar").is_err());
        // Single quote.
        assert!(validate_profile_path("/tmp/foo'bar").is_err());
        // Pipe.
        assert!(validate_profile_path("/tmp/foo|bar").is_err());
        // Ampersand.
        assert!(validate_profile_path("/tmp/foo&bar").is_err());
    }

    #[test]
    fn test_generate_profile() {
        let dir = std::env::temp_dir().join("arapuca-test-profile");
        let _ = std::fs::create_dir_all(&dir);

        let data = ProfileData {
            read_paths: vec!["/home/user/src".into()],
            write_paths: vec!["/tmp/work".into()],
            exec_paths: vec!["/usr/local/bin".into()],
            control_socket: Some("/tmp/sock/control.sock".into()),
            llm_socket: Some("/tmp/sock/llm.sock".into()),
        };

        let path = generate_profile(&dir, &data).unwrap();
        let content = std::fs::read_to_string(&path).unwrap();

        // Verify deny-default.
        assert!(content.contains("(deny default)"));

        // Verify root directory access for dyld bootstrap.
        assert!(content.contains("(allow file-read* (literal \"/\"))"));

        // Verify ancestor directories for path traversal.
        assert!(content.contains("(allow file-read* (literal \"/opt\"))"));
        assert!(content.contains("(allow file-read* (literal \"/etc\"))"));
        assert!(content.contains("(allow file-read* (literal \"/private\"))"));
        assert!(content.contains("(allow file-read* (literal \"/private/var\"))"));

        // Verify /private/var/select is readable (shell resolution).
        assert!(content.contains("(allow file-read* (subpath \"/private/var/select\"))"));

        // Verify /etc paths use canonical /private/etc prefix.
        assert!(content.contains("(allow file-read* (literal \"/private/etc/hosts\"))"));
        assert!(content.contains("(allow file-read* (subpath \"/private/etc/ssl/certs\"))"));

        // Verify /System is a subpath (covers /System/Library and
        // /System/Cryptexes).
        assert!(content.contains("(allow file-read* (subpath \"/System\"))"));

        // Verify read paths.
        assert!(content.contains("(allow file-read* (subpath \"/home/user/src\"))"));

        // Verify write paths include both read and write.
        assert!(content.contains("(allow file-read* (subpath \"/tmp/work\"))"));
        assert!(content.contains("(allow file-write* (subpath \"/tmp/work\"))"));

        // Verify socket paths.
        assert!(content.contains("(allow file-read* (literal \"/tmp/sock/control.sock\"))"));
        assert!(content.contains("(allow file-write* (literal \"/tmp/sock/llm.sock\"))"));

        // Verify exec paths — explicit + auto-included from write paths.
        assert!(content.contains("(allow process-exec (subpath \"/usr/local/bin\"))"));
        assert!(content.contains("(allow process-exec (subpath \"/tmp/work\"))"));

        // Verify file permissions.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let meta = std::fs::metadata(&path).unwrap();
            assert_eq!(meta.permissions().mode() & 0o777, 0o400);
        }

        // Cleanup.
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_generate_profile_rejects_injection() {
        let dir = std::env::temp_dir().join("arapuca-test-injection");
        let _ = std::fs::create_dir_all(&dir);

        // Crafted path that tries to inject Seatbelt syntax.
        let data = ProfileData {
            read_paths: vec!["/tmp/evil\") (allow default) (deny nothing \"".into()],
            write_paths: vec![],
            exec_paths: vec![],
            control_socket: None,
            llm_socket: None,
        };

        let result = generate_profile(&dir, &data);
        assert!(result.is_err(), "injection path should be rejected");

        // Cleanup.
        let _ = std::fs::remove_dir_all(&dir);
    }
}
