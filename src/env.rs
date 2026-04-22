//! Environment and directory utilities for sandboxed processes.
//!
//! Provides functions for constructing minimal environments, creating
//! temp directories, socket directories, and canonicalizing paths.

use std::path::{Path, PathBuf};

/// Construct a minimal environment for a sandboxed subprocess.
///
/// Only includes HOME, TMPDIR, PATH, and LANG. This prevents
/// information leakage from the host environment to the agent.
pub fn minimal_env(tmp_dir: &Path) -> Vec<(String, String)> {
    vec![
        ("HOME".into(), tmp_dir.to_string_lossy().into_owned()),
        ("TMPDIR".into(), tmp_dir.to_string_lossy().into_owned()),
        (
            "PATH".into(),
            "/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin".into(),
        ),
        ("LANG".into(), "C.UTF-8".into()),
    ]
}

/// Filter caller-supplied env vars, dropping dangerous entries.
///
/// Drops vars that could subvert sandbox confinement:
/// - `ARAPUCA_*` — sandbox config re-injection
/// - `AGENT_NETWORK_PROXY` — set by launcher, not caller
/// - `LD_*`, `DYLD_*` — dynamic linker injection
/// - `COR_*`, `CORECLR_*`, `DOTNET_*`, `COMPLUS_*` — .NET profiler/runtime injection
/// - `__COMPAT_LAYER` — Windows compatibility shim injection
/// - Interpreter injection: `BASH_ENV`, `ENV`, `PYTHONPATH`,
///   `PYTHONSTARTUP`, `NODE_OPTIONS`, `PERL5OPT`, `PERL5LIB`
/// - `COMSPEC`, `PSModulePath`, `PATHEXT` — Windows shell/exec injection
pub fn filter_caller_env(env: &[(String, String)]) -> Vec<(String, String)> {
    const BLOCKED_PREFIXES: &[&str] = &[
        "ARAPUCA_", "LD_", "DYLD_", "COR_", "CORECLR_", "DOTNET_", "COMPLUS_",
    ];
    const BLOCKED_NAMES: &[&str] = &[
        "AGENT_NETWORK_PROXY",
        "BASH_ENV",
        "ENV",
        "PYTHONPATH",
        "PYTHONSTARTUP",
        "NODE_OPTIONS",
        "PERL5OPT",
        "PERL5LIB",
        "COMSPEC",
        "PSModulePath",
        "PATHEXT",
        "__COMPAT_LAYER",
    ];

    env.iter()
        .filter(|(k, _)| {
            !BLOCKED_PREFIXES.iter().any(|p| k.starts_with(p))
                && !BLOCKED_NAMES.contains(&k.as_str())
        })
        .cloned()
        .collect()
}

/// Create a temporary directory for the sandbox.
///
/// The directory is created under the system temp dir with a random
/// suffix to prevent symlink attacks and directory squatting.
pub fn make_tmp_dir(task_id: &str) -> crate::Result<PathBuf> {
    let prefix = format!("arapuca-{task_id}-");
    let dir = make_temp_dir(&prefix)?;
    Ok(dir)
}

/// Create a socket directory for JSON-RPC communication.
///
/// Creates a directory with mode 0700 and a random suffix for the
/// control and LLM sockets.
pub fn make_socket_dir() -> crate::Result<PathBuf> {
    make_temp_dir("arapuca-sock-")
}

/// Canonicalize a list of paths, resolving symlinks and making them absolute.
///
/// Prevents symlink escape attacks where a crafted symlink inside a
/// writable path points outside it. For paths that don't exist, falls
/// back to canonicalizing the parent directory + the final component
/// (matching Go's behavior). Returns empty vec only if all paths fail.
pub fn canonicalize_paths(paths: &[PathBuf]) -> Vec<PathBuf> {
    paths
        .iter()
        .filter_map(|p| {
            // Try direct canonicalization first.
            if let Ok(canon) = std::fs::canonicalize(p) {
                return Some(canon);
            }
            // Fallback: canonicalize parent + append basename.
            let parent = p.parent()?;
            let name = p.file_name()?;
            let canon_parent = std::fs::canonicalize(parent).ok()?;
            Some(canon_parent.join(name))
        })
        .collect()
}

/// Platform-specific path list separator.
///
/// `:` on Unix, `;` on Windows (where `:` appears in drive letters).
const PATH_LIST_SEP: char = if cfg!(windows) { ';' } else { ':' };

/// Parse paths from a separator-delimited string.
///
/// Used by the binary to parse ARAPUCA_READ_PATHS and ARAPUCA_WRITE_PATHS
/// environment variables. Uses `:` on Unix, `;` on Windows.
pub fn parse_paths(s: &str) -> Vec<PathBuf> {
    if s.is_empty() {
        return Vec::new();
    }
    s.split(PATH_LIST_SEP)
        .map(|p| p.trim())
        .filter(|p| !p.is_empty())
        .map(PathBuf::from)
        .collect()
}

/// Binary name for the arapuca wrapper.
const WRAPPER_BIN: &str = if cfg!(windows) {
    "arapuca.exe"
} else {
    "arapuca"
};

/// Returns the path to the arapuca binary if it exists.
///
/// Looks next to the current executable first, then in PATH.
/// Returns None if not found.
pub fn wrapper_path() -> Option<PathBuf> {
    // Look next to the current executable.
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let candidate = dir.join(WRAPPER_BIN);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    // Fall back to PATH.
    for dir in std::env::var("PATH")
        .unwrap_or_default()
        .split(PATH_LIST_SEP)
    {
        let candidate = PathBuf::from(dir).join(WRAPPER_BIN);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// Build environment variables for the arapuca wrapper binary.
///
/// These configure Landlock paths and rlimits. Uses the `ARAPUCA_*`
/// prefix so the wrapper strips them after applying.
pub fn wrapper_env(profile: &crate::Profile) -> Vec<(String, String)> {
    let mut env = Vec::new();
    if !profile.read_paths.is_empty() {
        let paths: Vec<String> = profile
            .read_paths
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect();
        let sep = &PATH_LIST_SEP.to_string();
        env.push(("ARAPUCA_READ_PATHS".into(), paths.join(sep)));
    }
    if !profile.write_paths.is_empty() {
        let paths: Vec<String> = profile
            .write_paths
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect();
        let sep = &PATH_LIST_SEP.to_string();
        env.push(("ARAPUCA_WRITE_PATHS".into(), paths.join(sep)));
    }
    if profile.max_memory_mb > 0 {
        env.push((
            "ARAPUCA_RLIMIT_AS".into(),
            (profile.max_memory_mb * 1024 * 1024).to_string(),
        ));
    }
    if profile.max_pids > 0 {
        env.push(("ARAPUCA_RLIMIT_NPROC".into(), profile.max_pids.to_string()));
    }
    if profile.max_file_size_mb > 0 {
        env.push((
            "ARAPUCA_RLIMIT_FSIZE".into(),
            (profile.max_file_size_mb * 1024 * 1024).to_string(),
        ));
    }
    env
}

/// Create a temporary directory with a random suffix.
///
/// Uses the `tempfile` crate which calls `mkdtemp` on Unix (mode 0700,
/// created atomically) and secure temp-dir creation on Windows.
/// `keep()` prevents auto-deletion — the caller owns cleanup.
fn make_temp_dir(prefix: &str) -> crate::Result<PathBuf> {
    let dir = tempfile::Builder::new()
        .prefix(prefix)
        .tempdir_in(std::env::temp_dir())?;
    Ok(dir.keep())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minimal_env_contains_essentials() {
        let env = minimal_env(Path::new("/tmp/test"));
        let keys: Vec<&str> = env.iter().map(|(k, _)| k.as_str()).collect();
        assert!(keys.contains(&"HOME"));
        assert!(keys.contains(&"TMPDIR"));
        assert!(keys.contains(&"PATH"));
        assert!(keys.contains(&"LANG"));
        assert_eq!(env.len(), 4);
    }

    #[test]
    fn parse_paths_empty() {
        assert!(parse_paths("").is_empty());
    }

    #[test]
    fn parse_paths_single() {
        let paths = parse_paths("/usr/lib");
        assert_eq!(paths, vec![PathBuf::from("/usr/lib")]);
    }

    #[test]
    fn parse_paths_multiple() {
        let sep = PATH_LIST_SEP;
        let input = format!("/a{sep}/b{sep}/c");
        let paths = parse_paths(&input);
        assert_eq!(
            paths,
            vec![
                PathBuf::from("/a"),
                PathBuf::from("/b"),
                PathBuf::from("/c")
            ]
        );
    }

    #[test]
    fn parse_paths_trims_whitespace() {
        let sep = PATH_LIST_SEP;
        let input = format!(" /a {sep} /b ");
        let paths = parse_paths(&input);
        assert_eq!(paths, vec![PathBuf::from("/a"), PathBuf::from("/b")]);
    }

    #[test]
    fn filter_drops_arapuca_prefix() {
        let env = vec![("ARAPUCA_READ_PATHS".into(), "/".into())];
        assert!(filter_caller_env(&env).is_empty());
    }

    #[test]
    fn filter_drops_ld_prefix() {
        let env = vec![
            ("LD_PRELOAD".into(), "/evil.so".into()),
            ("LD_LIBRARY_PATH".into(), "/tmp".into()),
        ];
        assert!(filter_caller_env(&env).is_empty());
    }

    #[test]
    fn filter_drops_dyld_prefix() {
        let env = vec![("DYLD_INSERT_LIBRARIES".into(), "/evil.dylib".into())];
        assert!(filter_caller_env(&env).is_empty());
    }

    #[test]
    fn filter_drops_interpreter_injection() {
        let blocked = vec![
            "BASH_ENV",
            "ENV",
            "PYTHONPATH",
            "PYTHONSTARTUP",
            "NODE_OPTIONS",
            "PERL5OPT",
            "PERL5LIB",
        ];
        let env: Vec<(String, String)> = blocked
            .iter()
            .map(|k| (k.to_string(), "malicious".into()))
            .collect();
        assert!(filter_caller_env(&env).is_empty());
    }

    #[test]
    fn filter_drops_agent_network_proxy() {
        let env = vec![("AGENT_NETWORK_PROXY".into(), "/tmp/evil.sock".into())];
        assert!(filter_caller_env(&env).is_empty());
    }

    #[test]
    fn filter_preserves_normal_vars() {
        let env = vec![
            ("MY_TOKEN".into(), "secret123".into()),
            ("JIRA_URL".into(), "https://jira.example.com".into()),
        ];
        let filtered = filter_caller_env(&env);
        assert_eq!(filtered.len(), 2);
        assert_eq!(filtered[0].0, "MY_TOKEN");
        assert_eq!(filtered[1].0, "JIRA_URL");
    }

    #[test]
    fn filter_preserves_value_with_equals() {
        let env = vec![("CONFIG".into(), "key=value=extra".into())];
        let filtered = filter_caller_env(&env);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].1, "key=value=extra");
    }

    #[test]
    fn canonicalize_existing_paths() {
        let existing = std::env::temp_dir();
        let nonexistent_child = existing.join("nonexistent-xyz-arapuca-test");
        let paths = vec![existing.clone(), nonexistent_child];
        let result = canonicalize_paths(&paths);
        let canon_existing = std::fs::canonicalize(&existing).unwrap();
        assert!(result.contains(&canon_existing));
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn canonicalize_fully_nonexistent() {
        let paths = vec![PathBuf::from("/no-such-parent-xyz/child")];
        let result = canonicalize_paths(&paths);
        assert!(result.is_empty());
    }
}
