use crate::Error;

/// Maximum length for a task ID.
const MAX_TASK_ID_LEN: usize = 128;

/// Maximum size (bytes) for a single guest file's content.
pub const MAX_GUEST_FILE_SIZE: usize = 1024 * 1024;

/// Maximum number of write_files entries.
pub const MAX_GUEST_WRITE_FILES: usize = 16;

/// Guest paths that must not be written to via write_files.
#[cfg(unix)]
pub const GUEST_PATH_DENY_PREFIXES: &[&str] = &["/proc", "/sys", "/dev", "/cidata", "/agent"];

/// Validate and sanitize a task ID.
///
/// Task IDs are used in filesystem paths (cgroup directories, temp dirs),
/// so they must be safe for path construction. Allowed: `[a-zA-Z0-9-]`,
/// max 128 characters.
///
/// Returns the validated ID on success, or an error if the ID is invalid.
pub fn sanitize_task_id(id: &str) -> crate::Result<&str> {
    if id.is_empty() {
        return Err(Error::Validation("empty task ID".into()));
    }
    if id.len() > MAX_TASK_ID_LEN {
        return Err(Error::Validation(format!(
            "task ID too long ({} chars, max {MAX_TASK_ID_LEN})",
            id.len()
        )));
    }
    if !id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
        return Err(Error::Validation(format!(
            "task ID contains invalid characters: {id:?}"
        )));
    }
    Ok(id)
}

/// Validate a guest file path (must be absolute, no `..`, not in denied prefixes).
#[cfg(unix)]
pub fn validate_guest_path(path: &str) -> crate::Result<()> {
    if !path.starts_with('/') {
        return Err(Error::Validation("guest path must be absolute".into()));
    }
    if path.split('/').any(|c| c == "..") {
        return Err(Error::Validation(format!(
            "guest path contains '..': {path}"
        )));
    }
    let normalized = normalize_path(std::path::Path::new(path));
    let ns = normalized.to_string_lossy();
    if ns == "/" {
        return Err(Error::Validation("guest path must not be '/'".into()));
    }
    for prefix in GUEST_PATH_DENY_PREFIXES {
        if ns == *prefix || ns.starts_with(&format!("{prefix}/")) {
            return Err(Error::Validation(format!(
                "guest path in denied prefix: {path}"
            )));
        }
    }
    Ok(())
}

/// Validate guest file content size (must not exceed MAX_GUEST_FILE_SIZE).
#[cfg(unix)]
pub fn validate_guest_file_content(content: &str) -> crate::Result<()> {
    if content.len() > MAX_GUEST_FILE_SIZE {
        return Err(Error::Validation(format!(
            "guest file content too large ({} bytes, max {MAX_GUEST_FILE_SIZE})",
            content.len()
        )));
    }
    Ok(())
}

/// Validate guest file permissions (3-4 octal digits, no setuid/setgid/sticky).
#[cfg(unix)]
pub fn validate_guest_permissions(perms: &str) -> crate::Result<()> {
    if perms.len() < 3 || perms.len() > 4 {
        return Err(Error::Validation(format!(
            "permissions must be 3-4 octal digits: {perms}"
        )));
    }
    if !perms.bytes().all(|b| (b'0'..=b'7').contains(&b)) {
        return Err(Error::Validation(format!(
            "permissions must be octal digits: {perms}"
        )));
    }
    if perms.len() == 4 && perms.as_bytes()[0] != b'0' {
        return Err(Error::Validation(format!(
            "setuid/setgid/sticky bits not allowed: {perms}"
        )));
    }
    Ok(())
}

/// Validate the working directory for the sandboxed process.
///
/// Defense-in-depth: ensures `work_dir` (when set) is absolute, exists as a
/// directory, and falls within a configured read or write path. Landlock
/// enforces filesystem access at runtime, but rejecting invalid `work_dir`
/// early produces clear errors instead of confusing EACCES failures.
///
/// Both `work_dir` and mount paths are canonicalized to handle symlinks.
#[cfg(unix)]
pub fn validate_work_dir(
    work_dir: &Option<std::path::PathBuf>,
    read_paths: &[std::path::PathBuf],
    write_paths: &[std::path::PathBuf],
) -> crate::Result<()> {
    let dir = match work_dir {
        Some(d) => d,
        None => return Ok(()),
    };
    if !dir.is_absolute() {
        return Err(Error::Validation(format!(
            "work_dir must be absolute: {}",
            dir.display()
        )));
    }
    let canonical = dir.canonicalize().map_err(|e| {
        Error::Validation(format!(
            "work_dir cannot be resolved: {}: {e}",
            dir.display()
        ))
    })?;
    if !canonical.is_dir() {
        return Err(Error::Validation(format!(
            "work_dir is not a directory: {}",
            canonical.display()
        )));
    }
    let in_mounts = read_paths.iter().chain(write_paths.iter()).any(|p| {
        let resolved = p.canonicalize().unwrap_or_else(|_| p.clone());
        canonical.starts_with(&resolved)
    });
    if !in_mounts {
        return Err(Error::Validation(format!(
            "work_dir must be within a mounted path: {}",
            canonical.display()
        )));
    }
    Ok(())
}

/// Reject paths that resolve to `/sys/fs/cgroup`.
///
/// Defense-in-depth: prevents a sandboxed process from modifying its own
/// cgroup resource limits (memory.max, cpu.max, pids.max) if the path
/// were allowed through Landlock.
///
/// Uses both lexical normalization (handles `..`/`.` without filesystem
/// access) and filesystem canonicalization (resolves symlinks for paths
/// that exist). Landlock itself resolves paths at enforcement time, so
/// this check is defense-in-depth.
#[cfg(unix)]
pub fn reject_cgroup_paths(paths: &[std::path::PathBuf]) -> crate::Result<()> {
    let cgroup_prefix = std::path::Path::new("/sys/fs/cgroup");
    for p in paths {
        let normalized = normalize_path(p);
        let ns = normalized.to_string_lossy();
        if ns.starts_with("/sys/fs/cgroup") || cgroup_prefix.starts_with(&*normalized) {
            return Err(Error::Validation(format!(
                "path must not include or be an ancestor of /sys/fs/cgroup: {}",
                p.display()
            )));
        }
        if let Ok(resolved) = std::fs::canonicalize(p) {
            let rs = resolved.to_string_lossy();
            if rs.starts_with("/sys/fs/cgroup") || cgroup_prefix.starts_with(&*resolved) {
                return Err(Error::Validation(format!(
                    "path must not include or be an ancestor of /sys/fs/cgroup: {}",
                    p.display()
                )));
            }
        }
    }
    Ok(())
}

/// Lexically normalize a path by resolving `.` and `..` components
/// without accessing the filesystem.
#[cfg(unix)]
pub fn normalize_path(p: &std::path::Path) -> std::path::PathBuf {
    use std::path::Component;
    let mut parts = Vec::new();
    for c in p.components() {
        match c {
            Component::ParentDir => {
                if parts.last() != Some(&Component::RootDir) {
                    parts.pop();
                }
            }
            Component::CurDir => {}
            other => parts.push(other),
        }
    }
    parts.iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn valid_task_ids() {
        assert!(sanitize_task_id("abc-123").is_ok());
        assert!(sanitize_task_id("A").is_ok());
        assert!(sanitize_task_id("task-with-dashes-42").is_ok());
    }

    #[test]
    fn empty_task_id() {
        assert!(sanitize_task_id("").is_err());
    }

    #[test]
    fn task_id_too_long() {
        let long = "a".repeat(MAX_TASK_ID_LEN + 1);
        assert!(sanitize_task_id(&long).is_err());
    }

    #[test]
    fn task_id_max_length_ok() {
        let max = "a".repeat(MAX_TASK_ID_LEN);
        assert!(sanitize_task_id(&max).is_ok());
    }

    #[test]
    fn task_id_bad_chars() {
        assert!(sanitize_task_id("../escape").is_err());
        assert!(sanitize_task_id("has space").is_err());
        assert!(sanitize_task_id("has/slash").is_err());
        assert!(sanitize_task_id("has_underscore").is_err());
        assert!(sanitize_task_id("has.dot").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn cgroup_path_rejected() {
        let paths = vec![PathBuf::from("/sys/fs/cgroup/user.slice")];
        assert!(reject_cgroup_paths(&paths).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn cgroup_exact_path_rejected() {
        let paths = vec![PathBuf::from("/sys/fs/cgroup")];
        assert!(reject_cgroup_paths(&paths).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn normal_paths_ok() {
        let paths = vec![
            PathBuf::from("/usr/lib"),
            PathBuf::from("/tmp/agent-123"),
            PathBuf::from("/home/user/project"),
        ];
        assert!(reject_cgroup_paths(&paths).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn empty_paths_ok() {
        assert!(reject_cgroup_paths(&[]).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn cgroup_path_dotdot_bypass_rejected() {
        let paths = vec![PathBuf::from("/nonexistent/../sys/fs/cgroup")];
        assert!(reject_cgroup_paths(&paths).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn cgroup_path_dot_component_rejected() {
        let paths = vec![PathBuf::from("/sys/fs/./cgroup/user.slice")];
        assert!(reject_cgroup_paths(&paths).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn cgroup_path_excessive_dotdot_rejected() {
        let paths = vec![PathBuf::from("/../../../sys/fs/cgroup")];
        assert!(reject_cgroup_paths(&paths).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn normalize_preserves_root_on_excess_dotdot() {
        assert_eq!(
            normalize_path(&PathBuf::from("/../../../sys/fs/cgroup")),
            PathBuf::from("/sys/fs/cgroup")
        );
    }

    #[cfg(unix)]
    #[test]
    fn normalize_resolves_dotdot() {
        assert_eq!(
            normalize_path(&PathBuf::from("/a/b/../c")),
            PathBuf::from("/a/c")
        );
    }

    #[cfg(unix)]
    #[test]
    fn guest_path_absolute_ok() {
        assert!(validate_guest_path("/etc/hostname").is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn guest_path_relative_rejected() {
        assert!(validate_guest_path("relative/path").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn guest_path_dotdot_rejected() {
        assert!(validate_guest_path("/tmp/../../etc/shadow").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn permissions_valid_octal() {
        assert!(validate_guest_permissions("644").is_ok());
        assert!(validate_guest_permissions("0755").is_ok());
        assert!(validate_guest_permissions("0600").is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn permissions_setuid_rejected() {
        assert!(validate_guest_permissions("4755").is_err());
        assert!(validate_guest_permissions("2755").is_err());
        assert!(validate_guest_permissions("6755").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn permissions_non_octal_rejected() {
        assert!(validate_guest_permissions("abc").is_err());
        assert!(validate_guest_permissions("--reference=/etc/shadow").is_err());
        assert!(validate_guest_permissions("u+s").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn normalize_resolves_dot() {
        assert_eq!(
            normalize_path(&PathBuf::from("/a/./b")),
            PathBuf::from("/a/b")
        );
    }

    #[cfg(unix)]
    #[test]
    fn guest_path_sensitive_prefixes_rejected() {
        assert!(validate_guest_path("/proc/self").is_err());
        assert!(validate_guest_path("/sys/kernel").is_err());
        assert!(validate_guest_path("/dev/null").is_err());
        assert!(validate_guest_path("/cidata/init.sh").is_err());
        assert!(validate_guest_path("/agent/bin").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn guest_path_bare_prefix_rejected() {
        assert!(validate_guest_path("/proc").is_err());
        assert!(validate_guest_path("/sys").is_err());
        assert!(validate_guest_path("/dev").is_err());
        assert!(validate_guest_path("/cidata").is_err());
        assert!(validate_guest_path("/agent").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn guest_path_root_rejected() {
        assert!(validate_guest_path("/").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn guest_path_etc_allowed() {
        assert!(validate_guest_path("/etc/hostname").is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn guest_path_similar_prefix_allowed() {
        assert!(validate_guest_path("/process_data").is_ok());
        assert!(validate_guest_path("/system/config").is_ok());
        assert!(validate_guest_path("/devices/usb").is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn guest_path_dot_component_rejected() {
        assert!(validate_guest_path("/proc/./self").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn guest_path_double_slash_rejected() {
        assert!(validate_guest_path("//proc/self").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn guest_path_trailing_slash_rejected() {
        assert!(validate_guest_path("/proc/").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn guest_file_content_empty_ok() {
        assert!(validate_guest_file_content("").is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn guest_file_content_at_limit_ok() {
        let content = "a".repeat(MAX_GUEST_FILE_SIZE);
        assert!(validate_guest_file_content(&content).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn guest_file_content_one_over_rejected() {
        let content = "a".repeat(MAX_GUEST_FILE_SIZE + 1);
        assert!(validate_guest_file_content(&content).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn work_dir_none_ok() {
        assert!(validate_work_dir(&None, &[], &[]).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn work_dir_relative_rejected() {
        let dir = Some(PathBuf::from("relative/path"));
        assert!(validate_work_dir(&dir, &[], &[]).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn work_dir_nonexistent_rejected() {
        let dir = Some(PathBuf::from("/nonexistent-arapuca-test-path"));
        assert!(validate_work_dir(&dir, &[], &[]).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn work_dir_file_not_dir_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("not-a-dir");
        std::fs::write(&file, "").unwrap();
        let dir = Some(file);
        let mounts = vec![tmp.path().to_path_buf()];
        assert!(validate_work_dir(&dir, &mounts, &[]).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn work_dir_outside_mounts_rejected() {
        let dir = Some(PathBuf::from("/tmp"));
        let mounts = vec![PathBuf::from("/usr")];
        assert!(validate_work_dir(&dir, &mounts, &[]).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn work_dir_in_read_paths_ok() {
        let dir = Some(PathBuf::from("/tmp"));
        let read = vec![PathBuf::from("/tmp")];
        assert!(validate_work_dir(&dir, &read, &[]).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn work_dir_in_write_paths_ok() {
        let dir = Some(PathBuf::from("/tmp"));
        let write = vec![PathBuf::from("/tmp")];
        assert!(validate_work_dir(&dir, &[], &write).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn work_dir_subdir_of_mount_ok() {
        let dir = Some(std::env::temp_dir());
        let mounts = vec![PathBuf::from("/")];
        assert!(validate_work_dir(&dir, &mounts, &[]).is_ok());
    }
}
