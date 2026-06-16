//! Cgroups v2 resource limit management.
//!
//! Manages per-task cgroups under the orchestrator's own cgroup path.
//! Provides memory, CPU, and PID limits with OOM detection and resource
//! usage telemetry.
//!
//! Graceful degradation: if cgroups v2 is unavailable or controllers are
//! not delegated, returns structured errors so the caller can decide the
//! degradation policy (not hardcoded log-and-continue).

use std::fs;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

use crate::{Error, ResourceUsage};

const CGROUP_PREFIX: &str = "arapuca-";
const LEAF_NAME: &str = "leaf";
const NEEDED_CONTROLLERS: &[&str] = &["memory", "pids", "cpu"];
const DESTROY_RETRIES: u32 = 3;
const DESTROY_BACKOFF: Duration = Duration::from_millis(100);
const CPU_PERIOD: i64 = 100_000; // microseconds

/// Result of creating a cgroup directory.
#[derive(Debug)]
pub struct CgroupCreateResult {
    pub path: PathBuf,
    pub swap_disabled: bool,
}

/// Resource limits for a cgroup.
#[derive(Debug, Clone, Default)]
pub struct CgroupLimits {
    /// Memory limit in MB (0 = no limit).
    pub memory_max_mb: u64,
    /// Maximum number of PIDs (0 = no limit).
    pub pids_max: u32,
    /// CPU percentage limit (0 = no limit; 200 = 2 cores).
    pub cpu_max_pct: u32,
    /// Extra PID slots for sandbox infrastructure (e.g. the PID
    /// namespace relay parent). Added to `pids_max` at the cgroup
    /// write site so the user's intent is preserved.
    pub pids_overhead: u32,
}

impl CgroupLimits {
    /// Returns true if any limits are set.
    pub fn has_limits(&self) -> bool {
        self.memory_max_mb > 0 || self.pids_max > 0 || self.cpu_max_pct > 0
    }

    /// Validate that limits are sensible.
    pub fn validate(&self) -> crate::Result<()> {
        // All fields are unsigned, so no negative check needed.
        Ok(())
    }
}

/// Manages per-agent cgroups v2 resource limits.
///
/// The base path is discovered from `/proc/self/cgroup` at startup.
/// Available controllers are detected from `cgroup.controllers`, then
/// enabled in `cgroup.subtree_control`. The `controllers` field holds
/// the final set of enabled controllers (what child cgroups inherit).
pub struct CgroupManager {
    base_path: PathBuf,
    controllers: Vec<String>,
}

impl CgroupManager {
    /// Create a new CgroupManager by probing the system.
    ///
    /// Returns `Ok(Some(mgr))` if cgroups v2 is available with delegated
    /// controllers, `Ok(None)` if unavailable (graceful degradation),
    /// or `Err` on unexpected errors.
    pub fn new() -> crate::Result<Option<Self>> {
        let base_path = match discover_cgroup_path() {
            Ok(p) => p,
            Err(e) => {
                log::info!("cgroup: unavailable: {e}");
                return Ok(None);
            }
        };

        let available = match read_cgroup_list(&base_path, "cgroup.controllers") {
            Ok(c) => c,
            Err(e) => {
                log::info!("cgroup: cannot read controllers: {e}");
                return Ok(None);
            }
        };

        if available.is_empty() {
            log::info!(
                "cgroup: no controllers available at {}",
                base_path.display()
            );
            return Ok(None);
        }

        if let Err(e) = enable_subtree_control(&base_path, &available) {
            log::warn!("cgroup: enable_subtree_control: {e}");
        }

        let controllers =
            read_cgroup_list(&base_path, "cgroup.subtree_control").unwrap_or_default();
        if controllers.is_empty() {
            log::info!("cgroup: no controllers enabled at {}", base_path.display());
            return Ok(None);
        }

        log::info!(
            "cgroup: available at {} (controllers: {})",
            base_path.display(),
            controllers.join(", ")
        );

        let mgr = Self {
            base_path,
            controllers,
        };

        mgr.cleanup_stale();
        Ok(Some(mgr))
    }

    /// Check whether a specific controller is delegated.
    pub fn has_controller(&self, name: &str) -> bool {
        self.controllers.iter().any(|c| c == name)
    }

    /// Create a cgroup for the given task with the specified limits.
    ///
    /// Returns the cgroup directory path and whether swap was disabled.
    /// On failure, any partially created directory is cleaned up.
    pub fn create(
        &self,
        task_id: &str,
        limits: &CgroupLimits,
    ) -> crate::Result<CgroupCreateResult> {
        let clean_id = crate::sanitize_task_id(task_id)?;
        limits.validate()?;

        let cg_path = self.base_path.join(format!("{CGROUP_PREFIX}{clean_id}"));

        fs::create_dir(&cg_path)
            .map_err(|e| Error::Cgroup(format!("mkdir {}: {e}", cg_path.display())))?;

        match self.write_controller_files(&cg_path, limits) {
            Ok(swap_disabled) => Ok(CgroupCreateResult {
                path: cg_path,
                swap_disabled,
            }),
            Err(e) => {
                let _ = fs::remove_dir(&cg_path);
                Err(e)
            }
        }
    }

    /// Write a PID to the cgroup's cgroup.procs file.
    pub fn add_pid(&self, cg_path: &Path, pid: u32) -> crate::Result<()> {
        let procs_path = cg_path.join("cgroup.procs");
        fs::write(&procs_path, pid.to_string())
            .map_err(|e| Error::Cgroup(format!("write {}: {e}", procs_path.display())))
    }

    /// Remove a cgroup directory.
    ///
    /// Handles non-empty cgroups by writing to `cgroup.kill` first,
    /// then retrying rmdir with backoff.
    pub fn destroy(&self, cg_path: &Path) -> crate::Result<()> {
        // Try cgroup.kill first (kernel 5.14+).
        let kill_path = cg_path.join("cgroup.kill");
        if fs::write(&kill_path, "1").is_err() {
            // Fallback: manually kill processes.
            self.kill_procs(cg_path);
        }

        for _ in 0..DESTROY_RETRIES {
            if fs::remove_dir(cg_path).is_ok() {
                return Ok(());
            }
            thread::sleep(DESTROY_BACKOFF);
        }

        // Non-fatal — orphaned empty cgroup is harmless.
        log::warn!("cgroup: could not remove {}", cg_path.display());
        Ok(())
    }

    /// Read OOM kill count from memory.events.
    ///
    /// Returns 0 if the file doesn't exist or can't be parsed.
    pub fn read_oom_events(&self, cg_path: &Path) -> u32 {
        let events_path = cg_path.join("memory.events");
        let data = match fs::read_to_string(&events_path) {
            Ok(d) => d,
            Err(_) => return 0,
        };
        for line in data.lines() {
            if let Some(rest) = line.strip_prefix("oom_kill ") {
                return rest.trim().parse().unwrap_or(0);
            }
        }
        0
    }

    /// Read resource usage from cgroup v2 stat files.
    ///
    /// Returns zero values for unavailable metrics. Never returns an
    /// error — this is best-effort telemetry.
    pub fn read_stats(&self, cg_path: &Path) -> ResourceUsage {
        let mut usage = ResourceUsage::default();

        if let Ok(v) = read_i64_file(cg_path, "memory.current") {
            usage.memory_current_bytes = v;
        }
        if let Ok(v) = read_i64_file(cg_path, "memory.peak") {
            usage.memory_peak_bytes = v;
        }

        // cpu.stat: usage_usec line.
        if let Ok(data) = fs::read_to_string(cg_path.join("cpu.stat")) {
            for line in data.lines() {
                if let Some(rest) = line.strip_prefix("usage_usec ") {
                    if let Ok(usec) = rest.trim().parse::<i64>() {
                        usage.cpu_usage_seconds = usec as f64 / 1e6;
                    }
                    break;
                }
            }
        }

        if let Ok(v) = read_i64_file(cg_path, "pids.current") {
            usage.pid_count = v;
        }

        // io.stat: sum rbytes/wbytes across all devices.
        if let Ok(data) = fs::read_to_string(cg_path.join("io.stat")) {
            for line in data.lines() {
                for field in line.split_whitespace() {
                    if let Some(val) = field.strip_prefix("rbytes=") {
                        if let Ok(v) = val.parse::<i64>() {
                            usage.io_read_bytes += v;
                        }
                    } else if let Some(val) = field.strip_prefix("wbytes=") {
                        if let Ok(v) = val.parse::<i64>() {
                            usage.io_write_bytes += v;
                        }
                    }
                }
            }
        }

        usage
    }

    /// Returns `Ok(true)` if all writes succeeded (swap disabled),
    /// `Ok(false)` if swap.max write failed (memory limits still applied).
    fn write_controller_files(&self, cg_path: &Path, limits: &CgroupLimits) -> crate::Result<bool> {
        let mut swap_disabled = true;
        if limits.memory_max_mb > 0 {
            if self.has_controller("memory") {
                let mem_max = limits
                    .memory_max_mb
                    .checked_mul(1024 * 1024)
                    .ok_or_else(|| Error::Cgroup("memory_max_mb overflow".into()))?;
                write_cgroup_file(cg_path, "memory.max", &mem_max.to_string())?;
                let mem_high = mem_max / 10 * 9;
                write_cgroup_file(cg_path, "memory.high", &mem_high.to_string())?;
                if let Err(e) = write_cgroup_file(cg_path, "memory.swap.max", "0") {
                    log::warn!("cgroup: memory.swap.max: {e} (continuing)");
                    swap_disabled = false;
                }
            } else {
                return Err(Error::CgroupDegraded(
                    "memory controller not delegated".into(),
                ));
            }
        }

        if limits.pids_max > 0 {
            if self.has_controller("pids") {
                let effective_pids = limits.pids_max.saturating_add(limits.pids_overhead);
                write_cgroup_file(cg_path, "pids.max", &effective_pids.to_string())?;
            } else {
                return Err(Error::CgroupDegraded(
                    "pids controller not delegated".into(),
                ));
            }
        }

        if limits.cpu_max_pct > 0 {
            if self.has_controller("cpu") {
                let quota = i64::from(limits.cpu_max_pct) * CPU_PERIOD / 100;
                let val = format!("{quota} {CPU_PERIOD}");
                write_cgroup_file(cg_path, "cpu.max", &val)?;
            } else {
                return Err(Error::CgroupDegraded("cpu controller not delegated".into()));
            }
        }

        Ok(swap_disabled)
    }

    /// Clean up leftover cgroup directories from previous sessions.
    fn cleanup_stale(&self) {
        let entries = match fs::read_dir(&self.base_path) {
            Ok(e) => e,
            Err(_) => return,
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if !entry.file_type().is_ok_and(|ft| ft.is_dir()) {
                continue;
            }

            if name_str == LEAF_NAME {
                // Stale leaf from a previous run: rmdir only (never
                // cgroup.kill — it could contain a sibling orchestrator).
                let leaf = entry.path();
                let procs = fs::read_to_string(leaf.join("cgroup.procs")).unwrap_or_default();
                if procs.trim().is_empty() && fs::remove_dir(&leaf).is_ok() {
                    log::info!("cgroup: cleaned up stale leaf");
                }
                continue;
            }

            if !name_str.starts_with(CGROUP_PREFIX) {
                continue;
            }

            let cg_path = entry.path();
            let kill_path = cg_path.join("cgroup.kill");
            if fs::write(&kill_path, "1").is_err() {
                self.kill_procs(&cg_path);
            }
            thread::sleep(DESTROY_BACKOFF);
            match fs::remove_dir(&cg_path) {
                Ok(()) => log::info!("cgroup: cleaned up stale cgroup {name_str}"),
                Err(e) => log::warn!("cgroup: stale cleanup: could not remove {name_str}: {e}"),
            }
        }
    }

    /// Send SIGKILL to all processes in a cgroup.
    fn kill_procs(&self, cg_path: &Path) {
        let procs_path = cg_path.join("cgroup.procs");
        let data = match fs::read_to_string(&procs_path) {
            Ok(d) => d,
            Err(_) => return,
        };
        for line in data.lines() {
            if let Ok(pid) = line.trim().parse::<i32>() {
                if pid > 0 {
                    // SAFETY: kill() with a valid signal is safe. The PID
                    // may no longer exist (race), which returns ESRCH (harmless).
                    unsafe {
                        libc::kill(pid, libc::SIGKILL);
                    }
                }
            }
        }
    }
}

/// Discover the orchestrator's own cgroup path from /proc/self/cgroup.
fn discover_cgroup_path() -> crate::Result<PathBuf> {
    let file = fs::File::open("/proc/self/cgroup")
        .map_err(|e| Error::Cgroup(format!("open /proc/self/cgroup: {e}")))?;

    let reader = BufReader::new(file);
    for line in reader.lines() {
        let line = line.map_err(|e| Error::Cgroup(format!("read /proc/self/cgroup: {e}")))?;
        // cgroups v2 unified hierarchy: "0::/<path>"
        if let Some(rel_path) = line.strip_prefix("0::") {
            let mut full_path =
                PathBuf::from("/sys/fs/cgroup").join(rel_path.trim_start_matches('/'));
            // Strip trailing /leaf segments left by previous leaf
            // dances, so we always operate on the scope root.
            while full_path.file_name().is_some_and(|n| n == LEAF_NAME) {
                full_path.pop();
            }
            if !full_path.is_dir() {
                return Err(Error::Cgroup(format!(
                    "cgroup path {} is not a directory",
                    full_path.display()
                )));
            }
            return Ok(full_path);
        }
    }

    Err(Error::Cgroup(
        "no cgroups v2 entry in /proc/self/cgroup".into(),
    ))
}

/// Enable controllers in `cgroup.subtree_control` so child cgroups
/// inherit them. Handles the cgroups v2 "no internal processes"
/// constraint via a leaf cgroup dance when needed.
fn enable_subtree_control(base_path: &Path, available: &[String]) -> crate::Result<()> {
    let filtered: Vec<&str> = available
        .iter()
        .filter(|c| NEEDED_CONTROLLERS.contains(&c.as_str()))
        .map(String::as_str)
        .collect();

    if filtered.is_empty() {
        return Ok(());
    }

    let current = read_cgroup_list(base_path, "cgroup.subtree_control").unwrap_or_default();
    let missing: Vec<&str> = filtered
        .iter()
        .filter(|c| !current.iter().any(|e| e == *c))
        .copied()
        .collect();

    if missing.is_empty() {
        return Ok(());
    }

    let batch: String = missing
        .iter()
        .map(|c| format!("+{c}"))
        .collect::<Vec<_>>()
        .join(" ");
    let sc_path = base_path.join("cgroup.subtree_control");

    match fs::write(&sc_path, &batch) {
        Ok(()) => {
            log::info!("cgroup: enabled subtree_control: {batch}");
            return Ok(());
        }
        Err(e) if e.raw_os_error() == Some(libc::EBUSY) => {
            // "No internal processes" constraint: move ALL processes
            // from the scope root into a leaf cgroup, then retry.
            // This handles the case where a parent process (e.g.,
            // viveiro or bash) shares the same delegated scope.
            let leaf_path = base_path.join(LEAF_NAME);
            if let Err(e) = fs::create_dir(&leaf_path) {
                if e.kind() != std::io::ErrorKind::AlreadyExists {
                    return Err(Error::Cgroup(format!("mkdir {}: {e}", leaf_path.display())));
                }
            }

            let leaf_procs = leaf_path.join("cgroup.procs");
            let root_procs = base_path.join("cgroup.procs");
            const MAX_DRAIN_ATTEMPTS: u32 = 3;

            for attempt in 0..MAX_DRAIN_ATTEMPTS {
                let data = fs::read_to_string(&root_procs).unwrap_or_default();
                let pids: Vec<&str> = data
                    .lines()
                    .map(|l| l.trim())
                    .filter(|l| !l.is_empty())
                    .collect();

                if pids.is_empty() {
                    break;
                }

                for pid in &pids {
                    match fs::write(&leaf_procs, pid) {
                        Ok(()) => {}
                        Err(e) if e.raw_os_error() == Some(libc::ESRCH) => {}
                        Err(e) => {
                            log::warn!("cgroup: cannot move PID {pid} to leaf: {e}");
                        }
                    }
                }

                if attempt + 1 < MAX_DRAIN_ATTEMPTS {
                    thread::sleep(Duration::from_millis(1));
                }
            }

            match fs::write(&sc_path, &batch) {
                Ok(()) => {
                    log::info!("cgroup: enabled subtree_control: {batch} (via leaf dance)");
                    return Ok(());
                }
                Err(retry_err) => {
                    return Err(Error::Cgroup(format!(
                        "enable subtree_control: {retry_err}",
                    )));
                }
            }
        }
        Err(e) => {
            log::debug!("cgroup: batch subtree_control failed: {e}, trying per-controller");
        }
    }

    // Per-controller fallback: try enabling one at a time.
    let mut enabled = 0u32;
    for controller in &missing {
        let enable = format!("+{controller}");
        match fs::write(&sc_path, &enable) {
            Ok(()) => {
                log::info!("cgroup: enabled controller: {controller}");
                enabled += 1;
            }
            Err(e) => log::warn!("cgroup: cannot enable {controller}: {e}"),
        }
    }

    if enabled == 0 {
        return Err(Error::Cgroup(
            "per-controller fallback: no controllers enabled".into(),
        ));
    }

    Ok(())
}

/// Read a space-separated list from a cgroup control file.
fn read_cgroup_list(cg_path: &Path, filename: &str) -> crate::Result<Vec<String>> {
    let path = cg_path.join(filename);
    let data = fs::read_to_string(&path)
        .map_err(|e| Error::Cgroup(format!("read {}: {e}", path.display())))?;
    Ok(data.split_whitespace().map(String::from).collect())
}

/// Read a single integer value from a cgroup stat file.
fn read_i64_file(dir: &Path, name: &str) -> Result<i64, ()> {
    let data = fs::read_to_string(dir.join(name)).map_err(|_| ())?;
    data.trim().parse().map_err(|_| ())
}

/// Write a value to a cgroup controller file.
fn write_cgroup_file(dir: &Path, name: &str, value: &str) -> crate::Result<()> {
    let path = dir.join(name);
    fs::write(&path, value).map_err(|e| Error::Cgroup(format!("{}: {e}", path.display())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cgroup_limits_default_has_no_limits() {
        let limits = CgroupLimits::default();
        assert!(!limits.has_limits());
    }

    #[test]
    fn cgroup_limits_with_memory() {
        let limits = CgroupLimits {
            memory_max_mb: 2048,
            ..Default::default()
        };
        assert!(limits.has_limits());
    }

    #[test]
    fn cgroup_limits_validate() {
        let limits = CgroupLimits {
            memory_max_mb: 2048,
            pids_max: 256,
            cpu_max_pct: 200,
            ..Default::default()
        };
        assert!(limits.validate().is_ok());
    }

    #[test]
    fn discover_cgroup_path_works() {
        // On Linux, this should find a cgroup path.
        // On non-Linux, it will fail gracefully.
        match discover_cgroup_path() {
            Ok(path) => {
                assert!(path.starts_with("/sys/fs/cgroup"));
                eprintln!("cgroup path: {}", path.display());
            }
            Err(e) => {
                eprintln!("cgroup unavailable: {e}");
            }
        }
    }

    #[test]
    fn cgroup_manager_new() {
        match CgroupManager::new() {
            Ok(Some(mgr)) => {
                eprintln!(
                    "cgroup manager: {} controllers: {:?}",
                    mgr.base_path.display(),
                    mgr.controllers
                );
                assert!(!mgr.controllers.is_empty());
            }
            Ok(None) => {
                eprintln!("cgroup: not available (OK for non-Linux)");
            }
            Err(e) => {
                eprintln!("cgroup error: {e}");
            }
        }
    }

    #[test]
    fn read_stats_nonexistent() {
        // Reading stats from a nonexistent path should return defaults.
        let mgr = CgroupManager {
            base_path: PathBuf::from("/nonexistent"),
            controllers: vec![],
        };
        let stats = mgr.read_stats(Path::new("/nonexistent-cgroup"));
        assert_eq!(stats.memory_current_bytes, 0);
        assert_eq!(stats.pid_count, 0);
    }

    #[test]
    fn read_cgroup_list_parses_space_separated() {
        let dir = std::env::temp_dir().join("arapuca-test-cgroup-list");
        let _ = fs::create_dir(&dir);
        fs::write(dir.join("controllers"), "memory pids cpu\n").unwrap();
        let result = read_cgroup_list(&dir, "controllers").unwrap();
        assert_eq!(result, vec!["memory", "pids", "cpu"]);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn read_cgroup_list_empty_file() {
        let dir = std::env::temp_dir().join("arapuca-test-cgroup-empty");
        let _ = fs::create_dir(&dir);
        fs::write(dir.join("controllers"), "").unwrap();
        let result = read_cgroup_list(&dir, "controllers").unwrap();
        assert!(result.is_empty());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn read_cgroup_list_trailing_whitespace() {
        let dir = std::env::temp_dir().join("arapuca-test-cgroup-ws");
        let _ = fs::create_dir(&dir);
        fs::write(dir.join("controllers"), "  memory  pids  \n").unwrap();
        let result = read_cgroup_list(&dir, "controllers").unwrap();
        assert_eq!(result, vec!["memory", "pids"]);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn read_cgroup_list_missing_file() {
        let dir = std::env::temp_dir().join("arapuca-test-cgroup-missing");
        let _ = fs::create_dir(&dir);
        assert!(read_cgroup_list(&dir, "nonexistent").is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn enable_subtree_control_already_enabled() {
        let dir = std::env::temp_dir().join("arapuca-test-esc-noop");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("cgroup.subtree_control"), "memory pids cpu\n").unwrap();
        let available = vec!["memory".into(), "pids".into(), "cpu".into()];
        let result = enable_subtree_control(&dir, &available);
        assert!(result.is_ok());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn enable_subtree_control_filters_needed() {
        let dir = std::env::temp_dir().join("arapuca-test-esc-filter");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("cgroup.subtree_control"), "memory pids cpu\n").unwrap();
        let available: Vec<String> = vec![
            "memory".into(),
            "pids".into(),
            "cpu".into(),
            "io".into(),
            "rdma".into(),
        ];
        let result = enable_subtree_control(&dir, &available);
        assert!(result.is_ok());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn enable_subtree_control_no_needed_available() {
        let dir = std::env::temp_dir().join("arapuca-test-esc-none");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let available: Vec<String> = vec!["io".into(), "rdma".into()];
        let result = enable_subtree_control(&dir, &available);
        assert!(result.is_ok());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn enable_subtree_control_writes_batch_when_none_enabled() {
        let dir = std::env::temp_dir().join("arapuca-test-esc-write-all");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("cgroup.subtree_control"), "\n").unwrap();
        let available: Vec<String> = vec!["memory".into(), "pids".into(), "cpu".into()];
        let result = enable_subtree_control(&dir, &available);
        assert!(result.is_ok());
        let written = fs::read_to_string(dir.join("cgroup.subtree_control")).unwrap();
        assert!(written.contains("+memory"));
        assert!(written.contains("+pids"));
        assert!(written.contains("+cpu"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn enable_subtree_control_writes_only_missing() {
        let dir = std::env::temp_dir().join("arapuca-test-esc-partial");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("cgroup.subtree_control"), "memory\n").unwrap();
        let available: Vec<String> = vec!["memory".into(), "pids".into(), "cpu".into()];
        let result = enable_subtree_control(&dir, &available);
        assert!(result.is_ok());
        let written = fs::read_to_string(dir.join("cgroup.subtree_control")).unwrap();
        assert!(written.contains("+pids"));
        assert!(written.contains("+cpu"));
        assert!(!written.contains("+memory"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn cleanup_stale_removes_empty_leaf() {
        let dir = std::env::temp_dir().join("arapuca-test-cleanup-leaf");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let leaf = dir.join("leaf");
        fs::create_dir(&leaf).unwrap();
        // No cgroup.procs file: read_to_string returns Err,
        // unwrap_or_default gives "", which is "empty". On a real
        // cgroupfs the kernel pseudo-files don't block rmdir; here
        // the empty directory lets remove_dir succeed.
        let mgr = CgroupManager {
            base_path: dir.clone(),
            controllers: vec!["memory".into()],
        };
        mgr.cleanup_stale();
        assert!(!leaf.exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn cleanup_stale_preserves_occupied_leaf() {
        let dir = std::env::temp_dir().join("arapuca-test-cleanup-leaf-busy");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let leaf = dir.join("leaf");
        fs::create_dir(&leaf).unwrap();
        fs::write(leaf.join("cgroup.procs"), "12345\n").unwrap();
        let mgr = CgroupManager {
            base_path: dir.clone(),
            controllers: vec!["memory".into()],
        };
        mgr.cleanup_stale();
        assert!(leaf.exists());
        let _ = fs::remove_dir_all(&dir);
    }
}
