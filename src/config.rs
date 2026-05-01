//! TOML configuration file support for arapuca.
//!
//! Provides structured configuration via TOML files with precedence:
//! CLI flags > project config > user config > environment variables > defaults
//!
//! Configuration files are loaded from:
//! - User config: `~/.config/arapuca/config.toml`
//! - Project config: `./arapuca.toml` or `./.arapuca.toml`
//! - Custom path: via `--config` CLI flag

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::{GuestFile, ImageSource, Isolation, MicroVmConfig, Profile};

/// Validation severity level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ValidationLevel {
    Error,
    Warning,
    Info,
}

/// A validation issue found in configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationIssue {
    pub level: ValidationLevel,
    pub location: String,
    pub message: String,
    pub suggestion: Option<String>,
}

/// Options for config validation.
#[derive(Debug, Clone, Default)]
pub struct ValidateOptions {
    pub strict: bool,
    pub check_paths: bool,
    pub check_images: bool,
}

/// Root TOML configuration structure.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(default)]
pub struct ArapucaConfig {
    pub general: GeneralConfig,
    pub sandbox: SandboxConfig,
    pub resources: ResourcesConfig,
    pub network: NetworkConfig,
    pub microvm: Option<TomlMicroVmConfig>,
    pub env: HashMap<String, String>,
    pub audit: AuditConfig,
    pub vm: VmConfig,
}

/// General configuration (task ID, working directory, etc.).
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(default)]
pub struct GeneralConfig {
    pub task_id: Option<String>,
    pub work_dir: Option<PathBuf>,
    pub socket_dir: Option<PathBuf>,
    pub phase: Option<String>,
}

/// Sandbox configuration (isolation type, paths, etc.).
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct SandboxConfig {
    pub isolation: String,
    pub allow_exec: bool,
    pub use_netns: bool,
    pub read_paths: Vec<PathBuf>,
    pub write_paths: Vec<PathBuf>,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            isolation: "process".into(),
            allow_exec: true,
            use_netns: true,
            read_paths: Vec::new(),
            write_paths: Vec::new(),
        }
    }
}

/// Resource limits configuration.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(default)]
pub struct ResourcesConfig {
    pub max_memory_mb: u64,
    pub max_cpu_pct: u32,
    pub max_pids: u32,
    pub max_file_size_mb: u64,
}

/// Network configuration.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(default)]
pub struct NetworkConfig {
    pub proxy_socket: Option<PathBuf>,
    pub proxy_bridge: Option<String>,
}

/// MicroVM configuration (TOML representation).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TomlMicroVmConfig {
    pub image: String,
    #[serde(default = "default_cpus")]
    pub cpus: u32,
    #[serde(default = "default_mem")]
    pub mem_mb: u32,
    #[serde(default)]
    pub enable_network: bool,
    #[serde(default)]
    pub timeout: Option<u64>,
    pub name: Option<String>,
    pub max_lifetime: Option<u64>,
    #[serde(default)]
    pub volume: Vec<VolumeConfig>,
    #[serde(default)]
    pub write_file: Vec<WriteFileConfig>,
}

/// Volume mount configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct VolumeConfig {
    pub host: String,
    pub guest: String,
    #[serde(default)]
    pub read_only: bool,
}

/// File injection configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WriteFileConfig {
    pub host_path: String,
    pub guest_path: String,
    #[serde(default = "default_permissions")]
    pub permissions: String,
}

/// Audit configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct AuditConfig {
    pub verbosity: String,
    pub principal: Option<String>,
    pub correlation_id: Option<String>,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            verbosity: "standard".into(),
            principal: None,
            correlation_id: None,
        }
    }
}

/// VM subcommand configuration.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(default)]
pub struct VmConfig {
    pub exec: VmExecConfig,
    pub stop: VmStopConfig,
}

/// VM exec configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct VmExecConfig {
    pub user: String,
    pub tty: bool,
    pub env: HashMap<String, String>,
}

impl Default for VmExecConfig {
    fn default() -> Self {
        Self {
            user: "root".into(),
            tty: false,
            env: HashMap::new(),
        }
    }
}

/// VM stop configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct VmStopConfig {
    pub force: bool,
    pub timeout: u64,
}

impl Default for VmStopConfig {
    fn default() -> Self {
        Self {
            force: false,
            timeout: 10,
        }
    }
}

// Default value functions for serde.
fn default_cpus() -> u32 {
    2
}

fn default_mem() -> u32 {
    4096
}

fn default_permissions() -> String {
    "0644".into()
}

impl ArapucaConfig {
    /// Load configuration with precedence: CLI > project > user > env > defaults.
    pub fn load() -> crate::Result<Self> {
        let mut config = Self::default();

        // 1. Load user config (~/.config/arapuca/config.toml).
        if let Some(user_config) = Self::load_user_config()? {
            config.merge(user_config);
        }

        // 2. Load project config (./arapuca.toml or ./.arapuca.toml).
        if let Some(project_config) = Self::load_project_config()? {
            config.merge(project_config);
        }

        // 3. Merge from environment variables (backward compatibility).
        config.merge_from_env();

        Ok(config)
    }

    /// Load configuration from a custom path.
    pub fn load_from_path(path: &PathBuf) -> crate::Result<Self> {
        if !path.exists() {
            return Err(crate::Error::Config(format!(
                "configuration file not found: {}",
                path.display()
            )));
        }
        let content = std::fs::read_to_string(path).map_err(|e| {
            crate::Error::Config(format!("cannot read {}: {}", path.display(), e))
        })?;
        let config: Self = toml::from_str(&content).map_err(|e| {
            crate::Error::Config(format!("invalid TOML in {}: {}", path.display(), e))
        })?;
        Ok(config)
    }

    fn load_user_config() -> crate::Result<Option<Self>> {
        let path = match dirs::config_dir() {
            Some(dir) => dir.join("arapuca").join("config.toml"),
            None => return Ok(None),
        };
        Self::load_from_path_optional(&path)
    }

    fn load_project_config() -> crate::Result<Option<Self>> {
        // Check ./arapuca.toml then ./.arapuca.toml.
        for name in &["arapuca.toml", ".arapuca.toml"] {
            let path = PathBuf::from(name);
            if let Some(cfg) = Self::load_from_path_optional(&path)? {
                return Ok(Some(cfg));
            }
        }
        Ok(None)
    }

    fn load_from_path_optional(path: &PathBuf) -> crate::Result<Option<Self>> {
        if !path.exists() {
            return Ok(None);
        }
        Self::load_from_path(path).map(Some)
    }

    /// Merge another config into this one. Non-default values from `other` override `self`.
    pub fn merge(&mut self, other: Self) {
        // General config.
        if other.general.task_id.is_some() {
            self.general.task_id = other.general.task_id;
        }
        if other.general.work_dir.is_some() {
            self.general.work_dir = other.general.work_dir;
        }
        if other.general.socket_dir.is_some() {
            self.general.socket_dir = other.general.socket_dir;
        }
        if other.general.phase.is_some() {
            self.general.phase = other.general.phase;
        }

        // Sandbox config (arrays replace, not merge).
        if other.sandbox.isolation != "process" {
            self.sandbox.isolation = other.sandbox.isolation;
        }
        if !other.sandbox.read_paths.is_empty() {
            self.sandbox.read_paths = other.sandbox.read_paths;
        }
        if !other.sandbox.write_paths.is_empty() {
            self.sandbox.write_paths = other.sandbox.write_paths;
        }
        self.sandbox.allow_exec = other.sandbox.allow_exec;
        self.sandbox.use_netns = other.sandbox.use_netns;

        // Resources.
        if other.resources.max_memory_mb > 0 {
            self.resources.max_memory_mb = other.resources.max_memory_mb;
        }
        if other.resources.max_cpu_pct > 0 {
            self.resources.max_cpu_pct = other.resources.max_cpu_pct;
        }
        if other.resources.max_pids > 0 {
            self.resources.max_pids = other.resources.max_pids;
        }
        if other.resources.max_file_size_mb > 0 {
            self.resources.max_file_size_mb = other.resources.max_file_size_mb;
        }

        // Network.
        if other.network.proxy_socket.is_some() {
            self.network.proxy_socket = other.network.proxy_socket;
        }
        if other.network.proxy_bridge.is_some() {
            self.network.proxy_bridge = other.network.proxy_bridge;
        }

        // MicroVM.
        if other.microvm.is_some() {
            self.microvm = other.microvm;
        }

        // Environment variables (merge maps).
        self.env.extend(other.env);

        // Audit.
        if other.audit.verbosity != "standard" {
            self.audit.verbosity = other.audit.verbosity;
        }
        if other.audit.principal.is_some() {
            self.audit.principal = other.audit.principal;
        }
        if other.audit.correlation_id.is_some() {
            self.audit.correlation_id = other.audit.correlation_id;
        }

        // VM exec/stop config.
        if other.vm.exec.user != "root" {
            self.vm.exec.user = other.vm.exec.user;
        }
        self.vm.exec.tty = other.vm.exec.tty;
        self.vm.exec.env.extend(other.vm.exec.env);
        self.vm.stop.force = other.vm.stop.force;
        if other.vm.stop.timeout != 10 {
            self.vm.stop.timeout = other.vm.stop.timeout;
        }
    }

    /// Merge configuration from environment variables (backward compatibility).
    fn merge_from_env(&mut self) {
        // ARAPUCA_READ_PATHS
        if let Ok(paths) = std::env::var("ARAPUCA_READ_PATHS") {
            self.sandbox.read_paths = crate::env::parse_paths(&paths);
        }

        // ARAPUCA_WRITE_PATHS
        if let Ok(paths) = std::env::var("ARAPUCA_WRITE_PATHS") {
            self.sandbox.write_paths = crate::env::parse_paths(&paths);
        }

        // ARAPUCA_RLIMIT_AS
        if let Ok(val) = std::env::var("ARAPUCA_RLIMIT_AS") {
            if let Ok(bytes) = val.parse::<u64>() {
                self.resources.max_memory_mb = bytes / (1024 * 1024);
            }
        }

        // ARAPUCA_RLIMIT_NPROC
        if let Ok(val) = std::env::var("ARAPUCA_RLIMIT_NPROC") {
            if let Ok(n) = val.parse::<u32>() {
                self.resources.max_pids = n;
            }
        }

        // ARAPUCA_RLIMIT_FSIZE
        if let Ok(val) = std::env::var("ARAPUCA_RLIMIT_FSIZE") {
            if let Ok(bytes) = val.parse::<u64>() {
                self.resources.max_file_size_mb = bytes / (1024 * 1024);
            }
        }
    }

    /// Convert TOML configuration to arapuca::Profile.
    pub fn to_profile(&self) -> crate::Result<Profile> {
        let isolation = match self.sandbox.isolation.as_str() {
            "process" => Isolation::Process,
            "microvm" => {
                let vm_cfg = self.microvm.as_ref().ok_or_else(|| {
                    crate::Error::Config(
                        "isolation=microvm requires [microvm] section".into(),
                    )
                })?;
                Isolation::MicroVm(self.parse_microvm_config(vm_cfg)?)
            }
            other => {
                return Err(crate::Error::Config(format!(
                    "invalid isolation type: {other} (expected 'process' or 'microvm')"
                )));
            }
        };

        Ok(Profile {
            isolation,
            read_paths: self.sandbox.read_paths.clone(),
            write_paths: self.sandbox.write_paths.clone(),
            max_memory_mb: self.resources.max_memory_mb,
            max_cpu_pct: self.resources.max_cpu_pct,
            max_pids: self.resources.max_pids,
            max_file_size_mb: self.resources.max_file_size_mb,
            allow_exec: self.sandbox.allow_exec,
            use_netns: self.sandbox.use_netns,
        })
    }

    fn parse_microvm_config(&self, cfg: &TomlMicroVmConfig) -> crate::Result<MicroVmConfig> {
        let image = self.parse_image_source(&cfg.image)?;

        let write_files: Vec<GuestFile> = cfg
            .write_file
            .iter()
            .map(|wf| {
                let content = std::fs::read_to_string(&wf.host_path).map_err(|e| {
                    crate::Error::Config(format!(
                        "cannot read {}: {}",
                        wf.host_path, e
                    ))
                })?;
                Ok(GuestFile {
                    path: wf.guest_path.clone(),
                    content,
                    permissions: Some(wf.permissions.clone()),
                })
            })
            .collect::<crate::Result<Vec<_>>>()?;

        Ok(MicroVmConfig {
            image,
            cpus: cfg.cpus,
            mem_mb: cfg.mem_mb,
            write_files,
        })
    }

    fn parse_image_source(&self, spec: &str) -> crate::Result<ImageSource> {
        if spec.contains('/') || spec.ends_with(".qcow2") || spec.ends_with(".raw") {
            Ok(ImageSource::Path(PathBuf::from(spec)))
        } else if let Some((distro, version)) = spec.split_once(':') {
            if distro.is_empty() || version.is_empty() {
                return Err(crate::Error::Config(format!(
                    "invalid image: {spec} (expected distro:version or path)"
                )));
            }
            Ok(ImageSource::Distro {
                name: distro.to_string(),
                version: version.to_string(),
            })
        } else {
            Err(crate::Error::Config(format!(
                "invalid image: {spec} (expected distro:version or path)"
            )))
        }
    }

    /// Validate configuration, returning all issues found.
    pub fn validate(&self, opts: &ValidateOptions) -> Vec<ValidationIssue> {
        let mut issues = Vec::new();

        // Structure validation
        issues.extend(self.validate_structure());

        // Value validation
        issues.extend(self.validate_values());

        // Cross-field validation
        issues.extend(self.validate_consistency());

        // Optional: filesystem checks
        if opts.check_paths {
            issues.extend(self.validate_paths());
        }

        // Optional: image checks
        if opts.check_images {
            issues.extend(self.validate_images());
        }

        issues
    }

    fn validate_structure(&self) -> Vec<ValidationIssue> {
        let mut issues = Vec::new();

        // Required fields for microvm
        if self.sandbox.isolation == "microvm" {
            if self.microvm.is_none() {
                issues.push(ValidationIssue {
                    level: ValidationLevel::Error,
                    location: "[microvm]".into(),
                    message: "isolation=microvm requires [microvm] section".into(),
                    suggestion: Some(
                        "Add [microvm] section with image, cpus, and mem_mb".into(),
                    ),
                });
            }
        }

        // Invalid isolation type
        if self.sandbox.isolation != "process" && self.sandbox.isolation != "microvm" {
            issues.push(ValidationIssue {
                level: ValidationLevel::Error,
                location: "sandbox.isolation".into(),
                message: format!(
                    "invalid isolation type: '{}' (expected 'process' or 'microvm')",
                    self.sandbox.isolation
                ),
                suggestion: Some("isolation = \"process\"".into()),
            });
        }

        issues
    }

    fn validate_values(&self) -> Vec<ValidationIssue> {
        let mut issues = Vec::new();

        // MicroVM numeric ranges
        if let Some(ref vm) = self.microvm {
            if vm.cpus == 0 {
                issues.push(ValidationIssue {
                    level: ValidationLevel::Error,
                    location: "microvm.cpus".into(),
                    message: "must be > 0".into(),
                    suggestion: Some("cpus = 2".into()),
                });
            }

            if vm.mem_mb == 0 {
                issues.push(ValidationIssue {
                    level: ValidationLevel::Error,
                    location: "microvm.mem_mb".into(),
                    message: "must be > 0".into(),
                    suggestion: Some("mem_mb = 2048".into()),
                });
            } else if vm.mem_mb < 128 {
                issues.push(ValidationIssue {
                    level: ValidationLevel::Warning,
                    location: "microvm.mem_mb".into(),
                    message: format!(
                        "{}MB is very low, minimum 128MB recommended",
                        vm.mem_mb
                    ),
                    suggestion: Some("mem_mb = 2048".into()),
                });
            }

            // Check volume paths
            for (idx, vol) in vm.volume.iter().enumerate() {
                if !vol.guest.starts_with('/') {
                    issues.push(ValidationIssue {
                        level: ValidationLevel::Error,
                        location: format!("microvm.volume[{}].guest", idx),
                        message: format!(
                            "guest path must be absolute: '{}'",
                            vol.guest
                        ),
                        suggestion: Some(format!("guest = \"{}\"", vol.guest)),
                    });
                }
            }

            // Check write_file paths
            for (idx, wf) in vm.write_file.iter().enumerate() {
                if !wf.guest_path.starts_with('/') {
                    issues.push(ValidationIssue {
                        level: ValidationLevel::Error,
                        location: format!("microvm.write_file[{}].guest_path", idx),
                        message: format!(
                            "guest path must be absolute: '{}'",
                            wf.guest_path
                        ),
                        suggestion: Some(format!("guest_path = \"{}\"", wf.guest_path)),
                    });
                }
            }
        }

        // Resource limits sanity
        if self.resources.max_memory_mb > 0 {
            if let Ok(system_mem) = get_system_memory_mb() {
                if self.resources.max_memory_mb > system_mem {
                    issues.push(ValidationIssue {
                        level: ValidationLevel::Warning,
                        location: "resources.max_memory_mb".into(),
                        message: format!(
                            "{}MB exceeds system memory ({}MB)",
                            self.resources.max_memory_mb, system_mem
                        ),
                        suggestion: Some(format!("max_memory_mb = {}", system_mem / 2)),
                    });
                }
            }
        }

        // Audit verbosity
        if !matches!(
            self.audit.verbosity.as_str(),
            "minimal" | "standard" | "verbose"
        ) {
            issues.push(ValidationIssue {
                level: ValidationLevel::Error,
                location: "audit.verbosity".into(),
                message: format!(
                    "invalid verbosity: '{}' (expected 'minimal', 'standard', or 'verbose')",
                    self.audit.verbosity
                ),
                suggestion: Some("verbosity = \"standard\"".into()),
            });
        }

        issues
    }

    fn validate_consistency(&self) -> Vec<ValidationIssue> {
        let mut issues = Vec::new();

        // Check for path overlaps (write_path shouldn't contain read_path)
        for (widx, write_path) in self.sandbox.write_paths.iter().enumerate() {
            for (ridx, read_path) in self.sandbox.read_paths.iter().enumerate() {
                if read_path.starts_with(write_path) && read_path != write_path {
                    issues.push(ValidationIssue {
                        level: ValidationLevel::Info,
                        location: format!("sandbox.read_paths[{}]", ridx),
                        message: format!(
                            "{} is redundant (covered by write_paths[{}]: {})",
                            read_path.display(),
                            widx,
                            write_path.display()
                        ),
                        suggestion: None,
                    });
                }
            }
        }

        issues
    }

    fn validate_paths(&self) -> Vec<ValidationIssue> {
        let mut issues = Vec::new();

        for (idx, path) in self.sandbox.read_paths.iter().enumerate() {
            if !path.exists() {
                issues.push(ValidationIssue {
                    level: ValidationLevel::Warning,
                    location: format!("sandbox.read_paths[{}]", idx),
                    message: format!("path does not exist: {}", path.display()),
                    suggestion: Some(
                        "Create the directory or remove from config".into(),
                    ),
                });
            }
        }

        for (idx, path) in self.sandbox.write_paths.iter().enumerate() {
            if !path.exists() {
                issues.push(ValidationIssue {
                    level: ValidationLevel::Warning,
                    location: format!("sandbox.write_paths[{}]", idx),
                    message: format!("path does not exist: {}", path.display()),
                    suggestion: Some(
                        "Create the directory or remove from config".into(),
                    ),
                });
            }
        }

        // Check microvm volume host paths
        if let Some(ref vm) = self.microvm {
            for (idx, vol) in vm.volume.iter().enumerate() {
                let host_path = Path::new(&vol.host);
                if !host_path.exists() {
                    issues.push(ValidationIssue {
                        level: ValidationLevel::Warning,
                        location: format!("microvm.volume[{}].host", idx),
                        message: format!("path does not exist: {}", vol.host),
                        suggestion: Some(
                            "Create the directory or remove this volume".into(),
                        ),
                    });
                }
            }

            // Check write_file host paths
            for (idx, wf) in vm.write_file.iter().enumerate() {
                let host_path = Path::new(&wf.host_path);
                if !host_path.exists() {
                    issues.push(ValidationIssue {
                        level: ValidationLevel::Error,
                        location: format!("microvm.write_file[{}].host_path", idx),
                        message: format!("file does not exist: {}", wf.host_path),
                        suggestion: Some("Create the file or remove this entry".into()),
                    });
                }
            }
        }

        issues
    }

    fn validate_images(&self) -> Vec<ValidationIssue> {
        let mut issues = Vec::new();

        if let Some(ref vm) = self.microvm {
            // Parse the image source
            if let Ok(image_source) = self.parse_image_source(&vm.image) {
                match image_source {
                    ImageSource::Path(ref path) => {
                        if !path.exists() {
                            issues.push(ValidationIssue {
                                level: ValidationLevel::Error,
                                location: "microvm.image".into(),
                                message: format!(
                                    "image file does not exist: {}",
                                    path.display()
                                ),
                                suggestion: Some(
                                    "Provide a valid path or use distro:version format"
                                        .into(),
                                ),
                            });
                        }
                    }
                    ImageSource::Distro { ref name, .. } => {
                        // Check if it's a known distro
                        if !matches!(name.as_str(), "fedora" | "centos") {
                            issues.push(ValidationIssue {
                                level: ValidationLevel::Warning,
                                location: "microvm.image".into(),
                                message: format!(
                                    "unknown distro: '{}' (built-in: fedora, centos)",
                                    name
                                ),
                                suggestion: Some(
                                    "Use a known distro or provide a file path".into(),
                                ),
                            });
                        }
                    }
                }
            }
        }

        issues
    }

    /// Create config from environment variables only.
    pub fn from_env_only() -> Self {
        let mut config = Self::default();
        config.merge_from_env();
        config
    }
}

/// Get system memory in MB (best effort).
fn get_system_memory_mb() -> crate::Result<u64> {
    #[cfg(target_os = "linux")]
    {
        let meminfo = std::fs::read_to_string("/proc/meminfo")
            .map_err(|e| crate::Error::Io(e))?;
        for line in meminfo.lines() {
            if let Some(mem) = line.strip_prefix("MemTotal:") {
                let kb: u64 = mem
                    .trim()
                    .split_whitespace()
                    .next()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
                return Ok(kb / 1024);
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        // Fallback: assume 8GB
        return Ok(8192);
    }
    Ok(0)
}

// ─── TOML Generation ───────────────────────────────────────────────

/// Style for generating TOML output.
#[derive(Debug, Clone, Copy)]
pub enum TomlStyle {
    /// Only include non-default settings
    Minimal,
    /// Include all options with comments
    Full,
}

/// Template for config generation.
#[derive(Debug, Clone, Copy)]
pub enum ConfigTemplate {
    Process,
    MicroVm,
    Strict,
}

/// Generate TOML configuration string.
pub fn generate_toml(config: &ArapucaConfig, style: TomlStyle) -> String {
    match style {
        TomlStyle::Minimal => generate_minimal_toml(config),
        TomlStyle::Full => generate_full_toml(config),
    }
}

/// Generate minimal TOML (only non-default values).
fn generate_minimal_toml(config: &ArapucaConfig) -> String {
    let mut output = String::new();
    output.push_str("# Generated by arapuca config init\n");
    output.push_str("# Configuration based on current environment\n\n");

    // General section
    if has_non_default_general(config) {
        output.push_str("[general]\n");
        if let Some(ref task_id) = config.general.task_id {
            output.push_str(&format!("task_id = \"{}\"\n", task_id));
        }
        if let Some(ref work_dir) = config.general.work_dir {
            output.push_str(&format!("work_dir = \"{}\"\n", work_dir.display()));
        }
        if let Some(ref socket_dir) = config.general.socket_dir {
            output.push_str(&format!("socket_dir = \"{}\"\n", socket_dir.display()));
        }
        if let Some(ref phase) = config.general.phase {
            output.push_str(&format!("phase = \"{}\"\n", phase));
        }
        output.push('\n');
    }

    // Sandbox section
    if has_non_default_sandbox(config) {
        output.push_str("[sandbox]\n");
        if config.sandbox.isolation != "process" {
            output.push_str(&format!("isolation = \"{}\"\n", config.sandbox.isolation));
        }
        if !config.sandbox.read_paths.is_empty() {
            output.push_str(&format!(
                "read_paths = {}\n",
                format_path_array(&config.sandbox.read_paths)
            ));
        }
        if !config.sandbox.write_paths.is_empty() {
            output.push_str(&format!(
                "write_paths = {}\n",
                format_path_array(&config.sandbox.write_paths)
            ));
        }
        if !config.sandbox.allow_exec {
            output.push_str("allow_exec = false\n");
        }
        if !config.sandbox.use_netns {
            output.push_str("use_netns = false\n");
        }
        output.push('\n');
    }

    // Resources section
    if has_non_default_resources(config) {
        output.push_str("[resources]\n");
        if config.resources.max_memory_mb > 0 {
            output.push_str(&format!(
                "max_memory_mb = {}\n",
                config.resources.max_memory_mb
            ));
        }
        if config.resources.max_cpu_pct > 0 {
            output.push_str(&format!("max_cpu_pct = {}\n", config.resources.max_cpu_pct));
        }
        if config.resources.max_pids > 0 {
            output.push_str(&format!("max_pids = {}\n", config.resources.max_pids));
        }
        if config.resources.max_file_size_mb > 0 {
            output.push_str(&format!(
                "max_file_size_mb = {}\n",
                config.resources.max_file_size_mb
            ));
        }
        output.push('\n');
    }

    // Network section
    if config.network.proxy_socket.is_some() || config.network.proxy_bridge.is_some() {
        output.push_str("[network]\n");
        if let Some(ref proxy_socket) = config.network.proxy_socket {
            output.push_str(&format!(
                "proxy_socket = \"{}\"\n",
                proxy_socket.display()
            ));
        }
        if let Some(ref proxy_bridge) = config.network.proxy_bridge {
            output.push_str(&format!("proxy_bridge = \"{}\"\n", proxy_bridge));
        }
        output.push('\n');
    }

    // MicroVM section
    if let Some(ref vm) = config.microvm {
        output.push_str("[microvm]\n");
        output.push_str(&format!("image = \"{}\"\n", vm.image));
        output.push_str(&format!("cpus = {}\n", vm.cpus));
        output.push_str(&format!("mem_mb = {}\n", vm.mem_mb));
        if vm.enable_network {
            output.push_str("enable_network = true\n");
        }
        if let Some(timeout) = vm.timeout {
            output.push_str(&format!("timeout = {}\n", timeout));
        }
        if let Some(ref name) = vm.name {
            output.push_str(&format!("name = \"{}\"\n", name));
        }
        output.push('\n');

        // Volumes
        for vol in &vm.volume {
            output.push_str("[[microvm.volume]]\n");
            output.push_str(&format!("host = \"{}\"\n", vol.host));
            output.push_str(&format!("guest = \"{}\"\n", vol.guest));
            if vol.read_only {
                output.push_str("read_only = true\n");
            }
            output.push('\n');
        }

        // Write files
        for wf in &vm.write_file {
            output.push_str("[[microvm.write_file]]\n");
            output.push_str(&format!("host_path = \"{}\"\n", wf.host_path));
            output.push_str(&format!("guest_path = \"{}\"\n", wf.guest_path));
            if wf.permissions != "0644" {
                output.push_str(&format!("permissions = \"{}\"\n", wf.permissions));
            }
            output.push('\n');
        }
    }

    // Environment variables
    if !config.env.is_empty() {
        output.push_str("[env]\n");
        for (key, value) in &config.env {
            output.push_str(&format!("{} = \"{}\"\n", key, value));
        }
        output.push('\n');
    }

    output
}

/// Generate full TOML (all options with comments).
fn generate_full_toml(_config: &ArapucaConfig) -> String {
    // For now, just return the example config
    // In a real implementation, we'd merge current values with the template
    include_str!("../config.example.toml").to_string()
}

/// Generate config from template.
pub fn generate_from_template(template: ConfigTemplate) -> ArapucaConfig {
    match template {
        ConfigTemplate::Process => ArapucaConfig {
            sandbox: SandboxConfig {
                isolation: "process".into(),
                read_paths: vec![
                    PathBuf::from("/usr"),
                    PathBuf::from("/lib"),
                    PathBuf::from("/lib64"),
                    PathBuf::from("/bin"),
                    PathBuf::from("/etc"),
                ],
                write_paths: vec![PathBuf::from("/tmp")],
                allow_exec: true,
                use_netns: true,
            },
            resources: ResourcesConfig {
                max_memory_mb: 2048,
                max_pids: 256,
                ..Default::default()
            },
            ..Default::default()
        },
        ConfigTemplate::MicroVm => ArapucaConfig {
            sandbox: SandboxConfig {
                isolation: "microvm".into(),
                ..Default::default()
            },
            microvm: Some(TomlMicroVmConfig {
                image: "fedora:44".into(),
                cpus: 2,
                mem_mb: 4096,
                enable_network: false,
                timeout: None,
                name: Some("arapuca-vm".into()),
                max_lifetime: Some(86400),
                volume: vec![],
                write_file: vec![],
            }),
            ..Default::default()
        },
        ConfigTemplate::Strict => ArapucaConfig {
            sandbox: SandboxConfig {
                isolation: "process".into(),
                read_paths: vec![
                    PathBuf::from("/usr"),
                    PathBuf::from("/lib"),
                    PathBuf::from("/lib64"),
                ],
                write_paths: vec![],
                allow_exec: false,
                use_netns: true,
            },
            resources: ResourcesConfig {
                max_memory_mb: 1024,
                max_cpu_pct: 100,
                max_pids: 64,
                max_file_size_mb: 100,
            },
            ..Default::default()
        },
    }
}

fn has_non_default_general(config: &ArapucaConfig) -> bool {
    config.general.task_id.is_some()
        || config.general.work_dir.is_some()
        || config.general.socket_dir.is_some()
        || config.general.phase.is_some()
}

fn has_non_default_sandbox(config: &ArapucaConfig) -> bool {
    config.sandbox.isolation != "process"
        || !config.sandbox.read_paths.is_empty()
        || !config.sandbox.write_paths.is_empty()
        || !config.sandbox.allow_exec
        || !config.sandbox.use_netns
}

fn has_non_default_resources(config: &ArapucaConfig) -> bool {
    config.resources.max_memory_mb > 0
        || config.resources.max_cpu_pct > 0
        || config.resources.max_pids > 0
        || config.resources.max_file_size_mb > 0
}

fn format_path_array(paths: &[PathBuf]) -> String {
    let formatted: Vec<String> = paths
        .iter()
        .map(|p| format!("\"{}\"", p.display()))
        .collect();
    format!("[{}]", formatted.join(", "))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_config() {
        let toml = r#"
[general]
task_id = "test-task"

[sandbox]
read_paths = ["/usr", "/lib"]
write_paths = ["/tmp"]

[resources]
max_memory_mb = 2048
max_pids = 256
"#;
        let config: ArapucaConfig = toml::from_str(toml).unwrap();
        assert_eq!(config.general.task_id, Some("test-task".into()));
        assert_eq!(config.sandbox.read_paths.len(), 2);
        assert_eq!(config.resources.max_memory_mb, 2048);
    }

    #[test]
    fn test_microvm_config() {
        let toml = r#"
[microvm]
image = "fedora:42"
cpus = 4
mem_mb = 4096

[[microvm.volume]]
host = "/home/user/project"
guest = "/workspace"
read_only = false

[[microvm.write_file]]
host_path = "./config.yaml"
guest_path = "/etc/app/config.yaml"
permissions = "0644"
"#;
        let config: ArapucaConfig = toml::from_str(toml).unwrap();
        let vm_cfg = config.microvm.unwrap();
        assert_eq!(vm_cfg.image, "fedora:42");
        assert_eq!(vm_cfg.cpus, 4);
        assert_eq!(vm_cfg.volume.len(), 1);
        assert_eq!(vm_cfg.write_file.len(), 1);
    }

    #[test]
    fn test_merge_configs() {
        let mut base = ArapucaConfig::default();
        base.sandbox.read_paths = vec![PathBuf::from("/usr")];
        base.resources.max_memory_mb = 1024;

        let mut override_cfg = ArapucaConfig::default();
        override_cfg.sandbox.read_paths = vec![PathBuf::from("/lib")];
        override_cfg.resources.max_pids = 128;

        base.merge(override_cfg);

        assert_eq!(base.sandbox.read_paths, vec![PathBuf::from("/lib")]);
        assert_eq!(base.resources.max_memory_mb, 1024);
        assert_eq!(base.resources.max_pids, 128);
    }

    #[test]
    fn test_validate_microvm_missing_section() {
        let config = ArapucaConfig {
            sandbox: SandboxConfig {
                isolation: "microvm".into(),
                ..Default::default()
            },
            microvm: None,
            ..Default::default()
        };

        let issues = config.validate(&ValidateOptions::default());
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].level, ValidationLevel::Error);
        assert!(issues[0].message.contains("requires [microvm] section"));
    }

    #[test]
    fn test_validate_microvm_zero_cpus() {
        let config = ArapucaConfig {
            sandbox: SandboxConfig {
                isolation: "microvm".into(),
                ..Default::default()
            },
            microvm: Some(TomlMicroVmConfig {
                image: "fedora:42".into(),
                cpus: 0,
                mem_mb: 2048,
                enable_network: false,
                timeout: None,
                name: None,
                max_lifetime: None,
                volume: vec![],
                write_file: vec![],
            }),
            ..Default::default()
        };

        let issues = config.validate(&ValidateOptions::default());
        let errors: Vec<_> = issues
            .iter()
            .filter(|i| i.level == ValidationLevel::Error)
            .collect();
        assert!(!errors.is_empty());
        assert!(errors.iter().any(|i| i.location == "microvm.cpus"));
    }

    #[test]
    fn test_validate_invalid_isolation() {
        let config = ArapucaConfig {
            sandbox: SandboxConfig {
                isolation: "invalid".into(),
                ..Default::default()
            },
            ..Default::default()
        };

        let issues = config.validate(&ValidateOptions::default());
        assert!(!issues.is_empty());
        assert_eq!(issues[0].level, ValidationLevel::Error);
        assert!(issues[0].message.contains("invalid isolation type"));
    }

    #[test]
    fn test_generate_minimal_toml() {
        let config = ArapucaConfig {
            sandbox: SandboxConfig {
                read_paths: vec![PathBuf::from("/usr"), PathBuf::from("/lib")],
                write_paths: vec![PathBuf::from("/tmp")],
                ..Default::default()
            },
            resources: ResourcesConfig {
                max_memory_mb: 2048,
                max_pids: 256,
                ..Default::default()
            },
            ..Default::default()
        };

        let toml = generate_toml(&config, TomlStyle::Minimal);
        assert!(toml.contains("read_paths = [\"/usr\", \"/lib\"]"));
        assert!(toml.contains("write_paths = [\"/tmp\"]"));
        assert!(toml.contains("max_memory_mb = 2048"));
        assert!(toml.contains("max_pids = 256"));
    }

    #[test]
    fn test_generate_from_env() {
        // SAFETY: Single-threaded test environment, no other code reads these vars.
        unsafe {
            std::env::set_var("ARAPUCA_READ_PATHS", "/usr:/lib");
            std::env::set_var("ARAPUCA_WRITE_PATHS", "/tmp");
        }

        let config = ArapucaConfig::from_env_only();
        assert_eq!(config.sandbox.read_paths.len(), 2);
        assert_eq!(config.sandbox.write_paths.len(), 1);

        // SAFETY: Cleanup, single-threaded test.
        unsafe {
            std::env::remove_var("ARAPUCA_READ_PATHS");
            std::env::remove_var("ARAPUCA_WRITE_PATHS");
        }
    }

    #[test]
    fn test_template_process() {
        let config = generate_from_template(ConfigTemplate::Process);
        assert_eq!(config.sandbox.isolation, "process");
        assert!(!config.sandbox.read_paths.is_empty());
        assert_eq!(config.resources.max_memory_mb, 2048);
    }

    #[test]
    fn test_template_microvm() {
        let config = generate_from_template(ConfigTemplate::MicroVm);
        assert_eq!(config.sandbox.isolation, "microvm");
        assert!(config.microvm.is_some());
        let vm = config.microvm.unwrap();
        assert_eq!(vm.image, "fedora:42");
        assert_eq!(vm.cpus, 2);
    }

    #[test]
    fn test_template_strict() {
        let config = generate_from_template(ConfigTemplate::Strict);
        assert_eq!(config.sandbox.isolation, "process");
        assert!(!config.sandbox.allow_exec);
        assert!(config.sandbox.write_paths.is_empty());
        assert_eq!(config.resources.max_pids, 64);
    }
}
