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
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::{GuestFile, ImageSource, Isolation, MicroVmConfig, Profile};

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
    2048
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
}
