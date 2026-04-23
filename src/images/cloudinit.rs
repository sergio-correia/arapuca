//! Cloud-init NoCloud datasource generation.
//!
//! Creates a directory with `meta-data` and `user-data` files that
//! cloud-init consumes on first boot. The directory can be shared
//! into the VM via virtio-fs.

use std::io;
use std::path::{Path, PathBuf};

/// Configuration for cloud-init datasource generation.
pub struct CloudInitConfig<'a> {
    /// Hostname for the VM.
    pub hostname: &'a str,
    /// Username to create.
    pub user: &'a str,
    /// Directories to mount via virtio-fs.
    /// Each entry: (virtiofs tag, mount point).
    pub virtiofs_mounts: Vec<(&'a str, &'a str)>,
    /// Files to write into the VM filesystem.
    pub write_files: Vec<WriteFile<'a>>,
    /// Shell commands to run after boot (optional).
    /// Each string is passed to `/bin/sh -c` by cloud-init.
    pub runcmd: Option<Vec<&'a str>>,
}

/// A file to write into the VM via cloud-init's `write_files`.
pub struct WriteFile<'a> {
    /// Absolute path in the VM (e.g., "/etc/yum.repos.d/internal.repo").
    pub path: &'a str,
    /// File content.
    pub content: &'a str,
    /// File permissions (e.g., "0644"). Defaults to "0644" if None.
    pub permissions: Option<&'a str>,
}

/// Generate a NoCloud datasource directory.
///
/// Creates `meta-data` and `user-data` files in `output_dir`.
/// Returns the path to the directory.
///
/// # Errors
///
/// Returns an error if the directory cannot be created or files
/// cannot be written.
pub fn generate_datasource(cfg: &CloudInitConfig<'_>, output_dir: &Path) -> io::Result<PathBuf> {
    let ds_dir = output_dir.join("cidata");
    std::fs::create_dir_all(&ds_dir)?;

    let meta_data = format!(
        "instance-id: \"{}\"\nlocal-hostname: \"{}\"\n",
        yaml_escape(cfg.hostname),
        yaml_escape(cfg.hostname),
    );
    std::fs::write(ds_dir.join("meta-data"), meta_data)?;

    let mut user_data = String::from("#cloud-config\n");

    user_data.push_str(&format!(
        "users:\n  - name: \"{}\"\n    shell: /bin/bash\n    sudo: ALL=(ALL) NOPASSWD:ALL\n",
        yaml_escape(cfg.user),
    ));

    if !cfg.virtiofs_mounts.is_empty() {
        user_data.push_str("mounts:\n");
        for (tag, mountpoint) in &cfg.virtiofs_mounts {
            user_data.push_str(&format!(
                "  - [\"{}\", \"{}\", \"virtiofs\", \"defaults\", \"0\", \"0\"]\n",
                yaml_escape(tag),
                yaml_escape(mountpoint),
            ));
        }
    }

    if !cfg.write_files.is_empty() {
        user_data.push_str("write_files:\n");
        for wf in &cfg.write_files {
            let perms = wf.permissions.unwrap_or("0644");
            user_data.push_str(&format!("  - path: \"{}\"\n", yaml_escape(wf.path)));
            user_data.push_str(&format!("    permissions: \"{}\"\n", yaml_escape(perms)));
            if wf.content.is_empty() {
                user_data.push_str("    content: \"\"\n");
            } else {
                user_data.push_str("    content: |\n");
                for line in wf.content.lines() {
                    if line.is_empty() {
                        user_data.push('\n');
                    } else {
                        user_data.push_str(&format!("      {line}\n"));
                    }
                }
            }
        }
    }

    if let Some(ref cmds) = cfg.runcmd {
        user_data.push_str("runcmd:\n");
        for cmd in cmds {
            // Shell-string form: cloud-init runs via /bin/sh -c.
            user_data.push_str(&format!("  - \"{}\"\n", yaml_escape(cmd)));
        }
    }

    std::fs::write(ds_dir.join("user-data"), user_data)?;

    Ok(ds_dir)
}

/// Escape a string for use inside YAML double quotes.
fn yaml_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_minimal_datasource() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = CloudInitConfig {
            hostname: "test-vm",
            user: "agent",
            virtiofs_mounts: vec![],
            write_files: vec![],
            runcmd: None,
        };

        let ds = generate_datasource(&cfg, dir.path()).unwrap();
        assert!(ds.join("meta-data").exists());
        assert!(ds.join("user-data").exists());

        let meta = std::fs::read_to_string(ds.join("meta-data")).unwrap();
        assert!(meta.contains("test-vm"));

        let user = std::fs::read_to_string(ds.join("user-data")).unwrap();
        assert!(user.starts_with("#cloud-config"));
        assert!(user.contains("agent"));
        assert!(!user.contains("mounts:"));
        assert!(!user.contains("runcmd:"));
    }

    #[test]
    fn generate_datasource_with_mounts_and_cmd() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = CloudInitConfig {
            hostname: "worker",
            user: "agent",
            virtiofs_mounts: vec![("work", "/home/agent/work"), ("data", "/mnt/data")],
            write_files: vec![],
            runcmd: Some(vec!["dnf install -y podman", "/usr/bin/setup.sh"]),
        };

        let ds = generate_datasource(&cfg, dir.path()).unwrap();
        let user = std::fs::read_to_string(ds.join("user-data")).unwrap();

        assert!(user.contains("mounts:"));
        assert!(user.contains("work"));
        assert!(user.contains("/home/agent/work"));
        assert!(user.contains("runcmd:"));
        assert!(user.contains("dnf install -y podman"));
        assert!(user.contains("/usr/bin/setup.sh"));
    }

    #[test]
    fn generate_datasource_with_write_files() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = CloudInitConfig {
            hostname: "worker",
            user: "agent",
            virtiofs_mounts: vec![],
            write_files: vec![
                WriteFile {
                    path: "/etc/yum.repos.d/internal.repo",
                    content: "[internal]\nname=Internal\nbaseurl=https://mirror.corp/repo\nenabled=1\n",
                    permissions: None,
                },
                WriteFile {
                    path: "/etc/resolv.conf",
                    content: "nameserver 10.0.0.1\n",
                    permissions: Some("0644"),
                },
            ],
            runcmd: None,
        };

        let ds = generate_datasource(&cfg, dir.path()).unwrap();
        let user = std::fs::read_to_string(ds.join("user-data")).unwrap();

        assert!(user.contains("write_files:"));
        assert!(user.contains("/etc/yum.repos.d/internal.repo"));
        assert!(user.contains("Internal"));
        assert!(user.contains("content: |"));
        assert!(user.contains("/etc/resolv.conf"));
    }

    #[test]
    fn write_files_empty_content() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = CloudInitConfig {
            hostname: "test",
            user: "agent",
            virtiofs_mounts: vec![],
            write_files: vec![WriteFile {
                path: "/tmp/empty",
                content: "",
                permissions: None,
            }],
            runcmd: None,
        };

        let ds = generate_datasource(&cfg, dir.path()).unwrap();
        let user = std::fs::read_to_string(ds.join("user-data")).unwrap();

        assert!(user.contains("content: \"\""));
        assert!(!user.contains("content: |"));
    }

    #[test]
    fn yaml_escaping() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = CloudInitConfig {
            hostname: "vm-with-\"quotes\"",
            user: "agent",
            virtiofs_mounts: vec![],
            write_files: vec![],
            runcmd: Some(vec!["echo \"hello world\""]),
        };

        let ds = generate_datasource(&cfg, dir.path()).unwrap();
        let meta = std::fs::read_to_string(ds.join("meta-data")).unwrap();
        let user = std::fs::read_to_string(ds.join("user-data")).unwrap();

        assert!(meta.contains(r#"vm-with-\"quotes\""#));
        assert!(user.contains(r#"echo \"hello world\""#));
    }
}
