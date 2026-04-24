//! Image metadata for micro-VM root filesystems.

use std::io;
use std::path::Path;

/// Metadata describing how to boot a qcow2 image with libkrun.
#[derive(Debug, Clone)]
pub struct ImageMetadata {
    /// Root device path (e.g., "/dev/vda1", "/dev/vda4").
    pub root_device: String,
    /// Filesystem type (e.g., "ext4", "xfs", "btrfs").
    pub fstype: String,
    /// Mount options (e.g., "subvol=root" for btrfs subvolumes).
    pub mount_options: Option<String>,
    /// Init binary to execute (e.g., "/sbin/init").
    pub init: String,
    /// SHA256 hex digest of the qcow2 file (for integrity verification).
    pub sha256: Option<String>,
}

impl ImageMetadata {
    /// Load metadata from a sidecar JSON file next to a qcow2 image.
    ///
    /// Given `/path/to/image.qcow2`, looks for
    /// `/path/to/image.meta.json`.
    pub fn load_sidecar(qcow2_path: &Path) -> io::Result<Self> {
        let meta_path = sidecar_path(qcow2_path);
        let contents = std::fs::read_to_string(&meta_path)?;
        parse_metadata_json(&contents).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{}: {e}", meta_path.display()),
            )
        })
    }

    /// Save metadata as a sidecar JSON file next to a qcow2 image.
    pub fn save_sidecar(&self, qcow2_path: &Path) -> io::Result<()> {
        let meta_path = sidecar_path(qcow2_path);
        let mut json = format!(
            "{{\n  \"root_device\": \"{}\",\n  \"fstype\": \"{}\"",
            json_escape(&self.root_device),
            json_escape(&self.fstype),
        );
        if let Some(ref opts) = self.mount_options {
            json.push_str(&format!(
                ",\n  \"mount_options\": \"{}\"",
                json_escape(opts)
            ));
        }
        json.push_str(&format!(",\n  \"init\": \"{}\"", json_escape(&self.init)));
        if let Some(ref hash) = self.sha256 {
            json.push_str(&format!(",\n  \"sha256\": \"{}\"", json_escape(hash)));
        }
        json.push_str("\n}\n");
        std::fs::write(meta_path, json)
    }
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if c < '\u{0020}' => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

pub(crate) fn sidecar_path(qcow2_path: &Path) -> std::path::PathBuf {
    qcow2_path.with_extension("meta.json")
}

fn parse_metadata_json(json: &str) -> Result<ImageMetadata, String> {
    let root_device =
        extract_json_string(json, "root_device").ok_or("missing \"root_device\" field")?;
    let fstype = extract_json_string(json, "fstype").ok_or("missing \"fstype\" field")?;
    let mount_options = extract_json_string(json, "mount_options");
    let init = extract_json_string(json, "init").unwrap_or_else(|| "/sbin/init".to_string());
    let sha256 = extract_json_string(json, "sha256")
        .filter(|h| h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()));
    Ok(ImageMetadata {
        root_device,
        fstype,
        mount_options,
        init,
        sha256,
    })
}

/// Minimal JSON string field extractor. Avoids a serde_json
/// dependency for the images module (serde is optional).
///
/// Limitation: does not handle escape sequences in values.
/// Field values must not contain `"` or `\`.
pub(crate) fn extract_json_string(json: &str, key: &str) -> Option<String> {
    let pattern = format!("\"{key}\"");
    let key_pos = json.find(&pattern)?;
    let after_key = &json[key_pos + pattern.len()..];
    let colon_pos = after_key.find(':')?;
    let after_colon = after_key[colon_pos + 1..].trim_start();
    if !after_colon.starts_with('"') {
        return None;
    }
    let value_start = 1;
    let value_end = after_colon[value_start..].find('"')?;
    Some(after_colon[value_start..value_start + value_end].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_metadata() {
        let json = r#"{
  "root_device": "/dev/vda4",
  "fstype": "xfs",
  "init": "/sbin/init"
}"#;
        let meta = parse_metadata_json(json).unwrap();
        assert_eq!(meta.root_device, "/dev/vda4");
        assert_eq!(meta.fstype, "xfs");
        assert_eq!(meta.init, "/sbin/init");
    }

    #[test]
    fn parse_metadata_default_init() {
        let json = r#"{"root_device": "/dev/vda1", "fstype": "ext4"}"#;
        let meta = parse_metadata_json(json).unwrap();
        assert_eq!(meta.init, "/sbin/init");
    }

    #[test]
    fn parse_metadata_missing_root_device() {
        let json = r#"{"fstype": "ext4"}"#;
        assert!(parse_metadata_json(json).is_err());
    }

    #[test]
    fn parse_metadata_missing_fstype() {
        let json = r#"{"root_device": "/dev/vda1"}"#;
        assert!(parse_metadata_json(json).is_err());
    }

    #[test]
    fn sidecar_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let qcow2 = dir.path().join("test.qcow2");
        std::fs::write(&qcow2, b"fake").unwrap();

        let meta = ImageMetadata {
            root_device: "/dev/vda3".into(),
            fstype: "xfs".into(),
            mount_options: None,
            init: "/sbin/init".into(),
            sha256: None,
        };
        meta.save_sidecar(&qcow2).unwrap();

        let loaded = ImageMetadata::load_sidecar(&qcow2).unwrap();
        assert_eq!(loaded.root_device, "/dev/vda3");
        assert_eq!(loaded.fstype, "xfs");
        assert!(loaded.mount_options.is_none());
        assert_eq!(loaded.init, "/sbin/init");
    }

    #[test]
    fn sidecar_round_trip_with_sha256() {
        let dir = tempfile::tempdir().unwrap();
        let qcow2 = dir.path().join("test.qcow2");
        std::fs::write(&qcow2, b"fake").unwrap();

        let hash = "e401a4db2e5e04d1967b6729774faa96da629bcf3ba90b67d8d9cce9906bec0f";
        let meta = ImageMetadata {
            root_device: "/dev/vda4".into(),
            fstype: "btrfs".into(),
            mount_options: Some("subvol=root".into()),
            init: "/sbin/init".into(),
            sha256: Some(hash.into()),
        };
        meta.save_sidecar(&qcow2).unwrap();

        let loaded = ImageMetadata::load_sidecar(&qcow2).unwrap();
        assert_eq!(loaded.sha256.as_deref(), Some(hash));
        assert_eq!(loaded.root_device, "/dev/vda4");
        assert_eq!(loaded.fstype, "btrfs");
        assert_eq!(loaded.mount_options.as_deref(), Some("subvol=root"));
    }

    #[test]
    fn sidecar_path_derivation() {
        let path = std::path::PathBuf::from("/data/images/fedora-43.qcow2");
        assert_eq!(
            sidecar_path(&path),
            std::path::PathBuf::from("/data/images/fedora-43.meta.json")
        );
    }
}
