//! External image provider protocol.
//!
//! Discovers `arapuca-images-{distro}` executables in `$PATH` and
//! calls them with `--resolve <version> <arch>` to resolve distro
//! images. The provider prints JSON to stdout with the image path
//! and metadata.

use std::io;
use std::path::PathBuf;
use std::process::Command;

use super::cache::CachedImage;
use super::metadata::ImageMetadata;

/// Discover a provider for the given distro.
///
/// Looks for `arapuca-images-{distro}` in `$PATH`. Returns the
/// full path if found, `None` otherwise.
pub fn discover(distro: &str) -> Option<PathBuf> {
    if distro.is_empty() || distro.contains('/') || distro.contains('\\') || distro.contains("..") {
        return None;
    }

    let bin_name = format!("arapuca-images-{distro}");
    let path_var = std::env::var("PATH").ok()?;

    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    for dir in path_var.split(':') {
        let candidate = PathBuf::from(dir).join(&bin_name);
        if candidate.is_file() {
            #[cfg(unix)]
            {
                if let Ok(meta) = candidate.metadata() {
                    if meta.permissions().mode() & 0o111 == 0 {
                        continue;
                    }
                }
            }
            return Some(candidate);
        }
    }
    None
}

/// Resolve an image via an external provider.
///
/// Calls `arapuca-images-{distro} --resolve <version> <arch>` and
/// parses the JSON response. The provider is expected to download
/// and cache the image itself, returning the path to the cached
/// qcow2 file.
///
/// # Provider JSON protocol
///
/// ```json
/// {
///   "image": "/absolute/path/to/image.qcow2",
///   "root_device": "/dev/vda4",
///   "fstype": "xfs",
///   "init": "/sbin/init"
/// }
/// ```
pub fn resolve_external(distro: &str, version: &str) -> io::Result<CachedImage> {
    let provider = discover(distro).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("no provider found for '{distro}' (install arapuca-images-{distro} in $PATH)"),
        )
    })?;

    let arch = std::env::consts::ARCH;
    eprintln!(
        "resolving {distro} {version} ({arch}) via {}...",
        provider.display()
    );

    let output = Command::new(&provider)
        .args(["--resolve", version, arch])
        .output()
        .map_err(|e| io::Error::other(format!("failed to run {}: {e}", provider.display())))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(io::Error::other(format!(
            "{} --resolve {version} {arch} failed (exit {}): {}",
            provider.display(),
            output.status.code().unwrap_or(-1),
            stderr.trim(),
        )));
    }

    let stdout = String::from_utf8(output.stdout).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("provider output is not valid UTF-8: {e}"),
        )
    })?;

    parse_provider_response(&stdout)
}

fn parse_provider_response(json: &str) -> io::Result<CachedImage> {
    let image = extract_json_string(json, "image").ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "provider response missing \"image\" field",
        )
    })?;

    let path = PathBuf::from(&image);
    if !path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("provider image path must be absolute: {image}"),
        ));
    }

    let root_device = extract_json_string(json, "root_device").ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "provider response missing \"root_device\" field",
        )
    })?;

    let fstype = extract_json_string(json, "fstype").ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "provider response missing \"fstype\" field",
        )
    })?;

    let init = extract_json_string(json, "init").unwrap_or_else(|| "/sbin/init".to_string());

    let mount_options = extract_json_string(json, "mount_options");

    Ok(CachedImage {
        path,
        metadata: ImageMetadata {
            root_device,
            fstype,
            mount_options,
            init,
            sha256: None,
            base_sha256: None,
        },
    })
}

use super::metadata::extract_json_string;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_response() {
        let json = r#"{
  "image": "/data/images/rhel-10.0.qcow2",
  "root_device": "/dev/vda4",
  "fstype": "xfs",
  "init": "/sbin/init"
}"#;
        let cached = parse_provider_response(json).unwrap();
        assert_eq!(cached.path, PathBuf::from("/data/images/rhel-10.0.qcow2"));
        assert_eq!(cached.metadata.root_device, "/dev/vda4");
        assert_eq!(cached.metadata.fstype, "xfs");
    }

    #[test]
    fn parse_response_default_init() {
        let json = r#"{"image": "/img.qcow2", "root_device": "/dev/vda1", "fstype": "ext4"}"#;
        let cached = parse_provider_response(json).unwrap();
        assert_eq!(cached.metadata.init, "/sbin/init");
    }

    #[test]
    fn parse_response_missing_image() {
        let json = r#"{"root_device": "/dev/vda1", "fstype": "ext4"}"#;
        assert!(parse_provider_response(json).is_err());
    }

    #[test]
    fn parse_response_relative_path() {
        let json =
            r#"{"image": "relative/path.qcow2", "root_device": "/dev/vda1", "fstype": "ext4"}"#;
        let err = parse_provider_response(json).unwrap_err();
        assert!(err.to_string().contains("absolute"));
    }

    #[test]
    fn discover_nonexistent_provider() {
        assert!(discover("nonexistent-xyz-test").is_none());
    }

    #[test]
    fn discover_rejects_path_traversal() {
        assert!(discover("../etc").is_none());
        assert!(discover("foo/bar").is_none());
        assert!(discover("").is_none());
        assert!(discover("foo\\bar").is_none());
    }
}
