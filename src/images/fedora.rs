//! Built-in Fedora cloud image provider.
//!
//! Resolves `fedora:<version>` to a Fedora Cloud Base Generic qcow2
//! image from the official mirror.

use super::metadata::ImageMetadata;

/// Fedora Cloud Base Generic images use this partition layout:
/// - /dev/vda1: bios_grub (1MB)
/// - /dev/vda2: /boot (ext4, ~1GB)
/// - /dev/vda3: / (ext4, rest of disk)
///
/// Filesystem is ext4 (not btrfs) on cloud images.
const FEDORA_ROOT_DEVICE: &str = "/dev/vda3";
const FEDORA_FSTYPE: &str = "ext4";

/// Resolve and cache a Fedora cloud image.
///
/// Returns the cached image if already downloaded, otherwise
/// discovers the correct filename from the Fedora mirror,
/// downloads it, and caches the result.
#[cfg(feature = "microvm")]
pub fn resolve(version: &str) -> std::io::Result<super::cache::CachedImage> {
    use std::io;

    if version.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "fedora version must not be empty",
        ));
    }

    let arch = std::env::consts::ARCH;
    let cache_name = format!("fedora-{version}-{arch}");

    if let Some(cached) = super::cache::lookup(&cache_name)? {
        return Ok(cached);
    }

    let filename = discover_image_filename(version, arch)?;
    let url = format!("{}{filename}", images_dir_url(version, arch));

    let dir = super::cache::images_dir()?;
    let tmp_path = dir.join(format!("{cache_name}.qcow2.partial"));

    // Clean up partial file on all exit paths.
    let result = (|| {
        super::download::fetch_to_file(&url, &tmp_path)?;
        let metadata = fedora_metadata();
        super::cache::store(&cache_name, &tmp_path, &metadata)
    })();

    let _ = std::fs::remove_file(&tmp_path);
    result
}

/// Discover the actual qcow2 filename from the Fedora mirror.
///
/// The build suffix (e.g., `-1.1`, `-1.14`) and filename format
/// change between releases, so we scrape the mirror directory
/// listing rather than hardcoding the suffix.
#[cfg(feature = "microvm")]
fn discover_image_filename(version: &str, arch: &str) -> std::io::Result<String> {
    use std::io;

    let dir_url = images_dir_url(version, arch);

    let client = reqwest::blocking::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(30))
        .timeout(std::time::Duration::from_secs(60))
        .build()
        .map_err(|e| io::Error::other(format!("HTTP client: {e}")))?;

    let response = client
        .get(&dir_url)
        .send()
        .map_err(|e| io::Error::other(format!("GET {dir_url}: {e}")))?;

    if !response.status().is_success() {
        return Err(io::Error::other(format!(
            "GET {dir_url}: HTTP {}",
            response.status()
        )));
    }

    let body = response
        .text()
        .map_err(|e| io::Error::other(format!("reading {dir_url}: {e}")))?;

    // Look for the Generic cloud image filename in the HTML.
    let pattern = "Fedora-Cloud-Base-Generic";
    for segment in body.split('"') {
        if segment.contains(pattern) && segment.ends_with(".qcow2") && !segment.contains('/') {
            return Ok(segment.to_string());
        }
    }

    Err(io::Error::new(
        io::ErrorKind::NotFound,
        format!("no Fedora Cloud Base Generic qcow2 found at {dir_url}"),
    ))
}

/// Base URL for the Fedora cloud images directory.
#[cfg(any(feature = "microvm", test))]
fn images_dir_url(version: &str, arch: &str) -> String {
    format!(
        "https://download.fedoraproject.org/pub/fedora/linux/releases/{version}/Cloud/{arch}/images/"
    )
}

/// Return the default metadata for Fedora cloud images.
pub fn fedora_metadata() -> ImageMetadata {
    ImageMetadata {
        root_device: FEDORA_ROOT_DEVICE.into(),
        fstype: FEDORA_FSTYPE.into(),
        init: "/sbin/init".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn images_dir_url_construction() {
        let url = images_dir_url("42", "x86_64");
        assert_eq!(
            url,
            "https://download.fedoraproject.org/pub/fedora/linux/releases/42/Cloud/x86_64/images/"
        );
    }

    #[test]
    fn images_dir_url_aarch64() {
        let url = images_dir_url("42", "aarch64");
        assert!(url.contains("/aarch64/"));
    }

    #[test]
    fn metadata_defaults() {
        let meta = fedora_metadata();
        assert_eq!(meta.root_device, "/dev/vda3");
        assert_eq!(meta.fstype, "ext4");
        assert_eq!(meta.init, "/sbin/init");
    }
}
