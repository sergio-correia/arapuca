//! Built-in Fedora cloud image provider.
//!
//! Resolves `fedora:<version>` to a Fedora Cloud Base Generic qcow2
//! image from the official mirror.

use super::metadata::ImageMetadata;

/// Fedora Cloud Base Generic images (F42+) use this partition layout:
/// - /dev/vda1: BIOS boot (2MB)
/// - /dev/vda2: EFI System (100MB, vfat)
/// - /dev/vda3: /boot (1GB, ext4)
/// - /dev/vda4: / (rest, btrfs)
const FEDORA_ROOT_DEVICE: &str = "/dev/vda4";
const FEDORA_FSTYPE: &str = "btrfs";

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

    eprintln!("resolving fedora {version} ({arch})...");
    let (filename, checksum_name) = discover_image_and_checksum(version, arch)?;
    let base_url = images_dir_url(version, arch);
    let url = format!("{base_url}{filename}");
    eprintln!("downloading {filename}...");

    let dir = super::cache::images_dir()?;
    let tmp_path = dir.join(format!("{cache_name}.qcow2.partial"));

    // Clean up partial file on all exit paths.
    let result = (|| {
        let sha256 = super::download::fetch_to_file(&url, &tmp_path)?;

        // Verify checksum against the mirror's CHECKSUM file.
        if let Some(ref cksum_file) = checksum_name {
            let cksum_url = format!("{base_url}{cksum_file}");
            match super::download::fetch_text(&cksum_url, 1024 * 1024) {
                Ok(body) => match super::download::parse_checksum(&body, &filename) {
                    Some(expected) => {
                        if sha256 != expected {
                            return Err(io::Error::other(format!(
                                "checksum mismatch for {filename}: \
                                 expected {expected}, got {sha256}"
                            )));
                        }
                        eprintln!("checksum verified (sha256:{sha256})");
                        eprintln!(
                            "warning: PGP signature not checked \
                             — image authenticity is not confirmed"
                        );
                    }
                    None => {
                        eprintln!(
                            "warning: CHECKSUM file found but no SHA256 entry for {filename}"
                        );
                    }
                },
                Err(e) => {
                    eprintln!("warning: could not fetch CHECKSUM file: {e}");
                }
            }
        } else {
            eprintln!("warning: no CHECKSUM file found on mirror");
        }

        eprintln!("caching image...");
        let mut metadata = fedora_metadata();
        metadata.sha256 = Some(sha256);
        super::cache::store(&cache_name, &tmp_path, &metadata)
    })();

    let _ = std::fs::remove_file(&tmp_path);
    if result.is_ok() {
        eprintln!("done");
    }
    result
}

/// Discover the qcow2 image and CHECKSUM filenames from the Fedora
/// mirror directory listing.
///
/// The build suffix (e.g., `-1.1`, `-1.14`) and filename format
/// change between releases, so we scrape the mirror directory
/// listing rather than hardcoding the suffix.
#[cfg(feature = "microvm")]
fn discover_image_and_checksum(
    version: &str,
    arch: &str,
) -> std::io::Result<(String, Option<String>)> {
    use std::io;

    let dir_url = images_dir_url(version, arch);
    let body = super::download::fetch_text(&dir_url, 1024 * 1024)?;

    let mut image_name = None;
    let mut checksum_name = None;

    let pattern = "Fedora-Cloud-Base-Generic";
    for segment in body.split('"') {
        if segment.contains('/') {
            continue;
        }
        if image_name.is_none() && segment.contains(pattern) && segment.ends_with(".qcow2") {
            image_name = Some(segment.to_string());
        }
        if checksum_name.is_none() && segment.ends_with("-CHECKSUM") {
            checksum_name = Some(segment.to_string());
        }
        if image_name.is_some() && checksum_name.is_some() {
            break;
        }
    }

    match image_name {
        Some(name) => Ok((name, checksum_name)),
        None => Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("no Fedora Cloud Base Generic qcow2 found at {dir_url}"),
        )),
    }
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
        mount_options: Some("subvol=root".into()),
        init: "/sbin/init".into(),
        sha256: None,
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
        assert_eq!(meta.root_device, "/dev/vda4");
        assert_eq!(meta.fstype, "btrfs");
        assert_eq!(meta.init, "/sbin/init");
    }
}
