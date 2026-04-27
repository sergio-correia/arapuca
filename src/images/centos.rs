//! Built-in CentOS Stream cloud image provider.
//!
//! Resolves `centos:<version>` to a CentOS Stream GenericCloud qcow2
//! image from cloud.centos.org.

use super::metadata::ImageMetadata;

const CENTOS_ROOT_DEVICE: &str = "/dev/vda4";
const CENTOS_FSTYPE: &str = "xfs";

/// Resolve and cache a CentOS Stream cloud image.
///
/// Returns the cached image if already downloaded, otherwise
/// downloads the `-latest` image from the CentOS mirror and
/// caches the result.
#[cfg(feature = "microvm")]
pub fn resolve(version: &str) -> std::io::Result<super::cache::CachedImage> {
    use std::io;

    validate_version(version)?;

    let arch = std::env::consts::ARCH;
    let cache_name = format!("centos-{version}-{arch}");

    if let Some(cached) = super::cache::lookup(&cache_name)? {
        return Ok(cached);
    }

    eprintln!("resolving centos stream {version} ({arch})...");
    let filename = image_filename(version, arch);
    let base_url = images_dir_url(version, arch);
    let url = format!("{base_url}{filename}");
    eprintln!("downloading {filename}...");

    let dir = super::cache::images_dir()?;
    let tmp_path = dir.join(format!("{cache_name}.qcow2.partial"));

    let result = (|| {
        let sha256 = super::download::fetch_to_file(&url, &tmp_path)?;

        let cksum_url = format!("{url}.SHA256SUM");
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
                        "warning: CentOS images are not PGP-signed \
                         — image authenticity relies on HTTPS transport only"
                    );
                }
                None => {
                    eprintln!("warning: SHA256SUM file found but no entry for {filename}");
                }
            },
            Err(e) => {
                eprintln!("warning: could not fetch SHA256SUM file: {e}");
            }
        }

        eprintln!("detecting image layout...");
        let mut metadata = match super::probe::probe_image(&tmp_path) {
            Ok(m) => m,
            Err(e) => {
                eprintln!("warning: partition probe failed ({e}), using defaults");
                centos_metadata()
            }
        };
        metadata.sha256 = Some(sha256);
        eprintln!(
            "caching image (root={} fs={})...",
            metadata.root_device, metadata.fstype
        );
        super::cache::store(&cache_name, &tmp_path, &metadata)
    })();

    let _ = std::fs::remove_file(&tmp_path);
    if result.is_ok() {
        eprintln!("done");
    }
    result
}

#[cfg(any(feature = "microvm", test))]
fn validate_version(version: &str) -> std::io::Result<()> {
    match version {
        "9" | "10" => Ok(()),
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "unsupported CentOS Stream version: {version} \
                 (supported: 9, 10)"
            ),
        )),
    }
}

/// The `-latest` image filename is deterministic (no directory scraping needed).
#[cfg(any(feature = "microvm", test))]
fn image_filename(version: &str, arch: &str) -> String {
    format!("CentOS-Stream-GenericCloud-{version}-latest.{arch}.qcow2")
}

/// Base URL for the CentOS Stream cloud images directory.
#[cfg(any(feature = "microvm", test))]
fn images_dir_url(version: &str, arch: &str) -> String {
    format!("https://cloud.centos.org/centos/{version}-stream/{arch}/images/")
}

/// Return the default metadata for CentOS Stream cloud images.
pub fn centos_metadata() -> ImageMetadata {
    ImageMetadata {
        root_device: CENTOS_ROOT_DEVICE.into(),
        fstype: CENTOS_FSTYPE.into(),
        mount_options: None,
        init: "/sbin/init".into(),
        sha256: None,
        base_sha256: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn images_dir_url_stream9() {
        let url = images_dir_url("9", "x86_64");
        assert_eq!(
            url,
            "https://cloud.centos.org/centos/9-stream/x86_64/images/"
        );
    }

    #[test]
    fn images_dir_url_stream10() {
        let url = images_dir_url("10", "aarch64");
        assert_eq!(
            url,
            "https://cloud.centos.org/centos/10-stream/aarch64/images/"
        );
    }

    #[test]
    fn image_filename_format() {
        assert_eq!(
            image_filename("9", "x86_64"),
            "CentOS-Stream-GenericCloud-9-latest.x86_64.qcow2"
        );
        assert_eq!(
            image_filename("10", "aarch64"),
            "CentOS-Stream-GenericCloud-10-latest.aarch64.qcow2"
        );
    }

    #[test]
    fn metadata_defaults() {
        let meta = centos_metadata();
        assert_eq!(meta.root_device, "/dev/vda4");
        assert_eq!(meta.fstype, "xfs");
        assert!(meta.mount_options.is_none());
        assert_eq!(meta.init, "/sbin/init");
    }

    #[test]
    fn validate_supported_versions() {
        assert!(validate_version("9").is_ok());
        assert!(validate_version("10").is_ok());
    }

    #[test]
    fn validate_unsupported_versions() {
        assert!(validate_version("8").is_err());
        assert!(validate_version("11").is_err());
        assert!(validate_version("").is_err());
        assert!(validate_version("latest").is_err());
    }
}
