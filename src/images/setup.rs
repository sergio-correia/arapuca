//! Setup layers — cached pre-configured images.
//!
//! A setup layer is a qcow2 overlay on a base image with
//! pre-installed software. It sits between the base image and the
//! ephemeral per-run overlay in the qcow2 backing chain:
//!
//! ```text
//! base.qcow2 → setup.qcow2 → ephemeral.qcow2
//! ```

use std::io;
use std::path::Path;

/// Naming convention: `{base_name}.setup-{hash}` where hash is the
/// first 32 hex chars of SHA256(setup_script).
const HASH_PREFIX_LEN: usize = 32;

/// Compute the setup layer cache name from the base image name and
/// the setup script content.
pub fn setup_name(base_name: &str, script: &str) -> io::Result<String> {
    let hash = script_hash(script)?;
    Ok(format!("{base_name}.setup-{hash}"))
}

/// Look up a cached setup layer for a base image + script.
///
/// Returns `None` if no matching setup layer exists. If found,
/// verifies that the base image SHA256 still matches (the setup
/// layer was built against the same base image build).
pub fn lookup(
    base_name: &str,
    script: &str,
    base_sha256: Option<&str>,
) -> io::Result<Option<super::cache::CachedImage>> {
    let name = setup_name(base_name, script)?;
    let cached = match super::cache::lookup(&name)? {
        Some(c) => c,
        None => return Ok(None),
    };

    // Verify base image hasn't changed since the setup layer was created.
    if let (Some(expected), Some(actual)) = (cached.metadata.base_sha256.as_deref(), base_sha256) {
        if expected != actual {
            eprintln!(
                "warning: setup layer {name} was built against a different \
                 base image build — run `arapuca image setup` again to rebuild"
            );
            return Ok(None);
        }
    }

    Ok(Some(cached))
}

/// Store a setup layer overlay in the cache.
///
/// The overlay at `overlay_path` is moved into the cache directory.
/// The sidecar metadata includes the base image's SHA256 so we can
/// detect when the base changes.
pub fn store(
    base_name: &str,
    script: &str,
    overlay_path: &Path,
    base_metadata: &super::metadata::ImageMetadata,
    base_sha256: Option<&str>,
) -> io::Result<super::cache::CachedImage> {
    let name = setup_name(base_name, script)?;

    let mut metadata = base_metadata.clone();
    metadata.base_sha256 = base_sha256.map(String::from);

    // Hash the setup layer itself for integrity tracking.
    #[cfg(feature = "microvm")]
    {
        let hash = super::download::sha256_file(overlay_path)?;
        metadata.sha256 = Some(hash);
    }

    super::cache::store(&name, overlay_path, &metadata)
}

/// List all setup layers for a given base image.
pub fn list_for_base(base_name: &str) -> io::Result<Vec<(String, super::cache::CachedImage)>> {
    let prefix = format!("{base_name}.setup-");
    let all = super::cache::list()?;
    Ok(all
        .into_iter()
        .filter(|(name, _)| name.starts_with(&prefix))
        .collect())
}

/// Remove orphaned setup layers whose base image SHA256 no longer
/// matches the current base image.
pub fn clean_orphaned(base_name: &str, current_sha256: Option<&str>) -> io::Result<usize> {
    let layers = list_for_base(base_name)?;
    let mut removed = 0;

    for (name, cached) in layers {
        let stale = match (cached.metadata.base_sha256.as_deref(), current_sha256) {
            (Some(expected), Some(actual)) => expected != actual,
            (Some(_), None) => true,
            _ => false,
        };
        if stale {
            eprintln!("removing orphaned setup layer: {name}");
            super::cache::remove(&name)?;
            removed += 1;
        }
    }

    Ok(removed)
}

/// Compute the first 32 hex chars of SHA256(script_content).
fn script_hash(script: &str) -> io::Result<String> {
    let mut hasher = openssl::hash::Hasher::new(openssl::hash::MessageDigest::sha256())
        .map_err(|e| io::Error::other(format!("SHA256 init: {e}")))?;
    hasher
        .update(script.as_bytes())
        .map_err(|e| io::Error::other(format!("SHA256 update: {e}")))?;
    let digest = hasher
        .finish()
        .map_err(|e| io::Error::other(format!("SHA256 finish: {e}")))?;

    let hex = super::download::hex_encode(&digest);
    Ok(hex[..HASH_PREFIX_LEN].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn setup_name_format() {
        let name = setup_name("fedora-42-x86_64", "dnf install -y git").unwrap();
        assert!(name.starts_with("fedora-42-x86_64.setup-"));
        let hash_part = name.strip_prefix("fedora-42-x86_64.setup-").unwrap();
        assert_eq!(hash_part.len(), HASH_PREFIX_LEN);
        assert!(hash_part.bytes().all(|b| b.is_ascii_hexdigit()));
    }

    #[test]
    fn setup_name_deterministic() {
        let a = setup_name("base", "script1").unwrap();
        let b = setup_name("base", "script1").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn setup_name_different_scripts() {
        let a = setup_name("base", "script1").unwrap();
        let b = setup_name("base", "script2").unwrap();
        assert_ne!(a, b);
    }
}
