//! Micro-VM image management.
//!
//! Provides image caching, metadata handling, and provider
//! resolution for micro-VM root filesystem images.

pub mod cache;
pub mod cloudinit;
#[cfg(feature = "microvm")]
pub mod download;
pub mod fedora;
pub mod metadata;
pub mod overlay;
#[cfg(feature = "microvm")]
pub mod probe;
pub mod provider;

pub use cache::CachedImage;
pub use metadata::ImageMetadata;

/// Resolve an image source to a cached image.
///
/// Dispatches to the built-in Fedora provider or an external
/// `arapuca-images-{distro}` provider based on the distro name.
/// For explicit paths, loads the sidecar metadata.
#[cfg(feature = "microvm")]
pub fn resolve(source: &crate::ImageSource) -> std::io::Result<CachedImage> {
    match source {
        crate::ImageSource::Path(path) => {
            let metadata = ImageMetadata::load_sidecar(path)?;
            Ok(CachedImage {
                path: path.clone(),
                metadata,
            })
        }
        crate::ImageSource::Distro { name, version } => match name.as_str() {
            "fedora" => fedora::resolve(version),
            _ => provider::resolve_external(name, version),
        },
    }
}
