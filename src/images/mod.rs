//! Micro-VM image management.
//!
//! Provides image caching, metadata handling, and provider
//! resolution for micro-VM root filesystem images.

pub mod cache;
#[cfg(feature = "microvm")]
pub mod download;
pub mod fedora;
pub mod metadata;

pub use cache::CachedImage;
pub use metadata::ImageMetadata;
