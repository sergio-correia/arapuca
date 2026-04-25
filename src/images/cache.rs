//! Image cache management.
//!
//! Cached images live under `$XDG_DATA_HOME/arapuca/images/`
//! (or `~/.local/share/arapuca/images/`). Each image is a pair:
//! `{name}.qcow2` + `{name}.meta.json`.

use std::io;
use std::path::{Path, PathBuf};

use super::metadata::ImageMetadata;

/// A cached image with its metadata.
#[derive(Debug, Clone)]
pub struct CachedImage {
    /// Path to the qcow2 file.
    pub path: PathBuf,
    /// Boot metadata (root device, fstype, init).
    pub metadata: ImageMetadata,
}

/// Return the images cache directory, creating it if needed.
pub fn images_dir() -> io::Result<PathBuf> {
    let base = data_home()?;
    let dir = base.join("arapuca").join("images");
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

/// Look up a cached image by name.
///
/// Names must be simple identifiers (alphanumeric, hyphens, dots,
/// underscores). Path separators and `..` are rejected.
pub fn lookup(name: &str) -> io::Result<Option<CachedImage>> {
    validate_name(name)?;
    let dir = images_dir()?;
    let qcow2 = dir.join(format!("{name}.qcow2"));
    if !qcow2.exists() {
        return Ok(None);
    }
    let metadata = ImageMetadata::load_sidecar(&qcow2)?;
    Ok(Some(CachedImage {
        path: qcow2,
        metadata,
    }))
}

/// Store an image in the cache by moving/copying it from `src_path`.
pub fn store(name: &str, src_path: &Path, metadata: &ImageMetadata) -> io::Result<CachedImage> {
    validate_name(name)?;
    let dir = images_dir()?;
    let dest = dir.join(format!("{name}.qcow2"));

    if src_path != dest {
        std::fs::copy(src_path, &dest)?;
    }
    metadata.save_sidecar(&dest)?;

    Ok(CachedImage {
        path: dest,
        metadata: metadata.clone(),
    })
}

/// Remove a cached image by name. Returns true if removed.
pub fn remove(name: &str) -> io::Result<bool> {
    validate_name(name)?;
    let dir = images_dir()?;
    let qcow2 = dir.join(format!("{name}.qcow2"));
    let meta = super::metadata::sidecar_path(&qcow2);

    if !qcow2.exists() {
        return Ok(false);
    }

    std::fs::remove_file(&qcow2)?;
    let _ = std::fs::remove_file(&meta);
    Ok(true)
}

/// List all cached images.
pub fn list() -> io::Result<Vec<(String, CachedImage)>> {
    let dir = match images_dir() {
        Ok(d) => d,
        Err(_) => return Ok(Vec::new()),
    };

    let mut result = Vec::new();
    let entries = match std::fs::read_dir(&dir) {
        Ok(e) => e,
        Err(_) => return Ok(Vec::new()),
    };

    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("qcow2") {
            continue;
        }
        let name = match path.file_stem().and_then(|s| s.to_str()) {
            Some(n) => n.to_string(),
            None => continue,
        };
        let metadata = match ImageMetadata::load_sidecar(&path) {
            Ok(m) => m,
            Err(_) => continue,
        };
        result.push((name, CachedImage { path, metadata }));
    }

    result.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(result)
}

fn data_home() -> io::Result<PathBuf> {
    if let Ok(xdg) = std::env::var("XDG_DATA_HOME") {
        if !xdg.is_empty() {
            return Ok(PathBuf::from(xdg));
        }
    }
    match std::env::var("HOME") {
        Ok(home) if !home.is_empty() => Ok(PathBuf::from(home).join(".local").join("share")),
        _ => Err(io::Error::new(
            io::ErrorKind::NotFound,
            "neither XDG_DATA_HOME nor HOME is set",
        )),
    }
}

fn validate_name(name: &str) -> io::Result<()> {
    if name.is_empty()
        || name.contains('/')
        || name.contains('\\')
        || name == "."
        || name == ".."
        || name.contains("..")
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid image name: {name}"),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Mutex;

    // Serialize cache tests that mutate XDG_DATA_HOME.
    static CACHE_LOCK: Mutex<()> = Mutex::new(());

    fn with_test_cache(f: impl FnOnce()) {
        let _guard = CACHE_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        // SAFETY: serialized by CACHE_LOCK — no other test is
        // reading/writing XDG_DATA_HOME concurrently.
        unsafe { std::env::set_var("XDG_DATA_HOME", dir.path()) };
        f();
        unsafe { std::env::remove_var("XDG_DATA_HOME") };
    }

    #[test]
    fn store_and_lookup() {
        with_test_cache(|| {
            let tmp = tempfile::tempdir().unwrap();
            let src = tmp.path().join("test.qcow2");
            std::fs::write(&src, b"fake qcow2 data").unwrap();

            let meta = ImageMetadata {
                root_device: "/dev/vda1".into(),
                fstype: "ext4".into(),
                mount_options: None,
                init: "/sbin/init".into(),
                sha256: None,
                base_sha256: None,
            };

            let cached = store("fedora-43-x86_64", &src, &meta).unwrap();
            assert!(cached.path.exists());
            assert_eq!(cached.metadata.root_device, "/dev/vda1");

            let found = lookup("fedora-43-x86_64").unwrap().unwrap();
            assert_eq!(found.metadata.fstype, "ext4");
        });
    }

    #[test]
    fn lookup_missing() {
        with_test_cache(|| {
            let found = lookup("nonexistent").unwrap();
            assert!(found.is_none());
        });
    }

    #[test]
    fn remove_existing() {
        with_test_cache(|| {
            let tmp = tempfile::tempdir().unwrap();
            let src = tmp.path().join("test.qcow2");
            std::fs::write(&src, b"data").unwrap();

            let meta = ImageMetadata {
                root_device: "/dev/vda1".into(),
                fstype: "ext4".into(),
                mount_options: None,
                init: "/sbin/init".into(),
                sha256: None,
                base_sha256: None,
            };
            store("to-remove", &src, &meta).unwrap();

            assert!(remove("to-remove").unwrap());
            assert!(lookup("to-remove").unwrap().is_none());
        });
    }

    #[test]
    fn remove_missing() {
        with_test_cache(|| {
            assert!(!remove("nonexistent").unwrap());
        });
    }

    #[test]
    fn list_empty() {
        with_test_cache(|| {
            let images = list().unwrap();
            assert!(images.is_empty());
        });
    }

    #[test]
    fn list_with_images() {
        with_test_cache(|| {
            let tmp = tempfile::tempdir().unwrap();
            let src = tmp.path().join("test.qcow2");
            std::fs::write(&src, b"data").unwrap();

            let meta = ImageMetadata {
                root_device: "/dev/vda1".into(),
                fstype: "ext4".into(),
                mount_options: None,
                init: "/sbin/init".into(),
                sha256: None,
                base_sha256: None,
            };
            store("alpha", &src, &meta).unwrap();
            store("beta", &src, &meta).unwrap();

            let images = list().unwrap();
            assert_eq!(images.len(), 2);
            assert_eq!(images[0].0, "alpha");
            assert_eq!(images[1].0, "beta");
        });
    }

    #[test]
    fn reject_path_traversal_names() {
        with_test_cache(|| {
            assert!(lookup("../etc/shadow").is_err());
            assert!(lookup("foo/bar").is_err());
            assert!(lookup("").is_err());
            assert!(lookup("..").is_err());
            assert!(lookup(".").is_err());
        });
    }

    #[test]
    fn accept_valid_names() {
        with_test_cache(|| {
            assert!(lookup("fedora-43-x86_64").unwrap().is_none());
            assert!(lookup("rhel-10.0-aarch64").unwrap().is_none());
        });
    }
}
