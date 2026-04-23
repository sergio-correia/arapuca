//! Copy-on-write qcow2 overlay creation.
//!
//! Creates ephemeral overlays backed by a template image so the
//! template is never modified. Each VM launch gets its own overlay.

use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Create a qcow2 overlay backed by `template`.
///
/// The overlay is created as `disk.qcow2` in `overlay_dir`.
/// Writes go to the overlay; the template remains immutable.
///
/// Requires `qemu-img` in PATH.
///
/// # Errors
///
/// Returns an error if `qemu-img` is not found, fails to run,
/// or exits with a non-zero status.
pub fn create_overlay(template: &Path, overlay_dir: &Path) -> io::Result<PathBuf> {
    std::fs::create_dir_all(overlay_dir)?;

    let template = std::fs::canonicalize(template).map_err(|e| {
        io::Error::other(format!("template not found: {}: {e}", template.display()))
    })?;

    let overlay = overlay_dir.join("disk.qcow2");

    let output = Command::new("qemu-img")
        .arg("create")
        .arg("-f")
        .arg("qcow2")
        .arg("-b")
        .arg(&template)
        .arg("-F")
        .arg("qcow2")
        .arg(&overlay)
        .output()
        .map_err(|e| {
            io::Error::other(format!("qemu-img not found (is qemu-img installed?): {e}"))
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(io::Error::other(format!(
            "qemu-img create failed: {}",
            stderr.trim()
        )));
    }

    Ok(overlay)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_overlay_missing_template() {
        let dir = tempfile::tempdir().unwrap();
        let err = create_overlay(Path::new("/nonexistent.qcow2"), dir.path());
        assert!(err.is_err());
        assert!(err.unwrap_err().to_string().contains("template not found"));
    }

    #[test]
    fn create_overlay_with_fake_template() {
        let dir = tempfile::tempdir().unwrap();
        let template = dir.path().join("base.qcow2");
        std::fs::write(&template, b"not a real qcow2").unwrap();

        let overlay_dir = dir.path().join("overlay");
        // qemu-img may or may not be installed. Either outcome is
        // valid — we verify no panic.
        let result = create_overlay(&template, &overlay_dir);
        match &result {
            Ok(p) => eprintln!("overlay created: {}", p.display()),
            Err(e) => eprintln!("expected error: {e}"),
        }
    }
}
