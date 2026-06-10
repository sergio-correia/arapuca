#![no_main]
use libfuzzer_sys::fuzz_target;

use std::path::Path;

fuzz_target!(|data: &[u8]| {
    let Ok(input) = std::str::from_utf8(data) else {
        return;
    };

    if arapuca::validate_guest_path(input).is_ok() {
        let normalized = arapuca::normalize_path(Path::new(input));
        let ns = normalized.to_string_lossy();

        // Must not resolve to root.
        assert!(ns != "/");

        // Must not contain `..` components after normalization.
        assert!(!Path::new(&*ns).components().any(|c| {
            matches!(c, std::path::Component::ParentDir)
        }));

        // Must not land in any denied prefix.
        for prefix in arapuca::GUEST_PATH_DENY_PREFIXES {
            assert!(
                ns != *prefix && !ns.starts_with(&format!("{prefix}/")),
                "accepted path resolved to denied prefix {prefix}: {input} -> {ns}"
            );
        }
    }
});
