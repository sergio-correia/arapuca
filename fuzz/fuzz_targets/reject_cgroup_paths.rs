#![no_main]
use libfuzzer_sys::fuzz_target;

use std::path::{Path, PathBuf};

fuzz_target!(|data: &[u8]| {
    let Ok(input) = std::str::from_utf8(data) else {
        return;
    };

    let paths = vec![PathBuf::from(input)];

    if arapuca::reject_cgroup_paths(&paths).is_ok() {
        // Lexical normalization must not resolve to /sys/fs/cgroup.
        let normalized = arapuca::normalize_path(Path::new(input));
        let ns = normalized.to_string_lossy();
        assert!(
            !ns.starts_with("/sys/fs/cgroup"),
            "accepted path normalized to cgroup: {input} -> {ns}"
        );
    }
});
