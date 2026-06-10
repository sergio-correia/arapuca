#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(input) = std::str::from_utf8(data) else {
        return;
    };

    if let Ok(id) = arapuca::sanitize_task_id(input) {
        assert!(id.len() <= 128);
        assert!(id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-'));
        assert!(!id.is_empty());
    }
});
