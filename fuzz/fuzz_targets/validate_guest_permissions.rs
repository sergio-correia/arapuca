#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(input) = std::str::from_utf8(data) else {
        return;
    };

    if arapuca::validate_guest_permissions(input).is_ok() {
        let bytes = input.as_bytes();

        // Must be 3-4 octal digits.
        assert!(bytes.len() == 3 || bytes.len() == 4);
        assert!(bytes.iter().all(|b| (b'0'..=b'7').contains(b)));

        // 4-digit form must not have setuid/setgid/sticky.
        if bytes.len() == 4 {
            assert_eq!(bytes[0], b'0');
        }
    }
});
