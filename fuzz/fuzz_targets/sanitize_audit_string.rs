#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(input) = std::str::from_utf8(data) else {
        return;
    };

    let output = arapuca::sanitize_audit_string(input);

    for c in output.chars() {
        // Control chars must be stripped (except newline).
        assert!(
            !c.is_control() || c == '\n',
            "control char survived: U+{:04X}",
            c as u32
        );

        // Bidi overrides and zero-width chars must be stripped.
        assert!(
            !matches!(
                c,
                '\u{200B}'..='\u{200D}'
                    | '\u{2028}'..='\u{2029}'
                    | '\u{2060}'
                    | '\u{FEFF}'
                    | '\u{202A}'..='\u{202E}'
                    | '\u{2066}'..='\u{2069}'
                    | '\u{200E}'
                    | '\u{200F}'
            ),
            "bidi/zero-width char survived: U+{:04X}",
            c as u32
        );
    }
});
