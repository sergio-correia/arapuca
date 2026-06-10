#![no_main]
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct EnvInput {
    vars: Vec<(String, String)>,
}

fuzz_target!(|input: EnvInput| {
    let result = arapuca::env::filter_caller_env(&input.vars);

    // Every passed key must not match any blocked pattern.
    for (key, _) in &result.passed {
        assert!(
            arapuca::env::drop_reason(key).is_none(),
            "dangerous key passed through filter: {key:?}"
        );
    }

    // Every dropped key must have a reason.
    for dropped in &result.dropped {
        assert!(
            arapuca::env::drop_reason(&dropped.key).is_some(),
            "key dropped without matching any rule: {:?}",
            dropped.key
        );
    }

    // Total must equal input count.
    assert_eq!(
        result.passed.len() + result.dropped.len(),
        input.vars.len()
    );
});
