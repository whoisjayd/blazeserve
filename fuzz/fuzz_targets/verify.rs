#![no_main]

use blazeserve::cli::parse_lists_for_fuzz;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|text: &str| {
    for name in parse_lists_for_fuzz(text) {
        assert!(!name.is_empty() && name != "." && name != "..", "bad name: {name:?}");
        assert!(!name.contains(['/', '\0']), "not a file name: {name:?}");
    }
});
