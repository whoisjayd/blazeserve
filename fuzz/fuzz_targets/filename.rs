#![no_main]

use blazeserve::cli::suggested_name_for_fuzz;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|header: &str| {
    if let Some(name) = suggested_name_for_fuzz(header) {
        assert!(!name.is_empty() && name.len() <= 255, "bad len: {name:?}");
        assert!(!name.contains(['/', '\\']), "separator in {name:?}");
        assert!(
            !name
                .chars()
                .any(|c| c.is_control() || matches!(c, ':' | '<' | '>' | '"' | '|' | '?' | '*')),
            "unsafe char in {name:?}"
        );
        assert_ne!(name, ".");
        assert_ne!(name, "..");
        assert!(!name.ends_with('.'), "trailing dot in {name:?}");
        assert!(!name.ends_with(' '), "trailing space in {name:?}");
    }
});
