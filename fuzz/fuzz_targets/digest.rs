#![no_main]

use blazeserve::cli::parse_digest_for_fuzz;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Split on the first NUL byte: JSON body before, optional Repr-Digest header after.
    let (body, repr_digest) = match data.iter().position(|b| *b == 0) {
        Some(i) => (&data[..i], std::str::from_utf8(&data[i + 1..]).ok()),
        None => (data, None),
    };
    if let Some((sha256, _size)) = parse_digest_for_fuzz(body, repr_digest) {
        assert_eq!(sha256.len(), 64);
        assert!(
            sha256
                .bytes()
                .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')),
            "non-lowercase hex digest: {sha256:?}"
        );
    }
});
