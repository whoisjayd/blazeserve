#![no_main]

use blazeserve::range::{RangeSpec, parse_range_header};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // First 8 bytes pick the representation size; the rest is the Range header value.
    if data.len() < 8 {
        return;
    }
    let size = u64::from_le_bytes(data[..8].try_into().expect("8 bytes"));
    let Ok(header) = std::str::from_utf8(&data[8..]) else {
        return;
    };
    match parse_range_header(Some(header), size) {
        RangeSpec::Ranges(ranges) => {
            assert!(!ranges.is_empty(), "empty Ranges for {header:?}");
            for (start, end) in ranges {
                assert!(start <= end, "start {start} > end {end} for {header:?}");
                assert!(end < size, "end {end} >= size {size} for {header:?}");
            }
        }
        RangeSpec::Ignore | RangeSpec::Unsatisfiable => {}
    }
});
