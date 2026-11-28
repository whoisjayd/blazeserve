# BlazeServe fuzz targets

Separate Cargo workspace for `cargo-fuzz` (nightly Rust + libFuzzer). It builds `blazeserve` with `default-features = false` so `extract` (bundled zstd C sources) is skipped.

## Targets

| Target | Exercises | Invariants checked |
| :--- | :--- | :--- |
| `range` | `blazeserve::range::parse_range_header` | Non-empty ranges, `start <= end`, `end < size`, no panic on arbitrary input |
| `digest` | `discover::parse_digest` (JSON body + `Repr-Digest`) | Lowercase 64-char hex SHA-256 on success, no panic on malformed JSON/base64 |
| `path` | `resolve::decode_components`, `security::resolve_under`, `security::is_safe_path` | Single-pass decode, no `.`/`..`/separators/NUL in components, canonical path stays inside root |
| `filename` | `filename::suggested_name` (`Content-Disposition`) | Non-empty, <= 255 bytes, no path separators, no control/Windows-illegal chars, not `.`/`..`, no trailing dot/space |
| `verify` | `verify` checksum and SFV list parsers | A listed name is a bare file name: never empty, `.`, `..`, or holding `/` or NUL |

## Running locally

```sh
rustup toolchain install nightly --profile minimal
cargo install cargo-fuzz --version 0.13.2 --locked
cargo +nightly fuzz run range -- -max_total_time=120 -max_len=4096
```

Only small seed inputs belong under `corpus/<target>/`; generated artifacts and coverage stay untracked.
