## Summary

What changed and why. Mention anything that could break for existing users.

Fixes #

## Testing

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --all-targets --locked -- -D warnings`
- [ ] `cargo test --all-targets --locked`
- [ ] I tested on these platforms (Linux, Windows, macOS), and noted any difference in behaviour below.

## Checklist

- [ ] No passwords, tokens, keys or private data in the diff, tests or logs.
- [ ] The guides in `docs/`, `deploy/README.md` and `CONTRIBUTING.md` are updated if behaviour, commands or deployment changed.
- [ ] If this touches paths, uploads, authentication, TLS or logging, I checked how data is handled.
