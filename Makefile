.PHONY: build test lint fmt check audit wheel clean

build:
	cargo build --release

test:
	cargo test --all-targets

lint:
	cargo fmt --all -- --check
	cargo clippy --all-targets -- -D warnings

fmt:
	cargo fmt --all

check: lint test

audit:
	cargo deny check

wheel:
	uvx maturin build --release --out dist

clean:
	cargo clean
	rm -rf dist
