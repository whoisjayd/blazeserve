.PHONY: build test lint fmt check audit wheel hooks clean

build:
	cargo build --release

test:
	cargo test --all-targets --locked

lint:
	cargo fmt --all -- --check
	cargo clippy --all-targets --locked -- -D warnings

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

hooks:
	git config core.hooksPath .githooks
