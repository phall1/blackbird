.PHONY: fmt lint test check build

fmt:
	cargo fmt --manifest-path rust/Cargo.toml

lint:
	cargo fmt --manifest-path rust/Cargo.toml -- --check
	cargo clippy --manifest-path rust/Cargo.toml --all-targets -- -D warnings

test:
	cargo test --manifest-path rust/Cargo.toml

check: lint test

build:
	cargo build --manifest-path rust/Cargo.toml --release --bin blackbird
