.DEFAULT_GOAL := help
export PATH := $(HOME)/.cargo/bin:$(PATH)
export RUSTUP_TOOLCHAIN := $(shell sed -n 's/^channel = "\(.*\)"/\1/p' rust-toolchain.toml)

help: ## List the targets
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-12s %s\n", $$1, $$2}'

test: ## Build, test (workspace, then tv-enclave alone without test-hooks), a tiny tv-bench run, clippy -D warnings, fmt check
	cargo build --workspace --release && cargo test --workspace --release && cargo test -p tv-enclave --release && ./target/release/tv-bench --payments 5 --checks 8 --appends 8 --iterations 5 && cargo clippy --workspace --all-targets -- -D warnings && cargo clippy -p tv-enclave --all-targets -- -D warnings && cargo fmt --check

demo: ## Bank, mock enclave, two wallets: issue, pay, finish, refresh, redeem, recover
	./scripts/demo.sh

crash-demo: ## Enclave killed before its answer, bank killed after its append: retries settle, balances unchanged
	./scripts/crash-demo.sh

bench: ## Enclave checks, store appends, bank settles, loopback latency, client cost, message sizes
	cargo run --release -p tv-bench -- --payments 1000

.PHONY: help test demo crash-demo bench
