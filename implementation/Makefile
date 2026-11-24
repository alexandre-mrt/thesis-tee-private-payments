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

nitro-up: ## On the EC2 parent: build, start the enclave from ~/tv-enclave.eif and the bank under its PCR0, register
	cargo build --release -p tv-bank -p tv-client -p tv-bench && ./scripts/nitro-up.sh

nitro-bench: nitro-up ## On the EC2 parent: nitro-up, then the mock baseline and the Nitro run, saved to ~/bench-results
	./scripts/nitro-bench.sh

nitro-down: ## On the EC2 parent: stop the bank and terminate the enclave
	./scripts/nitro-down.sh

.PHONY: help test demo crash-demo bench nitro-up nitro-bench nitro-down
