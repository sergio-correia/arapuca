.PHONY: build release build-microvm release-microvm agent agent-release test test-unit test-integration lint fmt fmt-check clippy check ci ci-full audit header man clean static

FEATURES ?= microvm

build:
	cargo build $(if $(FEATURES),--features $(FEATURES))
	cargo build --features vm-agent --bin arapuca-agent

release:
	cargo build --release $(if $(FEATURES),--features $(FEATURES))
	cargo build --release --features vm-agent --bin arapuca-agent

# Build with micro-VM support (requires libkrun).
build-microvm:
	cargo build --features microvm
	cargo build --features vm-agent --bin arapuca-agent

release-microvm:
	cargo build --release --features microvm
	cargo build --release --features vm-agent --bin arapuca-agent

# Build the guest agent only (no libkrun dependency).
agent:
	cargo build --features vm-agent --bin arapuca-agent

agent-release:
	cargo build --release --features vm-agent --bin arapuca-agent

test:
	cargo test $(if $(FEATURES),--features $(FEATURES))

# Unit tests only (no integration tests — safe on all platforms).
test-unit:
	cargo test --lib

# Integration tests (Linux only — exercises Landlock, seccomp, cgroups).
test-integration:
	cargo test --test adversarial

lint: fmt-check clippy

fmt:
	cargo fmt

fmt-check:
	cargo fmt --check

clippy:
	cargo clippy -- -D warnings
	$(if $(FEATURES),cargo clippy --features $(FEATURES) -- -D warnings)
	cargo clippy --features vm-agent --bin arapuca-agent -- -D warnings

# Full pre-commit / CI gate: format, lint, unit tests.
check: fmt-check clippy test-unit

# CI-only: full check + integration tests (Linux) or unit-only (other).
# Usage: make ci              (auto-detects platform)
#        make ci-full          (Linux: includes integration tests)
ci: check
ifeq ($(shell uname -s),Linux)
	cargo test --test adversarial
endif

ci-full: fmt-check clippy test

audit:
	cargo audit
	cargo deny check

header:
	cbindgen --config cbindgen.toml --crate arapuca --output include/arapuca.h

man:
	pandoc doc/arapuca.1.md -s -t man -o doc/arapuca.1

clean:
	cargo clean

# Static Linux binary (musl).
static:
	cargo build --release --target x86_64-unknown-linux-musl
