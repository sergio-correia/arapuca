.PHONY: build release build-microvm release-microvm agent agent-release test test-unit test-integration lint fmt fmt-check clippy check ci ci-full audit header man clean static install uninstall

ifeq ($(shell uname -s),Linux)
  FEATURES ?= microvm
else
  FEATURES ?=
endif
PREFIX  ?= /usr/local
LIBDIR  ?= $(PREFIX)/lib
DESTDIR ?=
VERSION := $(shell sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)

build:
	cargo build $(if $(FEATURES),--features $(FEATURES))
ifeq ($(shell uname -s),Linux)
	cargo build --features vm-agent --bin arapuca-agent
endif

release:
	cargo build --release $(if $(FEATURES),--features $(FEATURES))
ifeq ($(shell uname -s),Linux)
	cargo build --release --features vm-agent --bin arapuca-agent
endif

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
ifeq ($(shell uname -s),Linux)
	cargo clippy --features vm-agent --bin arapuca-agent -- -D warnings
endif

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

# Install static library, header, and pkg-config file.
# Runs its own cargo rustc to both build and capture native-static-libs
# in one invocation. Override INSTALL_FEATURES to include optional
# features (e.g., make install INSTALL_FEATURES=microvm).
INSTALL_FEATURES ?=
install: header
	touch src/lib.rs
	cargo rustc --release --lib \
	    $(if $(INSTALL_FEATURES),--features $(INSTALL_FEATURES)) \
	    -- --print native-static-libs 2>&1 \
	    | grep 'native-static-libs:' \
	    | sed 's/.*native-static-libs: //' > target/native-static-libs.txt
	test -s target/native-static-libs.txt || \
	    { echo "ERROR: failed to capture native-static-libs"; exit 1; }
	install -d $(DESTDIR)$(LIBDIR)/pkgconfig
	install -d $(DESTDIR)$(PREFIX)/include
	install -m 644 target/release/libarapuca.a $(DESTDIR)$(LIBDIR)/
	install -m 644 include/arapuca.h $(DESTDIR)$(PREFIX)/include/
	sed -e 's|@PREFIX@|$(PREFIX)|g' \
	    -e 's|@LIBDIR@|$(LIBDIR)|g' \
	    -e 's|@VERSION@|$(VERSION)|g' \
	    -e "s|@NATIVE_LIBS@|$$(cat target/native-static-libs.txt)|g" \
	    -e 's|@INSTALL_FEATURES@|$(INSTALL_FEATURES)|g' \
	    arapuca.pc.in > $(DESTDIR)$(LIBDIR)/pkgconfig/arapuca.pc

uninstall:
	rm -f $(DESTDIR)$(LIBDIR)/libarapuca.a
	rm -f $(DESTDIR)$(PREFIX)/include/arapuca.h
	rm -f $(DESTDIR)$(LIBDIR)/pkgconfig/arapuca.pc
