CARGO_ORIGIN := $(origin CARGO)
RUSTUP ?= rustup
RUST_TOOLCHAIN ?= $(shell $(RUSTUP) show active-toolchain 2>/dev/null | head -n1 | cut -d' ' -f1)
ifeq ($(strip $(RUST_TOOLCHAIN)),)
RUST_TOOLCHAIN := $(shell sed -n "s/^channel[[:space:]]*=[[:space:]]*\"\\(.*\\)\"/\\1/p" rust-toolchain.toml 2>/dev/null)
endif
CARGO ?= cargo
ifneq ($(strip $(RUST_TOOLCHAIN)),)
ifeq ($(CARGO_ORIGIN),undefined)
CARGO := $(RUSTUP) run $(RUST_TOOLCHAIN) cargo
endif
endif
CARGO_TARGET_DIR ?= target
DOCKER ?= docker

.PHONY: fmt lint test audit build-release docker-build testnet-up testnet-down e2e-up e2e-down

fmt:
	$(CARGO) fmt --all

lint:
	$(CARGO) fmt --all --check
	$(CARGO) clippy --workspace --all-targets --all-features -- -D warnings

test:
	$(CARGO) test --workspace --all-targets --locked

audit:
	cargo deny check
	cargo audit

build-release:
	$(CARGO) build --workspace --locked --release

docker-build:
	$(DOCKER) build -f docker/Dockerfile -t pqpriv:dev .

testnet-up:
	CARGO="$(CARGO)" bash scripts/testnet-up.sh

testnet-down:
	bash scripts/testnet-down.sh

e2e-up:
	$(DOCKER) compose -f docker/docker-compose.yml up -d

e2e-down:
	$(DOCKER) compose -f docker/docker-compose.yml down --remove-orphans
