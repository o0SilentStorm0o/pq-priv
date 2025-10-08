CARGO ?= cargo
CARGO_TARGET_DIR ?= target
DOCKER ?= docker

.PHONY: fmt lint test audit build-release docker-build testnet-up testnet-down

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
RUSTFLAGS="-C link-arg=-s" $(CARGO) build --workspace --locked --release

docker-build:
$(DOCKER) build -f docker/Dockerfile -t pqpriv:dev .

testnet-up:
bash scripts/testnet-up.sh

testnet-down:
bash scripts/testnet-down.sh
