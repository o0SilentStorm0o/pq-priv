CARGO ?= cargo
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
	bash scripts/testnet-up.sh

testnet-down:
        bash scripts/testnet-down.sh

e2e-up:
	$(DOCKER) compose -f docker/docker-compose.yml up -d

e2e-down:
	$(DOCKER) compose -f docker/docker-compose.yml down --remove-orphans
