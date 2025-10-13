# syntax=docker/dockerfile:1

FROM rust:1.90-bullseye AS builder
WORKDIR /usr/src/pq-priv

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    clang \
    pkg-config \
    libssl-dev \
 && rm -rf /var/lib/apt/lists/*

COPY . .
RUN cargo build --release --locked --bins

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
 && rm -rf /var/lib/apt/lists/*
RUN useradd --create-home --uid 1000 pqpriv
WORKDIR /home/pqpriv

COPY --from=builder /usr/src/pq-priv/target/release/node /usr/local/bin/pqprivd
COPY --from=builder /usr/src/pq-priv/target/release/wallet /usr/local/bin/pqpriv-wallet

# Create data directory with correct permissions
RUN mkdir -p /home/pqpriv/.pqpriv && chown -R pqpriv:pqpriv /home/pqpriv/.pqpriv

USER pqpriv
ENTRYPOINT ["/usr/local/bin/pqprivd"]
CMD ["--help"]
