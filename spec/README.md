# Protocol Specifications

This directory will host human-readable specifications that accompany the PQ-PRIV whitepaper and implementation blueprint. Drafts should cover transaction formats, consensus constants, proof system interfaces, and upgrade processes so that contributors have a canonical reference while implementing the workspace crates.

## Getting Started

* Start with the existing implementation blueprint in the repository root for the overall roadmap.
* Add focused RFC-style documents here as features stabilize (e.g., transaction serialization, STARK circuit interfaces, wallet audit flows).
* Keep each document versioned and include open questions plus acceptance criteria so downstream teams can plan audits.

## Available drafts

- [`blueprint.md`](./blueprint.md) – long-term architectural roadmap.
- [`build.md`](./build.md) – build and release procedures.
- [`storage.md`](./storage.md) – RocksDB schema, checkpoints, and batch semantics.
- [`fork-choice.md`](./fork-choice.md) – chain selection, reorg handling, and sync tasks.
- [`metrics.md`](./metrics.md) – Prometheus gauges exported via JSON-RPC.

> **Note:** Until the individual specs are filled in, treat this directory as the staging area for protocol documentation contributions.
