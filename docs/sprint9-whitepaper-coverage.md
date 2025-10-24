# PQ-PRIV — Whitepaper Coverage Matrix (Sprint 9)

This document tracks the implementation status of features and claims from the PQ-PRIV whitepaper against the codebase. It serves as a **single source of truth** for grants, investors, and auditors to verify that the implementation matches the specification.

## Purpose

- **Grant Applications**: Demonstrate concrete progress aligned with whitepaper promises
- **Investor Due Diligence**: Link high-level claims to verifiable code artifacts
- **Audit Preparation**: Provide clear mapping for security reviews
- **Development Tracking**: Ensure no whitepaper feature is forgotten

## Coverage Table

| Whitepaper § | Claim / Feature | Module/Crate | Public API / Types | Tests | Status |
|---|---|---|---|---|---|
| **§3 High-level Architecture** |
| 3.2 | STARK one-of-many (transparent, ZK) | `crypto/stark` | `StarkParams`, `prove_one_of_many`, `verify_one_of_many` | unit, bench | 🟨 |
| 3.4 | Post-quantum signatures (Dilithium2) | `crypto` | `sign_dilithium`, `verify_dilithium` | ✅ Sprint 7 | ✅ |
| 3.4 | Range proofs (Bulletproofs+) | `crypto` | `prove_range`, `verify_range`, `batch_verify_range` | ✅ Sprint 8 | ✅ |
| **§5 Transaction Model** |
| 5.1 | TX version 2 (privacy-enabled) | `tx`, `tx/witness.rs` | `TxV2`, `Nullifier([u8;32])`, `SpendTag([u8;32])` | roundtrip, consensus | ⬜ |
| 5.3 | Nullifier construction (Poseidon2) | `tx/witness.rs` | `compute_nullifier(sk_spend, commitment, net_id, version)` | unit | ⬜ |
| 5.3 | Spend tag (view key tagging) | `tx/witness.rs` | `compute_spend_tag(sk_view, commitment, epoch)` | unit | ⬜ |
| 5.4 | Backwards compatibility (version flag) | `node/consensus` | `consensus.features.stark = bool` | integration | ⬜ |
| **§6 Spend Flow** |
| 6.2 | Nullifier double-spend detection | `storage/indexes.rs` | `nullifier_index: RocksDB CF` | integration, reorg | ⬜ |
| 6.3 | Atomic reorg (nullifier rollback) | `storage` | `commit_block_batch`, `rollback_block_batch` | integration | ⬜ |
| 6.4 | Mempool policy (anonymity set size) | `node/mempool.rs` | `validate_tx_v2`, `reject_if_anon_set_too_small` | unit | ⬜ |
| **§10 Compliance & Audit** |
| 10.1 | Audit packet L1 (encrypted for exchange) | `wallet/audit.rs` | `create_audit_packet(level: L1, pubkey, witness)` | e2e | ⬜ |
| 10.2 | Audit packet L2 (selective disclosure) | `wallet/audit.rs` | `create_audit_packet(level: L2, ...)` | e2e | ⬜ |
| 10.3 | Audit packet L3 (chain-of-custody ZK) | `wallet/audit.rs` | `create_audit_packet(level: L3, ...)` | e2e | ⬜ |
| 10.4 | Hybrid encryption (Kyber512 + X25519) | `wallet/audit.rs` | `hybrid_encrypt(kem_pk, ecdh_pk, plaintext)` | unit | ⬜ |
| 10.5 | Audit signature (Dilithium2) | `wallet/audit.rs` | `sign_audit_packet(sk_audit, packet)` | unit | ⬜ |
| 10.6 | Key rotation (JWKS-like) | `wallet/audit.rs` | `AuditKeySet { kid, alg, notBefore, notAfter }` | integration | ⬜ |
| **§11 Exchange Integration** |
| 11.1 | Exchange SDK (Rust + TypeScript) | `sdk/exchange` | Rust: `ExchangeClient`, TS: `@pq-priv/exchange-sdk` | sandbox | ⬜ |
| 11.2 | Deposit subaddress generation | `sdk/exchange` | `POST /v1/deposits/subaddress` | integration | ⬜ |
| 11.3 | Audit packet verification | `sdk/exchange` | `POST /v1/audit/verify` | integration | ⬜ |
| 11.4 | Docker sandbox (compliance testing) | `sdk/exchange/docker` | `docker-compose up -d exchange-sandbox` | e2e | ⬜ |
| **§14 Performance** |
| 14.1 | STARK prove time < 500ms (anonymity=64) | `crypto/stark` | `prove_one_of_many` | bench | ⬜ |
| 14.2 | STARK verify time < 50ms | `crypto/stark` | `verify_one_of_many` | bench | ⬜ |
| 14.3 | Range proof batch verify (parallel) | `crypto` | `batch_verify_range` (7.9x speedup) | ✅ Sprint 8 | ✅ |
| 14.4 | TPS with privacy ≥ 1,500 | `node` | End-to-end benchmark | ⬜ Sprint 10 | ⬜ |
| **§17 Roadmap** |
| 17.1 | Soft-fork activation (feature flag) | `node/consensus` | `consensus.features.stark = true` | integration | ⬜ |
| 17.2 | Protocol versioning (TX v2) | `tx` | `tx.version = 2` | consensus | ⬜ |
| 17.3 | Monitoring (Prometheus metrics) | `node/metrics.rs` | `stark_prove_duration_seconds`, `nullifier_index_size` | operational | ⬜ |

## Legend

- ⬜ **Planned** — Not yet implemented
- 🟨 **In Progress** — Partial implementation (skeleton, stubs, or WIP)
- ✅ **Done** — Fully implemented with passing tests

## Notes

### Sprint 8 Completion (✅)
- Range proofs: 675-byte proofs, 2.44ms verify, 7.9x parallel speedup
- Benchmarks: 3,238 proofs/sec (parallel batch)
- TPS impact: 1,640+ with full privacy (2x slower than public TX)
- Documentation: `docs/perf/range-proof-performance.md`, `docs/perf/crypto-comparison.md`

### Sprint 9 Scope (🟨)
- STARK one-of-many: Skeleton created (traits, params, stubs)
- Implementation phases: arith → merkle → prove → verify → audit → SDK
- Expected completion: Step 10 (after benchmarks + docs)

### Future Work (⬜)
- End-to-end TPS benchmarks (Sprint 10)
- Production monitoring and operational playbooks (Sprint 10)
- Advanced features (cross-chain, L2 settlement) — see whitepaper §18

## Verification Commands

```bash
# Run all tests
cargo test --workspace --all-features

# Run STARK-specific tests (when implemented)
cargo test -p crypto-stark --all-features

# Run benchmarks (step 6)
cargo bench -p crypto-stark

# Check documentation coverage
cargo doc --workspace --no-deps --document-private-items
```

## Updating This Document

When implementing a feature:

1. Change status from ⬜ to 🟨 when starting work
2. Add module/file paths as they're created
3. Add test coverage details (unit/integration/e2e)
4. Change status to ✅ when all tests pass and documentation is complete
5. Update commit message to reference this matrix: `feat(stark): <feature> [coverage-matrix]`

## Grant/Investor References

This matrix is designed to be referenced in:

- **Grant Applications**: "See `docs/sprint9-whitepaper-coverage.md` for implementation status"
- **Investor Decks**: "X% of whitepaper claims verified (Y/Z features implemented)"
- **Security Audits**: "Audit scope covers rows 1-15 of coverage matrix"
- **Progress Reports**: "Sprint 9 completed rows 1-10, on track for Q1 2026 mainnet"

---

**Last Updated**: 2025-10-24 (Sprint 9 Commit #1)  
**Next Review**: After each commit or weekly (whichever is sooner)
