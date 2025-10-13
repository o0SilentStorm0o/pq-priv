# PQ-PRIV Project Status Report
**Date:** October 14, 2025  
**Version:** 0.1.0  
**Branch:** fix/axum-07-router-state  
**Report Type:** Technical & Managerial Analysis

---

## Executive Summary

PQ-PRIV je výzkumný post-kvantový privacy blockchain v raném stadiu MVP vývoje. Projekt má solidní technický základ s funkčním full-node implementací, persistence vrstvou, P2P sítí a kompletním CI/CD pipeline. **Aktuální stav: 35-40% MVP dokončeno** s kritickými kryptografickými komponentami (Dilithium, STARK proofs) stále v placeholder fázi.

### Klíčové metriky
- **Codebase:** 37 Rust souborů, ~248 KB kódu
- **Test Coverage:** 48 testů (100% passing), 19 unit + 5 integration + 24 crate-level
- **Build Time:** ~8-10s (dev), ~42s (release)
- **CI Status:** ✅ Plně funkční (GitHub Actions)
- **Docker:** ✅ Multi-node testnet ready
- **Documentation:** 13 markdown souborů (profesionální standard)

---

## 1. TECHNICKÁ ANALÝZA

### 1.1 Architektura & Struktura

#### Workspace Crates (11 celkem)

| Crate | LoC Estimate | Purpose | Status | Priority |
|-------|--------------|---------|--------|----------|
| **`codec`** | ~500 | Binary serialization (CBOR-style, varint) | ✅ Complete | Low |
| **`consensus`** | ~800 | Block rules, PoW validation, merkle trees | ✅ Complete | Medium |
| **`crypto`** | ~1,200 | **PLACEHOLDER** Ed25519 místo Dilithium | ⚠️ Critical Gap | **CRITICAL** |
| **`node`** | ~2,500 | Full node: RPC, sync, mempool, chain state | ✅ Sprint 3 Done | Medium |
| **`p2p`** | ~1,500 | Peer management, handshake, inventory | ✅ Complete | Low |
| **`pow`** | ~300 | PoW target calculation, hash validation | ✅ Complete | Low |
| **`rocksdb_stub`** | ~200 | Dev-only in-memory RocksDB replacement | ⚠️ Dev Only | Medium |
| **`spec`** | ~100 | Shared constants, chain parameters | ✅ Complete | Low |
| **`storage`** | ~1,000 | RocksDB persistence, checkpoints | ✅ Sprint 3 Done | Low |
| **`tx`** | ~800 | Transaction model, builder, sighash | ✅ Complete | Medium |
| **`utxo`** | ~700 | In-memory UTXO store, double-spend detection | ✅ Complete | Low |
| **`wallet`** | ~400 | CLI wallet prototype (minimal) | ⚠️ Stub Only | High |

**Total Estimated LoC:** ~10,000 lines (bez testů a dependencies)

#### Dependency Graph
```
node (main binary)
├── consensus
│   ├── pow
│   ├── tx
│   │   └── crypto ⚠️
│   └── utxo
│       ├── crypto ⚠️
│       └── tx
├── p2p
│   └── codec
├── storage
│   └── rocksdb (patched to rocksdb_stub) ⚠️
├── mempool (internal module)
└── rpc (internal module)
    └── axum 0.7.9 ✅

wallet (CLI binary)
└── crypto ⚠️
└── tx
```

### 1.2 Implementované Funkce (Sprint 0-3)

#### ✅ **Sprint 0: Foundation** (100% Complete)
- [x] Reproducible builds (Rust 1.90.0, edition 2024)
- [x] CI/CD pipeline (GitHub Actions, 3 platforms)
- [x] Docker multi-stage build + compose
- [x] Testnet scripts (PowerShell + Bash)
- [x] Repository templates (.github/ISSUE_TEMPLATE, etc.)
- [x] Security tooling (cargo-deny, cargo-audit)

#### ✅ **Sprint 1: P2P & RPC** (100% Complete)
- [x] P2P networking (TCP, handshake protocol)
- [x] Peer manager (connection pool, ban scores)
- [x] Message codec (inventory, headers, blocks, txs)
- [x] TxPool mempool (fee policy, orphan handling, LRU eviction)
- [x] JSON-RPC HTTP server (Axum 0.7)
- [x] Basic endpoints: `/health`, `/chain/tip`, `/metrics`
- [x] DevNet mining endpoint: `/dev/mine` (feature-gated)

#### ✅ **Sprint 3: Persistence & Sync** (95% Complete)
- [x] RocksDB schema (5 column families: HEADERS, BLOCKS, UTXO, LINKTAG, META)
- [x] Atomic batch commits with WAL
- [x] Checkpoint/snapshot system (interval + retention)
- [x] Fork-choice reorg handling (cumulative work, UTXO unwind/rewind)
- [x] Header→Block sync pipeline (SyncManager, orphan pool)
- [x] Peer event loop + chain event loop
- [x] Mempool hygiene (confirmed tx removal, reorg reinsertion)
- [x] Prometheus metrics (/metrics endpoint)
- [~] Integration tests (5 tests: sync, reorg, persistence, metrics, handshake)

**Missing from Sprint 3:**
- [ ] Multi-node P2P sync tests (nodes run isolated, need network topology tests)
- [ ] Ban score enforcement tests
- [ ] Snapshot restore verification

### 1.3 Kritické Gaps & Placeholder Code

#### 🚨 **CRITICAL: Cryptography Module**
**File:** `crates/crypto/src/lib.rs` (line 1-10)

```rust
//! The current signing routine relies on Ed25519 as a stand-in 
//! until Dilithium/SPHINCS+ bindings are wired in
```

**Status:** 
- ✅ API design complete (AlgTag enum, Signature wrapper)
- ❌ **Ed25519 je pouze placeholder** pro Dilithium
- ❌ SPHINCS+ fallback není implementován
- ❌ STARK proofs pro privacy zcela chybí

**Impact:** 
- Blockchain není post-quantum secure
- Privacy features nefunkční (stealth addresses fungují, ale bez ZK proofs)
- **Blocker pro production deployment**

**Effort Estimate:** 
- Dilithium integration: 2-3 týdny (pokud existuje Rust binding)
- STARK proofs: 3-6 měsíců (vyžaduje výzkum + implementaci)

#### ⚠️ **HIGH: Range Proofs Missing**
**File:** `crates/tx/src/lib.rs` (Witness struct)

```rust
pub struct Witness {
    pub range_proofs: Vec<u8>,  // Always empty Vec::new()
    pub stamp: u64,
    pub extra: Vec<u8>,
}
```

**Status:** Range proofs jsou placeholder - transakce nemají amount validation.

**Impact:**
- Inflation risk (lze vytvořit coiny z ničeho)
- Confidential amounts nefunkční
- **Blocker pro mainnet**

**Effort Estimate:** 4-8 týdnů (Bulletproofs implementace)

#### ⚠️ **MEDIUM: RocksDB Stub**
**File:** `Cargo.toml` (line 24-26)

```toml
[patch.crates-io]
rocksdb = { path = "crates/rocksdb_stub" }
```

**Status:** Dev-only in-memory stub pro rychlejší kompilaci.

**Impact:** 
- Production build vyžaduje odstranění patche
- Performance neověřena s reálným RocksDB
- Snapshot/checkpoint code netestován s reálnou DB

**Action Required:** 
1. Odstranit patch před production build
2. Benchmark RocksDB performance
3. Otestovat snapshot restore s multi-GB databází

#### ⚠️ **MEDIUM: Wallet Stub**
**File:** `crates/wallet/src/main.rs`

**Status:** CLI má pouze základní příkazy:
- ✅ `keygen` - funguje
- ⚠️ `send` - vytvoří placeholder tx, ale nepodepisuje
- ⚠️ `audit` - vygeneruje view token, ale není validace

**Missing:**
- [ ] Transaction signing a broadcasting
- [ ] UTXO scanning a balance calculation
- [ ] Key derivation (BIP32/44 style)
- [ ] RPC client pro komunikaci s node

**Effort Estimate:** 3-4 týdny pro základní funkční wallet

### 1.4 Test Coverage Analysis

#### Test Suite Breakdown (48 testů total)

| Crate | Unit Tests | Integration Tests | Coverage Focus |
|-------|------------|-------------------|----------------|
| codec | 1 | 0 | Serialization round-trips |
| consensus | 5 | 0 | PoW validation, merkle roots, LWMA difficulty |
| crypto | 4 | 0 | Signature round-trips, verification (Ed25519) |
| node | 19 | 5 | Mempool, chain state, sync, reorg, metrics |
| p2p | 2 | 0 | Message codec round-trips |
| pow | 1 | 0 | PoW hash calculation |
| spec | 1 | 0 | Sanity check |
| storage | 3 | 0 | Block batch commits, rewind, UTXO counts |
| tx | 2 | 0 | TxID calculation, link tags |
| utxo | 5 | 0 | UTXO store operations, double-spend detection |
| wallet | 0 | 0 | ❌ No tests |

#### Integration Tests (crates/node/tests/integration.rs)
1. ✅ `syncs_headers_and_blocks_between_nodes` - P2P sync
2. ✅ `reorgs_to_the_longest_chain_across_peers` - Fork choice
3. ✅ `persists_chain_across_restart_with_storage_crate` - Persistence
4. ✅ `exposes_metrics_over_http` - Prometheus metrics
5. ✅ `rejects_peers_with_invalid_handshake` - P2P security

**Missing Integration Tests:**
- [ ] Multi-node network topology (3+ nodes)
- [ ] Transaction propagation across network
- [ ] Mempool sync between peers
- [ ] Large blockchain sync (1000+ blocks)
- [ ] Concurrent mining + reorg scenarios
- [ ] RPC endpoint full coverage

#### Test Execution Time
- **Unit tests:** 0.37s total
- **Integration tests:** 2.04s
- **Full suite:** ~10s (včetně compilation)

**Assessment:** Test coverage je dobrá pro core komponenty, ale chybí E2E testy a wallet coverage.

### 1.5 Performance Characteristics

#### Build Times (Windows, Ryzen/Intel i7 class)
- **Dev build (debug):** 8-10s incremental, 45s clean
- **Release build:** 42-50s
- **Docker build:** 42s (multi-stage)

#### Runtime Performance (testnet)
- **Node startup:** < 1s (in-memory DB)
- **Block validation:** < 50ms per block
- **Mining (dev):** Instant (0x207fffff difficulty)
- **RPC latency:** < 10ms (localhost)
- **Memory usage:** ~50 MB baseline

**Note:** Performance netestována s production RocksDB a velkými databázemi.

### 1.6 Security Posture

#### ✅ Implemented Security Features
1. **Dependency Audit:** cargo-deny + cargo-audit v CI
2. **License Compliance:** cargo-about report generation
3. **Linting:** Clippy deny warnings mode
4. **Format Enforcement:** rustfmt check v CI
5. **Type Safety:** Rust edition 2024, strict mode
6. **P2P Security:** 
   - Handshake protocol s version negotiation
   - Ban scores pro misbehaving peers
   - Rate limiting na message processing

#### ❌ Missing Security Features
1. **Post-Quantum Signatures:** Ed25519 placeholder ⚠️
2. **ZK Proofs:** Range proofs, ring signatures placeholder
3. **TLS/Encryption:** P2P komunikace plain TCP
4. **Authentication:** RPC endpoints bez auth
5. **DoS Protection:** Minimální rate limiting
6. **Audit Trail:** Žádný formal security audit

**Risk Level:** **HIGH** - Production deployment by vyžadoval kompletní security audit a krypto implementaci.

---

## 2. MANAŽERSKÁ ANALÝZA

### 2.1 Project Maturity: MVP Stage (~40% Complete)

#### Maturity Matrix

| Component | Design | Implementation | Testing | Documentation | Production Ready |
|-----------|--------|----------------|---------|---------------|------------------|
| **Infrastructure** | ✅ 100% | ✅ 100% | ✅ 95% | ✅ 90% | ✅ Yes |
| **Consensus Layer** | ✅ 100% | ✅ 95% | ✅ 90% | ✅ 85% | ⚠️ Needs audit |
| **P2P Network** | ✅ 100% | ✅ 95% | ✅ 80% | ✅ 80% | ⚠️ Needs encryption |
| **Storage** | ✅ 100% | ✅ 95% | ✅ 75% | ✅ 90% | ⚠️ RocksDB stub |
| **Cryptography** | ✅ 90% | ❌ 20% | ⚠️ 50% | ✅ 80% | ❌ **BLOCKER** |
| **Privacy Features** | ⚠️ 60% | ❌ 15% | ❌ 10% | ⚠️ 40% | ❌ **BLOCKER** |
| **Wallet** | ⚠️ 50% | ❌ 25% | ❌ 0% | ⚠️ 30% | ❌ No |
| **RPC/API** | ✅ 80% | ✅ 70% | ✅ 60% | ⚠️ 50% | ⚠️ Needs auth |

**Overall MVP Completion: 38-42%**

### 2.2 Sprint Status & Roadmap

#### Completed Sprints
- ✅ **Sprint 0:** Foundation & Tooling (Q4 2024)
- ✅ **Sprint 1:** P2P & Basic RPC (Q1 2025)  
- ✅ **Sprint 3:** Persistence & Sync (Q2-Q3 2025)

#### Missing Sprint 2
**Sprint 2 byl přeskočen nebo sloučen se Sprint 3.** Dokumentace nespecifikuje původní Sprint 2 scope.

**Inference:** Sprint 2 pravděpodobně zahrnoval:
- Transaction validation logic (částečně v Sprint 3)
- Mempool rozšíření (dokončeno v Sprint 1+3)
- Initial wallet work (nedokončeno)

### 2.3 Critical Path Analysis

#### Blockers pro Production (Red)
1. 🔴 **Dilithium/SPHINCS+ Implementation** (3-6 měsíců)
   - External dependency: Rust binding for liboqs or pqcrypto
   - Alternative: použít existující crate jako `pqcrypto-dilithium`
   
2. 🔴 **STARK Proofs for Privacy** (6-12 měsíců)
   - Vyžaduje: Circuit design, prover implementation
   - Možná spolupráce: StarkWare, Risc0, nebo vlastní implementace
   
3. 🔴 **Range Proofs (Bulletproofs)** (2-3 měsíce)
   - Existing crate: `bulletproofs` by Dalek Cryptography
   - Integration effort: střední

4. 🔴 **Security Audit** (1-2 měsíce + $50k-150k)
   - Scope: Cryptography, consensus, P2P, storage
   - Timeline: Po dokončení krypto implementace

#### High Priority (Orange)
5. 🟠 **Full Wallet Implementation** (1-2 měsíce)
6. 🟠 **RocksDB Production Testing** (2-3 týdny)
7. 🟠 **P2P Encryption (TLS)** (2-3 týdny)
8. 🟠 **RPC Authentication** (1-2 týdny)
9. 🟠 **E2E Integration Tests** (2-3 týdny)

#### Medium Priority (Yellow)
10. 🟡 **JSON-RPC 2.0 API** (Bitcoin-compatible methods)
11. 🟡 **Light Client Support** (headers-only sync)
12. 🟡 **Governance Mechanism** (pokud v roadmapu)
13. 🟡 **Exchange Integration SDK**

### 2.4 Resource Requirements

#### Estimated Team Composition pro Next Phase
- **1x Senior Cryptography Engineer** (Dilithium, STARK proofs) - 6-12 měsíců
- **1x Blockchain Core Developer** (Range proofs, wallet) - 3-6 měsíců  
- **1x DevOps/Testing Engineer** (Production RocksDB, E2E tests) - 2-3 měsíce
- **1x Security Auditor** (External contractor) - 1-2 měsíce

**Total FTE:** ~2.5 full-time equivalent na 6-12 měsíců

#### Budget Estimate (Rough)
- **Engineering:** $200k-400k (6-12 měsíců, 2-3 engineers)
- **Security Audit:** $50k-150k (external)
- **Infrastructure:** $5k-10k (testnet hosting, CI credits)
- **Total:** **$255k-560k** pro dokončení MVP

### 2.5 Risk Assessment

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| Dilithium standardization change | Medium | High | Use abstraction layer, monitor NIST |
| STARK prover performance issues | High | High | Benchmark early, consider hybrid approach |
| RocksDB performance bottleneck | Medium | Medium | Profiling, consider alternatives (sled, redb) |
| Key developer departure | Medium | High | Documentation, code review, knowledge sharing |
| Security vulnerability discovered | Medium | Critical | Continuous auditing, bug bounty program |
| Regulatory uncertainty (privacy coins) | High | High | Legal counsel, compliance features |

### 2.6 Competitive Analysis

#### Positioning
- **Target:** Research-focused post-quantum privacy L1
- **Competitors:** Monero (not PQ), Zcash (not PQ), Mina (ZK but not privacy)
- **Differentiation:** PQ + Privacy + UTXO model

#### Market Readiness
- ⚠️ **Too early for mainnet** (krypto placeholders)
- ✅ **Good for academic research** (solid architecture)
- ✅ **Suitable for testnet grants** (working devnet)

---

## 3. KVALITA CODEBASE

### 3.1 Code Quality Metrics

#### Static Analysis (Clippy)
- **Warnings:** 0 ✅
- **Errors:** 0 ✅
- **Deny warnings:** Enforced in CI ✅

#### Code Style
- **Format:** rustfmt enforced ✅
- **Naming:** Consistent (snake_case for functions, PascalCase for types) ✅
- **Comments:** Moderate (module-level docs good, function docs patchy)

#### Technical Debt
- **TODO/FIXME:** 0 found ✅
- **HACK/XXX:** 0 found ✅
- **Placeholder Code:** ~5 major areas (crypto, wallet, range proofs)

#### Dependencies
- **Total dependencies:** ~60 crates (moderate)
- **Vulnerable crates:** 0 (cargo-audit passing) ✅
- **License compliance:** All checked (cargo-about) ✅
- **Version pinning:** cargo.lock committed ✅

### 3.2 Documentation Quality

#### Code Documentation
- Module docs: ⚠️ 60% coverage
- Public API docs: ⚠️ 50% coverage
- Examples: ❌ Minimal

#### External Documentation
- ✅ README.md - Excellent (updated, clear structure)
- ✅ CHANGELOG.md - Good (Keep a Changelog format)
- ✅ CONTRIBUTING.md - Good (clear guidelines)
- ✅ SECURITY.md - Good (disclosure policy)
- ✅ CODE_OF_CONDUCT.md - Standard
- ✅ spec/ - Good (8 spec documents)

#### Missing Documentation
- [ ] Architecture Decision Records (ADRs)
- [ ] API reference docs (rustdoc publish)
- [ ] Deployment guide (production checklist)
- [ ] Performance tuning guide
- [ ] Troubleshooting guide

### 3.3 Maintainability Score: **7.5/10**

**Strengths:**
- ✅ Clean architecture (clear separation of concerns)
- ✅ Type-safe (Rust benefits)
- ✅ CI/CD automation
- ✅ Cross-platform support (Windows/Linux/macOS)
- ✅ Reproducible builds

**Weaknesses:**
- ⚠️ Crypto module tightly coupled to Ed25519
- ⚠️ Wallet je stub (vyžaduje refactor)
- ⚠️ RocksDB stub mask production issues
- ⚠️ Limited inline documentation

---

## 4. STRATEGICKÁ DOPORUČENÍ

### 4.1 Immediate Actions (Next 30 Days)

1. **Remove RocksDB Stub** (1 týden)
   - [ ] Odstranit patch z Cargo.toml
   - [ ] Benchmark s reálným RocksDB
   - [ ] Fix performance issues
   - [ ] Document production configuration

2. **Expand Test Suite** (2 týdny)
   - [ ] Multi-node network topology tests
   - [ ] Wallet unit tests
   - [ ] RPC endpoint full coverage
   - [ ] Snapshot restore verification

3. **Documentation Sprint** (1 týden)
   - [ ] Generate rustdoc a publish na docs.rs
   - [ ] Create deployment checklist
   - [ ] Write troubleshooting guide

### 4.2 Short-Term (Next 3 Months)

4. **Cryptography Phase 1** (6-8 týdnů)
   - [ ] Evaluate Dilithium Rust crates (pqcrypto-dilithium, liboqs-rust)
   - [ ] Implement Dilithium signature scheme
   - [ ] Migrate all Ed25519 code
   - [ ] Add comprehensive crypto tests

5. **Wallet MVP** (4-6 týdnů)
   - [ ] UTXO scanning a indexing
   - [ ] Transaction signing a broadcasting
   - [ ] Balance calculation
   - [ ] Basic key management

6. **Security Hardening** (3-4 týdny)
   - [ ] P2P TLS encryption
   - [ ] RPC authentication (JWT/API keys)
   - [ ] Rate limiting improvements
   - [ ] DoS protection

### 4.3 Medium-Term (3-6 Months)

7. **Privacy Layer** (12-16 týdnů)
   - [ ] Range proofs (Bulletproofs integration)
   - [ ] Ring signatures (one-of-many proofs)
   - [ ] Begin STARK research/prototyping
   - [ ] Privacy feature testing

8. **Production Readiness** (8-10 týdnů)
   - [ ] External security audit
   - [ ] Chaos engineering tests
   - [ ] Production monitoring setup (Grafana/Prometheus)
   - [ ] Incident response plan

9. **Ecosystem Development** (ongoing)
   - [ ] JSON-RPC 2.0 full spec
   - [ ] Exchange integration SDK
   - [ ] Block explorer
   - [ ] Light client implementation

### 4.4 Long-Term (6-12 Months)

10. **STARK Proof System** (24-40 týdnů)
    - [ ] Circuit design for confidential transactions
    - [ ] Prover implementation
    - [ ] Verifier integration
    - [ ] Performance optimization

11. **Mainnet Launch Preparation**
    - [ ] Testnet bug bounty program
    - [ ] Genesis block ceremony
    - [ ] Network bootstrapping strategy
    - [ ] Community building

---

## 5. ZÁVĚR

### 5.1 Overall Assessment

**PQ-PRIV je architektonicky solidní blockchain projekt v rané MVP fázi**, s těmito charakteristikami:

**Strengths:**
- ✅ Čistá, modulární architektura
- ✅ Funkční full-node s persistence a sync
- ✅ Profesionální CI/CD a tooling
- ✅ Cross-platform support
- ✅ Dobrá test coverage pro core komponenty

**Critical Gaps:**
- ❌ Post-quantum cryptography je placeholder (BLOCKER)
- ❌ Privacy features nejsou implementované (BLOCKER)
- ❌ Wallet je stub
- ⚠️ RocksDB stub mask production issues

**Readiness:**
- 🟢 **Academic Research:** Ready now
- 🟢 **Testnet Grants:** Ready now
- 🟡 **Public Testnet:** 3-6 měsíců (po krypto implementaci)
- 🔴 **Mainnet:** 9-18 měsíců (po security audit a STARK proofs)

### 5.2 Go/No-Go Recommendation

**RECOMMENDATION: GO** s podmínkami

**Podmínky pro pokračování:**
1. **Secure funding** pro 6-12 měsíců vývoje ($255k-560k)
2. **Hire senior cryptography engineer** (kritická role)
3. **Commit to security audit** po krypto implementaci
4. **Remove RocksDB stub** v příštím sprintu
5. **Define clear mainnet launch criteria**

**Alternative Strategy:**
Pokud financování není dostupné, zvažte **open-source community approach**:
- Publikovat roadmap a technical challenges
- Bounty program pro key features (Dilithium integration, range proofs)
- Academic partnerships (univerzity s PQ crypto research)
- Grant applications (Ethereum Foundation, Web3 Foundation, NSF)

### 5.3 Success Metrics pro Next Phase

**3-Month Goals:**
- [ ] Dilithium integration complete (tests passing)
- [ ] RocksDB production-ready
- [ ] Wallet MVP functional
- [ ] Zero critical vulnerabilities

**6-Month Goals:**
- [ ] Range proofs implemented
- [ ] Security audit passed
- [ ] Public testnet launched
- [ ] 100+ community nodes

**12-Month Goals:**
- [ ] STARK proofs working prototype
- [ ] Mainnet genesis block
- [ ] Exchange partnerships signed
- [ ] 1000+ active addresses

---

## APPENDIX

### A. Technology Stack

**Language:** Rust 1.90.0 (edition 2024)  
**Consensus:** Hybrid PoW (LWMA difficulty adjustment)  
**Cryptography (current):** Ed25519 (placeholder), Blake3, SHA3-256  
**Cryptography (planned):** Dilithium, SPHINCS+, Bulletproofs, STARKs  
**Storage:** RocksDB (currently stubbed)  
**Networking:** TCP (async tokio), custom binary protocol  
**RPC:** Axum 0.7.9 (HTTP/JSON)  
**Metrics:** Prometheus exposition format  
**Build System:** Cargo, Docker multi-stage  
**CI/CD:** GitHub Actions (3 platforms)  

### B. Key Files Reference

**Core Implementation:**
- `crates/node/src/main.rs` - Node entry point
- `crates/node/src/state.rs` - Chain state & reorg logic (1,200 LoC)
- `crates/node/src/rpc.rs` - RPC server (552 LoC)
- `crates/crypto/src/lib.rs` - ⚠️ Placeholder crypto (324 LoC)
- `crates/storage/src/store.rs` - RocksDB wrapper (460 LoC)

**Configuration:**
- `Cargo.toml` - Workspace config + RocksDB patch
- `rust-toolchain.toml` - Toolchain pinning
- `.github/workflows/ci.yml` - CI pipeline
- `docker/docker-compose.yml` - Multi-node testnet

**Documentation:**
- `README.md` - Project overview
- `spec/blueprint.md` - Architecture roadmap
- `spec/storage.md` - RocksDB schema
- `spec/fork-choice.md` - Reorg algorithm

### C. Contact & Resources

**Repository:** github.com/o0SilentStorm0o/pq-priv  
**Branch:** fix/axum-07-router-state  
**Primary Maintainer:** (undisclosed)  
**Security Contact:** security@pq-priv.org (placeholder)  
**License:** Apache-2.0 OR MIT  

---

**Report Generated:** October 14, 2025  
**Next Review:** January 15, 2026 (after Dilithium integration)
