# PQ-PRIV

**PQ-PRIV (Post-Quantum Privacy Layer-1)** is a research blockchain designed from day one to combine:

- 🧩 **Post-quantum cryptography** (CRYSTALS-Dilithium + STARK proofs)  
- 🕵️ **Strong privacy by default** (stealth addresses, confidential amounts)  
- ⚖️ **Compliance-ready UX** (selective disclosure, exchange subaddresses)  
- 🧠 **Built in Rust**, hybrid PoW/PoS consensus, and future-proof crypto-agility.

---

## Project Structure

| Path | Description |
|------|--------------|
| `crates/node`   | Full node daemon (p2p, mempool, consensus) |
| `crates/crypto` | PQ signatures, hashing, domain separation |
| `crates/spec`   | Protocol constants, types, network params |
| `crates/codec`  | Binary serialization (wire format) |
| `crates/pow`    | Proof-of-Work target & retarget logic |
| `crates/wallet` | CLI wallet, key management, stealth outputs |
| `spec/`         | RFC-style protocol specs |

---

## Development

```bash
cargo build --workspace
cargo test  --workspace
