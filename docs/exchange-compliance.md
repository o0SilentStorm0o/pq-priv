# Exchange Compliance Guide

**Status**: Sprint 9 Infrastructure Complete (Audit Packet Framework)

This document describes the three-tier selective disclosure system for cryptocurrency exchange compliance, enabling privacy-preserving regulatory adherence.

## Table of Contents

1. [Overview](#overview)
2. [Audit Levels](#audit-levels)
3. [Integration Guide](#integration-guide)
4. [Security Model](#security-model)
5. [Regulatory Considerations](#regulatory-considerations)

---

## Overview

The PQ-PRIV exchange compliance system provides **selective disclosure** mechanisms that allow users to prove compliance without revealing full transaction details publicly. This balances privacy rights with regulatory obligations.

### Key Features

- **Three-tier disclosure**: L1 (Existence), L2 (Amount), L3 (Full Identity)
- **Post-quantum encryption**: Kyber512 + X25519 hybrid encryption
- **Post-quantum signatures**: Dilithium2 digital signatures
- **Exchange-controlled decryption**: Only exchange can decrypt audit packets
- **Blockchain anchoring**: Audit packets reference on-chain nullifiers

### Compliance Workflow

```
┌─────────────────────────────────────────────────────────────┐
│              Exchange Deposit Compliance Flow                │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  User Wallet          Blockchain           Exchange          │
│      │                    │                    │              │
│      │  1. TX v2 + STARK  │                    │              │
│      ├───────────────────>│                    │              │
│      │    (anonymous)     │                    │              │
│      │                    │                    │              │
│      │  2. Audit Packet   │                    │              │
│      │    (L2/L3 level)   │                    │              │
│      ├────────────────────────────────────────>│              │
│      │                    │                    │              │
│      │                    │  3. Verify TX      │              │
│      │                    │<───────────────────┤              │
│      │                    │  (check nullifier) │              │
│      │                    │                    │              │
│      │                    │  4. Decrypt Audit  │              │
│      │                    │    (amount/identity)              │
│      │                    │                    │              │
│      │  5. Confirm Deposit│                    │              │
│      │<────────────────────────────────────────┤              │
│      │                    │                    │              │
└─────────────────────────────────────────────────────────────┘
```

---

## Audit Levels

### **Level 1: Existence Proof** (L1)

**Purpose**: Prove a transaction exists on-chain without revealing amount or identity.

**Use Cases**:
- Payment proof for disputes
- Timestamping for legal records
- Minimal-disclosure compliance

**Disclosed Data**:
```rust
pub struct L1Data {
    /// Spend tag (links to on-chain TX)
    pub spend_tag: [u8; 32],
    
    /// Nullifier (proves TX uniqueness)
    pub nullifier: [u8; 32],
    
    /// STARK proof bytes (proves ownership)
    pub stark_proof: Vec<u8>,
}
```

**Privacy Level**: **High**
- Amount: Hidden
- Sender: Hidden
- Receiver: Hidden
- Transaction graph: Hidden

**Regulatory Compliance**:
- ✅ Proof of transaction existence
- ✅ Proof of ownership (STARK proof)
- ❌ Amount disclosure (required for AML)
- ❌ Identity disclosure (required for KYC)

---

### **Level 2: Amount Disclosure** (L2)

**Purpose**: Prove transaction amount for AML/CTF compliance while preserving identity privacy.

**Use Cases**:
- Exchange deposits (KYC on file, need amount for AML)
- Tax reporting (amount disclosure required)
- Large transaction monitoring (>$10k threshold)

**Disclosed Data**:
```rust
pub struct L2Data {
    /// L1 data (existence proof)
    pub l1: L1Data,
    
    /// Transaction amount (disclosed)
    pub amount: u64,
    
    /// Range proof opening (proves amount matches commitment)
    pub range_proof_opening: RangeProofOpening,
}
```

**Privacy Level**: **Medium**
- Amount: **Disclosed**
- Sender: Hidden
- Receiver: Hidden (exchange knows via deposit address)
- Transaction graph: Partially hidden

**Regulatory Compliance**:
- ✅ Amount disclosure for AML/CTF
- ✅ Large transaction reporting (FinCEN Form 104)
- ✅ Tax basis calculation
- ❌ Full sender identity (exchange may have KYC separately)

**Verification Steps**:
1. Exchange verifies `nullifier` exists on-chain
2. Exchange verifies `amount` matches Pedersen commitment using `range_proof_opening`
3. Exchange checks amount against AML thresholds ($10k USD)
4. Exchange applies risk scoring based on amount + user history

---

### **Level 3: Full Identity Disclosure** (L3)

**Purpose**: Full regulatory compliance with complete sender identity disclosure.

**Use Cases**:
- High-risk jurisdictions (FATF grey/blacklist countries)
- Suspicious activity reports (SARs)
- Law enforcement requests (with legal process)
- Enhanced due diligence (EDD) requirements

**Disclosed Data**:
```rust
pub struct L3Data {
    /// L2 data (amount + existence)
    pub l2: L2Data,
    
    /// Sender spend public key (identity)
    pub sender_spend_pubkey: [u8; 32],
    
    /// Sender view public key (transaction scanning)
    pub sender_view_pubkey: [u8; 32],
    
    /// KYC hash (links to off-chain identity database)
    pub kyc_hash: [u8; 32],
}
```

**Privacy Level**: **Low (Full Disclosure)**
- Amount: **Disclosed**
- Sender: **Disclosed** (via public keys + KYC hash)
- Receiver: **Disclosed** (exchange deposit address)
- Transaction graph: **Fully visible** (exchange can scan all TXs with sender's view key)

**Regulatory Compliance**:
- ✅ Full KYC/AML compliance
- ✅ Travel Rule compliance (sender/receiver identity)
- ✅ OFAC sanctions screening (via kyc_hash lookup)
- ✅ Enhanced due diligence (EDD)
- ✅ Suspicious activity reporting (SAR)

**KYC Hash Construction**:
```rust
kyc_hash = BLAKE3(
    user_email ||
    user_full_name ||
    user_date_of_birth ||
    user_address ||
    user_document_number ||
    exchange_customer_id
)
```

**Security Properties**:
- KYC hash is **one-way** (cannot reverse to PII)
- Exchange maintains **off-chain database** mapping kyc_hash → full KYC data
- Blockchain only stores kyc_hash (privacy-preserving)

---

## Integration Guide

### **Step 1: Exchange Setup**

#### Generate Encryption Key Pair (Kyber512 + X25519)

```rust
use pqcrypto_kyber::kyber512;
use x25519_dalek::{PublicKey, StaticSecret};

// Kyber512 (post-quantum KEM)
let (kyber_pk, kyber_sk) = kyber512::keypair();

// X25519 (classical ECDH, fallback)
let x25519_sk = StaticSecret::random();
let x25519_pk = PublicKey::from(&x25519_sk);

// Publish public keys on exchange website
exchange.publish_audit_pubkey(kyber_pk, x25519_pk);
```

**Key Rotation**: Rotate keys every 12 months or upon compromise.

#### Generate Signature Key Pair (Dilithium2)

```rust
use pqcrypto_dilithium::dilithium2;

let (dilithium_pk, dilithium_sk) = dilithium2::keypair();

// User will verify audit packets with this public key
exchange.publish_audit_signature_pubkey(dilithium_pk);
```

---

### **Step 2: User Creates Audit Packet**

#### L2 Audit Packet (Amount Disclosure)

```rust
use wallet::{AuditPacketBuilder, AuditLevel};

// User fetches exchange public keys
let exchange_pubkey = exchange.get_audit_pubkey()?;

// Create L2 audit packet
let packet = AuditPacketBuilder::new(
    AuditLevel::L2Amount,
    tx.txid.clone(),
    tx.spend_tags[0],
    tx.nullifiers[0],
    tx.stark_proofs[0].proof_bytes.clone(),
)
.with_amount(50_000_000) // 0.5 BTC in satoshis
.with_exchange_pubkey(exchange_pubkey)
.build()?;

// Submit to exchange via API
exchange.submit_audit_packet(user_id, packet)?;
```

#### L3 Audit Packet (Full Disclosure)

```rust
// L3 requires sender identity keys
let packet = AuditPacketBuilder::new(
    AuditLevel::L3Full,
    tx.txid.clone(),
    tx.spend_tags[0],
    tx.nullifiers[0],
    tx.stark_proofs[0].proof_bytes.clone(),
)
.with_amount(50_000_000)
.with_sender_keys(
    wallet.get_spend_pubkey(),
    wallet.get_view_pubkey(),
)
.with_exchange_pubkey(exchange_pubkey)
.build()?;

// KYC hash is computed from user's verified identity
let kyc_hash = compute_kyc_hash(user_email, user_full_name, ...);
packet.metadata.exchange_key_id = Some(kyc_hash);

exchange.submit_audit_packet(user_id, packet)?;
```

---

### **Step 3: Exchange Processes Audit Packet**

#### Decrypt Audit Packet

```rust
use pqcrypto_kyber::kyber512;
use chacha20poly1305::{ChaCha20Poly1305, Nonce};

// 1. Decrypt with Kyber512 (post-quantum)
let kyber_ss = kyber512::decapsulate(&packet.kyber_ciphertext, &exchange_kyber_sk);

// 2. Derive ChaCha20-Poly1305 key from shared secret
let cipher_key = BLAKE3::derive_key("AUDIT_ENCRYPTION", &kyber_ss);

// 3. Decrypt payload
let cipher = ChaCha20Poly1305::new(&cipher_key);
let nonce = Nonce::from_slice(&packet.nonce);
let plaintext = cipher.decrypt(nonce, &packet.encrypted_payload)?;

// 4. Deserialize audit data
let audit_data: L2Data = serde_json::from_slice(&plaintext)?;
```

#### Verify Audit Packet

```rust
// 1. Check TX exists on blockchain
let tx = blockchain.get_transaction_by_nullifier(&audit_data.l1.nullifier)?;
if tx.is_none() {
    return Err("Transaction not found on-chain");
}

// 2. Verify STARK proof (proves ownership)
verify_stark_proof(&audit_data.l1.stark_proof)?;

// 3. Verify amount matches Pedersen commitment
let commitment = tx.inputs[0]; // Commitment from on-chain TX
verify_commitment_opening(
    commitment,
    audit_data.amount,
    &audit_data.range_proof_opening,
)?;

// 4. Check spend tag matches
if tx.spend_tags[0] != audit_data.l1.spend_tag {
    return Err("Spend tag mismatch");
}

// 5. Apply AML checks
if audit_data.amount >= 10_000_00 { // $10k threshold
    exchange.file_ctr_report(user_id, audit_data.amount)?;
}

// 6. Credit user account
exchange.credit_account(user_id, audit_data.amount)?;
```

---

### **Step 4: Exchange API Endpoints**

#### GET /api/v1/audit/pubkey

**Response**:
```json
{
  "kyber512_pubkey": "base64_encoded_pubkey",
  "x25519_pubkey": "base64_encoded_pubkey",
  "dilithium2_pubkey": "base64_encoded_pubkey",
  "key_id": "2024-10-25-001",
  "expires_at": "2025-10-25T00:00:00Z"
}
```

#### POST /api/v1/audit/submit

**Request**:
```json
{
  "user_id": "usr_12345",
  "audit_packet": {
    "metadata": {
      "level": "L2Amount",
      "txid": "abc123...",
      "timestamp": 1698192000,
      "wallet_version": "1.0.0",
      "exchange_key_id": "2024-10-25-001"
    },
    "encrypted_payload": "base64_encoded_ciphertext",
    "signature": "base64_encoded_dilithium2_signature"
  }
}
```

**Response**:
```json
{
  "status": "accepted",
  "audit_id": "aud_67890",
  "estimated_processing_time": "5-10 minutes",
  "compliance_checks": [
    "AML threshold check",
    "OFAC sanctions screening",
    "Transaction graph analysis"
  ]
}
```

#### GET /api/v1/audit/status/:audit_id

**Response**:
```json
{
  "audit_id": "aud_67890",
  "status": "approved",
  "amount_credited": 50000000,
  "processed_at": "2024-10-25T12:34:56Z",
  "compliance_notes": "Amount within normal range, no flags"
}
```

---

## Security Model

### **Threat Model**

#### Protected Against:
- ✅ **Passive blockchain observers**: Cannot link transactions (anonymity set)
- ✅ **Man-in-the-middle attacks**: Kyber512 + X25519 hybrid encryption
- ✅ **Quantum adversaries**: Post-quantum cryptography (Kyber, Dilithium)
- ✅ **Exchange data breaches**: Encrypted audit packets (forward secrecy)
- ✅ **Replay attacks**: Unique nonces + timestamp verification

#### **NOT** Protected Against:
- ❌ **Exchange collusion**: Exchange can correlate deposits with KYC data
- ❌ **Regulatory subpoenas**: Exchange must comply with legal orders
- ❌ **Compromised wallet**: Malware can steal sk_spend and sk_view
- ❌ **Spend tag linkage**: Holder of sk_view can scan all user transactions

### **Privacy Guarantees**

| Adversary             | L1 Privacy | L2 Privacy | L3 Privacy |
|-----------------------|------------|------------|------------|
| Blockchain Observer   | ✅ High    | ✅ High    | ✅ High    |
| Exchange (honest)     | ✅ High    | ⚠️ Medium  | ❌ Low     |
| Exchange (malicious)  | ⚠️ Medium  | ❌ Low     | ❌ None    |
| Law Enforcement       | ✅ High    | ⚠️ Medium  | ❌ None    |
| Quantum Adversary     | ✅ High    | ✅ High    | ✅ High    |

**Key Insight**: Privacy is **conditional on exchange honesty** for L2/L3. Users must trust exchange to:
- Not leak audit packet contents
- Not correlate deposits with blockchain activity
- Comply with data retention policies

### **Encryption Security**

**Kyber512 Parameters**:
- Security level: NIST Level 1 (~AES-128)
- Public key: 800 bytes
- Ciphertext: 768 bytes
- Shared secret: 32 bytes
- Quantum security: ✅ Yes (lattice-based)

**Dilithium2 Parameters**:
- Security level: NIST Level 2 (~AES-128)
- Public key: 1312 bytes
- Signature: 2420 bytes
- Quantum security: ✅ Yes (lattice-based)

**Hybrid Encryption Rationale**:
- Kyber512: Post-quantum security (primary)
- X25519: Classical ECDH (fallback, faster)
- Both must be broken to decrypt audit packet

---

## Regulatory Considerations

### **Travel Rule Compliance (FATF Recommendation 16)**

**Requirement**: Transfer originator and beneficiary information for transactions ≥ $1,000 USD.

**PQ-PRIV Solution**:
- L3 audit packets include sender identity (spend_pubkey + kyc_hash)
- Exchange can retrieve full KYC data from off-chain database
- Beneficiary info already known (exchange deposit address)

**Compliance Status**: ✅ Full compliance with L3 audit packets

---

### **AML/CTF Regulations (Bank Secrecy Act, USA PATRIOT Act)**

**Requirement**: Currency Transaction Reports (CTRs) for transactions > $10,000 USD.

**PQ-PRIV Solution**:
- L2/L3 audit packets include amount disclosure
- Exchange can automatically file CTR when `amount >= $10,000`
- Suspicious Activity Reports (SARs) can reference nullifiers

**Compliance Status**: ✅ Full compliance with L2/L3 audit packets

---

### **GDPR (EU General Data Protection Regulation)**

**Challenge**: "Right to erasure" (Article 17) conflicts with immutable blockchain.

**PQ-PRIV Solution**:
- **On-chain**: Only cryptographic hashes (nullifiers, spend tags, kyc_hash)
- **Off-chain**: Full KYC data stored by exchange (can be deleted)
- **Audit packets**: Encrypted, exchange controls decryption keys

**Compliance Status**: ⚠️ Partial compliance
- ✅ Minimal on-chain PII (only hashes)
- ✅ Off-chain data can be deleted
- ❌ Nullifiers cannot be removed from blockchain (permanent record)

**Mitigation**: KYC hash is one-way, cannot reverse to PII.

---

### **5th Anti-Money Laundering Directive (5AMLD, EU)**

**Requirement**: Virtual Asset Service Providers (VASPs) must register and conduct KYC.

**PQ-PRIV Solution**:
- Exchanges require L2/L3 audit packets for deposits
- L3 packets link to off-chain KYC database (exchange responsibility)
- Spend tags enable transaction monitoring

**Compliance Status**: ✅ Full compliance with L3 audit packets

---

### **Jurisdictional Risk Matrix**

| Jurisdiction | Privacy Tolerance | Recommended Audit Level | Notes                          |
|--------------|-------------------|-------------------------|--------------------------------|
| Switzerland  | High              | L1 / L2                 | Strong financial privacy laws  |
| Singapore    | Medium            | L2                      | Crypto-friendly, AML enforced  |
| USA          | Low               | L2 / L3                 | FinCEN, IRS reporting required |
| EU           | Medium            | L2 / L3                 | 5AMLD, GDPR considerations     |
| China        | None              | ❌ Prohibited           | Crypto banned                  |
| Russia       | Low               | L3                      | Strict capital controls        |
| Japan        | Medium            | L2                      | FSA regulated, KYC required    |

**Recommendation**: Exchanges should enforce minimum audit levels based on:
1. User jurisdiction (determined during KYC)
2. Transaction amount (higher amounts → higher audit level)
3. Risk score (behavioral analysis, source of funds)

---

## Next Steps

1. **Step 6 Implementation** (Post-Sprint 9): Wire up real Kyber512 + Dilithium2
   - Replace stub encryption with hybrid KEM
   - Replace stub signature with Dilithium2

2. **Exchange SDK Development**:
   - Rust library for audit packet processing
   - TypeScript SDK for web integration
   - Docker container for self-hosted compliance server

3. **Regulatory Review**: Engage legal counsel for jurisdictional analysis

4. **Testnet Deployment**: Deploy to testnet with sandbox exchange

---

## References

- [FATF Recommendation 16 (Travel Rule)](https://www.fatf-gafi.org/recommendations.html)
- [FinCEN CTR Requirements](https://www.fincen.gov/currency-transaction-report-ctr)
- [GDPR Article 17 (Right to Erasure)](https://gdpr-info.eu/art-17-gdpr/)
- [5AMLD (EU)](https://eur-lex.europa.eu/eli/dir/2018/843/oj)
- [Kyber Cryptographic Specification](https://pq-crystals.org/kyber/)
- [Dilithium Cryptographic Specification](https://pq-crystals.org/dilithium/)

---

**Document Version**: 1.0  
**Last Updated**: Sprint 9 Completion  
**Status**: Framework Complete, Cryptography Deferred to Step 6
