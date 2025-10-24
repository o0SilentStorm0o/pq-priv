//! Transaction data structures and helpers.

use std::fmt;

use blake3::Hasher;
use codec::to_vec_cbor;
use crypto::{self, AlgTag, Commitment, PublicKey, RangeProof, Signature, SpendKeypair, compute_link_tag};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// 32 byte transaction identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TxId(pub [u8; 32]);

impl TxId {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for TxId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0 {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

/// Metadata describing optional deposit behaviour.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutputMeta {
    pub deposit_flag: bool,
    pub deposit_id: Option<[u8; 32]>,
}

/// Transaction output representation.
///
/// Supports both transparent and confidential outputs:
/// - Transparent: `value` is set, `commitment` is None
/// - Confidential: `value` is 0, `commitment` is Some(...)
///
/// # Consensus Rules
///
/// If `commitment.is_some()`:
/// - `value` MUST be 0
/// - A corresponding range proof MUST be present in `Witness::range_proofs`
/// - The commitment MUST be valid and balance with inputs
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Output {
    #[serde(with = "serde_bytes")]
    pub stealth_blob: Vec<u8>,
    /// Transparent value (0 if using commitment)
    pub value: u64,
    /// Optional Pedersen commitment for confidential amounts
    pub commitment: Option<Commitment>,
    /// Legacy field (kept for backward compatibility, unused if commitment is present)
    #[serde(default)]
    pub value_commitment: [u8; 32],
    pub output_meta: OutputMeta,
}

impl Output {
    /// Create a new transparent output.
    pub fn new(stealth_blob: Vec<u8>, value: u64, output_meta: OutputMeta) -> Self {
        Self {
            stealth_blob,
            value,
            commitment: None,
            value_commitment: [0u8; 32], // Unused for transparent outputs
            output_meta,
        }
    }

    /// Create a new confidential output with Pedersen commitment.
    pub fn new_confidential(
        stealth_blob: Vec<u8>,
        commitment: Commitment,
        output_meta: OutputMeta,
    ) -> Self {
        Self {
            stealth_blob,
            value: 0, // Must be 0 for confidential outputs
            commitment: Some(commitment),
            value_commitment: [0u8; 32], // Unused
            output_meta,
        }
    }

    /// Check if this output is confidential.
    pub fn is_confidential(&self) -> bool {
        self.commitment.is_some()
    }
}

/// Proof bundle for a spend input.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Input {
    pub prev_txid: [u8; 32],
    pub prev_index: u32,
    pub ann_link_tag: [u8; 32],
    pub spend_public: PublicKey,
    #[serde(with = "serde_bytes")]
    pub one_of_many_proof: Vec<u8>,
    pub pq_signature: Signature,
}

impl Input {
    pub fn new(
        prev_txid: [u8; 32],
        prev_index: u32,
        ann_link_tag: [u8; 32],
        spend_public: PublicKey,
        proof: Vec<u8>,
        signature: Signature,
    ) -> Self {
        Self {
            prev_txid,
            prev_index,
            ann_link_tag,
            spend_public,
            one_of_many_proof: proof,
            pq_signature: signature,
        }
    }
}

/// Witness data shared across the transaction.
///
/// Contains range proofs for confidential outputs and other auxiliary data.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Witness {
    /// Range proofs for confidential outputs (one per confidential output, in order)
    pub range_proofs: Vec<RangeProof>,
    /// Timestamp or block height
    pub stamp: u64,
    /// Additional data (e.g., memos, metadata)
    #[serde(with = "serde_bytes")]
    pub extra: Vec<u8>,
}

impl Witness {
    /// Create a new witness with range proofs.
    pub fn new(range_proofs: Vec<RangeProof>, stamp: u64, extra: Vec<u8>) -> Self {
        Self {
            range_proofs,
            stamp,
            extra,
        }
    }

    /// Get the number of range proofs.
    pub fn proof_count(&self) -> usize {
        self.range_proofs.len()
    }
}

/// Canonical transaction structure.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tx {
    pub version: u16,
    pub inputs: Vec<Input>,
    pub outputs: Vec<Output>,
    pub witness: Witness,
    pub locktime: u32,
}

impl Tx {
    pub fn new(inputs: Vec<Input>, outputs: Vec<Output>, witness: Witness) -> Self {
        Self {
            version: 1,
            inputs,
            outputs,
            witness,
            locktime: 0,
        }
    }

    /// Compute the transaction identifier (without witness data).
    pub fn txid(&self) -> TxId {
        let inputs: Vec<InputEssenceRef<'_>> = self
            .inputs
            .iter()
            .map(|input| InputEssenceRef {
                prev_txid: &input.prev_txid,
                prev_index: input.prev_index,
                ann_link_tag: &input.ann_link_tag,
                spend_public: input.spend_public.as_bytes(),
                one_of_many_proof: &input.one_of_many_proof,
            })
            .collect();
        let essence = TxEssenceRef {
            version: self.version,
            inputs,
            outputs: &self.outputs,
            locktime: self.locktime,
        };
        let encoded = to_vec_cbor(&essence).expect("encode tx essence");
        let hash: [u8; 32] = blake3::hash(&encoded).into();
        TxId(hash)
    }

    /// Compute the sighash for signing.
    pub fn sighash(&self, extra: &[u8]) -> [u8; 32] {
        let mut hasher = Hasher::new();
        hasher.update(self.txid().as_bytes());
        hasher.update(extra);
        hasher.finalize().into()
    }
}

#[derive(Serialize)]
struct TxEssenceRef<'a> {
    version: u16,
    inputs: Vec<InputEssenceRef<'a>>,
    outputs: &'a [Output],
    locktime: u32,
}

#[derive(Serialize)]
struct InputEssenceRef<'a> {
    prev_txid: &'a [u8; 32],
    prev_index: u32,
    ann_link_tag: &'a [u8; 32],
    #[serde(with = "serde_bytes")]
    spend_public: &'a [u8],
    #[serde(with = "serde_bytes")]
    one_of_many_proof: &'a [u8],
}

/// Convenience builder used in tests and wallet prototypes.
pub struct TxBuilder {
    inputs: Vec<Input>,
    outputs: Vec<Output>,
    witness: Witness,
}

impl TxBuilder {
    pub fn new() -> Self {
        Self {
            inputs: Vec::new(),
            outputs: Vec::new(),
            witness: Witness::default(),
        }
    }

    pub fn add_input(mut self, input: Input) -> Self {
        self.inputs.push(input);
        self
    }

    pub fn add_output(mut self, output: Output) -> Self {
        self.outputs.push(output);
        self
    }

    pub fn set_witness(mut self, witness: Witness) -> Self {
        self.witness = witness;
        self
    }

    pub fn build(self) -> Tx {
        Tx {
            version: 1,
            inputs: self.inputs,
            outputs: self.outputs,
            witness: self.witness,
            locktime: 0,
        }
    }
}

impl Default for TxBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Errors surfaced by helper APIs.
#[derive(Debug, Error)]
pub enum TxError {
    #[error("signature failed to verify")]
    InvalidSignature,
    #[error("confidential output missing range proof")]
    MissingRangeProof,
    #[error("confidential output has non-zero value (must be 0)")]
    InvalidConfidentialValue,
    #[error("invalid range proof")]
    InvalidRangeProof,
    #[error("commitment balance check failed (inflation detected)")]
    UnbalancedCommitments,
    #[error("too many range proofs: {got}, max allowed: {max}")]
    TooManyProofs { got: usize, max: usize },
}

/// Compute the binding hash over outputs and witness data.
pub fn binding_hash(outputs: &[Output], witness: &Witness) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(&(outputs.len() as u64).to_le_bytes());
    for output in outputs {
        hasher.update(&(output.stealth_blob.len() as u64).to_le_bytes());
        hasher.update(&output.stealth_blob);
        
        // Hash value or commitment
        if let Some(ref commitment) = output.commitment {
            hasher.update(&[1u8]); // Confidential marker
            hasher.update(commitment.as_bytes());
        } else {
            hasher.update(&[0u8]); // Transparent marker
            hasher.update(&output.value.to_le_bytes());
        }
        
        hasher.update(&output.value_commitment); // Legacy field
        hasher.update(&[output.output_meta.deposit_flag as u8]);
        match &output.output_meta.deposit_id {
            Some(id) => {
                hasher.update(&[1]);
                hasher.update(id);
            }
            None => {
                hasher.update(&[0]);
            }
        }
    }
    hasher.update(&witness.stamp.to_le_bytes());
    
    // Hash range proofs
    hasher.update(&(witness.range_proofs.len() as u64).to_le_bytes());
    for proof in &witness.range_proofs {
        let proof_bytes = proof.as_bytes();
        hasher.update(&(proof_bytes.len() as u64).to_le_bytes());
        hasher.update(proof_bytes);
    }
    
    hasher.update(&(witness.extra.len() as u64).to_le_bytes());
    hasher.update(&witness.extra);
    hasher.finalize().into()
}

fn auth_message_raw(
    prev_txid: &[u8; 32],
    prev_index: u32,
    ann_link_tag: &[u8; 32],
    spend_public: &PublicKey,
    ring_proof: &[u8],
    binding_hash: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(prev_txid);
    hasher.update(&prev_index.to_le_bytes());
    hasher.update(ann_link_tag);
    hasher.update(spend_public.as_bytes());
    hasher.update(binding_hash);
    hasher.update(blake3::hash(ring_proof).as_bytes());
    hasher.finalize().into()
}

/// Compute the signing message for an input that is part of the provided binding.
pub fn input_auth_message(input: &Input, binding_hash: &[u8; 32]) -> [u8; 32] {
    auth_message_raw(
        &input.prev_txid,
        input.prev_index,
        &input.ann_link_tag,
        &input.spend_public,
        &input.one_of_many_proof,
        binding_hash,
    )
}

/// Assemble a basic input by signing the binding-aware message with the spend key.
pub fn build_signed_input(
    prev_txid: [u8; 32],
    prev_index: u32,
    spend_key: &SpendKeypair,
    ring_proof: Vec<u8>,
    binding_hash: &[u8; 32],
) -> Input {
    let nonce = crypto::random_nonce::<16>();
    let link = compute_link_tag(&spend_key.public, &nonce);
    let message = auth_message_raw(
        &prev_txid,
        prev_index,
        &link,
        &spend_key.public,
        &ring_proof,
        binding_hash,
    );
    // Use Ed25519 for dev/test, will be Dilithium2 in production
    #[cfg(feature = "dev_stub_signing")]
    let alg = AlgTag::Ed25519;
    #[cfg(not(feature = "dev_stub_signing"))]
    let alg = AlgTag::Dilithium2;

    // Sign with TX context for domain separation
    let signature = crypto::sign(&message, &spend_key.secret, alg, crypto::context::TX)
        .expect("signing should not fail with valid key");
    Input::new(
        prev_txid,
        prev_index,
        link,
        spend_key.public.clone(),
        ring_proof,
        signature,
    )
}

/// Deterministically construct a stealth blob using the recipient's scan key.
pub fn build_stealth_blob(
    scan_pub: &PublicKey,
    spend_pub: &PublicKey,
    randomness: &[u8],
) -> Vec<u8> {
    let mut hasher = Hasher::new();
    hasher.update(b"stealth-v0");
    hasher.update(scan_pub.as_bytes());
    hasher.update(spend_pub.as_bytes());
    hasher.update(randomness);
    hasher.finalize().as_bytes().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::KeyMaterial;

    #[test]
    fn txid_changes_with_outputs() {
        let km = KeyMaterial::random();
        let scan = km.derive_scan_keypair(0);
        let spend = km.derive_spend_keypair(0);
        let stealth = build_stealth_blob(&scan.public, &spend.public, b"rnd");
        let commitment = crypto::commitment(42, b"blind");
        let output = Output::new(stealth, commitment, OutputMeta::default());
        let tx1 = TxBuilder::new().add_output(output.clone()).build();
        let tx2 = TxBuilder::new()
            .add_output(output)
            .add_output(Output::new(
                vec![1, 2, 3],
                commitment,
                OutputMeta::default(),
            ))
            .build();
        assert_ne!(tx1.txid(), tx2.txid());
    }

    #[test]
    fn link_tag_not_deterministic_with_builder() {
        let km = KeyMaterial::random();
        let spend = km.derive_spend_keypair(0);
        let prev = [7u8; 32];
        let outputs = vec![Output::new(vec![1], [0u8; 32], OutputMeta::default())];
        let witness = Witness::default();
        let binding = binding_hash(&outputs, &witness);

        let first = build_signed_input(prev, 0, &spend, vec![0xAA], &binding);
        let second = build_signed_input(prev, 0, &spend, vec![0xAA], &binding);

        // The helper draws a fresh random nonce per call, so link tags differ and double-spend detection cannot rely on them.
        assert_ne!(first.ann_link_tag, second.ann_link_tag);
    }
}
