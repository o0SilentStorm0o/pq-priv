//! Transaction data structures and helpers.

use std::fmt;

use blake3::Hasher;
use codec::to_vec_cbor;
use crypto::{self, AlgTag, PublicKey, Signature, SpendKeypair, compute_link_tag};
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
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Output {
    #[serde(with = "serde_bytes")]
    pub stealth_blob: Vec<u8>,
    pub value_commitment: [u8; 32],
    pub output_meta: OutputMeta,
}

impl Output {
    pub fn new(stealth_blob: Vec<u8>, value_commitment: [u8; 32], output_meta: OutputMeta) -> Self {
        Self {
            stealth_blob,
            value_commitment,
            output_meta,
        }
    }
}

/// Proof bundle for a spend input.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Input {
    pub prev_txid: [u8; 32],
    pub prev_index: u32,
    pub ann_link_tag: [u8; 32],
    #[serde(with = "serde_bytes")]
    pub one_of_many_proof: Vec<u8>,
    pub pq_signature: Signature,
}

impl Input {
    pub fn new(
        prev_txid: [u8; 32],
        prev_index: u32,
        ann_link_tag: [u8; 32],
        proof: Vec<u8>,
        signature: Signature,
    ) -> Self {
        Self {
            prev_txid,
            prev_index,
            ann_link_tag,
            one_of_many_proof: proof,
            pq_signature: signature,
        }
    }
}

/// Witness data shared across the transaction.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Witness {
    #[serde(with = "serde_bytes")]
    pub range_proofs: Vec<u8>,
    pub stamp: u64,
    #[serde(with = "serde_bytes")]
    pub extra: Vec<u8>,
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
        let essence = TxEssenceRef {
            version: self.version,
            inputs: &self.inputs,
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
    inputs: &'a [Input],
    outputs: &'a [Output],
    locktime: u32,
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

/// Errors surfaced by helper APIs.
#[derive(Debug, Error)]
pub enum TxError {
    #[error("signature failed to verify")]
    InvalidSignature,
}

/// Assemble a basic input by signing the provided message with the spend key.
pub fn build_signed_input(
    prev_txid: [u8; 32],
    prev_index: u32,
    spend_key: &SpendKeypair,
    ring_proof: Vec<u8>,
    sighash: &[u8],
) -> Input {
    let nonce = crypto::random_nonce::<16>();
    let link = compute_link_tag(&spend_key.public, &nonce);
    let signature = crypto::sign(sighash, &spend_key.secret, AlgTag::Dilithium);
    Input::new(prev_txid, prev_index, link, ring_proof, signature)
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
}
