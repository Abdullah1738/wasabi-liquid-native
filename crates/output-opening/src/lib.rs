#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Confidential Liquid output opening with an explicitly borrowed blinding key.
//!
//! This crate exposes no C symbols, derives no keys, and retains no hidden
//! caller key or operation state beyond the returned result. Opening an output
//! does not independently establish transaction validity, chain inclusion, or
//! transaction-level proof validity.

use core::fmt;

use elements::secp256k1_zkp::{Secp256k1, SecretKey, Signing, Tweak, Verification};
use elements::{TxOut, TxOutSecrets, UnblindError};
use zeroize::Zeroize;

/// The private facts recovered from one confidential transaction output.
///
/// This type deliberately does not implement `Debug`, `Copy`, or `Clone` so
/// private output facts are not accidentally formatted or duplicated through
/// those traits. Its accessors borrow every recovered field; any copies made by
/// a caller become caller-owned private data and require an appropriate
/// lifecycle outside this crate.
pub struct OpenedOutput {
    asset_id: [u8; 32],
    value: u64,
    asset_blinding_factor: [u8; 32],
    value_blinding_factor: [u8; 32],
}

impl OpenedOutput {
    fn from_secrets(secrets: TxOutSecrets) -> Self {
        Self {
            asset_id: secrets.asset.to_byte_array(),
            value: secrets.value,
            asset_blinding_factor: tweak_bytes(secrets.asset_bf.into_inner()),
            value_blinding_factor: tweak_bytes(secrets.value_bf.into_inner()),
        }
    }

    /// Returns the consensus-order asset identifier bytes.
    pub const fn asset_id(&self) -> &[u8; 32] {
        &self.asset_id
    }

    /// Borrows the explicit amount in the asset's indivisible unit.
    pub const fn value(&self) -> &u64 {
        &self.value
    }

    /// Returns the asset blinding factor bytes.
    pub const fn asset_blinding_factor(&self) -> &[u8; 32] {
        &self.asset_blinding_factor
    }

    /// Returns the value blinding factor bytes.
    pub const fn value_blinding_factor(&self) -> &[u8; 32] {
        &self.value_blinding_factor
    }

    fn zeroize(&mut self) {
        self.asset_id.zeroize();
        self.value.zeroize();
        self.asset_blinding_factor.zeroize();
        self.value_blinding_factor.zeroize();
    }
}

impl Drop for OpenedOutput {
    fn drop(&mut self) {
        self.zeroize()
    }
}

/// A privacy-redacted output-opening failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum OutputOpenError {
    /// The output does not contain confidential asset and value commitments.
    NotConfidential,
    /// The output has no nonce commitment.
    MissingNonce,
    /// The output has no range proof.
    MissingRangeProof,
    /// The output could not be opened or its embedded message was invalid.
    InvalidOpening,
}

impl fmt::Display for OutputOpenError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::NotConfidential => "output is not confidential",
            Self::MissingNonce => "confidential output nonce is missing",
            Self::MissingRangeProof => "confidential output range proof is missing",
            Self::InvalidOpening => "confidential output opening failed",
        })
    }
}

impl std::error::Error for OutputOpenError {}

/// Opens one confidential output using a borrowed receiver blinding key.
///
/// The caller retains ownership of `blinding_key`. The function retains no
/// hidden state after returning and maps dependency errors to privacy-redacted
/// categories. It does not verify transaction-level surjection proofs,
/// commitment balance, chain inclusion, whether the output is currently
/// unspent, script ownership, or blinding-key provenance; callers must
/// establish those facts separately before crediting a wallet balance.
pub fn open_confidential_output<C: Signing + Verification>(
    secp: &Secp256k1<C>,
    output: &TxOut,
    blinding_key: &SecretKey,
) -> Result<OpenedOutput, OutputOpenError> {
    let range_proof_is_absent = output.witness.rangeproof.as_ref().is_none();
    output
        .unblind_with_key(secp, blinding_key)
        .map(OpenedOutput::from_secrets)
        .map_err(|error| map_unblind_error(error, range_proof_is_absent))
}

fn map_unblind_error(error: UnblindError, range_proof_is_absent: bool) -> OutputOpenError {
    match error {
        UnblindError::NotConfidential => OutputOpenError::NotConfidential,
        UnblindError::MissingNonce => OutputOpenError::MissingNonce,
        UnblindError::MissingRangeproof if range_proof_is_absent => {
            OutputOpenError::MissingRangeProof
        }
        UnblindError::MissingRangeproof
        | UnblindError::RangeProofMessage(_)
        | UnblindError::Rewind(_) => OutputOpenError::InvalidOpening,
        _ => OutputOpenError::InvalidOpening,
    }
}

fn tweak_bytes(tweak: Tweak) -> [u8; 32] {
    let mut bytes = [0_u8; 32];
    bytes.copy_from_slice(tweak.as_ref());
    bytes
}
