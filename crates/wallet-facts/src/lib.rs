#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Bounded public-descriptor derivation and independently validated transaction,
//! input, and owned-output observations for the ordinary Liquid wallet.
//!
//! This crate performs no network access and accepts no LWK wallet, update,
//! store, PSET, signer, or broadcast type. The narrow upstream Bitcoin
//! Miniscript leaf is used only for public-key grammar and script
//! derivation. Candidate transaction bytes are reparsed and amount-proof
//! validated with the pinned rust-elements 0.27 stack before any owned output
//! is opened. Success does not establish chain inclusion, current unspentness,
//! confirmation, node identity, or balance credit.

use core::fmt;
use std::borrow::Borrow;
use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;

use elements::encode::{deserialize, serialize};
use elements::hashes::{hash160, sha256};
use elements::secp256k1_zkp::rand::{CryptoRng, RngCore};
use elements::secp256k1_zkp::{PublicKey, Secp256k1, SecretKey};
use elements::{OutPoint, Transaction, TxOut, Txid};
use miniscript::bitcoin::bip32::ChildNumber;
use miniscript::descriptor::{DescriptorPublicKey, Wildcard};
use miniscript::{Descriptor, ForEachKey};
use sha2::digest::Output;
use sha2::{Digest, Sha256};
use wasabi_liquid_native_transaction_validation::{
    TransactionValidationError, ValidatedOutputOpenError, validate_transaction_amount_proofs,
};
use zeroize::Zeroize;

/// Maximum accepted public descriptor length.
pub const MAX_PUBLIC_DESCRIPTOR_BYTES: usize = 16_384;
/// Maximum derivation index accepted by one catalog.
pub const MAX_DERIVATION_INDEX: u32 = 100_000;
/// Maximum candidate transactions accepted in one atomic batch.
pub const MAX_CANDIDATE_TRANSACTIONS: usize = 4_096;
/// Maximum previous-transaction entries accepted in one atomic batch.
pub const MAX_PREVIOUS_TRANSACTIONS_PER_BATCH: usize = 16_384;
/// Maximum serialized transaction length accepted by this crate.
pub const MAX_TRANSACTION_BYTES: usize = 4 * 1_024 * 1_024;
/// Maximum aggregate serialized bytes accepted in one atomic batch.
pub const MAX_BATCH_BYTES: usize = 64 * 1_024 * 1_024;

/// Validates the complete public shape and native-P2WPKH binding of one
/// observed output without deriving keys or retaining input bytes.
///
/// This helper is total and deliberately reports only a boolean. Both public
/// keys must be complete compressed secp256k1 points, and `script_pubkey` must
/// be the exact version-zero P2WPKH script for `spend_public_key`.
pub fn validates_observed_public_output(
    script_pubkey: &[u8],
    spend_public_key: &[u8],
    blinding_public_key: &[u8],
) -> bool {
    if script_pubkey.len() != 22
        || spend_public_key.len() != 33
        || blinding_public_key.len() != 33
        || PublicKey::from_slice(spend_public_key).is_err()
        || PublicKey::from_slice(blinding_public_key).is_err()
    {
        return false;
    }

    let spend_key_hash = hash160::Hash::hash(spend_public_key).to_byte_array();
    let [0, 20, script_hash @ ..] = script_pubkey else {
        return false;
    };
    script_hash == spend_key_hash
}

/// The public derivation branch associated with an owned script.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum DescriptorBranch {
    /// External receive branch.
    External,
    /// Internal change branch.
    Internal,
}

/// The extended-public-key network class required by a descriptor catalog.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DescriptorNetwork {
    /// Liquid mainnet descriptors must contain mainnet extended public keys.
    Mainnet,
    /// Test and regtest descriptors must contain test extended public keys.
    Test,
}

/// A privacy-redacted descriptor-catalog construction failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum DescriptorCatalogError {
    /// The public descriptor is empty or exceeds its byte limit.
    DescriptorLength,
    /// The public descriptor is malformed or contains non-public key material.
    InvalidPublicDescriptor,
    /// Only native P2WPKH public descriptors are supported by this slice.
    UnsupportedDescriptor,
    /// Exactly one external and one internal wildcard branch are required.
    InvalidBranchShape,
    /// The extended public key belongs to a different network class.
    NetworkMismatch,
    /// A derivation index exceeds the supported normal-child range.
    DerivationIndex,
    /// Script or key derivation failed.
    DerivationFailed,
    /// Two derivation coordinates produced the same script.
    DuplicateScript,
}

impl fmt::Display for DescriptorCatalogError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::DescriptorLength => "public descriptor length is invalid",
            Self::InvalidPublicDescriptor => "public descriptor is invalid",
            Self::UnsupportedDescriptor => "public descriptor type is unsupported",
            Self::InvalidBranchShape => "public descriptor branch shape is invalid",
            Self::NetworkMismatch => "public descriptor network class does not match",
            Self::DerivationIndex => "descriptor derivation index is invalid",
            Self::DerivationFailed => "public descriptor derivation failed",
            Self::DuplicateScript => "public descriptor derived a duplicate script",
        })
    }
}

impl std::error::Error for DescriptorCatalogError {}

struct CatalogEntry {
    script_pubkey: Vec<u8>,
    spend_public_key: [u8; 33],
    branch: DescriptorBranch,
    index: u32,
}

impl Drop for CatalogEntry {
    fn drop(&mut self) {
        self.script_pubkey.zeroize();
        self.spend_public_key.zeroize();
        self.branch = DescriptorBranch::External;
        self.index.zeroize();
    }
}

#[derive(Eq, Ord, PartialEq, PartialOrd)]
struct CatalogScript(Vec<u8>);

impl Borrow<[u8]> for CatalogScript {
    fn borrow(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for CatalogScript {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// A bounded catalog derived from one public native-P2WPKH descriptor.
///
/// This type deliberately implements neither `Debug` nor `Clone`. It contains
/// only public scripts, public spend keys, and derivation coordinates; it never
/// receives or retains blinding-key material.
pub struct DescriptorCatalog {
    entries: BTreeMap<CatalogScript, CatalogEntry>,
    last_index: u32,
}

impl Drop for DescriptorCatalog {
    fn drop(&mut self) {
        self.last_index.zeroize();
    }
}

impl DescriptorCatalog {
    /// Derives both descriptor branches through `last_index`, inclusive.
    pub fn derive(
        public_spend_descriptor: &str,
        expected_network: DescriptorNetwork,
        last_index: u32,
    ) -> Result<Self, DescriptorCatalogError> {
        if public_spend_descriptor.is_empty()
            || public_spend_descriptor.len() > MAX_PUBLIC_DESCRIPTOR_BYTES
        {
            return Err(DescriptorCatalogError::DescriptorLength);
        }
        if last_index > MAX_DERIVATION_INDEX || last_index >= (1 << 31) {
            return Err(DescriptorCatalogError::DerivationIndex);
        }

        let descriptor = parse_public_spend_descriptor(public_spend_descriptor)?;
        if !matches!(descriptor, Descriptor::Wpkh(_)) || !descriptor.has_wildcard() {
            return Err(DescriptorCatalogError::UnsupportedDescriptor);
        }
        if !descriptor.for_each_key(key_uses_unhardened_wildcard) {
            return Err(DescriptorCatalogError::InvalidBranchShape);
        }
        if !descriptor.for_each_key(|key| key_matches_network(key, expected_network)) {
            return Err(DescriptorCatalogError::NetworkMismatch);
        }

        let singles = descriptor
            .into_single_descriptors()
            .map_err(|_| DescriptorCatalogError::InvalidBranchShape)?;
        if singles.len() != 2 {
            return Err(DescriptorCatalogError::InvalidBranchShape);
        }

        let mut entries = BTreeMap::new();
        let mut branches = BTreeSet::new();
        let secp = miniscript::bitcoin::secp256k1::Secp256k1::verification_only();
        for single in singles {
            if !matches!(single, Descriptor::Wpkh(_)) || !single.has_wildcard() {
                return Err(DescriptorCatalogError::UnsupportedDescriptor);
            }
            let branch = if keys_match_branch(&single, DescriptorBranch::External) {
                DescriptorBranch::External
            } else if keys_match_branch(&single, DescriptorBranch::Internal) {
                DescriptorBranch::Internal
            } else {
                return Err(DescriptorCatalogError::InvalidBranchShape);
            };
            if !branches.insert(branch) {
                return Err(DescriptorCatalogError::InvalidBranchShape);
            }
            for index in 0..=last_index {
                let definite = single
                    .at_derivation_index(index)
                    .map_err(|_| DescriptorCatalogError::DerivationFailed)?;
                let derived = definite
                    .derived_descriptor(&secp)
                    .map_err(|_| DescriptorCatalogError::DerivationFailed)?;
                let Descriptor::Wpkh(wpkh) = &derived else {
                    return Err(DescriptorCatalogError::UnsupportedDescriptor);
                };

                let script = derived.script_pubkey();
                let script_pubkey = script.as_bytes().to_vec();
                let spend_public_key = wpkh.as_inner().inner.serialize();
                let entry = CatalogEntry {
                    script_pubkey: script_pubkey.clone(),
                    spend_public_key,
                    branch,
                    index,
                };
                if entries
                    .insert(CatalogScript(script_pubkey), entry)
                    .is_some()
                {
                    return Err(DescriptorCatalogError::DuplicateScript);
                }
            }
        }

        if branches != BTreeSet::from([DescriptorBranch::External, DescriptorBranch::Internal]) {
            return Err(DescriptorCatalogError::InvalidBranchShape);
        }

        Ok(Self {
            entries,
            last_index,
        })
    }

    /// Returns the inclusive maximum derivation index in this catalog.
    pub const fn last_index(&self) -> u32 {
        self.last_index
    }

    /// Returns the total number of derived external and internal scripts.
    pub fn script_count(&self) -> usize {
        self.entries.len()
    }
}

fn key_uses_unhardened_wildcard(key: &DescriptorPublicKey) -> bool {
    match key {
        DescriptorPublicKey::XPub(key) => key.wildcard == Wildcard::Unhardened,
        DescriptorPublicKey::MultiXPub(key) => key.wildcard == Wildcard::Unhardened,
        DescriptorPublicKey::Single(_) => false,
    }
}

fn parse_public_spend_descriptor(
    public_spend_descriptor: &str,
) -> Result<Descriptor<DescriptorPublicKey>, DescriptorCatalogError> {
    let (descriptor_body, supplied_checksum) =
        if let Some((body, checksum)) = public_spend_descriptor.split_once('#') {
            if checksum.contains('#') || checksum.len() != 8 {
                return Err(DescriptorCatalogError::InvalidPublicDescriptor);
            }
            (body, Some(checksum))
        } else {
            (public_spend_descriptor, None)
        };
    let expected_checksum = miniscript::descriptor::checksum::desc_checksum(descriptor_body)
        .map_err(|_| DescriptorCatalogError::InvalidPublicDescriptor)?;
    if supplied_checksum.is_some_and(|checksum| checksum != expected_checksum) {
        return Err(DescriptorCatalogError::InvalidPublicDescriptor);
    }
    let inner = descriptor_body
        .strip_prefix("elwpkh(")
        .and_then(|value| value.strip_suffix(')'))
        .ok_or(DescriptorCatalogError::UnsupportedDescriptor)?;
    let bitcoin_descriptor = format!("wpkh({inner})");
    Descriptor::<DescriptorPublicKey>::from_str(&bitcoin_descriptor)
        .map_err(|_| DescriptorCatalogError::InvalidPublicDescriptor)
}

fn key_matches_network(key: &DescriptorPublicKey, expected: DescriptorNetwork) -> bool {
    let is_mainnet = match key {
        DescriptorPublicKey::XPub(key) => key.xkey.network.is_mainnet(),
        DescriptorPublicKey::MultiXPub(key) => key.xkey.network.is_mainnet(),
        DescriptorPublicKey::Single(_) => return false,
    };
    is_mainnet == matches!(expected, DescriptorNetwork::Mainnet)
}

fn keys_match_branch(
    descriptor: &Descriptor<DescriptorPublicKey>,
    expected_branch: DescriptorBranch,
) -> bool {
    descriptor.for_each_key(|key| {
        let Some(path) = key.full_derivation_path() else {
            return false;
        };
        let expected = match expected_branch {
            DescriptorBranch::External => ChildNumber::Normal { index: 0 },
            DescriptorBranch::Internal => ChildNumber::Normal { index: 1 },
        };
        path.into_iter().last() == Some(&expected) && key.has_wildcard()
    })
}

/// A borrowed candidate transaction and the complete previous transactions
/// needed to validate all of its inputs before any payload is copied.
///
/// Values must be canonical transaction consensus bytes. This type deliberately
/// implements neither `Debug`, `Clone`, nor `Copy`.
pub struct BorrowedCandidateTransaction<'candidate> {
    transaction: &'candidate [u8],
    previous_transactions: &'candidate [Vec<u8>],
}

impl<'candidate> BorrowedCandidateTransaction<'candidate> {
    /// Borrows a candidate without allocating or copying any payload bytes.
    pub const fn new(
        transaction: &'candidate [u8],
        previous_transactions: &'candidate [Vec<u8>],
    ) -> Self {
        Self {
            transaction,
            previous_transactions,
        }
    }
}

struct CandidateTransaction {
    transaction: Vec<u8>,
    previous_transactions: Vec<Vec<u8>>,
}

impl Drop for CandidateTransaction {
    fn drop(&mut self) {
        self.transaction.zeroize();
        for previous in &mut self.previous_transactions {
            previous.zeroize();
        }
        self.previous_transactions.clear();
    }
}

/// An owned candidate batch whose count and aggregate byte limits were checked
/// atomically before any payload was copied.
///
/// This type deliberately implements neither `Debug`, `Clone`, nor `Copy`.
pub struct CandidateBatch {
    candidates: Vec<CandidateTransaction>,
}

impl CandidateBatch {
    /// Validates all borrowed sizes and counts before copying the whole batch.
    pub fn new(
        candidates: &[BorrowedCandidateTransaction<'_>],
    ) -> Result<Self, WalletObservationError> {
        if candidates.len() > MAX_CANDIDATE_TRANSACTIONS {
            return Err(WalletObservationError::BatchLimit);
        }

        let mut aggregate_bytes = 0_usize;
        let mut previous_entries = 0_usize;
        for candidate in candidates {
            if candidate.transaction.is_empty()
                || candidate.transaction.len() > MAX_TRANSACTION_BYTES
            {
                return Err(WalletObservationError::TransactionLength);
            }
            previous_entries = previous_entries
                .checked_add(candidate.previous_transactions.len())
                .ok_or(WalletObservationError::BatchLimit)?;
            if previous_entries > MAX_PREVIOUS_TRANSACTIONS_PER_BATCH
                || candidate
                    .previous_transactions
                    .iter()
                    .any(|bytes| bytes.is_empty() || bytes.len() > MAX_TRANSACTION_BYTES)
            {
                return Err(WalletObservationError::PreviousTransactionSet);
            }
            aggregate_bytes = candidate
                .previous_transactions
                .iter()
                .try_fold(
                    aggregate_bytes
                        .checked_add(candidate.transaction.len())
                        .ok_or(WalletObservationError::BatchLimit)?,
                    |total, previous| total.checked_add(previous.len()),
                )
                .ok_or(WalletObservationError::BatchLimit)?;
            if aggregate_bytes > MAX_BATCH_BYTES {
                return Err(WalletObservationError::BatchLimit);
            }
        }

        let candidates = candidates
            .iter()
            .map(|candidate| CandidateTransaction {
                transaction: clone_candidate_payload(candidate.transaction),
                previous_transactions: candidate
                    .previous_transactions
                    .iter()
                    .map(|bytes| clone_candidate_payload(bytes))
                    .collect(),
            })
            .collect();
        Ok(Self { candidates })
    }
}

fn clone_candidate_payload(bytes: &[u8]) -> Vec<u8> {
    #[cfg(test)]
    CANDIDATE_PAYLOAD_CLONES.with(|count| count.set(count.get() + 1));
    bytes.to_vec()
}

/// A privacy-redacted failure while validating an observation batch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum WalletObservationError {
    /// The atomic batch exceeds its transaction-count or byte limit.
    BatchLimit,
    /// The caller-provided context-randomness source could not provide a seed.
    ContextRandomnessUnavailable,
    /// A candidate transaction has an invalid serialized length.
    TransactionLength,
    /// The previous-transaction set is missing, extra, duplicate, or oversized.
    PreviousTransactionSet,
    /// Canonical transaction decoding or round-trip encoding failed.
    InvalidTransactionEncoding,
    /// A previous transaction does not match an input outpoint.
    PreviousTransactionMismatch,
    /// Two candidates repeat the same transaction identifier.
    DuplicateTransaction,
    /// Transaction amount-proof validation failed.
    TransactionValidation,
    /// An owned script was attached to an explicit output, which is outside
    /// this confidential-observation policy.
    ExplicitOwnedOutput,
    /// An owned output was not fully confidential or could not be opened.
    OwnedOutputOpening,
    /// A normalized outpoint was repeated or exceeded its supported index.
    DuplicateOwnedOutpoint,
}

impl fmt::Display for WalletObservationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::BatchLimit => "wallet observation batch limit exceeded",
            Self::ContextRandomnessUnavailable => {
                "wallet observation context randomness is unavailable"
            }
            Self::TransactionLength => "wallet observation transaction length is invalid",
            Self::PreviousTransactionSet => {
                "wallet observation previous-transaction set is invalid"
            }
            Self::InvalidTransactionEncoding => {
                "wallet observation transaction encoding is invalid"
            }
            Self::PreviousTransactionMismatch => {
                "wallet observation previous transaction does not match"
            }
            Self::DuplicateTransaction => "wallet observation repeats a transaction",
            Self::TransactionValidation => "wallet observation transaction validation failed",
            Self::ExplicitOwnedOutput => "wallet observation explicit owned output is unsupported",
            Self::OwnedOutputOpening => "wallet observation owned output opening failed",
            Self::DuplicateOwnedOutpoint => "wallet observation repeats an owned outpoint",
        })
    }
}

impl std::error::Error for WalletObservationError {}

impl From<TransactionValidationError> for WalletObservationError {
    fn from(_: TransactionValidationError) -> Self {
        Self::TransactionValidation
    }
}

impl From<ValidatedOutputOpenError> for WalletObservationError {
    fn from(_: ValidatedOutputOpenError) -> Self {
        Self::OwnedOutputOpening
    }
}

/// One input outpoint from an independently amount-proof-validated transaction.
///
/// This public transaction fact intentionally implements neither `Debug`,
/// `Clone`, nor `Copy`. It establishes no wallet ownership, chain inclusion,
/// current unspentness, or spend authority.
pub struct ObservedTransactionInput {
    previous_transaction_id: [u8; 32],
    previous_output_index: u32,
}

impl Drop for ObservedTransactionInput {
    fn drop(&mut self) {
        self.previous_transaction_id.zeroize();
        self.previous_output_index.zeroize();
        #[cfg(test)]
        OBSERVED_TRANSACTION_INPUT_DROPS.with(|count| count.set(count.get() + 1));
    }
}

impl ObservedTransactionInput {
    /// Returns the consensus-order previous transaction identifier bytes.
    pub const fn previous_transaction_id(&self) -> &[u8; 32] {
        &self.previous_transaction_id
    }

    /// Returns the previous transaction output index.
    pub const fn previous_output_index(&self) -> u32 {
        self.previous_output_index
    }
}

/// One independently amount-proof-validated candidate transaction.
///
/// Inputs retain exact consensus transaction order. This observation
/// deliberately implements neither `Debug`, `Clone`, nor `Copy`, and it grants
/// no chain ordering, wallet ownership, confirmation, UTXO, or balance-credit
/// authority.
pub struct ObservedWalletTransaction {
    transaction_id: [u8; 32],
    transaction_witness_binding: [u8; 32],
    inputs: Vec<ObservedTransactionInput>,
}

impl Drop for ObservedWalletTransaction {
    fn drop(&mut self) {
        self.transaction_id.zeroize();
        self.transaction_witness_binding.zeroize();
        self.inputs.clear();
        #[cfg(test)]
        OBSERVED_WALLET_TRANSACTION_DROPS.with(|count| count.set(count.get() + 1));
    }
}

impl ObservedWalletTransaction {
    /// Returns the consensus-order transaction identifier bytes.
    pub const fn transaction_id(&self) -> &[u8; 32] {
        &self.transaction_id
    }

    /// Returns a single SHA-256 binding to the exact witness-inclusive bytes.
    pub const fn transaction_witness_binding(&self) -> &[u8; 32] {
        &self.transaction_witness_binding
    }

    /// Borrows inputs in exact consensus transaction order.
    pub fn inputs(&self) -> &[ObservedTransactionInput] {
        &self.inputs
    }
}

/// One independently amount-proof-validated output matching the bounded public
/// descriptor catalog.
///
/// The fact intentionally omits blinding secrets and implements neither
/// `Debug` nor `Clone`. It is an observation only, not UTXO, confirmation, or
/// wallet-credit authority.
pub struct ObservedOwnedOutput {
    transaction_id: [u8; 32],
    output_index: u32,
    transaction_witness_binding: [u8; 32],
    script_pubkey: Vec<u8>,
    spend_public_key: [u8; 33],
    blinding_public_key: [u8; 33],
    branch: DescriptorBranch,
    derivation_index: u32,
    asset_id: [u8; 32],
    value: u64,
}

impl Drop for ObservedOwnedOutput {
    fn drop(&mut self) {
        self.transaction_id.zeroize();
        self.output_index.zeroize();
        self.transaction_witness_binding.zeroize();
        self.script_pubkey.zeroize();
        self.spend_public_key.zeroize();
        self.blinding_public_key.zeroize();
        self.branch = DescriptorBranch::External;
        self.derivation_index.zeroize();
        self.asset_id.zeroize();
        self.value.zeroize();
        #[cfg(test)]
        OBSERVED_OWNED_OUTPUT_DROPS.with(|count| count.set(count.get() + 1));
    }
}

impl ObservedOwnedOutput {
    /// Returns the consensus-order transaction identifier bytes.
    pub const fn transaction_id(&self) -> &[u8; 32] {
        &self.transaction_id
    }

    /// Returns the output index.
    pub const fn output_index(&self) -> u32 {
        self.output_index
    }

    /// Returns a SHA-256 binding to the exact witness-inclusive transaction bytes.
    pub const fn transaction_witness_binding(&self) -> &[u8; 32] {
        &self.transaction_witness_binding
    }

    /// Borrows the consensus scriptPubKey bytes.
    pub fn script_pubkey(&self) -> &[u8] {
        &self.script_pubkey
    }

    /// Returns the compressed spend public key.
    pub const fn spend_public_key(&self) -> &[u8; 33] {
        &self.spend_public_key
    }

    /// Returns the compressed blinding public key.
    pub const fn blinding_public_key(&self) -> &[u8; 33] {
        &self.blinding_public_key
    }

    /// Returns the descriptor branch.
    pub const fn branch(&self) -> DescriptorBranch {
        self.branch
    }

    /// Returns the normal child index.
    pub const fn derivation_index(&self) -> u32 {
        self.derivation_index
    }

    /// Returns the consensus-order asset identifier bytes.
    pub const fn asset_id(&self) -> &[u8; 32] {
        &self.asset_id
    }

    /// Returns the strictly positive asset amount in its indivisible unit.
    pub const fn value(&self) -> u64 {
        self.value
    }
}

/// An atomic deterministic batch of validated transaction and owned-output
/// observations.
///
/// This type deliberately implements neither `Debug` nor `Clone`.
pub struct ObservedWalletBatch {
    transactions: Vec<ObservedWalletTransaction>,
    outputs: Vec<ObservedOwnedOutput>,
}

/// A scoped borrow of one SLIP-77 master blinding key.
///
/// This wrapper deliberately implements neither `Debug`, `Clone`, nor `Copy`
/// and never owns or retains the borrowed bytes.
pub struct BorrowedSlip77<'key> {
    bytes: &'key [u8; 32],
}

impl<'key> BorrowedSlip77<'key> {
    /// Creates a scoped borrow without copying the master key.
    pub const fn new(bytes: &'key [u8; 32]) -> Self {
        Self { bytes }
    }
}

impl ObservedWalletBatch {
    /// Borrows every candidate transaction sorted by consensus-order transaction
    /// identifier. This deterministic representation is not chain order.
    pub fn transactions(&self) -> &[ObservedWalletTransaction] {
        &self.transactions
    }

    /// Borrows observations sorted by consensus-order transaction ID and vout.
    pub fn outputs(&self) -> &[ObservedOwnedOutput] {
        &self.outputs
    }

    /// Returns whether the candidate batch contained no transaction observation.
    /// Output absence is reported separately by [`Self::outputs`].
    pub fn is_empty(&self) -> bool {
        self.transactions.is_empty()
    }
}

struct PreparedCandidate {
    owned_output_indices: Vec<u32>,
}

impl Drop for PreparedCandidate {
    fn drop(&mut self) {
        self.owned_output_indices.zeroize();
        #[cfg(test)]
        PREPARED_CANDIDATE_DROPS.with(|count| count.set(count.get() + 1));
    }
}

#[derive(Eq, Ord, PartialEq, PartialOrd)]
struct PreparedTransactionId([u8; 32]);

impl Drop for PreparedTransactionId {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

struct PreparedCandidateOrder(Vec<usize>);

impl Drop for PreparedCandidateOrder {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Validates one bounded candidate batch and atomically normalizes every output
/// matching the descriptor catalog.
///
/// Every candidate transaction is decoded canonically, bound to its complete
/// previous-transaction set, and amount-proof validated before any output is
/// opened. A single malformed transaction or owned-output opening rejects the
/// entire batch without returning partial facts. Product-owned HMAC pads and
/// digests are cleared on every return or unwind path, the pinned SHA-256 state
/// and finalization temporary are zeroized, and each scoped derived key is
/// erased on every return path. The caller must supply a cryptographically
/// secure random generator. When the batch has at least one owned output,
/// exactly one call obtains 32 bytes to randomize the secp256k1 context before
/// any blinding-key operation, and that seed is then erased. A batch with no
/// owned outputs performs no random request or blinding-key derivation. No
/// guarantee is made about compiler-made copies.
pub fn observe_owned_outputs<R: RngCore + CryptoRng>(
    catalog: &DescriptorCatalog,
    slip77_master_key: BorrowedSlip77<'_>,
    candidates: &CandidateBatch,
    rng: &mut R,
) -> Result<ObservedWalletBatch, WalletObservationError> {
    let mut candidate_indices_by_id = BTreeMap::new();
    let public_validation_context = Secp256k1::new();
    let mut prepared_candidates = Vec::with_capacity(candidates.candidates.len());
    let mut total_inputs = 0_usize;
    let mut total_owned_outputs = 0_usize;

    for (candidate_index, candidate) in candidates.candidates.iter().enumerate() {
        let transaction = decode_candidate_transaction(&candidate.transaction)?;
        let transaction_id = Box::new(PreparedTransactionId(transaction.txid().to_byte_array()));
        if candidate_indices_by_id
            .insert(transaction_id, candidate_index)
            .is_some()
        {
            return Err(WalletObservationError::DuplicateTransaction);
        }

        let previous_outputs =
            previous_outputs_for(&transaction, &candidate.previous_transactions)?;
        let validated = validate_transaction_amount_proofs(
            &public_validation_context,
            &transaction,
            previous_outputs,
        )?;
        total_inputs =
            checked_total_input_count(total_inputs, validated.transaction().input.len())?;
        let owned_output_count = validated
            .transaction()
            .output
            .iter()
            .filter(|output| {
                catalog
                    .entries
                    .contains_key(output.script_pubkey.as_bytes())
            })
            .count();
        let mut prepared_candidate = PreparedCandidate {
            owned_output_indices: Vec::with_capacity(owned_output_count),
        };

        for (output_index, output) in validated.transaction().output.iter().enumerate() {
            if !catalog
                .entries
                .contains_key(output.script_pubkey.as_bytes())
            {
                continue;
            }
            let output_index = u32::try_from(output_index)
                .map_err(|_| WalletObservationError::DuplicateOwnedOutpoint)?;
            if output_index >= (1 << 30) {
                return Err(WalletObservationError::DuplicateOwnedOutpoint);
            }
            if !output.asset.is_confidential()
                || !output.value.is_confidential()
                || !output.nonce.is_confidential()
            {
                return Err(WalletObservationError::ExplicitOwnedOutput);
            }
            debug_assert!(prepared_candidate.owned_output_indices.len() < owned_output_count);
            prepared_candidate.owned_output_indices.push(output_index);
        }
        debug_assert_eq!(
            prepared_candidate.owned_output_indices.len(),
            owned_output_count
        );
        total_owned_outputs = total_owned_outputs
            .checked_add(owned_output_count)
            .ok_or(WalletObservationError::BatchLimit)?;

        prepared_candidates.push(prepared_candidate);
    }

    let mut candidate_order =
        PreparedCandidateOrder(Vec::with_capacity(candidate_indices_by_id.len()));
    candidate_order
        .0
        .extend(candidate_indices_by_id.into_values());
    debug_assert_eq!(candidate_order.0.len(), candidates.candidates.len());

    let mut secp = public_validation_context;
    if total_owned_outputs != 0 {
        let mut context_randomization_seed = ScopedContextRandomizationSeed([0; 32]);
        rng.try_fill_bytes(&mut context_randomization_seed.0)
            .map_err(|_| WalletObservationError::ContextRandomnessUnavailable)?;
        secp.seeded_randomize(&context_randomization_seed.0);
        drop(context_randomization_seed);
    }

    let mut transactions = Vec::with_capacity(candidates.candidates.len());
    let mut outputs = Vec::with_capacity(total_owned_outputs);
    for candidate_index in candidate_order.0.iter().copied() {
        let candidate = &candidates.candidates[candidate_index];
        let prepared = &prepared_candidates[candidate_index];
        let transaction = decode_candidate_transaction(&candidate.transaction)?;
        let previous_outputs =
            previous_outputs_for(&transaction, &candidate.previous_transactions)?;
        let validated = validate_transaction_amount_proofs(&secp, &transaction, previous_outputs)?;
        let validated_transaction = validated.transaction();
        let transaction_id = validated_transaction.txid().to_byte_array();
        let witness_binding = sha256::Hash::hash(&candidate.transaction).to_byte_array();
        let mut inputs = Vec::with_capacity(validated_transaction.input.len());
        for input in &validated_transaction.input {
            inputs.push(ObservedTransactionInput {
                previous_transaction_id: input.previous_output.txid.to_byte_array(),
                previous_output_index: input.previous_output.vout,
            });
        }
        debug_assert_eq!(inputs.len(), inputs.capacity());
        let observed_transaction = ObservedWalletTransaction {
            transaction_id,
            transaction_witness_binding: witness_binding,
            inputs,
        };

        for output_index in prepared.owned_output_indices.iter().copied() {
            let output = validated_transaction
                .output
                .get(output_index as usize)
                .ok_or(WalletObservationError::InvalidTransactionEncoding)?;
            let entry = catalog
                .entries
                .get(output.script_pubkey.as_bytes())
                .ok_or(WalletObservationError::InvalidTransactionEncoding)?;
            let blinding_key = derive_blinding_key(slip77_master_key.bytes, &entry.script_pubkey)?;
            let blinding_public_key = blinding_key.0.public_key(&secp).serialize();
            let opened = validated.open_output(&secp, output_index as usize, &blinding_key.0)?;
            require_positive_owned_output_value(opened.value())?;
            debug_assert!(outputs.len() < total_owned_outputs);
            outputs.push(ObservedOwnedOutput {
                transaction_id,
                output_index,
                transaction_witness_binding: witness_binding,
                script_pubkey: entry.script_pubkey.clone(),
                spend_public_key: entry.spend_public_key,
                blinding_public_key,
                branch: entry.branch,
                derivation_index: entry.index,
                asset_id: *opened.asset_id(),
                value: *opened.value(),
            });
        }
        debug_assert!(transactions.len() < candidates.candidates.len());
        transactions.push(observed_transaction);
    }

    debug_assert_eq!(transactions.len(), candidates.candidates.len());
    debug_assert_eq!(transactions.len(), transactions.capacity());
    debug_assert_eq!(
        transactions
            .iter()
            .map(|transaction| transaction.inputs.len())
            .sum::<usize>(),
        total_inputs
    );
    debug_assert!(
        transactions
            .windows(2)
            .all(|pair| { pair[0].transaction_id.cmp(&pair[1].transaction_id).is_lt() })
    );
    debug_assert_eq!(outputs.len(), total_owned_outputs);
    debug_assert!(outputs.windows(2).all(|pair| {
        pair[0]
            .transaction_id
            .cmp(&pair[1].transaction_id)
            .then(pair[0].output_index.cmp(&pair[1].output_index))
            .is_le()
    }));
    Ok(ObservedWalletBatch {
        transactions,
        outputs,
    })
}

fn require_positive_owned_output_value(value: &u64) -> Result<(), WalletObservationError> {
    if *value == 0 {
        Err(WalletObservationError::TransactionValidation)
    } else {
        Ok(())
    }
}

fn checked_total_input_count(
    current: usize,
    additional: usize,
) -> Result<usize, WalletObservationError> {
    current
        .checked_add(additional)
        .ok_or(WalletObservationError::BatchLimit)
}

fn derive_blinding_key(
    slip77_master_key: &[u8; 32],
    script_pubkey: &[u8],
) -> Result<ScopedSecretKey, WalletObservationError> {
    #[cfg(test)]
    DERIVATION_CALLS.with(|count| count.set(count.get() + 1));
    let mut inner_pad = ScopedSecretBytes([0x36; 64]);
    let mut outer_pad = ScopedSecretBytes([0x5c; 64]);
    for (index, key_byte) in slip77_master_key.iter().enumerate() {
        inner_pad.0[index] ^= key_byte;
        outer_pad.0[index] ^= key_byte;
    }

    let mut inner = Sha256::new();
    inner.update(&inner_pad.0);
    inner.update(script_pubkey);
    let inner_digest = ScopedHashOutput(inner.finalize());

    let mut outer = Sha256::new();
    outer.update(&outer_pad.0);
    outer.update(&inner_digest.0);
    let key_digest = ScopedHashOutput(outer.finalize());
    #[cfg(test)]
    let mut key_digest = key_digest;

    #[cfg(test)]
    match derivation_test_mode() {
        DerivationTestMode::Normal => {}
        DerivationTestMode::InvalidScalar => key_digest.0.as_mut_slice().zeroize(),
        DerivationTestMode::PanicAfterOuter => {
            set_derivation_test_mode(DerivationTestMode::Normal);
            panic!("test-only derivation unwind");
        }
    }

    SecretKey::from_slice(&key_digest.0)
        .map(ScopedSecretKey)
        .map_err(|_| WalletObservationError::OwnedOutputOpening)
}

struct ScopedSecretBytes<const LENGTH: usize>([u8; LENGTH]);

struct ScopedContextRandomizationSeed([u8; 32]);

impl Drop for ScopedContextRandomizationSeed {
    fn drop(&mut self) {
        self.0.zeroize();
        #[cfg(test)]
        CONTEXT_RANDOMIZATION_SEED_DROPS.with(|count| count.set(count.get() + 1));
    }
}

impl<const LENGTH: usize> Drop for ScopedSecretBytes<LENGTH> {
    fn drop(&mut self) {
        self.0.zeroize();
        #[cfg(test)]
        DERIVATION_SECRET_BUFFER_DROPS.with(|count| count.set(count.get() + 1));
    }
}

struct ScopedHashOutput(Output<Sha256>);

impl Drop for ScopedHashOutput {
    fn drop(&mut self) {
        self.0.as_mut_slice().zeroize();
        #[cfg(test)]
        DERIVATION_SECRET_BUFFER_DROPS.with(|count| count.set(count.get() + 1));
    }
}

struct ScopedSecretKey(SecretKey);

impl Drop for ScopedSecretKey {
    fn drop(&mut self) {
        self.0.non_secure_erase();
        #[cfg(test)]
        SCOPED_SECRET_KEY_DROPS.with(|count| count.set(count.get() + 1));
    }
}

#[cfg(test)]
thread_local! {
    static SCOPED_SECRET_KEY_DROPS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static DERIVATION_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static PREPARED_CANDIDATE_DROPS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static DERIVATION_SECRET_BUFFER_DROPS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static CONTEXT_RANDOMIZATION_SEED_DROPS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static CANDIDATE_PAYLOAD_CLONES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static OBSERVED_OWNED_OUTPUT_DROPS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static OBSERVED_TRANSACTION_INPUT_DROPS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static OBSERVED_WALLET_TRANSACTION_DROPS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static CANDIDATE_TRANSACTION_DECODES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static PREVIOUS_TRANSACTION_DECODES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static DERIVATION_TEST_MODE: std::cell::Cell<DerivationTestMode> = const {
        std::cell::Cell::new(DerivationTestMode::Normal)
    };
}

#[cfg(test)]
fn scoped_secret_key_drop_count() -> usize {
    SCOPED_SECRET_KEY_DROPS.with(std::cell::Cell::get)
}

#[cfg(test)]
fn derivation_call_count() -> usize {
    DERIVATION_CALLS.with(std::cell::Cell::get)
}

#[cfg(test)]
fn prepared_candidate_drop_count() -> usize {
    PREPARED_CANDIDATE_DROPS.with(std::cell::Cell::get)
}

#[cfg(test)]
fn derivation_secret_buffer_drop_count() -> usize {
    DERIVATION_SECRET_BUFFER_DROPS.with(std::cell::Cell::get)
}

#[cfg(test)]
fn context_randomization_seed_drop_count() -> usize {
    CONTEXT_RANDOMIZATION_SEED_DROPS.with(std::cell::Cell::get)
}

#[cfg(test)]
fn candidate_payload_clone_count() -> usize {
    CANDIDATE_PAYLOAD_CLONES.with(std::cell::Cell::get)
}

#[cfg(test)]
fn observed_owned_output_drop_count() -> usize {
    OBSERVED_OWNED_OUTPUT_DROPS.with(std::cell::Cell::get)
}

#[cfg(test)]
fn observed_transaction_input_drop_count() -> usize {
    OBSERVED_TRANSACTION_INPUT_DROPS.with(std::cell::Cell::get)
}

#[cfg(test)]
fn observed_wallet_transaction_drop_count() -> usize {
    OBSERVED_WALLET_TRANSACTION_DROPS.with(std::cell::Cell::get)
}

#[cfg(test)]
fn candidate_transaction_decode_count() -> usize {
    CANDIDATE_TRANSACTION_DECODES.with(std::cell::Cell::get)
}

#[cfg(test)]
fn previous_transaction_decode_count() -> usize {
    PREVIOUS_TRANSACTION_DECODES.with(std::cell::Cell::get)
}

#[cfg(test)]
#[derive(Clone, Copy)]
enum DerivationTestMode {
    Normal,
    InvalidScalar,
    PanicAfterOuter,
}

#[cfg(test)]
fn set_derivation_test_mode(mode: DerivationTestMode) {
    DERIVATION_TEST_MODE.with(|current| current.set(mode));
}

#[cfg(test)]
fn derivation_test_mode() -> DerivationTestMode {
    DERIVATION_TEST_MODE.with(|current| current.replace(DerivationTestMode::Normal))
}

#[cfg(test)]
mod tests;

fn decode_transaction(bytes: &[u8]) -> Result<Transaction, WalletObservationError> {
    if bytes.is_empty() || bytes.len() > MAX_TRANSACTION_BYTES {
        return Err(WalletObservationError::TransactionLength);
    }
    let transaction = deserialize::<Transaction>(bytes)
        .map_err(|_| WalletObservationError::InvalidTransactionEncoding)?;
    if serialize(&transaction) != bytes {
        return Err(WalletObservationError::InvalidTransactionEncoding);
    }
    Ok(transaction)
}

fn decode_candidate_transaction(bytes: &[u8]) -> Result<Transaction, WalletObservationError> {
    #[cfg(test)]
    CANDIDATE_TRANSACTION_DECODES.with(|count| count.set(count.get() + 1));
    decode_transaction(bytes)
}

fn decode_previous_transaction(bytes: &[u8]) -> Result<Transaction, WalletObservationError> {
    #[cfg(test)]
    PREVIOUS_TRANSACTION_DECODES.with(|count| count.set(count.get() + 1));
    decode_transaction(bytes)
}

fn previous_outputs_for(
    transaction: &Transaction,
    previous_transactions: &[Vec<u8>],
) -> Result<BTreeMap<OutPoint, TxOut>, WalletObservationError> {
    let mut previous_by_id = BTreeMap::<Txid, Transaction>::new();
    for bytes in previous_transactions {
        let previous = decode_previous_transaction(bytes)?;
        let txid = previous.txid();
        if previous_by_id.insert(txid, previous).is_some() {
            return Err(WalletObservationError::PreviousTransactionSet);
        }
    }

    let referenced_ids = transaction
        .input
        .iter()
        .map(|input| input.previous_output.txid)
        .collect::<BTreeSet<_>>();
    if referenced_ids.len() != previous_by_id.len()
        || !referenced_ids
            .iter()
            .all(|txid| previous_by_id.contains_key(txid))
    {
        return Err(WalletObservationError::PreviousTransactionSet);
    }

    let mut outputs = BTreeMap::new();
    for input in &transaction.input {
        let outpoint = input.previous_output;
        let previous = previous_by_id
            .get(&outpoint.txid)
            .ok_or(WalletObservationError::PreviousTransactionMismatch)?;
        let output = previous
            .output
            .get(outpoint.vout as usize)
            .ok_or(WalletObservationError::PreviousTransactionMismatch)?;
        outputs.insert(outpoint, output.clone());
    }
    Ok(outputs)
}
