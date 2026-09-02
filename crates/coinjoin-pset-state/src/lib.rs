#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Strict validation and V1 protocol-state projection for one raw Elements PSET v2.
//!
//! This encoding is the Wasabi Liquid CoinJoin PSET-state V1 protocol encoding. It
//! is deliberately narrower than PSET and is not generic PSET canonicalization.
//! The crate parses and validates public pre-signing state only; it does not blind,
//! sign, retain secrets, coordinate a round, or infer confidential values.

use core::fmt;
use std::collections::BTreeSet;

use elements::{
    Txid, encode,
    issuance::AssetId,
    pset::{Input, Output, PartiallySignedTransaction},
    secp256k1_zkp::{Generator, Secp256k1},
};
use wasabi_liquid_native_coinjoin_state_transcript::{CoinJoinStateDigest, hash_coinjoin_state};

/// Fixed non-empty transcript domain for this canonical-state profile.
pub const PROTOCOL_DOMAIN: &[u8] = b"WL-COINJOIN-PSET-CANONICAL-STATE-V1";
/// Maximum accepted raw PSET size (1 MiB).
pub const MAX_RAW_PSET_BYTES: usize = 1_048_576;
/// Maximum emitted projection size (4 MiB).
pub const MAX_CANONICAL_BYTES: usize = 4_194_304;
/// Maximum network/profile identity length.
pub const MAX_NETWORK_IDENTITY_BYTES: usize = 64;
/// Maximum round/domain identifier length.
pub const MAX_ROUND_ID_BYTES: usize = 128;
/// Maximum input count for the two-party MVP profile.
pub const MAX_INPUT_COUNT: usize = 16;
/// Maximum output count for the two-party MVP profile.
pub const MAX_OUTPUT_COUNT: usize = 16;
/// Maximum ordered global scalar count for the two-party MVP profile.
pub const MAX_SCALAR_COUNT: usize = 8;
/// Maximum scriptPubKey size.
pub const MAX_SCRIPT_BYTES: usize = 10_000;
/// Maximum individual rangeproof size.
pub const MAX_RANGEPROOF_BYTES: usize = 1_048_576;
/// Maximum individual surjection-proof size.
pub const MAX_SURJECTION_PROOF_BYTES: usize = 1_048_576;
/// Maximum L-BTC atomic units admitted for checked explicit sums.
pub const MAX_LBTC_ATOMIC_UNITS: u64 = 21_000_000 * 100_000_000;

const MAGIC: &[u8] = b"WL-CJ-PSET-STATE";
const PROFILE_V1: u8 = 1;
const OUTPOINT_PEGIN_FLAG: u32 = 1 << 30;
const OUTPOINT_ISSUANCE_FLAG: u32 = 1 << 31;
const OUTPOINT_COINBASE_INDEX: u32 = u32::MAX;

/// Stable canonical-state profile version.
#[derive(Copy, Clone, PartialEq, Eq)]
#[repr(u8)]
pub enum ProfileVersion {
    /// The only supported projection profile.
    V1 = 1,
}

/// Stable round phase committed by the V1 context.
#[derive(Copy, Clone, PartialEq, Eq)]
#[repr(u8)]
pub enum Phase {
    /// Inputs and outputs are being registered.
    Construction = 1,
    /// Contributions are frozen for proof production.
    Proofs = 2,
    /// The accepted pre-signing state is frozen.
    PreSigning = 3,
}

/// Stable participant role committed by the V1 context.
#[derive(Copy, Clone, PartialEq, Eq)]
#[repr(u8)]
pub enum ParticipantRole {
    /// The first participant in the bounded two-party profile.
    Initiator = 1,
    /// The second participant in the bounded two-party profile.
    Responder = 2,
}

/// Typed predecessor-state presence; absence is distinct from an all-zero digest.
pub enum PredecessorDigest {
    /// This contribution has no predecessor.
    Absent,
    /// This contribution follows the exact public digest.
    Present([u8; 32]),
}

/// Immutable public context bound into every V1 transcript.
pub struct CanonicalStateContext<'a> {
    /// Explicit profile version; only V1 is accepted.
    pub profile: ProfileVersion,
    /// Bounded Elements network/profile identity bytes.
    pub network_identity: &'a [u8],
    /// Elements genesis block hash bytes.
    pub genesis_hash: [u8; 32],
    /// Canonical L-BTC asset identity.
    pub lbtc_asset: AssetId,
    /// Effective fee asset, required to equal `lbtc_asset`.
    pub fee_asset: AssetId,
    /// Bounded round/domain identifier.
    pub round_id: &'a [u8],
    /// Current protocol phase.
    pub phase: Phase,
    /// Current participant role.
    pub participant_role: ParticipantRole,
    /// Monotonic contribution ordinal supplied by the caller.
    pub contribution_ordinal: u32,
    /// Typed predecessor state.
    pub predecessor: PredecessorDigest,
}

/// Public accepted canonical state and its transcript digest.
pub struct CanonicalState {
    canonical_bytes: Vec<u8>,
    digest: CoinJoinStateDigest,
}

impl CanonicalState {
    /// Borrows the public V1 canonical projection.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    /// Returns the public transcript digest.
    #[must_use]
    pub const fn digest(&self) -> CoinJoinStateDigest {
        self.digest
    }

    /// Splits the public result into owned projection bytes and digest.
    #[must_use]
    pub fn into_parts(self) -> (Vec<u8>, CoinJoinStateDigest) {
        (self.canonical_bytes, self.digest)
    }
}

/// Privacy-redacted rejection categories. Values and source bytes are never included.
#[derive(Copy, Clone, PartialEq, Eq)]
pub enum Error {
    /// A documented public size/count bound was exceeded.
    LimitExceeded,
    /// The immutable caller context is invalid for V1.
    InvalidContext,
    /// Raw bytes do not decode as exactly one PSET v2.
    InvalidEncoding,
    /// Parsed bytes are not the pinned library's canonical wire serialization.
    NonCanonicalEncoding,
    /// A global field is unsupported or invalid.
    UnsupportedGlobal,
    /// An input field or shape is unsupported or invalid.
    UnsupportedInput,
    /// An output field or lifecycle shape is unsupported or invalid.
    UnsupportedOutput,
    /// L-BTC identity was absent, mismatched, or could not be verified.
    UnknownAsset,
    /// A duplicate outpoint or invalid cross-record relation was found.
    InvalidStructure,
    /// The transcript primitive rejected the bounded projection.
    TranscriptRejected,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::LimitExceeded => "canonical PSET state limit exceeded",
            Self::InvalidContext => "canonical PSET state context rejected",
            Self::InvalidEncoding => "raw PSET encoding rejected",
            Self::NonCanonicalEncoding => "non-canonical PSET encoding rejected",
            Self::UnsupportedGlobal => "unsupported PSET global state",
            Self::UnsupportedInput => "unsupported PSET input state",
            Self::UnsupportedOutput => "unsupported PSET output state",
            Self::UnknownAsset => "PSET state asset identity rejected",
            Self::InvalidStructure => "PSET state structure rejected",
            Self::TranscriptRejected => "canonical state transcript rejected",
        })
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}
impl std::error::Error for Error {}

/// Parses, validates, projects, and hashes one canonical raw PSET v2.
///
/// # Errors
///
/// Returns a privacy-redacted [`Error`] for malformed/noncanonical wire data,
/// invalid context, unsupported PSET fields, invalid L-BTC evidence, or limits.
pub fn canonicalize_pset_state(
    raw_pset: &[u8],
    context: &CanonicalStateContext<'_>,
) -> Result<CanonicalState, Error> {
    validate_context(context)?;
    if raw_pset.is_empty() || raw_pset.len() > MAX_RAW_PSET_BYTES {
        return Err(Error::LimitExceeded);
    }
    let pset: PartiallySignedTransaction =
        encode::deserialize(raw_pset).map_err(|_| Error::InvalidEncoding)?;
    if encode::serialize(&pset) != raw_pset {
        return Err(Error::NonCanonicalEncoding);
    }
    validate_counts(&pset)?;

    let context_bytes = encode_context(context);
    let mut out = Encoder::new(MAX_CANONICAL_BYTES);
    out.fixed(MAGIC)?;
    out.u8(PROFILE_V1)?;
    out.fixed(&context_bytes)?;
    project_globals(&pset, &mut out)?;
    let input_asset_generators = project_inputs(&pset, context.lbtc_asset, &mut out)?;
    project_outputs(&pset, context.lbtc_asset, &input_asset_generators, &mut out)?;
    let canonical_bytes = out.finish();
    let digest = hash_coinjoin_state(PROTOCOL_DOMAIN, &context_bytes, &canonical_bytes)
        .map_err(|_| Error::TranscriptRejected)?;
    Ok(CanonicalState {
        canonical_bytes,
        digest,
    })
}

fn validate_context(context: &CanonicalStateContext<'_>) -> Result<(), Error> {
    if context.profile as u8 != PROFILE_V1
        || context.network_identity.is_empty()
        || context.network_identity.len() > MAX_NETWORK_IDENTITY_BYTES
        || context.round_id.is_empty()
        || context.round_id.len() > MAX_ROUND_ID_BYTES
        || context.fee_asset != context.lbtc_asset
    {
        return Err(Error::InvalidContext);
    }
    Ok(())
}

fn validate_counts(pset: &PartiallySignedTransaction) -> Result<(), Error> {
    let inputs = pset.inputs().len();
    let outputs = pset.outputs().len();
    if inputs == 0
        || outputs == 0
        || inputs > MAX_INPUT_COUNT
        || outputs > MAX_OUTPUT_COUNT
        || pset.n_inputs() != inputs
        || pset.n_outputs() != outputs
        || pset.global.scalars.len() > MAX_SCALAR_COUNT
    {
        return Err(Error::LimitExceeded);
    }
    Ok(())
}

fn encode_context(context: &CanonicalStateContext<'_>) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(384);
    bytes.extend_from_slice(b"WL-CJ-CONTEXT-V1");
    bytes.push(PROFILE_V1);
    push_bytes(&mut bytes, context.network_identity);
    bytes.extend_from_slice(&context.genesis_hash);
    bytes.extend_from_slice(&context.lbtc_asset.to_byte_array());
    bytes.extend_from_slice(&context.fee_asset.to_byte_array());
    push_bytes(&mut bytes, context.round_id);
    bytes.push(context.phase as u8);
    bytes.push(context.participant_role as u8);
    bytes.extend_from_slice(&context.contribution_ordinal.to_be_bytes());
    match context.predecessor {
        PredecessorDigest::Absent => bytes.push(0),
        PredecessorDigest::Present(digest) => {
            bytes.push(1);
            bytes.extend_from_slice(&digest);
        }
    }
    bytes
}

fn project_globals(pset: &PartiallySignedTransaction, out: &mut Encoder) -> Result<(), Error> {
    let global = &pset.global;
    if global.version != 2
        || global.tx_data.version != 2
        || global.tx_data.tx_modifiable.is_some()
        || global.elements_tx_modifiable_flag.is_some()
        || !global.xpub.is_empty()
        || !global.proprietary.is_empty()
        || !global.unknown.is_empty()
    {
        return Err(Error::UnsupportedGlobal);
    }
    out.u32(global.version)?;
    out.u32(global.tx_data.version)?;
    out.option_u32(
        global
            .tx_data
            .fallback_locktime
            .map(|v| v.to_consensus_u32()),
    )?;
    out.u32(u32::try_from(pset.n_inputs()).map_err(|_| Error::LimitExceeded)?)?;
    out.u32(u32::try_from(pset.n_outputs()).map_err(|_| Error::LimitExceeded)?)?;
    out.u8(0)?; // absent tx-modifiable flag; V1 frozen representation
    out.u8(0)?; // absent Elements tx-modifiable flag
    out.u32(u32::try_from(global.scalars.len()).map_err(|_| Error::LimitExceeded)?)?;
    for scalar in &global.scalars {
        out.fixed(scalar.as_ref())?;
    }
    Ok(())
}

fn project_inputs(
    pset: &PartiallySignedTransaction,
    lbtc: AssetId,
    out: &mut Encoder,
) -> Result<Vec<Generator>, Error> {
    let mut seen = BTreeSet::<(Txid, u32)>::new();
    let secp = Secp256k1::new();
    let mut asset_generators = Vec::with_capacity(pset.inputs().len());
    out.u32(u32::try_from(pset.inputs().len()).map_err(|_| Error::LimitExceeded)?)?;
    for (index, input) in pset.inputs().iter().enumerate() {
        validate_input_fields(input)?;
        let raw_vout = input.previous_output_index;
        if input.previous_txid == Txid::from_byte_array([0; 32])
            || raw_vout == OUTPOINT_COINBASE_INDEX
            || raw_vout & (OUTPOINT_PEGIN_FLAG | OUTPOINT_ISSUANCE_FLAG) != 0
            || input.is_pegin()
            || input.has_issuance()
        {
            return Err(Error::UnsupportedInput);
        }
        if !seen.insert((input.previous_txid, raw_vout)) {
            return Err(Error::InvalidStructure);
        }
        let utxo = input.witness_utxo.as_ref().ok_or(Error::UnsupportedInput)?;
        if utxo.script_pubkey.len() > MAX_SCRIPT_BYTES {
            return Err(Error::LimitExceeded);
        }
        match utxo.asset {
            elements::confidential::Asset::Explicit(asset) if asset == lbtc => {
                if input.asset.is_some() || input.blind_asset_proof.is_some() {
                    return Err(Error::UnsupportedInput);
                }
            }
            elements::confidential::Asset::Confidential(commitment) => {
                let asset = input.asset.ok_or(Error::UnknownAsset)?;
                let proof = input
                    .blind_asset_proof
                    .as_ref()
                    .ok_or(Error::UnknownAsset)?;
                if asset != lbtc || !proof.blind_asset_proof_verify(&secp, asset, commitment) {
                    return Err(Error::UnknownAsset);
                }
            }
            _ => return Err(Error::UnknownAsset),
        }
        let asset_generator = utxo
            .asset
            .into_asset_gen(&secp)
            .ok_or(Error::UnknownAsset)?;
        asset_generators.push(asset_generator);
        match (&utxo.value, &utxo.nonce) {
            (elements::confidential::Value::Explicit(_), elements::confidential::Nonce::Null)
            | (
                elements::confidential::Value::Confidential(_),
                elements::confidential::Nonce::Confidential(_),
            ) => {}
            _ => return Err(Error::UnsupportedInput),
        }
        let range = input.in_utxo_rangeproof.as_ref();
        if matches!(utxo.value, elements::confidential::Value::Explicit(_)) && range.is_some() {
            return Err(Error::UnsupportedInput);
        }
        if matches!(utxo.value, elements::confidential::Value::Confidential(_)) && range.is_none() {
            return Err(Error::UnsupportedInput);
        }
        check_rangeproof(range)?;
        if let elements::confidential::Value::Confidential(value_commitment) = utxo.value {
            let proof = range
                .and_then(elements::confidential::RangeProof::as_ref)
                .ok_or(Error::UnsupportedInput)?;
            proof
                .verify_inclusive(
                    &secp,
                    value_commitment,
                    utxo.script_pubkey.as_bytes(),
                    asset_generator,
                )
                .map_err(|_| Error::UnsupportedInput)?;
        }
        check_surjection(input.blind_asset_proof.as_ref())?;

        out.u32(u32::try_from(index).map_err(|_| Error::LimitExceeded)?)?;
        out.fixed(&input.previous_txid.to_byte_array())?;
        out.u32(raw_vout)?;
        out.option_u32(input.sequence.map(|v| v.to_consensus_u32()))?;
        project_txout(utxo, out)?;
        out.option_bytes(range.map(|p| p.to_vec()).as_deref())?;
        out.option_asset(input.asset)?;
        out.option_bytes(
            input
                .blind_asset_proof
                .as_ref()
                .map(|p| p.to_vec())
                .as_deref(),
        )?;
    }
    Ok(asset_generators)
}

fn validate_input_fields(input: &Input) -> Result<(), Error> {
    let unsupported = input.non_witness_utxo.is_some()
        || !input.partial_sigs.is_empty()
        || input.sighash_type.is_some()
        || input.redeem_script.is_some()
        || input.witness_script.is_some()
        || !input.bip32_derivation.is_empty()
        || input.final_script_sig.is_some()
        || input.final_script_witness.is_some()
        || !input.ripemd160_preimages.is_empty()
        || !input.sha256_preimages.is_empty()
        || !input.hash160_preimages.is_empty()
        || !input.hash256_preimages.is_empty()
        || input.required_time_locktime.is_some()
        || input.required_height_locktime.is_some()
        || input.tap_key_sig.is_some()
        || !input.tap_script_sigs.is_empty()
        || !input.tap_scripts.is_empty()
        || !input.tap_key_origins.is_empty()
        || input.tap_internal_key.is_some()
        || input.tap_merkle_root.is_some()
        || input.issuance_value_amount.is_some()
        || input.issuance_value_comm.is_some()
        || input.issuance_value_rangeproof.is_some()
        || input.issuance_keys_rangeproof.is_some()
        || input.pegin_tx.is_some()
        || input.pegin_txout_proof.is_some()
        || input.pegin_genesis_hash.is_some()
        || input.pegin_claim_script.is_some()
        || input.pegin_value.is_some()
        || input.pegin_witness.is_some()
        || input.issuance_inflation_keys.is_some()
        || input.issuance_inflation_keys_comm.is_some()
        || input.issuance_blinding_nonce.is_some()
        || input.issuance_asset_entropy.is_some()
        || input.in_issuance_blind_value_proof.is_some()
        || input.in_issuance_blind_inflation_keys_proof.is_some()
        || input.amount.is_some()
        || input.blind_value_proof.is_some()
        || input.blinded_issuance.is_some()
        || !input.proprietary.is_empty()
        || !input.unknown.is_empty();
    if unsupported {
        Err(Error::UnsupportedInput)
    } else {
        Ok(())
    }
}

fn project_outputs(
    pset: &PartiallySignedTransaction,
    lbtc: AssetId,
    input_asset_generators: &[Generator],
    out: &mut Encoder,
) -> Result<(), Error> {
    let secp = Secp256k1::new();
    let mut fee_count = 0usize;
    let mut explicit_sum = 0u64;
    out.u32(u32::try_from(pset.outputs().len()).map_err(|_| Error::LimitExceeded)?)?;
    for (index, output) in pset.outputs().iter().enumerate() {
        validate_output_fields(output)?;
        if output.script_pubkey.len() > MAX_SCRIPT_BYTES {
            return Err(Error::LimitExceeded);
        }
        check_rangeproof(output.value_rangeproof.as_ref())?;
        check_rangeproof(output.blind_value_proof.as_ref())?;
        check_surjection(output.asset_surjection_proof.as_ref())?;
        check_surjection(output.blind_asset_proof.as_ref())?;

        let is_fee = output.script_pubkey.is_empty()
            && output.asset == Some(lbtc)
            && output.asset_comm.is_none()
            && output.amount.is_some()
            && output.amount_comm.is_none()
            && output.blinding_key.is_none()
            && output.ecdh_pubkey.is_none()
            && output.blinder_index.is_none()
            && output.value_rangeproof.is_none()
            && output.asset_surjection_proof.is_none()
            && output.blind_value_proof.is_none()
            && output.blind_asset_proof.is_none();
        let role = if is_fee {
            fee_count += 1;
            let value = output.amount.ok_or(Error::UnsupportedOutput)?;
            if value == 0 {
                return Err(Error::UnsupportedOutput);
            }
            explicit_sum = explicit_sum
                .checked_add(value)
                .ok_or(Error::InvalidStructure)?;
            if explicit_sum > MAX_LBTC_ATOMIC_UNITS {
                return Err(Error::InvalidStructure);
            }
            1u8
        } else {
            let blinder = output.blinder_index.ok_or(Error::UnsupportedOutput)?;
            if usize::try_from(blinder).map_err(|_| Error::InvalidStructure)? >= pset.inputs().len()
            {
                return Err(Error::InvalidStructure);
            }
            let preblind = output.asset == Some(lbtc)
                && output.asset_comm.is_none()
                && output.amount.is_some()
                && output.amount_comm.is_none()
                && output.blinding_key.is_some()
                && output.ecdh_pubkey.is_none()
                && output.value_rangeproof.is_none()
                && output.asset_surjection_proof.is_none()
                && output.blind_value_proof.is_none()
                && output.blind_asset_proof.is_none();
            let fully_blinded = output.asset.is_some()
                && output.asset_comm.is_some()
                && output.amount.is_some()
                && output.amount_comm.is_some()
                && output.blinding_key.is_some()
                && output.ecdh_pubkey.is_some()
                && output.value_rangeproof.is_some()
                && output.asset_surjection_proof.is_some()
                && output.blind_value_proof.is_some()
                && output.blind_asset_proof.is_some();
            if preblind {
                let value = output.amount.ok_or(Error::UnsupportedOutput)?;
                if value == 0 {
                    return Err(Error::UnsupportedOutput);
                }
                explicit_sum = explicit_sum
                    .checked_add(value)
                    .ok_or(Error::InvalidStructure)?;
                if explicit_sum > MAX_LBTC_ATOMIC_UNITS {
                    return Err(Error::InvalidStructure);
                }
                2u8
            } else if fully_blinded {
                let asset = output.asset.ok_or(Error::UnknownAsset)?;
                let commitment = output.asset_comm.ok_or(Error::UnknownAsset)?;
                let proof = output
                    .blind_asset_proof
                    .as_ref()
                    .ok_or(Error::UnknownAsset)?;
                let amount = output.amount.ok_or(Error::UnsupportedOutput)?;
                let amount_commitment = output.amount_comm.ok_or(Error::UnsupportedOutput)?;
                let value_proof = output
                    .blind_value_proof
                    .as_ref()
                    .ok_or(Error::UnsupportedOutput)?;
                let transaction_rangeproof = output
                    .value_rangeproof
                    .as_ref()
                    .and_then(elements::confidential::RangeProof::as_ref)
                    .ok_or(Error::UnsupportedOutput)?;
                let transaction_surjection_proof = output
                    .asset_surjection_proof
                    .as_ref()
                    .and_then(elements::confidential::SurjectionProof::as_ref)
                    .ok_or(Error::UnsupportedOutput)?;
                if asset != lbtc
                    || !proof.blind_asset_proof_verify(&secp, asset, commitment)
                    || !value_proof.blind_value_proof_verify(
                        &secp,
                        amount,
                        commitment,
                        amount_commitment,
                    )
                    || transaction_rangeproof
                        .verify_inclusive(
                            &secp,
                            amount_commitment,
                            output.script_pubkey.as_bytes(),
                            commitment,
                        )
                        .is_err()
                    || !transaction_surjection_proof.verify(
                        &secp,
                        commitment,
                        input_asset_generators,
                    )
                {
                    return Err(Error::UnknownAsset);
                }
                3u8
            } else {
                return Err(Error::UnsupportedOutput);
            }
        };

        out.u32(u32::try_from(index).map_err(|_| Error::LimitExceeded)?)?;
        out.u8(role)?;
        out.bytes(output.script_pubkey.as_bytes())?;
        out.option_asset(output.asset)?;
        match output.asset_comm {
            None => out.u8(0)?,
            Some(v) => {
                out.u8(1)?;
                out.bytes(&v.serialize())?;
            }
        }
        out.option_u64(output.amount)?;
        match output.amount_comm {
            None => out.u8(0)?,
            Some(v) => {
                out.u8(1)?;
                out.bytes(&v.serialize())?;
            }
        }
        out.option_bytes(output.blinding_key.map(|v| v.to_bytes()).as_deref())?;
        out.option_bytes(output.ecdh_pubkey.map(|v| v.to_bytes()).as_deref())?;
        out.option_u32(output.blinder_index)?;
        out.option_bytes(
            output
                .value_rangeproof
                .as_ref()
                .map(|p| p.to_vec())
                .as_deref(),
        )?;
        out.option_bytes(
            output
                .asset_surjection_proof
                .as_ref()
                .map(|p| p.to_vec())
                .as_deref(),
        )?;
        out.option_bytes(
            output
                .blind_value_proof
                .as_ref()
                .map(|p| p.to_vec())
                .as_deref(),
        )?;
        out.option_bytes(
            output
                .blind_asset_proof
                .as_ref()
                .map(|p| p.to_vec())
                .as_deref(),
        )?;
    }
    if fee_count != 1 {
        return Err(Error::InvalidStructure);
    }
    Ok(())
}

fn validate_output_fields(output: &Output) -> Result<(), Error> {
    if output.redeem_script.is_some()
        || output.witness_script.is_some()
        || !output.bip32_derivation.is_empty()
        || output.tap_internal_key.is_some()
        || output.tap_tree.is_some()
        || !output.tap_key_origins.is_empty()
        || !output.proprietary.is_empty()
        || !output.unknown.is_empty()
    {
        Err(Error::UnsupportedOutput)
    } else {
        Ok(())
    }
}

fn project_txout(utxo: &elements::TxOut, out: &mut Encoder) -> Result<(), Error> {
    match utxo.asset {
        elements::confidential::Asset::Null => out.u8(0)?,
        elements::confidential::Asset::Explicit(asset) => {
            out.u8(1)?;
            out.fixed(&asset.to_byte_array())?;
        }
        elements::confidential::Asset::Confidential(value) => {
            out.u8(2)?;
            out.fixed(&value.serialize())?;
        }
    }
    match utxo.value {
        elements::confidential::Value::Null => out.u8(0)?,
        elements::confidential::Value::Explicit(value) => {
            out.u8(1)?;
            out.u64(value)?;
        }
        elements::confidential::Value::Confidential(value) => {
            out.u8(2)?;
            out.fixed(&value.serialize())?;
        }
    }
    match utxo.nonce {
        elements::confidential::Nonce::Null => out.u8(0)?,
        elements::confidential::Nonce::Explicit(value) => {
            out.u8(1)?;
            out.fixed(&value)?;
        }
        elements::confidential::Nonce::Confidential(value) => {
            out.u8(2)?;
            out.fixed(&value.serialize())?;
        }
    }
    out.bytes(utxo.script_pubkey.as_bytes())?;
    let surjection = utxo.witness.surjection_proof.to_vec();
    let range = utxo.witness.rangeproof.to_vec();
    if surjection.len() > MAX_SURJECTION_PROOF_BYTES || range.len() > MAX_RANGEPROOF_BYTES {
        return Err(Error::LimitExceeded);
    }
    out.bytes(&surjection)?;
    out.bytes(&range)?;
    Ok(())
}

fn check_rangeproof(proof: Option<&elements::confidential::RangeProof>) -> Result<(), Error> {
    if proof.is_some_and(|p| p.len() > MAX_RANGEPROOF_BYTES) {
        Err(Error::LimitExceeded)
    } else {
        Ok(())
    }
}
fn check_surjection(proof: Option<&elements::confidential::SurjectionProof>) -> Result<(), Error> {
    if proof.is_some_and(|p| p.len() > MAX_SURJECTION_PROOF_BYTES) {
        Err(Error::LimitExceeded)
    } else {
        Ok(())
    }
}
fn push_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(
        &u32::try_from(bytes.len())
            .expect("bounded context length fits u32")
            .to_be_bytes(),
    );
    out.extend_from_slice(bytes);
}

struct Encoder {
    bytes: Vec<u8>,
    limit: usize,
}
impl Encoder {
    fn new(limit: usize) -> Self {
        Self {
            bytes: Vec::new(),
            limit,
        }
    }
    fn reserve(&self, n: usize) -> Result<(), Error> {
        if self
            .bytes
            .len()
            .checked_add(n)
            .is_none_or(|v| v > self.limit)
        {
            Err(Error::LimitExceeded)
        } else {
            Ok(())
        }
    }
    fn fixed(&mut self, bytes: &[u8]) -> Result<(), Error> {
        self.reserve(bytes.len())?;
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }
    fn u8(&mut self, value: u8) -> Result<(), Error> {
        self.fixed(&[value])
    }
    fn u32(&mut self, value: u32) -> Result<(), Error> {
        self.fixed(&value.to_be_bytes())
    }
    fn u64(&mut self, value: u64) -> Result<(), Error> {
        self.fixed(&value.to_be_bytes())
    }
    fn bytes(&mut self, bytes: &[u8]) -> Result<(), Error> {
        self.u32(u32::try_from(bytes.len()).map_err(|_| Error::LimitExceeded)?)?;
        self.fixed(bytes)
    }
    fn option_u32(&mut self, value: Option<u32>) -> Result<(), Error> {
        match value {
            None => self.u8(0),
            Some(v) => {
                self.u8(1)?;
                self.u32(v)
            }
        }
    }
    fn option_u64(&mut self, value: Option<u64>) -> Result<(), Error> {
        match value {
            None => self.u8(0),
            Some(v) => {
                self.u8(1)?;
                self.u64(v)
            }
        }
    }
    fn option_bytes(&mut self, value: Option<&[u8]>) -> Result<(), Error> {
        match value {
            None => self.u8(0),
            Some(v) => {
                self.u8(1)?;
                self.bytes(v)
            }
        }
    }
    fn option_asset(&mut self, value: Option<AssetId>) -> Result<(), Error> {
        match value {
            None => self.u8(0),
            Some(v) => {
                self.u8(1)?;
                self.fixed(&v.to_byte_array())
            }
        }
    }
    fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

#[cfg(test)]
mod tests;
