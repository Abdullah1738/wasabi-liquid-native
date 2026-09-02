#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Role-typed two-participant collaborative PSET blinding state machine.
//!
//! Participant A blinds its outputs as the non-last blinder, the PSET crosses the
//! trust boundary only as serialized bytes with the pending balancing scalars in
//! `global.scalars`, and participant B decodes those bytes and blinds last,
//! clearing the scalars. The final blinded PSET is verified for value balance and
//! is accepted by the canonical PSET-state projection, while the mid-lifecycle
//! scalar-bearing state is rejected as non-signable. This crate does not
//! coordinate a round, move bytes over a network, sign, or manage keys.

use core::fmt;
use std::collections::{BTreeSet, HashMap};

use elements::{
    TxOut, Txid,
    confidential::{Asset, AssetBlindingFactor, Nonce, Value},
    encode,
    pset::PartiallySignedTransaction,
    secp256k1_zkp::{
        All, Secp256k1,
        rand::{CryptoRng, RngCore},
    },
};
use wasabi_liquid_native_coinjoin_pset_state::{
    CanonicalState, CanonicalStateContext, MAX_INPUT_COUNT, MAX_LBTC_ATOMIC_UNITS,
    MAX_OUTPUT_COUNT, MAX_SCALAR_COUNT, MAX_SCRIPT_BYTES, canonicalize_pset_state,
};

/// Maximum serialized PSET bytes accepted at either blinding handoff.
pub const MAX_BLINDING_PSET_BYTES: usize = 1_048_576;

const OUTPOINT_PEGIN_FLAG: u32 = 1 << 30;
const OUTPOINT_ISSUANCE_FLAG: u32 = 1 << 31;
const OUTPOINT_COINBASE_INDEX: u32 = u32::MAX;

/// Privacy-redacted error categories for the collaborative blinding lifecycle.
///
/// Wrapped fork errors never contribute inner detail to `Display`, so secret
/// material (blinding factors, values, secrets) cannot leak through messages.
#[derive(Copy, Clone, PartialEq, Eq)]
pub enum Error {
    /// The supplied unblinded PSET or secrets violate this slice's shape policy.
    UnblindedShapeInvalid,
    /// The fork's non-last blinding call rejected the PSET.
    BlindNonLastFailed,
    /// The fork's last blinding call rejected the intermediate PSET, including
    /// every input-domain or witness-UTXO mutation surfaced by the fork's
    /// surjection-domain re-verification.
    BlindLastFailed,
    /// `global.scalars` was not empty at a lifecycle point that requires it.
    ScalarsNotCleared,
    /// `extract_tx` + `verify_tx_amt_proofs` rejected the final blinded PSET.
    BalanceVerificationFailed,
    /// A post-handoff mutation was detected before the fork call ran.
    DomainMutationRejected,
    /// The canonical PSET-state projection rejected the final blinded PSET.
    CanonicalStateRejected,
    /// Serialized handoff bytes did not decode as one canonical PSET v2.
    Deserialization,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::UnblindedShapeInvalid => "unblinded PSET shape rejected",
            Self::BlindNonLastFailed => "non-last blinding rejected",
            Self::BlindLastFailed => "last blinding rejected",
            Self::ScalarsNotCleared => "blinding scalars not cleared",
            Self::BalanceVerificationFailed => "final amount balance verification rejected",
            Self::DomainMutationRejected => "input domain or witness UTXO mutation rejected",
            Self::CanonicalStateRejected => "canonical PSET state rejected",
            Self::Deserialization => "serialized PSET handoff rejected",
        })
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}
impl std::error::Error for Error {}

/// Participant role in the bounded two-party collaborative blinding lifecycle.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Role {
    /// The participant that blinds non-last and transfers first.
    A,
    /// The participant that blinds last and clears the scalars.
    B,
}

/// One validated unblinded CoinJoin PSET frozen for collaborative blinding.
///
/// Construction enforces the L-BTC-only sponsor-free shape policy: bounded
/// counts, explicit L-BTC witness UTXOs, exactly one explicit fee output, and
/// every other output carrying a blinding key and a valid `blinder_index`.
pub struct UnblindedCoinJoin {
    pset: PartiallySignedTransaction,
    role_outputs: [Vec<usize>; 2],
    confidential_outputs: Vec<usize>,
    lbtc_asset: elements::AssetId,
}

/// Serializes, re-parses, and validates one raw canonical PSET v2 handoff.
fn decode_handoff(raw: &[u8]) -> Result<PartiallySignedTransaction, Error> {
    if raw.is_empty() || raw.len() > MAX_BLINDING_PSET_BYTES {
        return Err(Error::Deserialization);
    }
    let pset: PartiallySignedTransaction =
        encode::deserialize(raw).map_err(|_| Error::Deserialization)?;
    if encode::serialize(&pset) != raw {
        return Err(Error::Deserialization);
    }
    Ok(pset)
}

impl UnblindedCoinJoin {
    /// Validates and freezes one fully-constructed unblinded PSET.
    ///
    /// `role_of_output` maps each non-fee output index to the participant role
    /// that blinds it; it must cover every non-fee output exactly once.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnblindedShapeInvalid`] for any shape-policy violation.
    /// No blinding call runs on a rejected PSET.
    pub fn new(
        pset: PartiallySignedTransaction,
        role_of_output: &HashMap<usize, Role>,
        lbtc_asset: elements::AssetId,
    ) -> Result<Self, Error> {
        validate_unblinded_shape(&pset, role_of_output, lbtc_asset)?;
        let mut role_outputs: [Vec<usize>; 2] = [Vec::new(), Vec::new()];
        let mut confidential_outputs: Vec<usize> = role_of_output.keys().copied().collect();
        confidential_outputs.sort_unstable();
        for (&index, role) in role_of_output {
            role_outputs[match role {
                Role::A => 0,
                Role::B => 1,
            }]
            .push(index);
        }
        role_outputs[0].sort_unstable();
        role_outputs[1].sort_unstable();
        Ok(Self {
            pset,
            role_outputs,
            confidential_outputs,
            lbtc_asset,
        })
    }

    /// Borrows the frozen unblinded PSET.
    #[must_use]
    pub fn pset(&self) -> &PartiallySignedTransaction {
        &self.pset
    }

    /// Returns the context L-BTC asset this state was validated against.
    #[must_use]
    pub const fn lbtc_asset(&self) -> elements::AssetId {
        self.lbtc_asset
    }

    /// Returns the ascending non-fee output indices blinded by `role`.
    #[must_use]
    pub fn outputs_of(&self, role: Role) -> &[usize] {
        &self.role_outputs[match role {
            Role::A => 0,
            Role::B => 1,
        }]
    }

    /// Returns the ascending output indices expected to be confidential.
    #[must_use]
    pub fn expected_confidential_outputs(&self) -> &[usize] {
        &self.confidential_outputs
    }

    /// Witness UTXOs in PSET input order; every input has one after validation.
    #[must_use]
    pub fn witness_utxos(&self) -> Vec<TxOut> {
        self.pset
            .inputs()
            .iter()
            .map(|input| {
                input
                    .witness_utxo
                    .clone()
                    .expect("validated unblinded shape requires witness UTXOs")
            })
            .collect()
    }
}

fn validate_unblinded_shape(
    pset: &PartiallySignedTransaction,
    role_of_output: &HashMap<usize, Role>,
    lbtc_asset: elements::AssetId,
) -> Result<(), Error> {
    let inputs = pset.inputs();
    let outputs = pset.outputs();
    if inputs.is_empty()
        || outputs.is_empty()
        || inputs.len() > MAX_INPUT_COUNT
        || outputs.len() > MAX_OUTPUT_COUNT
        || pset.n_inputs() != inputs.len()
        || pset.n_outputs() != outputs.len()
        || !pset.global.scalars.is_empty()
    {
        return Err(Error::UnblindedShapeInvalid);
    }
    let global = &pset.global;
    if global.version != 2
        || global.tx_data.version != 2
        || global.tx_data.tx_modifiable.is_some()
        || global.elements_tx_modifiable_flag.is_some()
        || !global.xpub.is_empty()
        || !global.proprietary.is_empty()
        || !global.unknown.is_empty()
    {
        return Err(Error::UnblindedShapeInvalid);
    }

    let mut seen_outpoints = BTreeSet::<(Txid, u32)>::new();
    for input in inputs {
        let raw_vout = input.previous_output_index;
        if input.previous_txid == Txid::from_byte_array([0; 32])
            || raw_vout == OUTPOINT_COINBASE_INDEX
            || raw_vout & (OUTPOINT_PEGIN_FLAG | OUTPOINT_ISSUANCE_FLAG) != 0
            || input.is_pegin()
            || input.has_issuance()
            || !seen_outpoints.insert((input.previous_txid, raw_vout))
        {
            return Err(Error::UnblindedShapeInvalid);
        }
        let utxo = input
            .witness_utxo
            .as_ref()
            .ok_or(Error::UnblindedShapeInvalid)?;
        if utxo.script_pubkey.len() > MAX_SCRIPT_BYTES
            || utxo.asset != Asset::Explicit(lbtc_asset)
            || !matches!(utxo.value, Value::Explicit(_))
            || utxo.nonce != Nonce::Null
            || input.asset.is_some()
            || input.blind_asset_proof.is_some()
            || input.in_utxo_rangeproof.is_some()
        {
            return Err(Error::UnblindedShapeInvalid);
        }
    }

    let mut fee_count = 0usize;
    let mut explicit_sum = 0u64;
    for (index, output) in outputs.iter().enumerate() {
        if output.script_pubkey.len() > MAX_SCRIPT_BYTES {
            return Err(Error::UnblindedShapeInvalid);
        }
        let is_fee = output.script_pubkey.is_empty()
            && output.blinding_key.is_none()
            && output.blinder_index.is_none();
        if is_fee {
            fee_count += 1;
            if role_of_output.contains_key(&index)
                || output.asset != Some(lbtc_asset)
                || output.asset_comm.is_some()
                || output.amount_comm.is_some()
                || output.ecdh_pubkey.is_some()
                || output.value_rangeproof.is_some()
                || output.asset_surjection_proof.is_some()
                || output.blind_value_proof.is_some()
                || output.blind_asset_proof.is_some()
            {
                return Err(Error::UnblindedShapeInvalid);
            }
            let fee = output.amount.ok_or(Error::UnblindedShapeInvalid)?;
            if fee == 0 {
                return Err(Error::UnblindedShapeInvalid);
            }
        } else {
            if !role_of_output.contains_key(&index) {
                return Err(Error::UnblindedShapeInvalid);
            }
            let blinder = output.blinder_index.ok_or(Error::UnblindedShapeInvalid)?;
            if usize::try_from(blinder).map_err(|_| Error::UnblindedShapeInvalid)? >= inputs.len()
                || output.asset != Some(lbtc_asset)
                || output.blinding_key.is_none()
                || output.amount.is_none()
                || output.amount_comm.is_some()
                || output.asset_comm.is_some()
                || output.ecdh_pubkey.is_some()
                || output.value_rangeproof.is_some()
                || output.asset_surjection_proof.is_some()
                || output.blind_value_proof.is_some()
                || output.blind_asset_proof.is_some()
            {
                return Err(Error::UnblindedShapeInvalid);
            }
        }
        let value = output.amount.ok_or(Error::UnblindedShapeInvalid)?;
        explicit_sum = explicit_sum
            .checked_add(value)
            .ok_or(Error::UnblindedShapeInvalid)?;
        if explicit_sum > MAX_LBTC_ATOMIC_UNITS {
            return Err(Error::UnblindedShapeInvalid);
        }
    }
    if fee_count != 1 || role_of_output.len() != outputs.len() - 1 {
        return Err(Error::UnblindedShapeInvalid);
    }
    Ok(())
}

fn validate_input_secrets(
    pset: &PartiallySignedTransaction,
    input_secrets: &HashMap<usize, elements::TxOutSecrets>,
    lbtc_asset: elements::AssetId,
) -> Result<(), Error> {
    let secp = Secp256k1::new();
    for (index, secrets) in input_secrets {
        let input = pset
            .inputs()
            .get(*index)
            .ok_or(Error::UnblindedShapeInvalid)?;
        let utxo = input
            .witness_utxo
            .as_ref()
            .ok_or(Error::UnblindedShapeInvalid)?;
        if utxo.script_pubkey.len() > MAX_SCRIPT_BYTES || secrets.asset != lbtc_asset {
            return Err(Error::UnblindedShapeInvalid);
        }
        let expected_asset = if secrets.asset_bf == AssetBlindingFactor::zero() {
            Asset::Explicit(lbtc_asset)
        } else {
            Asset::new_confidential(&secp, secrets.asset, secrets.asset_bf)
        };
        if utxo.asset != expected_asset {
            return Err(Error::UnblindedShapeInvalid);
        }
        match utxo.value {
            Value::Explicit(value) => {
                if value != secrets.value {
                    return Err(Error::UnblindedShapeInvalid);
                }
            }
            Value::Confidential(commitment) => {
                let generator = match utxo.asset {
                    Asset::Confidential(generator) => generator,
                    _ => return Err(Error::UnblindedShapeInvalid),
                };
                if commitment
                    != elements::secp256k1_zkp::PedersenCommitment::new(
                        &secp,
                        secrets.value,
                        secrets.value_bf.into_inner(),
                        generator,
                    )
                {
                    return Err(Error::UnblindedShapeInvalid);
                }
            }
            Value::Null => return Err(Error::UnblindedShapeInvalid),
        }
    }
    Ok(())
}

fn decode_intermediate(
    bytes: &[u8],
    state: &UnblindedCoinJoin,
) -> Result<PartiallySignedTransaction, Error> {
    let pset = decode_handoff(bytes)?;
    let expected_inputs = state.pset.inputs().len();
    let expected_outputs = state.pset.outputs().len();
    if pset.inputs().len() != expected_inputs
        || pset.outputs().len() != expected_outputs
        || pset.n_inputs() != expected_inputs
        || pset.n_outputs() != expected_outputs
    {
        return Err(Error::DomainMutationRejected);
    }
    // Identity binding: the intermediate must spend exactly the frozen input
    // set, in order, with byte-identical witness UTXOs. A same-count outpoint
    // swap or witness-UTXO byte drift is a domain mutation the wrapper itself
    // guarantees, independent of the fork's internal re-verification.
    for (index, input) in pset.inputs().iter().enumerate() {
        let frozen = &state.pset.inputs()[index];
        if input.previous_txid != frozen.previous_txid
            || input.previous_output_index != frozen.previous_output_index
            || input.witness_utxo.as_ref() != frozen.witness_utxo.as_ref()
        {
            return Err(Error::DomainMutationRejected);
        }
    }
    if pset.global.scalars.is_empty() || pset.global.scalars.len() > MAX_SCALAR_COUNT {
        return Err(Error::ScalarsNotCleared);
    }
    Ok(pset)
}

/// Runs participant A: blinds the role-A outputs as the non-last blinder.
///
/// Wraps the pinned fork's `blind_non_last_with_all_surjection_inputs`; every
/// current surjection-domain entry is selected in each transaction-output
/// surjection proof. The returned bytes are the only handoff representation:
/// they carry the post-blinding PSET with non-empty `global.scalars`, never the
/// in-memory object.
///
/// # Errors
///
/// Returns [`Error::UnblindedShapeInvalid`] for secret/shape mismatches,
/// [`Error::BlindNonLastFailed`] when the fork rejects the PSET, and
/// [`Error::ScalarsNotCleared`] when no pending scalar remains (A blinds
/// nothing).
pub fn participant_a_blind_non_last<R: RngCore + CryptoRng>(
    state: &UnblindedCoinJoin,
    rng: &mut R,
    input_secrets: &HashMap<usize, elements::TxOutSecrets>,
) -> Result<Vec<u8>, Error> {
    if state.outputs_of(Role::A).is_empty() {
        return Err(Error::UnblindedShapeInvalid);
    }
    validate_input_secrets(&state.pset, input_secrets, state.lbtc_asset)?;
    let secp = Secp256k1::new();
    let mut pset = state.pset.clone();
    pset.blind_non_last_with_all_surjection_inputs(rng, &secp, input_secrets)
        .map_err(|_| Error::BlindNonLastFailed)?;
    if pset.global.scalars.is_empty() || pset.global.scalars.len() > MAX_SCALAR_COUNT {
        return Err(Error::ScalarsNotCleared);
    }
    Ok(encode::serialize(&pset))
}

/// Runs participant B: decodes the intermediate bytes and blinds last.
///
/// Wraps the pinned fork's `blind_last_with_all_surjection_inputs`, which
/// internally re-verifies every surjection proof against the exact current
/// ordered input domain before committing any change; this surfaces (rather
/// than re-implements) the fork's `verify_all_surjection_proofs_use_all_inputs`
/// enforcement. Any post-handoff input-domain or witness-UTXO mutation is
/// rejected by that fork verification and mapped to [`Error::BlindLastFailed`].
/// On success `global.scalars` is asserted empty.
///
/// # Errors
///
/// Returns [`Error::Deserialization`] for non-canonical bytes,
/// [`Error::DomainMutationRejected`] for input/output-count drift,
/// [`Error::BlindLastFailed`] for fork rejections (including domain and
/// witness-UTXO mutations), and [`Error::ScalarsNotCleared`] if scalars remain.
pub fn participant_b_blind_last<R: RngCore + CryptoRng>(
    state: &UnblindedCoinJoin,
    intermediate_bytes: &[u8],
    rng: &mut R,
    input_secrets: &HashMap<usize, elements::TxOutSecrets>,
) -> Result<PartiallySignedTransaction, Error> {
    let mut pset = decode_intermediate(intermediate_bytes, state)?;
    validate_input_secrets(&pset, input_secrets, state.lbtc_asset)
        .map_err(|_| Error::DomainMutationRejected)?;
    let secp = Secp256k1::new();
    pset.blind_last_with_all_surjection_inputs(
        rng,
        &secp,
        input_secrets,
        state.expected_confidential_outputs(),
    )
    .map_err(|_| Error::BlindLastFailed)?;
    if !pset.global.scalars.is_empty() {
        return Err(Error::ScalarsNotCleared);
    }
    Ok(pset)
}

/// Proves the completed blinding balances against the real witness UTXOs.
///
/// Runs `extract_tx()` + `verify_tx_amt_proofs(secp, witness_utxos)` against
/// the witness UTXOs frozen into `state` (the UTXOs the inputs actually spend,
/// not anything re-read from the blinded PSET).
///
/// # Errors
///
/// Returns [`Error::BalanceVerificationFailed`] when extraction or the amount
/// proof verification rejects, and [`Error::ScalarsNotCleared`] when residual
/// scalars remain.
pub fn verify_final(
    state: &UnblindedCoinJoin,
    final_pset: &PartiallySignedTransaction,
) -> Result<(), Error> {
    if !final_pset.global.scalars.is_empty() {
        return Err(Error::ScalarsNotCleared);
    }
    let secp: Secp256k1<All> = Secp256k1::new();
    let transaction = final_pset
        .extract_tx()
        .map_err(|_| Error::BalanceVerificationFailed)?;
    transaction
        .verify_tx_amt_proofs(&secp, &state.witness_utxos())
        .map_err(|_| Error::BalanceVerificationFailed)
}

/// Runs the canonical PSET-state projection on the final blinded PSET.
///
/// The fully-blinded path must be accepted; the caller supplies the immutable
/// V1 context. A scalar-bearing mid-lifecycle state is rejected here only
/// because it cannot match the fully-blinded projection — the canonical crate
/// itself remains the authority.
///
/// # Errors
///
/// Returns [`Error::CanonicalStateRejected`] when the canonical validator
/// rejects the final blinded PSET, and [`Error::Deserialization`] when the
/// serialization round-trip is not exact.
pub fn canonical_accept_final(
    final_pset: &PartiallySignedTransaction,
    context: &CanonicalStateContext<'_>,
) -> Result<CanonicalState, Error> {
    let raw = encode::serialize(final_pset);
    let reparsed: PartiallySignedTransaction =
        encode::deserialize(&raw).map_err(|_| Error::Deserialization)?;
    if encode::serialize(&reparsed) != raw {
        return Err(Error::Deserialization);
    }
    canonicalize_pset_state(&raw, context).map_err(|_| Error::CanonicalStateRejected)
}

/// Proves a scalar-bearing mid-lifecycle state is non-canonical as a FINAL
/// state: residual `global.scalars` mark the non-signable pre-balance point,
/// and any such state whose outputs all claim full blinding cannot pass the
/// canonical validator's cryptographic output verification (a mid-lifecycle
/// surjection proof can never verify against the full ordered input domain,
/// because the last blinder has not yet produced its proofs).
///
/// Returns `Ok(())` only when the canonical projection rejects the bytes.
///
/// # Errors
///
/// Returns [`Error::ScalarsNotCleared`] when the handoff carries no pending
/// scalars, and [`Error::CanonicalStateRejected`] when the canonical validator
/// unexpectedly accepts the scalar-bearing state as final.
pub fn canonical_reject_partial(
    intermediate_bytes: &[u8],
    context: &CanonicalStateContext<'_>,
) -> Result<(), Error> {
    let pset = decode_handoff(intermediate_bytes)?;
    if pset.global.scalars.is_empty() {
        return Err(Error::ScalarsNotCleared);
    }
    match canonicalize_pset_state(intermediate_bytes, context) {
        Err(_) => Ok(()),
        Ok(_) => Err(Error::CanonicalStateRejected),
    }
}

/// Serializes one PSET for the inter-participant handoff.
#[must_use]
pub fn serialize_handoff(pset: &PartiallySignedTransaction) -> Vec<u8> {
    encode::serialize(pset)
}

/// Parses one serialized handoff back into a PSET without validation beyond
/// canonical encoding (used by fixtures to prove byte-exact scalar survival).
///
/// # Errors
///
/// Returns [`Error::Deserialization`] for non-canonical or oversized bytes.
pub fn deserialize_handoff(raw: &[u8]) -> Result<PartiallySignedTransaction, Error> {
    decode_handoff(raw)
}

#[cfg(test)]
mod tests;
