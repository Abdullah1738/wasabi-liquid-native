#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Registration-boundary binding of WabiSabi/Liquid value-equality proofs.
//!
//! This crate binds the generalized-Schnorr commitment-equality proof of
//! `credential-commitment-equality` to ONE exact input or output registration:
//! one round context, one participant role and contribution ordinal, one
//! registration kind, one canonical PSET element index, and the canonical PSET
//! state digest of the exact revision the registration binds to. The encoded
//! [`RegistrationContext`] is the `context` argument passed to `prove` and
//! `verify`, so a proof produced for one registration cannot be replayed for
//! any other round, revision, element, or kind.
//!
//! The statement adapters are the ONLY way to build a statement here: the
//! Liquid side of every statement is read directly from the referenced PSET
//! element (a confidential witness UTXO for input registrations, a fully
//! blinded output for output registrations), so byte drift between statement
//! and PSET element is impossible by construction. For output registrations
//! the context additionally commits the output's exact `value_rangeproof` and
//! `asset_surjection_proof` bytes, so an equality proof cannot be replayed
//! against a different proof pair carrying the same commitments.
//!
//! This is a pure binding primitive. It contains no credential issuance
//! protocol, no coordinator, no network, no signing, no custody, no blinding,
//! no round engine, and no FFI. The caller supplies the PSET, the canonical
//! state digest (from `coinjoin-pset-state`), all witnesses, and all entropy.

use core::fmt;

use elements::{
    TxOut,
    confidential::{Asset, Value},
    pset::PartiallySignedTransaction,
    secp256k1_zkp::{All, Secp256k1},
};
use wasabi_liquid_native_coinjoin_pset_state::{
    MAX_NETWORK_IDENTITY_BYTES, MAX_ROUND_ID_BYTES, ParticipantRole, Phase, ProfileVersion,
};
use wasabi_liquid_native_credential_commitment_equality::{
    self as equality, EqualityProof, EqualityStatement, EqualityWitness,
};

/// Registration proof kinds bound by this profile.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum RegistrationKind {
    /// Binds a WabiSabi amount commitment to the confidential value commitment
    /// of one PSET input's witness UTXO.
    InputRegistration = 1,
    /// Binds a WabiSabi amount commitment to one fully blinded PSET output's
    /// amount commitment and exact proof bytes.
    OutputRegistration = 2,
}

/// Immutable registration context; its deterministic byte encoding is the
/// replay-binding `context` mixed into the equality proof challenge transcript
/// and the prover's synthetic nonce derivation.
///
/// Every field except `output_proof_binding` mirrors the canonical-state V1
/// context conventions (length-prefixed variable fields, fixed-width big-endian
/// scalars, single-byte enums). `pset_state_digest` MUST be the
/// [`wasabi_liquid_native_coinjoin_pset_state::CanonicalState::digest`] bytes
/// of the exact PSET revision the registration binds to; the caller obtains it
/// by running `canonicalize_pset_state` on that revision.
pub struct RegistrationContext<'a> {
    /// Explicit profile version; only V1 is accepted.
    pub profile: ProfileVersion,
    /// Bounded Elements network/profile identity bytes.
    pub network_identity: &'a [u8],
    /// Elements genesis block hash bytes.
    pub genesis_hash: [u8; 32],
    /// Canonical L-BTC asset identity.
    pub lbtc_asset: elements::AssetId,
    /// Bounded round/domain identifier.
    pub round_id: &'a [u8],
    /// Current protocol phase.
    pub phase: Phase,
    /// Registering participant role.
    pub participant_role: ParticipantRole,
    /// Monotonic participant/contribution ordinal supplied by the caller.
    pub contribution_ordinal: u32,
    /// Whether this registration binds an input or an output.
    pub kind: RegistrationKind,
    /// Canonical element index: the PSET input index for input registrations,
    /// the PSET output index for output registrations.
    pub element_index: u32,
    /// Canonical PSET state digest of the exact revision being bound.
    pub pset_state_digest: [u8; 32],
    /// Exact output proof bytes committed by output registrations; MUST be
    /// `None` for input registrations and `Some` for output registrations.
    pub output_proof_binding: Option<OutputProofBinding<'a>>,
}

/// Exact proof bytes of the bound blinded output, committed by output
/// registrations so an equality proof cannot be replayed against a different
/// proof pair carrying the same commitments.
#[derive(Copy, Clone)]
pub struct OutputProofBinding<'a> {
    /// The output's `value_rangeproof` bytes.
    pub value_rangeproof: &'a [u8],
    /// The output's `asset_surjection_proof` bytes.
    pub asset_surjection_proof: &'a [u8],
}

/// Privacy-redacted rejection categories. Statement bytes, witness material,
/// and proof bytes are never included.
#[derive(Copy, Clone, PartialEq, Eq)]
pub enum Error {
    /// A documented public size/count bound was exceeded.
    LimitExceeded,
    /// The immutable registration context is invalid for this profile.
    InvalidContext,
    /// A proof encoding had the wrong length, trailing bytes, or non-canonical
    /// scalars.
    InvalidProofEncoding,
    /// A statement point encoding was invalid or carried the wrong prefix.
    InvalidStatementEncoding,
    /// The referenced PSET element is missing or not in the required lifecycle
    /// shape (explicit witness value, missing commitment, missing proofs).
    ElementShape,
    /// Equality proof generation rejected the witness or entropy.
    ProveRejected,
    /// Equality proof verification failed for the exact statement and context.
    VerificationFailed,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::LimitExceeded => "registration limit exceeded",
            Self::InvalidContext => "registration context rejected",
            Self::InvalidProofEncoding => "proof encoding rejected",
            Self::InvalidStatementEncoding => "statement encoding rejected",
            Self::ElementShape => "referenced PSET element shape rejected",
            Self::ProveRejected => "equality proof generation rejected",
            Self::VerificationFailed => "registration equality proof verification failed",
        })
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}
impl std::error::Error for Error {}

fn validate_context(context: &RegistrationContext<'_>) -> Result<(), Error> {
    if context.profile as u8 != ProfileVersion::V1 as u8
        || context.network_identity.is_empty()
        || context.network_identity.len() > MAX_NETWORK_IDENTITY_BYTES
        || context.round_id.is_empty()
        || context.round_id.len() > MAX_ROUND_ID_BYTES
    {
        return Err(Error::InvalidContext);
    }
    match (context.kind, context.output_proof_binding) {
        (RegistrationKind::InputRegistration, None) => Ok(()),
        (
            RegistrationKind::OutputRegistration,
            Some(OutputProofBinding {
                value_rangeproof,
                asset_surjection_proof,
            }),
        ) if !value_rangeproof.is_empty() && !asset_surjection_proof.is_empty() => Ok(()),
        _ => Err(Error::InvalidContext),
    }
}

/// Encodes the registration context deterministically.
///
/// Layout mirrors the canonical-state V1 context encoding conventions: a fixed
/// magic and profile byte, length-prefixed variable fields (u32 big-endian
/// length prefix), fixed 32-byte hashes, and single-byte enums. Every replay
/// domain component — round id, network identity, genesis hash, L-BTC asset,
/// phase, role, ordinal, registration kind, element index, canonical PSET state
/// digest, and (for outputs) the exact proof bytes — is committed exactly once.
pub fn encode_registration_context(context: &RegistrationContext<'_>) -> Result<Vec<u8>, Error> {
    validate_context(context)?;
    let mut bytes = Vec::with_capacity(256);
    bytes.extend_from_slice(b"WL-CJ-REGISTRATION-CONTEXT-V1");
    bytes.push(context.profile as u8);
    push_bytes(&mut bytes, context.network_identity);
    bytes.extend_from_slice(&context.genesis_hash);
    bytes.extend_from_slice(&context.lbtc_asset.to_byte_array());
    push_bytes(&mut bytes, context.round_id);
    bytes.push(context.phase as u8);
    bytes.push(context.participant_role as u8);
    bytes.extend_from_slice(&context.contribution_ordinal.to_be_bytes());
    bytes.push(context.kind as u8);
    bytes.extend_from_slice(&context.element_index.to_be_bytes());
    bytes.extend_from_slice(&context.pset_state_digest);
    match context.output_proof_binding {
        None => bytes.push(0),
        Some(binding) => {
            bytes.push(1);
            push_bytes(&mut bytes, binding.value_rangeproof);
            push_bytes(&mut bytes, binding.asset_surjection_proof);
        }
    }
    Ok(bytes)
}

fn push_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(
        &u32::try_from(bytes.len())
            .expect("bounded context length fits u32")
            .to_be_bytes(),
    );
    out.extend_from_slice(bytes);
}

/// Builds the input-registration statement from the WabiSabi amount-credential
/// commitment bytes and the referenced input's witness UTXO.
///
/// Input equality applies ONLY to confidential witness UTXOs: the UTXO must
/// carry a confidential value commitment and a confidential asset commitment
/// (the Liquid side the proof binds). An explicit-value witness UTXO has no
/// value commitment to bind and is rejected fail-closed, as is a missing UTXO,
/// an uncommitted asset, or any invalid point encoding.
///
/// # Errors
///
/// Returns [`Error::ElementShape`] when the witness UTXO is missing or not
/// confidential in both value and asset, and [`Error::InvalidStatementEncoding`]
/// when a commitment byte encoding is invalid.
pub fn input_registration_statement(
    credential_commitment_bytes: &[u8],
    witness_utxo: &TxOut,
) -> Result<EqualityStatement, Error> {
    let value_commitment = match witness_utxo.value {
        Value::Confidential(commitment) => commitment,
        _ => return Err(Error::ElementShape),
    };
    let asset_generator = match witness_utxo.asset {
        Asset::Confidential(generator) => generator,
        _ => return Err(Error::ElementShape),
    };
    EqualityStatement::from_native_bytes(
        credential_commitment_bytes,
        &value_commitment.serialize(),
        &asset_generator.serialize(),
    )
    .map_err(|_| Error::InvalidStatementEncoding)
}

/// Builds the output-registration statement from the WabiSabi amount-credential
/// commitment bytes and the referenced PSET output.
///
/// Output equality applies ONLY to fully blinded outputs: `amount_comm`,
/// `asset_comm`, `value_rangeproof`, and `asset_surjection_proof` must all be
/// present, since the proof binds the amount commitment and the context binds
/// the exact proof bytes. Anything else — a missing output, an explicit or
/// partially blinded output, a fee output — is rejected fail-closed.
///
/// # Errors
///
/// Returns [`Error::ElementShape`] when the output index is out of range or
/// the output is not fully blinded, and [`Error::InvalidStatementEncoding`]
/// when a commitment byte encoding is invalid.
pub fn output_registration_statement(
    credential_commitment_bytes: &[u8],
    pset: &PartiallySignedTransaction,
    output_index: usize,
) -> Result<EqualityStatement, Error> {
    let output = pset
        .outputs()
        .get(output_index)
        .ok_or(Error::ElementShape)?;
    if output.amount_comm.is_none()
        || output.asset_comm.is_none()
        || output.value_rangeproof.is_none()
        || output.asset_surjection_proof.is_none()
    {
        return Err(Error::ElementShape);
    }
    let amount_commitment = output.amount_comm.ok_or(Error::ElementShape)?;
    let asset_generator = output.asset_comm.ok_or(Error::ElementShape)?;
    EqualityStatement::from_native_bytes(
        credential_commitment_bytes,
        &amount_commitment.serialize(),
        &asset_generator.serialize(),
    )
    .map_err(|_| Error::InvalidStatementEncoding)
}

/// Verifies one registration equality proof against the exact statement and
/// the exact encoded registration context.
///
/// The proof encoding is decoded fail-closed (exact 162-byte canonical
/// `R1 || R2 || s_v || s_1 || s_2`; wrong length, trailing bytes, invalid
/// points, and non-canonical scalars all reject) before verification runs.
///
/// # Errors
///
/// Returns [`Error::InvalidContext`] for an invalid or unencodable context,
/// [`Error::InvalidProofEncoding`] for a malformed proof, and
/// [`Error::VerificationFailed`] when the proof does not satisfy both
/// verification equations under this exact context.
pub fn verify_registration(
    secp: &Secp256k1<All>,
    statement: &EqualityStatement,
    proof_bytes: &[u8],
    context: &RegistrationContext<'_>,
) -> Result<(), Error> {
    let context_bytes = encode_registration_context(context)?;
    let proof = equality::decode_proof(proof_bytes).map_err(|_| Error::InvalidProofEncoding)?;
    equality::verify(secp, statement, &proof, &context_bytes).map_err(|_| Error::VerificationFailed)
}

/// Produces one registration equality proof bound to the exact encoded
/// registration context.
///
/// `entropy` MUST be 32 fresh caller-supplied bytes; it is mixed into the
/// synthetic nonce derivation so fixtures and callers control determinism.
/// The statement MUST come from [`input_registration_statement`] or
/// [`output_registration_statement`] so the Liquid side is exactly the
/// referenced PSET element.
///
/// # Errors
///
/// Returns [`Error::InvalidContext`] for an invalid or unencodable context and
/// [`Error::ProveRejected`] when the witness or entropy is rejected.
pub fn prove_registration(
    secp: &Secp256k1<All>,
    witness: &EqualityWitness,
    statement: &EqualityStatement,
    context: &RegistrationContext<'_>,
    entropy: &[u8],
) -> Result<EqualityProof, Error> {
    let context_bytes = encode_registration_context(context)?;
    equality::prove(secp, statement, witness, entropy, &context_bytes)
        .map_err(|_| Error::ProveRejected)
}

#[cfg(test)]
mod tests;
