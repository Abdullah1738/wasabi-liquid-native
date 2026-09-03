#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Per-participant partial-balance proof primitive for Liquid CoinJoin.
//!
//! This crate proves that ONE participant's own L-BTC inputs equal its own
//! confidential outputs plus its exact assigned fee share, without revealing
//! any value to the coordinator. The relation (per participant P) is
//!
//! ```text
//! Σ_{i in P.inputs} C_i  −  Σ_{o in P.outputs} C_o  −  fee_P · H_A  ==  Δr · H
//! ```
//!
//! where `C_i`/`C_o` are Pedersen value commitments over the canonical L-BTC
//! asset generator `H_A` (explicit witness UTXOs contribute `v·H_A` directly,
//! with blinding factor zero), `H` is the secp256k1-zkp value/blinding
//! generator (the standard base point `G`, the same constant the
//! commitment-equality primitive uses for its `H`), and
//! `Δr = Σ r_i − Σ r_o (mod n)`. When P's books balance, every `H_A` term
//! cancels and the residual commitment `R` opens to zero under `H_A`; the
//! proof is a Schnorr proof of knowledge of `Δr` on `(R, H)`:
//! `s·H == k·H + c·R`. When the books do not balance, `R` carries a nonzero
//! value component `v·H_A` and no valid witness exists, because the
//! discrete-log relation between `H_A` and `H` is unknown.
//!
//! The statement is ALWAYS recomputed from the referenced PSET elements and
//! the fee share (inside [`prove_partial_balance`] and
//! [`verify_partial_balance`]), so a prover cannot substitute elements. The
//! Fiat-Shamir challenge binds the residual commitment and nonce commitment
//! directly, and binds every other replay domain — asset generator, canonical
//! L-BTC asset id, and the exact PSET element bytes — through the
//! [`PartialBalanceContext`] encoding: profile, network identity, genesis
//! hash, L-BTC asset id, round id, phase, participant role, contribution
//! ordinal, the canonical PSET state digest of the exact revision, the
//! participant's ordered input indices and output indices, the fee share, and
//! every bound element byte (input witness asset/value/nonce commitments,
//! output asset/amount commitments, and the explicit value of every explicit
//! witness UTXO). Asset identity is established by the canonical/surjection
//! layer; this crate binds the exact element bytes whose asset that layer
//! verified.
//!
//! This is a pure proof/binding primitive. It contains no credential
//! protocol, no coordinator, no network, no signing, no custody, no blinding,
//! no round engine, and no FFI. The caller supplies the PSET, the canonical
//! state digest (from `coinjoin-pset-state`), all witnesses, and all entropy.

use core::fmt;

use elements::{
    confidential::{Asset, Nonce, Value},
    encode::serialize as encode_element,
    pset::PartiallySignedTransaction,
    secp256k1_zkp::{All, PublicKey, Scalar, Secp256k1, SecretKey},
};
use sha2::{Digest, Sha256};
use wasabi_liquid_native_coinjoin_pset_state::{
    MAX_INPUT_COUNT, MAX_LBTC_ATOMIC_UNITS, MAX_NETWORK_IDENTITY_BYTES, MAX_ROUND_ID_BYTES,
    ParticipantRole, Phase, ProfileVersion,
};
use zeroize::Zeroize;

/// Byte length of one compressed point encoding.
pub const POINT_BYTES: usize = 33;
/// Byte length of one canonical scalar encoding.
pub const SCALAR_BYTES: usize = 32;
/// Byte length of the canonical proof encoding: `R_k || s` (33 + 32).
pub const PROOF_BYTES: usize = POINT_BYTES + SCALAR_BYTES;
/// Maximum input or output indices bound by one partial-balance proof.
pub const MAX_INDICES: usize = MAX_INPUT_COUNT;

/// Privacy-redacted rejection categories. Statement bytes, witness material,
/// and proof bytes are never included.
#[derive(Copy, Clone, PartialEq, Eq)]
pub enum Error {
    /// A documented public size/count bound was exceeded.
    LimitExceeded,
    /// The immutable partial-balance context is invalid for this profile.
    InvalidContext,
    /// A proof encoding had the wrong length, trailing bytes, an invalid
    /// point, or a non-canonical scalar.
    InvalidProofEncoding,
    /// The witness residual blinding factor is invalid (zero or
    /// non-canonical), or the caller entropy was not exactly 32 bytes.
    InvalidWitness,
    /// A referenced PSET element is missing or not in the required lifecycle
    /// shape (missing witness UTXO, wrong or Null asset/value shape, an
    /// output without an amount commitment, a non-L-BTC generator).
    ElementShape,
    /// Proof generation failed on a curve operation.
    ProveRejected,
    /// Partial-balance proof verification failed for the exact statement and
    /// context.
    VerificationFailed,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::LimitExceeded => "partial-balance limit exceeded",
            Self::InvalidContext => "partial-balance context rejected",
            Self::InvalidProofEncoding => "partial-balance proof encoding rejected",
            Self::InvalidWitness => "partial-balance witness rejected",
            Self::ElementShape => "referenced PSET element shape rejected",
            Self::ProveRejected => "partial-balance proof generation rejected",
            Self::VerificationFailed => "partial-balance proof verification failed",
        })
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}
impl std::error::Error for Error {}

/// Immutable per-participant balance context; its deterministic byte encoding
/// is the replay-binding transcript domain mixed into the Fiat-Shamir
/// challenge and the prover's synthetic nonce derivation.
///
/// Field order and encoding mirror the canonical-state V1 conventions (fixed
/// magic, profile byte, length-prefixed variable fields, fixed-width
/// big-endian scalars, single-byte enums). `pset_state_digest` MUST be the
/// [`wasabi_liquid_native_coinjoin_pset_state::CanonicalState::digest`] bytes
/// of the exact PSET revision the proof binds to.
pub struct PartialBalanceContext<'a> {
    /// Explicit profile version; only V1 is accepted.
    pub profile: ProfileVersion,
    /// Bounded Elements network/profile identity bytes.
    pub network_identity: &'a [u8],
    /// Elements genesis block hash bytes.
    pub genesis_hash: [u8; 32],
    /// Canonical L-BTC asset identity; the ONLY asset generator admitted.
    pub lbtc_asset: elements::AssetId,
    /// Bounded round/domain identifier.
    pub round_id: &'a [u8],
    /// Current protocol phase.
    pub phase: Phase,
    /// Proving participant role.
    pub participant_role: ParticipantRole,
    /// Monotonic participant/contribution ordinal supplied by the caller.
    pub contribution_ordinal: u32,
    /// Canonical PSET state digest of the exact revision being bound.
    pub pset_state_digest: [u8; 32],
    /// The participant's ordered PSET input indices (in range).
    pub input_indices: &'a [u32],
    /// The participant's ordered PSET output indices (in range).
    pub output_indices: &'a [u32],
    /// The participant's exact assigned fee share in L-BTC atomic units
    /// (zero is valid; the sum across participants is validated elsewhere).
    pub fee_share: u64,
}

/// The witness: the residual blinding factor
/// `Δr = Σ r_i − Σ r_o (mod n)` opening the residual commitment under `H`.
///
/// The value is caller-owned secret material; this type deliberately does not
/// implement `Clone` or `Debug` so witness material is not silently
/// duplicated or exposed through formatting.
pub struct PartialBalanceWitness {
    delta_r: [u8; 32],
}

impl Drop for PartialBalanceWitness {
    fn drop(&mut self) {
        self.delta_r.zeroize();
    }
}

impl PartialBalanceWitness {
    /// Builds the witness from the residual blinding factor as a canonical
    /// 32-byte scalar encoding. Zero is rejected: it is not a valid secp256k1
    /// secret key, and the response arithmetic is defined on keys.
    pub fn from_scalar_bytes(delta_r: &[u8; 32]) -> Result<Self, Error> {
        SecretKey::from_slice(delta_r).map_err(|_| Error::InvalidWitness)?;
        Ok(Self { delta_r: *delta_r })
    }

    /// Builds the witness from the residual blinding factor as a secret key.
    pub fn from_secret_key(delta_r: &SecretKey) -> Self {
        Self {
            delta_r: delta_r.secret_bytes(),
        }
    }
}

/// A partial-balance proof: `(R_k, s)` with `s = k + c·Δr (mod n)`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PartialBalanceProof {
    nonce_commitment: PublicKey,
    response: [u8; 32],
}

impl fmt::Debug for PartialBalanceProof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PartialBalanceProof(..)")
    }
}

fn validate_context(context: &PartialBalanceContext<'_>) -> Result<(), Error> {
    if context.profile as u8 != ProfileVersion::V1 as u8
        || context.network_identity.is_empty()
        || context.network_identity.len() > MAX_NETWORK_IDENTITY_BYTES
        || context.round_id.is_empty()
        || context.round_id.len() > MAX_ROUND_ID_BYTES
        || context.input_indices.len() > MAX_INDICES
        || context.output_indices.len() > MAX_INDICES
        || context.fee_share > MAX_LBTC_ATOMIC_UNITS
    {
        return Err(Error::InvalidContext);
    }
    Ok(())
}

fn push_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(
        &u32::try_from(bytes.len())
            .expect("bounded context length fits u32")
            .to_be_bytes(),
    );
    out.extend_from_slice(bytes);
}

fn push_indices(out: &mut Vec<u8>, indices: &[u32]) {
    out.extend_from_slice(
        &u32::try_from(indices.len())
            .expect("bounded index count fits u32")
            .to_be_bytes(),
    );
    for index in indices {
        out.extend_from_slice(&index.to_be_bytes());
    }
}

/// Encodes the static replay-binding context (magic through fee share)
/// deterministically. The bound PSET element bytes are appended by the
/// statement builder, which owns the only construction admitted by this
/// crate.
fn encode_static_context(context: &PartialBalanceContext<'_>) -> Result<Vec<u8>, Error> {
    validate_context(context)?;
    let mut bytes = Vec::with_capacity(256);
    bytes.extend_from_slice(b"WL-CJ-PARTIAL-BALANCE-V1");
    bytes.push(context.profile as u8);
    push_bytes(&mut bytes, context.network_identity);
    bytes.extend_from_slice(&context.genesis_hash);
    bytes.extend_from_slice(&context.lbtc_asset.to_byte_array());
    push_bytes(&mut bytes, context.round_id);
    bytes.push(context.phase as u8);
    bytes.push(context.participant_role as u8);
    bytes.extend_from_slice(&context.contribution_ordinal.to_be_bytes());
    bytes.extend_from_slice(&context.pset_state_digest);
    push_indices(&mut bytes, context.input_indices);
    push_indices(&mut bytes, context.output_indices);
    bytes.extend_from_slice(&context.fee_share.to_be_bytes());
    Ok(bytes)
}

/// The secp256k1-zkp value/blinding generator `H` as a plain curve point: the
/// standard base point `G` (the fixed value generator of every
/// `PedersenCommitment`), the same constant the commitment-equality primitive
/// derives internally for its `H`.
fn blinding_generator() -> PublicKey {
    let mut encoding = [0u8; POINT_BYTES];
    encoding[0] = 0x02;
    encoding[1..].copy_from_slice(&elements::secp256k1_zkp::constants::GENERATOR_X);
    PublicKey::from_slice(&encoding).expect("the base point is a valid point")
}

fn scalar_of(key: &SecretKey) -> Scalar {
    Scalar::from_be_bytes(key.secret_bytes()).expect("secret keys are valid scalars")
}

fn value_scalar(value: u64) -> Scalar {
    let mut bytes = [0u8; 32];
    bytes[24..].copy_from_slice(&value.to_be_bytes());
    Scalar::from_be_bytes(bytes).expect("u64 values are valid scalars")
}

/// The recomputed statement: residual commitment, asset generator, and the
/// full transcript domain (static context plus bound element bytes).
struct Statement {
    residual: PublicKey,
    asset_generator: PublicKey,
    transcript: Vec<u8>,
}

/// Recomputes the residual commitment from the exact PSET elements and the
/// fee share, appending every bound element byte to the transcript domain.
///
/// Inputs MUST carry a witness UTXO whose asset is the canonical L-BTC asset
/// — explicit and equal to `lbtc_asset`, or confidential (any `asset_comm`;
/// the Pedersen value commitment `C = v·H_A + r·H` is over the canonical
/// L-BTC generator regardless of the asset blinding, and the exact
/// `asset_comm` bytes are bound into the transcript so the canonical/
/// surjection layer's asset proof is committed) — and whose value is
/// confidential (its commitment is used directly) or explicit (contributing
/// `v·H_A` with blinding factor zero; the explicit value is byte-committed).
/// Outputs MUST carry `amount_comm` plus an explicit L-BTC asset id; the
/// output `asset_comm` is bound into the transcript but not required to be
/// the unblinded generator. Anything else — a missing element, a Null shape,
/// a wrong explicit asset — is rejected fail-closed.
fn build_statement(
    secp: &Secp256k1<All>,
    pset: &PartiallySignedTransaction,
    context: &PartialBalanceContext<'_>,
) -> Result<Statement, Error> {
    let mut transcript = encode_static_context(context)?;
    let canonical_generator =
        elements::secp256k1_zkp::Generator::new_unblinded(secp, context.lbtc_asset.into_tag());
    let canonical_generator_bytes = canonical_generator.serialize();
    let asset_generator = parse_generator(&canonical_generator_bytes)?;
    transcript.extend_from_slice(&canonical_generator_bytes);

    let inputs = pset.inputs();
    let outputs = pset.outputs();
    let mut positive: Option<PublicKey> = None;
    let mut negative: Option<PublicKey> = None;

    for &raw_index in context.input_indices {
        let index = usize::try_from(raw_index).map_err(|_| Error::ElementShape)?;
        let input = inputs.get(index).ok_or(Error::ElementShape)?;
        let utxo = input.witness_utxo.as_ref().ok_or(Error::ElementShape)?;
        match utxo.asset {
            Asset::Explicit(asset) if asset == context.lbtc_asset => {}
            Asset::Confidential(_) => {}
            _ => return Err(Error::ElementShape),
        }
        let nonce = match utxo.nonce {
            Nonce::Null => [0u8; 33],
            Nonce::Confidential(commitment) => commitment.serialize(),
            _ => return Err(Error::ElementShape),
        };
        let value_commitment = match utxo.value {
            Value::Confidential(commitment) => {
                transcript.push(1u8);
                transcript.extend_from_slice(&commitment.serialize());
                parse_pedersen_commitment(&commitment.serialize())?
            }
            Value::Explicit(value) => {
                transcript.push(2u8);
                transcript.extend_from_slice(&value.to_be_bytes());
                asset_generator
                    .mul_tweak(secp, &value_scalar(value))
                    .map_err(|_| Error::ElementShape)?
            }
            Value::Null => return Err(Error::ElementShape),
        };
        transcript.extend_from_slice(&encode_element(&utxo.asset));
        transcript.extend_from_slice(&nonce);
        positive = Some(match positive {
            None => value_commitment,
            Some(accumulated) => accumulated
                .combine(&value_commitment)
                .map_err(|_| Error::ElementShape)?,
        });
    }

    for &raw_index in context.output_indices {
        let index = usize::try_from(raw_index).map_err(|_| Error::ElementShape)?;
        let output = outputs.get(index).ok_or(Error::ElementShape)?;
        if output.asset != Some(context.lbtc_asset) {
            return Err(Error::ElementShape);
        }
        let output_generator = output.asset_comm.ok_or(Error::ElementShape)?.serialize();
        let amount_commitment = output.amount_comm.ok_or(Error::ElementShape)?.serialize();
        transcript.extend_from_slice(&output_generator);
        transcript.extend_from_slice(&amount_commitment);
        let point = parse_pedersen_commitment(&amount_commitment)?;
        negative = Some(match negative {
            None => point,
            Some(accumulated) => accumulated
                .combine(&point)
                .map_err(|_| Error::ElementShape)?,
        });
    }

    let fee_point = asset_generator
        .mul_tweak(secp, &value_scalar(context.fee_share))
        .map_err(|_| Error::ElementShape)?;
    negative = Some(match negative {
        None => fee_point,
        Some(accumulated) => accumulated
            .combine(&fee_point)
            .map_err(|_| Error::ElementShape)?,
    });

    // R = Σ C_i − (Σ C_o + fee·H_A). Subtraction is addition of the negated
    // aggregate; a genuine point-at-infinity aggregate is reported fail-closed
    // by `combine`.
    let residual = match (positive, negative) {
        (Some(positive), negative) => {
            let negated = negative.map(|point| point.negate(secp));
            match negated {
                Some(negated) => positive
                    .combine(&negated)
                    .map_err(|_| Error::ElementShape)?,
                None => positive,
            }
        }
        (None, Some(negative)) => negative.negate(secp),
        (None, None) => return Err(Error::ElementShape),
    };
    Ok(Statement {
        residual,
        asset_generator,
        transcript,
    })
}

/// Computes the Fiat-Shamir challenge over the full statement: a BIP-340
/// style tagged hash (the tag string is hashed once, the 32-byte tag digest
/// is written twice, then the payload) binding the residual commitment, the
/// nonce commitment, and the complete context encoding.
fn challenge(statement: &Statement, nonce_commitment: &PublicKey) -> [u8; 32] {
    let tag = Sha256::digest(b"WL-CJ-PARTIAL-BALANCE-V1-FS");
    let mut hasher = Sha256::new();
    hasher.update(tag);
    hasher.update(tag);
    let mut absorb = |bytes: &[u8]| {
        hasher.update(
            u64::try_from(bytes.len())
                .expect("field length fits u64")
                .to_be_bytes(),
        );
        hasher.update(bytes);
    };
    absorb(&statement.residual.serialize());
    absorb(&nonce_commitment.serialize());
    absorb(&statement.transcript);
    hasher.finalize().into()
}

/// Derives the Schnorr nonce synthetically (H_DRBG style over a domain tag,
/// the witness, caller entropy, and the full statement), retrying with a
/// counter on the cryptographically-negligible chance a digest is not a valid
/// nonzero scalar. Never panics; never returns an invalid nonce.
fn derive_nonce(
    entropy: &[u8; 32],
    witness: &PartialBalanceWitness,
    statement: &Statement,
) -> SecretKey {
    let tag = Sha256::digest(b"WL-CJ-PARTIAL-BALANCE-V1-NONCE");
    for counter in 0u32.. {
        let mut hasher = Sha256::new();
        hasher.update(tag);
        hasher.update(counter.to_be_bytes());
        hasher.update(witness.delta_r);
        hasher.update(entropy);
        hasher.update(statement.residual.serialize());
        hasher.update(statement.asset_generator.serialize());
        hasher.update(&statement.transcript);
        let digest = hasher.finalize();
        if let Ok(nonce) = SecretKey::from_slice(&digest) {
            return nonce;
        }
    }
    unreachable!("the counter loop always finds a valid nonce");
}

/// Produces a partial-balance proof for the exact statement recomputed from
/// `pset`, `context`, and the caller's witness.
///
/// `entropy` MUST be 32 fresh caller-supplied bytes; it is mixed into the
/// synthetic nonce derivation so fixtures and callers control determinism.
///
/// # Errors
///
/// Returns [`Error::InvalidContext`] for an invalid context,
/// [`Error::ElementShape`] for a referenced element that is missing or not in
/// the required lifecycle shape, [`Error::InvalidWitness`] for a rejected
/// witness or entropy length, and [`Error::ProveRejected`] when a curve
/// operation fails (including the cryptographically-negligible zero-response
/// case, which verification independently rejects).
pub fn prove_partial_balance(
    secp: &Secp256k1<All>,
    pset: &PartiallySignedTransaction,
    context: &PartialBalanceContext<'_>,
    witness: &PartialBalanceWitness,
    entropy: &[u8],
) -> Result<PartialBalanceProof, Error> {
    if entropy.len() != 32 {
        return Err(Error::InvalidWitness);
    }
    let mut entropy_bytes = [0u8; 32];
    entropy_bytes.copy_from_slice(entropy);
    let statement = build_statement(secp, pset, context)?;
    let nonce = derive_nonce(&entropy_bytes, witness, &statement);
    entropy_bytes.zeroize();

    let h = blinding_generator();
    let nonce_commitment = h
        .mul_tweak(secp, &scalar_of(&nonce))
        .map_err(|_| Error::ProveRejected)?;

    // s = k + c·Δr (mod n), computed through the curve's own scalar
    // arithmetic: s·G = k·G + (c·Δr)·G, so the response is the secret key
    // whose public point is that combination (exact modular addition via the
    // secret-key tweak path).
    let challenge = challenge(&statement, &nonce_commitment);
    let challenge_scalar = Scalar::from_be_bytes(challenge).map_err(|_| Error::ProveRejected)?;
    let witness_key = SecretKey::from_slice(&witness.delta_r).map_err(|_| Error::InvalidWitness)?;
    let challenged_witness = witness_key
        .mul_tweak(&challenge_scalar)
        .map_err(|_| Error::ProveRejected)?;
    let response_key = nonce
        .add_tweak(&scalar_of(&challenged_witness))
        .map_err(|_| Error::ProveRejected)?;
    let response = response_key.secret_bytes();

    Ok(PartialBalanceProof {
        nonce_commitment,
        response,
    })
}

/// Verifies a partial-balance proof against the exact statement recomputed
/// from `pset` and `context`.
///
/// # Errors
///
/// Returns [`Error::InvalidContext`] for an invalid context,
/// [`Error::ElementShape`] for a referenced element that is missing or not in
/// the required lifecycle shape, and [`Error::VerificationFailed`] when the
/// Schnorr equation `s·H == R_k + c·R` does not hold under this exact
/// statement.
pub fn verify_partial_balance(
    secp: &Secp256k1<All>,
    pset: &PartiallySignedTransaction,
    context: &PartialBalanceContext<'_>,
    proof: &PartialBalanceProof,
) -> Result<(), Error> {
    let statement = build_statement(secp, pset, context)?;
    let challenge = challenge(&statement, &proof.nonce_commitment);
    let challenge_scalar =
        Scalar::from_be_bytes(challenge).map_err(|_| Error::VerificationFailed)?;
    let response = Scalar::from_be_bytes(proof.response).map_err(|_| Error::VerificationFailed)?;

    let h = blinding_generator();
    // s·H == R_k + c·R
    let lhs = h
        .mul_tweak(secp, &response)
        .map_err(|_| Error::VerificationFailed)?;
    let rhs = proof
        .nonce_commitment
        .combine(
            &statement
                .residual
                .mul_tweak(secp, &challenge_scalar)
                .map_err(|_| Error::VerificationFailed)?,
        )
        .map_err(|_| Error::VerificationFailed)?;
    if lhs != rhs {
        return Err(Error::VerificationFailed);
    }
    Ok(())
}

/// Serializes the proof to its canonical fixed-size encoding:
/// `R_k || s` (33 + 32 = 65 bytes).
pub fn encode_proof(proof: &PartialBalanceProof) -> [u8; PROOF_BYTES] {
    let mut out = [0u8; PROOF_BYTES];
    out[0..33].copy_from_slice(&proof.nonce_commitment.serialize());
    out[33..65].copy_from_slice(&proof.response);
    out
}

/// Parses a canonical proof encoding, rejecting trailing or missing bytes,
/// invalid points, and non-canonical scalars.
pub fn decode_proof(bytes: &[u8]) -> Result<PartialBalanceProof, Error> {
    if bytes.len() != PROOF_BYTES {
        return Err(Error::InvalidProofEncoding);
    }
    let nonce_commitment =
        PublicKey::from_slice(&bytes[0..33]).map_err(|_| Error::InvalidProofEncoding)?;
    let response: [u8; 32] = bytes[33..65]
        .try_into()
        .map_err(|_| Error::InvalidProofEncoding)?;
    Scalar::from_be_bytes(response).map_err(|_| Error::InvalidProofEncoding)?;
    Ok(PartialBalanceProof {
        nonce_commitment,
        response,
    })
}

/// Decodes a serialized secp256k1-zkp `Generator` (33 bytes, first byte
/// `0x0A` when y is a quadratic residue, `0x0B` when it is not) into the
/// exact curve point it encodes. The quadratic-residue branch selection is
/// performed internally; callers never re-encode.
fn parse_generator(bytes: &[u8; 33]) -> Result<PublicKey, Error> {
    let negate = match bytes[0] {
        0x0A => false,
        0x0B => true,
        _ => return Err(Error::ElementShape),
    };
    parse_xquad_point(&bytes[1..], negate)
}

/// Decodes a serialized secp256k1-zkp `PedersenCommitment` (33 bytes, first
/// byte `0x08` when y is a quadratic residue, `0x09` when it is not) into the
/// exact curve point it encodes. The quadratic-residue branch selection is
/// performed internally; callers never re-encode.
fn parse_pedersen_commitment(bytes: &[u8; 33]) -> Result<PublicKey, Error> {
    let negate = match bytes[0] {
        0x08 => false,
        0x09 => true,
        _ => return Err(Error::ElementShape),
    };
    parse_xquad_point(&bytes[1..], negate)
}

/// Recovers the point encoded by the secp256k1-zkp XQuad scheme: lift `x` to
/// the curve point whose y is the quadratic-residue root, negating when the
/// prefix flagged the non-residue root. This matches
/// `secp256k1_generator_parse` and the point that
/// `secp256k1_pedersen_commitment_parse`/`serialize` round-trips, exactly.
fn parse_xquad_point(x: &[u8], negate: bool) -> Result<PublicKey, Error> {
    let x: &[u8; 32] = x.try_into().map_err(|_| Error::ElementShape)?;
    let lifted = xquad_lift(x).ok_or(Error::ElementShape)?;
    let mut encoding = lifted.serialize();
    if negate {
        // Negating flips y's parity: 0x02 <-> 0x03.
        encoding[0] ^= 1;
    }
    PublicKey::from_slice(&encoding).map_err(|_| Error::ElementShape)
}

/// Lifts a 32-byte candidate x-coordinate to the curve point whose y is the
/// quadratic-residue root (the XQuad point), or `None` when `x` is not a
/// canonical field element or `x^3 + 7` is a non-residue. Since the field
/// prime satisfies `p ≡ 3 (mod 4)`, the XQuad root is exactly
/// `y = (x^3 + 7)^((p + 1) / 4) mod p`, verified by squaring back; the
/// quadratic-residue branch is selected by Euler's criterion
/// (`y^((p − 1) / 2) == 1`), NOT by even/odd parity.
fn xquad_lift(x: &[u8; 32]) -> Option<PublicKey> {
    let x_limbs = field::from_be_bytes(x)?;
    let y_squared = field::add(field::cube(&x_limbs), field::SEVEN);
    let y = field::sqrt(&y_squared)?;
    if field::legendre(&y) != field::ONE {
        return None;
    }
    let mut encoding = [0u8; 33];
    encoding[0] = 0x02 | u8::from(field::is_odd(&y));
    encoding[1..].copy_from_slice(x);
    PublicKey::from_slice(&encoding).ok()
}

/// Field arithmetic modulo the secp256k1 prime `p = 2^256 − 2^32 − 977`,
/// scoped to exactly what the XQuad lift needs: canonical parse, addition,
/// multiplication (for cubing and the power ladder), the `(p + 1) / 4`
/// square root, the Legendre symbol (Euler's criterion at `(p − 1) / 2`),
/// and parity. Mirrors the byte-exact rules the commitment-equality
/// primitive pins for the same encodings.
mod field {
    /// The secp256k1 field prime `p`, little-endian 64-bit limbs.
    const MODULUS: [u64; 4] = [
        0xffff_fffe_ffff_fc2f,
        0xffff_ffff_ffff_ffff,
        0xffff_ffff_ffff_ffff,
        0xffff_ffff_ffff_ffff,
    ];

    /// The field element 7 (the curve constant in `y^2 = x^3 + 7`).
    pub(crate) const SEVEN: [u64; 4] = [7, 0, 0, 0];

    /// The field element 1.
    pub(crate) const ONE: [u64; 4] = [1, 0, 0, 0];

    /// Parses a canonical big-endian field element, rejecting values `>= p`.
    pub(crate) fn from_be_bytes(bytes: &[u8; 32]) -> Option<[u64; 4]> {
        let mut limbs = [0u64; 4];
        for (index, chunk) in bytes.chunks_exact(8).enumerate() {
            limbs[3 - index] = u64::from_be_bytes(chunk.try_into().expect("8-byte chunk"));
        }
        if cmp(&limbs, &MODULUS) != core::cmp::Ordering::Less {
            return None;
        }
        Some(limbs)
    }

    /// Returns `(a + b) mod p`.
    pub(crate) fn add(a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
        let (sum, carry) = adc(a, b);
        if carry == 1 || cmp(&sum, &MODULUS) != core::cmp::Ordering::Less {
            sub(sum, MODULUS)
        } else {
            sum
        }
    }

    /// Returns `a^3 mod p`.
    pub(crate) fn cube(a: &[u64; 4]) -> [u64; 4] {
        mul(mul(*a, *a), *a)
    }

    /// Returns the quadratic-residue square root of `a` when it exists:
    /// `a^((p + 1) / 4) mod p`, accepted only when squaring it reproduces
    /// `a` (i.e. `a` is a quadratic residue). `p ≡ 3 (mod 4)`.
    pub(crate) fn sqrt(a: &[u64; 4]) -> Option<[u64; 4]> {
        // (p + 1) / 4 = 2^254 − 2^30 − 244, little-endian 64-bit limbs.
        const EXPONENT: [u64; 4] = [
            0xffff_ffff_bfff_ff0c,
            0xffff_ffff_ffff_ffff,
            0xffff_ffff_ffff_ffff,
            0x3fff_ffff_ffff_ffff,
        ];
        let root = pow(a, &EXPONENT);
        if mul(root, root) == *a {
            Some(root)
        } else {
            None
        }
    }

    /// Returns `a^((p − 1) / 2) mod p` (Euler's criterion): [`ONE`] when `a`
    /// is a nonzero quadratic residue, `p − 1` when it is a non-residue, and
    /// zero when `a` is zero.
    pub(crate) fn legendre(a: &[u64; 4]) -> [u64; 4] {
        // (p − 1) / 2 = 2^255 − 2^31 − 489, little-endian 64-bit limbs.
        const EXPONENT: [u64; 4] = [
            0xffff_ffff_7fff_fe17,
            0xffff_ffff_ffff_ffff,
            0xffff_ffff_ffff_ffff,
            0x7fff_ffff_ffff_ffff,
        ];
        pow(a, &EXPONENT)
    }

    /// Returns whether the canonical representative is odd.
    pub(crate) fn is_odd(a: &[u64; 4]) -> bool {
        a[0] & 1 == 1
    }

    /// Returns `base^exponent mod p` by square-and-multiply over the 256
    /// exponent bits (most significant first). The exponent limbs are
    /// little-endian, so bit `bit` lives in limb `bit / 64`.
    fn pow(base: &[u64; 4], exponent: &[u64; 4]) -> [u64; 4] {
        let mut result = ONE;
        for bit in (0..256).rev() {
            result = mul(result, result);
            if (exponent[bit / 64] >> (bit % 64)) & 1 == 1 {
                result = mul(result, *base);
            }
        }
        result
    }

    /// Returns `a * b mod p` via 256x256-bit schoolbook multiply followed by
    /// bitwise reduction.
    fn mul(a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
        let mut wide = [0u64; 8];
        for (i, &ai) in a.iter().enumerate() {
            let mut carry = 0u128;
            for (j, &bj) in b.iter().enumerate() {
                let acc = wide[i + j] as u128 + ai as u128 * bj as u128 + carry;
                wide[i + j] = acc as u64;
                carry = acc >> 64;
            }
            let mut k = i + 4;
            while carry != 0 && k < 8 {
                let acc = wide[k] as u128 + carry;
                wide[k] = acc as u64;
                carry = acc >> 64;
                k += 1;
            }
        }
        reduce_wide(wide)
    }

    /// Reduces a 512-bit value modulo `p` by binary long division: process
    /// bits from most significant down, maintaining `r = (2r + bit) mod p`
    /// with a 5-limb running remainder.
    fn reduce_wide(wide: [u64; 8]) -> [u64; 4] {
        let mut r = [0u64; 5];
        for bit in (0..512).rev() {
            let mut carry = u64::from(get_bit(&wide, bit));
            for limb in r.iter_mut() {
                let next = *limb >> 63;
                *limb = (*limb << 1) | carry;
                carry = next;
            }
            if cmp5_modulus(&r) != core::cmp::Ordering::Less {
                sub_modulus5(&mut r);
            }
        }
        [r[0], r[1], r[2], r[3]]
    }

    fn get_bit(wide: &[u64; 8], bit: usize) -> u8 {
        ((wide[bit / 64] >> (bit % 64)) & 1) as u8
    }

    fn cmp(a: &[u64; 4], b: &[u64; 4]) -> core::cmp::Ordering {
        for i in (0..4).rev() {
            match a[i].cmp(&b[i]) {
                core::cmp::Ordering::Equal => {}
                other => return other,
            }
        }
        core::cmp::Ordering::Equal
    }

    fn cmp5_modulus(a: &[u64; 5]) -> core::cmp::Ordering {
        if a[4] != 0 {
            return core::cmp::Ordering::Greater;
        }
        cmp(&[a[0], a[1], a[2], a[3]], &MODULUS)
    }

    fn adc(a: [u64; 4], b: [u64; 4]) -> ([u64; 4], u64) {
        let mut out = [0u64; 4];
        let mut carry = 0u128;
        for i in 0..4 {
            let acc = a[i] as u128 + b[i] as u128 + carry;
            out[i] = acc as u64;
            carry = acc >> 64;
        }
        (out, carry as u64)
    }

    fn sub(a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
        let mut out = [0u64; 4];
        let mut borrow = false;
        for i in 0..4 {
            let (difference, overflow) = a[i].overflowing_sub(b[i]);
            let (difference, overflow2) = difference.overflowing_sub(u64::from(borrow));
            out[i] = difference;
            borrow = overflow || overflow2;
        }
        out
    }

    fn sub_modulus5(a: &mut [u64; 5]) {
        let reduced = sub([a[0], a[1], a[2], a[3]], MODULUS);
        a[0] = reduced[0];
        a[1] = reduced[1];
        a[2] = reduced[2];
        a[3] = reduced[3];
        a[4] = 0;
    }
}

#[cfg(test)]
mod tests;
