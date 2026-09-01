#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Cross-commitment value-equality proof primitive for Liquid CoinJoin.
//!
//! This crate implements the M0-design zero-knowledge proof that a WabiSabi
//! amount-credential Pedersen commitment
//! `Ma = v·Gg + r1·Gh` commits to the same value `v` as a Liquid confidential
//! value commitment `C = v·A + r2·H`, where `Gg`/`Gh` are the fixed WabiSabi
//! NUMS generators, `A` is the Liquid asset generator (for the pegged asset,
//! the confidential asset generator derived from the L-BTC asset id), `H` is
//! the secp256k1-zkp value generator (the standard base point `G`), and the
//! prover knows `(v, r1, r2)`.
//!
//! The proof is a composed two-equation Chaum-Pedersen / generalized-Schnorr
//! linear-relation proof over secp256k1: one Fiat-Shamir challenge covers both
//! equations, so the two limbs cannot be mixed from independent proofs.
//!
//! This is a pure crypto primitive. It contains no CoinJoin round logic, no
//! coordinator, no PSET handling, no FFI export, no signing custody, and no
//! broadcast. Callers MUST bind each proof to the round transcript (round id,
//! phase, output index, and prior round messages) via the `context` argument
//! so proofs cannot be replayed across rounds or outputs.

mod field;
mod generators;
mod scalar;
mod transcript;

use core::fmt;

use elements::secp256k1_zkp::{PublicKey, Scalar, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use transcript::Transcript;

/// Byte length of one compressed point encoding.
pub const POINT_BYTES: usize = 33;
/// Byte length of one canonical scalar encoding.
pub const SCALAR_BYTES: usize = 32;
/// Byte length of the canonical proof encoding: `R1 || R2 || s_v || s_1 || s_2`.
pub const PROOF_BYTES: usize = 2 * POINT_BYTES + 3 * SCALAR_BYTES;

/// Maximum accepted value: the largest amount expressible in L-BTC atomic
/// units (`21_000_000 * 100_000_000`).
pub const MAX_VALUE: u64 = 2_100_000_000_000_000;

/// Errors returned by proof generation, parsing, and verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EqualityProofError {
    /// A 33-byte encoding was not a valid compressed secp256k1 point.
    InvalidPoint,
    /// A 32-byte encoding was not a canonical scalar in `[1, n-1]`.
    InvalidScalar,
    /// A slice had the wrong length for the item being parsed.
    InvalidLength,
    /// The value exceeded [`MAX_VALUE`].
    ValueOutOfRange,
    /// The caller-supplied entropy was not exactly 32 bytes.
    InvalidEntropyLength,
    /// The proof did not satisfy both verification equations.
    VerificationFailed,
}

impl fmt::Display for EqualityProofError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPoint => f.write_str("invalid point encoding"),
            Self::InvalidScalar => f.write_str("non-canonical scalar encoding"),
            Self::InvalidLength => f.write_str("wrong encoding length"),
            Self::ValueOutOfRange => f.write_str("value exceeds maximum"),
            Self::InvalidEntropyLength => f.write_str("entropy must be 32 bytes"),
            Self::VerificationFailed => f.write_str("equality proof verification failed"),
        }
    }
}

impl std::error::Error for EqualityProofError {}

/// The witness: value `v` and blinding factors `r1`, `r2`.
///
/// The blinding factors are caller-owned secrets; this type deliberately does
/// not implement `Clone` or `Debug` so witness material is not silently
/// duplicated or formatted.
pub struct EqualityWitness {
    /// The value `v` as a canonical 32-byte scalar (may be zero).
    value: [u8; 32],
    /// Blinding factor `r1` as a canonical 32-byte scalar (may be zero).
    r1: [u8; 32],
    /// Blinding factor `r2` as a canonical 32-byte scalar (may be zero).
    r2: [u8; 32],
}

impl Drop for EqualityWitness {
    fn drop(&mut self) {
        self.value.zeroize();
        self.r1.zeroize();
        self.r2.zeroize();
    }
}

impl EqualityWitness {
    /// Builds a witness from the explicit value and the two blinding factors.
    ///
    /// `value` must not exceed [`MAX_VALUE`]. `r1` and `r2` are the blinding
    /// factors of the WabiSabi commitment and the Liquid value commitment.
    pub fn new(value: u64, r1: &SecretKey, r2: &SecretKey) -> Result<Self, EqualityProofError> {
        Self::from_scalar_blindings(value, &r1.secret_bytes(), &r2.secret_bytes())
    }

    /// Builds a witness from the explicit value and the two blinding factors as
    /// canonical 32-byte scalar encodings.
    ///
    /// Unlike [`EqualityWitness::new`], this accepts zero blinding factors: a
    /// zero `r` is a valid (unblinded) commitment whenever `v > 0`, and the
    /// secp256k1-zkp `Tweak` type likewise permits zero. Both factors must still
    /// be canonical scalars (`< n`); `value` must not exceed [`MAX_VALUE`].
    pub fn from_scalar_blindings(
        value: u64,
        r1: &[u8; 32],
        r2: &[u8; 32],
    ) -> Result<Self, EqualityProofError> {
        if value > MAX_VALUE {
            return Err(EqualityProofError::ValueOutOfRange);
        }
        // Canonical scalars are `< n`; zero is valid.
        scalar::from_be_bytes(*r1).ok_or(EqualityProofError::InvalidScalar)?;
        scalar::from_be_bytes(*r2).ok_or(EqualityProofError::InvalidScalar)?;
        let mut value_bytes = [0u8; 32];
        value_bytes[24..].copy_from_slice(&value.to_be_bytes());
        Ok(Self {
            value: value_bytes,
            r1: *r1,
            r2: *r2,
        })
    }
}

/// The public statement: `Ma`, `C`, and the asset generator `A`.
///
/// All three are secp256k1 curve points. Callers construct them either from
/// canonical compressed encodings via [`EqualityStatement::new`], or directly
/// from the native secp256k1-zkp serializations of the Liquid value
/// commitment (a `PedersenCommitment`) and asset generator (a `Generator`)
/// via [`EqualityStatement::from_native_bytes`]. Both reject invalid points.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EqualityStatement {
    /// WabiSabi amount-credential commitment `Ma = v·Gg + r1·Gh`.
    pub credential_commitment: PublicKey,
    /// Liquid confidential value commitment `C = v·A + r2·H`.
    pub value_commitment: PublicKey,
    /// Liquid asset generator `A`.
    pub asset_generator: PublicKey,
}

impl EqualityStatement {
    /// Builds a statement from canonical compressed (33-byte) point encodings.
    ///
    /// Each point MUST be the compressed encoding of the corresponding group
    /// element: `Ma`, the value commitment `C`, and the asset generator `A`.
    /// For points that arrive in the native secp256k1-zkp serializations
    /// (`Generator` with prefix `0x0A`/`0x0B`, `PedersenCommitment` with
    /// prefix `0x08`/`0x09`), prefer [`EqualityStatement::from_native_bytes`]
    /// or the [`point_from_generator_bytes`] / [`point_from_pedersen_commitment_bytes`]
    /// conversion helpers; this constructor rejects those prefixes rather than
    /// guessing at a re-encoding.
    pub fn new(
        credential_commitment: &[u8],
        value_commitment: &[u8],
        asset_generator: &[u8],
    ) -> Result<Self, EqualityProofError> {
        Ok(Self {
            credential_commitment: generators::parse_compressed(credential_commitment)?,
            value_commitment: generators::parse_compressed(value_commitment)?,
            asset_generator: generators::parse_compressed(asset_generator)?,
        })
    }

    /// Builds a statement from the native secp256k1-zkp serializations.
    ///
    /// `credential_commitment` is the WabiSabi amount-credential commitment in
    /// canonical compressed form (33 bytes). `value_commitment` MUST be the
    /// 33-byte serialization of the Liquid confidential value commitment as a
    /// secp256k1-zkp `PedersenCommitment` (prefix `0x08` when y is a quadratic
    /// residue, `0x09` when it is not), and `asset_generator` MUST be the
    /// 33-byte serialization of the Liquid asset generator as a secp256k1-zkp
    /// `Generator` (prefix `0x0A`/`0x0B` on the same rule). The two kinds are
    /// distinguished by prefix and never accepted in each other's place; the
    /// exact curve point is recovered internally (including the
    /// Legendre/quadratic-residue branch selection), so callers pass the bytes
    /// straight through without any re-encoding.
    pub fn from_native_bytes(
        credential_commitment: &[u8],
        value_commitment: &[u8],
        asset_generator: &[u8],
    ) -> Result<Self, EqualityProofError> {
        Ok(Self {
            credential_commitment: generators::parse_compressed(credential_commitment)?,
            value_commitment: generators::parse_pedersen_commitment(value_commitment)?,
            asset_generator: generators::parse_generator(asset_generator)?,
        })
    }

    /// Returns the canonical compressed encodings `(Ma, C, A)`.
    pub fn to_bytes(&self) -> ([u8; 33], [u8; 33], [u8; 33]) {
        (
            self.credential_commitment.serialize(),
            self.value_commitment.serialize(),
            self.asset_generator.serialize(),
        )
    }
}

/// A composed value-equality proof: `(R1, R2, s_v, s_1, s_2)`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct EqualityProof {
    r1_commitment: PublicKey,
    r2_commitment: PublicKey,
    /// Canonical scalar `s_v` (may be any value in `[0, n-1]`).
    s_v: [u8; 32],
    s_1: [u8; 32],
    s_2: [u8; 32],
}

impl fmt::Debug for EqualityProof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EqualityProof(..)")
    }
}

/// Secret nonce material, zeroized on drop.
struct Nonces {
    k_v: SecretKey,
    k_1: SecretKey,
    k_2: SecretKey,
}

impl Drop for Nonces {
    fn drop(&mut self) {
        self.k_v.non_secure_erase();
        self.k_1.non_secure_erase();
        self.k_2.non_secure_erase();
    }
}

fn scalar_of(key: &SecretKey) -> Scalar {
    Scalar::from_be_bytes(key.secret_bytes()).expect("secret keys are valid scalars")
}

/// Converts canonical scalar bytes to a [`Scalar`] for point multiplication,
/// rejecting non-canonical encodings.
fn scalar_from_bytes(bytes: &[u8; 32]) -> Result<Scalar, EqualityProofError> {
    Scalar::from_be_bytes(*bytes).map_err(|_| EqualityProofError::InvalidScalar)
}

/// s = k + c·w  (mod n). `k` is a nonzero nonce; `w` may be any canonical
/// scalar (including zero, for `v = 0`). All arithmetic is modulo the group
/// order via [`scalar`]. Fails closed on a non-canonical challenge rather than
/// panicking: the challenge is a transcript digest and is `< n` with
/// overwhelming probability, but the conversion is checked, not assumed.
fn response(
    k: &SecretKey,
    challenge: &[u8; 32],
    witness: &[u8; 32],
) -> Result<[u8; 32], EqualityProofError> {
    let k = scalar::from_be_bytes(k.secret_bytes()).ok_or(EqualityProofError::InvalidScalar)?;
    let c = scalar::from_be_bytes(*challenge).ok_or(EqualityProofError::InvalidScalar)?;
    let w = scalar::from_be_bytes(*witness).ok_or(EqualityProofError::InvalidScalar)?;
    Ok(scalar::to_be_bytes(scalar::add(k, scalar::mul(c, w))))
}

/// Derives one synthetic nonce from the transcript-bound label, the witness
/// scalars, and caller-supplied fresh entropy (SyntheticSecretNonceProvider
/// style: `H_DRBG(label || witness || entropy)`), never from the raw RNG.
///
/// The digest is a valid nonce only when it is a nonzero scalar `< n`; on the
/// cryptographically-negligible chance it is not, a deterministic counter is
/// mixed in and rehashed until a valid nonce results, so the function never
/// panics and never returns an invalid nonce.
fn derive_nonce(
    label: &[u8],
    witness: &EqualityWitness,
    entropy: &[u8; 32],
    gg: &PublicKey,
    gh: &PublicKey,
    statement: &EqualityStatement,
    context: &[u8],
) -> SecretKey {
    let tag = Sha256::digest(b"WL-COINJOIN-EQ-V1-NONCE");
    for counter in 0u32.. {
        let mut hasher = Sha256::new();
        hasher.update(tag);
        hasher.update(label);
        hasher.update(counter.to_be_bytes());
        hasher.update(witness.value);
        hasher.update(witness.r1);
        hasher.update(witness.r2);
        hasher.update(entropy);
        hasher.update(gg.serialize());
        hasher.update(gh.serialize());
        hasher.update(statement.credential_commitment.serialize());
        hasher.update(statement.value_commitment.serialize());
        hasher.update(statement.asset_generator.serialize());
        hasher.update(context);
        let digest = hasher.finalize();
        if let Ok(nonce) = SecretKey::from_slice(&digest) {
            return nonce;
        }
    }
    unreachable!("the counter loop always finds a valid nonce");
}

/// Computes the Fiat-Shamir challenge over the full transcript.
fn challenge(
    r1_commitment: &PublicKey,
    r2_commitment: &PublicKey,
    statement: &EqualityStatement,
    gg: &PublicKey,
    gh: &PublicKey,
    context: &[u8],
) -> [u8; 32] {
    let mut transcript = Transcript::new();
    transcript.absorb(&r1_commitment.serialize());
    transcript.absorb(&r2_commitment.serialize());
    transcript.absorb(&statement.credential_commitment.serialize());
    transcript.absorb(&statement.value_commitment.serialize());
    transcript.absorb(&statement.asset_generator.serialize());
    transcript.absorb(&gg.serialize());
    transcript.absorb(&gh.serialize());
    transcript.absorb(context);
    transcript.finalize()
}

/// Produces a proof that `Ma` and `C` commit to the same value.
///
/// `entropy` MUST be 32 fresh random bytes from the caller; it is mixed into
/// the synthetic nonce derivation so nonces are never reused across proofs.
/// `context` MUST bind the round transcript (round id, phase, output index).
pub fn prove(
    secp: &Secp256k1<elements::secp256k1_zkp::All>,
    statement: &EqualityStatement,
    witness: &EqualityWitness,
    entropy: &[u8],
    context: &[u8],
) -> Result<EqualityProof, EqualityProofError> {
    if entropy.len() != 32 {
        return Err(EqualityProofError::InvalidEntropyLength);
    }
    let mut entropy_bytes = [0u8; 32];
    entropy_bytes.copy_from_slice(entropy);

    let gg = generators::wabisabi_gg();
    let gh = generators::wabisabi_gh();

    let nonces = Nonces {
        k_v: derive_nonce(
            b"k_v",
            witness,
            &entropy_bytes,
            &gg,
            &gh,
            statement,
            context,
        ),
        k_1: derive_nonce(
            b"k_1",
            witness,
            &entropy_bytes,
            &gg,
            &gh,
            statement,
            context,
        ),
        k_2: derive_nonce(
            b"k_2",
            witness,
            &entropy_bytes,
            &gg,
            &gh,
            statement,
            context,
        ),
    };
    entropy_bytes.zeroize();

    // R1 = k_v·Gg + k_1·Gh
    let r1_commitment = gg
        .mul_tweak(secp, &scalar_of(&nonces.k_v))
        .and_then(|p| p.combine(&gh.mul_tweak(secp, &scalar_of(&nonces.k_1))?))
        .map_err(|_| EqualityProofError::InvalidPoint)?;
    // R2 = k_v·A + k_2·H
    let value_generator = value_generator_point();
    let r2_commitment = statement
        .asset_generator
        .mul_tweak(secp, &scalar_of(&nonces.k_v))
        .and_then(|p| p.combine(&value_generator.mul_tweak(secp, &scalar_of(&nonces.k_2))?))
        .map_err(|_| EqualityProofError::InvalidPoint)?;

    let challenge = challenge(&r1_commitment, &r2_commitment, statement, &gg, &gh, context);

    let s_v = response(&nonces.k_v, &challenge, &witness.value)?;
    let s_1 = response(&nonces.k_1, &challenge, &witness.r1)?;
    let s_2 = response(&nonces.k_2, &challenge, &witness.r2)?;

    Ok(EqualityProof {
        r1_commitment,
        r2_commitment,
        s_v,
        s_1,
        s_2,
    })
}

/// Verifies a proof that `Ma` and `C` commit to the same value.
pub fn verify(
    secp: &Secp256k1<elements::secp256k1_zkp::All>,
    statement: &EqualityStatement,
    proof: &EqualityProof,
    context: &[u8],
) -> Result<(), EqualityProofError> {
    let gg = generators::wabisabi_gg();
    let gh = generators::wabisabi_gh();
    let challenge = challenge(
        &proof.r1_commitment,
        &proof.r2_commitment,
        statement,
        &gg,
        &gh,
        context,
    );
    let challenge = scalar_from_bytes(&challenge)?;
    let s_v = scalar_from_bytes(&proof.s_v)?;
    let s_1 = scalar_from_bytes(&proof.s_1)?;
    let s_2 = scalar_from_bytes(&proof.s_2)?;

    // Equation (1): s_v·Gg + s_1·Gh == R1 + c·Ma
    let lhs1 = gg
        .mul_tweak(secp, &s_v)
        .and_then(|p| p.combine(&gh.mul_tweak(secp, &s_1)?))
        .map_err(|_| EqualityProofError::VerificationFailed)?;
    let rhs1 = proof
        .r1_commitment
        .combine(
            &statement
                .credential_commitment
                .mul_tweak(secp, &challenge)
                .map_err(|_| EqualityProofError::VerificationFailed)?,
        )
        .map_err(|_| EqualityProofError::VerificationFailed)?;
    if lhs1 != rhs1 {
        return Err(EqualityProofError::VerificationFailed);
    }

    // Equation (2): s_v·A + s_2·H == R2 + c·C
    let value_generator = value_generator_point();
    let lhs2 = statement
        .asset_generator
        .mul_tweak(secp, &s_v)
        .and_then(|p| p.combine(&value_generator.mul_tweak(secp, &s_2)?))
        .map_err(|_| EqualityProofError::VerificationFailed)?;
    let rhs2 = proof
        .r2_commitment
        .combine(
            &statement
                .value_commitment
                .mul_tweak(secp, &challenge)
                .map_err(|_| EqualityProofError::VerificationFailed)?,
        )
        .map_err(|_| EqualityProofError::VerificationFailed)?;
    if lhs2 != rhs2 {
        return Err(EqualityProofError::VerificationFailed);
    }

    Ok(())
}

/// Serializes the proof to its canonical fixed-size encoding:
/// `R1 || R2 || s_v || s_1 || s_2` (33+33+32+32+32 = 162 bytes).
pub fn encode_proof(proof: &EqualityProof) -> [u8; PROOF_BYTES] {
    let mut out = [0u8; PROOF_BYTES];
    out[0..33].copy_from_slice(&proof.r1_commitment.serialize());
    out[33..66].copy_from_slice(&proof.r2_commitment.serialize());
    out[66..98].copy_from_slice(&proof.s_v);
    out[98..130].copy_from_slice(&proof.s_1);
    out[130..162].copy_from_slice(&proof.s_2);
    out
}

/// Parses a canonical proof encoding, rejecting trailing or missing bytes and
/// non-canonical scalars.
pub fn decode_proof(bytes: &[u8]) -> Result<EqualityProof, EqualityProofError> {
    if bytes.len() != PROOF_BYTES {
        return Err(EqualityProofError::InvalidLength);
    }
    let r1_commitment = generators::parse_compressed(&bytes[0..33])?;
    let r2_commitment = generators::parse_compressed(&bytes[33..66])?;
    let s_v = parse_scalar(&bytes[66..98])?;
    let s_1 = parse_scalar(&bytes[98..130])?;
    let s_2 = parse_scalar(&bytes[130..162])?;
    Ok(EqualityProof {
        r1_commitment,
        r2_commitment,
        s_v,
        s_1,
        s_2,
    })
}

fn parse_scalar(bytes: &[u8]) -> Result<[u8; 32], EqualityProofError> {
    let array: [u8; 32] = bytes
        .try_into()
        .map_err(|_| EqualityProofError::InvalidLength)?;
    // Canonical scalars are `< n`; zero is a valid response value.
    scalar::from_be_bytes(array).ok_or(EqualityProofError::InvalidScalar)?;
    Ok(array)
}

/// Converts a serialized secp256k1-zkp `Generator` (33 bytes, first byte
/// `0x0A` when y is a quadratic residue, `0x0B` when it is not) into the
/// exact curve point it encodes.
///
/// This is the safe first-class conversion for Liquid asset generators: the
/// quadratic-residue branch selection is performed internally, so callers
/// pass the serialized generator straight through and never re-encode or
/// reason about Legendre symbols themselves. Wrong lengths, prefixes of the
/// other kind (`0x08`/`0x09`), and x-coordinates with no curve point are
/// rejected.
pub fn point_from_generator_bytes(bytes: &[u8]) -> Result<PublicKey, EqualityProofError> {
    generators::parse_generator(bytes)
}

/// Converts a serialized secp256k1-zkp `PedersenCommitment` (33 bytes, first
/// byte `0x08` when y is a quadratic residue, `0x09` when it is not) into the
/// exact curve point it encodes.
///
/// This is the safe first-class conversion for Liquid confidential value
/// commitments: the quadratic-residue branch selection is performed
/// internally, so callers pass the serialized commitment straight through and
/// never re-encode or reason about Legendre symbols themselves. Wrong
/// lengths, prefixes of the other kind (`0x0A`/`0x0B`), and x-coordinates
/// with no curve point are rejected.
pub fn point_from_pedersen_commitment_bytes(bytes: &[u8]) -> Result<PublicKey, EqualityProofError> {
    generators::parse_pedersen_commitment(bytes)
}

/// The secp256k1-zkp value/blinding generator `H` as a plain curve point.
///
/// `H` is the standard secp256k1 base point `G` in generator serialization
/// (the fixed value generator used by `PedersenCommitment`).
fn value_generator_point() -> PublicKey {
    let mut encoding = [0u8; POINT_BYTES];
    encoding[0] = 0x02;
    encoding[1..].copy_from_slice(&elements::secp256k1_zkp::constants::GENERATOR_X);
    PublicKey::from_slice(&encoding).expect("the base point is a valid point")
}

#[cfg(test)]
mod tests;
