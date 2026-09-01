//! WabiSabi NUMS generators `Gg` and `Gh`, plus the secp256k1-zkp native
//! `Generator` / `PedersenCommitment` point decoders.
//!
//! Byte-exact reproduction of NWabiSabi `WabiSabi/Crypto/Groups/Generators.cs`:
//! `FromText(name)` sets `buffer = UTF8(name)` and repeatedly replaces it with
//! `SHA256(buffer)` until the 32-byte buffer is a valid x-coordinate of a
//! secp256k1 point whose y is the quadratic-residue root — the "XQuad" rule of
//! NBitcoin.Secp256k1's `GE.TryCreateXQuad`, which matches libsecp256k1-zkp's
//! `secp256k1_ge_set_xquad`. Since the field prime satisfies `p ≡ 3 (mod 4)`,
//! the XQuad root is exactly `y = (x^3 + 7)^((p + 1) / 4) mod p`, verified by
//! squaring back; it is NOT selected by even/odd parity. `Gg = FromText("Gg")`
//! and `Gh = FromText("Gh")`. The constants are pinned by known-answer tests
//! against independently computed compressed encodings.
//!
//! The secp256k1-zkp native serializations reuse the same XQuad rule: a
//! `Generator` encodes `0x0A | (y non-residue)` and a `PedersenCommitment`
//! encodes `0x08 | (y non-residue)` in the first of 33 bytes. The decoders
//! here recover the exact curve point from either encoding, keeping the
//! Legendre/QR branch selection internal.

use elements::secp256k1_zkp::PublicKey;
use sha2::{Digest, Sha256};

use crate::{EqualityProofError, field};

/// Derives a WabiSabi NUMS generator from its text name by the exact XQuad
/// rule: starting from `SHA256(UTF8(name))`, each candidate 32-byte buffer is
/// tried as the x-coordinate of the point with quadratic-residue y; invalid
/// x-coordinates are rehashed until one lifts. This is the single source of
/// truth for the hash-to-curve direction used by [`wabisabi_gg`] and
/// [`wabisabi_gh`].
pub(crate) fn from_text_xquad(name: &[u8]) -> PublicKey {
    let mut buffer: [u8; 32] = Sha256::digest(name).into();
    loop {
        if let Some(point) = xquad_lift(&buffer) {
            return point;
        }
        buffer = Sha256::digest(buffer).into();
    }
}

/// Returns the WabiSabi amount-credential value generator `Gg`.
pub(crate) fn wabisabi_gg() -> PublicKey {
    from_text_xquad(b"Gg")
}

/// Returns the WabiSabi amount-credential blinding generator `Gh`.
pub(crate) fn wabisabi_gh() -> PublicKey {
    from_text_xquad(b"Gh")
}

/// Lifts a 32-byte candidate x-coordinate to the curve point whose y is the
/// quadratic-residue root (the XQuad point), or `None` when `x` is not a
/// canonical field element or `x^3 + 7` is a non-residue.
fn xquad_lift(x: &[u8; 32]) -> Option<PublicKey> {
    let x_limbs = field::from_be_bytes(x)?;
    let y_squared = field::add(field::cube(&x_limbs), field::SEVEN);
    let y = field::sqrt(&y_squared)?;
    let mut encoding = [0u8; 33];
    encoding[0] = 0x02 | u8::from(field::is_odd(&y));
    encoding[1..].copy_from_slice(x);
    PublicKey::from_slice(&encoding).ok()
}

/// Parses a compressed 33-byte point encoding.
pub(crate) fn parse_compressed(bytes: &[u8]) -> Result<PublicKey, EqualityProofError> {
    PublicKey::from_slice(bytes).map_err(|_| EqualityProofError::InvalidPoint)
}

/// Decodes a serialized secp256k1-zkp `Generator` (33 bytes, first byte
/// `0x0A` when y is a quadratic residue, `0x0B` when it is not) into the
/// exact curve point it encodes. The QR branch selection is handled
/// internally; callers never re-encode.
pub(crate) fn parse_generator(bytes: &[u8]) -> Result<PublicKey, EqualityProofError> {
    if bytes.len() != 33 {
        return Err(EqualityProofError::InvalidLength);
    }
    let negate = match bytes[0] {
        0x0A => false,
        0x0B => true,
        _ => return Err(EqualityProofError::InvalidPoint),
    };
    parse_xquad_point(&bytes[1..], negate)
}

/// Decodes a serialized secp256k1-zkp `PedersenCommitment` (33 bytes, first
/// byte `0x08` when y is a quadratic residue, `0x09` when it is not) into the
/// exact curve point it encodes. The QR branch selection is handled
/// internally; callers never re-encode.
pub(crate) fn parse_pedersen_commitment(bytes: &[u8]) -> Result<PublicKey, EqualityProofError> {
    if bytes.len() != 33 {
        return Err(EqualityProofError::InvalidLength);
    }
    let negate = match bytes[0] {
        0x08 => false,
        0x09 => true,
        _ => return Err(EqualityProofError::InvalidPoint),
    };
    parse_xquad_point(&bytes[1..], negate)
}

/// Recovers the point encoded by the secp256k1-zkp XQuad scheme: lift `x` to
/// the quadratic-residue-root point, negating when the prefix flagged a
/// non-residue y. This matches `secp256k1_generator_parse` and the point
/// `secp256k1_pedersen_commitment_parse`/`serialize` round-trip, exactly.
fn parse_xquad_point(x: &[u8], negate: bool) -> Result<PublicKey, EqualityProofError> {
    let x: &[u8; 32] = x
        .try_into()
        .map_err(|_| EqualityProofError::InvalidLength)?;
    let lifted = xquad_lift(x).ok_or(EqualityProofError::InvalidPoint)?;
    let mut encoding = lifted.serialize();
    if negate {
        // Negating flips y's parity: 0x02 <-> 0x03.
        encoding[0] ^= 1;
    }
    PublicKey::from_slice(&encoding).map_err(|_| EqualityProofError::InvalidPoint)
}

/// Test-only consistency check: the point must be the XQuad lift of `x`,
/// negated exactly when `negate` is set.
#[cfg(test)]
pub(crate) fn point_matches_xquad_encoding(point: &PublicKey, negate: bool, x: &[u8]) -> bool {
    let Ok(expected) = parse_xquad_point(x, negate) else {
        return false;
    };
    &expected == point
}
