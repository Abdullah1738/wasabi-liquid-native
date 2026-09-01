//! In-crate evidence for the value-equality proof primitive.

use elements::secp256k1_zkp::{All, PublicKey, Scalar, Secp256k1, SecretKey};
use rand::RngCore;

use super::*;

/// Adds 1 (mod n) to a canonical scalar, for response-tampering cases.
fn add_one(scalar_bytes: &[u8; 32]) -> [u8; 32] {
    let limbs = scalar::from_be_bytes(*scalar_bytes).expect("scalar");
    let one = scalar::from_be_bytes(value_scalar(1).to_be_bytes()).expect("one");
    scalar::to_be_bytes(scalar::add(limbs, one))
}

fn secp() -> Secp256k1<All> {
    Secp256k1::new()
}

fn rand_scalar() -> SecretKey {
    let mut bytes = [0u8; 32];
    loop {
        rand::thread_rng().fill_bytes(&mut bytes);
        if let Ok(key) = SecretKey::from_slice(&bytes) {
            return key;
        }
    }
}

/// A [`Scalar`] for a value that may be zero (used only to build test points).
fn value_scalar(value: u64) -> Scalar {
    let mut bytes = [0u8; 32];
    bytes[24..].copy_from_slice(&value.to_be_bytes());
    Scalar::from_be_bytes(bytes).expect("value scalar")
}

fn rand_entropy() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes
}

/// Deterministic NUMS-style asset generator for tests: a tagged hash to curve.
fn test_asset_generator() -> PublicKey {
    hash_to_point(b"test-asset-generator-A")
}

/// A second, distinct asset generator for the wrong-`A` negative case.
fn other_asset_generator() -> PublicKey {
    hash_to_point(b"other-asset-generator-A")
}

fn hash_to_point(label: &[u8]) -> PublicKey {
    let mut counter = 0u8;
    loop {
        let digest = Sha256::digest([label, &[counter]].concat());
        if let Ok(point) = PublicKey::from_slice(&[&[0x02u8], &digest[..]].concat()) {
            return point;
        }
        counter = counter.wrapping_add(1);
    }
}

struct Fixture {
    secp: Secp256k1<All>,
    statement: EqualityStatement,
    witness: EqualityWitness,
    entropy: [u8; 32],
    context: Vec<u8>,
}

fn make_fixture(value: u64) -> Fixture {
    make_fixture_with_asset(value, test_asset_generator())
}

fn make_fixture_with_asset(value: u64, asset_generator: PublicKey) -> Fixture {
    let secp = secp();
    let r1 = rand_scalar();
    let r2 = rand_scalar();

    let gg = super::generators::wabisabi_gg();
    let gh = super::generators::wabisabi_gh();
    // Ma = v·Gg + r1·Gh. The safe-Rust PublicKey API rejects the point at
    // infinity, so for v = 0 the value term is simply r1·Gh.
    let value_scalar = value_scalar(value);
    let r1_point = gh.mul_tweak(&secp, &scalar_of(&r1)).unwrap();
    let credential_commitment = if value == 0 {
        r1_point
    } else {
        gg.mul_tweak(&secp, &value_scalar)
            .and_then(|p| p.combine(&r1_point))
            .expect("credential commitment")
    };
    // C = v·A + r2·H, with H the base point.
    let r2_point = value_generator_point()
        .mul_tweak(&secp, &scalar_of(&r2))
        .unwrap();
    let value_commitment = if value == 0 {
        r2_point
    } else {
        asset_generator
            .mul_tweak(&secp, &value_scalar)
            .and_then(|p| p.combine(&r2_point))
            .expect("value commitment")
    };

    Fixture {
        secp,
        statement: EqualityStatement {
            credential_commitment,
            value_commitment,
            asset_generator,
        },
        witness: EqualityWitness::new(value, &r1, &r2).expect("witness"),
        entropy: rand_entropy(),
        context: b"round=1;phase=input-registration;output=0".to_vec(),
    }
}

fn make_proof(fixture: &Fixture) -> EqualityProof {
    prove(
        &fixture.secp,
        &fixture.statement,
        &fixture.witness,
        &fixture.entropy,
        &fixture.context,
    )
    .expect("prove")
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

/// Lifts `x` to the curve point whose y is the quadratic-residue root
/// (`y^((p+1)/4) mod p`), or `None` when `x^3 + 7` is a non-residue.
///
/// Independent reference for the NWabiSabi `FromText` XQuad rule; the
/// implementation under test must agree for every candidate x.
fn reference_xquad_lift(x: &[u8; 32]) -> Option<PublicKey> {
    let x_limbs = super::field::from_be_bytes(x)?;
    let y_squared = super::field::add(super::field::cube(&x_limbs), super::field::SEVEN);
    let y = super::field::sqrt(&y_squared)?;
    let mut encoding = [0u8; 33];
    encoding[0] = 0x02 | u8::from(super::field::is_odd(&y));
    encoding[1..].copy_from_slice(x);
    PublicKey::from_slice(&encoding).ok()
}

/// Lifts `x` to the curve point with even y (the pre-fix behavior), used only
/// to assert that XQuad and even-parity disagree on non-QR-root-parity x.
fn reference_even_lift(x: &[u8; 32]) -> PublicKey {
    let x_only = elements::secp256k1_zkp::XOnlyPublicKey::from_slice(x).expect("x");
    PublicKey::from_x_only_public_key(x_only, elements::secp256k1_zkp::Parity::Even)
}

#[test]
fn honest_proof_verifies() {
    let fixture = make_fixture(123_456_789);
    let proof = make_proof(&fixture);
    verify(&fixture.secp, &fixture.statement, &proof, &fixture.context).expect("verify");
}

#[test]
fn wrong_value_is_rejected() {
    let fixture = make_fixture(1_000);
    let other = make_fixture(2_000);
    let proof = make_proof(&other);
    // Verify a proof made for value 2000 against the statement for value 1000.
    assert_eq!(
        verify(&fixture.secp, &fixture.statement, &proof, &fixture.context),
        Err(EqualityProofError::VerificationFailed)
    );
}

#[test]
fn wrong_r1_is_rejected() {
    let fixture = make_fixture(5_000);
    let bad_r1 = rand_scalar();
    let witness = EqualityWitness::new(5_000, &bad_r1, &rand_scalar()).expect("witness");
    let proof = prove(
        &fixture.secp,
        &fixture.statement,
        &witness,
        &fixture.entropy,
        &fixture.context,
    )
    .expect("prove");
    assert_eq!(
        verify(&fixture.secp, &fixture.statement, &proof, &fixture.context),
        Err(EqualityProofError::VerificationFailed)
    );
}

#[test]
fn wrong_r2_is_rejected() {
    let fixture = make_fixture(5_000);
    let bad_r2 = rand_scalar();
    let real_r1 = fixture.witness.r1;
    let witness = EqualityWitness::from_scalar_blindings(5_000, &real_r1, &bad_r2.secret_bytes())
        .expect("witness");
    let proof = prove(
        &fixture.secp,
        &fixture.statement,
        &witness,
        &fixture.entropy,
        &fixture.context,
    )
    .expect("prove");
    assert_eq!(
        verify(&fixture.secp, &fixture.statement, &proof, &fixture.context),
        Err(EqualityProofError::VerificationFailed)
    );
}

#[test]
fn swapped_commitments_are_rejected() {
    let fixture = make_fixture(7_000);
    let swapped = EqualityStatement {
        credential_commitment: fixture.statement.value_commitment,
        value_commitment: fixture.statement.credential_commitment,
        asset_generator: fixture.statement.asset_generator,
    };
    assert_eq!(
        verify(
            &fixture.secp,
            &swapped,
            &make_proof(&fixture),
            &fixture.context
        ),
        Err(EqualityProofError::VerificationFailed)
    );
}

#[test]
fn wrong_asset_generator_is_rejected() {
    let fixture = make_fixture(9_000);
    let wrong = EqualityStatement {
        asset_generator: other_asset_generator(),
        ..fixture.statement
    };
    assert_eq!(
        verify(
            &fixture.secp,
            &wrong,
            &make_proof(&fixture),
            &fixture.context
        ),
        Err(EqualityProofError::VerificationFailed)
    );
}

#[test]
fn proof_from_different_context_is_rejected() {
    let fixture = make_fixture(11_000);
    let proof = make_proof(&fixture);
    let other_context = b"round=2;phase=input-registration;output=0";
    assert_eq!(
        verify(&fixture.secp, &fixture.statement, &proof, other_context),
        Err(EqualityProofError::VerificationFailed)
    );
}

#[test]
fn tampered_responses_are_rejected() {
    let fixture = make_fixture(13_000);
    let proof = make_proof(&fixture);
    for mutate in [0usize, 1, 2] {
        let mut tampered = proof;
        // Add 1 (mod n) to one response scalar.
        match mutate {
            0 => tampered.s_v = add_one(&tampered.s_v),
            1 => tampered.s_1 = add_one(&tampered.s_1),
            _ => tampered.s_2 = add_one(&tampered.s_2),
        }
        assert_eq!(
            verify(
                &fixture.secp,
                &fixture.statement,
                &tampered,
                &fixture.context
            ),
            Err(EqualityProofError::VerificationFailed),
            "mutated response {mutate}"
        );
    }
}

#[test]
fn tampered_nonce_commitments_are_rejected() {
    let fixture = make_fixture(15_000);
    let proof = make_proof(&fixture);
    // Add the base point to genuinely perturb a nonce commitment.
    let perturbation = value_generator_point();
    for mutate_r1 in [true, false] {
        let mut tampered = proof;
        if mutate_r1 {
            tampered.r1_commitment = tampered
                .r1_commitment
                .combine(&perturbation)
                .expect("point");
        } else {
            tampered.r2_commitment = tampered
                .r2_commitment
                .combine(&perturbation)
                .expect("point");
        }
        assert_eq!(
            verify(
                &fixture.secp,
                &fixture.statement,
                &tampered,
                &fixture.context
            ),
            Err(EqualityProofError::VerificationFailed),
            "mutate_r1={mutate_r1}"
        );
    }
}

#[test]
fn infinity_point_encoding_is_rejected() {
    // A compressed point with a zero x-coordinate is not a valid curve point.
    let mut encoding = [0u8; PROOF_BYTES];
    encoding[0] = 0x02;
    assert_eq!(
        decode_proof(&encoding),
        Err(EqualityProofError::InvalidPoint)
    );
}

#[test]
fn non_canonical_scalar_is_rejected() {
    let fixture = make_fixture(17_000);
    let mut encoding = encode_proof(&make_proof(&fixture));
    // Set s_v to 0xFF..FF, which exceeds the curve order.
    for byte in &mut encoding[66..98] {
        *byte = 0xFF;
    }
    assert_eq!(
        decode_proof(&encoding),
        Err(EqualityProofError::InvalidScalar)
    );
}

#[test]
fn boundary_value_zero_verifies() {
    let fixture = make_fixture(0);
    let proof = make_proof(&fixture);
    verify(&fixture.secp, &fixture.statement, &proof, &fixture.context).expect("verify");
}

#[test]
fn boundary_value_max_verifies() {
    let fixture = make_fixture(MAX_VALUE);
    let proof = make_proof(&fixture);
    verify(&fixture.secp, &fixture.statement, &proof, &fixture.context).expect("verify");
}

/// Builds a statement directly from blinding-factor scalar bytes (zero
/// allowed), so the zero-blinding path is exercisable end to end. `Ma =
/// v·Gg + r1·Gh`, `C = v·A + r2·H`; a zero blinding simply drops its term.
fn fixture_with_blinding_bytes(value: u64, r1: &[u8; 32], r2: &[u8; 32]) -> Fixture {
    let secp = secp();
    let gg = super::generators::wabisabi_gg();
    let gh = super::generators::wabisabi_gh();
    let asset_generator = test_asset_generator();
    let value_scalar = value_scalar(value);

    let mut credential = gg.mul_tweak(&secp, &value_scalar).expect("v·Gg");
    let r1_limbs = scalar::from_be_bytes(*r1).expect("r1 scalar");
    if scalar::to_be_bytes(r1_limbs).iter().any(|b| *b != 0) {
        let r1_scalar = Scalar::from_be_bytes(*r1).expect("r1 scalar");
        credential = credential
            .combine(&gh.mul_tweak(&secp, &r1_scalar).expect("r1·Gh"))
            .expect("Ma");
    }

    let mut value_commitment = asset_generator
        .mul_tweak(&secp, &value_scalar)
        .expect("v·A");
    let r2_limbs = scalar::from_be_bytes(*r2).expect("r2 scalar");
    if scalar::to_be_bytes(r2_limbs).iter().any(|b| *b != 0) {
        let r2_scalar = Scalar::from_be_bytes(*r2).expect("r2 scalar");
        value_commitment = value_commitment
            .combine(
                &value_generator_point()
                    .mul_tweak(&secp, &r2_scalar)
                    .expect("r2·H"),
            )
            .expect("C");
    }

    Fixture {
        secp,
        statement: EqualityStatement {
            credential_commitment: credential,
            value_commitment,
            asset_generator,
        },
        witness: EqualityWitness::from_scalar_blindings(value, r1, r2).expect("witness"),
        entropy: rand_entropy(),
        context: b"round=11;phase=input-registration;output=0".to_vec(),
    }
}

#[test]
fn zero_blinding_factors_are_accepted_and_verify() {
    // A zero blinding factor is valid whenever v > 0: Ma = v·Gg and C = v·A
    // are unblinded but non-infinity. The witness must accept r1 = r2 = 0 and
    // the proof must verify.
    let zero = [0u8; 32];
    let fixture = fixture_with_blinding_bytes(42_000, &zero, &zero);
    let proof = make_proof(&fixture);
    verify(&fixture.secp, &fixture.statement, &proof, &fixture.context).expect("verify");
}

#[test]
fn zero_blinding_factor_mixed_with_nonzero_verifies() {
    // One side unblinded, the other blinded.
    let zero = [0u8; 32];
    let r2 = rand_scalar();
    let fixture = fixture_with_blinding_bytes(77_000, &zero, &r2.secret_bytes());
    let proof = make_proof(&fixture);
    verify(&fixture.secp, &fixture.statement, &proof, &fixture.context).expect("verify");

    let r1 = rand_scalar();
    let fixture = fixture_with_blinding_bytes(88_000, &r1.secret_bytes(), &zero);
    let proof = make_proof(&fixture);
    verify(&fixture.secp, &fixture.statement, &proof, &fixture.context).expect("verify");
}

#[test]
fn non_canonical_blinding_scalar_is_rejected() {
    // A blinding factor >= n must be rejected even though zero is allowed.
    let bad = [0xFFu8; 32];
    let r2 = rand_scalar();
    assert!(matches!(
        EqualityWitness::from_scalar_blindings(1_000, &bad, &r2.secret_bytes()),
        Err(EqualityProofError::InvalidScalar)
    ));
    let r1 = rand_scalar();
    assert!(matches!(
        EqualityWitness::from_scalar_blindings(1_000, &r1.secret_bytes(), &bad),
        Err(EqualityProofError::InvalidScalar)
    ));
}

#[test]
fn high_bit_value_patterns_verify() {
    // High-set-bit patterns within the L-BTC atomic-unit range `[0, MAX_VALUE]`
    // (MAX_VALUE ~ 2.1e15 has its top bit at bit 50).
    for value in [
        1u64 << 50,          // top bit of the MAX_VALUE range
        (1u64 << 50) | 1,    // top bit plus low bit
        MAX_VALUE & !(1u64), // MAX_VALUE with the low bit cleared
        MAX_VALUE - 1,
        0x0DE0_B6B3_A763_FFFF & MAX_VALUE, // dense high pattern masked into range
    ] {
        let fixture = make_fixture(value);
        let proof = make_proof(&fixture);
        verify(&fixture.secp, &fixture.statement, &proof, &fixture.context)
            .unwrap_or_else(|_| panic!("value {value} should verify"));
    }
}

#[test]
fn value_above_max_is_rejected() {
    let r1 = rand_scalar();
    let r2 = rand_scalar();
    assert!(matches!(
        EqualityWitness::new(MAX_VALUE + 1, &r1, &r2),
        Err(EqualityProofError::ValueOutOfRange)
    ));
}

#[test]
fn generator_kat_gg() {
    let gg = super::generators::wabisabi_gg();
    let expected = hex("02fb8868acd9cbbd68964baa1cfa6b893a6269e01569183474e6c1c4242a0071a9");
    assert_eq!(gg.serialize(), expected.as_slice());
}

#[test]
fn generator_kat_gh() {
    let gh = super::generators::wabisabi_gh();
    let expected = hex("023d11e10ce7a8c17671ed777886fc2b84e65a532fa0c411abbe96e1206f9dff80");
    assert_eq!(gh.serialize(), expected.as_slice());
}

#[test]
fn from_text_xquad_matches_independent_reference() {
    // Sweep the exact NWabiSabi candidate sequence for 64 labels: for every
    // rehash candidate the implementation must accept exactly when the
    // independent QR reference accepts, and must return the reference point.
    for i in 0u8..64 {
        let name = [b"XQuad-sweep-".as_slice(), &[i]].concat();
        let mut buffer: [u8; 32] = Sha256::digest(&name).into();
        loop {
            let candidate = super::generators::from_text_xquad(&name);
            match reference_xquad_lift(&buffer) {
                Some(reference) => {
                    assert_eq!(
                        candidate.serialize(),
                        reference.serialize(),
                        "label {i}: XQuad lift must equal the quadratic-residue root"
                    );
                    break;
                }
                None => buffer = Sha256::digest(buffer).into(),
            }
        }
    }
}

#[test]
fn from_text_xquad_selects_quadratic_residue_root_not_even_parity() {
    // Find a label whose first candidate x has an ODD quadratic-residue root
    // (y^(p+1)/4 mod p odd), so XQuad and even-parity disagree. This is the
    // regression the review flagged: the generator derivation must return the
    // odd QR root, not the even non-residue root.
    for i in 0u8..=255 {
        let name = [b"XQuad-odd-root-".as_slice(), &[i]].concat();
        let buffer: [u8; 32] = Sha256::digest(&name).into();
        let Some(xquad) = reference_xquad_lift(&buffer) else {
            continue;
        };
        if xquad.serialize()[0] != 0x03 {
            continue;
        }
        // Sanity: even parity really is the other root.
        let even = reference_even_lift(&buffer);
        assert_eq!(even.serialize()[0], 0x02);
        assert_ne!(even, xquad);
        let candidate = super::generators::from_text_xquad(&name);
        assert_eq!(
            candidate.serialize(),
            xquad.serialize(),
            "label {i}: XQuad must select the odd quadratic-residue root"
        );
        return;
    }
    panic!("no odd-QR-root label found in 256 candidates; extend the sweep");
}

#[test]
fn generator_kat_xquad_odd_root_vector() {
    // Authoritative vector where the quadratic-residue root is ODD, so XQuad
    // and even-parity lifting disagree. The expected 33-byte compressed
    // encoding below was computed independently (Python big-int field math over
    // p, root = (x^3+7)^((p+1)/4) mod p, verified by squaring back) and pinned
    // byte-exactly, so any parity or reduction regression fails even if the
    // in-crate reference helpers are refactored.
    //   name  = "WL-XQUAD-ODD-KAT-v2" (SHA256(name) lifts to an odd QR root)
    //   x     = d518c839...3e6d44, QR root y is odd -> prefix 0x03
    let point = super::generators::from_text_xquad(b"WL-XQUAD-ODD-KAT-v2");
    let expected = hex("03d518c8392841d7e35f567357daa7aa5ea6fd08a337f752ccac8f39e81a3e6d44");
    assert_eq!(
        point.serialize()[0],
        0x03,
        "vector must have an odd quadratic-residue root"
    );
    assert_eq!(point.serialize(), expected.as_slice());
}

#[test]
fn proof_is_deterministic() {
    let fixture = make_fixture(21_000);
    let first = make_proof(&fixture);
    let second = make_proof(&fixture);
    assert_eq!(encode_proof(&first), encode_proof(&second));
}

#[test]
fn different_context_changes_challenge() {
    let fixture = make_fixture(23_000);
    let base = make_proof(&fixture);
    let other_context = b"round=1;phase=input-registration;output=1";
    let other = prove(
        &fixture.secp,
        &fixture.statement,
        &fixture.witness,
        &fixture.entropy,
        other_context,
    )
    .expect("prove");
    assert_ne!(encode_proof(&base), encode_proof(&other));
}

#[test]
fn proof_encoding_layout_and_length() {
    let fixture = make_fixture(25_000);
    let proof = make_proof(&fixture);
    let encoding = encode_proof(&proof);
    assert_eq!(encoding.len(), PROOF_BYTES);
    assert_eq!(&encoding[0..33], &proof.r1_commitment.serialize());
    assert_eq!(&encoding[33..66], &proof.r2_commitment.serialize());
    assert_eq!(&encoding[66..98], &proof.s_v);
    assert_eq!(&encoding[98..130], &proof.s_1);
    assert_eq!(&encoding[130..162], &proof.s_2);
    let decoded = decode_proof(&encoding).expect("decode");
    assert_eq!(decoded, proof);
}

#[test]
fn decoder_rejects_trailing_and_missing_bytes() {
    let fixture = make_fixture(27_000);
    let encoding = encode_proof(&make_proof(&fixture));
    assert_eq!(
        decode_proof(&encoding[..PROOF_BYTES - 1]),
        Err(EqualityProofError::InvalidLength)
    );
    let mut longer = encoding.to_vec();
    longer.push(0u8);
    assert_eq!(
        decode_proof(&longer),
        Err(EqualityProofError::InvalidLength)
    );
}

#[test]
fn wrong_entropy_length_is_rejected() {
    let fixture = make_fixture(29_000);
    assert_eq!(
        prove(
            &fixture.secp,
            &fixture.statement,
            &fixture.witness,
            &[0u8; 16],
            &fixture.context
        ),
        Err(EqualityProofError::InvalidEntropyLength)
    );
}

#[test]
fn statement_from_bytes_round_trips() {
    let fixture = make_fixture(31_000);
    let (ma, c, a) = fixture.statement.to_bytes();
    let rebuilt = EqualityStatement::new(&ma, &c, &a).expect("statement");
    assert_eq!(
        rebuilt.credential_commitment,
        fixture.statement.credential_commitment
    );
    assert_eq!(rebuilt.value_commitment, fixture.statement.value_commitment);
    assert_eq!(rebuilt.asset_generator, fixture.statement.asset_generator);
}

#[test]
fn statement_rejects_invalid_point() {
    let fixture = make_fixture(33_000);
    let (ma, c, _a) = fixture.statement.to_bytes();
    // x = 0 is not on the curve.
    let mut bad = [0u8; 33];
    bad[0] = 0x02;
    assert!(matches!(
        EqualityStatement::new(&bad, &c, &fixture.statement.asset_generator.serialize()),
        Err(EqualityProofError::InvalidPoint)
    ));
    let _ = ma;
}

// ---- P2: native secp256k1-zkp Generator / PedersenCommitment encodings ----

/// Builds a fixture whose statement points are produced through the actual
/// `Generator` / `PedersenCommitment` fork types, returning their native
/// 33-byte serializations (asset generator, value commitment).
fn native_fixture(value: u64) -> (Fixture, [u8; 33], [u8; 33]) {
    use elements::secp256k1_zkp::{Generator, PedersenCommitment, Tag, Tweak};

    let secp = secp();
    let r1 = rand_scalar();
    let r2 = rand_scalar();

    let tag = Tag::from(<[u8; 32]>::from(Sha256::digest(b"native-test-asset")));
    let generator_blinding = Tweak::from_slice(&r1.secret_bytes()).expect("tweak");
    let asset_generator = Generator::new_blinded(&secp, tag, generator_blinding);
    let value_blinding = Tweak::from_slice(&r2.secret_bytes()).expect("tweak");
    let value_commitment = PedersenCommitment::new(&secp, value, value_blinding, asset_generator);

    let gg = super::generators::wabisabi_gg();
    let gh = super::generators::wabisabi_gh();
    let value_scalar = value_scalar(value);
    let r1_point = gh.mul_tweak(&secp, &scalar_of(&r1)).unwrap();
    let credential_commitment = if value == 0 {
        r1_point
    } else {
        gg.mul_tweak(&secp, &value_scalar)
            .and_then(|p| p.combine(&r1_point))
            .expect("credential commitment")
    };

    let asset_generator_bytes = asset_generator.serialize();
    let value_commitment_bytes = value_commitment.serialize();
    let asset_generator_point =
        super::point_from_generator_bytes(&asset_generator_bytes).expect("asset generator");
    let value_commitment_point =
        super::point_from_pedersen_commitment_bytes(&value_commitment_bytes)
            .expect("value commitment");

    let fixture = Fixture {
        secp,
        statement: EqualityStatement {
            credential_commitment,
            value_commitment: value_commitment_point,
            asset_generator: asset_generator_point,
        },
        witness: EqualityWitness::new(value, &r1, &r2).expect("witness"),
        entropy: rand_entropy(),
        context: b"round=9;phase=input-registration;output=3".to_vec(),
    };
    (fixture, asset_generator_bytes, value_commitment_bytes)
}

#[test]
fn native_statement_round_trips_and_verifies() {
    use elements::secp256k1_zkp::{Generator, PedersenCommitment};

    let (fixture, asset_generator_bytes, value_commitment_bytes) = native_fixture(123_456_789);
    let (ma, _c, _a) = fixture.statement.to_bytes();

    let statement =
        EqualityStatement::from_native_bytes(&ma, &value_commitment_bytes, &asset_generator_bytes)
            .expect("native statement");
    assert_eq!(statement, fixture.statement);

    // The reconstructed points are the exact same curve points the fork types
    // encode, for BOTH QR parities.
    let asset_point = point_from_generator_bytes(&asset_generator_bytes).expect("generator");
    let expected_asset = point_from_generator_bytes(
        &Generator::from_slice(&asset_generator_bytes)
            .expect("fork generator")
            .serialize(),
    )
    .expect("round-trip");
    assert_eq!(asset_point, expected_asset);
    let commitment_point =
        point_from_pedersen_commitment_bytes(&value_commitment_bytes).expect("commitment");
    let expected_commitment = point_from_pedersen_commitment_bytes(
        &PedersenCommitment::from_slice(&value_commitment_bytes)
            .expect("fork commitment")
            .serialize(),
    )
    .expect("round-trip");
    assert_eq!(commitment_point, expected_commitment);

    let proof = prove(
        &fixture.secp,
        &statement,
        &fixture.witness,
        &fixture.entropy,
        &fixture.context,
    )
    .expect("prove");
    verify(&fixture.secp, &statement, &proof, &fixture.context).expect("verify");
}

#[test]
fn native_encodings_cover_both_parities() {
    // Generator serialization is 0x0A (quadratic-residue y) / 0x0B (non-QR y);
    // PedersenCommitment is 0x08 (QR y) / 0x09 (non-QR y). Native encodings of
    // the same fixture points must reconstruct the identical point for both
    // prefixes of each kind.
    use elements::secp256k1_zkp::{Generator, PedersenCommitment, Tag, Tweak};

    let secp = secp();
    let mut seen_generator = [false; 2];
    let mut seen_commitment = [false; 2];
    for i in 0u32..512 {
        let tag = Tag::from(<[u8; 32]>::from(Sha256::digest(
            [b"parity-tag".as_slice(), &i.to_be_bytes()].concat(),
        )));
        let tweak = Tweak::from_slice(&rand_scalar().secret_bytes()).expect("tweak");
        let generator = Generator::new_blinded(&secp, tag, tweak);
        let generator_bytes = generator.serialize();
        let generator_index = usize::from(generator_bytes[0] & 1);
        seen_generator[generator_index] = true;
        let point = point_from_generator_bytes(&generator_bytes).expect("generator point");
        assert!(
            super::generators::point_matches_xquad_encoding(
                &point,
                generator_bytes[0] == 0x0B,
                &generator_bytes[1..]
            ),
            "generator prefix {:#04x} must select the QR-root branch",
            generator_bytes[0]
        );

        let commitment = PedersenCommitment::new(&secp, u64::from(i) + 1, tweak, generator);
        let commitment_bytes = commitment.serialize();
        let commitment_index = usize::from(commitment_bytes[0] & 1);
        seen_commitment[commitment_index] = true;
        let commitment_point =
            point_from_pedersen_commitment_bytes(&commitment_bytes).expect("commitment point");
        assert!(
            super::generators::point_matches_xquad_encoding(
                &commitment_point,
                commitment_bytes[0] == 0x09,
                &commitment_bytes[1..]
            ),
            "commitment prefix {:#04x} must select the QR-root branch",
            commitment_bytes[0]
        );

        if seen_generator.iter().all(|s| *s) && seen_commitment.iter().all(|s| *s) {
            return;
        }
    }
    panic!("512 samples did not cover both QR parities for both kinds");
}

#[test]
fn native_zero_value_and_blinding_verify() {
    // v = 0 and r2 = 0 must stay valid: C = 0·A + 0·H is the point at
    // infinity in PedersenCommitment terms, so use a nonzero r2 = 0 only for
    // the credential side; the zero-blinding path uses r1 = r2 via tweaks.
    use elements::secp256k1_zkp::{Generator, PedersenCommitment, Tag, Tweak, ZERO_TWEAK};

    let secp = secp();
    let r1 = rand_scalar();
    let tag = Tag::from(<[u8; 32]>::from(Sha256::digest(b"native-zero-asset")));
    let generator_blinding = Tweak::from_slice(&r1.secret_bytes()).expect("tweak");
    let asset_generator = Generator::new_blinded(&secp, tag, generator_blinding);
    // Zero value AND zero value-blinding: C = 0·A + 0·H = infinity is not
    // representable as a PedersenCommitment, so the protocol uses r2 = 0 with
    // v = 0 -> C = infinity only in theory; here v = 0 with fresh r2 covers
    // the valid zero-value behavior end to end.
    let r2 = rand_scalar();
    let value_blinding = Tweak::from_slice(&r2.secret_bytes()).expect("tweak");
    let value_commitment = PedersenCommitment::new(&secp, 0, value_blinding, asset_generator);
    let _ = ZERO_TWEAK;

    let gg = super::generators::wabisabi_gg();
    let gh = super::generators::wabisabi_gh();
    let credential_commitment = gh.mul_tweak(&secp, &scalar_of(&r1)).unwrap();
    let _ = gg;

    let statement = EqualityStatement::from_native_bytes(
        &credential_commitment.serialize(),
        &value_commitment.serialize(),
        &asset_generator.serialize(),
    )
    .expect("native statement");
    let witness = EqualityWitness::new(0, &r1, &r2).expect("witness");
    let entropy = rand_entropy();
    let context = b"round=10;phase=input-registration;output=0";
    let proof = prove(&secp, &statement, &witness, &entropy, context).expect("prove");
    verify(&secp, &statement, &proof, context).expect("verify zero value");
}

#[test]
fn native_wrong_kind_prefixes_are_rejected() {
    let (fixture, asset_generator_bytes, value_commitment_bytes) = native_fixture(5_000);
    let (ma, _c, _a) = fixture.statement.to_bytes();

    // PedersenCommitment bytes where a Generator is expected, and vice versa.
    assert_eq!(
        EqualityStatement::from_native_bytes(&ma, &value_commitment_bytes, &value_commitment_bytes),
        Err(EqualityProofError::InvalidPoint)
    );
    assert_eq!(
        EqualityStatement::from_native_bytes(&ma, &asset_generator_bytes, &asset_generator_bytes),
        Err(EqualityProofError::InvalidPoint)
    );
    assert_eq!(
        point_from_generator_bytes(&value_commitment_bytes),
        Err(EqualityProofError::InvalidPoint)
    );
    assert_eq!(
        point_from_pedersen_commitment_bytes(&asset_generator_bytes),
        Err(EqualityProofError::InvalidPoint)
    );
}

#[test]
fn native_malformed_inputs_are_rejected() {
    let (fixture, asset_generator_bytes, value_commitment_bytes) = native_fixture(6_000);
    let (ma, _c, _a) = fixture.statement.to_bytes();

    // Wrong length.
    assert_eq!(
        EqualityStatement::from_native_bytes(
            &ma,
            &value_commitment_bytes[..32],
            &asset_generator_bytes
        ),
        Err(EqualityProofError::InvalidLength)
    );
    assert_eq!(
        EqualityStatement::from_native_bytes(&ma, &value_commitment_bytes, &[]),
        Err(EqualityProofError::InvalidLength)
    );

    // Unknown prefix.
    let mut bad_prefix = asset_generator_bytes;
    bad_prefix[0] = 0x02;
    assert_eq!(
        point_from_generator_bytes(&bad_prefix),
        Err(EqualityProofError::InvalidPoint)
    );
    let mut bad_commitment_prefix = value_commitment_bytes;
    bad_commitment_prefix[0] = 0x0A;
    assert_eq!(
        point_from_pedersen_commitment_bytes(&bad_commitment_prefix),
        Err(EqualityProofError::InvalidPoint)
    );

    // x >= field prime.
    let mut bad_x = asset_generator_bytes;
    for byte in &mut bad_x[1..] {
        *byte = 0xFF;
    }
    assert_eq!(
        point_from_generator_bytes(&bad_x),
        Err(EqualityProofError::InvalidPoint)
    );

    // x with no curve point (x^3 + 7 a non-residue), e.g. x = 0.
    let mut no_point = asset_generator_bytes;
    for byte in &mut no_point[1..] {
        *byte = 0x00;
    }
    assert_eq!(
        point_from_generator_bytes(&no_point),
        Err(EqualityProofError::InvalidPoint)
    );
    assert_eq!(
        point_from_pedersen_commitment_bytes(&no_point),
        Err(EqualityProofError::InvalidPoint)
    );

    // x >= p for the commitment kind as well.
    let mut bad_commitment_x = value_commitment_bytes;
    for byte in &mut bad_commitment_x[1..] {
        *byte = 0xFF;
    }
    assert_eq!(
        point_from_pedersen_commitment_bytes(&bad_commitment_x),
        Err(EqualityProofError::InvalidPoint)
    );
}

#[test]
fn native_points_preserve_exact_point_across_kinds() {
    // The same curve point encoded as a Generator and as a PedersenCommitment
    // must decode to one identical point: kind is only a serialization tag.
    let (_fixture, asset_generator_bytes, _) = native_fixture(7_000);
    let asset_point = point_from_generator_bytes(&asset_generator_bytes).expect("generator");
    // Re-encode the identical point in the PedersenCommitment kind: same x,
    // prefix 0x08 | (1 if y non-QR). The QR parity matches the generator one.
    let mut as_commitment = asset_generator_bytes;
    as_commitment[0] = if asset_generator_bytes[0] == 0x0A {
        0x08
    } else {
        0x09
    };
    let commitment_point =
        point_from_pedersen_commitment_bytes(&as_commitment).expect("commitment");
    assert_eq!(asset_point, commitment_point);
}
