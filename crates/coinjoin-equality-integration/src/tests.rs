use std::collections::HashMap;

use super::*;
use elements::{
    CtLocation, CtLocationType, OutPoint, Script, Txid,
    bitcoin::PublicKey as BitcoinPublicKey,
    confidential::{AssetBlindingFactor, Nonce, RangeProof, SurjectionProof, ValueBlindingFactor},
    encode,
    pset::{Input, Output},
    secp256k1_zkp::{Generator, PedersenCommitment, PublicKey, Scalar, SecretKey},
};
use rand::{SeedableRng, rngs::StdRng};
use wasabi_liquid_native_coinjoin_pset_state::{CanonicalStateContext, canonicalize_pset_state};
use wasabi_liquid_native_credential_commitment_equality::PROOF_BYTES;

const NETWORK: &[u8] = b"elements-liquid-mainnet";
const ROUND: &[u8] = b"round-equality-0001";
const GENESIS: [u8; 32] = [0x22; 32];
const SEED: u64 = 0x5eed_5eed_e0a1_0001;

/// WabiSabi NUMS generator `Gg`, pinned by the credential crate's
/// known-answer test (`generator_kat_gg`).
const WABISABI_GG_BYTES: [u8; 33] = [
    0x02, 0xfb, 0x88, 0x68, 0xac, 0xd9, 0xcb, 0xbd, 0x68, 0x96, 0x4b, 0xaa, 0x1c, 0xfa, 0x6b, 0x89,
    0x3a, 0x62, 0x69, 0xe0, 0x15, 0x69, 0x18, 0x34, 0x74, 0xe6, 0xc1, 0xc4, 0x24, 0x2a, 0x00, 0x71,
    0xa9,
];
/// WabiSabi NUMS generator `Gh`, pinned by the credential crate's
/// known-answer test (`generator_kat_gh`).
const WABISABI_GH_BYTES: [u8; 33] = [
    0x02, 0x3d, 0x11, 0xe1, 0x0c, 0xe7, 0xa8, 0xc1, 0x76, 0x71, 0xed, 0x77, 0x78, 0x86, 0xfc, 0x2b,
    0x84, 0xe6, 0x5a, 0x53, 0x2f, 0xa0, 0xc4, 0x11, 0xab, 0xbe, 0x96, 0xe1, 0x20, 0x6f, 0x9d, 0xff,
    0x80,
];

fn asset() -> elements::AssetId {
    elements::AssetId::from_byte_array([0x11; 32])
}

fn canonical_state_context() -> CanonicalStateContext<'static> {
    CanonicalStateContext {
        profile: ProfileVersion::V1,
        network_identity: NETWORK,
        genesis_hash: GENESIS,
        lbtc_asset: asset(),
        fee_asset: asset(),
        round_id: ROUND,
        phase: Phase::Construction,
        participant_role: ParticipantRole::Initiator,
        contribution_ordinal: 1,
        predecessor: wasabi_liquid_native_coinjoin_pset_state::PredecessorDigest::Absent,
    }
}

fn registration_context(
    kind: RegistrationKind,
    element_index: u32,
    pset_state_digest: [u8; 32],
    output_proof_binding: Option<OutputProofBinding<'static>>,
) -> RegistrationContext<'static> {
    RegistrationContext {
        profile: ProfileVersion::V1,
        network_identity: NETWORK,
        genesis_hash: GENESIS,
        lbtc_asset: asset(),
        round_id: ROUND,
        phase: Phase::Construction,
        participant_role: ParticipantRole::Initiator,
        contribution_ordinal: 1,
        kind,
        element_index,
        pset_state_digest,
        output_proof_binding,
    }
}

fn clone_context(base: &RegistrationContext<'static>) -> RegistrationContext<'static> {
    registration_context(
        base.kind,
        base.element_index,
        base.pset_state_digest,
        base.output_proof_binding,
    )
}

fn blinding_key(byte: u8) -> BitcoinPublicKey {
    let secp = Secp256k1::new();
    BitcoinPublicKey::new(
        SecretKey::from_slice(&[byte; 32])
            .unwrap()
            .public_key(&secp),
    )
}

fn p2wpkh_script(tag: u8) -> Script {
    let mut bytes = vec![0x00, 0x14];
    bytes.extend_from_slice(&[tag; 20]);
    Script::from(bytes)
}

fn scalar_of(key: &SecretKey) -> Scalar {
    Scalar::from_be_bytes(key.secret_bytes()).expect("secret keys are valid scalars")
}

fn value_scalar(value: u64) -> Scalar {
    let mut bytes = [0u8; 32];
    bytes[24..].copy_from_slice(&value.to_be_bytes());
    Scalar::from_be_bytes(bytes).expect("u64 values are valid scalars")
}

/// Builds the genuine WabiSabi amount commitment `Ma = v·Gg + r1·Gh` for the
/// fixture value and WabiSabi blinding factor, from the credential crate's
/// KAT-pinned NUMS generators.
fn credential_commitment(secp: &Secp256k1<All>, value: u64, r1: &SecretKey) -> PublicKey {
    let gg = PublicKey::from_slice(&WABISABI_GG_BYTES).unwrap();
    let gh = PublicKey::from_slice(&WABISABI_GH_BYTES).unwrap();
    gg.mul_tweak(secp, &value_scalar(value))
        .unwrap()
        .combine(&gh.mul_tweak(secp, &scalar_of(r1)).unwrap())
        .unwrap()
}

/// Real cryptographic material for one round: confidential witness UTXOs and
/// fully blinded outputs, produced through the same seeded fork blinding path
/// as the collab-blinding fixtures, with the blinded output blinding factors
/// recovered from the fork's return value so output witnesses are genuine.
struct Fixture {
    /// Final blinded PSET: revision R1.
    pset: PartiallySignedTransaction,
    /// A second genuine revision (different fee), same round context.
    pset_v2: PartiallySignedTransaction,
    /// Canonical state digest of revision R1.
    digest: [u8; 32],
    /// Canonical state digest of revision R2.
    digest_v2: [u8; 32],
    /// Per-input `(asset_bf, value_bf)` of the confidential witness UTXOs.
    input_blindings: Vec<(AssetBlindingFactor, ValueBlindingFactor)>,
    /// Per-output `(asset_bf, value_bf)` recovered from the blinding call.
    output_blindings: Vec<(AssetBlindingFactor, ValueBlindingFactor)>,
    input_values: [u64; 2],
    output_values: [u64; 2],
}

/// Builds the unblinded shape: confidential witness UTXOs (with the asset and
/// in-utxo range proofs the canonical V1 profile requires), two preblind
/// outputs, and one explicit fee with the caller's value.
fn unblinded_pset(
    input_values: &[u64; 2],
    input_blindings: &[(AssetBlindingFactor, ValueBlindingFactor)],
    output_values: &[u64; 2],
    fee: u64,
) -> (
    PartiallySignedTransaction,
    HashMap<usize, elements::TxOutSecrets>,
) {
    let secp = Secp256k1::new();
    let mut rng = StdRng::seed_from_u64(SEED ^ 0xb000);
    let mut pset = PartiallySignedTransaction::new_v2();
    let mut input_secrets = HashMap::new();
    for (tag, value) in input_values.iter().enumerate() {
        let tag = tag as u8;
        let (asset_bf, value_bf) = input_blindings[usize::from(tag)];
        let generator = Generator::new_blinded(&secp, asset().into_tag(), asset_bf.into_inner());
        let commitment = PedersenCommitment::new(&secp, *value, value_bf.into_inner(), generator);
        let mut input = Input::from_prevout(OutPoint::new(
            Txid::from_byte_array([0x30 + tag; 32]),
            u32::from(tag),
        ));
        input.witness_utxo = Some(TxOut {
            asset: Asset::Confidential(generator),
            value: Value::Confidential(commitment),
            nonce: Nonce::Confidential(blinding_key(7 + tag).inner),
            script_pubkey: p2wpkh_script(tag),
            witness: Default::default(),
        });
        input.asset = Some(asset());
        input.blind_asset_proof =
            Some(SurjectionProof::blind_asset_proof(&mut rng, &secp, asset(), asset_bf).unwrap());
        input.in_utxo_rangeproof = Some(
            RangeProof::new(
                &secp,
                1,
                commitment,
                *value,
                value_bf.into_inner(),
                &[],
                p2wpkh_script(tag).as_bytes(),
                SecretKey::new(&mut rng),
                0,
                52,
                generator,
            )
            .unwrap(),
        );
        pset.add_input(input);
        input_secrets.insert(
            usize::from(tag),
            elements::TxOutSecrets::new(asset(), asset_bf, *value, value_bf),
        );
    }
    for (index, value) in output_values.iter().enumerate() {
        let mut output = Output::new_explicit(
            p2wpkh_script(0x40 + index as u8),
            *value,
            asset(),
            Some(blinding_key(3 + index as u8)),
        );
        output.blinder_index = Some(index as u32);
        pset.add_output(output);
    }
    pset.add_output(Output::new_explicit(Script::new(), fee, asset(), None));
    (pset, input_secrets)
}

fn build_revision(
    input_values: &[u64; 2],
    input_blindings: &[(AssetBlindingFactor, ValueBlindingFactor)],
    output_values: &[u64; 2],
    fee: u64,
    seed: u64,
) -> (
    PartiallySignedTransaction,
    [u8; 32],
    Vec<(AssetBlindingFactor, ValueBlindingFactor)>,
) {
    let secp = Secp256k1::new();
    let (mut pset, input_secrets) =
        unblinded_pset(input_values, input_blindings, output_values, fee);
    let mut rng = StdRng::seed_from_u64(seed);
    let blinding = pset
        .blind_last_with_all_surjection_inputs(&mut rng, &secp, &input_secrets, &[0, 1])
        .expect("seeded fixture blinding must succeed");
    let mut output_blindings = Vec::new();
    for index in 0..output_values.len() {
        let (asset_bf, value_bf, _nonce) = blinding
            .get(&CtLocation {
                input_index: index,
                ty: CtLocationType::Input,
            })
            .copied()
            .expect("blinding returns factors for every confidential output");
        output_blindings.push((asset_bf, value_bf));
    }
    let raw = encode::serialize(&pset);
    let digest = canonicalize_pset_state(&raw, &canonical_state_context())
        .expect("fixture revision must pass canonical validation")
        .digest()
        .into_bytes();
    (pset, digest, output_blindings)
}

fn build_fixture() -> Fixture {
    let input_values = [5_000u64, 4_000u64];
    let output_values = [3_500u64, 4_400u64];
    let mut input_blindings = Vec::new();
    for tag in 0u8..2 {
        let mut rng = StdRng::seed_from_u64(SEED ^ 0xa000 ^ u64::from(tag));
        input_blindings.push((
            AssetBlindingFactor::new(&mut rng),
            ValueBlindingFactor::new(&mut rng),
        ));
    }
    let (pset, digest, output_blindings) =
        build_revision(&input_values, &input_blindings, &output_values, 1_100, SEED);
    let (pset_v2, digest_v2, _) = build_revision(
        &input_values,
        &input_blindings,
        &output_values,
        1_101,
        SEED ^ 0x00ff,
    );
    assert_ne!(digest, digest_v2);
    Fixture {
        pset,
        pset_v2,
        digest,
        digest_v2,
        input_blindings,
        output_blindings,
        input_values,
        output_values,
    }
}

/// A genuine (statement, proof, context) input-registration triple plus the
/// witness that produced it, from the fixture's first confidential witness
/// UTXO.
struct InputTriple {
    statement: EqualityStatement,
    witness_r1: SecretKey,
    proof_bytes: [u8; PROOF_BYTES],
    context: RegistrationContext<'static>,
}

fn input_triple(fixture: &Fixture) -> InputTriple {
    let secp = Secp256k1::new();
    let utxo = fixture.pset.inputs()[0].witness_utxo.as_ref().unwrap();
    let value = fixture.input_values[0];
    let (_asset_bf, value_bf) = fixture.input_blindings[0];
    let r1 = SecretKey::from_slice(&[0x51; 32]).unwrap();
    let r2 = SecretKey::from_slice(value_bf.into_inner().as_ref()).unwrap();
    let ma = credential_commitment(&secp, value, &r1);
    let statement = input_registration_statement(&ma.serialize(), utxo)
        .expect("confidential witness UTXO must yield a statement");
    let witness = EqualityWitness::new(value, &r1, &r2).unwrap();
    let context =
        registration_context(RegistrationKind::InputRegistration, 0, fixture.digest, None);
    let proof = prove_registration(&secp, &witness, &statement, &context, &[0x77; 32])
        .expect("genuine fixture proof must succeed");
    InputTriple {
        statement,
        witness_r1: r1,
        proof_bytes: wasabi_liquid_native_credential_commitment_equality::encode_proof(&proof),
        context,
    }
}

/// A genuine (statement, proof, context) output-registration triple from the
/// fixture's first blinded output.
struct OutputTriple {
    statement: EqualityStatement,
    proof_bytes: [u8; PROOF_BYTES],
    context: RegistrationContext<'static>,
}

fn output_proof_binding(
    pset: &PartiallySignedTransaction,
    index: usize,
) -> OutputProofBinding<'static> {
    let output = &pset.outputs()[index];
    OutputProofBinding {
        value_rangeproof: Box::leak(
            output
                .value_rangeproof
                .as_ref()
                .expect("blinded output carries a rangeproof")
                .to_vec()
                .into_boxed_slice(),
        ),
        asset_surjection_proof: Box::leak(
            output
                .asset_surjection_proof
                .as_ref()
                .expect("blinded output carries a surjection proof")
                .to_vec()
                .into_boxed_slice(),
        ),
    }
}

fn output_triple(fixture: &Fixture) -> OutputTriple {
    let secp = Secp256k1::new();
    let value = fixture.output_values[0];
    let (_asset_bf, value_bf) = fixture.output_blindings[0];
    let r1 = SecretKey::from_slice(&[0x61; 32]).unwrap();
    let r2 = SecretKey::from_slice(value_bf.into_inner().as_ref()).unwrap();
    let ma = credential_commitment(&secp, value, &r1);
    let statement = output_registration_statement(&ma.serialize(), &fixture.pset, 0)
        .expect("blinded output must yield a statement");
    let witness = EqualityWitness::new(value, &r1, &r2).unwrap();
    let context = registration_context(
        RegistrationKind::OutputRegistration,
        0,
        fixture.digest,
        Some(output_proof_binding(&fixture.pset, 0)),
    );
    let proof = prove_registration(&secp, &witness, &statement, &context, &[0x88; 32])
        .expect("genuine fixture proof must succeed");
    OutputTriple {
        statement,
        proof_bytes: wasabi_liquid_native_credential_commitment_equality::encode_proof(&proof),
        context,
    }
}

/// Mutates `context` in exactly one domain component and asserts the genuine
/// proof fails verification under it.
fn assert_replay_fails(
    secp: &Secp256k1<All>,
    statement: &EqualityStatement,
    proof_bytes: &[u8],
    base: &RegistrationContext<'static>,
    mutate: impl FnOnce(&mut RegistrationContext<'static>),
) {
    let mut mutated = clone_context(base);
    mutate(&mut mutated);
    assert_eq!(
        verify_registration(secp, statement, proof_bytes, &mutated),
        Err(Error::VerificationFailed),
    );
}

#[test]
fn input_registration_genuine_proof_verifies() {
    let fixture = build_fixture();
    let triple = input_triple(&fixture);
    let secp = Secp256k1::new();
    verify_registration(
        &secp,
        &triple.statement,
        &triple.proof_bytes,
        &triple.context,
    )
    .expect("genuine input registration proof must verify");
}

#[test]
fn input_registration_anti_replay_matrix() {
    let fixture = build_fixture();
    let triple = input_triple(&fixture);
    let secp = Secp256k1::new();
    verify_registration(
        &secp,
        &triple.statement,
        &triple.proof_bytes,
        &triple.context,
    )
    .unwrap();

    assert_replay_fails(
        &secp,
        &triple.statement,
        &triple.proof_bytes,
        &triple.context,
        |c| {
            c.round_id = b"round-equality-0002";
        },
    );
    assert_replay_fails(
        &secp,
        &triple.statement,
        &triple.proof_bytes,
        &triple.context,
        |c| {
            c.network_identity = b"elements-liquid-testnet";
        },
    );
    assert_replay_fails(
        &secp,
        &triple.statement,
        &triple.proof_bytes,
        &triple.context,
        |c| {
            c.genesis_hash = [0x33; 32];
        },
    );
    assert_replay_fails(
        &secp,
        &triple.statement,
        &triple.proof_bytes,
        &triple.context,
        |c| {
            c.lbtc_asset = elements::AssetId::from_byte_array([0x99; 32]);
        },
    );
    assert_replay_fails(
        &secp,
        &triple.statement,
        &triple.proof_bytes,
        &triple.context,
        |c| {
            c.participant_role = ParticipantRole::Responder;
        },
    );
    assert_replay_fails(
        &secp,
        &triple.statement,
        &triple.proof_bytes,
        &triple.context,
        |c| {
            c.kind = RegistrationKind::OutputRegistration;
            c.output_proof_binding = Some(output_proof_binding(&fixture.pset, 0));
        },
    );
    assert_replay_fails(
        &secp,
        &triple.statement,
        &triple.proof_bytes,
        &triple.context,
        |c| {
            c.contribution_ordinal = 2;
        },
    );
    assert_replay_fails(
        &secp,
        &triple.statement,
        &triple.proof_bytes,
        &triple.context,
        |c| {
            c.element_index = 1;
        },
    );
    // A second genuine revision's digest binds a different PSET state.
    assert_replay_fails(
        &secp,
        &triple.statement,
        &triple.proof_bytes,
        &triple.context,
        |c| {
            c.pset_state_digest = fixture.digest_v2;
        },
    );
    assert_replay_fails(
        &secp,
        &triple.statement,
        &triple.proof_bytes,
        &triple.context,
        |c| {
            c.phase = Phase::Proofs;
        },
    );
}

#[test]
fn output_registration_genuine_proof_verifies() {
    let fixture = build_fixture();
    let triple = output_triple(&fixture);
    let secp = Secp256k1::new();
    verify_registration(
        &secp,
        &triple.statement,
        &triple.proof_bytes,
        &triple.context,
    )
    .expect("genuine output registration proof must verify");
}

#[test]
fn output_registration_anti_replay_matrix() {
    let fixture = build_fixture();
    let triple = output_triple(&fixture);
    let secp = Secp256k1::new();
    verify_registration(
        &secp,
        &triple.statement,
        &triple.proof_bytes,
        &triple.context,
    )
    .unwrap();

    assert_replay_fails(
        &secp,
        &triple.statement,
        &triple.proof_bytes,
        &triple.context,
        |c| {
            c.round_id = b"round-equality-0002";
        },
    );
    assert_replay_fails(
        &secp,
        &triple.statement,
        &triple.proof_bytes,
        &triple.context,
        |c| {
            c.network_identity = b"elements-liquid-testnet";
        },
    );
    assert_replay_fails(
        &secp,
        &triple.statement,
        &triple.proof_bytes,
        &triple.context,
        |c| {
            c.genesis_hash = [0x33; 32];
        },
    );
    assert_replay_fails(
        &secp,
        &triple.statement,
        &triple.proof_bytes,
        &triple.context,
        |c| {
            c.lbtc_asset = elements::AssetId::from_byte_array([0x99; 32]);
        },
    );
    assert_replay_fails(
        &secp,
        &triple.statement,
        &triple.proof_bytes,
        &triple.context,
        |c| {
            c.participant_role = ParticipantRole::Responder;
        },
    );
    assert_replay_fails(
        &secp,
        &triple.statement,
        &triple.proof_bytes,
        &triple.context,
        |c| {
            c.kind = RegistrationKind::InputRegistration;
            c.output_proof_binding = None;
        },
    );
    assert_replay_fails(
        &secp,
        &triple.statement,
        &triple.proof_bytes,
        &triple.context,
        |c| {
            c.contribution_ordinal = 2;
        },
    );
    assert_replay_fails(
        &secp,
        &triple.statement,
        &triple.proof_bytes,
        &triple.context,
        |c| {
            c.element_index = 1;
        },
    );
    assert_replay_fails(
        &secp,
        &triple.statement,
        &triple.proof_bytes,
        &triple.context,
        |c| {
            c.pset_state_digest = fixture.digest_v2;
        },
    );
    // The output's exact proof bytes are committed: binding the OTHER output's
    // genuine rangeproof or surjection proof fails replay even though the
    // commitments still match the statement.
    assert_replay_fails(
        &secp,
        &triple.statement,
        &triple.proof_bytes,
        &triple.context,
        |c| {
            let other = output_proof_binding(&fixture.pset, 1);
            c.output_proof_binding = Some(OutputProofBinding {
                value_rangeproof: other.value_rangeproof,
                asset_surjection_proof: c.output_proof_binding.unwrap().asset_surjection_proof,
            });
        },
    );
    assert_replay_fails(
        &secp,
        &triple.statement,
        &triple.proof_bytes,
        &triple.context,
        |c| {
            let other = output_proof_binding(&fixture.pset, 1);
            c.output_proof_binding = Some(OutputProofBinding {
                value_rangeproof: c.output_proof_binding.unwrap().value_rangeproof,
                asset_surjection_proof: other.asset_surjection_proof,
            });
        },
    );
}

#[test]
fn cross_kind_replay_at_same_index_fails() {
    let fixture = build_fixture();
    let input = input_triple(&fixture);
    let output = output_triple(&fixture);
    let secp = Secp256k1::new();
    // An INPUT registration proof replayed as an OUTPUT registration at the
    // same index binds a different context, so verification fails even though
    // the statement bytes are unchanged.
    let output_context = registration_context(
        RegistrationKind::OutputRegistration,
        0,
        fixture.digest,
        Some(output_proof_binding(&fixture.pset, 0)),
    );
    assert_eq!(
        verify_registration(&secp, &input.statement, &input.proof_bytes, &output_context),
        Err(Error::VerificationFailed),
    );
    // An OUTPUT registration proof replayed as an INPUT registration fails the
    // same way.
    let input_context =
        registration_context(RegistrationKind::InputRegistration, 0, fixture.digest, None);
    assert_eq!(
        verify_registration(
            &secp,
            &output.statement,
            &output.proof_bytes,
            &input_context
        ),
        Err(Error::VerificationFailed),
    );
    // Cross-statement replay: the input proof against the output statement and
    // vice versa fails because each statement binds its own PSET element.
    assert_eq!(
        verify_registration(
            &secp,
            &output.statement,
            &input.proof_bytes,
            &output.context
        ),
        Err(Error::VerificationFailed),
    );
    assert_eq!(
        verify_registration(&secp, &input.statement, &output.proof_bytes, &input.context),
        Err(Error::VerificationFailed),
    );
}

#[test]
fn malformed_proof_encodings_fail_closed() {
    let fixture = build_fixture();
    let triple = input_triple(&fixture);
    let secp = Secp256k1::new();

    // Wrong length (truncated and extended-with-trailing-bytes).
    assert_eq!(
        verify_registration(
            &secp,
            &triple.statement,
            &triple.proof_bytes[..161],
            &triple.context
        ),
        Err(Error::InvalidProofEncoding),
    );
    let mut extended = triple.proof_bytes.to_vec();
    extended.push(0x00);
    assert_eq!(
        verify_registration(&secp, &triple.statement, &extended, &triple.context),
        Err(Error::InvalidProofEncoding),
    );
    // Non-canonical scalar: s_v set to 0xFF..FF exceeds the curve order.
    let mut bad_scalar = triple.proof_bytes;
    for byte in &mut bad_scalar[66..98] {
        *byte = 0xFF;
    }
    assert_eq!(
        verify_registration(&secp, &triple.statement, &bad_scalar, &triple.context),
        Err(Error::InvalidProofEncoding),
    );
    // Invalid point: R1 replaced by an x-coordinate with no curve point.
    let mut bad_point = triple.proof_bytes;
    bad_point[0] = 0x02;
    for byte in &mut bad_point[1..33] {
        *byte = 0xFF;
    }
    assert_eq!(
        verify_registration(&secp, &triple.statement, &bad_point, &triple.context),
        Err(Error::InvalidProofEncoding),
    );
}

#[test]
fn invalid_statement_encodings_fail_closed() {
    let fixture = build_fixture();
    let utxo = fixture.pset.inputs()[0].witness_utxo.as_ref().unwrap();
    let (ma_bytes, _, _) = {
        let triple = input_triple(&fixture);
        triple.statement.to_bytes()
    };

    // Credential commitment of the wrong length.
    assert_eq!(
        input_registration_statement(&ma_bytes[..32], utxo),
        Err(Error::InvalidStatementEncoding),
    );
    // Credential commitment that is not a valid compressed point.
    let mut bad_ma = ma_bytes;
    bad_ma[0] = 0x07;
    assert_eq!(
        input_registration_statement(&bad_ma, utxo),
        Err(Error::InvalidStatementEncoding),
    );
    // Same mutation against the output adapter.
    assert_eq!(
        output_registration_statement(&bad_ma, &fixture.pset, 0),
        Err(Error::InvalidStatementEncoding),
    );
    // A witness UTXO whose value is flipped to explicit (a byte mutation of
    // the PSET element) no longer yields a statement.
    let mut mutated_utxo = utxo.clone();
    mutated_utxo.value = Value::Explicit(fixture.input_values[0]);
    assert_eq!(
        input_registration_statement(&ma_bytes, &mutated_utxo),
        Err(Error::ElementShape),
    );
}

#[test]
fn explicit_value_witness_utxo_rejected() {
    let secp = Secp256k1::new();
    let ma = credential_commitment(&secp, 1_000, &SecretKey::from_slice(&[0x51; 32]).unwrap());
    // Unblinded input: explicit value carries no value commitment to bind.
    let explicit_utxo = TxOut {
        asset: Asset::Explicit(asset()),
        value: Value::Explicit(1_000),
        nonce: Nonce::Null,
        script_pubkey: p2wpkh_script(0x30),
        witness: Default::default(),
    };
    assert_eq!(
        input_registration_statement(&ma.serialize(), &explicit_utxo),
        Err(Error::ElementShape),
    );
    // Null value and asset are likewise unbindable.
    let null_utxo = TxOut {
        asset: Asset::Null,
        value: Value::Null,
        nonce: Nonce::Null,
        script_pubkey: p2wpkh_script(0x30),
        witness: Default::default(),
    };
    assert_eq!(
        input_registration_statement(&ma.serialize(), &null_utxo),
        Err(Error::ElementShape),
    );
    // Confidential value but explicit asset: no asset generator to bind.
    let half_utxo = TxOut {
        asset: Asset::Explicit(asset()),
        value: Value::Confidential(PedersenCommitment::new(
            &secp,
            1_000,
            ValueBlindingFactor::from_slice(&[0x31; 32])
                .unwrap()
                .into_inner(),
            Generator::new_unblinded(&secp, asset().into_tag()),
        )),
        nonce: Nonce::Null,
        script_pubkey: p2wpkh_script(0x30),
        witness: Default::default(),
    };
    assert_eq!(
        input_registration_statement(&ma.serialize(), &half_utxo),
        Err(Error::ElementShape),
    );
}

#[test]
fn unblinded_and_partially_blinded_outputs_rejected() {
    let secp = Secp256k1::new();
    let ma = credential_commitment(&secp, 1_000, &SecretKey::from_slice(&[0x61; 32]).unwrap());
    // Preblind output: no amount/asset commitments yet.
    let mut pset = PartiallySignedTransaction::new_v2();
    let mut output =
        Output::new_explicit(p2wpkh_script(0x40), 1_000, asset(), Some(blinding_key(3)));
    output.blinder_index = Some(0);
    pset.add_output(output);
    assert_eq!(
        output_registration_statement(&ma.serialize(), &pset, 0),
        Err(Error::ElementShape),
    );
    // Explicit fee output likewise has no commitments.
    let mut fee_pset = PartiallySignedTransaction::new_v2();
    fee_pset.add_output(Output::new_explicit(Script::new(), 100, asset(), None));
    assert_eq!(
        output_registration_statement(&ma.serialize(), &fee_pset, 0),
        Err(Error::ElementShape),
    );
    // Out-of-range index.
    assert_eq!(
        output_registration_statement(&ma.serialize(), &pset, 7),
        Err(Error::ElementShape),
    );
    // Partially blinded: commitments present but proofs missing.
    let fixture = build_fixture();
    let mut partial = fixture.pset.clone();
    partial.outputs_mut()[0].value_rangeproof = None;
    assert_eq!(
        output_registration_statement(&ma.serialize(), &partial, 0),
        Err(Error::ElementShape),
    );
    let mut partial2 = fixture.pset.clone();
    partial2.outputs_mut()[0].asset_surjection_proof = None;
    assert_eq!(
        output_registration_statement(&ma.serialize(), &partial2, 0),
        Err(Error::ElementShape),
    );
}

#[test]
fn statement_pset_element_mismatch_fails() {
    // Mutating the PSET after statement construction and rebuilding the context
    // against the mutated revision must fail: the statement still binds the
    // ORIGINAL element bytes while the mutated element no longer opens to the
    // witness (and the rebuilt digest binds different bytes).
    let fixture = build_fixture();
    let triple = output_triple(&fixture);
    let secp = Secp256k1::new();

    // Mutate the PSET: swap output 0's amount commitment for output 1's.
    let mut mutated = fixture.pset.clone();
    mutated.outputs_mut()[0].amount_comm = fixture.pset.outputs()[1].amount_comm;
    // The adapter is the only way to build a statement; rebuilding from the
    // mutated element yields a DIFFERENT statement, and the original proof
    // verifies against neither the mutated statement nor the original
    // statement under the mutated revision's binding.
    let (ma_bytes, _, _) = triple.statement.to_bytes();
    let mutated_statement = output_registration_statement(&ma_bytes, &mutated, 0).unwrap();
    assert_ne!(mutated_statement, triple.statement);
    assert_eq!(
        verify_registration(
            &secp,
            &mutated_statement,
            &triple.proof_bytes,
            &triple.context
        ),
        Err(Error::VerificationFailed),
    );

    // The second genuine revision binds a different digest; the original proof
    // fails under a context rebuilt for that revision.
    let context_v2 = registration_context(
        RegistrationKind::OutputRegistration,
        0,
        fixture.digest_v2,
        Some(output_proof_binding(&fixture.pset, 0)),
    );
    assert_eq!(
        verify_registration(&secp, &triple.statement, &triple.proof_bytes, &context_v2),
        Err(Error::VerificationFailed),
    );
    // The second revision's statement (its output 0 carries different
    // commitments) against the original proof fails as well.
    let statement_v2 = output_registration_statement(&ma_bytes, &fixture.pset_v2, 0).unwrap();
    assert_ne!(statement_v2, triple.statement);
    assert_eq!(
        verify_registration(&secp, &statement_v2, &triple.proof_bytes, &triple.context),
        Err(Error::VerificationFailed),
    );
}

#[test]
fn seeded_rerun_produces_identical_proof_bytes() {
    let fixture = build_fixture();
    let first = input_triple(&fixture);
    let second = input_triple(&fixture);
    assert_eq!(first.proof_bytes, second.proof_bytes);
    let first_out = output_triple(&fixture);
    let second_out = output_triple(&fixture);
    assert_eq!(first_out.proof_bytes, second_out.proof_bytes);
    // The contexts encode deterministically too.
    assert_eq!(
        encode_registration_context(&first.context).unwrap(),
        encode_registration_context(&second.context).unwrap(),
    );
}

#[test]
fn context_bounds_fail_closed() {
    let fixture = build_fixture();
    // Empty and oversized network identity / round id.
    for (network, round) in [
        (b"".as_slice(), ROUND),
        (&[0x55; 65][..], ROUND),
        (NETWORK, b"".as_slice()),
        (NETWORK, &[0x55; 129][..]),
    ] {
        let mut context =
            registration_context(RegistrationKind::InputRegistration, 0, fixture.digest, None);
        context.network_identity = network;
        context.round_id = round;
        assert_eq!(
            encode_registration_context(&context),
            Err(Error::InvalidContext),
        );
    }
    // Output registration without proof binding, and input registration with
    // one, are invalid contexts.
    let mut missing_binding =
        registration_context(RegistrationKind::InputRegistration, 0, fixture.digest, None);
    missing_binding.kind = RegistrationKind::OutputRegistration;
    assert_eq!(
        encode_registration_context(&missing_binding),
        Err(Error::InvalidContext),
    );
    let mut spurious_binding =
        registration_context(RegistrationKind::InputRegistration, 0, fixture.digest, None);
    spurious_binding.output_proof_binding = Some(OutputProofBinding {
        value_rangeproof: b"x",
        asset_surjection_proof: b"y",
    });
    assert_eq!(
        encode_registration_context(&spurious_binding),
        Err(Error::InvalidContext),
    );
    let mut empty_proof = registration_context(
        RegistrationKind::OutputRegistration,
        0,
        fixture.digest,
        None,
    );
    empty_proof.output_proof_binding = Some(OutputProofBinding {
        value_rangeproof: b"",
        asset_surjection_proof: b"y",
    });
    assert_eq!(
        encode_registration_context(&empty_proof),
        Err(Error::InvalidContext),
    );
}

#[test]
fn prove_registration_rejects_bad_entropy() {
    let fixture = build_fixture();
    let secp = Secp256k1::new();
    let utxo = fixture.pset.inputs()[0].witness_utxo.as_ref().unwrap();
    let value = fixture.input_values[0];
    let (_asset_bf, value_bf) = fixture.input_blindings[0];
    let r1 = SecretKey::from_slice(&[0x51; 32]).unwrap();
    let r2 = SecretKey::from_slice(value_bf.into_inner().as_ref()).unwrap();
    let ma = credential_commitment(&secp, value, &r1);
    let statement = input_registration_statement(&ma.serialize(), utxo).unwrap();
    let witness = EqualityWitness::new(value, &r1, &r2).unwrap();
    let context =
        registration_context(RegistrationKind::InputRegistration, 0, fixture.digest, None);
    assert!(matches!(
        prove_registration(&secp, &witness, &statement, &context, &[0x77; 31]),
        Err(Error::ProveRejected),
    ));
}

#[test]
fn tampered_proof_bytes_fail_verification_not_decoding() {
    // A bit-flip inside a still-canonical proof encoding decodes fine but must
    // fail the verification equations (not the decoder), proving the failure
    // is cryptographic, not lexical.
    let fixture = build_fixture();
    let triple = input_triple(&fixture);
    let secp = Secp256k1::new();
    let mut tampered = triple.proof_bytes;
    tampered[100] ^= 0x01;
    assert_eq!(
        verify_registration(&secp, &triple.statement, &tampered, &triple.context),
        Err(Error::VerificationFailed),
    );
}

#[test]
fn wrong_witness_blinding_factor_cannot_verify() {
    // A witness whose r1 does not match the statement's Ma produces a proof
    // that fails verification: the prover relation is genuinely checked.
    let fixture = build_fixture();
    let triple = input_triple(&fixture);
    let secp = Secp256k1::new();
    let wrong_r1 = SecretKey::from_slice(&[0x52; 32]).unwrap();
    let value = fixture.input_values[0];
    let (_asset_bf, value_bf) = fixture.input_blindings[0];
    let r2 = SecretKey::from_slice(value_bf.into_inner().as_ref()).unwrap();
    let wrong_witness = EqualityWitness::new(value, &wrong_r1, &r2).unwrap();
    let proof = prove_registration(
        &secp,
        &wrong_witness,
        &triple.statement,
        &triple.context,
        &[0x79; 32],
    )
    .unwrap();
    assert_eq!(
        verify_registration(
            &secp,
            &triple.statement,
            &wasabi_liquid_native_credential_commitment_equality::encode_proof(&proof),
            &triple.context,
        ),
        Err(Error::VerificationFailed),
    );
    let _ = triple.witness_r1;
}

#[test]
fn context_encoding_layout_is_stable() {
    // Pin the exact encoding conventions (magic, field order, length prefixes)
    // so a drift in the encoder is caught by bytes, not by behavior.
    let fixture = build_fixture();
    let context =
        registration_context(RegistrationKind::InputRegistration, 0, fixture.digest, None);
    let encoded = encode_registration_context(&context).unwrap();
    let mut expected = Vec::new();
    expected.extend_from_slice(b"WL-CJ-REGISTRATION-CONTEXT-V1");
    expected.push(1u8); // profile V1
    expected.extend_from_slice(&(NETWORK.len() as u32).to_be_bytes());
    expected.extend_from_slice(NETWORK);
    expected.extend_from_slice(&GENESIS);
    expected.extend_from_slice(&asset().to_byte_array());
    expected.extend_from_slice(&(ROUND.len() as u32).to_be_bytes());
    expected.extend_from_slice(ROUND);
    expected.push(1u8); // Phase::Construction
    expected.push(1u8); // ParticipantRole::Initiator
    expected.extend_from_slice(&1u32.to_be_bytes()); // contribution ordinal
    expected.push(1u8); // RegistrationKind::InputRegistration
    expected.extend_from_slice(&0u32.to_be_bytes()); // element index
    expected.extend_from_slice(&fixture.digest);
    expected.push(0u8); // no output proof binding
    assert_eq!(encoded, expected);

    // Output registration encoding appends the two length-prefixed proofs.
    let binding = output_proof_binding(&fixture.pset, 0);
    let output_context = registration_context(
        RegistrationKind::OutputRegistration,
        0,
        fixture.digest,
        Some(binding),
    );
    let encoded_out = encode_registration_context(&output_context).unwrap();
    let mut expected_out = Vec::new();
    expected_out.extend_from_slice(b"WL-CJ-REGISTRATION-CONTEXT-V1");
    expected_out.push(1u8);
    expected_out.extend_from_slice(&(NETWORK.len() as u32).to_be_bytes());
    expected_out.extend_from_slice(NETWORK);
    expected_out.extend_from_slice(&GENESIS);
    expected_out.extend_from_slice(&asset().to_byte_array());
    expected_out.extend_from_slice(&(ROUND.len() as u32).to_be_bytes());
    expected_out.extend_from_slice(ROUND);
    expected_out.push(1u8);
    expected_out.push(1u8);
    expected_out.extend_from_slice(&1u32.to_be_bytes());
    expected_out.push(2u8); // RegistrationKind::OutputRegistration
    expected_out.extend_from_slice(&0u32.to_be_bytes());
    expected_out.extend_from_slice(&fixture.digest);
    expected_out.push(1u8);
    expected_out.extend_from_slice(&(binding.value_rangeproof.len() as u32).to_be_bytes());
    expected_out.extend_from_slice(binding.value_rangeproof);
    expected_out.extend_from_slice(&(binding.asset_surjection_proof.len() as u32).to_be_bytes());
    expected_out.extend_from_slice(binding.asset_surjection_proof);
    assert_eq!(encoded_out, expected_out);
}
