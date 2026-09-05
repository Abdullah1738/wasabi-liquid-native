//! Derivation scratch for the wire-KAT constants: builds the genuine
//! two-participant round and prints the pinned request/response identities.
//! The printed values are copied into `tests.rs` exactly once; this scratch is
//! never a substitute for the pinned assertions.
use super::*;

use elements::bitcoin::PublicKey as BitcoinPublicKey;
use elements::confidential::{Asset, Nonce, RangeProof, SurjectionProof, Value};
use elements::pset::{Input, Output};
use elements::secp256k1_zkp::{Generator, PedersenCommitment, PublicKey, Scalar, SecretKey};
use elements::{AssetId, CtLocation, CtLocationType, OutPoint, Script, TxOut, Txid};
use rand::{SeedableRng, rngs::StdRng};
use wasabi_liquid_native_coinjoin_partial_balance::{
    PartialBalanceWitness, encode_proof as encode_partial_balance_proof, prove_partial_balance,
};
use wasabi_liquid_native_credential_commitment_equality::{
    EqualityWitness, encode_proof as encode_equality_proof,
};

const NETWORK: &[u8] = b"elements-liquid-mainnet";
const ROUND: &[u8] = b"round-coinjoin-ffi-0001";
const GENESIS: [u8; 32] = [0x22; 32];
const SEED: u64 = 0x5eed_5eed_ff10_0001;

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

fn asset() -> AssetId {
    AssetId::from_byte_array([0x11; 32])
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

fn credential_commitment(secp: &Secp256k1<All>, value: u64, r1: &SecretKey) -> PublicKey {
    let gg = PublicKey::from_slice(&WABISABI_GG_BYTES).unwrap();
    let gh = PublicKey::from_slice(&WABISABI_GH_BYTES).unwrap();
    gg.mul_tweak(secp, &value_scalar(value))
        .unwrap()
        .combine(&gh.mul_tweak(secp, &scalar_of(r1)).unwrap())
        .unwrap()
}

// ---------------------------------------------------------------------------
// Genuine fixture: the two-participant round built through the landed crates.
//
// Two confidential witness UTXOs (A owns input 0, B owns input 1), two
// confidential outputs (A blinds output 0 non-last, B blinds output 1 last),
// one explicit fee. All entropy is seeded; all blinding factors are recovered
// from the fork's own return values, so every witness is genuine.
// ---------------------------------------------------------------------------

const INPUT_VALUES: [u64; 2] = [5_000, 4_000];
const OUTPUT_VALUES: [u64; 2] = [3_500, 4_400];
const FEE: u64 = 1_100;
const FEE_A: u64 = 500;
const FEE_B: u64 = 600;

const ENTROPY_BLIND_A: [u8; 32] = [0xA1; 32];
const ENTROPY_BLIND_B: [u8; 32] = [0xB2; 32];
const ENTROPY_PROVE_INPUT: [u8; 32] = [0x77; 32];
const ENTROPY_PROVE_OUTPUT: [u8; 32] = [0x88; 32];
const ENTROPY_PROVE_BALANCE: [u8; 32] = [0x99; 32];

// ---------------------------------------------------------------------------
// Typed context builders (mirrors of the frozen ABI parsers' layouts).
// ---------------------------------------------------------------------------

fn canonical_context(
    phase: Phase,
    role: ParticipantRole,
    ordinal: u32,
) -> CanonicalStateContext<'static> {
    CanonicalStateContext {
        profile: ProfileVersion::V1,
        network_identity: NETWORK,
        genesis_hash: GENESIS,
        lbtc_asset: asset(),
        fee_asset: asset(),
        round_id: ROUND,
        phase,
        participant_role: role,
        contribution_ordinal: ordinal,
        predecessor: PredecessorDigest::Absent,
    }
}

fn registration_context(
    kind: RegistrationKind,
    role: ParticipantRole,
    ordinal: u32,
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
        phase: Phase::Proofs,
        participant_role: role,
        contribution_ordinal: ordinal,
        kind,
        element_index,
        pset_state_digest,
        output_proof_binding,
    }
}

fn balance_context<'a>(
    role: ParticipantRole,
    ordinal: u32,
    pset_state_digest: [u8; 32],
    input_indices: &'a [u32],
    output_indices: &'a [u32],
    fee_share: u64,
) -> PartialBalanceContext<'a> {
    PartialBalanceContext {
        profile: ProfileVersion::V1,
        network_identity: NETWORK,
        genesis_hash: GENESIS,
        lbtc_asset: asset(),
        round_id: ROUND,
        phase: Phase::Proofs,
        participant_role: role,
        contribution_ordinal: ordinal,
        pset_state_digest,
        input_indices,
        output_indices,
        fee_share,
    }
}

// ---------------------------------------------------------------------------
// PSET builders.
//
// Two shapes share one round context:
//  * The BLINDING shape (explicit witness UTXOs) is the pre-registration
//    preblind revision the collaborative-blinding state machine accepts; it
//    drives op 1, op 4, op 5, op 6, and op 3.
//  * The CONFIDENTIAL shape (confidential witness UTXOs with asset-blind and
//    in-utxo range proofs) is the input-registration revision; it drives op 2,
//    whose statement requires a confidential witness UTXO.
//  * The BALANCE shape (explicit inputs, outputs blinded over the canonical
//    unblinded L-BTC generator) drives op 7; the collab-blinded outputs use a
//    blinded asset generator, whose per-participant residual has no clean
//    blind-factor witness, so op 7 is exercised over the shape its own crate
//    uses.
// ---------------------------------------------------------------------------

fn explicit_input(index: u8, value: u64) -> Input {
    let mut input = Input::from_prevout(OutPoint::new(
        Txid::from_byte_array([0x30 + index; 32]),
        u32::from(index),
    ));
    input.witness_utxo = Some(TxOut {
        asset: Asset::Explicit(asset()),
        value: Value::Explicit(value),
        nonce: Nonce::Null,
        script_pubkey: p2wpkh_script(index),
        witness: Default::default(),
    });
    input
}

fn confidential_input(
    secp: &Secp256k1<All>,
    rng: &mut StdRng,
    index: u8,
    value: u64,
    asset_bf: AssetBlindingFactor,
    value_bf: ValueBlindingFactor,
) -> Input {
    let generator = Generator::new_blinded(secp, asset().into_tag(), asset_bf.into_inner());
    let commitment = PedersenCommitment::new(secp, value, value_bf.into_inner(), generator);
    let mut input = Input::from_prevout(OutPoint::new(
        Txid::from_byte_array([0x30 + index; 32]),
        u32::from(index),
    ));
    input.witness_utxo = Some(TxOut {
        asset: Asset::Confidential(generator),
        value: Value::Confidential(commitment),
        nonce: Nonce::Confidential(blinding_key(7 + index).inner),
        script_pubkey: p2wpkh_script(index),
        witness: Default::default(),
    });
    input.asset = Some(asset());
    input.blind_asset_proof =
        Some(SurjectionProof::blind_asset_proof(rng, secp, asset(), asset_bf).unwrap());
    input.in_utxo_rangeproof = Some(
        RangeProof::new(
            secp,
            1,
            commitment,
            value,
            value_bf.into_inner(),
            &[],
            p2wpkh_script(index).as_bytes(),
            SecretKey::new(rng),
            0,
            52,
            generator,
        )
        .unwrap(),
    );
    input
}

fn preblind_output(index: u8, value: u64) -> Output {
    let mut output = Output::new_explicit(
        p2wpkh_script(0x40 + index),
        value,
        asset(),
        Some(blinding_key(3 + index)),
    );
    output.blinder_index = Some(u32::from(index));
    output
}

/// The preblind blinding revision: explicit witness UTXOs, two preblind
/// outputs, one explicit fee. Accepted by both `canonicalize_pset_state` and
/// `collab::UnblindedCoinJoin`.
fn build_preblind() -> PartiallySignedTransaction {
    let mut pset = PartiallySignedTransaction::new_v2();
    for (index, value) in INPUT_VALUES.iter().enumerate() {
        pset.add_input(explicit_input(index as u8, *value));
    }
    for (index, value) in OUTPUT_VALUES.iter().enumerate() {
        pset.add_output(preblind_output(index as u8, *value));
    }
    pset.add_output(Output::new_explicit(Script::new(), FEE, asset(), None));
    pset
}

/// The input-registration revision: confidential witness UTXOs over the same
/// outpoints and values, two preblind outputs, one explicit fee.
fn build_confidential(
    secp: &Secp256k1<All>,
    input_blindings: &[(AssetBlindingFactor, ValueBlindingFactor); 2],
) -> PartiallySignedTransaction {
    let mut rng = StdRng::seed_from_u64(SEED ^ 0xb000);
    let mut pset = PartiallySignedTransaction::new_v2();
    for (index, value) in INPUT_VALUES.iter().enumerate() {
        let (asset_bf, value_bf) = input_blindings[index];
        pset.add_input(confidential_input(
            secp,
            &mut rng,
            index as u8,
            *value,
            asset_bf,
            value_bf,
        ));
    }
    for (index, value) in OUTPUT_VALUES.iter().enumerate() {
        pset.add_output(preblind_output(index as u8, *value));
    }
    pset.add_output(Output::new_explicit(Script::new(), FEE, asset(), None));
    pset
}

// ---------------------------------------------------------------------------
// Wire framing helpers (test-side mirror of the frozen ABI layout).
// ---------------------------------------------------------------------------

fn field(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn frame(op: u32, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(16 + payload.len());
    out.extend_from_slice(&WLCJ_MAGIC_V1.to_be_bytes());
    out.extend_from_slice(&WLCJ_ABI_VERSION_V1.to_be_bytes());
    out.extend_from_slice(&op.to_be_bytes());
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

fn request(op: u32, fields: &[&[u8]]) -> Vec<u8> {
    let mut payload = Vec::new();
    for bytes in fields {
        field(&mut payload, bytes);
    }
    frame(op, &payload)
}

/// Executes one op through the exported entry point and returns the complete
/// response frame; asserts the two-call capacity protocol.
fn execute(request_frame: &[u8]) -> Vec<u8> {
    let mut required = 0u64;
    let status = unsafe {
        wlcj_execute_impl_v1(
            request_frame.as_ptr(),
            request_frame.len() as u64,
            ptr::null_mut(),
            0,
            &mut required,
        )
    };
    assert_eq!(status, WLCJ_STATUS_OUTPUT_CAPACITY_V1);
    assert!(required >= 16);
    let mut out = vec![0u8; usize::try_from(required).unwrap()];
    let mut written = 0u64;
    let status = unsafe {
        wlcj_execute_impl_v1(
            request_frame.as_ptr(),
            request_frame.len() as u64,
            out.as_mut_ptr(),
            out.len() as u64,
            &mut written,
        )
    };
    assert_eq!(status, WLCJ_STATUS_OK_V1);
    assert_eq!(written, required);
    out
}

/// Executes one op expecting a rejection; the published length must be 0 and
/// the caller's output buffer must be untouched.
fn execute_reject(request_frame: &[u8]) -> i32 {
    let mut required = 0xAAAA_AAAA_AAAA_AAAAu64;
    let mut out = vec![0xA5u8; 256];
    let status = unsafe {
        wlcj_execute_impl_v1(
            request_frame.as_ptr(),
            request_frame.len() as u64,
            out.as_mut_ptr(),
            out.len() as u64,
            &mut required,
        )
    };
    assert_ne!(status, WLCJ_STATUS_OK_V1);
    assert_ne!(status, WLCJ_STATUS_OUTPUT_CAPACITY_V1);
    assert_eq!(required, 0);
    assert!(out.iter().all(|byte| *byte == 0xA5));
    status
}

// ---------------------------------------------------------------------------
// Context field encoders (positional layouts frozen by the ABI parsers).
// ---------------------------------------------------------------------------

fn bounded(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn encode_context(phase: Phase, role: ParticipantRole, ordinal: u32) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(ProfileVersion::V1 as u8);
    bounded(&mut out, NETWORK);
    out.extend_from_slice(&GENESIS);
    out.extend_from_slice(&asset().to_byte_array());
    out.extend_from_slice(&asset().to_byte_array());
    bounded(&mut out, ROUND);
    out.push(phase as u8);
    out.push(role as u8);
    out.extend_from_slice(&ordinal.to_be_bytes());
    out.push(0); // predecessor absent
    out
}

fn encode_registration_context(
    kind: RegistrationKind,
    role: ParticipantRole,
    ordinal: u32,
    element_index: u32,
    digest: &[u8; 32],
) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(ProfileVersion::V1 as u8);
    bounded(&mut out, NETWORK);
    out.extend_from_slice(&GENESIS);
    out.extend_from_slice(&asset().to_byte_array());
    bounded(&mut out, ROUND);
    out.push(Phase::Proofs as u8);
    out.push(role as u8);
    out.extend_from_slice(&ordinal.to_be_bytes());
    out.push(kind as u8);
    out.extend_from_slice(&element_index.to_be_bytes());
    out.extend_from_slice(digest);
    out
}

fn encode_balance_context(
    role: ParticipantRole,
    ordinal: u32,
    digest: &[u8; 32],
    input_indices: &[u32],
    output_indices: &[u32],
    fee_share: u64,
) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(ProfileVersion::V1 as u8);
    bounded(&mut out, NETWORK);
    out.extend_from_slice(&GENESIS);
    out.extend_from_slice(&asset().to_byte_array());
    bounded(&mut out, ROUND);
    out.push(Phase::Proofs as u8);
    out.push(role as u8);
    out.extend_from_slice(&ordinal.to_be_bytes());
    out.extend_from_slice(digest);
    out.extend_from_slice(&(input_indices.len() as u32).to_be_bytes());
    for index in input_indices {
        out.extend_from_slice(&index.to_be_bytes());
    }
    out.extend_from_slice(&(output_indices.len() as u32).to_be_bytes());
    for index in output_indices {
        out.extend_from_slice(&index.to_be_bytes());
    }
    out.extend_from_slice(&fee_share.to_be_bytes());
    out
}

fn encode_role_map(map: &HashMap<usize, collab::Role>) -> Vec<u8> {
    let mut ordered: Vec<(usize, collab::Role)> = map.iter().map(|(i, r)| (*i, *r)).collect();
    ordered.sort_unstable_by_key(|(index, _)| *index);
    let mut out = Vec::new();
    out.extend_from_slice(&(ordered.len() as u32).to_be_bytes());
    for (index, role) in ordered {
        out.extend_from_slice(&(index as u32).to_be_bytes());
        out.push(match role {
            collab::Role::A => 1,
            collab::Role::B => 2,
        });
    }
    out
}

fn encode_secrets(secrets: &HashMap<usize, elements::TxOutSecrets>) -> Vec<u8> {
    let mut ordered: Vec<(usize, elements::TxOutSecrets)> =
        secrets.iter().map(|(i, s)| (*i, *s)).collect();
    ordered.sort_unstable_by_key(|(index, _)| *index);
    let mut out = Vec::new();
    for (index, secret) in ordered {
        out.extend_from_slice(&(index as u32).to_be_bytes());
        out.extend_from_slice(&secret.asset.to_byte_array());
        out.extend_from_slice(secret.asset_bf.into_inner().as_ref());
        out.extend_from_slice(&secret.value.to_be_bytes());
        out.extend_from_slice(secret.value_bf.into_inner().as_ref());
    }
    out
}

fn response_fields(response: &[u8]) -> Vec<&[u8]> {
    assert!(response.len() >= 16);
    assert_eq!(&response[0..4], &WLCJ_MAGIC_V1.to_be_bytes());
    assert_eq!(&response[4..8], &WLCJ_ABI_VERSION_V1.to_be_bytes());
    let payload_len = u32::from_be_bytes(response[12..16].try_into().unwrap()) as usize;
    assert_eq!(payload_len, response.len() - 16);
    match split_fields(&response[16..]) {
        Ok(fields) => fields,
        Err(_) => panic!("response payload splits into fields"),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn explicit_secrets() -> HashMap<usize, elements::TxOutSecrets> {
    explicit_secrets_for(&(0..INPUT_VALUES.len()).collect::<Vec<_>>(), &INPUT_VALUES)
}

fn explicit_secrets_for(
    indices: &[usize],
    values: &[u64],
) -> HashMap<usize, elements::TxOutSecrets> {
    let mut map = HashMap::new();
    for (pos, index) in indices.iter().enumerate() {
        map.insert(
            *index,
            elements::TxOutSecrets::new(
                asset(),
                AssetBlindingFactor::zero(),
                values[pos],
                ValueBlindingFactor::zero(),
            ),
        );
    }
    map
}

// ---------------------------------------------------------------------------
// The genuine two-participant round, driven end-to-end through the frozen ABI.
// ---------------------------------------------------------------------------

struct Round {
    preblind_bytes: Vec<u8>,
    preblind_digest: [u8; 32],
    final_bytes: Vec<u8>,
    final_digest: [u8; 32],
    intermediate_bytes: Vec<u8>,
    confidential_bytes: Vec<u8>,
    confidential_digest: [u8; 32],
    balance_bytes: Vec<u8>,
    balance_digest: [u8; 32],
    input_proof_a: [u8; 162],
    output_proof_a: [u8; 162],
    balance_proof_a: [u8; 65],
    balance_proof_b: [u8; 65],
    ma_in: [u8; 33],
    ma_out: [u8; 33],
    role_map_bytes: Vec<u8>,
    secrets_a_bytes: Vec<u8>,
    secrets_b_bytes: Vec<u8>,
}

fn build_round() -> Round {
    let secp = Secp256k1::new();
    let mut input_blindings = Vec::new();
    for tag in 0u8..2 {
        let mut rng = StdRng::seed_from_u64(SEED ^ 0xa000 ^ u64::from(tag));
        input_blindings.push((
            AssetBlindingFactor::new(&mut rng),
            ValueBlindingFactor::new(&mut rng),
        ));
    }
    let input_blindings: [(AssetBlindingFactor, ValueBlindingFactor); 2] =
        [input_blindings[0], input_blindings[1]];

    let preblind = build_preblind();
    let preblind_bytes = serialize(&preblind);
    let confidential = build_confidential(&secp, &input_blindings);
    let confidential_bytes = serialize(&confidential);

    // Op 1: canonicalize the preblind revision (Construction, Initiator, 1).
    let op1_response = execute(&request(
        WLCJ_OP_CANONICALIZE_STATE_V1,
        &[
            &preblind_bytes,
            &encode_context(Phase::Construction, ParticipantRole::Initiator, 1),
        ],
    ));
    let op1_fields = response_fields(&op1_response);
    assert_eq!(op1_fields.len(), 2);
    let preblind_digest: [u8; 32] = op1_fields[1].try_into().unwrap();
    let expected_preblind = canonicalize_pset_state(
        &preblind_bytes,
        &canonical_context(Phase::Construction, ParticipantRole::Initiator, 1),
    )
    .unwrap();
    assert_eq!(op1_fields[0], expected_preblind.canonical_bytes());
    assert_eq!(preblind_digest, expected_preblind.digest().into_bytes());

    // Canonicalize the confidential input-registration revision (Construction).
    let confidential_digest = canonicalize_pset_state(
        &confidential_bytes,
        &canonical_context(Phase::Construction, ParticipantRole::Initiator, 1),
    )
    .unwrap()
    .digest()
    .into_bytes();

    // Op 2: verify A's input registration (confidential witness UTXO 0).
    let r1_in = SecretKey::from_slice(&[0x51; 32]).unwrap();
    let r2_in = SecretKey::from_slice(input_blindings[0].1.into_inner().as_ref()).unwrap();
    let ma_in = credential_commitment(&secp, INPUT_VALUES[0], &r1_in);
    let statement_in = equality::input_registration_statement(
        &ma_in.serialize(),
        confidential.inputs()[0].witness_utxo.as_ref().unwrap(),
    )
    .unwrap();
    let witness_in = EqualityWitness::new(INPUT_VALUES[0], &r1_in, &r2_in).unwrap();
    let reg_context_in = registration_context(
        RegistrationKind::InputRegistration,
        ParticipantRole::Initiator,
        1,
        0,
        confidential_digest,
        None,
    );
    let proof_in = equality::prove_registration(
        &secp,
        &witness_in,
        &statement_in,
        &reg_context_in,
        &ENTROPY_PROVE_INPUT,
    )
    .unwrap();
    let input_proof_a = encode_equality_proof(&proof_in);
    let op2_response = execute(&request(
        WLCJ_OP_VERIFY_INPUT_REGISTRATION_V1,
        &[
            &confidential_bytes,
            &encode_registration_context(
                RegistrationKind::InputRegistration,
                ParticipantRole::Initiator,
                1,
                0,
                &confidential_digest,
            ),
            &input_proof_a,
            &ma_in.serialize(),
        ],
    ));
    assert_eq!(response_fields(&op2_response)[0], b"OK\0\0");

    // Op 4: A blinds non-last over the preblind revision.
    let role_map: HashMap<usize, collab::Role> =
        HashMap::from([(0usize, collab::Role::A), (1usize, collab::Role::B)]);
    let role_map_bytes = encode_role_map(&role_map);
    let all_secrets = explicit_secrets();
    let secrets_a: HashMap<usize, elements::TxOutSecrets> = all_secrets
        .iter()
        .filter(|(i, _)| **i == 0)
        .map(|(i, s)| (*i, *s))
        .collect();
    let secrets_a_bytes = encode_secrets(&secrets_a);
    let op4_response = execute(&request(
        WLCJ_OP_BLIND_NON_LAST_V1,
        &[
            &preblind_bytes,
            &role_map_bytes,
            &secrets_a_bytes,
            &ENTROPY_BLIND_A,
        ],
    ));
    let op4_fields = response_fields(&op4_response);
    assert_eq!(op4_fields.len(), 1);
    let intermediate_bytes = op4_fields[0].to_vec();
    let intermediate: PartiallySignedTransaction = deserialize(&intermediate_bytes).unwrap();
    assert!(!intermediate.global.scalars.is_empty());

    // Op 5: B blinds last; the response is the final blinded PSET.
    let secrets_b: HashMap<usize, elements::TxOutSecrets> = all_secrets
        .iter()
        .filter(|(i, _)| **i == 1)
        .map(|(i, s)| (*i, *s))
        .collect();
    let secrets_b_bytes = encode_secrets(&secrets_b);
    let op5_response = execute(&request(
        WLCJ_OP_BLIND_LAST_V1,
        &[
            &preblind_bytes,
            &role_map_bytes,
            &intermediate_bytes,
            &secrets_b_bytes,
            &ENTROPY_BLIND_B,
        ],
    ));
    let op5_fields = response_fields(&op5_response);
    assert_eq!(op5_fields.len(), 1);
    let final_bytes = op5_fields[0].to_vec();
    let final_pset: PartiallySignedTransaction = deserialize(&final_bytes).unwrap();
    assert!(final_pset.global.scalars.is_empty());

    // Recover A's output value blinding factor by replaying the same seeded
    // non-last blinding natively (the FFI deterministically reproduces it);
    // this feeds the output-registration witness (op 3).
    let mut rng_a = HashDrbg::new(&ENTROPY_BLIND_A);
    let mut replay = preblind.clone();
    let blinded_a = replay
        .blind_non_last_with_all_surjection_inputs(&mut rng_a, &secp, &secrets_a)
        .unwrap();
    let (_abf_a, vbf_a, _eph_a) = blinded_a
        .get(&CtLocation {
            input_index: 0,
            ty: CtLocationType::Input,
        })
        .copied()
        .unwrap();
    assert_eq!(serialize(&replay), intermediate_bytes);

    // Op 6: the final signer-view validation accepts and returns the digest.
    let op6_response = execute(&request(
        WLCJ_OP_VALIDATE_SIGNER_VIEW_V1,
        &[
            &final_bytes,
            &encode_context(Phase::PreSigning, ParticipantRole::Initiator, 1),
        ],
    ));
    let op6_fields = response_fields(&op6_response);
    assert_eq!(op6_fields.len(), 2);
    assert_eq!(op6_fields[0], b"OK\0\0");
    let final_digest: [u8; 32] = op6_fields[1].try_into().unwrap();
    let expected_final = canonicalize_pset_state(
        &final_bytes,
        &canonical_context(Phase::PreSigning, ParticipantRole::Initiator, 1),
    )
    .unwrap();
    assert_eq!(final_digest, expected_final.digest().into_bytes());

    // Op 3: verify A's output registration over blinded output 0.
    let r1_out = SecretKey::from_slice(&[0x61; 32]).unwrap();
    let r2_out = SecretKey::from_slice(vbf_a.into_inner().as_ref()).unwrap();
    let ma_out = credential_commitment(&secp, OUTPUT_VALUES[0], &r1_out);
    let statement_out =
        equality::output_registration_statement(&ma_out.serialize(), &final_pset, 0).unwrap();
    let witness_out = EqualityWitness::new(OUTPUT_VALUES[0], &r1_out, &r2_out).unwrap();
    let output = &final_pset.outputs()[0];
    let value_rangeproof = output.value_rangeproof.as_ref().unwrap().to_vec();
    let asset_surjection_proof = output.asset_surjection_proof.as_ref().unwrap().to_vec();
    let reg_context_out = registration_context(
        RegistrationKind::OutputRegistration,
        ParticipantRole::Initiator,
        1,
        0,
        final_digest,
        Some(OutputProofBinding {
            value_rangeproof: Box::leak(value_rangeproof.clone().into_boxed_slice()),
            asset_surjection_proof: Box::leak(asset_surjection_proof.clone().into_boxed_slice()),
        }),
    );
    let proof_out = equality::prove_registration(
        &secp,
        &witness_out,
        &statement_out,
        &reg_context_out,
        &ENTROPY_PROVE_OUTPUT,
    )
    .unwrap();
    let output_proof_a = encode_equality_proof(&proof_out);
    let op3_response = execute(&request(
        WLCJ_OP_VERIFY_OUTPUT_REGISTRATION_V1,
        &[
            &final_bytes,
            &encode_registration_context(
                RegistrationKind::OutputRegistration,
                ParticipantRole::Initiator,
                1,
                0,
                &final_digest,
            ),
            &output_proof_a,
            &ma_out.serialize(),
            &value_rangeproof,
            &asset_surjection_proof,
        ],
    ));
    assert_eq!(response_fields(&op3_response)[0], b"OK\0\0");

    // Op 7: partial-balance proofs. The collab-blinded PSET blinds over a
    // BLINDED asset generator, whose per-participant residual has no clean
    // blind-factor witness; the partial-balance primitive is exercised over a
    // dedicated revision whose outputs commit directly over the CANONICAL
    // unblinded L-BTC generator (the exact shape its own crate uses). Each
    // participant's books balance exactly (input[i] = output[i] + fee[i]), so
    // the residual is exactly -r_o.
    let mut balance = PartiallySignedTransaction::new_v2();
    let balance_inputs = [OUTPUT_VALUES[0] + FEE_A, OUTPUT_VALUES[1] + FEE_B];
    balance.add_input(explicit_input(0, balance_inputs[0]));
    balance.add_input(explicit_input(1, balance_inputs[1]));
    let canonical_gen = Generator::new_unblinded(&secp, asset().into_tag());
    let mut balance_vbfs = Vec::new();
    for (index, output_value) in OUTPUT_VALUES.iter().enumerate() {
        let mut rng = StdRng::seed_from_u64(SEED ^ 0xc000 ^ (index as u64));
        let value_bf = ValueBlindingFactor::new(&mut rng);
        let commitment =
            PedersenCommitment::new(&secp, *output_value, value_bf.into_inner(), canonical_gen);
        let mut output = Output::new_explicit(
            p2wpkh_script(0x40 + index as u8),
            *output_value,
            asset(),
            None,
        );
        output.asset_comm = Some(canonical_gen);
        output.amount_comm = Some(commitment);
        balance.add_output(output);
        balance_vbfs.push(value_bf);
    }
    // No explicit fee output: the fee is the per-participant `fee_share` bound
    // in the context, which the verifier turns into fee·H_A directly.
    let balance_bytes = serialize(&balance);
    let balance_digest = Sha256::digest(&balance_bytes).into();
    let mut balance_proofs = Vec::new();
    for (role, ordinal, in_index, out_index, fee_share) in [
        (ParticipantRole::Initiator, 1u32, 0usize, 0usize, FEE_A),
        (ParticipantRole::Responder, 2u32, 1usize, 1usize, FEE_B),
    ] {
        let delta_r = SecretKey::from_slice(balance_vbfs[out_index].into_inner().as_ref())
            .unwrap()
            .negate();
        let in_indices = [in_index as u32];
        let out_indices = [out_index as u32];
        let context = balance_context(
            role,
            ordinal,
            balance_digest,
            &in_indices,
            &out_indices,
            fee_share,
        );
        let witness = PartialBalanceWitness::from_secret_key(&delta_r);
        let proof =
            prove_partial_balance(&secp, &balance, &context, &witness, &ENTROPY_PROVE_BALANCE)
                .unwrap();
        let proof_bytes = encode_partial_balance_proof(&proof);
        let response = execute(&request(
            WLCJ_OP_VERIFY_PARTIAL_BALANCE_V1,
            &[
                &balance_bytes,
                &encode_balance_context(
                    role,
                    ordinal,
                    &balance_digest,
                    &in_indices,
                    &out_indices,
                    fee_share,
                ),
                &proof_bytes,
            ],
        ));
        assert_eq!(response_fields(&response)[0], b"OK\0\0");
        balance_proofs.push(proof_bytes);
    }

    Round {
        preblind_bytes,
        preblind_digest,
        final_bytes,
        final_digest,
        intermediate_bytes,
        confidential_bytes,
        confidential_digest,
        balance_bytes,
        balance_digest,
        input_proof_a,
        output_proof_a,
        balance_proof_a: balance_proofs[0],
        balance_proof_b: balance_proofs[1],
        ma_in: ma_in.serialize(),
        ma_out: ma_out.serialize(),
        role_map_bytes,
        secrets_a_bytes,
        secrets_b_bytes,
    }
}

// ---------------------------------------------------------------------------
// Request builders for each op (used by the KAT, hostile, and leak tests).
// ---------------------------------------------------------------------------

fn op1_request(round: &Round) -> Vec<u8> {
    request(
        WLCJ_OP_CANONICALIZE_STATE_V1,
        &[
            &round.preblind_bytes,
            &encode_context(Phase::Construction, ParticipantRole::Initiator, 1),
        ],
    )
}

fn op2_request(round: &Round) -> Vec<u8> {
    request(
        WLCJ_OP_VERIFY_INPUT_REGISTRATION_V1,
        &[
            &round.confidential_bytes,
            &encode_registration_context(
                RegistrationKind::InputRegistration,
                ParticipantRole::Initiator,
                1,
                0,
                &round.confidential_digest,
            ),
            &round.input_proof_a,
            &round.ma_in,
        ],
    )
}

fn op4_request(round: &Round) -> Vec<u8> {
    request(
        WLCJ_OP_BLIND_NON_LAST_V1,
        &[
            &round.preblind_bytes,
            &round.role_map_bytes,
            &round.secrets_a_bytes,
            &ENTROPY_BLIND_A,
        ],
    )
}

fn op5_request(round: &Round) -> Vec<u8> {
    request(
        WLCJ_OP_BLIND_LAST_V1,
        &[
            &round.preblind_bytes,
            &round.role_map_bytes,
            &round.intermediate_bytes,
            &round.secrets_b_bytes,
            &ENTROPY_BLIND_B,
        ],
    )
}

fn op6_request(round: &Round) -> Vec<u8> {
    request(
        WLCJ_OP_VALIDATE_SIGNER_VIEW_V1,
        &[
            &round.final_bytes,
            &encode_context(Phase::PreSigning, ParticipantRole::Initiator, 1),
        ],
    )
}

fn op3_request(round: &Round) -> Vec<u8> {
    let final_pset: PartiallySignedTransaction = deserialize(&round.final_bytes).unwrap();
    let output = &final_pset.outputs()[0];
    let value_rangeproof = output.value_rangeproof.as_ref().unwrap().to_vec();
    let asset_surjection_proof = output.asset_surjection_proof.as_ref().unwrap().to_vec();
    request(
        WLCJ_OP_VERIFY_OUTPUT_REGISTRATION_V1,
        &[
            &round.final_bytes,
            &encode_registration_context(
                RegistrationKind::OutputRegistration,
                ParticipantRole::Initiator,
                1,
                0,
                &round.final_digest,
            ),
            &round.output_proof_a,
            &round.ma_out,
            &value_rangeproof,
            &asset_surjection_proof,
        ],
    )
}

fn op7_request(round: &Round, responder: bool) -> Vec<u8> {
    let (role, ordinal, in_index, out_index, fee_share, proof) = if responder {
        (
            ParticipantRole::Responder,
            2u32,
            1usize,
            1usize,
            FEE_B,
            &round.balance_proof_b,
        )
    } else {
        (
            ParticipantRole::Initiator,
            1u32,
            0usize,
            0usize,
            FEE_A,
            &round.balance_proof_a,
        )
    };
    request(
        WLCJ_OP_VERIFY_PARTIAL_BALANCE_V1,
        &[
            &round.balance_bytes,
            &encode_balance_context(
                role,
                ordinal,
                &round.balance_digest,
                &[in_index as u32],
                &[out_index as u32],
                fee_share,
            ),
            proof,
        ],
    )
}

// ---------------------------------------------------------------------------
// Pinned known-answer values (derived from the genuine round; regenerate only
// by re-deriving from a real run, never by hand).
// ---------------------------------------------------------------------------

mod kat {
    pub const PREBLIND_DIGEST: [u8; 32] = [
        0xdd, 0xef, 0xd8, 0xf2, 0x3e, 0xa4, 0x33, 0xf9, 0xa6, 0xc8, 0x04, 0x9a, 0x54, 0xf6, 0x60,
        0x53, 0x0f, 0xca, 0x40, 0xff, 0xf3, 0xc2, 0xc1, 0xcf, 0xef, 0x54, 0x21, 0xf2, 0xd8, 0x5c,
        0x72, 0x16,
    ];
    pub const FINAL_DIGEST: [u8; 32] = [
        0xc8, 0xdc, 0x56, 0xe7, 0xcb, 0xd5, 0x37, 0x58, 0x4c, 0x2e, 0x9d, 0xe9, 0x82, 0xe1, 0x16,
        0xfd, 0xc1, 0x07, 0x51, 0x9b, 0xaf, 0x51, 0x4a, 0x95, 0xb4, 0x4d, 0x0d, 0xc9, 0x5b, 0x89,
        0xd4, 0x59,
    ];
    pub const PREBLIND_SHA256: &str =
        "aeb70c16b7cae9ec4e7c65600b1ca6d6958b16a8c111fea5ed6f6b9b24404dae";
    pub const INTERMEDIATE_SHA256: &str =
        "0409d8678303f4188ea5e84cd5e65a5b79c06164d213aeef76eed0143a8fff8e";
    pub const FINAL_SHA256: &str =
        "9be308565a04c192347c97dc84137eb31e6ef12c6f9063bcdd0bb56f8107544b";
}

#[test]
fn e2e_two_participant_round_all_ops() {
    // The genuine round driven ENTIRELY through the FFI frames; every op
    // succeeds and returns the declared response shape.
    let round = build_round();
    assert_eq!(round.preblind_digest, kat::PREBLIND_DIGEST);
    assert_eq!(round.final_digest, kat::FINAL_DIGEST);
}

#[test]
fn wire_kat_pinned_bytes_per_op() {
    // Fixed request frames produce fixed response frames, pinned at the byte
    // level (digests, PSET handoffs, and verdicts).
    let round = build_round();
    assert_eq!(
        hex(&Sha256::digest(&round.preblind_bytes)),
        kat::PREBLIND_SHA256
    );
    assert_eq!(
        hex(&Sha256::digest(&round.intermediate_bytes)),
        kat::INTERMEDIATE_SHA256
    );
    assert_eq!(hex(&Sha256::digest(&round.final_bytes)), kat::FINAL_SHA256);
    assert_eq!(round.preblind_digest, kat::PREBLIND_DIGEST);
    assert_eq!(round.final_digest, kat::FINAL_DIGEST);
    // Verdict ops return the fixed 8-byte OK verdict field.
    let verdict = verdict_payload();
    for response in [
        execute(&op2_request(&round)),
        execute(&op3_request(&round)),
        execute(&op7_request(&round, false)),
        execute(&op7_request(&round, true)),
    ] {
        assert_eq!(response_fields(&response).len(), 1);
        assert_eq!(response_fields(&response)[0], &verdict[4..]);
        assert_eq!(response[16..].to_vec(), verdict);
    }
}

#[test]
fn determinism_identical_frames_identical_outputs() {
    let round = build_round();
    for request in [
        op1_request(&round),
        op2_request(&round),
        op3_request(&round),
        op4_request(&round),
        op5_request(&round),
        op6_request(&round),
        op7_request(&round, false),
        op7_request(&round, true),
    ] {
        assert_eq!(execute(&request), execute(&request));
    }
}

#[test]
fn hostile_malformed_frames_fail_closed() {
    let round = build_round();
    let good = op1_request(&round);
    // Wrong magic.
    let mut wrong_magic = good.clone();
    wrong_magic[0] ^= 0xFF;
    assert_eq!(execute_reject(&wrong_magic), WLCJ_STATUS_INVALID_FRAME_V1);
    // Wrong ABI version.
    let mut wrong_abi = good.clone();
    wrong_abi[7] = 0x02;
    assert_eq!(execute_reject(&wrong_abi), WLCJ_STATUS_UNSUPPORTED_ABI_V1);
    // Unknown op.
    let mut unknown_op = good.clone();
    unknown_op[11] = 0x7F;
    assert_eq!(execute_reject(&unknown_op), WLCJ_STATUS_UNKNOWN_OP_V1);
    // Truncated frame (payload_len claims more than supplied).
    let truncated = &good[..good.len() - 1];
    assert_eq!(execute_reject(truncated), WLCJ_STATUS_INVALID_FRAME_V1);
    // Trailing bytes (payload_len smaller than supplied).
    let mut trailing = good.clone();
    trailing.push(0x00);
    assert_eq!(execute_reject(&trailing), WLCJ_STATUS_INVALID_FRAME_V1);
    // Oversized payload (op 1 bound exceeded via a bloated declared length).
    let mut oversized = good.clone();
    let over = (OP_PAYLOAD_BOUNDS[0] + 1).to_be_bytes();
    oversized[12..16].copy_from_slice(&over);
    oversized.extend(std::iter::repeat_n(
        0u8,
        (OP_PAYLOAD_BOUNDS[0] + 1) as usize - (good.len() - 16),
    ));
    assert_eq!(execute_reject(&oversized), WLCJ_STATUS_PAYLOAD_TOO_LARGE_V1);
    // Empty frame.
    assert_eq!(execute_reject(&[]), WLCJ_STATUS_INVALID_FRAME_V1);
    // Short frame (header only, no payload).
    assert_eq!(execute_reject(&good[..16]), WLCJ_STATUS_INVALID_FRAME_V1);
}

#[test]
fn hostile_field_shape_failures_fail_closed() {
    let round = build_round();
    // Wrong field count for op 1 (one field instead of two).
    let mut one_field = Vec::new();
    field(&mut one_field, &round.preblind_bytes);
    let req = frame(WLCJ_OP_CANONICALIZE_STATE_V1, &one_field);
    assert_eq!(execute_reject(&req), WLCJ_STATUS_INVALID_FRAME_V1);
    // A field length that exceeds the per-field bound.
    let mut big_field = Vec::new();
    big_field.extend_from_slice(&(WLCJ_MAX_FIELD_BYTES_V1 + 1).to_be_bytes());
    big_field.extend_from_slice(&[0u8; 16]);
    let req = frame(WLCJ_OP_CANONICALIZE_STATE_V1, &big_field);
    assert_eq!(execute_reject(&req), WLCJ_STATUS_PAYLOAD_TOO_LARGE_V1);
    // Invalid context profile byte.
    let mut bad_ctx = encode_context(Phase::Construction, ParticipantRole::Initiator, 1);
    bad_ctx[0] = 0x7E;
    let req = request(
        WLCJ_OP_CANONICALIZE_STATE_V1,
        &[&round.preblind_bytes, &bad_ctx],
    );
    assert_eq!(execute_reject(&req), WLCJ_STATUS_VALIDATION_FAILED_V1);
    // Validation failure: garbage PSET bytes for op 1.
    let garbage = vec![0xDEu8; 64];
    let req = request(
        WLCJ_OP_CANONICALIZE_STATE_V1,
        &[
            &garbage,
            &encode_context(Phase::Construction, ParticipantRole::Initiator, 1),
        ],
    );
    assert_eq!(execute_reject(&req), WLCJ_STATUS_VALIDATION_FAILED_V1);
}

#[test]
fn no_secret_bytes_in_any_response() {
    // A witness supplied to a prove/blind op never appears in the response
    // frame bytes. The blinding entropy and the input secrets are witness-class.
    let round = build_round();
    for secret in [&ENTROPY_BLIND_A, &ENTROPY_BLIND_B] {
        for response in [execute(&op4_request(&round)), execute(&op5_request(&round))] {
            assert!(
                !windows_contains(&response, secret),
                "blinding entropy must never appear in a response frame"
            );
        }
    }
    // The input secret blinding factors are zero in this fixture (explicit
    // inputs), so the secret record's distinguishing bytes are the asset id and
    // values; assert the raw secret FIELD bytes are not echoed.
    for response in [execute(&op4_request(&round)), execute(&op5_request(&round))] {
        assert!(
            !windows_contains(&response, &round.secrets_a_bytes),
            "input secret records must never appear in a response frame"
        );
        assert!(
            !windows_contains(&response, &round.secrets_b_bytes),
            "input secret records must never appear in a response frame"
        );
    }
    // Grep-level: the response payloads carry only public projections, digests,
    // serialized handoffs, and verdicts — no 32-byte witness echoes.
    assert!(!windows_contains(
        &execute(&op4_request(&round)),
        &ENTROPY_BLIND_A
    ));
}

fn windows_contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}
