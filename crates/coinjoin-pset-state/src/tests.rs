use super::*;
use elements::{
    OutPoint, Script, Sequence, TxOut,
    bitcoin::PublicKey,
    confidential::{AssetBlindingFactor, Nonce, RangeProof, SurjectionProof, ValueBlindingFactor},
    pset::{Input, Output, PartiallySignedTransaction, raw},
    secp256k1_zkp::{Generator, PedersenCommitment, Secp256k1, SecretKey, Tweak, ZERO_TWEAK},
};

const NETWORK: &[u8] = b"elements-liquid-mainnet";
const ROUND: &[u8] = b"round-0001";

fn asset() -> AssetId {
    AssetId::from_byte_array([0x11; 32])
}

fn context() -> CanonicalStateContext<'static> {
    CanonicalStateContext {
        profile: ProfileVersion::V1,
        network_identity: NETWORK,
        genesis_hash: [0x22; 32],
        lbtc_asset: asset(),
        fee_asset: asset(),
        round_id: ROUND,
        phase: Phase::Construction,
        participant_role: ParticipantRole::Initiator,
        contribution_ordinal: 7,
        predecessor: PredecessorDigest::Absent,
    }
}

fn public_key(byte: u8) -> PublicKey {
    let secp = Secp256k1::new();
    PublicKey::new(
        SecretKey::from_slice(&[byte; 32])
            .unwrap()
            .public_key(&secp),
    )
}

fn fixture_pset() -> PartiallySignedTransaction {
    let mut pset = PartiallySignedTransaction::new_v2();
    let mut input = Input::from_prevout(OutPoint::new(Txid::from_byte_array([0x33; 32]), 4));
    input.sequence = Some(Sequence::MAX);
    input.witness_utxo = Some(TxOut {
        asset: elements::confidential::Asset::Explicit(asset()),
        value: elements::confidential::Value::Explicit(5_000),
        nonce: elements::confidential::Nonce::Null,
        script_pubkey: Script::from(vec![0x00, 0x14, 0x44, 0x44]),
        witness: Default::default(),
    });
    pset.add_input(input);
    let mut participant = Output::new_explicit(
        Script::from(vec![0x00, 0x14, 0x55, 0x55]),
        4_900,
        asset(),
        Some(public_key(3)),
    );
    participant.blinder_index = Some(0);
    pset.add_output(participant);
    pset.add_output(Output::new_explicit(Script::new(), 100, asset(), None));
    pset
}

fn fully_blinded_fixture_pset() -> PartiallySignedTransaction {
    use rand::{SeedableRng, rngs::StdRng};

    let mut rng = StdRng::seed_from_u64(0x5eed_cafe);
    let secp = Secp256k1::new();
    let mut pset = fixture_pset();
    let amount = pset.outputs()[0].amount.unwrap();
    let script = pset.outputs()[0].script_pubkey.clone();
    let abf = AssetBlindingFactor::from_byte_array([1; 32]).unwrap();
    let vbf = ValueBlindingFactor::from_slice(&[2; 32]).unwrap();
    let input_generator = Generator::new_unblinded(&secp, asset().into_tag());
    let generator = Generator::new_blinded(&secp, asset().into_tag(), abf.into_inner());
    let commitment = PedersenCommitment::new(&secp, amount, vbf.into_inner(), generator);
    let asset_proof = SurjectionProof::blind_asset_proof(&mut rng, &secp, asset(), abf).unwrap();
    let value_proof =
        RangeProof::blind_value_proof(&mut rng, &secp, amount, commitment, generator, vbf).unwrap();
    let transaction_rangeproof = RangeProof::new(
        &secp,
        1,
        commitment,
        amount,
        vbf.into_inner(),
        &[],
        script.as_bytes(),
        SecretKey::new(&mut rng),
        0,
        52,
        generator,
    )
    .unwrap();
    let transaction_surjection_proof = SurjectionProof::new_with_input_count(
        &secp,
        &mut rng,
        asset(),
        abf,
        [(input_generator, asset().into_tag(), ZERO_TWEAK)],
        1,
    )
    .unwrap();
    let output = &mut pset.outputs_mut()[0];
    output.asset_comm = Some(generator);
    output.amount_comm = Some(commitment);
    output.ecdh_pubkey = Some(public_key(4));
    output.value_rangeproof = Some(transaction_rangeproof);
    output.asset_surjection_proof = Some(transaction_surjection_proof);
    output.blind_value_proof = Some(value_proof);
    output.blind_asset_proof = Some(asset_proof);
    pset
}

fn confidential_input_fixture_pset() -> PartiallySignedTransaction {
    use rand::{SeedableRng, rngs::StdRng};

    let mut rng = StdRng::seed_from_u64(0x1a2b_3c4d);
    let secp = Secp256k1::new();
    let mut pset = fixture_pset();
    let amount = 5_000;
    let script = pset.inputs()[0]
        .witness_utxo
        .as_ref()
        .unwrap()
        .script_pubkey
        .clone();
    let abf = AssetBlindingFactor::from_byte_array([3; 32]).unwrap();
    let vbf = ValueBlindingFactor::from_slice(&[4; 32]).unwrap();
    let generator = Generator::new_blinded(&secp, asset().into_tag(), abf.into_inner());
    let commitment = PedersenCommitment::new(&secp, amount, vbf.into_inner(), generator);
    let rangeproof = RangeProof::new(
        &secp,
        1,
        commitment,
        amount,
        vbf.into_inner(),
        &[],
        script.as_bytes(),
        SecretKey::new(&mut rng),
        0,
        52,
        generator,
    )
    .unwrap();
    let asset_proof = SurjectionProof::blind_asset_proof(&mut rng, &secp, asset(), abf).unwrap();
    let input = &mut pset.inputs_mut()[0];
    input.asset = Some(asset());
    input.blind_asset_proof = Some(asset_proof);
    input.in_utxo_rangeproof = Some(rangeproof);
    let utxo = input.witness_utxo.as_mut().unwrap();
    utxo.asset = elements::confidential::Asset::Confidential(generator);
    utxo.value = elements::confidential::Value::Confidential(commitment);
    utxo.nonce = Nonce::Confidential(public_key(5).inner);
    pset
}

fn fixture_bytes() -> Vec<u8> {
    encode::serialize(&fixture_pset())
}

fn accepted(pset: &PartiallySignedTransaction) -> CanonicalState {
    canonicalize_pset_state(&encode::serialize(pset), &context()).unwrap()
}

#[test]
fn baseline_preblinding_fixture_is_a_fixed_kat_and_deterministic() {
    let raw = fixture_bytes();
    let first = canonicalize_pset_state(&raw, &context()).unwrap();
    let second = canonicalize_pset_state(&raw, &context()).unwrap();
    assert_eq!(first.canonical_bytes(), second.canonical_bytes());
    assert_eq!(first.digest(), second.digest());
    assert_eq!(first.canonical_bytes().len(), 481);
    assert_eq!(
        first.digest().into_bytes(),
        [
            241, 137, 146, 193, 93, 163, 25, 147, 101, 105, 166, 201, 123, 163, 194, 243, 201, 239,
            222, 36, 60, 190, 29, 52, 130, 124, 239, 163, 76, 77, 149, 161,
        ],
    );
    let reparsed: PartiallySignedTransaction = encode::deserialize(&raw).unwrap();
    assert_eq!(encode::serialize(&reparsed), raw);
}

#[test]
fn every_context_component_is_committed_or_rejected() {
    let baseline = accepted(&fixture_pset()).digest().into_bytes();
    let mut contexts = Vec::new();
    let mut c = context();
    c.network_identity = b"elements-liquid-testnet";
    contexts.push(c);
    let mut c = context();
    c.genesis_hash[0] ^= 1;
    contexts.push(c);
    let mut c = context();
    c.round_id = b"round-0002";
    contexts.push(c);
    let mut c = context();
    c.phase = Phase::Proofs;
    contexts.push(c);
    let mut c = context();
    c.participant_role = ParticipantRole::Responder;
    contexts.push(c);
    let mut c = context();
    c.contribution_ordinal += 1;
    contexts.push(c);
    let mut c = context();
    c.predecessor = PredecessorDigest::Present([0; 32]);
    contexts.push(c);
    let raw = fixture_bytes();
    for c in contexts {
        assert_ne!(
            canonicalize_pset_state(&raw, &c)
                .unwrap()
                .digest()
                .into_bytes(),
            baseline
        );
    }
    let mut c = context();
    c.fee_asset = AssetId::from_byte_array([0x99; 32]);
    assert!(matches!(
        canonicalize_pset_state(&raw, &c),
        Err(Error::InvalidContext)
    ));
    let mut c = context();
    c.lbtc_asset = AssetId::from_byte_array([0x12; 32]);
    c.fee_asset = c.lbtc_asset;
    assert!(matches!(
        canonicalize_pset_state(&raw, &c),
        Err(Error::UnknownAsset)
    ));
}

#[test]
fn context_limits_are_enforced_at_exact_boundaries() {
    let raw = fixture_bytes();
    let network = vec![1; MAX_NETWORK_IDENTITY_BYTES];
    let round = vec![2; MAX_ROUND_ID_BYTES];
    let mut c = context();
    c.network_identity = &network;
    c.round_id = &round;
    canonicalize_pset_state(&raw, &c).unwrap();
    let too_long = vec![1; MAX_NETWORK_IDENTITY_BYTES + 1];
    c.network_identity = &too_long;
    assert!(matches!(
        canonicalize_pset_state(&raw, &c),
        Err(Error::InvalidContext)
    ));
    let mut c = context();
    let too_long = vec![1; MAX_ROUND_ID_BYTES + 1];
    c.round_id = &too_long;
    assert!(matches!(
        canonicalize_pset_state(&raw, &c),
        Err(Error::InvalidContext)
    ));
}

#[test]
fn raw_limits_truncation_trailing_and_malformed_are_rejected() {
    let raw = fixture_bytes();
    assert!(matches!(
        canonicalize_pset_state(&[], &context()),
        Err(Error::LimitExceeded)
    ));
    assert!(matches!(
        canonicalize_pset_state(&vec![0; MAX_RAW_PSET_BYTES + 1], &context()),
        Err(Error::LimitExceeded)
    ));
    for cut in [1, raw.len() / 2, raw.len() - 1] {
        assert!(matches!(
            canonicalize_pset_state(&raw[..cut], &context()),
            Err(Error::InvalidEncoding)
        ));
    }
    let mut trailing = raw.clone();
    trailing.push(0);
    assert!(matches!(
        canonicalize_pset_state(&trailing, &context()),
        Err(Error::InvalidEncoding)
    ));
    let mut malformed = raw;
    malformed[0] ^= 1;
    assert!(matches!(
        canonicalize_pset_state(&malformed, &context()),
        Err(Error::InvalidEncoding)
    ));
}

#[test]
fn globals_versions_flags_maps_and_scalar_limit_are_strict() {
    let mut p = fixture_pset();
    p.global.tx_data.version = 3;
    assert!(matches!(accepted_result(&p), Err(Error::UnsupportedGlobal)));
    let mut p = fixture_pset();
    p.global.tx_data.tx_modifiable = Some(0);
    assert!(matches!(accepted_result(&p), Err(Error::UnsupportedGlobal)));
    let mut p = fixture_pset();
    p.global.elements_tx_modifiable_flag = Some(0);
    assert!(matches!(accepted_result(&p), Err(Error::UnsupportedGlobal)));
    let mut p = fixture_pset();
    p.global.unknown.insert(
        raw::Key {
            type_value: 0xfa,
            key: vec![],
        },
        vec![1],
    );
    assert!(matches!(accepted_result(&p), Err(Error::UnsupportedGlobal)));
    let mut p = fixture_pset();
    p.global.proprietary.insert(
        raw::ProprietaryKey {
            prefix: b"x".to_vec(),
            subtype: 1,
            key: vec![],
        },
        vec![1],
    );
    assert!(matches!(accepted_result(&p), Err(Error::UnsupportedGlobal)));
    let mut p = fixture_pset();
    for n in 1..=MAX_SCALAR_COUNT {
        p.global
            .scalars
            .push(Tweak::from_slice(&[n as u8; 32]).unwrap());
    }
    accepted(&p);
    p.global
        .scalars
        .push(Tweak::from_slice(&[0x44; 32]).unwrap());
    assert!(matches!(accepted_result(&p), Err(Error::LimitExceeded)));
}

#[test]
fn scalar_order_add_remove_and_substitution_change_state() {
    let mut a = fixture_pset();
    a.global.scalars = vec![
        Tweak::from_slice(&[1; 32]).unwrap(),
        Tweak::from_slice(&[2; 32]).unwrap(),
    ];
    let base = accepted(&a);
    let mut b = a.clone();
    b.global.scalars.swap(0, 1);
    let mut c = a.clone();
    c.global.scalars.pop();
    let mut d = a;
    d.global.scalars[0] = Tweak::from_slice(&[3; 32]).unwrap();
    for changed in [&b, &c, &d] {
        let result = accepted(changed);
        assert_ne!(result.canonical_bytes(), base.canonical_bytes());
        assert_ne!(result.digest(), base.digest());
    }
}

#[test]
fn input_mutations_are_committed_and_duplicate_outpoints_reject() {
    let base = accepted(&fixture_pset());
    let mut p = fixture_pset();
    p.inputs_mut()[0].previous_output_index += 1;
    assert_distinct(&base, &accepted(&p));
    let mut p = fixture_pset();
    p.inputs_mut()[0].sequence = None;
    assert_distinct(&base, &accepted(&p));
    let mut p = fixture_pset();
    p.inputs_mut()[0]
        .witness_utxo
        .as_mut()
        .unwrap()
        .script_pubkey = Script::from(vec![0x51]);
    assert_distinct(&base, &accepted(&p));
    let mut p = fixture_pset();
    let duplicate = p.inputs()[0].clone();
    p.add_input(duplicate);
    assert!(matches!(accepted_result(&p), Err(Error::InvalidStructure)));
    let mut p = fixture_pset();
    p.inputs_mut()[0].witness_utxo = None;
    assert!(matches!(accepted_result(&p), Err(Error::UnsupportedInput)));
}

#[test]
fn coinbase_flags_locktimes_and_unsupported_input_classes_reject() {
    for index in [
        u32::MAX,
        OUTPOINT_PEGIN_FLAG | 1,
        OUTPOINT_ISSUANCE_FLAG | 1,
    ] {
        let mut p = fixture_pset();
        p.inputs_mut()[0].previous_output_index = index;
        assert!(matches!(accepted_result(&p), Err(Error::UnsupportedInput)));
    }
    let mut p = fixture_pset();
    p.inputs_mut()[0].required_height_locktime =
        Some(elements::locktime::Height::from_consensus(5).unwrap());
    assert!(matches!(accepted_result(&p), Err(Error::UnsupportedInput)));
    let mut p = fixture_pset();
    p.inputs_mut()[0].sighash_type = Some(elements::pset::PsbtSighashType::from_u32(1));
    assert!(matches!(accepted_result(&p), Err(Error::UnsupportedInput)));
    let mut p = fixture_pset();
    p.inputs_mut()[0].unknown.insert(
        raw::Key {
            type_value: 0xfa,
            key: vec![],
        },
        vec![1],
    );
    assert!(matches!(accepted_result(&p), Err(Error::UnsupportedInput)));
}

#[test]
fn explicit_input_asset_value_nonce_and_witness_proof_policy_is_fail_closed() {
    let mut p = fixture_pset();
    p.inputs_mut()[0].witness_utxo.as_mut().unwrap().asset =
        elements::confidential::Asset::Explicit(AssetId::from_byte_array([9; 32]));
    assert!(matches!(accepted_result(&p), Err(Error::UnknownAsset)));
    let mut p = fixture_pset();
    p.inputs_mut()[0].witness_utxo.as_mut().unwrap().value = elements::confidential::Value::Null;
    assert!(matches!(accepted_result(&p), Err(Error::UnsupportedInput)));
    let mut p = fixture_pset();
    p.inputs_mut()[0].in_utxo_rangeproof = Some(elements::confidential::RangeProof::EMPTY);
    assert!(matches!(accepted_result(&p), Err(Error::UnsupportedInput)));
}

#[test]
fn output_mutations_are_committed_and_shape_is_strict() {
    let base = accepted(&fixture_pset());
    let mut p = fixture_pset();
    p.outputs_mut()[0].script_pubkey = Script::from(vec![0x51]);
    assert_distinct(&base, &accepted(&p));
    let mut p = fixture_pset();
    p.outputs_mut()[0].amount = Some(4_899);
    assert_distinct(&base, &accepted(&p));
    let mut p = fixture_pset();
    p.outputs_mut().swap(0, 1);
    assert_distinct(&base, &accepted(&p));
    let mut p = fixture_pset();
    p.outputs_mut()[0].blinder_index = None;
    assert!(matches!(
        accepted_result(&p),
        Err(Error::UnsupportedOutput) | Err(Error::InvalidEncoding)
    ));
    let mut p = fixture_pset();
    p.outputs_mut()[0].blinder_index = Some(1);
    assert!(matches!(accepted_result(&p), Err(Error::InvalidStructure)));
    let mut p = fixture_pset();
    p.outputs_mut()[0].asset = Some(AssetId::from_byte_array([9; 32]));
    assert!(matches!(accepted_result(&p), Err(Error::UnsupportedOutput)));
    let mut p = fixture_pset();
    p.outputs_mut()[0].unknown.insert(
        raw::Key {
            type_value: 0xfa,
            key: vec![],
        },
        vec![1],
    );
    assert!(matches!(accepted_result(&p), Err(Error::UnsupportedOutput)));
}

#[test]
fn exactly_one_explicit_fee_output_is_required() {
    let mut none = fixture_pset();
    none.remove_output(1);
    assert!(matches!(
        accepted_result(&none),
        Err(Error::InvalidStructure)
    ));
    let mut two = fixture_pset();
    two.add_output(Output::new_explicit(Script::new(), 1, asset(), None));
    assert!(matches!(
        accepted_result(&two),
        Err(Error::InvalidStructure)
    ));
    let mut wrong = fixture_pset();
    wrong.outputs_mut()[1].asset = Some(AssetId::from_byte_array([9; 32]));
    assert!(matches!(
        accepted_result(&wrong),
        Err(Error::UnsupportedOutput) | Err(Error::InvalidStructure)
    ));
}

#[test]
fn input_output_and_script_limits_have_boundaries() {
    let mut p = fixture_pset();
    p.inputs_mut()[0]
        .witness_utxo
        .as_mut()
        .unwrap()
        .script_pubkey = Script::from(vec![0x51; MAX_SCRIPT_BYTES]);
    accepted(&p);
    p.inputs_mut()[0]
        .witness_utxo
        .as_mut()
        .unwrap()
        .script_pubkey = Script::from(vec![0x51; MAX_SCRIPT_BYTES + 1]);
    assert!(matches!(accepted_result(&p), Err(Error::LimitExceeded)));

    let mut p = fixture_pset();
    while p.inputs().len() < MAX_INPUT_COUNT {
        let mut input = p.inputs()[0].clone();
        input.previous_txid = Txid::from_byte_array([p.inputs().len() as u8 + 1; 32]);
        p.add_input(input);
    }
    accepted(&p);
    let mut input = p.inputs()[0].clone();
    input.previous_txid = Txid::from_byte_array([0xfe; 32]);
    p.add_input(input);
    assert!(matches!(accepted_result(&p), Err(Error::LimitExceeded)));

    let mut p = fixture_pset();
    while p.outputs().len() < MAX_OUTPUT_COUNT {
        let mut output = p.outputs()[0].clone();
        output.blinder_index = Some(0);
        p.insert_output(output, 0);
    }
    accepted(&p);
    let output = p.outputs()[0].clone();
    p.insert_output(output, 0);
    assert!(matches!(accepted_result(&p), Err(Error::LimitExceeded)));
}

#[test]
fn all_errors_are_fixed_privacy_redacted_messages() {
    let variants = [
        Error::LimitExceeded,
        Error::InvalidContext,
        Error::InvalidEncoding,
        Error::NonCanonicalEncoding,
        Error::UnsupportedGlobal,
        Error::UnsupportedInput,
        Error::UnsupportedOutput,
        Error::UnknownAsset,
        Error::InvalidStructure,
        Error::TranscriptRejected,
    ];
    for error in variants {
        let display = error.to_string();
        let debug = format!("{error:?}");
        assert_eq!(display, debug);
        assert!(display.len() < 64);
        for forbidden in ["3333", "4444", "5000", "1111", "round-0001", "proof"] {
            assert!(!display.contains(forbidden));
        }
    }
}

#[test]
fn fully_blinded_proof_bearing_fixture_is_accepted_and_proofs_are_committed() {
    let pset = fully_blinded_fixture_pset();
    let baseline = accepted(&pset);
    let decoded: PartiallySignedTransaction =
        encode::deserialize(&encode::serialize(&pset)).unwrap();
    assert_eq!(
        decoded.outputs()[0].blind_value_proof,
        pset.outputs()[0].blind_value_proof
    );
    let mut changed = pset.clone();
    changed.outputs_mut()[0].amount = Some(changed.outputs()[0].amount.unwrap() + 1);
    assert!(matches!(
        accepted_result(&changed),
        Err(Error::UnknownAsset)
    ));
    let mut changed = pset;
    let bytes = changed.outputs()[0]
        .blind_asset_proof
        .as_ref()
        .unwrap()
        .to_vec();
    let mut mutated = bytes;
    let last = mutated.len() - 1;
    mutated[last] ^= 1;
    if let Ok(proof) = SurjectionProof::from_slice(&mutated) {
        changed.outputs_mut()[0].blind_asset_proof = Some(proof);
        assert!(matches!(
            accepted_result(&changed),
            Err(Error::UnknownAsset)
        ));
    }
    assert!(!baseline.canonical_bytes().is_empty());
}

#[test]
fn transaction_proofs_are_verified_against_exact_context() {
    let input_pset = confidential_input_fixture_pset();
    accepted(&input_pset);
    let mut input_changed = input_pset;
    input_changed.inputs_mut()[0]
        .witness_utxo
        .as_mut()
        .unwrap()
        .script_pubkey = Script::from(vec![0x51]);
    assert!(matches!(
        accepted_result(&input_changed),
        Err(Error::UnsupportedInput)
    ));

    let pset = fully_blinded_fixture_pset();
    accepted(&pset);

    let mut range_changed = pset.clone();
    range_changed.outputs_mut()[0].script_pubkey = Script::from(vec![0x51]);
    assert!(matches!(
        accepted_result(&range_changed),
        Err(Error::UnknownAsset)
    ));

    use rand::{SeedableRng, rngs::StdRng};
    let mut rng = StdRng::seed_from_u64(0xdec0_de01);
    let secp = Secp256k1::new();
    let output = &pset.outputs()[0];
    let wrong_domain_bf = Tweak::from_slice(&[0x66; 32]).unwrap();
    let wrong_generator = Generator::new_blinded(&secp, asset().into_tag(), wrong_domain_bf);
    let abf = AssetBlindingFactor::from_byte_array([1; 32]).unwrap();
    let wrong_domain_proof = SurjectionProof::new_with_input_count(
        &secp,
        &mut rng,
        asset(),
        abf,
        [(wrong_generator, asset().into_tag(), wrong_domain_bf)],
        1,
    )
    .unwrap();
    assert!(wrong_domain_proof.as_ref().unwrap().verify(
        &secp,
        output.asset_comm.unwrap(),
        &[wrong_generator]
    ));
    let mut surjection_changed = pset;
    surjection_changed.outputs_mut()[0].asset_surjection_proof = Some(wrong_domain_proof);
    assert!(matches!(
        accepted_result(&surjection_changed),
        Err(Error::UnknownAsset)
    ));
}

#[test]
fn add_remove_and_reorder_inputs_and_outputs_are_committed_or_rejected() {
    let base_pset = fixture_pset();
    let base = accepted(&base_pset);
    let mut added = base_pset.clone();
    let mut input = added.inputs()[0].clone();
    input.previous_txid = Txid::from_byte_array([0x77; 32]);
    added.add_input(input);
    assert_distinct(&base, &accepted(&added));
    let mut reordered = added.clone();
    reordered.inputs_mut().swap(0, 1);
    assert_distinct(&accepted(&added), &accepted(&reordered));
    let mut removed = added;
    removed.remove_input(0);
    assert_ne!(accepted(&removed).canonical_bytes(), base.canonical_bytes());

    let mut output_added = base_pset.clone();
    let mut output = output_added.outputs()[0].clone();
    output.amount = Some(1);
    output_added.insert_output(output, 0);
    assert_distinct(&base, &accepted(&output_added));
    let mut output_reordered = output_added.clone();
    output_reordered.outputs_mut().swap(0, 1);
    assert_distinct(&accepted(&output_added), &accepted(&output_reordered));
    let mut output_removed = output_added;
    output_removed.remove_output(0);
    assert_eq!(
        accepted(&output_removed).canonical_bytes(),
        base.canonical_bytes()
    );
}

#[test]
fn unsupported_standard_proprietary_unknown_and_taproot_classes_reject() {
    let mut p = fixture_pset();
    p.inputs_mut()[0].redeem_script = Some(Script::new());
    assert!(matches!(accepted_result(&p), Err(Error::UnsupportedInput)));
    let mut p = fixture_pset();
    p.inputs_mut()[0].tap_internal_key =
        Some(elements::bitcoin::key::XOnlyPublicKey::from_slice(&[2; 32]).unwrap());
    assert!(matches!(accepted_result(&p), Err(Error::UnsupportedInput)));
    let mut p = fixture_pset();
    p.inputs_mut()[0].proprietary.insert(
        raw::ProprietaryKey {
            prefix: b"x".to_vec(),
            subtype: 1,
            key: vec![],
        },
        vec![1],
    );
    assert!(matches!(accepted_result(&p), Err(Error::UnsupportedInput)));
    let mut p = fixture_pset();
    p.outputs_mut()[0].redeem_script = Some(Script::new());
    assert!(matches!(accepted_result(&p), Err(Error::UnsupportedOutput)));
    let mut p = fixture_pset();
    p.outputs_mut()[0].proprietary.insert(
        raw::ProprietaryKey {
            prefix: b"x".to_vec(),
            subtype: 1,
            key: vec![],
        },
        vec![1],
    );
    assert!(matches!(accepted_result(&p), Err(Error::UnsupportedOutput)));
}

#[test]
fn real_wire_noncanonical_forms_are_rejected() {
    let raw = fixture_bytes();

    let reordered = reorder_first_global_pairs(&raw);
    assert!(matches!(
        canonicalize_pset_state(&reordered, &context()),
        Err(Error::NonCanonicalEncoding)
    ));

    let mut duplicate = raw.clone();
    let (pairs, terminator) = global_pairs(&raw);
    let first = pairs[0].clone();
    duplicate.splice(terminator..terminator, first);
    assert!(matches!(
        canonicalize_pset_state(&duplicate, &context()),
        Err(Error::InvalidEncoding)
    ));

    let mut nonminimal = raw;
    assert_eq!(nonminimal[5], 1);
    nonminimal.splice(5..6, [0xfd, 1, 0]);
    assert!(matches!(
        canonicalize_pset_state(&nonminimal, &context()),
        Err(Error::InvalidEncoding)
    ));
}

#[test]
fn real_wire_duplicate_scalar_key_is_rejected() {
    let mut pset = fixture_pset();
    pset.global
        .scalars
        .push(Tweak::from_slice(&[0x41; 32]).unwrap());
    let raw = encode::serialize(&pset);
    let (pairs, terminator) = global_pairs(&raw);
    let scalar = pairs
        .iter()
        .rev()
        .find(|pair| pair[wire_varint(pair, 0).1] == 0xfc)
        .cloned()
        .expect("serialized scalar proprietary pair");
    let mut duplicate = raw;
    duplicate.splice(terminator..terminator, scalar);
    assert!(matches!(
        canonicalize_pset_state(&duplicate, &context()),
        Err(Error::InvalidEncoding)
    ));
}

#[test]
fn proof_bytes_are_each_committed_or_rejected() {
    let pset = fully_blinded_fixture_pset();
    let baseline = accepted(&pset);
    for field in [0u8, 1, 2, 3] {
        let mut changed = pset.clone();
        let proof = match field {
            0 => changed.outputs()[0]
                .value_rangeproof
                .as_ref()
                .unwrap()
                .to_vec(),
            1 => changed.outputs()[0]
                .asset_surjection_proof
                .as_ref()
                .unwrap()
                .to_vec(),
            2 => changed.outputs()[0]
                .blind_value_proof
                .as_ref()
                .unwrap()
                .to_vec(),
            _ => changed.outputs()[0]
                .blind_asset_proof
                .as_ref()
                .unwrap()
                .to_vec(),
        };
        let mut mutated = proof;
        *mutated.last_mut().unwrap() ^= 1;
        let parsed_range = RangeProof::from_slice(&mutated);
        let parsed_surjection = SurjectionProof::from_slice(&mutated);
        let result = match field {
            0 => parsed_range.map(|proof| {
                changed.outputs_mut()[0].value_rangeproof = Some(proof);
                accepted_result(&changed)
            }),
            1 => parsed_surjection.map(|proof| {
                changed.outputs_mut()[0].asset_surjection_proof = Some(proof);
                accepted_result(&changed)
            }),
            2 => parsed_range.map(|proof| {
                changed.outputs_mut()[0].blind_value_proof = Some(proof);
                accepted_result(&changed)
            }),
            _ => parsed_surjection.map(|proof| {
                changed.outputs_mut()[0].blind_asset_proof = Some(proof);
                accepted_result(&changed)
            }),
        };
        if let Ok(Ok(state)) = result {
            assert_distinct(&baseline, &state);
        }
    }
}

fn global_pairs(raw: &[u8]) -> (Vec<Vec<u8>>, usize) {
    let mut position = 5;
    let mut pairs = Vec::new();
    while raw[position] != 0 {
        let start = position;
        let (key_len, after_key_len) = wire_varint(raw, position);
        position = after_key_len + key_len;
        let (value_len, after_value_len) = wire_varint(raw, position);
        position = after_value_len + value_len;
        pairs.push(raw[start..position].to_vec());
    }
    (pairs, position)
}

fn reorder_first_global_pairs(raw: &[u8]) -> Vec<u8> {
    let (pairs, terminator) = global_pairs(raw);
    let mut reordered = raw[..5].to_vec();
    reordered.extend_from_slice(&pairs[1]);
    reordered.extend_from_slice(&pairs[0]);
    for pair in &pairs[2..] {
        reordered.extend_from_slice(pair);
    }
    reordered.push(0);
    reordered.extend_from_slice(&raw[terminator + 1..]);
    reordered
}

fn wire_varint(raw: &[u8], position: usize) -> (usize, usize) {
    match raw[position] {
        0xfd => (
            u16::from_le_bytes([raw[position + 1], raw[position + 2]]) as usize,
            position + 3,
        ),
        0xfe => (
            u32::from_le_bytes([
                raw[position + 1],
                raw[position + 2],
                raw[position + 3],
                raw[position + 4],
            ]) as usize,
            position + 5,
        ),
        0xff => (
            u64::from_le_bytes([
                raw[position + 1],
                raw[position + 2],
                raw[position + 3],
                raw[position + 4],
                raw[position + 5],
                raw[position + 6],
                raw[position + 7],
                raw[position + 8],
            ]) as usize,
            position + 9,
        ),
        length => (length as usize, position + 1),
    }
}

fn accepted_result(pset: &PartiallySignedTransaction) -> Result<CanonicalState, Error> {
    canonicalize_pset_state(&encode::serialize(pset), &context())
}

fn assert_distinct(left: &CanonicalState, right: &CanonicalState) {
    assert_ne!(left.canonical_bytes(), right.canonical_bytes());
    assert_ne!(left.digest(), right.digest());
}
