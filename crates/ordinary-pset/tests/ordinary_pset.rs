use std::collections::BTreeSet;

use elements::confidential::{AssetBlindingFactor, ValueBlindingFactor};
use elements::encode;
use elements::pset::PartiallySignedTransaction;
use elements::secp256k1_zkp::{Secp256k1, SecretKey, rand::thread_rng};
use elements::{
    AssetId, EcdsaSighashType, LockTime, OutPoint, RangeProof, RangeProofMessage, Script, Sequence,
    TxOut, TxOutSecrets, Txid,
};
use wasabi_liquid_native_address::{ConfidentialLiquidAddress, LiquidAddressProfile};
use wasabi_liquid_native_ordinary_pset::{
    ConfidentialOutput, ExplicitFee, MAX_ORDINARY_VALUE, PsetConstructionError, SpendableInput,
    SpendableInputError, prepare_ordinary_pset,
};
use wasabi_liquid_native_output_opening::open_confidential_output;

const CONFIDENTIAL_RECEIVE_ADDRESS: &str = "lq1qqf8er278e6nyvuwtgf39e6ewvdcnjupn9a86rzpx655y5lhkt0walu3djf9cklkxd3ryld97hu8h3xepw7sh2rlu7q45dcew5";

#[test]
fn constructs_balanced_multiasset_pset_with_one_fee_output() {
    let fee_asset = AssetId::from_byte_array([0x11; 32]);
    let second_asset = AssetId::from_byte_array([0x22; 32]);
    let inputs = vec![
        explicit_input(0x31, 0, fee_asset, 50_000),
        explicit_input(0x32, 1, second_asset, 9_000),
    ];
    let address = receive_address();
    let outputs = vec![
        ConfidentialOutput::from_address(fee_asset, 49_500, &address).unwrap(),
        ConfidentialOutput::from_address(second_asset, 9_000, &address).unwrap(),
    ];
    let fee = ExplicitFee::new(fee_asset, 500).unwrap();

    let prepared =
        prepare_ordinary_pset(inputs, outputs, fee, LockTime::ZERO).expect("balanced plan");
    let pset = prepared.as_pset();

    assert_eq!(pset.n_inputs(), 2);
    assert_eq!(pset.n_outputs(), 3);
    assert_eq!(prepared.confidential_output_indices(), &[0, 1]);
    assert_eq!(prepared.fee_output_index(), 2);
    assert_eq!(prepared.input_secret_count(), 2);
    assert_eq!(pset.global.version, 2);
    assert_eq!(pset.global.tx_data.version, 2);
    assert_eq!(pset.global.tx_data.fallback_locktime, Some(LockTime::ZERO));

    for input in pset.inputs() {
        assert!(input.witness_utxo.is_some());
        assert!(input.non_witness_utxo.is_none());
        assert_eq!(input.sequence, Some(Sequence::MAX));
        assert!(input.amount.is_none());
        assert!(input.asset.is_none());
        assert!(input.blind_value_proof.is_none());
        assert!(input.blind_asset_proof.is_none());
        assert_eq!(
            input.ecdsa_hash_ty(),
            Some(EcdsaSighashType::AllPlusRangeproof)
        );
    }
    for output in &pset.outputs()[..2] {
        assert!(output.blinding_key.is_some());
        assert_eq!(output.blinder_index, Some(0));
        assert!(output.amount_comm.is_none());
        assert!(output.asset_comm.is_none());
        assert!(output.value_rangeproof.is_none());
        assert!(output.asset_surjection_proof.is_none());
    }
    let fee_output = &pset.outputs()[2];
    assert!(fee_output.script_pubkey.is_empty());
    assert_eq!(fee_output.asset, Some(fee_asset));
    assert_eq!(fee_output.amount, Some(500));
    assert!(fee_output.blinding_key.is_none());
    assert!(fee_output.blinder_index.is_none());

    let extracted = pset.extract_tx().expect("structurally extractable");
    assert_eq!(
        extracted
            .output
            .iter()
            .filter(|output| output.is_fee())
            .count(),
        1
    );
    assert_eq!(extracted.output[2].asset.explicit(), Some(fee_asset));
    assert_eq!(extracted.output[2].value.explicit(), Some(500));

    let mut rng = thread_rng();
    let secp = Secp256k1::new();
    let blinded = prepared.blind(&mut rng, &secp).expect("valid blinding");
    assert_eq!(blinded.confidential_output_indices(), &[0, 1]);
    assert_eq!(blinded.fee_output_index(), 2);
    for output in &blinded.as_pset().outputs()[..2] {
        assert!(output.asset_comm.is_some());
        assert!(output.amount_comm.is_some());
        assert!(output.ecdh_pubkey.is_some());
        assert!(output.value_rangeproof.is_some());
        assert!(output.asset_surjection_proof.is_some());
        assert!(output.blind_value_proof.is_some());
        assert!(output.blind_asset_proof.is_some());
    }
    let blinded_tx = blinded.as_pset().extract_tx().unwrap();
    assert!(blinded_tx.output[0].asset.is_confidential());
    assert!(blinded_tx.output[0].value.is_confidential());
    assert!(blinded_tx.output[1].asset.is_confidential());
    assert!(blinded_tx.output[1].value.is_confidential());
    assert!(blinded_tx.output[2].is_fee());
    let serialized = blinded.serialize_sensitive();
    let decoded: PartiallySignedTransaction = encode::deserialize(&serialized).unwrap();
    assert_eq!(encode::serialize(&decoded), serialized);
    assert!(
        decoded
            .inputs()
            .iter()
            .all(|input| { input.ecdsa_hash_ty() == Some(EcdsaSighashType::AllPlusRangeproof) })
    );

    let original_output = &blinded.as_pset().outputs()[0];
    let original_amount = original_output.amount.unwrap();
    let original_asset = original_output.asset.unwrap();
    let asset_commitment = original_output.asset_comm.unwrap();
    let amount_commitment = original_output.amount_comm.unwrap();
    assert!(
        original_output
            .blind_value_proof
            .as_ref()
            .unwrap()
            .blind_value_proof_verify(&secp, original_amount, asset_commitment, amount_commitment,)
    );
    assert!(
        original_output
            .blind_asset_proof
            .as_ref()
            .unwrap()
            .blind_asset_proof_verify(&secp, original_asset, asset_commitment)
    );

    let mut tampered_amount = blinded.as_pset().clone();
    tampered_amount.outputs_mut()[0].amount = Some(original_amount + 1);
    let output = &tampered_amount.outputs()[0];
    assert!(
        !output
            .blind_value_proof
            .as_ref()
            .unwrap()
            .blind_value_proof_verify(
                &secp,
                output.amount.unwrap(),
                output.asset_comm.unwrap(),
                output.amount_comm.unwrap(),
            )
    );

    let mut tampered_asset = blinded.as_pset().clone();
    tampered_asset.outputs_mut()[0].asset = Some(AssetId::from_byte_array([0xa1; 32]));
    let output = &tampered_asset.outputs()[0];
    assert!(
        !output
            .blind_asset_proof
            .as_ref()
            .unwrap()
            .blind_asset_proof_verify(&secp, output.asset.unwrap(), output.asset_comm.unwrap())
    );

    let mut missing_value_proof = blinded.as_pset().clone();
    missing_value_proof.outputs_mut()[0].blind_value_proof = Some(RangeProof::EMPTY);
    let output = &missing_value_proof.outputs()[0];
    assert!(
        !output
            .blind_value_proof
            .as_ref()
            .unwrap()
            .blind_value_proof_verify(
                &secp,
                output.amount.unwrap(),
                output.asset_comm.unwrap(),
                output.amount_comm.unwrap(),
            )
    );
}

#[test]
fn confidential_input_opening_is_bound_without_pset_disclosure() {
    let mut rng = thread_rng();
    let secp = Secp256k1::new();
    let receiver_key = SecretKey::new(&mut rng);
    let asset = AssetId::from_byte_array([0x43; 32]);
    let value = 25_000;
    let secrets = TxOutSecrets::new(
        asset,
        AssetBlindingFactor::new(&mut rng),
        value,
        ValueBlindingFactor::new(&mut rng),
    );
    let spent_secrets = TxOutSecrets::new(
        asset,
        AssetBlindingFactor::new(&mut rng),
        value + 1,
        ValueBlindingFactor::new(&mut rng),
    );
    let ephemeral_key = SecretKey::new(&mut rng);
    let confidential_utxo = TxOut::with_txout_secrets(
        &mut rng,
        &secp,
        native_witness_script(),
        receiver_key.public_key(&secp),
        ephemeral_key,
        secrets,
        &[spent_secrets],
    )
    .unwrap();
    let opened = open_confidential_output(&secp, &confidential_utxo, &receiver_key).unwrap();
    let input = SpendableInput::from_confidential(
        &secp,
        OutPoint::new(Txid::from_byte_array([0x44; 32]), 2),
        confidential_utxo.clone(),
        Sequence::MAX,
        opened,
    )
    .expect("opening matches commitments");
    let address = receive_address();
    let output = ConfidentialOutput::from_address(asset, value - 100, &address).unwrap();

    let prepared = prepare_ordinary_pset(
        vec![input],
        vec![output],
        ExplicitFee::new(asset, 100).unwrap(),
        LockTime::ZERO,
    )
    .unwrap();
    let pset_input = &prepared.as_pset().inputs()[0];

    let pset_witness_utxo = pset_input.witness_utxo.as_ref().unwrap();
    assert_eq!(pset_witness_utxo.asset, confidential_utxo.asset);
    assert_eq!(pset_witness_utxo.value, confidential_utxo.value);
    assert_eq!(pset_witness_utxo.nonce, confidential_utxo.nonce);
    assert_eq!(
        pset_witness_utxo.script_pubkey,
        confidential_utxo.script_pubkey
    );
    assert!(pset_witness_utxo.witness.rangeproof.is_empty());
    assert!(pset_witness_utxo.witness.surjection_proof.is_empty());
    assert_eq!(
        pset_input.in_utxo_rangeproof.as_ref(),
        Some(&confidential_utxo.witness.rangeproof)
    );
    assert!(pset_input.amount.is_none());
    assert!(pset_input.asset.is_none());

    let bytes = prepared.serialize_unblinded();
    let decoded: PartiallySignedTransaction = encode::deserialize(&bytes).unwrap();
    assert!(decoded.inputs()[0].amount.is_none());
    assert!(decoded.inputs()[0].asset.is_none());
    assert_eq!(
        decoded.inputs()[0].in_utxo_rangeproof,
        pset_input.in_utxo_rangeproof
    );
    assert_eq!(encode::serialize(&decoded), bytes);

    let blinded = prepared
        .blind(&mut rng, &secp)
        .expect("retained opening supports blinding");
    let output = &blinded.as_pset().outputs()[0];
    assert!(output.asset_comm.is_some());
    assert!(output.amount_comm.is_some());
    assert!(output.value_rangeproof.is_some());
    assert!(output.asset_surjection_proof.is_some());
}

#[test]
fn rejects_opening_bound_to_different_confidential_output() {
    let mut rng = thread_rng();
    let secp = Secp256k1::new();
    let receiver_key = SecretKey::new(&mut rng);
    let asset = AssetId::from_byte_array([0x53; 32]);
    let make_output = |rng: &mut _, value| {
        let secrets = TxOutSecrets::new(
            asset,
            AssetBlindingFactor::new(rng),
            value,
            ValueBlindingFactor::new(rng),
        );
        let spent = TxOutSecrets::new(
            asset,
            AssetBlindingFactor::new(rng),
            value + 1,
            ValueBlindingFactor::new(rng),
        );
        let ephemeral_key = SecretKey::new(rng);
        TxOut::with_txout_secrets(
            rng,
            &secp,
            native_witness_script(),
            receiver_key.public_key(&secp),
            ephemeral_key,
            secrets,
            &[spent],
        )
        .unwrap()
    };
    let first = make_output(&mut rng, 2_000);
    let second = make_output(&mut rng, 2_000);
    let opened_first = open_confidential_output(&secp, &first, &receiver_key).unwrap();

    let result = SpendableInput::from_confidential(
        &secp,
        OutPoint::new(Txid::from_byte_array([0x54; 32]), 0),
        second,
        Sequence::MAX,
        opened_first,
    );

    assert!(matches!(result, Err(SpendableInputError::OpeningMismatch)));
}

#[test]
fn rejects_cross_asset_substitution_even_when_total_value_matches() {
    let first_asset = AssetId::from_byte_array([0x61; 32]);
    let second_asset = AssetId::from_byte_array([0x62; 32]);
    let input = explicit_input(0x63, 0, first_asset, 10_000);
    let address = receive_address();
    let output = ConfidentialOutput::from_address(second_asset, 9_500, &address).unwrap();

    let result = prepare_ordinary_pset(
        vec![input],
        vec![output],
        ExplicitFee::new(first_asset, 500).unwrap(),
        LockTime::ZERO,
    );

    assert!(matches!(
        result,
        Err(PsetConstructionError::AssetBalanceMismatch)
    ));
}

#[test]
fn rejects_duplicate_and_null_inputs() {
    let asset = AssetId::from_byte_array([0x71; 32]);
    let outpoint = OutPoint::new(Txid::from_byte_array([0x72; 32]), 1);
    let previous = explicit_output(asset, 2_000);
    let first = SpendableInput::from_explicit(outpoint, previous.clone(), Sequence::MAX).unwrap();
    let second = SpendableInput::from_explicit(outpoint, previous, Sequence::MAX).unwrap();
    let output = ConfidentialOutput::from_address(asset, 1_900, &receive_address()).unwrap();
    let duplicate = prepare_ordinary_pset(
        vec![first, second],
        vec![output],
        ExplicitFee::new(asset, 2_100).unwrap(),
        LockTime::ZERO,
    );
    assert!(matches!(
        duplicate,
        Err(PsetConstructionError::DuplicateInput)
    ));

    let null = SpendableInput::from_explicit(
        OutPoint::null(),
        explicit_output(asset, 1_000),
        Sequence::MAX,
    );
    assert!(matches!(null, Err(SpendableInputError::CoinbaseOutpoint)));

    for reserved_vout in [1 << 30, 1 << 31] {
        let reserved = SpendableInput::from_explicit(
            OutPoint::new(Txid::from_byte_array([0x73; 32]), reserved_vout),
            explicit_output(asset, 1_000),
            Sequence::MAX,
        );
        assert!(matches!(
            reserved,
            Err(SpendableInputError::ReservedOutpointIndex)
        ));
    }
}

#[test]
fn rejects_empty_plan_zero_values_and_overflow() {
    let asset = AssetId::from_byte_array([0x81; 32]);
    let fee = ExplicitFee::new(asset, 100).unwrap();
    assert!(matches!(
        prepare_ordinary_pset(vec![], vec![], fee, LockTime::ZERO),
        Err(PsetConstructionError::NoInputs)
    ));
    assert!(ExplicitFee::new(asset, 0).is_err());
    assert!(ConfidentialOutput::from_address(asset, 0, &receive_address()).is_err());
    assert!(
        ConfidentialOutput::from_address(asset, MAX_ORDINARY_VALUE + 1, &receive_address())
            .is_err()
    );
    assert!(ExplicitFee::new(asset, MAX_ORDINARY_VALUE + 1).is_err());
    assert!(matches!(
        SpendableInput::from_explicit(
            OutPoint::new(Txid::from_byte_array([0x84; 32]), 0),
            explicit_output(asset, MAX_ORDINARY_VALUE + 1),
            Sequence::MAX,
        ),
        Err(SpendableInputError::ValueOutOfRange)
    ));

    let inputs = vec![
        explicit_input(0x82, 0, asset, MAX_ORDINARY_VALUE),
        explicit_input(0x83, 1, asset, MAX_ORDINARY_VALUE),
        explicit_input(0x85, 2, asset, 2),
    ];
    let output = ConfidentialOutput::from_address(asset, 1, &receive_address()).unwrap();
    let overflow = prepare_ordinary_pset(
        inputs,
        vec![output],
        ExplicitFee::new(asset, 1).unwrap(),
        LockTime::ZERO,
    );
    assert!(matches!(
        overflow,
        Err(PsetConstructionError::AmountOverflow)
    ));
}

#[test]
fn blinds_the_maximum_supported_value_and_rejects_the_next_value() {
    let asset = AssetId::from_byte_array([0x8e; 32]);
    let fee_asset = AssetId::from_byte_array([0x8f; 32]);
    let address = receive_address();
    let output = ConfidentialOutput::from_address(asset, MAX_ORDINARY_VALUE, &address).unwrap();
    let prepared = prepare_ordinary_pset(
        vec![
            explicit_input(0x90, 0, asset, MAX_ORDINARY_VALUE),
            explicit_input(0x91, 1, fee_asset, 1),
        ],
        vec![output],
        ExplicitFee::new(fee_asset, 1).unwrap(),
        LockTime::ZERO,
    )
    .unwrap();
    let mut rng = thread_rng();
    let secp = Secp256k1::new();

    let blinded = prepared
        .blind(&mut rng, &secp)
        .expect("maximum supported value blinds");

    assert_eq!(
        blinded.as_pset().outputs()[0].amount,
        Some(MAX_ORDINARY_VALUE)
    );
    assert!(matches!(
        ConfidentialOutput::from_address(asset, MAX_ORDINARY_VALUE + 1, &address),
        Err(wasabi_liquid_native_ordinary_pset::ConfidentialOutputError::ValueOutOfRange)
    ));
}

#[test]
fn rejects_inert_locktime_and_preserves_active_height_and_time_locks() {
    let asset = AssetId::from_byte_array([0x86; 32]);
    let address = receive_address();
    let height_lock = LockTime::from_height(1_000).unwrap();
    let inert = prepare_ordinary_pset(
        vec![explicit_input(0x87, 0, asset, 1_000)],
        vec![ConfidentialOutput::from_address(asset, 900, &address).unwrap()],
        ExplicitFee::new(asset, 100).unwrap(),
        height_lock,
    );
    assert!(matches!(inert, Err(PsetConstructionError::InertLockTime)));

    for (txid_byte, lock_time) in [
        (0x88, height_lock),
        (0x89, LockTime::from_time(1_700_000_000).unwrap()),
    ] {
        let input = SpendableInput::from_explicit(
            OutPoint::new(Txid::from_byte_array([txid_byte; 32]), 0),
            explicit_output(asset, 1_000),
            Sequence::from_consensus(u32::MAX - 1),
        )
        .unwrap();
        let prepared = prepare_ordinary_pset(
            vec![input],
            vec![ConfidentialOutput::from_address(asset, 900, &address).unwrap()],
            ExplicitFee::new(asset, 100).unwrap(),
            lock_time,
        )
        .unwrap();
        assert_eq!(prepared.as_pset().locktime().unwrap(), lock_time);
        assert_eq!(
            prepared.as_pset().inputs()[0].sequence,
            Some(Sequence::from_consensus(u32::MAX - 1))
        );
    }
}

#[test]
fn rejects_non_witness_previous_output_scripts() {
    let asset = AssetId::from_byte_array([0x8a; 32]);
    let mut p2wsh = vec![0x00, 0x20];
    p2wsh.extend_from_slice(&[0x43; 32]);
    let mut p2tr = vec![0x51, 0x20];
    p2tr.extend_from_slice(&[0x44; 32]);

    for (vout, script) in [
        (0, Script::from(vec![0x51])),
        (1, Script::from(p2wsh)),
        (2, Script::from(p2tr)),
    ] {
        let mut output = explicit_output(asset, 1_000);
        output.script_pubkey = script;
        let result = SpendableInput::from_explicit(
            OutPoint::new(Txid::from_byte_array([0x8b; 32]), vout),
            output,
            Sequence::MAX,
        );
        assert!(matches!(
            result,
            Err(SpendableInputError::UnsupportedInputScript)
        ));
    }
}

#[test]
fn rejects_opened_confidential_zero_value() {
    let mut rng = thread_rng();
    let secp = Secp256k1::new();
    let receiver_key = SecretKey::new(&mut rng);
    let asset = AssetId::from_byte_array([0x8c; 32]);
    let asset_blinding_factor = AssetBlindingFactor::new(&mut rng);
    let value_blinding_factor = ValueBlindingFactor::new(&mut rng);
    let initial = TxOutSecrets::new(asset, asset_blinding_factor, 1, value_blinding_factor);
    let spent = TxOutSecrets::new(
        asset,
        AssetBlindingFactor::new(&mut rng),
        2,
        ValueBlindingFactor::new(&mut rng),
    );
    let ephemeral_key = SecretKey::new(&mut rng);
    let mut output = TxOut::with_txout_secrets(
        &mut rng,
        &secp,
        native_witness_script(),
        receiver_key.public_key(&secp),
        ephemeral_key,
        initial,
        &[spent],
    )
    .unwrap();
    let value_commitment = elements::confidential::Value::new_confidential_from_assetid(
        &secp,
        0,
        asset,
        value_blinding_factor,
        asset_blinding_factor,
    );
    let shared_secret = output.nonce.shared_secret(&receiver_key).unwrap();
    output.value = value_commitment;
    output.witness.rangeproof = RangeProof::new(
        &secp,
        0,
        value_commitment.commitment().unwrap(),
        0,
        value_blinding_factor.into_inner(),
        &RangeProofMessage::new(asset, asset_blinding_factor).to_byte_array(),
        output.script_pubkey.as_bytes(),
        shared_secret,
        TxOut::RANGEPROOF_EXP_SHIFT,
        TxOut::RANGEPROOF_MIN_PRIV_BITS,
        output.asset.commitment().unwrap(),
    )
    .unwrap();
    let opened = open_confidential_output(&secp, &output, &receiver_key).unwrap();

    let result = SpendableInput::from_confidential(
        &secp,
        OutPoint::new(Txid::from_byte_array([0x8d; 32]), 0),
        output,
        Sequence::MAX,
        opened,
    );

    assert!(matches!(result, Err(SpendableInputError::ZeroValue)));
}

#[test]
fn serialization_preserves_outpoint_order_and_exact_witness_utxos() {
    let asset = AssetId::from_byte_array([0x91; 32]);
    let inputs = vec![
        explicit_input(0x93, 3, asset, 4_000),
        explicit_input(0x92, 2, asset, 6_000),
    ];
    let expected = inputs
        .iter()
        .map(|input| (*input.outpoint(), input.witness_utxo().clone()))
        .collect::<Vec<_>>();
    let output = ConfidentialOutput::from_address(asset, 9_800, &receive_address()).unwrap();
    let prepared = prepare_ordinary_pset(
        inputs,
        vec![output],
        ExplicitFee::new(asset, 200).unwrap(),
        LockTime::ZERO,
    )
    .unwrap();
    let decoded: PartiallySignedTransaction =
        encode::deserialize(&prepared.serialize_unblinded()).unwrap();
    let actual = decoded
        .inputs()
        .iter()
        .map(|input| {
            (
                input.previous_outpoint(),
                input.witness_utxo.clone().unwrap(),
            )
        })
        .collect::<Vec<_>>();

    assert_eq!(actual, expected);
    assert_eq!(
        actual
            .iter()
            .map(|(outpoint, _)| *outpoint)
            .collect::<BTreeSet<_>>()
            .len(),
        2
    );
}

fn receive_address() -> ConfidentialLiquidAddress {
    ConfidentialLiquidAddress::parse(
        CONFIDENTIAL_RECEIVE_ADDRESS,
        LiquidAddressProfile::LiquidMainnet,
    )
    .unwrap()
}

fn explicit_input(txid_byte: u8, vout: u32, asset: AssetId, value: u64) -> SpendableInput {
    SpendableInput::from_explicit(
        OutPoint::new(Txid::from_byte_array([txid_byte; 32]), vout),
        explicit_output(asset, value),
        Sequence::MAX,
    )
    .unwrap()
}

fn explicit_output(asset: AssetId, value: u64) -> TxOut {
    TxOut {
        asset: elements::confidential::Asset::Explicit(asset),
        value: elements::confidential::Value::Explicit(value),
        nonce: elements::confidential::Nonce::Null,
        script_pubkey: native_witness_script(),
        witness: Default::default(),
    }
}

fn native_witness_script() -> Script {
    let mut bytes = vec![0x00, 0x14];
    bytes.extend_from_slice(&[0x42; 20]);
    Script::from(bytes)
}
