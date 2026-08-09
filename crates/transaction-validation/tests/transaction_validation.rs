use std::collections::BTreeMap;

use elements::confidential::{Asset, AssetBlindingFactor, Nonce, Value, ValueBlindingFactor};
use elements::secp256k1_zkp::{Secp256k1, SecretKey, rand::thread_rng};
use elements::{
    AssetId, LockTime, OutPoint, RangeProof, Script, Sequence, SurjectionProof, Transaction, TxIn,
    TxOut, TxOutSecrets, TxOutWitness, Txid,
};
use wasabi_liquid_native_transaction_validation::{
    TransactionValidationError, ValidatedOutputOpenError, validate_transaction_amount_proofs,
};

#[test]
fn validates_explicit_amounts_and_binds_previous_outpoint() {
    let secp = Secp256k1::new();
    let outpoint = OutPoint::new(Txid::from_byte_array([0x31; 32]), 2);
    let asset = AssetId::LIQUIDTESTNET_BTC;
    let spent_output = explicit_output(asset, 1_000);
    let transaction = transaction(
        outpoint,
        vec![explicit_output(asset, 900), TxOut::new_fee(100, asset)],
    );

    let validated = validate_transaction_amount_proofs(
        &secp,
        &transaction,
        previous_output_map([(outpoint, spent_output)]),
    )
    .unwrap();

    assert!(core::ptr::eq(validated.transaction(), &transaction));
    assert_eq!(validated.previous_outputs().len(), 1);
    assert_eq!(
        validated.input_previous_output(0).map(|(key, _)| *key),
        Some(outpoint),
    );

    let different_outpoint = OutPoint::new(Txid::from_byte_array([0x32; 32]), 2);
    assert!(matches!(
        validate_transaction_amount_proofs(
            &secp,
            &transaction,
            previous_output_map([(different_outpoint, explicit_output(asset, 1_000))]),
        ),
        Err(TransactionValidationError::PreviousOutputMissing)
    ));
}

#[test]
fn validates_confidential_output_before_opening_it() {
    let mut rng = thread_rng();
    let secp = Secp256k1::new();
    let outpoint = OutPoint::new(Txid::from_byte_array([0x41; 32]), 0);
    let asset = AssetId::LIQUIDTESTNET_BTC;
    let spent_output = explicit_output(asset, 1_000);
    let spent_secrets = TxOutSecrets::new(
        asset,
        AssetBlindingFactor::zero(),
        1_000,
        ValueBlindingFactor::zero(),
    );
    let receiver_key = SecretKey::new(&mut rng);
    let receiver_public_key = receiver_key.public_key(&secp);
    let (confidential_output, _, _, _) = TxOut::new_last_confidential(
        &mut rng,
        &secp,
        900,
        asset,
        Script::from(vec![0x51]),
        receiver_public_key,
        &[spent_secrets],
        &[],
    )
    .unwrap();
    let transaction = transaction(
        outpoint,
        vec![confidential_output, TxOut::new_fee(100, asset)],
    );

    let validated = validate_transaction_amount_proofs(
        &secp,
        &transaction,
        previous_output_map([(outpoint, spent_output)]),
    )
    .unwrap();
    let opened = validated.open_output(&secp, 0, &receiver_key).unwrap();

    assert_eq!(opened.asset_id(), &asset.to_byte_array());
    assert_eq!(opened.value(), &900);
    assert!(matches!(
        validated.open_output(&secp, transaction.output.len(), &receiver_key),
        Err(ValidatedOutputOpenError::OutputIndexOutOfRange)
    ));
}

#[test]
fn rejects_missing_proof_and_unbalanced_amounts() {
    let mut rng = thread_rng();
    let secp = Secp256k1::new();
    let outpoint = OutPoint::new(Txid::from_byte_array([0x51; 32]), 1);
    let asset = AssetId::LIQUIDTESTNET_BTC;
    let spent_output = explicit_output(asset, 1_000);
    let spent_secrets = TxOutSecrets::new(
        asset,
        AssetBlindingFactor::zero(),
        1_000,
        ValueBlindingFactor::zero(),
    );
    let receiver_key = SecretKey::new(&mut rng);
    let (confidential_output, _, _, _) = TxOut::new_last_confidential(
        &mut rng,
        &secp,
        900,
        asset,
        Script::from(vec![0x51]),
        receiver_key.public_key(&secp),
        &[spent_secrets],
        &[],
    )
    .unwrap();
    let mut missing_range_proof_output = confidential_output.clone();
    missing_range_proof_output.witness.rangeproof = RangeProof::EMPTY;
    let missing_proof = transaction(
        outpoint,
        vec![missing_range_proof_output, TxOut::new_fee(100, asset)],
    );

    assert!(matches!(
        validate_transaction_amount_proofs(
            &secp,
            &missing_proof,
            previous_output_map([(outpoint, spent_output.clone())]),
        ),
        Err(TransactionValidationError::MissingRangeProof)
    ));

    let mut missing_surjection_proof_output = confidential_output;
    missing_surjection_proof_output.witness.surjection_proof = SurjectionProof::EMPTY;
    let missing_surjection_proof = transaction(
        outpoint,
        vec![missing_surjection_proof_output, TxOut::new_fee(100, asset)],
    );
    assert!(matches!(
        validate_transaction_amount_proofs(
            &secp,
            &missing_surjection_proof,
            previous_output_map([(outpoint, spent_output.clone())]),
        ),
        Err(TransactionValidationError::MissingSurjectionProof)
    ));

    let unbalanced = transaction(
        outpoint,
        vec![explicit_output(asset, 901), TxOut::new_fee(100, asset)],
    );
    assert!(matches!(
        validate_transaction_amount_proofs(
            &secp,
            &unbalanced,
            previous_output_map([(outpoint, spent_output)]),
        ),
        Err(TransactionValidationError::BalanceMismatch)
    ));
}

#[test]
fn rejects_empty_coinbase_and_duplicate_input_shapes() {
    let secp = Secp256k1::new();
    let asset = AssetId::LIQUIDTESTNET_BTC;
    let empty = Transaction {
        version: 2,
        lock_time: LockTime::ZERO,
        input: vec![],
        output: vec![],
    };
    assert!(matches!(
        validate_transaction_amount_proofs(&secp, &empty, BTreeMap::new()),
        Err(TransactionValidationError::EmptyTransaction)
    ));

    let null_outpoint = OutPoint::null();
    let coinbase = transaction(null_outpoint, vec![explicit_output(asset, 1_000)]);
    assert!(matches!(
        validate_transaction_amount_proofs(&secp, &coinbase, BTreeMap::new()),
        Err(TransactionValidationError::UnsupportedCoinbase)
    ));

    let repeated_outpoint = OutPoint::new(Txid::from_byte_array([0x61; 32]), 3);
    let mut duplicate = transaction(
        repeated_outpoint,
        vec![explicit_output(asset, 1_900), TxOut::new_fee(100, asset)],
    );
    duplicate.input.push(duplicate.input[0].clone());
    assert!(matches!(
        validate_transaction_amount_proofs(&secp, &duplicate, BTreeMap::new()),
        Err(TransactionValidationError::DuplicatePreviousOutput)
    ));
}

#[test]
fn rejects_count_mismatch_empty_outputs_issuance_and_pegin() {
    let secp = Secp256k1::new();
    let asset = AssetId::LIQUIDTESTNET_BTC;
    let outpoint = OutPoint::new(Txid::from_byte_array([0x71; 32]), 4);
    let spent_output = explicit_output(asset, 1_000);
    let ordinary = transaction(
        outpoint,
        vec![explicit_output(asset, 900), TxOut::new_fee(100, asset)],
    );

    assert!(matches!(
        validate_transaction_amount_proofs(&secp, &ordinary, BTreeMap::new()),
        Err(TransactionValidationError::InputCountMismatch)
    ));

    let no_outputs = transaction(outpoint, vec![]);
    assert!(matches!(
        validate_transaction_amount_proofs(
            &secp,
            &no_outputs,
            previous_output_map([(outpoint, spent_output)]),
        ),
        Err(TransactionValidationError::EmptyTransaction)
    ));

    let mut issuance = ordinary.clone();
    issuance.input[0].asset_issuance.amount = Value::Explicit(1);
    assert!(matches!(
        validate_transaction_amount_proofs(&secp, &issuance, BTreeMap::new()),
        Err(TransactionValidationError::UnsupportedIssuance)
    ));

    let mut pegin = ordinary;
    pegin.input[0].is_pegin = true;
    assert!(matches!(
        validate_transaction_amount_proofs(&secp, &pegin, BTreeMap::new()),
        Err(TransactionValidationError::UnsupportedPegin)
    ));
}

#[test]
fn associates_previous_outputs_by_outpoint_in_transaction_input_order() {
    let secp = Secp256k1::new();
    let asset = AssetId::LIQUIDTESTNET_BTC;
    let first_input = OutPoint::new(Txid::from_byte_array([0x82; 32]), 1);
    let second_input = OutPoint::new(Txid::from_byte_array([0x81; 32]), 0);
    let mut transaction = transaction(
        first_input,
        vec![explicit_output(asset, 900), TxOut::new_fee(100, asset)],
    );
    transaction.input.push(TxIn {
        previous_output: second_input,
        is_pegin: false,
        script_sig: Script::new(),
        sequence: Sequence::MAX,
        asset_issuance: Default::default(),
        witness: Default::default(),
    });

    let validated = validate_transaction_amount_proofs(
        &secp,
        &transaction,
        previous_output_map([
            (second_input, explicit_output(asset, 700)),
            (first_input, explicit_output(asset, 300)),
        ]),
    )
    .unwrap();

    let first = validated.input_previous_output(0).unwrap();
    let second = validated.input_previous_output(1).unwrap();
    assert_eq!(
        (*first.0, first.1.value),
        (first_input, Value::Explicit(300))
    );
    assert_eq!(
        (*second.0, second.1.value),
        (second_input, Value::Explicit(700))
    );
}

fn explicit_output(asset: AssetId, value: u64) -> TxOut {
    TxOut {
        asset: Asset::Explicit(asset),
        value: Value::Explicit(value),
        nonce: Nonce::Null,
        script_pubkey: Script::from(vec![0x51]),
        witness: TxOutWitness::default(),
    }
}

fn transaction(outpoint: OutPoint, outputs: Vec<TxOut>) -> Transaction {
    Transaction {
        version: 2,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: outpoint,
            is_pegin: false,
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            asset_issuance: Default::default(),
            witness: Default::default(),
        }],
        output: outputs,
    }
}

fn previous_output_map<const N: usize>(
    entries: [(OutPoint, TxOut); N],
) -> BTreeMap<OutPoint, TxOut> {
    entries.into_iter().collect()
}
