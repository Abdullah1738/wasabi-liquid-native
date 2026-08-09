use elements::confidential::{AssetBlindingFactor, Nonce, ValueBlindingFactor};
use elements::secp256k1_zkp::{Secp256k1, SecretKey, Tweak, rand::thread_rng};
use elements::{AssetId, RangeProof, Script, TxOut, TxOutSecrets};
use wasabi_liquid_native_output_opening::{OutputOpenError, open_confidential_output};

#[test]
fn opens_confidential_output_without_consuming_receiver_key() {
    let mut rng = thread_rng();
    let secp = Secp256k1::new();
    let receiver_key = SecretKey::new(&mut rng);
    let receiver_public_key = receiver_key.public_key(&secp);
    let ephemeral_key = SecretKey::new(&mut rng);
    let asset = AssetId::LIQUIDTESTNET_BTC;
    let value = 21_000_000;
    let asset_blinding_factor = AssetBlindingFactor::new(&mut rng);
    let value_blinding_factor = ValueBlindingFactor::new(&mut rng);
    let secrets = TxOutSecrets::new(asset, asset_blinding_factor, value, value_blinding_factor);
    let spent_secrets = TxOutSecrets::new(
        asset,
        AssetBlindingFactor::new(&mut rng),
        value + 1,
        ValueBlindingFactor::new(&mut rng),
    );
    let output = TxOut::with_txout_secrets(
        &mut rng,
        &secp,
        Script::new(),
        receiver_public_key,
        ephemeral_key,
        secrets,
        &[spent_secrets],
    )
    .unwrap();

    let opened = open_confidential_output(&secp, &output, &receiver_key).unwrap();

    assert_eq!(opened.asset_id(), &asset.to_byte_array());
    assert_eq!(opened.value(), value);
    assert_eq!(
        opened.asset_blinding_factor(),
        &tweak_bytes(asset_blinding_factor.into_inner())
    );
    assert_eq!(
        opened.value_blinding_factor(),
        &tweak_bytes(value_blinding_factor.into_inner())
    );

    let reopened = open_confidential_output(&secp, &output, &receiver_key).unwrap();
    assert_eq!(reopened.asset_id(), opened.asset_id());
    assert_eq!(reopened.value(), opened.value());
    let (reopened_asset, reopened_value, reopened_asset_blind, reopened_value_blind) =
        reopened.into_parts();
    assert_eq!(reopened_asset, asset.to_byte_array());
    assert_eq!(reopened_value, value);
    assert_eq!(
        reopened_asset_blind,
        tweak_bytes(asset_blinding_factor.into_inner())
    );
    assert_eq!(
        reopened_value_blind,
        tweak_bytes(value_blinding_factor.into_inner())
    );
}

#[test]
fn classifies_nonconfidential_output() {
    let mut rng = thread_rng();
    let secp = Secp256k1::new();
    let receiver_key = SecretKey::new(&mut rng);
    let output = TxOut::new_fee(500, AssetId::from_byte_array([0x2c; 32]));

    let result = open_confidential_output(&secp, &output, &receiver_key);

    assert!(matches!(result, Err(OutputOpenError::NotConfidential)));
}

#[test]
fn classifies_missing_confidential_fields() {
    let mut rng = thread_rng();
    let secp = Secp256k1::new();
    let receiver_key = SecretKey::new(&mut rng);
    let receiver_public_key = receiver_key.public_key(&secp);
    let asset = AssetId::LIQUIDTESTNET_BTC;
    let secrets = TxOutSecrets::new(
        asset,
        AssetBlindingFactor::new(&mut rng),
        1_000,
        ValueBlindingFactor::new(&mut rng),
    );
    let spent_secrets = TxOutSecrets::new(
        asset,
        AssetBlindingFactor::new(&mut rng),
        1_001,
        ValueBlindingFactor::new(&mut rng),
    );
    let ephemeral_key = SecretKey::new(&mut rng);
    let output = TxOut::with_txout_secrets(
        &mut rng,
        &secp,
        Script::new(),
        receiver_public_key,
        ephemeral_key,
        secrets,
        &[spent_secrets],
    )
    .unwrap();

    let mut without_nonce = output.clone();
    without_nonce.nonce = Nonce::Null;
    assert!(matches!(
        open_confidential_output(&secp, &without_nonce, &receiver_key),
        Err(OutputOpenError::MissingNonce)
    ));

    let mut without_range_proof = output;
    without_range_proof.witness.rangeproof = RangeProof::EMPTY;
    assert!(matches!(
        open_confidential_output(&secp, &without_range_proof, &receiver_key),
        Err(OutputOpenError::MissingRangeProof)
    ));
}

fn tweak_bytes(tweak: Tweak) -> [u8; 32] {
    let mut bytes = [0_u8; 32];
    bytes.copy_from_slice(tweak.as_ref());
    bytes
}
