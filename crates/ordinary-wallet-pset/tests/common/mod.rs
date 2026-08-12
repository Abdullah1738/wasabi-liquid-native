use std::str::FromStr;

use elements::confidential::{Asset, AssetBlindingFactor, Nonce, Value, ValueBlindingFactor};
use elements::encode::serialize;
use elements::hashes::sha256;
use elements::secp256k1_zkp::{Secp256k1, SecretKey};
use elements::{
    Address, AddressParams, AssetId, LockTime, OutPoint, Script, Sequence, Transaction, TxIn,
    TxOut, TxOutSecrets, TxOutWitness,
};
use miniscript::Descriptor;
use miniscript::descriptor::DescriptorPublicKey;
use rand::SeedableRng;
use rand::rngs::StdRng;
use sha2::{Digest, Sha256};
use wasabi_liquid_native_address::{ConfidentialLiquidAddress, LiquidAddressProfile};
use wasabi_liquid_native_ordinary_pset::ConfidentialOutput;
use wasabi_liquid_native_wallet_facts::{
    BorrowedSelectedOutput, DescriptorCatalog, DescriptorNetwork, SelectedOutputBatch,
};

pub const TEST_PUBLIC_DESCRIPTOR: &str = "elwpkh([28b3f14e/84'/1'/0']tpubDC2Q4xK4XH72GM7MowNuajyWVbigRLBWKswyP5T88hpPwu5nGqJWnda8zhJEFt71av73Hm8mUMMFSz9acNVzz8b1UbdSHCDXKTbSv5eEytu/<0;1>/*)";

pub struct FundingFixture {
    pub transaction: Transaction,
    pub transaction_bytes: Vec<u8>,
    pub previous_transaction_bytes: Vec<u8>,
    pub fee_asset: AssetId,
    pub second_asset: AssetId,
    pub slip77: [u8; 32],
}

pub fn catalog() -> DescriptorCatalog {
    DescriptorCatalog::derive(TEST_PUBLIC_DESCRIPTOR, DescriptorNetwork::Test, 1).unwrap()
}

pub fn funding_fixture() -> FundingFixture {
    let slip77 = synthetic_material(b"ordinary wallet PSET SLIP77 material");
    let [external_script, internal_script] = descriptor_scripts();
    let fee_asset = AssetId::LIQUIDTESTNET_BTC;
    let second_asset = AssetId::from_byte_array([0x82; 32]);
    let previous = Transaction {
        version: 2,
        lock_time: LockTime::ZERO,
        input: vec![],
        output: vec![
            explicit_output(fee_asset, 1_000, Script::from(vec![0x51])),
            explicit_output(second_asset, 2_000, Script::from(vec![0x51])),
        ],
    };
    let spent_secrets = [
        TxOutSecrets::new(
            fee_asset,
            AssetBlindingFactor::zero(),
            1_000,
            ValueBlindingFactor::zero(),
        ),
        TxOutSecrets::new(
            second_asset,
            AssetBlindingFactor::zero(),
            2_000,
            ValueBlindingFactor::zero(),
        ),
    ];
    let secp = Secp256k1::new();
    let external_key = slip77_key(&slip77, external_script.as_bytes());
    let internal_key = slip77_key(&slip77, internal_script.as_bytes());
    let external_address = Address::from_script(
        &external_script,
        Some(external_key.public_key(&secp)),
        &AddressParams::ELEMENTS,
    )
    .unwrap();
    let mut rng = StdRng::from_seed(synthetic_material(
        b"ordinary wallet PSET funding fixture randomness",
    ));
    let (first_output, first_abf, first_vbf, _) = TxOut::new_not_last_confidential(
        &mut rng,
        &secp,
        900,
        &external_address,
        fee_asset,
        &spent_secrets,
    )
    .unwrap();
    let first_output_secrets = TxOutSecrets::new(fee_asset, first_abf, 900, first_vbf);
    let fee_secrets = TxOutSecrets::new(
        fee_asset,
        AssetBlindingFactor::zero(),
        100,
        ValueBlindingFactor::zero(),
    );
    let (second_output, _, _, _) = TxOut::new_last_confidential(
        &mut rng,
        &secp,
        2_000,
        second_asset,
        internal_script,
        internal_key.public_key(&secp),
        &spent_secrets,
        &[&first_output_secrets, &fee_secrets],
    )
    .unwrap();
    let transaction = Transaction {
        version: 2,
        lock_time: LockTime::ZERO,
        input: vec![
            input(OutPoint::new(previous.txid(), 0)),
            input(OutPoint::new(previous.txid(), 1)),
        ],
        output: vec![first_output, second_output, TxOut::new_fee(100, fee_asset)],
    };

    FundingFixture {
        transaction_bytes: serialize(&transaction),
        previous_transaction_bytes: serialize(&previous),
        transaction,
        fee_asset,
        second_asset,
        slip77,
    }
}

pub fn selected_batch(fixture: &FundingFixture, output_indices: &[u32]) -> SelectedOutputBatch {
    let previous = std::slice::from_ref(&fixture.previous_transaction_bytes);
    let requests = output_indices
        .iter()
        .map(|index| BorrowedSelectedOutput::new(&fixture.transaction_bytes, previous, *index))
        .collect::<Vec<_>>();
    SelectedOutputBatch::new(&requests).unwrap()
}

pub fn planned_outputs(fixture: &FundingFixture) -> Vec<ConfidentialOutput> {
    let address = receive_address();
    vec![
        ConfidentialOutput::from_address(fixture.second_asset, 2_000, &address).unwrap(),
        ConfidentialOutput::from_address(fixture.fee_asset, 800, &address).unwrap(),
    ]
}

pub fn receive_address() -> ConfidentialLiquidAddress {
    let script = descriptor_scripts()[0].clone();
    let secp = Secp256k1::new();
    let key = SecretKey::from_slice(&synthetic_material(
        b"ordinary wallet PSET receiver blinding key",
    ))
    .unwrap();
    let address = Address::from_script(
        &script,
        Some(key.public_key(&secp)),
        &AddressParams::ELEMENTS,
    )
    .unwrap();
    ConfidentialLiquidAddress::parse(&address.to_string(), LiquidAddressProfile::ElementsDefault)
        .unwrap()
}

pub fn synthetic_material(label: &[u8]) -> [u8; 32] {
    sha256::Hash::hash(label).to_byte_array()
}

fn descriptor_scripts() -> [Script; 2] {
    let inner = TEST_PUBLIC_DESCRIPTOR
        .strip_prefix("elwpkh(")
        .and_then(|value| value.strip_suffix(')'))
        .unwrap();
    let descriptor = Descriptor::<DescriptorPublicKey>::from_str(&format!("wpkh({inner})"))
        .unwrap()
        .into_single_descriptors()
        .unwrap();
    let secp = miniscript::bitcoin::secp256k1::Secp256k1::verification_only();
    let first = descriptor[0]
        .at_derivation_index(0)
        .unwrap()
        .derived_descriptor(&secp)
        .unwrap();
    let second = descriptor[1]
        .at_derivation_index(1)
        .unwrap()
        .derived_descriptor(&secp)
        .unwrap();
    [
        Script::from(first.script_pubkey().into_bytes()),
        Script::from(second.script_pubkey().into_bytes()),
    ]
}

fn slip77_key(master_key: &[u8; 32], script: &[u8]) -> SecretKey {
    let mut inner_pad = [0x36; 64];
    let mut outer_pad = [0x5c; 64];
    for (index, key_byte) in master_key.iter().enumerate() {
        inner_pad[index] ^= key_byte;
        outer_pad[index] ^= key_byte;
    }
    let mut inner = Sha256::new();
    inner.update(inner_pad);
    inner.update(script);
    let inner_digest = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(outer_pad);
    outer.update(inner_digest);
    SecretKey::from_slice(&outer.finalize()).unwrap()
}

fn explicit_output(asset: AssetId, value: u64, script_pubkey: Script) -> TxOut {
    TxOut {
        asset: Asset::Explicit(asset),
        value: Value::Explicit(value),
        nonce: Nonce::Null,
        script_pubkey,
        witness: TxOutWitness::default(),
    }
}

fn input(previous_output: OutPoint) -> TxIn {
    TxIn {
        previous_output,
        is_pegin: false,
        script_sig: Script::new(),
        sequence: Sequence::MAX,
        asset_issuance: Default::default(),
        witness: Default::default(),
    }
}
