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
use wasabi_liquid_native_ordinary_wallet_plan::{
    OrdinaryWalletPlanDestinationRef, OrdinaryWalletPlanRequestRef, OrdinaryWalletPlanSelectedRef,
    OrdinaryWalletPlanWireError, PubliclyPreparedOrdinaryWalletPlanRequest, decode_request,
    encode_request,
};
use wasabi_liquid_native_wallet_facts::{DescriptorCatalog, DescriptorNetwork};

const TEST_DESCRIPTOR: &str = "elwpkh([28b3f14e/84'/1'/0']tpubDC2Q4xK4XH72GM7MowNuajyWVbigRLBWKswyP5T88hpPwu5nGqJWnda8zhJEFt71av73Hm8mUMMFSz9acNVzz8b1UbdSHCDXKTbSv5eEytu/<0;1>/*)#u0khc0kg";
const TESTNET_ADDRESS: &str = "tlq1qq2xvpcvfup5j8zscjq05u2wxxjcyewk7979f3mmz5l7uw5pqmx6xf5xy50hsn6vhkm5euwt72x878eq6zxx2z58hd7zrsg9qn";
const TESTNET_MANIFEST: [u8; 32] = [
    0xe4, 0xe7, 0xec, 0x03, 0xe1, 0x9c, 0xe5, 0xf8, 0x3f, 0xd0, 0x4c, 0x58, 0x67, 0x88, 0xb7, 0x24,
    0xd8, 0x80, 0x52, 0xb6, 0x5e, 0xf2, 0x48, 0x0c, 0xc9, 0x3b, 0xcd, 0x50, 0x32, 0x4f, 0x6b, 0x20,
];
const MAINNET_DESCRIPTOR: &str = "elwpkh([73c5da0a/84'/1776'/0']xpub6CRFzUgHFDaiDAQFNX7VeV9JNPDRabq6NYSpzVZ8zW8ANUCiDdenkb1gBoEZuXNZb3wPc1SVcDXgD2ww5UBtTb8s8ArAbTkoRQ8qn34KgcY/<0;1>/*)";
const MAINNET_ADDRESS: &str = "lq1qqf8er278e6nyvuwtgf39e6ewvdcnjupn9a86rzpx655y5lhkt0walu3djf9cklkxd3ryld97hu8h3xepw7sh2rlu7q45dcew5";
const MAINNET_MANIFEST: [u8; 32] = [
    0xb8, 0x82, 0x44, 0xf8, 0x1d, 0xaf, 0x14, 0xb2, 0xf4, 0x79, 0x15, 0xd4, 0x30, 0xec, 0x41, 0xe5,
    0x40, 0x2d, 0xe5, 0x38, 0x02, 0x0f, 0x1e, 0x48, 0x47, 0xe8, 0xdd, 0xbd, 0x6f, 0x23, 0x8e, 0x5b,
];

#[test]
fn prepares_a_complete_publicly_validated_request_without_a_provider() {
    let catalog = DescriptorCatalog::derive(TEST_DESCRIPTOR, DescriptorNetwork::Test, 0).unwrap();
    let funding = funding_fixture();
    let source_epoch = [0x41; 32];
    let transaction_id = funding.transaction.txid().to_byte_array();
    let pegged_asset = funding.asset.to_byte_array();
    let previous_transactions = vec![funding.previous_bytes];
    let selected = [OrdinaryWalletPlanSelectedRef::new(
        &transaction_id,
        0,
        &pegged_asset,
        900,
        &funding.transaction_bytes,
        &previous_transactions,
    )];
    let destinations = [OrdinaryWalletPlanDestinationRef::new(
        &pegged_asset,
        800,
        TESTNET_ADDRESS,
    )];
    let request = OrdinaryWalletPlanRequestRef::new(
        &source_epoch,
        19,
        &TESTNET_MANIFEST,
        &pegged_asset,
        &selected,
        &destinations,
        100,
    );

    let encoded = encode_request(&request).unwrap();
    let parsed = decode_request(encoded.as_bytes(), &source_epoch).unwrap();
    let prepared = parsed.prepare(&catalog, &Secp256k1::new()).unwrap();
    assert_eq!(prepared.source_revision(), 19);
    assert_eq!(prepared.selected_input_count(), 1);
    assert_eq!(prepared.confidential_destination_count(), 1);
}

#[test]
fn request_prepare_binds_candidate_identifier_and_output_index() {
    let catalog = DescriptorCatalog::derive(TEST_DESCRIPTOR, DescriptorNetwork::Test, 0).unwrap();
    let funding = funding_fixture();
    let mut wrong_id = funding.transaction.txid().to_byte_array();
    wrong_id[0] ^= 1;
    assert_eq!(
        prepare_single(
            &catalog,
            &funding.transaction_bytes,
            std::slice::from_ref(&funding.previous_bytes),
            wrong_id,
            0,
            funding.asset,
            900,
            800,
            100,
        )
        .err()
        .unwrap(),
        OrdinaryWalletPlanWireError::FundingRejected
    );
    assert_eq!(
        prepare_single(
            &catalog,
            &funding.transaction_bytes,
            std::slice::from_ref(&funding.previous_bytes),
            funding.transaction.txid().to_byte_array(),
            2,
            funding.asset,
            900,
            800,
            100,
        )
        .err()
        .unwrap(),
        OrdinaryWalletPlanWireError::FundingRejected
    );
}

#[test]
fn request_prepare_rejects_noncanonical_and_incomplete_or_ambiguous_previous_sets() {
    let catalog = DescriptorCatalog::derive(TEST_DESCRIPTOR, DescriptorNetwork::Test, 0).unwrap();
    let funding = funding_fixture();
    let expected_id = funding.transaction.txid().to_byte_array();

    let mut noncanonical = funding.transaction_bytes.clone();
    noncanonical.push(0);
    assert_funding_rejected(prepare_single(
        &catalog,
        &noncanonical,
        std::slice::from_ref(&funding.previous_bytes),
        expected_id,
        0,
        funding.asset,
        900,
        800,
        100,
    ));
    assert_funding_rejected(prepare_single(
        &catalog,
        &funding.transaction_bytes,
        &[],
        expected_id,
        0,
        funding.asset,
        900,
        800,
        100,
    ));

    let unrelated = Transaction {
        version: 2,
        lock_time: LockTime::ZERO,
        input: vec![],
        output: vec![explicit_output(funding.asset, 7, Script::from(vec![0x51]))],
    };
    let mut extra = vec![funding.previous_bytes.clone(), serialize(&unrelated)];
    extra.sort();
    assert_funding_rejected(prepare_single(
        &catalog,
        &funding.transaction_bytes,
        &extra,
        expected_id,
        0,
        funding.asset,
        900,
        800,
        100,
    ));

    let mut witness_variant = funding.previous.clone();
    witness_variant.output[0].witness.rangeproof =
        funding.transaction.output[0].witness.rangeproof.clone();
    assert_eq!(witness_variant.txid(), funding.previous.txid());
    let mut duplicate_identity = vec![funding.previous_bytes.clone(), serialize(&witness_variant)];
    duplicate_identity.sort();
    assert_ne!(duplicate_identity[0], duplicate_identity[1]);
    assert_funding_rejected(prepare_single(
        &catalog,
        &funding.transaction_bytes,
        &duplicate_identity,
        expected_id,
        0,
        funding.asset,
        900,
        800,
        100,
    ));
}

#[test]
fn request_prepare_rejects_amount_proof_descriptor_and_public_shape_failures() {
    let catalog = DescriptorCatalog::derive(TEST_DESCRIPTOR, DescriptorNetwork::Test, 0).unwrap();
    let funding = funding_fixture();
    let mut damaged = funding.transaction.clone();
    damaged.output[0].witness.rangeproof = elements::RangeProof::EMPTY;
    assert_funding_rejected(prepare_single(
        &catalog,
        &serialize(&damaged),
        std::slice::from_ref(&funding.previous_bytes),
        damaged.txid().to_byte_array(),
        0,
        funding.asset,
        900,
        800,
        100,
    ));

    let unowned = funding_fixture_with_script(unowned_script());
    assert_funding_rejected(prepare_single(
        &catalog,
        &unowned.transaction_bytes,
        std::slice::from_ref(&unowned.previous_bytes),
        unowned.transaction.txid().to_byte_array(),
        0,
        unowned.asset,
        900,
        800,
        100,
    ));

    let explicit = explicit_funding_fixture();
    assert_funding_rejected(prepare_single(
        &catalog,
        &explicit.transaction_bytes,
        std::slice::from_ref(&explicit.previous_bytes),
        explicit.transaction.txid().to_byte_array(),
        0,
        explicit.asset,
        900,
        800,
        100,
    ));
}

#[test]
fn catalog_network_mismatch_rejects_in_both_context_directions() {
    let test_catalog =
        DescriptorCatalog::derive(TEST_DESCRIPTOR, DescriptorNetwork::Test, 0).unwrap();
    let main_catalog =
        DescriptorCatalog::derive(MAINNET_DESCRIPTOR, DescriptorNetwork::Mainnet, 0).unwrap();
    let funding = funding_fixture();
    assert_eq!(
        prepare_single(
            &main_catalog,
            &funding.transaction_bytes,
            std::slice::from_ref(&funding.previous_bytes),
            funding.transaction.txid().to_byte_array(),
            0,
            funding.asset,
            900,
            800,
            100,
        )
        .err()
        .unwrap(),
        OrdinaryWalletPlanWireError::ContextRejected
    );

    let candidate = [0x01];
    let previous = Vec::new();
    let selected_id = [0x31; 32];
    let main_asset = AssetId::LIQUID_BTC.to_byte_array();
    let selected = [OrdinaryWalletPlanSelectedRef::new(
        &selected_id,
        0,
        &main_asset,
        10,
        &candidate,
        &previous,
    )];
    let destinations = [OrdinaryWalletPlanDestinationRef::new(
        &main_asset,
        9,
        MAINNET_ADDRESS,
    )];
    let request = OrdinaryWalletPlanRequestRef::new(
        &[0x52; 32],
        1,
        &MAINNET_MANIFEST,
        &main_asset,
        &selected,
        &destinations,
        1,
    );
    let encoded = encode_request(&request).unwrap();
    assert_eq!(
        decode_request(encoded.as_bytes(), &[0x52; 32])
            .unwrap()
            .prepare(&test_catalog, &Secp256k1::new())
            .err()
            .unwrap(),
        OrdinaryWalletPlanWireError::ContextRejected
    );
}

#[test]
fn public_prepare_cannot_observe_confidential_value_or_asset_mismatches() {
    let catalog = DescriptorCatalog::derive(TEST_DESCRIPTOR, DescriptorNetwork::Test, 0).unwrap();
    let funding = funding_fixture();
    let value_mismatch = prepare_single(
        &catalog,
        &funding.transaction_bytes,
        std::slice::from_ref(&funding.previous_bytes),
        funding.transaction.txid().to_byte_array(),
        0,
        funding.asset,
        901,
        801,
        100,
    )
    .unwrap();
    drop(value_mismatch);

    let two = two_confidential_funding_fixture();
    let transaction_id = two.transaction.txid().to_byte_array();
    let actual_asset = two.asset.to_byte_array();
    let declared_other_asset = [0x77; 32];
    let previous_transactions = vec![two.previous_bytes];
    let selected = [
        OrdinaryWalletPlanSelectedRef::new(
            &transaction_id,
            0,
            &declared_other_asset,
            333,
            &two.transaction_bytes,
            &previous_transactions,
        ),
        OrdinaryWalletPlanSelectedRef::new(
            &transaction_id,
            1,
            &actual_asset,
            101,
            &two.transaction_bytes,
            &previous_transactions,
        ),
    ];
    let destinations = [
        OrdinaryWalletPlanDestinationRef::new(&declared_other_asset, 333, TESTNET_ADDRESS),
        OrdinaryWalletPlanDestinationRef::new(&actual_asset, 1, TESTNET_ADDRESS),
    ];
    let request = OrdinaryWalletPlanRequestRef::new(
        &[0x61; 32],
        23,
        &TESTNET_MANIFEST,
        &actual_asset,
        &selected,
        &destinations,
        100,
    );
    let encoded = encode_request(&request).unwrap();
    let prepared = decode_request(encoded.as_bytes(), &[0x61; 32])
        .unwrap()
        .prepare(&catalog, &Secp256k1::new())
        .unwrap();
    assert_eq!(prepared.selected_input_count(), 2);
}

struct FundingFixture {
    transaction: Transaction,
    transaction_bytes: Vec<u8>,
    previous: Transaction,
    previous_bytes: Vec<u8>,
    asset: AssetId,
}

fn funding_fixture() -> FundingFixture {
    funding_fixture_with_script(descriptor_script())
}

fn funding_fixture_with_script(script: Script) -> FundingFixture {
    let asset = AssetId::LIQUIDTESTNET_BTC;
    let previous = Transaction {
        version: 2,
        lock_time: LockTime::ZERO,
        input: vec![],
        output: vec![explicit_output(asset, 1_000, Script::from(vec![0x51]))],
    };
    let spent_secrets = [TxOutSecrets::new(
        asset,
        AssetBlindingFactor::zero(),
        1_000,
        ValueBlindingFactor::zero(),
    )];
    let secp = Secp256k1::new();
    let receiver_key = slip77_key(
        &synthetic_material(b"ordinary wallet plan test blinding material"),
        script.as_bytes(),
    );
    let address = Address::from_script(
        &script,
        Some(receiver_key.public_key(&secp)),
        &AddressParams::LIQUID_TESTNET,
    )
    .unwrap();
    let mut rng = StdRng::from_seed(synthetic_material(
        b"ordinary wallet plan test funding randomness",
    ));
    let fee_secrets = TxOutSecrets::new(
        asset,
        AssetBlindingFactor::zero(),
        100,
        ValueBlindingFactor::zero(),
    );
    let (selected_output, _, _, _) = TxOut::new_last_confidential(
        &mut rng,
        &secp,
        900,
        asset,
        address.script_pubkey(),
        receiver_key.public_key(&secp),
        &spent_secrets,
        &[&fee_secrets],
    )
    .unwrap();
    let transaction = Transaction {
        version: 2,
        lock_time: LockTime::ZERO,
        input: vec![transaction_input(OutPoint::new(previous.txid(), 0))],
        output: vec![selected_output, TxOut::new_fee(100, asset)],
    };
    FundingFixture {
        transaction_bytes: serialize(&transaction),
        previous_bytes: serialize(&previous),
        transaction,
        previous,
        asset,
    }
}

fn explicit_funding_fixture() -> FundingFixture {
    let asset = AssetId::LIQUIDTESTNET_BTC;
    let previous = Transaction {
        version: 2,
        lock_time: LockTime::ZERO,
        input: vec![],
        output: vec![explicit_output(asset, 1_000, Script::from(vec![0x51]))],
    };
    let transaction = Transaction {
        version: 2,
        lock_time: LockTime::ZERO,
        input: vec![transaction_input(OutPoint::new(previous.txid(), 0))],
        output: vec![
            explicit_output(asset, 900, descriptor_script()),
            TxOut::new_fee(100, asset),
        ],
    };
    FundingFixture {
        transaction_bytes: serialize(&transaction),
        previous_bytes: serialize(&previous),
        transaction,
        previous,
        asset,
    }
}

fn two_confidential_funding_fixture() -> FundingFixture {
    let asset = AssetId::LIQUIDTESTNET_BTC;
    let previous = Transaction {
        version: 2,
        lock_time: LockTime::ZERO,
        input: vec![],
        output: vec![explicit_output(asset, 1_700, Script::from(vec![0x51]))],
    };
    let spent_secrets = [TxOutSecrets::new(
        asset,
        AssetBlindingFactor::zero(),
        1_700,
        ValueBlindingFactor::zero(),
    )];
    let script = descriptor_script();
    let secp = Secp256k1::new();
    let receiver_key = slip77_key(
        &synthetic_material(b"ordinary wallet plan two-output blinding material"),
        script.as_bytes(),
    );
    let address = Address::from_script(
        &script,
        Some(receiver_key.public_key(&secp)),
        &AddressParams::LIQUID_TESTNET,
    )
    .unwrap();
    let mut rng = StdRng::from_seed(synthetic_material(
        b"ordinary wallet plan two-output funding randomness",
    ));
    let (first_output, first_abf, first_vbf, _) =
        TxOut::new_not_last_confidential(&mut rng, &secp, 900, &address, asset, &spent_secrets)
            .unwrap();
    let first_secrets = TxOutSecrets::new(asset, first_abf, 900, first_vbf);
    let fee_secrets = TxOutSecrets::new(
        asset,
        AssetBlindingFactor::zero(),
        100,
        ValueBlindingFactor::zero(),
    );
    let (second_output, _, _, _) = TxOut::new_last_confidential(
        &mut rng,
        &secp,
        700,
        asset,
        script,
        receiver_key.public_key(&secp),
        &spent_secrets,
        &[&first_secrets, &fee_secrets],
    )
    .unwrap();
    let transaction = Transaction {
        version: 2,
        lock_time: LockTime::ZERO,
        input: vec![transaction_input(OutPoint::new(previous.txid(), 0))],
        output: vec![first_output, second_output, TxOut::new_fee(100, asset)],
    };
    FundingFixture {
        transaction_bytes: serialize(&transaction),
        previous_bytes: serialize(&previous),
        transaction,
        previous,
        asset,
    }
}

fn unowned_script() -> Script {
    let mut bytes = vec![0x00, 0x14];
    bytes.extend_from_slice(&[0x77; 20]);
    Script::from(bytes)
}

#[allow(clippy::too_many_arguments)]
fn prepare_single<'catalog>(
    catalog: &'catalog DescriptorCatalog,
    transaction: &[u8],
    previous_transactions: &[Vec<u8>],
    expected_transaction_id: [u8; 32],
    expected_output_index: u32,
    expected_asset: AssetId,
    expected_value: u64,
    destination_value: u64,
    fee_value: u64,
) -> Result<PubliclyPreparedOrdinaryWalletPlanRequest<'catalog>, OrdinaryWalletPlanWireError> {
    let expected_asset = expected_asset.to_byte_array();
    let selected = [OrdinaryWalletPlanSelectedRef::new(
        &expected_transaction_id,
        expected_output_index,
        &expected_asset,
        expected_value,
        transaction,
        previous_transactions,
    )];
    let destinations = [OrdinaryWalletPlanDestinationRef::new(
        &expected_asset,
        destination_value,
        TESTNET_ADDRESS,
    )];
    let source_epoch = [0x41; 32];
    let request = OrdinaryWalletPlanRequestRef::new(
        &source_epoch,
        19,
        &TESTNET_MANIFEST,
        &expected_asset,
        &selected,
        &destinations,
        fee_value,
    );
    let encoded = encode_request(&request)?;
    decode_request(encoded.as_bytes(), &source_epoch)?.prepare(catalog, &Secp256k1::new())
}

fn assert_funding_rejected(
    result: Result<PubliclyPreparedOrdinaryWalletPlanRequest<'_>, OrdinaryWalletPlanWireError>,
) {
    assert_eq!(
        result.err().unwrap(),
        OrdinaryWalletPlanWireError::FundingRejected
    );
}

fn descriptor_script() -> Script {
    let inner = TEST_DESCRIPTOR
        .split_once('#')
        .map_or(TEST_DESCRIPTOR, |(body, _)| body)
        .strip_prefix("elwpkh(")
        .and_then(|value| value.strip_suffix(')'))
        .unwrap();
    let descriptors = Descriptor::<DescriptorPublicKey>::from_str(&format!("wpkh({inner})"))
        .unwrap()
        .into_single_descriptors()
        .unwrap();
    let secp = miniscript::bitcoin::secp256k1::Secp256k1::verification_only();
    Script::from(
        descriptors[0]
            .at_derivation_index(0)
            .unwrap()
            .derived_descriptor(&secp)
            .unwrap()
            .script_pubkey()
            .into_bytes(),
    )
}

fn synthetic_material(label: &[u8]) -> [u8; 32] {
    sha256::Hash::hash(label).to_byte_array()
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

fn transaction_input(previous_output: OutPoint) -> TxIn {
    TxIn {
        previous_output,
        is_pegin: false,
        script_sig: Script::new(),
        sequence: Sequence::MAX,
        asset_issuance: Default::default(),
        witness: Default::default(),
    }
}
