use std::str::FromStr;

use elements::confidential::{Asset, AssetBlindingFactor, Nonce, Value, ValueBlindingFactor};
use elements::encode::serialize;
use elements::hashes::sha256;
use elements::secp256k1_zkp::{All, Secp256k1, SecretKey};
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
use wasabi_liquid_native_ordinary_wallet_pset::OrdinaryWalletPsetError;
use wasabi_liquid_native_output_opening::{OpenedOutput, open_confidential_output};
use wasabi_liquid_native_wallet_facts::{
    DescriptorCatalog, DescriptorNetwork, SelectedOutputOpeningProvider,
};

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
fn prepared_request_consumes_into_a_blinded_pset() {
    let catalog = DescriptorCatalog::derive(TEST_DESCRIPTOR, DescriptorNetwork::Test, 0).unwrap();
    let funding = two_confidential_funding_fixture();
    let prepared = prepare_two_exact(&catalog, &funding);
    assert_eq!(prepared.source_revision(), 29);
    assert_eq!(prepared.selected_input_count(), 2);

    let mut provider = FixtureOpeningProvider::opening(synthetic_material(
        b"ordinary wallet plan two-output blinding material",
    ));
    let mut rng = StdRng::from_seed(synthetic_material(
        b"ordinary wallet plan two-output funding randomness",
    ));
    let blinded = prepared
        .into_blinded_ordinary_wallet_pset(&mut provider, &mut rng)
        .unwrap();

    assert_eq!(provider.calls(), 2);
    assert_eq!(provider.opened(), 2);
    assert_eq!(
        provider.seen_commitments(),
        funding.transaction.output[..2]
            .iter()
            .map(|output| output.value)
            .collect::<Vec<_>>()
    );
    assert_eq!(blinded.as_pset().inputs().len(), 2);
    assert_eq!(blinded.as_pset().outputs().len(), 2);
    assert_eq!(blinded.confidential_output_indices(), &[0]);
    assert_eq!(blinded.fee_output_index(), 1);
    assert!(blinded.as_pset().outputs()[1].script_pubkey.is_empty());
}

#[test]
fn two_row_refusal_is_nontransactional_and_retry_restarts_at_row_zero() {
    let catalog = DescriptorCatalog::derive(TEST_DESCRIPTOR, DescriptorNetwork::Test, 0).unwrap();
    let funding = two_confidential_funding_fixture();
    let expected_order = funding.transaction.output[..2]
        .iter()
        .map(|output| output.value)
        .collect::<Vec<_>>();
    let prepared = prepare_two_exact(&catalog, &funding);
    let mut refusing = FixtureOpeningProvider::refusing_at(
        synthetic_material(b"ordinary wallet plan two-output blinding material"),
        1,
    );
    let mut rng = StdRng::from_seed(synthetic_material(
        b"ordinary wallet plan two-output funding randomness",
    ));
    assert_eq!(
        prepared
            .into_blinded_ordinary_wallet_pset(&mut refusing, &mut rng)
            .err()
            .unwrap(),
        OrdinaryWalletPsetError::InvalidSelectedOutput
    );
    assert_eq!(refusing.calls(), 2);
    assert_eq!(refusing.opened(), 1);
    assert_eq!(refusing.seen_commitments(), expected_order);

    let prepared = prepare_two_exact(&catalog, &funding);
    let mut retry = FixtureOpeningProvider::opening(synthetic_material(
        b"ordinary wallet plan two-output blinding material",
    ));
    let mut rng = StdRng::from_seed(synthetic_material(
        b"ordinary wallet plan two-output funding randomness",
    ));
    let blinded = prepared
        .into_blinded_ordinary_wallet_pset(&mut retry, &mut rng)
        .unwrap();
    assert_eq!(retry.calls(), 2);
    assert_eq!(retry.opened(), 2);
    assert_eq!(retry.seen_commitments(), expected_order);
    assert_eq!(blinded.fee_output_index(), 1);
}

#[test]
fn composed_opening_refusal_and_value_mismatch_are_equally_redacted() {
    let catalog = DescriptorCatalog::derive(TEST_DESCRIPTOR, DescriptorNetwork::Test, 0).unwrap();
    let funding = funding_fixture();
    let prepared = prepare_single(
        &catalog,
        &funding.transaction_bytes,
        std::slice::from_ref(&funding.previous_bytes),
        funding.transaction.txid().to_byte_array(),
        0,
        funding.asset,
        900,
        800,
        100,
    )
    .unwrap();
    let mut refusing = FixtureOpeningProvider::refusing_at(
        synthetic_material(b"ordinary wallet plan test blinding material"),
        0,
    );
    let mut rng = StdRng::from_seed(synthetic_material(
        b"ordinary wallet plan test funding randomness",
    ));
    assert_eq!(
        prepared
            .into_blinded_ordinary_wallet_pset(&mut refusing, &mut rng)
            .err()
            .unwrap(),
        OrdinaryWalletPsetError::InvalidSelectedOutput
    );
    assert_eq!(refusing.calls(), 1);
    assert_eq!(refusing.opened(), 0);

    let funding = funding_fixture();
    let prepared = prepare_single(
        &catalog,
        &funding.transaction_bytes,
        std::slice::from_ref(&funding.previous_bytes),
        funding.transaction.txid().to_byte_array(),
        0,
        funding.asset,
        700,
        600,
        100,
    )
    .unwrap();
    let mut mismatched = FixtureOpeningProvider::opening(synthetic_material(
        b"ordinary wallet plan test blinding material",
    ));
    let mut rng = StdRng::from_seed(synthetic_material(
        b"ordinary wallet plan test funding randomness",
    ));
    assert_eq!(
        prepared
            .into_blinded_ordinary_wallet_pset(&mut mismatched, &mut rng)
            .err()
            .unwrap(),
        OrdinaryWalletPsetError::InvalidSelectedOutput
    );
    assert_eq!(mismatched.calls(), 1);
    assert_eq!(mismatched.opened(), 1);
}

#[test]
fn composed_randomness_failure_precedes_provider_and_provider_panic_unwinds() {
    let catalog = DescriptorCatalog::derive(TEST_DESCRIPTOR, DescriptorNetwork::Test, 0).unwrap();
    let funding = funding_fixture();
    let prepared = prepare_single(
        &catalog,
        &funding.transaction_bytes,
        std::slice::from_ref(&funding.previous_bytes),
        funding.transaction.txid().to_byte_array(),
        0,
        funding.asset,
        900,
        800,
        100,
    )
    .unwrap();
    let mut provider = FixtureOpeningProvider::opening(synthetic_material(
        b"ordinary wallet plan test blinding material",
    ));
    assert_eq!(
        prepared
            .into_blinded_ordinary_wallet_pset(&mut provider, &mut FailedRandomness)
            .err()
            .unwrap(),
        OrdinaryWalletPsetError::RandomnessUnavailable
    );
    assert_eq!(provider.calls(), 0);

    let prepared = prepare_single(
        &catalog,
        &funding.transaction_bytes,
        std::slice::from_ref(&funding.previous_bytes),
        funding.transaction.txid().to_byte_array(),
        0,
        funding.asset,
        900,
        800,
        100,
    )
    .unwrap();
    let mut provider = FixtureOpeningProvider::opening(synthetic_material(
        b"ordinary wallet plan test blinding material",
    ));
    let mut late_failure = ContextThenBlindingFailureRng {
        context_seed_supplied: false,
        try_fill_calls: 0,
    };
    assert_eq!(
        prepared
            .into_blinded_ordinary_wallet_pset(&mut provider, &mut late_failure)
            .err()
            .unwrap(),
        OrdinaryWalletPsetError::BlindingFailed
    );
    assert_eq!(provider.calls(), 1);
    assert_eq!(late_failure.try_fill_calls, 2);

    let prepared = prepare_single(
        &catalog,
        &funding.transaction_bytes,
        std::slice::from_ref(&funding.previous_bytes),
        funding.transaction.txid().to_byte_array(),
        0,
        funding.asset,
        900,
        800,
        100,
    )
    .unwrap();
    let mut panicking = FixtureOpeningProvider::panicking(synthetic_material(
        b"ordinary wallet plan test blinding material",
    ));
    let mut rng = StdRng::from_seed(synthetic_material(
        b"ordinary wallet plan test funding randomness",
    ));
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = prepared.into_blinded_ordinary_wallet_pset(&mut panicking, &mut rng);
        }))
        .is_err()
    );
    assert_eq!(panicking.calls(), 1);
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

fn prepare_two_exact<'catalog>(
    catalog: &'catalog DescriptorCatalog,
    funding: &FundingFixture,
) -> PubliclyPreparedOrdinaryWalletPlanRequest<'catalog> {
    let transaction_id = funding.transaction.txid().to_byte_array();
    let asset = funding.asset.to_byte_array();
    let previous_transactions = vec![funding.previous_bytes.clone()];
    let selected = [
        OrdinaryWalletPlanSelectedRef::new(
            &transaction_id,
            0,
            &asset,
            900,
            &funding.transaction_bytes,
            &previous_transactions,
        ),
        OrdinaryWalletPlanSelectedRef::new(
            &transaction_id,
            1,
            &asset,
            700,
            &funding.transaction_bytes,
            &previous_transactions,
        ),
    ];
    let destinations = [OrdinaryWalletPlanDestinationRef::new(
        &asset,
        1_500,
        TESTNET_ADDRESS,
    )];
    let source_epoch = [0x62; 32];
    let request = OrdinaryWalletPlanRequestRef::new(
        &source_epoch,
        29,
        &TESTNET_MANIFEST,
        &asset,
        &selected,
        &destinations,
        100,
    );
    let encoded = encode_request(&request).unwrap();
    decode_request(encoded.as_bytes(), &source_epoch)
        .unwrap()
        .prepare(catalog, &Secp256k1::new())
        .unwrap()
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

enum OpeningBehavior {
    Open,
    RefuseAt(usize),
    Panic,
}

struct FixtureOpeningProvider {
    master_material: [u8; 32],
    calls: usize,
    opened: usize,
    seen_commitments: Vec<Value>,
    behavior: OpeningBehavior,
}

impl FixtureOpeningProvider {
    fn opening(master_material: [u8; 32]) -> Self {
        Self {
            master_material,
            calls: 0,
            opened: 0,
            seen_commitments: Vec::new(),
            behavior: OpeningBehavior::Open,
        }
    }

    fn refusing_at(master_material: [u8; 32], call: usize) -> Self {
        Self {
            master_material,
            calls: 0,
            opened: 0,
            seen_commitments: Vec::new(),
            behavior: OpeningBehavior::RefuseAt(call),
        }
    }

    fn panicking(master_material: [u8; 32]) -> Self {
        Self {
            master_material,
            calls: 0,
            opened: 0,
            seen_commitments: Vec::new(),
            behavior: OpeningBehavior::Panic,
        }
    }

    const fn calls(&self) -> usize {
        self.calls
    }

    const fn opened(&self) -> usize {
        self.opened
    }

    fn seen_commitments(&self) -> &[Value] {
        &self.seen_commitments
    }
}

impl SelectedOutputOpeningProvider for FixtureOpeningProvider {
    fn open_selected_output(
        &mut self,
        secp: &Secp256k1<All>,
        output: &TxOut,
    ) -> Option<OpenedOutput> {
        let call = self.calls;
        self.calls += 1;
        self.seen_commitments.push(output.value);
        match &self.behavior {
            OpeningBehavior::RefuseAt(refuse_at) if *refuse_at == call => return None,
            OpeningBehavior::Panic => panic!("test-only prepared plan provider unwind"),
            OpeningBehavior::Open | OpeningBehavior::RefuseAt(_) => {}
        };
        let key = ScopedFixtureBlindingKey(slip77_key(
            &self.master_material,
            output.script_pubkey.as_bytes(),
        ));
        let opened = open_confidential_output(secp, output, &key.0).ok();
        if opened.is_some() {
            self.opened += 1;
        }
        opened
    }
}

impl Drop for FixtureOpeningProvider {
    fn drop(&mut self) {
        self.master_material.fill(0);
    }
}

struct ScopedFixtureBlindingKey(SecretKey);

impl Drop for ScopedFixtureBlindingKey {
    fn drop(&mut self) {
        self.0.non_secure_erase();
    }
}

struct FailedRandomness;

impl rand::RngCore for FailedRandomness {
    fn next_u32(&mut self) -> u32 {
        panic!("failed random source used infallibly")
    }

    fn next_u64(&mut self) -> u64 {
        panic!("failed random source used infallibly")
    }

    fn fill_bytes(&mut self, _: &mut [u8]) {
        panic!("failed random source used infallibly")
    }

    fn try_fill_bytes(&mut self, _: &mut [u8]) -> Result<(), rand::Error> {
        Err(rand::Error::new(std::io::Error::other(
            "test random source unavailable",
        )))
    }
}

impl rand::CryptoRng for FailedRandomness {}

struct ContextThenBlindingFailureRng {
    context_seed_supplied: bool,
    try_fill_calls: usize,
}

impl rand::RngCore for ContextThenBlindingFailureRng {
    fn next_u32(&mut self) -> u32 {
        panic!("late failing random source used infallibly")
    }

    fn next_u64(&mut self) -> u64 {
        panic!("late failing random source used infallibly")
    }

    fn fill_bytes(&mut self, _: &mut [u8]) {
        panic!("late failing random source used infallibly")
    }

    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), rand::Error> {
        self.try_fill_calls += 1;
        if !self.context_seed_supplied {
            assert_eq!(destination.len(), 32);
            destination.copy_from_slice(&synthetic_material(
                b"ordinary wallet plan test funding randomness",
            ));
            self.context_seed_supplied = true;
            return Ok(());
        }
        assert_eq!(destination.len(), 32);
        Err(rand::Error::new(std::io::Error::other(
            "test blinding-stage entropy unavailable",
        )))
    }
}

impl rand::CryptoRng for ContextThenBlindingFailureRng {}

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
