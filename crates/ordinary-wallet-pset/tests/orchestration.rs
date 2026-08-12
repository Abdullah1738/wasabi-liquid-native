mod common;

use elements::secp256k1_zkp::Secp256k1;
use elements::{EcdsaSighashType, LockTime, OutPoint, Sequence};
use rand::SeedableRng;
use rand::rngs::StdRng;
use wasabi_liquid_native_ordinary_pset::{
    BlindedOrdinaryPset, ConfidentialOutput, ExplicitFee, MAX_CONFIDENTIAL_OUTPUTS,
};
use wasabi_liquid_native_ordinary_wallet_pset::{
    OrdinaryWalletPsetError, build_blinded_ordinary_wallet_pset,
};
use wasabi_liquid_native_wallet_facts::{
    BorrowedSelectedOutput, BorrowedSlip77, SelectedOutputBatch,
};

use common::{
    catalog, funding_fixture, planned_outputs, receive_address, selected_batch, synthetic_material,
};

static_assertions::assert_not_impl_any!(BlindedOrdinaryPset: Copy, Clone, std::fmt::Debug);
static_assertions::assert_not_impl_any!(SelectedOutputBatch: Copy, Clone, std::fmt::Debug);

#[test]
fn builds_validated_two_asset_blinded_pset_with_exact_identity() {
    let catalog = catalog();
    let fixture = funding_fixture();
    let selected = selected_batch(&fixture, &[1, 0]);
    let mut rng = StdRng::from_seed(synthetic_material(
        b"ordinary wallet PSET orchestration success randomness",
    ));

    let blinded = build_blinded_ordinary_wallet_pset(
        &catalog,
        BorrowedSlip77::new(&fixture.slip77),
        selected,
        planned_outputs(&fixture),
        ExplicitFee::new(fixture.fee_asset, 100).unwrap(),
        &mut rng,
    )
    .unwrap();
    let pset = blinded.as_pset();

    assert_eq!(pset.n_inputs(), 2);
    assert_eq!(pset.n_outputs(), 3);
    assert_eq!(pset.global.tx_data.fallback_locktime, Some(LockTime::ZERO));
    let expected_outpoints = [
        OutPoint::new(fixture.transaction.txid(), 1),
        OutPoint::new(fixture.transaction.txid(), 0),
    ];
    assert_eq!(
        pset.inputs()
            .iter()
            .map(|input| input.previous_outpoint())
            .collect::<Vec<_>>(),
        expected_outpoints
    );
    for input in pset.inputs() {
        assert_eq!(input.sequence, Some(Sequence::MAX));
        assert_eq!(
            input.ecdsa_hash_ty(),
            Some(EcdsaSighashType::AllPlusRangeproof)
        );
        assert!(input.witness_utxo.is_some());
        assert!(input.in_utxo_rangeproof.is_some());
    }
    assert_eq!(pset.outputs()[0].asset, Some(fixture.second_asset));
    assert_eq!(pset.outputs()[0].amount, Some(2_000));
    assert_eq!(pset.outputs()[1].asset, Some(fixture.fee_asset));
    assert_eq!(pset.outputs()[1].amount, Some(800));
    for output in &pset.outputs()[..2] {
        assert!(output.asset_comm.is_some());
        assert!(output.amount_comm.is_some());
        assert!(output.ecdh_pubkey.is_some());
        assert!(output.value_rangeproof.is_some());
        assert!(output.asset_surjection_proof.is_some());
        assert!(output.blind_asset_proof.is_some());
        assert!(output.blind_value_proof.is_some());
    }
    let fee = &pset.outputs()[2];
    assert!(fee.script_pubkey.is_empty());
    assert_eq!(fee.asset, Some(fixture.fee_asset));
    assert_eq!(fee.amount, Some(100));
    assert_eq!(blinded.confidential_output_indices(), &[0, 1]);
    assert_eq!(blinded.fee_output_index(), 2);

    let secp = Secp256k1::new();
    pset.verify_all_surjection_proofs_use_all_inputs(&secp, &[0, 1])
        .unwrap();
    let transaction = pset.extract_tx().unwrap();
    let previous_outputs = pset
        .inputs()
        .iter()
        .map(|input| input.witness_utxo.clone().unwrap())
        .collect::<Vec<_>>();
    transaction
        .verify_tx_amt_proofs(&secp, &previous_outputs)
        .unwrap();
}

#[test]
fn rejects_public_selection_failures_before_randomness() {
    let catalog = catalog();
    let fixture = funding_fixture();
    let missing_previous = Vec::new();
    let missing_request = [BorrowedSelectedOutput::new(
        &fixture.transaction_bytes,
        &missing_previous,
        0,
    )];
    let selected = SelectedOutputBatch::new(&missing_request).unwrap();
    assert!(matches!(
        build_blinded_ordinary_wallet_pset(
            &catalog,
            BorrowedSlip77::new(&fixture.slip77),
            selected,
            planned_outputs(&fixture),
            ExplicitFee::new(fixture.fee_asset, 100).unwrap(),
            &mut NoRandomnessExpected,
        ),
        Err(OrdinaryWalletPsetError::InvalidFundingTransaction)
    ));

    let absent = selected_batch(&fixture, &[7]);
    assert!(matches!(
        build_blinded_ordinary_wallet_pset(
            &catalog,
            BorrowedSlip77::new(&fixture.slip77),
            absent,
            planned_outputs(&fixture),
            ExplicitFee::new(fixture.fee_asset, 100).unwrap(),
            &mut NoRandomnessExpected,
        ),
        Err(OrdinaryWalletPsetError::InvalidSelectedOutput)
    ));

    let duplicate = selected_batch(&fixture, &[0, 0]);
    assert!(matches!(
        build_blinded_ordinary_wallet_pset(
            &catalog,
            BorrowedSlip77::new(&fixture.slip77),
            duplicate,
            planned_outputs(&fixture),
            ExplicitFee::new(fixture.fee_asset, 100).unwrap(),
            &mut NoRandomnessExpected,
        ),
        Err(OrdinaryWalletPsetError::InvalidSelectedOutput)
    ));
}

#[test]
fn rejects_output_limits_before_opening_inputs() {
    let catalog = catalog();
    let fixture = funding_fixture();
    assert!(matches!(
        build_blinded_ordinary_wallet_pset(
            &catalog,
            BorrowedSlip77::new(&fixture.slip77),
            selected_batch(&fixture, &[1, 0]),
            vec![],
            ExplicitFee::new(fixture.fee_asset, 100).unwrap(),
            &mut NoRandomnessExpected,
        ),
        Err(OrdinaryWalletPsetError::InvalidPlan)
    ));

    let address = receive_address();
    let outputs = (0..=MAX_CONFIDENTIAL_OUTPUTS)
        .map(|_| ConfidentialOutput::from_address(fixture.fee_asset, 1, &address).unwrap())
        .collect();
    assert!(matches!(
        build_blinded_ordinary_wallet_pset(
            &catalog,
            BorrowedSlip77::new(&fixture.slip77),
            selected_batch(&fixture, &[1, 0]),
            outputs,
            ExplicitFee::new(fixture.fee_asset, 100).unwrap(),
            &mut NoRandomnessExpected,
        ),
        Err(OrdinaryWalletPsetError::InvalidPlan)
    ));
}

#[test]
fn rejects_entropy_secret_and_conservation_failures_without_output() {
    let catalog = catalog();
    let fixture = funding_fixture();
    assert!(matches!(
        build_blinded_ordinary_wallet_pset(
            &catalog,
            BorrowedSlip77::new(&fixture.slip77),
            selected_batch(&fixture, &[1, 0]),
            planned_outputs(&fixture),
            ExplicitFee::new(fixture.fee_asset, 100).unwrap(),
            &mut FailedRandomness,
        ),
        Err(OrdinaryWalletPsetError::RandomnessUnavailable)
    ));

    let wrong_slip77 = synthetic_material(b"ordinary wallet PSET wrong SLIP77 material");
    let mut private_failure_rng = StdRng::from_seed(synthetic_material(
        b"ordinary wallet PSET private failure randomness",
    ));
    assert!(matches!(
        build_blinded_ordinary_wallet_pset(
            &catalog,
            BorrowedSlip77::new(&wrong_slip77),
            selected_batch(&fixture, &[1, 0]),
            planned_outputs(&fixture),
            ExplicitFee::new(fixture.fee_asset, 100).unwrap(),
            &mut private_failure_rng,
        ),
        Err(OrdinaryWalletPsetError::InvalidSelectedOutput)
    ));

    let address = receive_address();
    let imbalanced = vec![
        ConfidentialOutput::from_address(fixture.second_asset, 2_000, &address).unwrap(),
        ConfidentialOutput::from_address(fixture.fee_asset, 799, &address).unwrap(),
    ];
    let mut imbalance_rng = StdRng::from_seed(synthetic_material(
        b"ordinary wallet PSET imbalance randomness",
    ));
    assert!(matches!(
        build_blinded_ordinary_wallet_pset(
            &catalog,
            BorrowedSlip77::new(&fixture.slip77),
            selected_batch(&fixture, &[1, 0]),
            imbalanced,
            ExplicitFee::new(fixture.fee_asset, 100).unwrap(),
            &mut imbalance_rng,
        ),
        Err(OrdinaryWalletPsetError::InvalidPlan)
    ));
}

#[test]
fn blinding_stage_entropy_failure_returns_no_partial_pset() {
    let catalog = catalog();
    let fixture = funding_fixture();
    let mut rng = ContextThenBlindingFailureRng {
        context_seed_supplied: false,
        try_fill_calls: 0,
        supplied_bytes: 0,
    };

    let result = build_blinded_ordinary_wallet_pset(
        &catalog,
        BorrowedSlip77::new(&fixture.slip77),
        selected_batch(&fixture, &[1, 0]),
        planned_outputs(&fixture),
        ExplicitFee::new(fixture.fee_asset, 100).unwrap(),
        &mut rng,
    );

    assert!(matches!(
        result,
        Err(OrdinaryWalletPsetError::BlindingFailed)
    ));
    assert_eq!(rng.try_fill_calls, 2);
    assert_eq!(rng.supplied_bytes, 32);
}

#[test]
fn errors_are_payload_free_and_privacy_redacted() {
    for error in [
        OrdinaryWalletPsetError::InvalidSelection,
        OrdinaryWalletPsetError::InvalidFundingTransaction,
        OrdinaryWalletPsetError::InvalidSelectedOutput,
        OrdinaryWalletPsetError::RandomnessUnavailable,
        OrdinaryWalletPsetError::InvalidPlan,
        OrdinaryWalletPsetError::BlindingFailed,
    ] {
        assert!(std::error::Error::source(&error).is_none());
        let text = error.to_string();
        for forbidden in [
            "txid",
            "script",
            "asset",
            "amount",
            "key",
            "proof",
            "address",
            "secret",
            "blind factor",
        ] {
            assert!(!text.contains(forbidden), "{text} contains {forbidden}");
        }
        assert!(!format!("{error:?}").contains(&"ab".repeat(32)));
    }
}

struct NoRandomnessExpected;

impl rand::RngCore for NoRandomnessExpected {
    fn next_u32(&mut self) -> u32 {
        panic!("public failure requested randomness")
    }

    fn next_u64(&mut self) -> u64 {
        panic!("public failure requested randomness")
    }

    fn fill_bytes(&mut self, _: &mut [u8]) {
        panic!("public failure requested randomness")
    }

    fn try_fill_bytes(&mut self, _: &mut [u8]) -> Result<(), rand::Error> {
        panic!("public failure requested randomness")
    }
}

impl rand::CryptoRng for NoRandomnessExpected {}

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
    supplied_bytes: usize,
}

impl rand::RngCore for ContextThenBlindingFailureRng {
    fn next_u32(&mut self) -> u32 {
        panic!("blinding-stage failure used infallible randomness")
    }

    fn next_u64(&mut self) -> u64 {
        panic!("blinding-stage failure used infallible randomness")
    }

    fn fill_bytes(&mut self, _: &mut [u8]) {
        panic!("blinding-stage failure used infallible randomness")
    }

    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), rand::Error> {
        self.try_fill_calls += 1;
        assert_eq!(destination.len(), 32);
        if !self.context_seed_supplied {
            destination.copy_from_slice(&synthetic_material(
                b"ordinary wallet PSET context-only entropy",
            ));
            self.context_seed_supplied = true;
            self.supplied_bytes += destination.len();
            return Ok(());
        }
        Err(rand::Error::new(std::io::Error::other(
            "test blinding-stage entropy unavailable",
        )))
    }
}

impl rand::CryptoRng for ContextThenBlindingFailureRng {}
