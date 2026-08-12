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
    BorrowedSelectedOutput, SelectedOutputBatch, WalletObservationError,
};

use common::{
    catalog, funding_fixture, planned_outputs, receive_address, second_receive_address,
    selected_batch, synthetic_material, zero_opening_output,
};

static_assertions::assert_not_impl_any!(BlindedOrdinaryPset: Copy, Clone, std::fmt::Debug);
static_assertions::assert_not_impl_any!(SelectedOutputBatch: Copy, Clone, std::fmt::Debug);

#[test]
fn independently_shuffles_inputs_and_outputs_before_building_a_valid_pset() {
    let catalog = catalog();
    let fixture = funding_fixture();
    let selected = selected_batch(&fixture, &[1, 0]);
    let mut rng = ScriptedLayoutRng::new(
        b"ordinary wallet PSET orchestration success randomness",
        [0, 0],
    );
    let mut provider = common::FixtureOpeningProvider::new(&fixture);

    let blinded = build_blinded_ordinary_wallet_pset(
        &catalog,
        &mut provider,
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
        OutPoint::new(fixture.transaction.txid(), 0),
        OutPoint::new(fixture.transaction.txid(), 1),
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
    assert_eq!(pset.outputs()[0].asset, Some(fixture.fee_asset));
    assert_eq!(pset.outputs()[0].amount, Some(800));
    assert_eq!(
        pset.outputs()[0].script_pubkey.as_bytes(),
        second_receive_address().as_parsed().script_pubkey()
    );
    assert_eq!(pset.outputs()[1].asset, Some(fixture.second_asset));
    assert_eq!(pset.outputs()[1].amount, Some(2_000));
    assert_eq!(
        pset.outputs()[1].script_pubkey.as_bytes(),
        receive_address().as_parsed().script_pubkey()
    );
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
    assert_eq!(rng.layout_draws_consumed, 2);
    assert_eq!(provider.calls(), 2);
    assert_eq!(
        provider.seen_scripts(),
        [
            fixture.transaction.output[1].script_pubkey.as_bytes(),
            fixture.transaction.output[0].script_pubkey.as_bytes(),
        ]
    );
}

#[test]
fn input_and_output_permutations_use_separate_consecutive_draws() {
    let catalog = catalog();
    let fixture = funding_fixture();
    let mut rng = ScriptedLayoutRng::new(
        b"ordinary wallet PSET independent layout randomness",
        [0, 1],
    );

    let blinded = build_blinded_ordinary_wallet_pset(
        &catalog,
        &mut common::FixtureOpeningProvider::new(&fixture),
        selected_batch(&fixture, &[1, 0]),
        planned_outputs(&fixture),
        ExplicitFee::new(fixture.fee_asset, 100).unwrap(),
        &mut rng,
    )
    .unwrap();
    let pset = blinded.as_pset();

    assert_eq!(
        pset.inputs()
            .iter()
            .map(|input| input.previous_outpoint())
            .collect::<Vec<_>>(),
        [
            OutPoint::new(fixture.transaction.txid(), 0),
            OutPoint::new(fixture.transaction.txid(), 1),
        ]
    );
    assert_eq!(pset.outputs()[0].asset, Some(fixture.second_asset));
    assert_eq!(pset.outputs()[1].asset, Some(fixture.fee_asset));
    assert_eq!(rng.layout_draws_consumed, 2);
}

#[test]
fn identity_permutations_remain_valid_and_fee_stays_last() {
    let catalog = catalog();
    let fixture = funding_fixture();
    let mut rng =
        ScriptedLayoutRng::new(b"ordinary wallet PSET identity layout randomness", [1, 1]);

    let blinded = build_blinded_ordinary_wallet_pset(
        &catalog,
        &mut common::FixtureOpeningProvider::new(&fixture),
        selected_batch(&fixture, &[1, 0]),
        planned_outputs(&fixture),
        ExplicitFee::new(fixture.fee_asset, 100).unwrap(),
        &mut rng,
    )
    .unwrap();
    let pset = blinded.as_pset();

    assert_eq!(
        pset.inputs()
            .iter()
            .map(|input| input.previous_outpoint())
            .collect::<Vec<_>>(),
        [
            OutPoint::new(fixture.transaction.txid(), 1),
            OutPoint::new(fixture.transaction.txid(), 0),
        ]
    );
    assert_eq!(pset.outputs()[0].asset, Some(fixture.second_asset));
    assert_eq!(pset.outputs()[1].asset, Some(fixture.fee_asset));
    assert_eq!(blinded.fee_output_index(), 2);
    assert!(pset.outputs()[2].script_pubkey.is_empty());
    assert_eq!(rng.layout_draws_consumed, 2);
}

#[test]
fn rejects_public_selection_failures_before_randomness() {
    let catalog = catalog();
    let fixture = funding_fixture();
    let missing_previous = Vec::new();
    let expected_outpoint = OutPoint::new(fixture.transaction.txid(), 0);
    let expected_value = 900;
    let missing_request = [BorrowedSelectedOutput::new(
        &expected_outpoint,
        &fixture.fee_asset,
        &expected_value,
        &fixture.transaction_bytes,
        &missing_previous,
    )];
    let selected = SelectedOutputBatch::new(&missing_request).unwrap();
    let balanced_fee_output =
        vec![ConfidentialOutput::from_address(fixture.fee_asset, 800, &receive_address()).unwrap()];
    assert!(matches!(
        build_blinded_ordinary_wallet_pset(
            &catalog,
            &mut common::FixtureOpeningProvider::new(&fixture),
            selected,
            balanced_fee_output,
            ExplicitFee::new(fixture.fee_asset, 100).unwrap(),
            &mut NoRandomnessExpected,
        ),
        Err(OrdinaryWalletPsetError::InvalidFundingTransaction)
    ));

    let absent_outpoint = OutPoint::new(fixture.transaction.txid(), 7);
    let absent_value = 900;
    let absent_request = [BorrowedSelectedOutput::new(
        &absent_outpoint,
        &fixture.fee_asset,
        &absent_value,
        &fixture.transaction_bytes,
        std::slice::from_ref(&fixture.previous_transaction_bytes),
    )];
    let absent = SelectedOutputBatch::new(&absent_request).unwrap();
    assert!(matches!(
        build_blinded_ordinary_wallet_pset(
            &catalog,
            &mut common::FixtureOpeningProvider::new(&fixture),
            absent,
            vec![
                ConfidentialOutput::from_address(fixture.fee_asset, 800, &receive_address(),)
                    .unwrap()
            ],
            ExplicitFee::new(fixture.fee_asset, 100).unwrap(),
            &mut NoRandomnessExpected,
        ),
        Err(OrdinaryWalletPsetError::InvalidSelectedOutput)
    ));

    let previous = std::slice::from_ref(&fixture.previous_transaction_bytes);
    let duplicate_requests = [
        BorrowedSelectedOutput::new(
            &expected_outpoint,
            &fixture.fee_asset,
            &expected_value,
            &fixture.transaction_bytes,
            previous,
        ),
        BorrowedSelectedOutput::new(
            &expected_outpoint,
            &fixture.fee_asset,
            &expected_value,
            &fixture.transaction_bytes,
            previous,
        ),
    ];
    assert!(matches!(
        SelectedOutputBatch::new(&duplicate_requests),
        Err(WalletObservationError::DuplicateSelectedOutpoint)
    ));
}

#[test]
fn rejects_output_limits_before_opening_inputs() {
    let catalog = catalog();
    let fixture = funding_fixture();
    assert!(matches!(
        build_blinded_ordinary_wallet_pset(
            &catalog,
            &mut common::FixtureOpeningProvider::new(&fixture),
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
            &mut common::FixtureOpeningProvider::new(&fixture),
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
    let mut failed_randomness_provider = common::FixtureOpeningProvider::new(&fixture);
    assert!(matches!(
        build_blinded_ordinary_wallet_pset(
            &catalog,
            &mut failed_randomness_provider,
            selected_batch(&fixture, &[1, 0]),
            planned_outputs(&fixture),
            ExplicitFee::new(fixture.fee_asset, 100).unwrap(),
            &mut FailedRandomness,
        ),
        Err(OrdinaryWalletPsetError::RandomnessUnavailable)
    ));
    assert_eq!(failed_randomness_provider.calls(), 0);

    let wrong_slip77 = synthetic_material(b"ordinary wallet PSET wrong SLIP77 material");
    let mut private_failure_rng = StdRng::from_seed(synthetic_material(
        b"ordinary wallet PSET private failure randomness",
    ));
    assert!(matches!(
        build_blinded_ordinary_wallet_pset(
            &catalog,
            &mut common::FixtureOpeningProvider::with_material(wrong_slip77),
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
    let mut imbalance_provider = common::FixtureOpeningProvider::new(&fixture);
    assert!(matches!(
        build_blinded_ordinary_wallet_pset(
            &catalog,
            &mut imbalance_provider,
            selected_batch(&fixture, &[1, 0]),
            imbalanced,
            ExplicitFee::new(fixture.fee_asset, 100).unwrap(),
            &mut imbalance_rng,
        ),
        Err(OrdinaryWalletPsetError::InvalidPlan)
    ));
    assert_eq!(imbalance_provider.calls(), 0);
}

#[test]
fn provider_zero_opening_maps_to_invalid_selected_output() {
    let catalog = catalog();
    let fixture = funding_fixture();
    let zero_output = zero_opening_output(&fixture);
    let mut provider = common::FixtureOpeningProvider::substituting(&fixture, 0, zero_output);
    let mut rng = StdRng::from_seed(synthetic_material(
        b"ordinary wallet PSET provider zero-opening randomness",
    ));

    assert!(matches!(
        build_blinded_ordinary_wallet_pset(
            &catalog,
            &mut provider,
            selected_batch(&fixture, &[0]),
            vec![
                ConfidentialOutput::from_address(fixture.fee_asset, 800, &receive_address(),)
                    .unwrap(),
            ],
            ExplicitFee::new(fixture.fee_asset, 100).unwrap(),
            &mut rng,
        ),
        Err(OrdinaryWalletPsetError::InvalidSelectedOutput)
    ));
    assert_eq!(provider.calls(), 1);
}

#[test]
fn singleton_input_and_output_require_no_layout_draw() {
    let catalog = catalog();
    let fixture = funding_fixture();
    let output =
        ConfidentialOutput::from_address(fixture.fee_asset, 800, &receive_address()).unwrap();
    let mut rng = ScriptedLayoutRng::new(
        b"ordinary wallet PSET singleton layout randomness",
        std::iter::empty(),
    );

    let blinded = build_blinded_ordinary_wallet_pset(
        &catalog,
        &mut common::FixtureOpeningProvider::new(&fixture),
        selected_batch(&fixture, &[0]),
        vec![output],
        ExplicitFee::new(fixture.fee_asset, 100).unwrap(),
        &mut rng,
    )
    .unwrap();

    assert_eq!(blinded.as_pset().n_inputs(), 1);
    assert_eq!(blinded.as_pset().n_outputs(), 2);
    assert_eq!(blinded.fee_output_index(), 1);
    assert_eq!(rng.layout_draws_consumed, 0);
}

#[test]
fn layout_failure_on_first_draw_returns_no_pset() {
    let catalog = catalog();
    let fixture = funding_fixture();
    let mut rng = LayoutFailureRng::new(0);
    let mut provider = common::FixtureOpeningProvider::new(&fixture);

    let result = build_blinded_ordinary_wallet_pset(
        &catalog,
        &mut provider,
        selected_batch(&fixture, &[1, 0]),
        planned_outputs(&fixture),
        ExplicitFee::new(fixture.fee_asset, 100).unwrap(),
        &mut rng,
    );

    assert!(matches!(
        result,
        Err(OrdinaryWalletPsetError::RandomnessUnavailable)
    ));
    assert_eq!(rng.successful_layout_draws, 0);
    assert_eq!(rng.layout_draw_attempts, 1);
    assert_eq!(provider.calls(), 0);
}

#[test]
fn layout_failure_after_an_input_swap_returns_no_pset() {
    let catalog = catalog();
    let fixture = funding_fixture();
    let mut rng = LayoutFailureRng::new(1);
    let mut provider = common::FixtureOpeningProvider::new(&fixture);

    let result = build_blinded_ordinary_wallet_pset(
        &catalog,
        &mut provider,
        selected_batch(&fixture, &[1, 0]),
        planned_outputs(&fixture),
        ExplicitFee::new(fixture.fee_asset, 100).unwrap(),
        &mut rng,
    );

    assert!(matches!(
        result,
        Err(OrdinaryWalletPsetError::RandomnessUnavailable)
    ));
    assert_eq!(rng.successful_layout_draws, 1);
    assert_eq!(rng.layout_draw_attempts, 2);
    assert_eq!(provider.calls(), 0);
}

#[test]
fn bounded_layout_rejection_exhaustion_precedes_provider_calls() {
    let catalog = catalog();
    let fixture = funding_fixture();
    let outputs = vec![
        ConfidentialOutput::from_address(fixture.second_asset, 1_000, &receive_address()).unwrap(),
        ConfidentialOutput::from_address(fixture.second_asset, 1_000, &second_receive_address())
            .unwrap(),
        ConfidentialOutput::from_address(fixture.fee_asset, 800, &receive_address()).unwrap(),
    ];
    let mut rng = RejectionExhaustionRng { calls: 0 };
    let mut provider = common::FixtureOpeningProvider::new(&fixture);

    let result = build_blinded_ordinary_wallet_pset(
        &catalog,
        &mut provider,
        selected_batch(&fixture, &[1, 0]),
        outputs,
        ExplicitFee::new(fixture.fee_asset, 100).unwrap(),
        &mut rng,
    );

    assert!(matches!(
        result,
        Err(OrdinaryWalletPsetError::RandomnessUnavailable)
    ));
    assert_eq!(rng.calls, 129);
    assert_eq!(provider.calls(), 0);
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
        &mut common::FixtureOpeningProvider::new(&fixture),
        selected_batch(&fixture, &[1, 0]),
        planned_outputs(&fixture),
        ExplicitFee::new(fixture.fee_asset, 100).unwrap(),
        &mut rng,
    );

    assert!(matches!(
        result,
        Err(OrdinaryWalletPsetError::BlindingFailed)
    ));
    assert_eq!(rng.try_fill_calls, 4);
    assert_eq!(rng.supplied_bytes, 48);
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

struct ScriptedLayoutRng {
    inner: StdRng,
    context_seed_supplied: bool,
    layout_draws: std::collections::VecDeque<u64>,
    layout_draws_consumed: usize,
}

impl ScriptedLayoutRng {
    fn new(seed_label: &[u8], layout_draws: impl IntoIterator<Item = u64>) -> ScriptedLayoutRng {
        Self {
            inner: StdRng::from_seed(synthetic_material(seed_label)),
            context_seed_supplied: false,
            layout_draws: layout_draws.into_iter().collect(),
            layout_draws_consumed: 0,
        }
    }
}

impl rand::RngCore for ScriptedLayoutRng {
    fn next_u32(&mut self) -> u32 {
        panic!("orchestration used infallible randomness")
    }

    fn next_u64(&mut self) -> u64 {
        panic!("orchestration used infallible randomness")
    }

    fn fill_bytes(&mut self, _: &mut [u8]) {
        panic!("orchestration used infallible randomness")
    }

    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), rand::Error> {
        if destination.len() == 8 {
            let draw = self
                .layout_draws
                .pop_front()
                .expect("layout draw available");
            assert_eq!(destination.len(), 8);
            destination.copy_from_slice(&draw.to_le_bytes());
            self.layout_draws_consumed += 1;
            return Ok(());
        }
        if !self.context_seed_supplied {
            assert_eq!(destination.len(), 32);
            self.context_seed_supplied = true;
        }
        self.inner.try_fill_bytes(destination)
    }
}

impl rand::CryptoRng for ScriptedLayoutRng {}

struct LayoutFailureRng {
    successful_draws_before_failure: usize,
    successful_layout_draws: usize,
    layout_draw_attempts: usize,
}

impl LayoutFailureRng {
    fn new(successful_draws_before_failure: usize) -> Self {
        Self {
            successful_draws_before_failure,
            successful_layout_draws: 0,
            layout_draw_attempts: 0,
        }
    }
}

impl rand::RngCore for LayoutFailureRng {
    fn next_u32(&mut self) -> u32 {
        panic!("layout failure used infallible randomness")
    }

    fn next_u64(&mut self) -> u64 {
        panic!("layout failure used infallible randomness")
    }

    fn fill_bytes(&mut self, _: &mut [u8]) {
        panic!("layout failure used infallible randomness")
    }

    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), rand::Error> {
        assert_eq!(destination.len(), 8);
        self.layout_draw_attempts += 1;
        if self.successful_layout_draws < self.successful_draws_before_failure {
            destination.copy_from_slice(&0_u64.to_le_bytes());
            self.successful_layout_draws += 1;
            return Ok(());
        }
        destination[..4].fill(0xa5);
        Err(rand::Error::new(std::io::Error::other(
            "test layout random source unavailable",
        )))
    }
}

impl rand::CryptoRng for LayoutFailureRng {}

struct RejectionExhaustionRng {
    calls: usize,
}

impl rand::RngCore for RejectionExhaustionRng {
    fn next_u32(&mut self) -> u32 {
        panic!("layout exhaustion used infallible randomness")
    }

    fn next_u64(&mut self) -> u64 {
        panic!("layout exhaustion used infallible randomness")
    }

    fn fill_bytes(&mut self, _: &mut [u8]) {
        panic!("layout exhaustion used infallible randomness")
    }

    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), rand::Error> {
        assert_eq!(destination.len(), 8);
        self.calls += 1;
        destination.fill(0);
        Ok(())
    }
}

impl rand::CryptoRng for RejectionExhaustionRng {}

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
        if destination.len() == 8 {
            destination.copy_from_slice(&0_u64.to_le_bytes());
            self.supplied_bytes += destination.len();
            return Ok(());
        }
        if !self.context_seed_supplied {
            assert_eq!(destination.len(), 32);
            destination.copy_from_slice(&synthetic_material(
                b"ordinary wallet PSET context-only entropy",
            ));
            self.context_seed_supplied = true;
            self.supplied_bytes += destination.len();
            return Ok(());
        }
        assert_eq!(destination.len(), 32);
        Err(rand::Error::new(std::io::Error::other(
            "test blinding-stage entropy unavailable",
        )))
    }
}

impl rand::CryptoRng for ContextThenBlindingFailureRng {}
