#[allow(dead_code)]
mod common;

use std::collections::HashMap;

use elements::bitcoin::PublicKey as BitcoinPublicKey;
use elements::encode;
use elements::secp256k1_zkp::{Message, Secp256k1, SecretKey, ecdsa};
use elements::{EcdsaSighashType, LockTime, OutPoint, Transaction};
use rand::SeedableRng;
use rand::rngs::StdRng;
use wasabi_liquid_native_ordinary_pset::{
    ConfidentialOutput, ExplicitFee, FinalizedOrdinaryTransaction, OrdinaryP2wpkhSigner,
    OrdinarySigningError,
};
use wasabi_liquid_native_ordinary_wallet_pset::{
    OrdinaryWalletPsetError, OrdinaryWalletTransactionFailure, OrdinaryWalletTransactionReason,
    build_blinded_ordinary_wallet_pset, build_sign_and_finalize_ordinary_wallet_transaction,
};
use wasabi_liquid_native_wallet_facts::{BorrowedSelectedOutput, SelectedOutputBatch};

use common::{
    planned_outputs, receive_address, selected_batch, signable_funding_fixture, synthetic_material,
};

static_assertions::assert_not_impl_any!(
    OrdinaryWalletTransactionFailure: Copy,
    Clone,
    std::fmt::Debug
);
static_assertions::assert_impl_all!(
    OrdinaryWalletTransactionReason: Copy,
    Clone,
    std::fmt::Debug,
    Eq,
    std::fmt::Display,
    std::error::Error
);

#[test]
fn signs_identity_and_nonidentity_layouts_by_exact_outpoint() {
    for (label, draws, expected_vouts) in [
        (
            b"ordinary wallet signed identity layout".as_slice(),
            [1, 1],
            [1, 0],
        ),
        (
            b"ordinary wallet signed nonidentity layout".as_slice(),
            [0, 0],
            [0, 1],
        ),
    ] {
        let (catalog, fixture, signing_keys) = signable_funding_fixture();
        let mut signer = FixtureSigner::accepting(&fixture, signing_keys);
        let mut rng = ScriptedLayoutRng::new(label, draws);
        let mut provider = common::FixtureOpeningProvider::new(&fixture);

        let finalized = expect_finalized(build_sign_and_finalize_ordinary_wallet_transaction(
            &catalog,
            &mut provider,
            selected_batch(&fixture, &[1, 0]),
            planned_outputs(&fixture),
            ExplicitFee::new(fixture.fee_asset, 100).unwrap(),
            &mut rng,
            &mut signer,
        ));
        let transaction = finalized.transaction();
        let observed_outpoints = transaction
            .input
            .iter()
            .map(|input| input.previous_output)
            .collect::<Vec<_>>();
        let expected_outpoints =
            expected_vouts.map(|vout| OutPoint::new(fixture.transaction.txid(), vout));

        assert_eq!(observed_outpoints, expected_outpoints);
        assert_all_public_keys_precede_signatures(&signer.events, &expected_outpoints);
        assert_finalized_transaction_valid(&finalized, &fixture.transaction);
        assert_eq!(rng.layout_draws_consumed, 2);
        assert_eq!(provider.calls(), 2);
    }
}

#[test]
fn late_signer_refusal_returns_exact_retryable_blinded_pset() {
    let (catalog, fixture, signing_keys) = signable_funding_fixture();
    let seed_label = b"ordinary wallet retryable signed layout";
    let draws = [0, 1];
    let mut baseline_rng = ScriptedLayoutRng::new(seed_label, draws);
    let mut baseline_provider = common::FixtureOpeningProvider::new(&fixture);
    let baseline = build_blinded_ordinary_wallet_pset(
        &catalog,
        &mut baseline_provider,
        selected_batch(&fixture, &[1, 0]),
        planned_outputs(&fixture),
        ExplicitFee::new(fixture.fee_asset, 100).unwrap(),
        &mut baseline_rng,
    )
    .unwrap();
    let baseline_bytes = baseline.serialize_sensitive();
    drop(baseline);

    let mut signer = FixtureSigner::refusing_signature(&fixture, signing_keys, 1);
    let mut signing_rng = ScriptedLayoutRng::new(seed_label, draws);
    let mut signing_provider = common::FixtureOpeningProvider::new(&fixture);
    let failure = expect_transaction_failure(build_sign_and_finalize_ordinary_wallet_transaction(
        &catalog,
        &mut signing_provider,
        selected_batch(&fixture, &[1, 0]),
        planned_outputs(&fixture),
        ExplicitFee::new(fixture.fee_asset, 100).unwrap(),
        &mut signing_rng,
        &mut signer,
    ));

    assert_eq!(
        failure.reason(),
        &OrdinaryWalletTransactionReason::Signing(OrdinarySigningError::SignatureUnavailable)
    );
    assert_eq!(signer.signature_request_count(), 2);
    assert_eq!(signing_provider.calls(), 2);
    assert!(matches!(signer.events[2], SignerEvent::Signature(0, _)));
    assert!(matches!(signer.events[3], SignerEvent::Signature(1, _)));
    let retryable = failure.into_retryable_blinded().unwrap();
    assert_eq!(retryable.serialize_sensitive(), baseline_bytes);

    let expected_outpoints = retryable
        .as_pset()
        .inputs()
        .iter()
        .map(|input| input.previous_outpoint())
        .collect::<Vec<_>>();
    let mut retry_signer = FixtureSigner::accepting(&fixture, signing_keys);
    let secp = Secp256k1::new();
    let signed = match retryable.sign_and_finalize(&secp, &mut retry_signer) {
        Ok(signed) => signed,
        Err(_) => panic!("retry unexpectedly failed"),
    };
    assert_eq!(signing_provider.calls(), 2);
    assert_all_public_keys_precede_signatures(&retry_signer.events, &expected_outpoints);
    assert_eq!(
        retry_signer.events[0],
        SignerEvent::PublicKey(0, expected_outpoints[0])
    );
    assert_finalized_transaction_valid(&signed.into_finalized_transaction(), &fixture.transaction);
}

#[test]
fn provider_failure_never_invokes_signer_or_returns_retry_capability() {
    let (catalog, fixture, signing_keys) = signable_funding_fixture();
    let mut provider = common::FixtureOpeningProvider::refusing(&fixture, 1);
    let mut signer = FixtureSigner::accepting(&fixture, signing_keys);
    let mut rng =
        ScriptedLayoutRng::new(b"ordinary wallet provider refusal signing boundary", [0, 0]);

    let failure = expect_transaction_failure(build_sign_and_finalize_ordinary_wallet_transaction(
        &catalog,
        &mut provider,
        selected_batch(&fixture, &[1, 0]),
        planned_outputs(&fixture),
        ExplicitFee::new(fixture.fee_asset, 100).unwrap(),
        &mut rng,
        &mut signer,
    ));

    assert_eq!(
        failure.reason(),
        &OrdinaryWalletTransactionReason::Preparation(
            OrdinaryWalletPsetError::InvalidSelectedOutput
        )
    );
    assert_eq!(provider.calls(), 2);
    assert!(signer.events.is_empty());
    assert!(failure.into_retryable_blinded().is_none());
}

#[test]
fn preparation_failure_never_invokes_signer_or_returns_retry_capability() {
    let (catalog, fixture, signing_keys) = signable_funding_fixture();
    let mut signer = FixtureSigner::accepting(&fixture, signing_keys);
    let failure = expect_transaction_failure(build_sign_and_finalize_ordinary_wallet_transaction(
        &catalog,
        &mut common::FixtureOpeningProvider::new(&fixture),
        selected_batch(&fixture, &[1, 0]),
        vec![],
        ExplicitFee::new(fixture.fee_asset, 100).unwrap(),
        &mut NoRandomnessExpected,
        &mut signer,
    ));

    assert_eq!(
        failure.reason(),
        &OrdinaryWalletTransactionReason::Preparation(OrdinaryWalletPsetError::InvalidPlan)
    );
    assert!(signer.events.is_empty());
    assert!(failure.into_retryable_blinded().is_none());
}

#[test]
fn selected_expectation_failure_never_invokes_signer_or_returns_retry_capability() {
    let (catalog, fixture, signing_keys) = signable_funding_fixture();
    let mut signer = FixtureSigner::accepting(&fixture, signing_keys);
    let expected_outpoint = OutPoint::new(fixture.transaction.txid(), 7);
    let expected_value = 900;
    let request = [BorrowedSelectedOutput::new(
        &expected_outpoint,
        &fixture.fee_asset,
        &expected_value,
        &fixture.transaction_bytes,
        std::slice::from_ref(&fixture.previous_transaction_bytes),
    )];
    let selected = SelectedOutputBatch::new(&request).unwrap();
    let failure = expect_transaction_failure(build_sign_and_finalize_ordinary_wallet_transaction(
        &catalog,
        &mut common::FixtureOpeningProvider::new(&fixture),
        selected,
        vec![ConfidentialOutput::from_address(fixture.fee_asset, 800, &receive_address()).unwrap()],
        ExplicitFee::new(fixture.fee_asset, 100).unwrap(),
        &mut NoRandomnessExpected,
        &mut signer,
    ));

    assert_eq!(
        failure.reason(),
        &OrdinaryWalletTransactionReason::Preparation(
            OrdinaryWalletPsetError::InvalidSelectedOutput
        )
    );
    assert!(signer.events.is_empty());
    assert!(failure.into_retryable_blinded().is_none());
}

#[test]
fn selected_txid_substitution_never_invokes_signer_or_returns_retry_capability() {
    let (catalog, fixture, signing_keys) = signable_funding_fixture();
    let mut signer = FixtureSigner::accepting(&fixture, signing_keys);
    let expected_outpoint = OutPoint::new(fixture.transaction.txid(), 0);
    let expected_value = 900;
    let mut substituted = fixture.transaction.clone();
    substituted.lock_time = LockTime::from_consensus(1);
    assert_ne!(substituted.txid(), expected_outpoint.txid);
    let substituted_bytes = encode::serialize(&substituted);
    let request = [BorrowedSelectedOutput::new(
        &expected_outpoint,
        &fixture.fee_asset,
        &expected_value,
        &substituted_bytes,
        std::slice::from_ref(&fixture.previous_transaction_bytes),
    )];
    let selected = SelectedOutputBatch::new(&request).unwrap();
    let failure = expect_transaction_failure(build_sign_and_finalize_ordinary_wallet_transaction(
        &catalog,
        &mut common::FixtureOpeningProvider::new(&fixture),
        selected,
        vec![ConfidentialOutput::from_address(fixture.fee_asset, 800, &receive_address()).unwrap()],
        ExplicitFee::new(fixture.fee_asset, 100).unwrap(),
        &mut NoRandomnessExpected,
        &mut signer,
    ));

    assert_eq!(
        failure.reason(),
        &OrdinaryWalletTransactionReason::Preparation(
            OrdinaryWalletPsetError::InvalidSelectedOutput
        )
    );
    assert!(signer.events.is_empty());
    assert!(failure.into_retryable_blinded().is_none());
}

#[test]
fn public_failure_reasons_are_payload_free_and_privacy_redacted() {
    let preparation = [
        OrdinaryWalletPsetError::InvalidSelection,
        OrdinaryWalletPsetError::InvalidFundingTransaction,
        OrdinaryWalletPsetError::InvalidSelectedOutput,
        OrdinaryWalletPsetError::RandomnessUnavailable,
        OrdinaryWalletPsetError::InvalidPlan,
        OrdinaryWalletPsetError::BlindingFailed,
    ]
    .map(OrdinaryWalletTransactionReason::Preparation);
    let signing = [
        OrdinarySigningError::InvalidBlindedPset,
        OrdinarySigningError::PublicKeyUnavailable,
        OrdinarySigningError::UncompressedPublicKey,
        OrdinarySigningError::PublicKeyDoesNotOwnInput,
        OrdinarySigningError::SignatureUnavailable,
        OrdinarySigningError::NonCanonicalSignature,
        OrdinarySigningError::InvalidSignature,
        OrdinarySigningError::FinalizationFailed,
    ]
    .map(OrdinaryWalletTransactionReason::Signing);

    for reason in preparation.into_iter().chain(signing) {
        assert!(std::error::Error::source(&reason).is_none());
        let text = format!("{reason} {reason:?}").to_lowercase();
        for forbidden in [
            "txid=",
            "outpoint=",
            "script=",
            "address=",
            "asset=",
            "amount=",
            "proof=",
            "digest=",
            "signature=",
            "pset=",
            "secret=",
            "abababababababababababababababab",
        ] {
            assert!(!text.contains(forbidden), "{text} contains {forbidden}");
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SignerEvent {
    PublicKey(usize, OutPoint),
    Signature(usize, OutPoint),
}

struct FixtureSigner {
    keys: HashMap<OutPoint, SecretKey>,
    refused_signature_request: Option<usize>,
    events: Vec<SignerEvent>,
}

impl FixtureSigner {
    fn accepting(fixture: &common::FundingFixture, keys: [SecretKey; 2]) -> Self {
        Self::new(fixture, keys, None)
    }

    fn refusing_signature(
        fixture: &common::FundingFixture,
        keys: [SecretKey; 2],
        refused_signature_request: usize,
    ) -> Self {
        Self::new(fixture, keys, Some(refused_signature_request))
    }

    fn new(
        fixture: &common::FundingFixture,
        keys: [SecretKey; 2],
        refused_signature_request: Option<usize>,
    ) -> Self {
        Self {
            keys: HashMap::from([
                (OutPoint::new(fixture.transaction.txid(), 0), keys[0]),
                (OutPoint::new(fixture.transaction.txid(), 1), keys[1]),
            ]),
            refused_signature_request,
            events: Vec::new(),
        }
    }

    fn signature_request_count(&self) -> usize {
        self.events
            .iter()
            .filter(|event| matches!(event, SignerEvent::Signature(_, _)))
            .count()
    }
}

impl OrdinaryP2wpkhSigner for FixtureSigner {
    fn public_key(&mut self, input_index: usize, outpoint: &OutPoint) -> Option<BitcoinPublicKey> {
        self.events
            .push(SignerEvent::PublicKey(input_index, *outpoint));
        self.keys.get(outpoint).map(|key| {
            let secp = Secp256k1::new();
            BitcoinPublicKey::new(key.public_key(&secp))
        })
    }

    fn sign_digest(
        &mut self,
        input_index: usize,
        outpoint: &OutPoint,
        digest: [u8; 32],
        sighash_type: EcdsaSighashType,
    ) -> Option<ecdsa::Signature> {
        assert_eq!(sighash_type, EcdsaSighashType::AllPlusRangeproof);
        let request = self.signature_request_count();
        self.events
            .push(SignerEvent::Signature(input_index, *outpoint));
        if self.refused_signature_request == Some(request) {
            return None;
        }
        self.keys.get(outpoint).map(|key| {
            let secp = Secp256k1::new();
            secp.sign_ecdsa(&Message::from_digest(digest), key)
        })
    }
}

fn assert_all_public_keys_precede_signatures(
    events: &[SignerEvent],
    expected_outpoints: &[OutPoint],
) {
    assert_eq!(events.len(), expected_outpoints.len() * 2);
    for (input_index, outpoint) in expected_outpoints.iter().enumerate() {
        assert_eq!(
            events[input_index],
            SignerEvent::PublicKey(input_index, *outpoint)
        );
        assert_eq!(
            events[expected_outpoints.len() + input_index],
            SignerEvent::Signature(input_index, *outpoint)
        );
    }
}

fn assert_finalized_transaction_valid(
    finalized: &FinalizedOrdinaryTransaction,
    funding_transaction: &Transaction,
) {
    let secp = Secp256k1::new();
    let transaction = finalized.transaction();
    for input in &transaction.input {
        assert!(input.script_sig.is_empty());
        assert_eq!(input.witness.script_witness.to_vec().len(), 2);
    }
    for output in &transaction.output[..transaction.output.len() - 1] {
        assert!(output.asset.is_confidential());
        assert!(output.value.is_confidential());
        assert!(output.nonce.is_confidential());
        assert!(!output.witness.rangeproof.is_empty());
        assert!(!output.witness.surjection_proof.is_empty());
    }
    let fee = transaction.output.last().unwrap();
    assert!(fee.script_pubkey.is_empty());
    assert!(fee.asset.is_explicit());
    assert!(fee.value.is_explicit());
    let previous_outputs = transaction
        .input
        .iter()
        .map(|input| {
            assert_eq!(input.previous_output.txid, funding_transaction.txid());
            funding_transaction.output[input.previous_output.vout as usize].clone()
        })
        .collect::<Vec<_>>();
    transaction
        .verify_tx_amt_proofs(&secp, &previous_outputs)
        .unwrap();

    let broadcast = finalized.serialize_for_broadcast();
    let decoded: Transaction = encode::deserialize(&broadcast).unwrap();
    assert_eq!(decoded, *transaction);
    assert!(encode::deserialize::<elements::pset::PartiallySignedTransaction>(&broadcast).is_err());
}

fn expect_finalized(
    result: Result<FinalizedOrdinaryTransaction, OrdinaryWalletTransactionFailure>,
) -> FinalizedOrdinaryTransaction {
    match result {
        Ok(finalized) => finalized,
        Err(_) => panic!("ordinary wallet transaction unexpectedly failed"),
    }
}

fn expect_transaction_failure(
    result: Result<FinalizedOrdinaryTransaction, OrdinaryWalletTransactionFailure>,
) -> OrdinaryWalletTransactionFailure {
    match result {
        Ok(_) => panic!("ordinary wallet transaction unexpectedly succeeded"),
        Err(failure) => failure,
    }
}

struct ScriptedLayoutRng {
    inner: StdRng,
    context_seed_supplied: bool,
    layout_draws: std::collections::VecDeque<u64>,
    layout_draws_consumed: usize,
}

impl ScriptedLayoutRng {
    fn new(seed_label: &[u8], layout_draws: impl IntoIterator<Item = u64>) -> Self {
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

struct NoRandomnessExpected;

impl rand::RngCore for NoRandomnessExpected {
    fn next_u32(&mut self) -> u32 {
        panic!("preparation failure requested randomness")
    }

    fn next_u64(&mut self) -> u64 {
        panic!("preparation failure requested randomness")
    }

    fn fill_bytes(&mut self, _: &mut [u8]) {
        panic!("preparation failure requested randomness")
    }

    fn try_fill_bytes(&mut self, _: &mut [u8]) -> Result<(), rand::Error> {
        panic!("preparation failure requested randomness")
    }
}

impl rand::CryptoRng for NoRandomnessExpected {}
