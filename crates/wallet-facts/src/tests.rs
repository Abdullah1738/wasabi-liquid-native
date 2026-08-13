use super::*;

use elements::confidential::{Asset, AssetBlindingFactor, Nonce, Value, ValueBlindingFactor};
use elements::secp256k1_zkp::{PedersenCommitment, verify_commitments_sum_to_equal};
use elements::{
    Address, AddressParams, AssetId, LockTime, RangeProof, RangeProofMessage, Script, Sequence,
    Transaction, TxIn, TxOut, TxOutError, TxOutSecrets, TxOutWitness, VerificationError,
};
use rand::SeedableRng;
use rand::rngs::StdRng;
use wasabi_liquid_native_output_opening::open_confidential_output;

const TEST_PUBLIC_DESCRIPTOR: &str = "elwpkh([28b3f14e/84'/1'/0']tpubDC2Q4xK4XH72GM7MowNuajyWVbigRLBWKswyP5T88hpPwu5nGqJWnda8zhJEFt71av73Hm8mUMMFSz9acNVzz8b1UbdSHCDXKTbSv5eEytu/<0;1>/*)";
const TEST_PUBLIC_DESCRIPTOR_CHECKSUM: &str = "u0khc0kg";
const MAINNET_PUBLIC_DESCRIPTOR: &str = "elwpkh([73c5da0a/84'/1776'/0']xpub6CRFzUgHFDaiDAQFNX7VeV9JNPDRabq6NYSpzVZ8zW8ANUCiDdenkb1gBoEZuXNZb3wPc1SVcDXgD2ww5UBtTb8s8ArAbTkoRQ8qn34KgcY/<0;1>/*)";

struct SelectedCountingCryptoRng {
    inner: StdRng,
    fill_calls: usize,
    filled_bytes: usize,
}

impl rand::RngCore for SelectedCountingCryptoRng {
    fn next_u32(&mut self) -> u32 {
        self.inner.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.inner.next_u64()
    }

    fn fill_bytes(&mut self, destination: &mut [u8]) {
        self.fill_calls += 1;
        self.filled_bytes += destination.len();
        self.inner.fill_bytes(destination);
    }

    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), rand::Error> {
        self.fill_calls += 1;
        self.filled_bytes += destination.len();
        self.inner.try_fill_bytes(destination)
    }
}

impl rand::CryptoRng for SelectedCountingCryptoRng {}

struct SelectedNoRandomnessExpected;

impl rand::RngCore for SelectedNoRandomnessExpected {
    fn next_u32(&mut self) -> u32 {
        panic!("selected-output public validation requested randomness")
    }

    fn next_u64(&mut self) -> u64 {
        panic!("selected-output public validation requested randomness")
    }

    fn fill_bytes(&mut self, _: &mut [u8]) {
        panic!("selected-output public validation requested randomness")
    }

    fn try_fill_bytes(&mut self, _: &mut [u8]) -> Result<(), rand::Error> {
        panic!("selected-output public validation requested randomness")
    }
}

impl rand::CryptoRng for SelectedNoRandomnessExpected {}

struct SelectedFailingCryptoRng {
    bytes_to_write: usize,
    try_fill_calls: usize,
}

impl rand::RngCore for SelectedFailingCryptoRng {
    fn next_u32(&mut self) -> u32 {
        unreachable!("selected-output validation requests bytes directly")
    }

    fn next_u64(&mut self) -> u64 {
        unreachable!("selected-output validation requests bytes directly")
    }

    fn fill_bytes(&mut self, _: &mut [u8]) {
        unreachable!("selected-output validation must use fallible entropy")
    }

    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), rand::Error> {
        self.try_fill_calls += 1;
        let written = self.bytes_to_write.min(destination.len());
        destination[..written].fill(0x5a);
        let code = std::num::NonZeroU32::new(rand::Error::CUSTOM_START).unwrap();
        Err(rand::Error::from(code))
    }
}

impl rand::CryptoRng for SelectedFailingCryptoRng {}

struct SyntheticSelectedOpeningProvider<'key> {
    slip77: &'key [u8; 32],
    calls: usize,
    refuse_at: Option<usize>,
    panic_at: Option<usize>,
    substitute_at: Option<(usize, TxOut)>,
    seen_scripts: Vec<Vec<u8>>,
}

struct SyntheticProviderScratch([u8; 32]);

impl Drop for SyntheticProviderScratch {
    fn drop(&mut self) {
        self.0.zeroize();
        assert!(self.0.iter().all(|byte| *byte == 0));
        SYNTHETIC_PROVIDER_SCRATCH_DROPS.with(|count| count.set(count.get() + 1));
    }
}

thread_local! {
    static SYNTHETIC_PROVIDER_SCRATCH_DROPS: std::cell::Cell<usize> = const {
        std::cell::Cell::new(0)
    };
}

impl<'key> SyntheticSelectedOpeningProvider<'key> {
    fn new(slip77: &'key [u8; 32]) -> Self {
        Self {
            slip77,
            calls: 0,
            refuse_at: None,
            panic_at: None,
            substitute_at: None,
            seen_scripts: Vec::new(),
        }
    }

    fn refusing(slip77: &'key [u8; 32], call: usize) -> Self {
        let mut provider = Self::new(slip77);
        provider.refuse_at = Some(call);
        provider
    }

    fn panicking(slip77: &'key [u8; 32], call: usize) -> Self {
        let mut provider = Self::new(slip77);
        provider.panic_at = Some(call);
        provider
    }

    fn substituting(slip77: &'key [u8; 32], call: usize, output: TxOut) -> Self {
        let mut provider = Self::new(slip77);
        provider.substitute_at = Some((call, output));
        provider
    }
}

impl SelectedOutputOpeningProvider for SyntheticSelectedOpeningProvider<'_> {
    fn open_selected_output(
        &mut self,
        secp: &Secp256k1<All>,
        output: &TxOut,
    ) -> Option<OpenedOutput> {
        let _scratch = SyntheticProviderScratch([0xa5; 32]);
        let call = self.calls;
        self.calls += 1;
        self.seen_scripts
            .push(output.script_pubkey.as_bytes().to_vec());
        if self.panic_at == Some(call) {
            panic!("test-only selected opening provider unwind");
        }
        if self.refuse_at == Some(call) {
            return None;
        }
        let output = self
            .substitute_at
            .as_ref()
            .filter(|(substitute_call, _)| *substitute_call == call)
            .map_or(output, |(_, substitute)| substitute);
        let blinding_key =
            derive_blinding_key(self.slip77, output.script_pubkey.as_bytes()).ok()?;
        open_confidential_output(secp, output, &blinding_key.0).ok()
    }
}

static_assertions::assert_not_impl_any!(BorrowedSlip77<'static>: Copy, Clone, std::fmt::Debug);
static_assertions::assert_not_impl_any!(BorrowedCandidateTransaction<'static>: Copy, Clone, std::fmt::Debug);
static_assertions::assert_not_impl_any!(BorrowedSelectedOutput<'static>: Copy, Clone, std::fmt::Debug);
static_assertions::assert_not_impl_any!(ScopedSecretKey: Copy, Clone, std::fmt::Debug);
static_assertions::assert_not_impl_any!(ScopedContextRandomizationSeed: Copy, Clone, std::fmt::Debug);
static_assertions::assert_not_impl_any!(PreparedCandidate: Copy, Clone, std::fmt::Debug);
static_assertions::assert_not_impl_any!(PreparedTransactionId: Copy, Clone, std::fmt::Debug);
static_assertions::assert_not_impl_any!(PreparedCandidateOrder: Copy, Clone, std::fmt::Debug);
static_assertions::assert_not_impl_any!(DescriptorCatalog: Copy, Clone, std::fmt::Debug);
static_assertions::assert_not_impl_any!(CandidateBatch: Copy, Clone, std::fmt::Debug);
static_assertions::assert_not_impl_any!(SelectedOutputBatch: Copy, Clone, std::fmt::Debug);
static_assertions::assert_not_impl_any!(PubliclyPreparedSelectedOutputs<'static>: Copy, Clone, std::fmt::Debug);
static_assertions::assert_not_impl_any!(SelectedOutputExpectation: Copy, Clone, std::fmt::Debug);
static_assertions::assert_not_impl_any!(SelectedOutputPayload: Copy, Clone, std::fmt::Debug);
static_assertions::assert_not_impl_any!(SelectedOutputRequest: Copy, Clone, std::fmt::Debug);
static_assertions::assert_not_impl_any!(ExpectedPlanTotal: Copy, Clone, std::fmt::Debug);
static_assertions::assert_not_impl_any!(ExpectedPlanTotals: Copy, Clone, std::fmt::Debug);
static_assertions::assert_not_impl_any!(ScopedExpectedPlanAsset: Copy, Clone, std::fmt::Debug);
static_assertions::assert_not_impl_any!(PubliclyValidatedSelectedOutput: Copy, Clone, std::fmt::Debug);
static_assertions::assert_not_impl_any!(ScopedSelectedRequestIndex: Copy, Clone, std::fmt::Debug);
static_assertions::assert_not_impl_any!(ValidatedOwnedInput: Copy, Clone, std::fmt::Debug);
static_assertions::assert_not_impl_any!(ObservedTransactionInput: Copy, Clone, std::fmt::Debug);
static_assertions::assert_not_impl_any!(ObservedWalletTransaction: Copy, Clone, std::fmt::Debug);
static_assertions::assert_not_impl_any!(ObservedOwnedOutput: Copy, Clone, std::fmt::Debug);
static_assertions::assert_not_impl_any!(ObservedWalletBatch: Copy, Clone, std::fmt::Debug);

#[test]
fn selected_output_validation_source_retains_only_one_owned_expectation() {
    let source = include_str!("lib.rs");
    let private_opening = source
        .split_once("pub fn open_prepared_selected_owned_inputs")
        .unwrap()
        .1
        .split_once("/// Validates and privately opens one bounded batch")
        .unwrap()
        .0;
    assert!(!private_opening.contains("BTreeSet"));
    assert_eq!(private_opening.matches("OutPoint::new(").count(), 1);
    assert!(!private_opening.contains("BorrowedSlip77"));
    assert!(!private_opening.contains("derive_blinding_key"));
    assert!(!private_opening.contains("SecretKey"));

    let provider_surface = source
        .split_once("pub trait SelectedOutputOpeningProvider")
        .unwrap()
        .1
        .split_once("/// An opaque, key-free capability")
        .unwrap()
        .0;
    assert!(provider_surface.contains("secp: &Secp256k1<All>"));
    assert!(provider_surface.contains("output: &TxOut"));
    for forbidden in [
        "OutPoint",
        "Txid",
        "AssetId",
        "Descriptor",
        "SelectedOutputBatch",
        "Transaction",
        "Pset",
        "SecretKey",
        "associated type",
    ] {
        assert!(!provider_surface.contains(forbidden), "{forbidden}");
    }

    let public_temporary = source
        .split_once("struct PubliclyValidatedSelectedOutput")
        .unwrap()
        .1
        .split_once("/// A privacy-redacted failure")
        .unwrap()
        .0;
    assert!(public_temporary.contains("request_index: ScopedSelectedRequestIndex"));
    assert!(!public_temporary.contains("output_index"));
    assert!(!public_temporary.contains("expected_"));

    let prepared_surface = source
        .split_once("impl PubliclyPreparedSelectedOutputs<'_>")
        .unwrap()
        .1
        .split_once("struct ScopedSelectedRequestIndex")
        .unwrap()
        .0;
    assert_eq!(prepared_surface.matches("pub fn ").count(), 1);
    assert!(prepared_surface.contains("pub fn input_count"));
}

#[test]
fn selected_output_provider_trait_is_object_safe() {
    fn borrow_object(_: &mut dyn SelectedOutputOpeningProvider) {}

    let slip77 = synthetic_material(b"wallet-facts object-safe selected provider");
    let mut provider = SyntheticSelectedOpeningProvider::new(&slip77);
    borrow_object(&mut provider);
}

#[test]
fn expected_plan_predicate_is_exact_and_clears_all_accumulators() {
    let catalog = test_catalog(1);
    let slip77 = synthetic_material(b"wallet-facts expected plan material");
    let fixture = confidential_fixture(&catalog, &slip77);
    let expectation = fixture.selected_expectation(2);
    let request = [BorrowedSelectedOutput::new(
        &expectation.outpoint,
        &expectation.asset,
        &expectation.value,
        &fixture.transaction_bytes,
        std::slice::from_ref(&fixture.previous_transaction_bytes),
    )];
    let selected = SelectedOutputBatch::new(&request).unwrap();
    let drops_before = expected_plan_total_drop_count();

    assert!(selected.expected_ordinary_plan_is_balanced(
        &[],
        wasabi_liquid_native_ordinary_pset::ExplicitFee::new(fixture.first_asset, 100).unwrap(),
    ));
    assert_eq!(expected_plan_total_drop_count() - drops_before, 2);
    assert!(!selected.expected_ordinary_plan_is_balanced(
        &[],
        wasabi_liquid_native_ordinary_pset::ExplicitFee::new(fixture.first_asset, 99).unwrap(),
    ));
    assert_eq!(expected_plan_total_drop_count() - drops_before, 4);
    assert!(!selected.expected_ordinary_plan_is_balanced(
        &[],
        wasabi_liquid_native_ordinary_pset::ExplicitFee::new(fixture.second_asset, 100).unwrap(),
    ));
    assert_eq!(expected_plan_total_drop_count() - drops_before, 6);

    let overflow_drops_before = expected_plan_total_drop_count();
    {
        let mut totals = ExpectedPlanTotals::with_capacity(1);
        assert!(totals.checked_add([0x5a; 32], u64::MAX));
        assert!(!totals.checked_add([0x5a; 32], 1));
    }
    assert_eq!(expected_plan_total_drop_count() - overflow_drops_before, 1);

    let partial_total_drops_before = expected_plan_total_drop_count();
    let partial_asset_drops_before = expected_plan_asset_drop_count();
    let unwind = std::panic::catch_unwind(|| {
        let mut totals = ExpectedPlanTotals::with_capacity(2);
        assert!(totals.checked_add([0x31; 32], 7));
        set_expected_plan_adds_before_panic(Some(0));
        let _ = totals.checked_add([0x32; 32], 9);
    });
    set_expected_plan_adds_before_panic(None);
    assert!(unwind.is_err());
    assert_eq!(
        expected_plan_total_drop_count() - partial_total_drops_before,
        1
    );
    assert_eq!(
        expected_plan_asset_drop_count() - partial_asset_drops_before,
        2
    );
}

#[test]
fn split_selected_opening_calls_provider_in_exact_request_order_and_retries_from_zero() {
    let catalog = test_catalog(1);
    let slip77 = synthetic_material(b"wallet-facts split selected provider material");
    let fixture = confidential_fixture(&catalog, &slip77);
    let expectations = [
        fixture.selected_expectation(1),
        fixture.selected_expectation(0),
    ];
    let requests = borrowed_selected_outputs(&fixture, &expectations);
    let selected = SelectedOutputBatch::new(&requests).unwrap();
    let mut provider = SyntheticSelectedOpeningProvider::new(&slip77);

    for retry in 0..2 {
        let mut secp = Secp256k1::new();
        let prepared = prepare_selected_owned_inputs(&catalog, &selected, &secp).unwrap();
        assert_eq!(prepared.input_count(), 2);
        assert_eq!(provider.calls, retry * 2);
        let mut rng = StdRng::from_seed(synthetic_material(
            b"wallet-facts split selected provider randomness",
        ));
        let validated =
            open_prepared_selected_owned_inputs(prepared, &mut provider, &mut secp, &mut rng)
                .unwrap();
        assert_eq!(validated.len(), 2);
        drop(validated);
    }

    assert_eq!(provider.calls, 4);
    let expected = [
        fixture.transaction.output[1].script_pubkey.as_bytes(),
        fixture.transaction.output[0].script_pubkey.as_bytes(),
        fixture.transaction.output[1].script_pubkey.as_bytes(),
        fixture.transaction.output[0].script_pubkey.as_bytes(),
    ];
    assert!(provider.seen_scripts.iter().map(Vec::as_slice).eq(expected));
}

#[test]
fn selected_provider_is_not_called_on_public_or_context_failure() {
    let catalog = test_catalog(1);
    let slip77 = synthetic_material(b"wallet-facts provider barrier material");
    let fixture = confidential_fixture(&catalog, &slip77);
    let absent = fixture.selected_expectation(7);
    let absent_request = [BorrowedSelectedOutput::new(
        &absent.outpoint,
        &absent.asset,
        &absent.value,
        &fixture.transaction_bytes,
        std::slice::from_ref(&fixture.previous_transaction_bytes),
    )];
    let absent = SelectedOutputBatch::new(&absent_request).unwrap();
    let mut provider = SyntheticSelectedOpeningProvider::new(&slip77);
    assert!(matches!(
        validate_selected_owned_inputs(
            &catalog,
            &mut provider,
            &absent,
            &mut Secp256k1::new(),
            &mut SelectedNoRandomnessExpected,
        ),
        Err(WalletObservationError::SelectedOutputExpectation)
    ));
    assert_eq!(provider.calls, 0);

    let expectation = fixture.selected_expectation(0);
    let request = [BorrowedSelectedOutput::new(
        &expectation.outpoint,
        &expectation.asset,
        &expectation.value,
        &fixture.transaction_bytes,
        std::slice::from_ref(&fixture.previous_transaction_bytes),
    )];
    let selected = SelectedOutputBatch::new(&request).unwrap();
    let mut failing_rng = SelectedFailingCryptoRng {
        bytes_to_write: 7,
        try_fill_calls: 0,
    };
    assert!(matches!(
        validate_selected_owned_inputs(
            &catalog,
            &mut provider,
            &selected,
            &mut Secp256k1::new(),
            &mut failing_rng,
        ),
        Err(WalletObservationError::ContextRandomnessUnavailable)
    ));
    assert_eq!(provider.calls, 0);
}

#[test]
fn selected_provider_refusal_substitution_and_unwind_return_no_partial_capability() {
    let catalog = test_catalog(1);
    let slip77 = synthetic_material(b"wallet-facts provider atomicity material");
    let fixture = confidential_fixture(&catalog, &slip77);
    let expectations = [
        fixture.selected_expectation(0),
        fixture.selected_expectation(1),
    ];
    let requests = borrowed_selected_outputs(&fixture, &expectations);

    for (refusal, expected_calls, expected_drops) in [(0, 1, 0), (1, 2, 1)] {
        let selected = SelectedOutputBatch::new(&requests).unwrap();
        let mut provider = SyntheticSelectedOpeningProvider::refusing(&slip77, refusal);
        let drops_before = validated_owned_input_drop_count();
        let result = validate_selected_owned_inputs(
            &catalog,
            &mut provider,
            &selected,
            &mut Secp256k1::new(),
            &mut StdRng::from_seed(synthetic_material(b"wallet-facts provider refusal rng")),
        );
        assert!(matches!(
            result,
            Err(WalletObservationError::OwnedOutputOpening)
        ));
        assert_eq!(provider.calls, expected_calls);
        assert_eq!(
            validated_owned_input_drop_count() - drops_before,
            expected_drops
        );
    }

    for (substitution, substituted_output, expected_calls, expected_drops) in [
        (0, fixture.transaction.output[1].clone(), 1, 0),
        (1, fixture.transaction.output[0].clone(), 2, 1),
    ] {
        let selected = SelectedOutputBatch::new(&requests).unwrap();
        let mut provider = SyntheticSelectedOpeningProvider::substituting(
            &slip77,
            substitution,
            substituted_output,
        );
        let drops_before = validated_owned_input_drop_count();
        assert!(matches!(
            validate_selected_owned_inputs(
                &catalog,
                &mut provider,
                &selected,
                &mut Secp256k1::new(),
                &mut StdRng::from_seed(synthetic_material(
                    b"wallet-facts provider substitution rng"
                )),
            ),
            Err(WalletObservationError::OwnedOutputOpening)
        ));
        assert_eq!(provider.calls, expected_calls);
        assert_eq!(
            validated_owned_input_drop_count() - drops_before,
            expected_drops
        );
    }

    let selected = SelectedOutputBatch::new(&requests).unwrap();
    let mut provider = SyntheticSelectedOpeningProvider::panicking(&slip77, 1);
    let drops_before = validated_owned_input_drop_count();
    let scratch_drops_before = SYNTHETIC_PROVIDER_SCRATCH_DROPS.with(std::cell::Cell::get);
    let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = validate_selected_owned_inputs(
            &catalog,
            &mut provider,
            &selected,
            &mut Secp256k1::new(),
            &mut StdRng::from_seed(synthetic_material(b"wallet-facts provider panic rng")),
        );
    }));
    assert!(unwind.is_err());
    assert_eq!(provider.calls, 2);
    assert_eq!(validated_owned_input_drop_count() - drops_before, 1);
    assert_eq!(
        SYNTHETIC_PROVIDER_SCRATCH_DROPS.with(std::cell::Cell::get) - scratch_drops_before,
        2
    );
}

#[test]
fn selected_provider_zero_opening_is_redacted_and_clears_earlier_capability() {
    let catalog = test_catalog(1);
    let slip77 = synthetic_material(b"wallet-facts provider zero-opening material");
    let fixture = confidential_fixture(&catalog, &slip77);
    let zero = confidential_actual_zero_fixture(&catalog, &slip77);
    let expectations = [
        fixture.selected_expectation(0),
        fixture.selected_expectation(1),
    ];
    let requests = borrowed_selected_outputs(&fixture, &expectations);

    for (substitution, expected_calls, expected_drops) in [(0, 1, 0), (1, 2, 1)] {
        let selected = SelectedOutputBatch::new(&requests).unwrap();
        let mut provider = SyntheticSelectedOpeningProvider::substituting(
            &slip77,
            substitution,
            zero.transaction.output[0].clone(),
        );
        let drops_before = validated_owned_input_drop_count();
        assert!(matches!(
            validate_selected_owned_inputs(
                &catalog,
                &mut provider,
                &selected,
                &mut Secp256k1::new(),
                &mut StdRng::from_seed(synthetic_material(
                    b"wallet-facts provider zero-opening randomness"
                )),
            ),
            Err(WalletObservationError::OwnedOutputOpening)
        ));
        assert_eq!(provider.calls, expected_calls);
        assert_eq!(
            validated_owned_input_drop_count() - drops_before,
            expected_drops
        );
    }
}

#[test]
fn validates_only_exact_observed_public_output_shapes() {
    let catalog = test_catalog(0);
    let entry = catalog_entry(&catalog, DescriptorBranch::External, 0);
    let script = entry.script_pubkey.as_slice();
    let spend_key = entry.spend_public_key.as_slice();
    let blinding_key = entry.spend_public_key.as_slice();

    assert!(validates_observed_public_output(
        script,
        spend_key,
        blinding_key
    ));
    for malformed_length in (0..=64).filter(|length| *length != 22) {
        let malformed_script = vec![0; malformed_length];
        assert!(!validates_observed_public_output(
            &malformed_script,
            spend_key,
            blinding_key
        ));
    }
    for malformed_length in (0..=65).filter(|length| *length != 33) {
        let malformed_key = vec![0; malformed_length];
        assert!(!validates_observed_public_output(
            script,
            &malformed_key,
            blinding_key
        ));
        assert!(!validates_observed_public_output(
            script,
            spend_key,
            &malformed_key
        ));
    }

    let mut invalid_x = [0xff_u8; 33];
    invalid_x[0] = 0x02;
    for invalid_point in [[0_u8; 33], [0x04_u8; 33], [0x06_u8; 33], invalid_x] {
        assert!(!validates_observed_public_output(
            script,
            &invalid_point,
            blinding_key
        ));
        assert!(!validates_observed_public_output(
            script,
            spend_key,
            &invalid_point
        ));
    }
    let mut mismatched_script = entry.script_pubkey.clone();
    mismatched_script[2] ^= 1;
    assert!(!validates_observed_public_output(
        &mismatched_script,
        spend_key,
        blinding_key
    ));
}

#[test]
fn observed_public_output_helper_source_has_only_the_frozen_nonallocating_calls() {
    let source = include_str!("lib.rs");
    let helper = source
        .split("pub fn validates_observed_public_output")
        .nth(1)
        .unwrap()
        .split("/// The public derivation branch")
        .next()
        .unwrap();
    for forbidden in [
        "Vec",
        "Box",
        "String",
        "format!",
        "to_vec",
        "collect",
        "SecretKey",
        "Transaction",
        "Pset",
        "rand",
        "std::",
        "unwrap",
        "expect",
        "panic!",
    ] {
        assert!(!helper.contains(forbidden), "helper surface: {forbidden}");
    }
    assert_eq!(helper.matches("PublicKey::from_slice(").count(), 2);
    assert_eq!(helper.matches("hash160::Hash::hash(").count(), 1);
}

#[test]
fn derives_only_the_expected_public_branches() {
    let catalog = test_catalog(2);

    assert_eq!(catalog.network(), DescriptorNetwork::Test);
    assert_eq!(catalog.last_index(), 2);
    assert_eq!(catalog.script_count(), 6);
    assert_eq!(
        catalog
            .entries
            .values()
            .filter(|entry| entry.branch == DescriptorBranch::External)
            .count(),
        3
    );
    assert_eq!(
        catalog
            .entries
            .values()
            .filter(|entry| entry.branch == DescriptorBranch::Internal)
            .count(),
        3
    );
    assert!(catalog.entries.values().all(|entry| {
        Script::from(entry.script_pubkey.clone()).is_v0_p2wpkh()
            && entry.spend_public_key.len() == 33
    }));
    assert_eq!(
        catalog_entry(&catalog, DescriptorBranch::External, 0).script_pubkey,
        [
            0x00, 0x14, 0xd3, 0x63, 0xd5, 0x38, 0xbe, 0xa1, 0x26, 0x47, 0xf6, 0x1c, 0x63, 0x4b,
            0xdd, 0x7a, 0x79, 0x1d, 0x67, 0x68, 0x50, 0xe9,
        ]
    );
    assert_eq!(
        catalog_entry(&catalog, DescriptorBranch::Internal, 0).script_pubkey,
        [
            0x00, 0x14, 0xcf, 0xaf, 0xcd, 0xd0, 0x50, 0xd9, 0x63, 0xb2, 0x32, 0x18, 0xd2, 0xb8,
            0x44, 0xac, 0xc7, 0x26, 0xa5, 0x1f, 0x69, 0x0e,
        ]
    );
}

#[test]
fn rejects_private_confidential_wrong_shape_and_network_descriptors() {
    assert!(matches!(
        DescriptorCatalog::derive("", DescriptorNetwork::Test, 0),
        Err(DescriptorCatalogError::DescriptorLength)
    ));
    assert!(matches!(
        DescriptorCatalog::derive(
            &"x".repeat(MAX_PUBLIC_DESCRIPTOR_BYTES + 1),
            DescriptorNetwork::Test,
            0,
        ),
        Err(DescriptorCatalogError::DescriptorLength)
    ));
    assert!(matches!(
        DescriptorCatalog::derive(
            TEST_PUBLIC_DESCRIPTOR,
            DescriptorNetwork::Test,
            MAX_DERIVATION_INDEX + 1,
        ),
        Err(DescriptorCatalogError::DerivationIndex)
    ));
    let mut synthetic_input = synthetic_material(b"wallet-facts private descriptor rejection");
    let mut private_key = miniscript::bitcoin::bip32::Xpriv::new_master(
        miniscript::bitcoin::NetworkKind::Test,
        &synthetic_input,
    )
    .unwrap();
    synthetic_input.zeroize();
    let mut private_descriptor = format!("elwpkh({private_key}/<0;1>/*)");
    private_key.private_key.non_secure_erase();
    let private_result = DescriptorCatalog::derive(&private_descriptor, DescriptorNetwork::Test, 0);
    private_descriptor.zeroize();
    assert!(matches!(
        private_result,
        Err(DescriptorCatalogError::InvalidPublicDescriptor)
    ));

    let mut synthetic_wif_input = synthetic_material(b"wallet-facts WIF rejection");
    let mut synthetic_private_key = miniscript::bitcoin::PrivateKey::new(
        miniscript::bitcoin::secp256k1::SecretKey::from_slice(&synthetic_wif_input).unwrap(),
        miniscript::bitcoin::NetworkKind::Test,
    );
    synthetic_wif_input.zeroize();
    let mut synthetic_wif = synthetic_private_key.to_wif();
    synthetic_private_key.inner.non_secure_erase();
    let mut wif_descriptor = format!("elwpkh({synthetic_wif})");
    synthetic_wif.zeroize();
    let wif_result = DescriptorCatalog::derive(&wif_descriptor, DescriptorNetwork::Test, 0);
    wif_descriptor.zeroize();
    assert!(matches!(
        wif_result,
        Err(DescriptorCatalogError::InvalidPublicDescriptor)
    ));
    assert!(matches!(
        DescriptorCatalog::derive(
            &format!("ct(elip151,{TEST_PUBLIC_DESCRIPTOR})"),
            DescriptorNetwork::Test,
            0,
        ),
        Err(DescriptorCatalogError::UnsupportedDescriptor)
    ));
    assert!(matches!(
        DescriptorCatalog::derive(
            "elwsh(pk([28b3f14e/84'/1'/0']tpubDC2Q4xK4XH72GM7MowNuajyWVbigRLBWKswyP5T88hpPwu5nGqJWnda8zhJEFt71av73Hm8mUMMFSz9acNVzz8b1UbdSHCDXKTbSv5eEytu/<0;1>/*))",
            DescriptorNetwork::Test,
            0,
        ),
        Err(DescriptorCatalogError::UnsupportedDescriptor)
    ));
    assert!(matches!(
        DescriptorCatalog::derive(
            "elwpkh([28b3f14e/84'/1'/0']tpubDC2Q4xK4XH72GM7MowNuajyWVbigRLBWKswyP5T88hpPwu5nGqJWnda8zhJEFt71av73Hm8mUMMFSz9acNVzz8b1UbdSHCDXKTbSv5eEytu/0/*)",
            DescriptorNetwork::Test,
            0,
        ),
        Err(DescriptorCatalogError::InvalidBranchShape)
    ));
    assert!(matches!(
        DescriptorCatalog::derive(MAINNET_PUBLIC_DESCRIPTOR, DescriptorNetwork::Test, 0),
        Err(DescriptorCatalogError::NetworkMismatch)
    ));
    assert!(matches!(
        DescriptorCatalog::derive(TEST_PUBLIC_DESCRIPTOR, DescriptorNetwork::Mainnet, 0),
        Err(DescriptorCatalogError::NetworkMismatch)
    ));
    assert!(matches!(
        DescriptorCatalog::derive(
            &format!("{TEST_PUBLIC_DESCRIPTOR}#deadbeef"),
            DescriptorNetwork::Test,
            0,
        ),
        Err(DescriptorCatalogError::InvalidPublicDescriptor)
    ));
    let checksum = miniscript::descriptor::checksum::desc_checksum(TEST_PUBLIC_DESCRIPTOR).unwrap();
    assert_eq!(checksum, TEST_PUBLIC_DESCRIPTOR_CHECKSUM);
    assert!(
        DescriptorCatalog::derive(
            &format!("{TEST_PUBLIC_DESCRIPTOR}#{checksum}"),
            DescriptorNetwork::Test,
            0,
        )
        .is_ok()
    );
}

#[test]
fn liquid_descriptor_adapter_checks_the_original_exact_form() {
    let inner = TEST_PUBLIC_DESCRIPTOR
        .strip_prefix("elwpkh(")
        .and_then(|descriptor| descriptor.strip_suffix(')'))
        .unwrap();
    let normalized = format!("wpkh({inner})");
    let normalized_checksum = miniscript::descriptor::checksum::desc_checksum(&normalized).unwrap();
    assert_ne!(normalized_checksum, TEST_PUBLIC_DESCRIPTOR_CHECKSUM);
    assert!(matches!(
        DescriptorCatalog::derive(
            &format!("{TEST_PUBLIC_DESCRIPTOR}#{normalized_checksum}"),
            DescriptorNetwork::Test,
            0,
        ),
        Err(DescriptorCatalogError::InvalidPublicDescriptor)
    ));

    for malformed in [
        format!("{TEST_PUBLIC_DESCRIPTOR}#short"),
        format!("{TEST_PUBLIC_DESCRIPTOR}#toolong99"),
        format!("{TEST_PUBLIC_DESCRIPTOR}#{TEST_PUBLIC_DESCRIPTOR_CHECKSUM}#extra"),
    ] {
        assert!(matches!(
            DescriptorCatalog::derive(&malformed, DescriptorNetwork::Test, 0),
            Err(DescriptorCatalogError::InvalidPublicDescriptor)
        ));
    }

    for unsupported in [
        format!(" {TEST_PUBLIC_DESCRIPTOR}"),
        TEST_PUBLIC_DESCRIPTOR.replacen("elwpkh", "ELWPKH", 1),
        normalized,
        format!("prefix-{TEST_PUBLIC_DESCRIPTOR}"),
    ] {
        assert!(matches!(
            DescriptorCatalog::derive(&unsupported, DescriptorNetwork::Test, 0),
            Err(DescriptorCatalogError::UnsupportedDescriptor)
        ));
    }

    let three_branches = TEST_PUBLIC_DESCRIPTOR.replacen("<0;1>", "<0;1;2>", 1);
    assert!(matches!(
        DescriptorCatalog::derive(&three_branches, DescriptorNetwork::Test, 0),
        Err(DescriptorCatalogError::InvalidBranchShape)
    ));

    let hardened_wildcard = TEST_PUBLIC_DESCRIPTOR.replacen("/*)", "/*h)", 1);
    assert!(matches!(
        DescriptorCatalog::derive(&hardened_wildcard, DescriptorNetwork::Test, 0),
        Err(DescriptorCatalogError::InvalidBranchShape)
    ));

    let mut public_key_input = synthetic_material(b"wallet-facts public key shape rejection");
    let mut public_key_secret =
        miniscript::bitcoin::secp256k1::SecretKey::from_slice(&public_key_input).unwrap();
    public_key_input.zeroize();
    let secp = miniscript::bitcoin::secp256k1::Secp256k1::new();
    let public_key =
        miniscript::bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &public_key_secret);
    public_key_secret.non_secure_erase();
    let uncompressed = public_key
        .serialize_uncompressed()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let x_only = public_key.x_only_public_key().0.to_string();
    for unsupported_key in [uncompressed, x_only] {
        assert!(
            DescriptorCatalog::derive(
                &format!("elwpkh({unsupported_key})"),
                DescriptorNetwork::Test,
                0,
            )
            .is_err()
        );
    }
}

#[test]
fn observes_two_validated_assets_without_retaining_blinding_material() {
    let catalog = test_catalog(1);
    let slip77 = synthetic_material(b"wallet-facts correct blinding material");
    let fixture = confidential_fixture(&catalog, &slip77);
    let candidate = fixture.candidate_batch();
    let drops_before = scoped_secret_key_drop_count();
    assert_eq!(
        fixture.transaction.txid().to_byte_array(),
        [
            0x35, 0xab, 0x90, 0x5f, 0xc9, 0x34, 0xc0, 0x8f, 0xa9, 0x76, 0xd5, 0x54, 0x27, 0xbd,
            0xd3, 0x97, 0x03, 0x83, 0xe0, 0xf0, 0x1e, 0xce, 0x05, 0x94, 0x26, 0xec, 0x04, 0x14,
            0x4b, 0x4e, 0xcc, 0x3d,
        ]
    );
    assert_eq!(
        sha256::Hash::hash(&fixture.transaction_bytes).to_byte_array(),
        [
            0x78, 0xee, 0x7e, 0x96, 0xe4, 0x86, 0xb0, 0xfb, 0xe2, 0xad, 0x4d, 0xf5, 0x82, 0x0f,
            0xe0, 0x0f, 0x4c, 0x77, 0xb0, 0xc7, 0x47, 0x55, 0x62, 0xbf, 0x9b, 0xf3, 0x18, 0x71,
            0xd3, 0x29, 0x4e, 0x01,
        ]
    );

    assert_eq!(
        fixture.first_asset.to_byte_array(),
        std::array::from_fn(|index| index as u8)
    );
    assert_eq!(
        fixture.first_asset.to_string(),
        "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100"
    );

    let batch = observe_owned_outputs(&catalog, BorrowedSlip77::new(&slip77), &candidate).unwrap();

    assert_eq!(scoped_secret_key_drop_count() - drops_before, 2);
    assert_eq!(batch.transactions().len(), 1);
    assert_eq!(batch.outputs().len(), 2);
    assert!(!batch.is_empty());
    let observed_transaction = &batch.transactions()[0];
    assert_eq!(
        observed_transaction.transaction_id(),
        &fixture.transaction.txid().to_byte_array()
    );
    assert_eq!(
        observed_transaction.transaction_witness_binding(),
        &sha256::Hash::hash(&fixture.transaction_bytes).to_byte_array()
    );
    assert_eq!(observed_transaction.inputs().len(), 2);
    assert_eq!(
        observed_transaction
            .inputs()
            .iter()
            .map(|input| (
                *input.previous_transaction_id(),
                input.previous_output_index()
            ))
            .collect::<Vec<_>>(),
        fixture
            .transaction
            .input
            .iter()
            .map(|input| {
                (
                    input.previous_output.txid.to_byte_array(),
                    input.previous_output.vout,
                )
            })
            .collect::<Vec<_>>()
    );
    assert_eq!(batch.transactions.capacity(), batch.transactions.len());
    assert_eq!(
        observed_transaction.inputs.capacity(),
        observed_transaction.inputs.len()
    );
    let secp = Secp256k1::new();
    let external_blinding_public_key = derived_blinding_key(
        catalog_entry(&catalog, DescriptorBranch::External, 0),
        &slip77,
    )
    .0
    .public_key(&secp)
    .serialize();
    let internal_blinding_public_key = derived_blinding_key(
        catalog_entry(&catalog, DescriptorBranch::Internal, 1),
        &slip77,
    )
    .0
    .public_key(&secp)
    .serialize();
    let expected = BTreeSet::from([
        (
            DescriptorBranch::External,
            0,
            fixture.first_asset.to_byte_array(),
            900,
            external_blinding_public_key,
        ),
        (
            DescriptorBranch::Internal,
            1,
            fixture.second_asset.to_byte_array(),
            2_000,
            internal_blinding_public_key,
        ),
    ]);
    let observed = batch
        .outputs()
        .iter()
        .map(|output| {
            assert_eq!(
                output.transaction_id(),
                &fixture.transaction.txid().to_byte_array()
            );
            assert_eq!(
                output.transaction_witness_binding(),
                &sha256::Hash::hash(&fixture.transaction_bytes).to_byte_array()
            );
            assert_eq!(output.script_pubkey().len(), 22);
            assert_eq!(output.spend_public_key().len(), 33);
            assert_eq!(output.blinding_public_key().len(), 33);
            assert_eq!(
                output.transaction_id(),
                observed_transaction.transaction_id()
            );
            assert_eq!(
                output.transaction_witness_binding(),
                observed_transaction.transaction_witness_binding()
            );
            (
                output.branch(),
                output.derivation_index(),
                *output.asset_id(),
                output.value(),
                *output.blinding_public_key(),
            )
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(observed, expected);
    assert!(batch.outputs().windows(2).all(|pair| {
        (pair[0].transaction_id(), pair[0].output_index())
            < (pair[1].transaction_id(), pair[1].output_index())
    }));
}

#[test]
fn validates_selected_outputs_into_only_consuming_spendable_capabilities() {
    let catalog = test_catalog(1);
    let slip77 = synthetic_material(b"wallet-facts selected-output material");
    let fixture = confidential_fixture(&catalog, &slip77);
    let expectations = [
        fixture.selected_expectation(1),
        fixture.selected_expectation(0),
    ];
    let requests = borrowed_selected_outputs(&fixture, &expectations);
    let selected = SelectedOutputBatch::new(&requests).unwrap();
    let mut secp = Secp256k1::new();
    let mut rng = SelectedCountingCryptoRng {
        inner: StdRng::from_seed(synthetic_material(
            b"wallet-facts selected-output context randomness",
        )),
        fill_calls: 0,
        filled_bytes: 0,
    };
    let seed_drops_before = context_randomization_seed_drop_count();
    let derivations_before = derivation_call_count();
    let expectation_drops_before = selected_output_expectation_drop_count();
    let request_index_drops_before = selected_output_request_index_drop_count();

    let validated = validate_selected_owned_inputs(
        &catalog,
        &mut SyntheticSelectedOpeningProvider::new(&slip77),
        &selected,
        &mut secp,
        &mut rng,
    )
    .unwrap();

    assert_eq!(rng.fill_calls, 1);
    assert_eq!(rng.filled_bytes, 32);
    assert_eq!(
        context_randomization_seed_drop_count() - seed_drops_before,
        1
    );
    assert_eq!(derivation_call_count() - derivations_before, 2);
    assert_eq!(
        selected_output_request_index_drop_count() - request_index_drops_before,
        2
    );
    assert_eq!(
        selected_output_expectation_drop_count(),
        expectation_drops_before
    );
    assert_eq!(validated.len(), 2);
    for (validated, output_index) in validated.into_iter().zip([1_u32, 0]) {
        let spendable = validated.into_spendable();
        assert_eq!(
            spendable.outpoint(),
            &OutPoint::new(fixture.transaction.txid(), output_index)
        );
        assert_eq!(
            spendable.witness_utxo(),
            &fixture.transaction.output[output_index as usize]
        );
    }
    drop(selected);
    assert_eq!(
        selected_output_expectation_drop_count() - expectation_drops_before,
        2
    );
}

#[test]
fn selected_output_preflight_rejects_before_copying_or_decoding() {
    let catalog = test_catalog(1);
    let slip77 = synthetic_material(b"wallet-facts selected preflight material");
    let fixture = confidential_fixture(&catalog, &slip77);
    let previous = std::slice::from_ref(&fixture.previous_transaction_bytes);
    let clones_before = candidate_payload_clone_count();
    let decodes_before = candidate_transaction_decode_count();

    assert!(matches!(
        SelectedOutputBatch::new(&[]),
        Err(WalletObservationError::BatchLimit)
    ));
    let reserved_expectation = SelectedExpectation {
        outpoint: OutPoint::new(fixture.transaction.txid(), 1 << 30),
        asset: fixture.first_asset,
        value: 900,
    };
    let reserved = [BorrowedSelectedOutput::new(
        &reserved_expectation.outpoint,
        &reserved_expectation.asset,
        &reserved_expectation.value,
        &fixture.transaction_bytes,
        previous,
    )];
    assert!(matches!(
        SelectedOutputBatch::new(&reserved),
        Err(WalletObservationError::SelectedOutputExpectation)
    ));

    for invalid in [
        SelectedExpectation {
            outpoint: OutPoint::new(Txid::from_byte_array([0; 32]), 0),
            asset: fixture.first_asset,
            value: 900,
        },
        SelectedExpectation {
            outpoint: OutPoint::new(fixture.transaction.txid(), 1 << 31),
            asset: fixture.first_asset,
            value: 900,
        },
        SelectedExpectation {
            outpoint: OutPoint::new(fixture.transaction.txid(), 0),
            asset: AssetId::from_byte_array([0; 32]),
            value: 900,
        },
        SelectedExpectation {
            outpoint: OutPoint::new(fixture.transaction.txid(), 0),
            asset: fixture.first_asset,
            value: 0,
        },
        SelectedExpectation {
            outpoint: OutPoint::new(fixture.transaction.txid(), 0),
            asset: fixture.first_asset,
            value: MAX_ORDINARY_VALUE + 1,
        },
    ] {
        assert_selected_preflight_rejects(&fixture, &invalid);
    }

    let later_invalid_expectations = [
        fixture.selected_expectation(0),
        SelectedExpectation {
            outpoint: OutPoint::new(fixture.transaction.txid(), 1),
            asset: fixture.second_asset,
            value: 0,
        },
    ];
    let later_invalid_requests = borrowed_selected_outputs(&fixture, &later_invalid_expectations);
    assert!(matches!(
        SelectedOutputBatch::new(&later_invalid_requests),
        Err(WalletObservationError::SelectedOutputExpectation)
    ));

    let duplicate_expectations = [
        fixture.selected_expectation(0),
        fixture.selected_expectation(0),
    ];
    let duplicate_requests = borrowed_selected_outputs(&fixture, &duplicate_expectations);
    assert!(matches!(
        SelectedOutputBatch::new(&duplicate_requests),
        Err(WalletObservationError::DuplicateSelectedOutpoint)
    ));
    let too_many_expectations = (0..=MAX_SELECTED_OUTPUTS)
        .map(|index| SelectedExpectation {
            outpoint: OutPoint::new(fixture.transaction.txid(), index as u32),
            asset: fixture.first_asset,
            value: 900,
        })
        .collect::<Vec<_>>();
    let too_many = borrowed_selected_outputs(&fixture, &too_many_expectations);
    assert!(matches!(
        SelectedOutputBatch::new(&too_many),
        Err(WalletObservationError::BatchLimit)
    ));
    assert_eq!(candidate_payload_clone_count(), clones_before);
    assert_eq!(candidate_transaction_decode_count(), decodes_before);

    let maximum_expectations = (0..MAX_SELECTED_OUTPUTS)
        .map(|index| SelectedExpectation {
            outpoint: OutPoint::new(fixture.transaction.txid(), index as u32),
            asset: fixture.first_asset,
            value: MAX_ORDINARY_VALUE,
        })
        .collect::<Vec<_>>();
    let maximum_requests = borrowed_selected_outputs(&fixture, &maximum_expectations);
    let maximum_batch = SelectedOutputBatch::new(&maximum_requests).unwrap();
    drop(maximum_batch);
    assert_eq!(
        candidate_payload_clone_count() - clones_before,
        MAX_SELECTED_OUTPUTS * 2
    );
    assert_eq!(candidate_transaction_decode_count(), decodes_before);
}

#[test]
fn selected_output_public_failures_precede_entropy_and_secret_derivation() {
    let catalog = test_catalog(1);
    let slip77 = synthetic_material(b"wallet-facts selected public validation material");
    let fixture = confidential_fixture(&catalog, &slip77);
    let previous = std::slice::from_ref(&fixture.previous_transaction_bytes);

    let mut secp = Secp256k1::new();
    let derivations_before = derivation_call_count();

    let absent_expectation = fixture.selected_expectation(3);
    let absent_request = [BorrowedSelectedOutput::new(
        &absent_expectation.outpoint,
        &absent_expectation.asset,
        &absent_expectation.value,
        &fixture.transaction_bytes,
        previous,
    )];
    let absent = SelectedOutputBatch::new(&absent_request).unwrap();
    let previous_decodes_before = previous_transaction_decode_count();
    let opens_before = selected_output_open_attempt_count();
    assert!(matches!(
        validate_selected_owned_inputs(
            &catalog,
            &mut SyntheticSelectedOpeningProvider::new(&slip77),
            &absent,
            &mut secp,
            &mut SelectedNoRandomnessExpected,
        ),
        Err(WalletObservationError::SelectedOutputExpectation)
    ));
    assert_eq!(previous_transaction_decode_count(), previous_decodes_before);
    assert_eq!(selected_output_open_attempt_count(), opens_before);
    let expectation_drops_before = selected_output_expectation_drop_count();
    drop(absent);
    assert_eq!(
        selected_output_expectation_drop_count() - expectation_drops_before,
        1
    );
    assert_eq!(derivation_call_count(), derivations_before);

    let unowned_expectation = fixture.selected_expectation(2);
    let unowned_request = [BorrowedSelectedOutput::new(
        &unowned_expectation.outpoint,
        &unowned_expectation.asset,
        &unowned_expectation.value,
        &fixture.transaction_bytes,
        previous,
    )];
    let unowned = SelectedOutputBatch::new(&unowned_request).unwrap();
    assert!(matches!(
        validate_selected_owned_inputs(
            &catalog,
            &mut SyntheticSelectedOpeningProvider::new(&slip77),
            &unowned,
            &mut secp,
            &mut SelectedNoRandomnessExpected,
        ),
        Err(WalletObservationError::SelectedOutputNotOwned)
    ));
    let expectation_drops_before = selected_output_expectation_drop_count();
    drop(unowned);
    assert_eq!(
        selected_output_expectation_drop_count() - expectation_drops_before,
        1
    );

    let mut damaged_transaction = fixture.transaction.clone();
    damaged_transaction.output[0].witness.rangeproof = RangeProof::EMPTY;
    let damaged_bytes = serialize(&damaged_transaction);
    let damaged_expectation = SelectedExpectation {
        outpoint: OutPoint::new(damaged_transaction.txid(), 0),
        asset: fixture.first_asset,
        value: 900,
    };
    let damaged_request = [BorrowedSelectedOutput::new(
        &damaged_expectation.outpoint,
        &damaged_expectation.asset,
        &damaged_expectation.value,
        &damaged_bytes,
        previous,
    )];
    let damaged = SelectedOutputBatch::new(&damaged_request).unwrap();
    assert!(matches!(
        validate_selected_owned_inputs(
            &catalog,
            &mut SyntheticSelectedOpeningProvider::new(&slip77),
            &damaged,
            &mut secp,
            &mut SelectedNoRandomnessExpected,
        ),
        Err(WalletObservationError::TransactionValidation)
    ));
    assert_eq!(derivation_call_count(), derivations_before);
    let expectation_drops_before = selected_output_expectation_drop_count();
    drop(damaged);
    assert_eq!(
        selected_output_expectation_drop_count() - expectation_drops_before,
        1
    );
}

#[test]
fn selected_output_txid_substitution_rejects_before_previous_or_private_work() {
    let catalog = test_catalog(1);
    let slip77 = synthetic_material(b"wallet-facts selected substitution material");
    let fixture = confidential_fixture(&catalog, &slip77);
    let expectation = fixture.selected_expectation(0);
    let mut substituted = fixture.transaction.clone();
    substituted.lock_time = LockTime::from_consensus(1);
    assert_ne!(substituted.txid(), expectation.outpoint.txid);
    let substituted_bytes = serialize(&substituted);
    let request = [BorrowedSelectedOutput::new(
        &expectation.outpoint,
        &expectation.asset,
        &expectation.value,
        &substituted_bytes,
        std::slice::from_ref(&fixture.previous_transaction_bytes),
    )];
    let selected = SelectedOutputBatch::new(&request).unwrap();
    let previous_decodes_before = previous_transaction_decode_count();
    let derivations_before = derivation_call_count();
    let opens_before = selected_output_open_attempt_count();
    let mut secp = Secp256k1::new();

    assert!(matches!(
        validate_selected_owned_inputs(
            &catalog,
            &mut SyntheticSelectedOpeningProvider::new(&slip77),
            &selected,
            &mut secp,
            &mut SelectedNoRandomnessExpected,
        ),
        Err(WalletObservationError::SelectedOutputExpectation)
    ));
    assert_eq!(previous_transaction_decode_count(), previous_decodes_before);
    assert_eq!(derivation_call_count(), derivations_before);
    assert_eq!(selected_output_open_attempt_count(), opens_before);
    let expectation_drops_before = selected_output_expectation_drop_count();
    drop(selected);
    assert_eq!(
        selected_output_expectation_drop_count() - expectation_drops_before,
        1
    );
}

#[test]
fn selected_output_expectations_bind_consensus_asset_order_and_value_after_opening() {
    let catalog = test_catalog(1);
    let slip77 = synthetic_material(b"wallet-facts selected expectation material");
    let fixture = confidential_fixture(&catalog, &slip77);
    let mut reversed_asset = fixture.first_asset.to_byte_array();
    reversed_asset.reverse();
    assert_ne!(reversed_asset, fixture.first_asset.to_byte_array());

    for expectation in [
        SelectedExpectation {
            outpoint: OutPoint::new(fixture.transaction.txid(), 0),
            asset: AssetId::from_byte_array(reversed_asset),
            value: 900,
        },
        SelectedExpectation {
            outpoint: OutPoint::new(fixture.transaction.txid(), 0),
            asset: fixture.first_asset,
            value: 899,
        },
    ] {
        let request = [BorrowedSelectedOutput::new(
            &expectation.outpoint,
            &expectation.asset,
            &expectation.value,
            &fixture.transaction_bytes,
            std::slice::from_ref(&fixture.previous_transaction_bytes),
        )];
        let selected = SelectedOutputBatch::new(&request).unwrap();
        let expectation_drops_before = selected_output_expectation_drop_count();
        let derivations_before = derivation_call_count();
        let opens_before = selected_output_open_attempt_count();
        let mut secp = Secp256k1::new();
        let mut rng = SelectedCountingCryptoRng {
            inner: StdRng::from_seed(synthetic_material(
                b"wallet-facts selected expectation mismatch randomness",
            )),
            fill_calls: 0,
            filled_bytes: 0,
        };

        assert!(matches!(
            validate_selected_owned_inputs(
                &catalog,
                &mut SyntheticSelectedOpeningProvider::new(&slip77),
                &selected,
                &mut secp,
                &mut rng,
            ),
            Err(WalletObservationError::OwnedOutputOpening)
        ));
        assert_eq!(rng.fill_calls, 1);
        assert_eq!(derivation_call_count() - derivations_before, 1);
        assert_eq!(selected_output_open_attempt_count() - opens_before, 1);
        assert_eq!(
            selected_output_expectation_drop_count(),
            expectation_drops_before
        );
        drop(selected);
        assert_eq!(
            selected_output_expectation_drop_count() - expectation_drops_before,
            1
        );
    }
}

#[test]
fn selected_output_late_expectation_mismatch_drops_earlier_capability() {
    let catalog = test_catalog(1);
    let slip77 = synthetic_material(b"wallet-facts selected late expectation material");
    let fixture = confidential_fixture(&catalog, &slip77);
    let mut expectations = [
        fixture.selected_expectation(0),
        fixture.selected_expectation(1),
    ];
    expectations[1].value -= 1;
    let requests = borrowed_selected_outputs(&fixture, &expectations);
    let selected = SelectedOutputBatch::new(&requests).unwrap();
    let capability_drops_before = validated_owned_input_drop_count();
    let request_index_drops_before = selected_output_request_index_drop_count();
    let expectation_drops_before = selected_output_expectation_drop_count();
    let mut secp = Secp256k1::new();
    let mut rng = SelectedCountingCryptoRng {
        inner: StdRng::from_seed(synthetic_material(
            b"wallet-facts selected late expectation randomness",
        )),
        fill_calls: 0,
        filled_bytes: 0,
    };

    assert!(matches!(
        validate_selected_owned_inputs(
            &catalog,
            &mut SyntheticSelectedOpeningProvider::new(&slip77),
            &selected,
            &mut secp,
            &mut rng,
        ),
        Err(WalletObservationError::OwnedOutputOpening)
    ));
    assert_eq!(
        validated_owned_input_drop_count() - capability_drops_before,
        1
    );
    assert_eq!(
        selected_output_request_index_drop_count() - request_index_drops_before,
        2
    );
    assert_eq!(
        selected_output_expectation_drop_count(),
        expectation_drops_before
    );
    drop(selected);
    assert_eq!(
        selected_output_expectation_drop_count() - expectation_drops_before,
        2
    );
}

#[test]
fn selected_output_private_failure_returns_no_capability() {
    let catalog = test_catalog(1);
    let slip77 = synthetic_material(b"wallet-facts selected private validation material");
    let wrong = synthetic_material(b"wallet-facts selected wrong private material");
    let fixture = confidential_fixture(&catalog, &slip77);
    let expectation = fixture.selected_expectation(0);
    let requests = [BorrowedSelectedOutput::new(
        &expectation.outpoint,
        &expectation.asset,
        &expectation.value,
        &fixture.transaction_bytes,
        std::slice::from_ref(&fixture.previous_transaction_bytes),
    )];
    let selected = SelectedOutputBatch::new(&requests).unwrap();
    let mut rng = SelectedCountingCryptoRng {
        inner: StdRng::from_seed(synthetic_material(
            b"wallet-facts selected private failure randomness",
        )),
        fill_calls: 0,
        filled_bytes: 0,
    };
    let mut secp = Secp256k1::new();
    let expectation_drops_before = selected_output_expectation_drop_count();

    assert!(matches!(
        validate_selected_owned_inputs(
            &catalog,
            &mut SyntheticSelectedOpeningProvider::new(&wrong),
            &selected,
            &mut secp,
            &mut rng,
        ),
        Err(WalletObservationError::OwnedOutputOpening)
    ));
    assert_eq!(rng.fill_calls, 1);
    assert_eq!(rng.filled_bytes, 32);
    assert_eq!(
        selected_output_expectation_drop_count(),
        expectation_drops_before
    );
    drop(selected);
    assert_eq!(
        selected_output_expectation_drop_count() - expectation_drops_before,
        1
    );
}

#[test]
fn selected_output_derivation_failure_clears_private_state_and_owned_expectation() {
    let catalog = test_catalog(1);
    let slip77 = synthetic_material(b"wallet-facts selected derivation failure material");
    let fixture = confidential_fixture(&catalog, &slip77);
    let expectation = fixture.selected_expectation(0);
    let requests = [BorrowedSelectedOutput::new(
        &expectation.outpoint,
        &expectation.asset,
        &expectation.value,
        &fixture.transaction_bytes,
        std::slice::from_ref(&fixture.previous_transaction_bytes),
    )];
    let selected = SelectedOutputBatch::new(&requests).unwrap();
    let expectation_drops_before = selected_output_expectation_drop_count();
    let secret_buffer_drops_before = derivation_secret_buffer_drop_count();
    let request_index_drops_before = selected_output_request_index_drop_count();
    let mut secp = Secp256k1::new();
    let mut rng = SelectedCountingCryptoRng {
        inner: StdRng::from_seed(synthetic_material(
            b"wallet-facts selected derivation failure randomness",
        )),
        fill_calls: 0,
        filled_bytes: 0,
    };

    set_derivation_test_mode(DerivationTestMode::InvalidScalar);
    assert!(matches!(
        validate_selected_owned_inputs(
            &catalog,
            &mut SyntheticSelectedOpeningProvider::new(&slip77),
            &selected,
            &mut secp,
            &mut rng,
        ),
        Err(WalletObservationError::OwnedOutputOpening)
    ));
    assert_eq!(rng.fill_calls, 1);
    assert_eq!(
        derivation_secret_buffer_drop_count() - secret_buffer_drops_before,
        4
    );
    assert_eq!(
        selected_output_request_index_drop_count() - request_index_drops_before,
        1
    );
    assert_eq!(
        selected_output_expectation_drop_count(),
        expectation_drops_before
    );
    drop(selected);
    assert_eq!(
        selected_output_expectation_drop_count() - expectation_drops_before,
        1
    );
}

#[test]
fn selected_output_late_opening_failure_drops_earlier_capability() {
    let catalog = test_catalog(1);
    let slip77 = synthetic_material(b"wallet-facts selected late failure material");
    let wrong = synthetic_material(b"wallet-facts selected late mismatched material");
    let fixture = confidential_fixture_with_second_blinder(&catalog, &slip77, &wrong);
    let expectations = [
        fixture.selected_expectation(0),
        fixture.selected_expectation(1),
    ];
    let requests = borrowed_selected_outputs(&fixture, &expectations);
    let selected = SelectedOutputBatch::new(&requests).unwrap();
    let mut secp = Secp256k1::new();
    let mut rng = SelectedCountingCryptoRng {
        inner: StdRng::from_seed(synthetic_material(
            b"wallet-facts selected late failure randomness",
        )),
        fill_calls: 0,
        filled_bytes: 0,
    };
    let derivations_before = derivation_call_count();
    let opens_before = selected_output_open_attempt_count();
    let key_drops_before = scoped_secret_key_drop_count();
    let capability_drops_before = validated_owned_input_drop_count();
    let expectation_drops_before = selected_output_expectation_drop_count();

    let result = validate_selected_owned_inputs(
        &catalog,
        &mut SyntheticSelectedOpeningProvider::new(&slip77),
        &selected,
        &mut secp,
        &mut rng,
    );

    assert!(matches!(
        result,
        Err(WalletObservationError::OwnedOutputOpening)
    ));
    assert_eq!(rng.fill_calls, 1);
    assert_eq!(rng.filled_bytes, 32);
    assert_eq!(derivation_call_count() - derivations_before, 2);
    assert_eq!(selected_output_open_attempt_count() - opens_before, 2);
    assert_eq!(scoped_secret_key_drop_count() - key_drops_before, 2);
    assert_eq!(
        validated_owned_input_drop_count() - capability_drops_before,
        1
    );
    assert_eq!(
        selected_output_expectation_drop_count(),
        expectation_drops_before
    );
    drop(selected);
    assert_eq!(
        selected_output_expectation_drop_count() - expectation_drops_before,
        2
    );
}

#[test]
fn selected_output_entropy_failures_erase_seed_before_private_work() {
    let catalog = test_catalog(1);
    let slip77 = synthetic_material(b"wallet-facts selected entropy failure material");
    let fixture = confidential_fixture(&catalog, &slip77);
    let expectation = fixture.selected_expectation(0);
    let requests = [BorrowedSelectedOutput::new(
        &expectation.outpoint,
        &expectation.asset,
        &expectation.value,
        &fixture.transaction_bytes,
        std::slice::from_ref(&fixture.previous_transaction_bytes),
    )];
    let selected = SelectedOutputBatch::new(&requests).unwrap();
    let expectation_drops_before = selected_output_expectation_drop_count();

    for bytes_to_write in [0, 13] {
        let mut secp = Secp256k1::new();
        let mut rng = SelectedFailingCryptoRng {
            bytes_to_write,
            try_fill_calls: 0,
        };
        let seed_drops_before = context_randomization_seed_drop_count();
        let derivations_before = derivation_call_count();
        let opens_before = selected_output_open_attempt_count();
        let capability_drops_before = validated_owned_input_drop_count();

        assert!(matches!(
            validate_selected_owned_inputs(
                &catalog,
                &mut SyntheticSelectedOpeningProvider::new(&slip77),
                &selected,
                &mut secp,
                &mut rng,
            ),
            Err(WalletObservationError::ContextRandomnessUnavailable)
        ));
        assert_eq!(rng.try_fill_calls, 1);
        assert_eq!(
            context_randomization_seed_drop_count() - seed_drops_before,
            1
        );
        assert_eq!(derivation_call_count(), derivations_before);
        assert_eq!(selected_output_open_attempt_count(), opens_before);
        assert_eq!(validated_owned_input_drop_count(), capability_drops_before);
        assert_eq!(
            selected_output_expectation_drop_count(),
            expectation_drops_before
        );
    }
    drop(selected);
    assert_eq!(
        selected_output_expectation_drop_count() - expectation_drops_before,
        1
    );
}

#[test]
fn selected_output_expectations_clear_on_batch_destruction_and_copy_unwind() {
    let catalog = test_catalog(1);
    let slip77 = synthetic_material(b"wallet-facts selected expectation lifetime material");
    let fixture = confidential_fixture(&catalog, &slip77);
    let expectations = [
        fixture.selected_expectation(0),
        fixture.selected_expectation(1),
    ];
    let requests = borrowed_selected_outputs(&fixture, &expectations);

    let drops_before = selected_output_expectation_drop_count();
    let payload_drops_before = selected_output_payload_drop_count();
    let selected = SelectedOutputBatch::new(&requests).unwrap();
    assert_eq!(selected_output_expectation_drop_count(), drops_before);
    assert_eq!(selected_output_payload_drop_count(), payload_drops_before);
    drop(selected);
    assert_eq!(selected_output_expectation_drop_count() - drops_before, 2);
    assert_eq!(
        selected_output_payload_drop_count() - payload_drops_before,
        4
    );

    let drops_before = selected_output_expectation_drop_count();
    let payload_drops_before = selected_output_payload_drop_count();
    let clones_before = candidate_payload_clone_count();
    set_candidate_payload_clones_before_panic(Some(1));
    let unwind = std::panic::catch_unwind(|| {
        let _ = SelectedOutputBatch::new(&requests[..1]);
    });
    set_candidate_payload_clones_before_panic(None);
    assert!(unwind.is_err());
    assert_eq!(candidate_payload_clone_count() - clones_before, 2);
    assert_eq!(selected_output_expectation_drop_count() - drops_before, 1);
    assert_eq!(
        selected_output_payload_drop_count() - payload_drops_before,
        1
    );

    let drops_before = selected_output_expectation_drop_count();
    let payload_drops_before = selected_output_payload_drop_count();
    let clones_before = candidate_payload_clone_count();
    set_candidate_payload_clones_before_panic(Some(3));
    let unwind = std::panic::catch_unwind(|| {
        let _ = SelectedOutputBatch::new(&requests);
    });
    set_candidate_payload_clones_before_panic(None);
    assert!(unwind.is_err());
    assert_eq!(candidate_payload_clone_count() - clones_before, 4);
    assert_eq!(selected_output_expectation_drop_count() - drops_before, 2);
    assert_eq!(
        selected_output_payload_drop_count() - payload_drops_before,
        3
    );
}

#[test]
fn selected_output_expectations_clear_on_validation_unwind_when_batch_is_consumed() {
    let catalog = test_catalog(1);
    let slip77 = synthetic_material(b"wallet-facts selected consumed unwind material");
    let fixture = confidential_fixture(&catalog, &slip77);
    let expectations = [fixture.selected_expectation(0)];
    let requests = borrowed_selected_outputs(&fixture, &expectations);
    let selected = SelectedOutputBatch::new(&requests).unwrap();
    let drops_before = selected_output_expectation_drop_count();
    let request_index_drops_before = selected_output_request_index_drop_count();

    set_derivation_test_mode(DerivationTestMode::PanicAfterOuter);
    let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut secp = Secp256k1::new();
        let mut rng = SelectedCountingCryptoRng {
            inner: StdRng::from_seed(synthetic_material(
                b"wallet-facts selected consumed unwind randomness",
            )),
            fill_calls: 0,
            filled_bytes: 0,
        };
        let consumed = selected;
        let _ = validate_selected_owned_inputs(
            &catalog,
            &mut SyntheticSelectedOpeningProvider::new(&slip77),
            &consumed,
            &mut secp,
            &mut rng,
        );
    }));
    assert!(unwind.is_err());
    assert_eq!(selected_output_expectation_drop_count() - drops_before, 1);
    assert_eq!(
        selected_output_request_index_drop_count() - request_index_drops_before,
        1
    );
}

#[test]
fn opens_reverse_candidate_input_directly_in_final_outpoint_order() {
    let catalog = test_catalog(1);
    let slip77 = synthetic_material(b"wallet-facts ordered observation material");
    let fixture = confidential_fixture(&catalog, &slip77);
    let mut other_transaction = fixture.transaction.clone();
    other_transaction.lock_time = LockTime::from_consensus(1);
    let other_bytes = serialize(&other_transaction);
    let base_id = fixture.transaction.txid().to_byte_array();
    let other_id = other_transaction.txid().to_byte_array();
    let previous = std::slice::from_ref(&fixture.previous_transaction_bytes);

    let (higher_bytes, higher_id, lower_bytes, lower_id) = if base_id > other_id {
        (&fixture.transaction_bytes, base_id, &other_bytes, other_id)
    } else {
        (&other_bytes, other_id, &fixture.transaction_bytes, base_id)
    };
    let reverse_order = [
        BorrowedCandidateTransaction::new(higher_bytes, previous),
        BorrowedCandidateTransaction::new(lower_bytes, previous),
    ];
    let candidates = CandidateBatch::new(&reverse_order).unwrap();
    let batch = observe_owned_outputs(&catalog, BorrowedSlip77::new(&slip77), &candidates).unwrap();

    let observed_order = batch
        .outputs()
        .iter()
        .map(|output| (*output.transaction_id(), output.output_index()))
        .collect::<Vec<_>>();
    assert_eq!(
        observed_order,
        vec![(lower_id, 0), (lower_id, 1), (higher_id, 0), (higher_id, 1),]
    );
    assert_eq!(
        batch
            .transactions()
            .iter()
            .map(|transaction| *transaction.transaction_id())
            .collect::<Vec<_>>(),
        vec![lower_id, higher_id]
    );
    for observed in batch.transactions() {
        assert_eq!(observed.inputs().len(), 2);
        assert_eq!(
            observed
                .inputs()
                .iter()
                .map(|input| input.previous_output_index())
                .collect::<Vec<_>>(),
            vec![0, 1]
        );
    }
    assert_eq!(
        batch.transactions()[0].inputs()[0].previous_transaction_id(),
        batch.transactions()[1].inputs()[0].previous_transaction_id()
    );
}

#[test]
fn preserves_nonmonotonic_consensus_input_order() {
    let catalog = test_catalog(1);
    let slip77 = synthetic_material(b"wallet-facts nonmonotonic input order material");
    let fixture = confidential_fixture_with_input_order(&catalog, &slip77, [1, 0]);
    let candidates = fixture.candidate_batch();

    let batch = observe_owned_outputs(&catalog, BorrowedSlip77::new(&slip77), &candidates).unwrap();

    assert_eq!(batch.transactions().len(), 1);
    assert_eq!(
        batch.transactions()[0]
            .inputs()
            .iter()
            .map(|input| input.previous_output_index())
            .collect::<Vec<_>>(),
        vec![1, 0]
    );
}

#[test]
fn observes_empty_spend_only_and_mixed_batches_without_assigning_chain_order() {
    struct PanicOnRandomness;

    impl rand::RngCore for PanicOnRandomness {
        fn next_u32(&mut self) -> u32 {
            panic!("a no-owned-output batch must not request randomness")
        }

        fn next_u64(&mut self) -> u64 {
            panic!("a no-owned-output batch must not request randomness")
        }

        fn fill_bytes(&mut self, _: &mut [u8]) {
            panic!("a no-owned-output batch must not request randomness")
        }

        fn try_fill_bytes(&mut self, _: &mut [u8]) -> Result<(), rand::Error> {
            panic!("a no-owned-output batch must not request randomness")
        }
    }

    impl rand::CryptoRng for PanicOnRandomness {}

    let catalog = test_catalog(1);
    let unowned_catalog =
        DescriptorCatalog::derive(MAINNET_PUBLIC_DESCRIPTOR, DescriptorNetwork::Mainnet, 1)
            .unwrap();
    assert_eq!(unowned_catalog.network(), DescriptorNetwork::Mainnet);
    let slip77 = synthetic_material(b"wallet-facts spend-only observation material");
    let fixture = confidential_fixture(&catalog, &slip77);
    let empty_candidates = CandidateBatch::new(&[]).unwrap();
    let derivations_before = derivation_call_count();
    let candidate_decodes_before = candidate_transaction_decode_count();
    let previous_decodes_before = previous_transaction_decode_count();
    let empty = super::observe_owned_outputs(
        &catalog,
        BorrowedSlip77::new(&slip77),
        &empty_candidates,
        &mut PanicOnRandomness,
    )
    .unwrap();
    assert!(empty.is_empty());
    assert!(empty.transactions().is_empty());
    assert!(empty.outputs().is_empty());
    assert_eq!(derivation_call_count(), derivations_before);
    assert_eq!(
        candidate_transaction_decode_count(),
        candidate_decodes_before
    );
    assert_eq!(previous_transaction_decode_count(), previous_decodes_before);

    let spend_only = confidential_fixture(&unowned_catalog, &slip77);
    let spend_derivations_before = derivation_call_count();
    let candidate_decodes_before = candidate_transaction_decode_count();
    let previous_decodes_before = previous_transaction_decode_count();
    let spend_batch = super::observe_owned_outputs(
        &catalog,
        BorrowedSlip77::new(&slip77),
        &spend_only.candidate_batch(),
        &mut PanicOnRandomness,
    )
    .unwrap();
    assert_eq!(
        candidate_transaction_decode_count() - candidate_decodes_before,
        2
    );
    assert_eq!(
        previous_transaction_decode_count() - previous_decodes_before,
        2
    );
    assert_eq!(derivation_call_count(), spend_derivations_before);
    assert_eq!(spend_batch.transactions().len(), 1);
    assert!(spend_batch.outputs().is_empty());
    assert!(!spend_batch.is_empty());
    assert_eq!(
        spend_batch.transactions()[0].transaction_id(),
        &spend_only.transaction.txid().to_byte_array()
    );
    assert_eq!(spend_batch.transactions()[0].inputs().len(), 2);
    let successful_input_drops = observed_transaction_input_drop_count();
    let successful_transaction_drops = observed_wallet_transaction_drop_count();
    drop(spend_batch);
    assert_eq!(
        observed_transaction_input_drop_count() - successful_input_drops,
        2
    );
    assert_eq!(
        observed_wallet_transaction_drop_count() - successful_transaction_drops,
        1
    );

    let mixed_candidates =
        CandidateBatch::new(&[fixture.borrowed(), spend_only.borrowed()]).unwrap();
    let candidate_decodes_before = candidate_transaction_decode_count();
    let previous_decodes_before = previous_transaction_decode_count();
    let mixed =
        observe_owned_outputs(&catalog, BorrowedSlip77::new(&slip77), &mixed_candidates).unwrap();
    assert_eq!(
        candidate_transaction_decode_count() - candidate_decodes_before,
        4
    );
    assert_eq!(
        previous_transaction_decode_count() - previous_decodes_before,
        4
    );
    assert_eq!(mixed.transactions().len(), 2);
    assert_eq!(mixed.transactions.capacity(), mixed.transactions.len());
    assert_eq!(mixed.outputs().len(), 2);
    assert!(!mixed.is_empty());
    assert!(
        mixed
            .transactions()
            .windows(2)
            .all(|pair| pair[0].transaction_id() < pair[1].transaction_id())
    );
}

#[test]
fn rejects_duplicate_inputs_and_same_txid_witness_variants_before_returning_facts() {
    let catalog = test_catalog(1);
    let slip77 = synthetic_material(b"wallet-facts duplicate input material");
    let fixture = confidential_fixture(&catalog, &slip77);
    let fact_drops_before = (
        observed_transaction_input_drop_count(),
        observed_wallet_transaction_drop_count(),
        observed_owned_output_drop_count(),
    );

    let mut duplicate_input = fixture.transaction.clone();
    duplicate_input.input[1] = duplicate_input.input[0].clone();
    let duplicate_input_bytes = serialize(&duplicate_input);
    let duplicate_input_candidates = CandidateBatch::new(&[BorrowedCandidateTransaction::new(
        &duplicate_input_bytes,
        std::slice::from_ref(&fixture.previous_transaction_bytes),
    )])
    .unwrap();
    assert!(matches!(
        observe_owned_outputs(
            &catalog,
            BorrowedSlip77::new(&slip77),
            &duplicate_input_candidates,
        ),
        Err(WalletObservationError::TransactionValidation)
    ));

    let mut witness_variant = fixture.transaction.clone();
    witness_variant.input[0]
        .witness
        .script_witness
        .push([0x01, 0x02, 0x03]);
    let witness_variant_bytes = serialize(&witness_variant);
    assert_eq!(witness_variant.txid(), fixture.transaction.txid());
    assert_ne!(witness_variant_bytes, fixture.transaction_bytes);
    let witness_variants = CandidateBatch::new(&[
        fixture.borrowed(),
        BorrowedCandidateTransaction::new(
            &witness_variant_bytes,
            std::slice::from_ref(&fixture.previous_transaction_bytes),
        ),
    ])
    .unwrap();
    assert!(matches!(
        observe_owned_outputs(&catalog, BorrowedSlip77::new(&slip77), &witness_variants,),
        Err(WalletObservationError::DuplicateTransaction)
    ));
    assert_eq!(
        (
            observed_transaction_input_drop_count(),
            observed_wallet_transaction_drop_count(),
            observed_owned_output_drop_count(),
        ),
        fact_drops_before
    );
}

#[test]
fn unsupported_candidate_shapes_reject_before_returning_facts() {
    let catalog = test_catalog(1);
    let slip77 = synthetic_material(b"wallet-facts unsupported shape material");
    let fixture = confidential_fixture(&catalog, &slip77);
    let facts_before = (
        observed_transaction_input_drop_count(),
        observed_wallet_transaction_drop_count(),
        observed_owned_output_drop_count(),
    );

    let mut empty = fixture.transaction.clone();
    empty.output.clear();
    let mut issuance = fixture.transaction.clone();
    issuance.input[0].asset_issuance.amount = Value::Explicit(1);
    let mut pegin = fixture.transaction.clone();
    pegin.input[0].is_pegin = true;
    let mut invalid_proof = fixture.transaction.clone();
    invalid_proof.output[0].witness.rangeproof = RangeProof::EMPTY;

    for transaction in [empty, issuance, pegin, invalid_proof] {
        let bytes = serialize(&transaction);
        let candidates = CandidateBatch::new(&[BorrowedCandidateTransaction::new(
            &bytes,
            std::slice::from_ref(&fixture.previous_transaction_bytes),
        )])
        .unwrap();
        assert!(matches!(
            observe_owned_outputs(&catalog, BorrowedSlip77::new(&slip77), &candidates,),
            Err(WalletObservationError::TransactionValidation)
        ));
    }

    let mut zero_input = fixture.transaction.clone();
    zero_input.input.clear();
    let zero_input_bytes = serialize(&zero_input);
    let zero_input_candidates =
        CandidateBatch::new(&[BorrowedCandidateTransaction::new(&zero_input_bytes, &[])]).unwrap();
    assert!(matches!(
        observe_owned_outputs(
            &catalog,
            BorrowedSlip77::new(&slip77),
            &zero_input_candidates,
        ),
        Err(WalletObservationError::TransactionValidation)
    ));

    let mut coinbase = fixture.transaction.clone();
    coinbase.input = vec![input(OutPoint::null())];
    let coinbase_bytes = serialize(&coinbase);
    let coinbase_candidates =
        CandidateBatch::new(&[BorrowedCandidateTransaction::new(&coinbase_bytes, &[])]).unwrap();
    assert!(
        observe_owned_outputs(&catalog, BorrowedSlip77::new(&slip77), &coinbase_candidates,)
            .is_err()
    );
    assert_eq!(
        (
            observed_transaction_input_drop_count(),
            observed_wallet_transaction_drop_count(),
            observed_owned_output_drop_count(),
        ),
        facts_before
    );
}

#[test]
fn owned_output_value_guard_requires_only_strict_positivity() {
    assert_eq!(
        require_positive_owned_output_value(&0),
        Err(WalletObservationError::TransactionValidation),
    );
    assert_eq!(require_positive_owned_output_value(&1), Ok(()));
    assert_eq!(require_positive_owned_output_value(&u64::MAX), Ok(()));
}

#[test]
fn wrong_blinding_material_and_explicit_owned_outputs_fail_closed() {
    let catalog = test_catalog(1);
    let slip77 = synthetic_material(b"wallet-facts correct blinding material");
    let wrong = synthetic_material(b"wallet-facts wrong blinding material");
    let fixture = confidential_fixture(&catalog, &slip77);
    let drops_before = scoped_secret_key_drop_count();

    assert!(matches!(
        observe_owned_outputs(
            &catalog,
            BorrowedSlip77::new(&wrong),
            &fixture.candidate_batch(),
        ),
        Err(WalletObservationError::OwnedOutputOpening)
    ));
    assert_eq!(scoped_secret_key_drop_count() - drops_before, 1);

    let explicit = explicit_owned_fixture(&catalog, &fixture);
    assert!(matches!(
        observe_owned_outputs(&catalog, BorrowedSlip77::new(&slip77), &explicit),
        Err(WalletObservationError::ExplicitOwnedOutput)
    ));
}

#[test]
fn late_explicit_owned_output_destroys_earlier_preparation() {
    let catalog = test_catalog(1);
    let slip77 = synthetic_material(b"wallet-facts late explicit output material");
    let fixture = confidential_fixture(&catalog, &slip77);
    let internal = catalog_entry(&catalog, DescriptorBranch::Internal, 1);
    let mut transaction = fixture.transaction.clone();
    transaction.lock_time = LockTime::from_consensus(3);
    transaction.output[2].script_pubkey = Script::from(internal.script_pubkey.clone());
    let transaction_bytes = serialize(&transaction);
    let borrowed = BorrowedCandidateTransaction::new(
        &transaction_bytes,
        std::slice::from_ref(&fixture.previous_transaction_bytes),
    );
    let candidates = CandidateBatch::new(&[borrowed]).unwrap();
    let prepared_drops_before = prepared_candidate_drop_count();

    assert!(matches!(
        observe_owned_outputs(&catalog, BorrowedSlip77::new(&slip77), &candidates),
        Err(WalletObservationError::ExplicitOwnedOutput)
    ));
    assert_eq!(prepared_candidate_drop_count() - prepared_drops_before, 1);
}

#[test]
fn late_owned_output_opening_failure_destroys_earlier_observation() {
    let catalog = test_catalog(1);
    let slip77 = synthetic_material(b"wallet-facts correct blinding material");
    let wrong = synthetic_material(b"wallet-facts wrong second output blinding material");
    let fixture = confidential_fixture_with_second_blinder(&catalog, &slip77, &wrong);
    let candidate = fixture.candidate_batch();
    let key_drops_before = scoped_secret_key_drop_count();
    let output_drops_before = observed_owned_output_drop_count();
    let input_drops_before = observed_transaction_input_drop_count();
    let transaction_drops_before = observed_wallet_transaction_drop_count();
    let prepared_drops_before = prepared_candidate_drop_count();

    assert!(matches!(
        observe_owned_outputs(&catalog, BorrowedSlip77::new(&slip77), &candidate),
        Err(WalletObservationError::OwnedOutputOpening)
    ));
    assert_eq!(scoped_secret_key_drop_count() - key_drops_before, 2);
    assert_eq!(observed_owned_output_drop_count() - output_drops_before, 1);
    assert_eq!(
        observed_transaction_input_drop_count() - input_drops_before,
        2
    );
    assert_eq!(
        observed_wallet_transaction_drop_count() - transaction_drops_before,
        1
    );
    assert_eq!(prepared_candidate_drop_count() - prepared_drops_before, 1);
}

#[test]
fn later_candidate_opening_failure_destroys_all_earlier_facts() {
    let catalog = test_catalog(1);
    let slip77 = synthetic_material(b"wallet-facts valid earlier candidate material");
    let wrong = synthetic_material(b"wallet-facts invalid later candidate material");
    let valid = confidential_fixture(&catalog, &slip77);
    let mut invalid = confidential_fixture_with_second_blinder(&catalog, &slip77, &wrong);
    for lock_time in 1..=u32::MAX {
        invalid.transaction.lock_time = LockTime::from_consensus(lock_time);
        if invalid.transaction.txid().to_byte_array() > valid.transaction.txid().to_byte_array() {
            break;
        }
    }
    assert!(invalid.transaction.txid().to_byte_array() > valid.transaction.txid().to_byte_array());
    invalid.transaction_bytes = serialize(&invalid.transaction);
    let candidates = CandidateBatch::new(&[invalid.borrowed(), valid.borrowed()]).unwrap();
    let key_drops_before = scoped_secret_key_drop_count();
    let output_drops_before = observed_owned_output_drop_count();
    let input_drops_before = observed_transaction_input_drop_count();
    let transaction_drops_before = observed_wallet_transaction_drop_count();

    assert!(matches!(
        observe_owned_outputs(&catalog, BorrowedSlip77::new(&slip77), &candidates),
        Err(WalletObservationError::OwnedOutputOpening)
    ));
    assert_eq!(scoped_secret_key_drop_count() - key_drops_before, 4);
    assert_eq!(observed_owned_output_drop_count() - output_drops_before, 3);
    assert_eq!(
        observed_transaction_input_drop_count() - input_drops_before,
        4
    );
    assert_eq!(
        observed_wallet_transaction_drop_count() - transaction_drops_before,
        2
    );
}

#[test]
fn blinding_key_derivation_erases_state_on_success_error_and_unwind() {
    fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
    assert_zeroize_on_drop::<Sha256>();

    let catalog = test_catalog(0);
    let entry = catalog_entry(&catalog, DescriptorBranch::External, 0);
    let slip77 = synthetic_material(b"wallet-facts derivation erasure material");

    let buffers_before = derivation_secret_buffer_drop_count();
    let key = derive_blinding_key(&slip77, &entry.script_pubkey).unwrap();
    assert_eq!(derivation_secret_buffer_drop_count() - buffers_before, 4);
    drop(key);

    let buffers_before = derivation_secret_buffer_drop_count();
    set_derivation_test_mode(DerivationTestMode::InvalidScalar);
    assert!(matches!(
        derive_blinding_key(&slip77, &entry.script_pubkey),
        Err(WalletObservationError::OwnedOutputOpening)
    ));
    assert_eq!(derivation_secret_buffer_drop_count() - buffers_before, 4);

    let buffers_before = derivation_secret_buffer_drop_count();
    set_derivation_test_mode(DerivationTestMode::PanicAfterOuter);
    let unwind = std::panic::catch_unwind(|| {
        let _ = derive_blinding_key(&slip77, &entry.script_pubkey);
    });
    assert!(unwind.is_err());
    assert_eq!(derivation_secret_buffer_drop_count() - buffers_before, 4);

    let catalog = test_catalog(1);
    let fixture = confidential_fixture(&catalog, &slip77);
    let input_drops_before = observed_transaction_input_drop_count();
    let transaction_drops_before = observed_wallet_transaction_drop_count();
    set_derivation_test_mode(DerivationTestMode::PanicAfterOuter);
    let unwind = std::panic::catch_unwind(|| {
        let _ = observe_owned_outputs(
            &catalog,
            BorrowedSlip77::new(&slip77),
            &fixture.candidate_batch(),
        );
    });
    assert!(unwind.is_err());
    assert_eq!(
        observed_transaction_input_drop_count() - input_drops_before,
        2
    );
    assert_eq!(
        observed_wallet_transaction_drop_count() - transaction_drops_before,
        1
    );
}

#[test]
fn context_randomization_consumes_and_erases_one_seed() {
    struct CountingCryptoRng {
        inner: StdRng,
        fill_calls: usize,
        filled_bytes: usize,
    }

    impl rand::RngCore for CountingCryptoRng {
        fn next_u32(&mut self) -> u32 {
            self.inner.next_u32()
        }

        fn next_u64(&mut self) -> u64 {
            self.inner.next_u64()
        }

        fn fill_bytes(&mut self, destination: &mut [u8]) {
            self.fill_calls += 1;
            self.filled_bytes += destination.len();
            self.inner.fill_bytes(destination);
        }

        fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), rand::Error> {
            self.fill_calls += 1;
            self.filled_bytes += destination.len();
            self.inner.try_fill_bytes(destination)
        }
    }

    impl rand::CryptoRng for CountingCryptoRng {}

    struct PanickingCryptoRng;

    impl rand::RngCore for PanickingCryptoRng {
        fn next_u32(&mut self) -> u32 {
            unreachable!("observation requests bytes directly")
        }

        fn next_u64(&mut self) -> u64 {
            unreachable!("observation requests bytes directly")
        }

        fn fill_bytes(&mut self, destination: &mut [u8]) {
            destination.fill(42);
            panic!("test-only random source unwind");
        }

        fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), rand::Error> {
            self.fill_bytes(destination);
            unreachable!("fill_bytes always unwinds")
        }
    }

    impl rand::CryptoRng for PanickingCryptoRng {}

    struct FailingCryptoRng;

    impl rand::RngCore for FailingCryptoRng {
        fn next_u32(&mut self) -> u32 {
            unreachable!("observation requests bytes directly")
        }

        fn next_u64(&mut self) -> u64 {
            unreachable!("observation requests bytes directly")
        }

        fn fill_bytes(&mut self, _: &mut [u8]) {
            unreachable!("observation must use the fallible random-source API")
        }

        fn try_fill_bytes(&mut self, _: &mut [u8]) -> Result<(), rand::Error> {
            let code = std::num::NonZeroU32::new(rand::Error::CUSTOM_START).unwrap();
            Err(rand::Error::from(code))
        }
    }

    impl rand::CryptoRng for FailingCryptoRng {}

    let catalog = test_catalog(1);
    let slip77 = synthetic_material(b"wallet-facts correct blinding material");
    let fixture = confidential_fixture(&catalog, &slip77);
    let candidate = fixture.candidate_batch();
    let mut counting_rng = CountingCryptoRng {
        inner: StdRng::from_seed(synthetic_material(
            b"wallet-facts context randomization test",
        )),
        fill_calls: 0,
        filled_bytes: 0,
    };

    let drops_before = context_randomization_seed_drop_count();
    assert!(
        super::observe_owned_outputs(
            &catalog,
            BorrowedSlip77::new(&slip77),
            &candidate,
            &mut counting_rng,
        )
        .is_ok()
    );
    assert_eq!(counting_rng.fill_calls, 1);
    assert_eq!(counting_rng.filled_bytes, 32);
    assert_eq!(context_randomization_seed_drop_count() - drops_before, 1);

    let drops_before = context_randomization_seed_drop_count();
    let fact_drops_before = (
        observed_transaction_input_drop_count(),
        observed_wallet_transaction_drop_count(),
        observed_owned_output_drop_count(),
    );
    assert!(matches!(
        super::observe_owned_outputs(
            &catalog,
            BorrowedSlip77::new(&slip77),
            &candidate,
            &mut FailingCryptoRng,
        ),
        Err(WalletObservationError::ContextRandomnessUnavailable)
    ));
    assert_eq!(context_randomization_seed_drop_count() - drops_before, 1);
    assert_eq!(
        (
            observed_transaction_input_drop_count(),
            observed_wallet_transaction_drop_count(),
            observed_owned_output_drop_count(),
        ),
        fact_drops_before
    );

    let drops_before = context_randomization_seed_drop_count();
    let fact_drops_before = (
        observed_transaction_input_drop_count(),
        observed_wallet_transaction_drop_count(),
        observed_owned_output_drop_count(),
    );
    let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = super::observe_owned_outputs(
            &catalog,
            BorrowedSlip77::new(&slip77),
            &candidate,
            &mut PanickingCryptoRng,
        );
    }));
    assert!(unwind.is_err());
    assert_eq!(context_randomization_seed_drop_count() - drops_before, 1);
    assert_eq!(
        (
            observed_transaction_input_drop_count(),
            observed_wallet_transaction_drop_count(),
            observed_owned_output_drop_count(),
        ),
        fact_drops_before
    );
}

#[test]
fn proof_failure_rejects_the_entire_candidate_batch() {
    let catalog = test_catalog(1);
    let slip77 = synthetic_material(b"wallet-facts correct blinding material");
    let fixture = confidential_fixture(&catalog, &slip77);
    let mut damaged = fixture.transaction.clone();
    damaged.output[0].witness.rangeproof = RangeProof::EMPTY;
    damaged.lock_time = LockTime::from_consensus(1);
    let damaged_bytes = serialize(&damaged);
    let damaged_borrowed = BorrowedCandidateTransaction::new(
        &damaged_bytes,
        std::slice::from_ref(&fixture.previous_transaction_bytes),
    );
    let candidates = CandidateBatch::new(&[fixture.borrowed(), damaged_borrowed]).unwrap();

    let derivations_before = derivation_call_count();
    let prepared_drops_before = prepared_candidate_drop_count();
    let fact_drops_before = (
        observed_transaction_input_drop_count(),
        observed_wallet_transaction_drop_count(),
        observed_owned_output_drop_count(),
    );
    assert!(matches!(
        observe_owned_outputs(&catalog, BorrowedSlip77::new(&slip77), &candidates,),
        Err(WalletObservationError::TransactionValidation)
    ));
    assert_eq!(derivation_call_count(), derivations_before);
    assert_eq!(prepared_candidate_drop_count() - prepared_drops_before, 1);
    assert_eq!(
        (
            observed_transaction_input_drop_count(),
            observed_wallet_transaction_drop_count(),
            observed_owned_output_drop_count(),
        ),
        fact_drops_before
    );

    let mut mismatched_proof = fixture.transaction.clone();
    mismatched_proof.output[0].witness.rangeproof =
        mismatched_proof.output[1].witness.rangeproof.clone();
    let mismatched_proof_bytes = serialize(&mismatched_proof);
    let mismatched_proof = CandidateBatch::new(&[BorrowedCandidateTransaction::new(
        &mismatched_proof_bytes,
        std::slice::from_ref(&fixture.previous_transaction_bytes),
    )])
    .unwrap();
    assert!(matches!(
        observe_owned_outputs(&catalog, BorrowedSlip77::new(&slip77), &mismatched_proof,),
        Err(WalletObservationError::TransactionValidation)
    ));
}

#[test]
fn confidential_actual_zero_rejects_after_independent_proof_checks_without_facts() {
    struct NoRandomnessExpected;

    impl rand::RngCore for NoRandomnessExpected {
        fn next_u32(&mut self) -> u32 {
            unreachable!("first-pass validation failure must precede randomness")
        }

        fn next_u64(&mut self) -> u64 {
            unreachable!("first-pass validation failure must precede randomness")
        }

        fn fill_bytes(&mut self, _: &mut [u8]) {
            unreachable!("first-pass validation failure must precede randomness")
        }

        fn try_fill_bytes(&mut self, _: &mut [u8]) -> Result<(), rand::Error> {
            unreachable!("first-pass validation failure must precede randomness")
        }
    }

    impl rand::CryptoRng for NoRandomnessExpected {}

    let catalog = test_catalog(1);
    let slip77 = synthetic_material(b"wallet-facts confidential zero material");
    let valid = confidential_fixture(&catalog, &slip77);
    let zero = confidential_actual_zero_fixture(&catalog, &slip77);
    let previous: Transaction = deserialize(&zero.previous_transaction_bytes).unwrap();
    let zero_output = &zero.transaction.output[0];
    let secp = Secp256k1::new();
    let entry = catalog_entry(&catalog, DescriptorBranch::External, 0);
    let blinding_key = derived_blinding_key(entry, &slip77);
    assert_eq!(zero_output.script_pubkey.as_bytes(), &entry.script_pubkey);
    assert!(zero_output.script_pubkey.is_v0_p2wpkh());
    assert!(zero_output.asset.is_confidential());
    assert!(zero_output.value.is_confidential());
    assert!(zero_output.nonce.is_confidential());
    let opened = zero_output
        .unblind_with_key(&secp, &blinding_key.0)
        .unwrap();
    assert_eq!(opened.value, 0);

    let asset_generator = zero_output.asset.into_asset_gen(&secp).unwrap();
    let public_range = zero_output
        .witness
        .rangeproof
        .as_ref()
        .unwrap()
        .verify_inclusive(
            &secp,
            zero_output.value.commitment().unwrap(),
            zero_output.script_pubkey.as_bytes(),
            asset_generator,
        )
        .unwrap();
    assert_eq!(*public_range.start(), 0);
    assert!(public_range.contains(&0));

    let surjection_domain = previous
        .output
        .iter()
        .map(|output| output.asset.into_asset_gen(&secp).unwrap())
        .collect::<Vec<_>>();
    assert!(
        zero_output
            .witness
            .surjection_proof
            .as_ref()
            .unwrap()
            .verify(&secp, asset_generator, &surjection_domain,)
    );
    let balancing_output = &zero.transaction.output[1];
    let balancing_asset_generator = balancing_output.asset.into_asset_gen(&secp).unwrap();
    let balancing_range = balancing_output
        .witness
        .rangeproof
        .as_ref()
        .unwrap()
        .verify_inclusive(
            &secp,
            balancing_output.value.commitment().unwrap(),
            balancing_output.script_pubkey.as_bytes(),
            balancing_asset_generator,
        )
        .unwrap();
    assert_eq!(*balancing_range.start(), 1);
    assert!(balancing_range.contains(&900));
    assert!(
        balancing_output
            .witness
            .surjection_proof
            .as_ref()
            .unwrap()
            .verify(&secp, balancing_asset_generator, &surjection_domain,)
    );

    let input_commitments = previous
        .output
        .iter()
        .map(|output| output_value_commitment(&secp, output))
        .collect::<Vec<_>>();
    let output_commitments = zero
        .transaction
        .output
        .iter()
        .map(|output| output_value_commitment(&secp, output))
        .collect::<Vec<_>>();
    assert!(verify_commitments_sum_to_equal(
        &secp,
        &input_commitments,
        &output_commitments,
    ));
    assert_eq!(
        zero.transaction
            .verify_tx_amt_proofs(&secp, &previous.output),
        Err(VerificationError::TxOutError(
            0,
            TxOutError::NonUnspendableZeroValue,
        )),
    );

    let candidates = CandidateBatch::new(&[valid.borrowed(), zero.borrowed()]).unwrap();
    let derivations_before = derivation_call_count();
    let prepared_drops_before = prepared_candidate_drop_count();
    let randomization_drops_before = context_randomization_seed_drop_count();
    let fact_drops_before = (
        observed_transaction_input_drop_count(),
        observed_wallet_transaction_drop_count(),
        observed_owned_output_drop_count(),
    );
    let mut rng = NoRandomnessExpected;
    assert!(matches!(
        super::observe_owned_outputs(
            &catalog,
            BorrowedSlip77::new(&slip77),
            &candidates,
            &mut rng,
        ),
        Err(WalletObservationError::TransactionValidation)
    ));
    assert_eq!(derivation_call_count(), derivations_before);
    assert_eq!(prepared_candidate_drop_count() - prepared_drops_before, 1);
    assert_eq!(
        context_randomization_seed_drop_count(),
        randomization_drops_before,
    );
    assert_eq!(
        (
            observed_transaction_input_drop_count(),
            observed_wallet_transaction_drop_count(),
            observed_owned_output_drop_count(),
        ),
        fact_drops_before,
    );
}

#[test]
fn previous_transaction_sets_and_duplicate_candidates_are_exact() {
    let catalog = test_catalog(1);
    let slip77 = synthetic_material(b"wallet-facts correct blinding material");
    let fixture = confidential_fixture(&catalog, &slip77);

    let missing = CandidateBatch::new(&[BorrowedCandidateTransaction::new(
        &fixture.transaction_bytes,
        &[],
    )])
    .unwrap();
    assert!(matches!(
        observe_owned_outputs(&catalog, BorrowedSlip77::new(&slip77), &missing),
        Err(WalletObservationError::PreviousTransactionSet)
    ));

    let duplicated_previous_bytes = [
        fixture.previous_transaction_bytes.clone(),
        fixture.previous_transaction_bytes.clone(),
    ];
    let duplicated_previous = CandidateBatch::new(&[BorrowedCandidateTransaction::new(
        &fixture.transaction_bytes,
        &duplicated_previous_bytes,
    )])
    .unwrap();
    assert!(matches!(
        observe_owned_outputs(&catalog, BorrowedSlip77::new(&slip77), &duplicated_previous,),
        Err(WalletObservationError::PreviousTransactionSet)
    ));

    let unrelated_previous = Transaction {
        version: 2,
        lock_time: LockTime::from_consensus(3),
        input: vec![],
        output: vec![explicit_output(
            fixture.first_asset,
            1,
            Script::from(vec![0x51]),
        )],
    };
    let extra_previous_bytes = [
        fixture.previous_transaction_bytes.clone(),
        serialize(&unrelated_previous),
    ];
    let extra_previous = CandidateBatch::new(&[BorrowedCandidateTransaction::new(
        &fixture.transaction_bytes,
        &extra_previous_bytes,
    )])
    .unwrap();
    assert!(matches!(
        observe_owned_outputs(&catalog, BorrowedSlip77::new(&slip77), &extra_previous,),
        Err(WalletObservationError::PreviousTransactionSet)
    ));

    let duplicated_candidates =
        CandidateBatch::new(&[fixture.borrowed(), fixture.borrowed()]).unwrap();
    assert!(matches!(
        observe_owned_outputs(
            &catalog,
            BorrowedSlip77::new(&slip77),
            &duplicated_candidates,
        ),
        Err(WalletObservationError::DuplicateTransaction)
    ));
}

#[test]
fn malformed_and_bounded_inputs_return_redacted_errors() {
    assert_eq!(checked_total_input_count(7, 9).unwrap(), 16);
    assert!(matches!(
        checked_total_input_count(usize::MAX, 1),
        Err(WalletObservationError::BatchLimit)
    ));
    assert!(matches!(
        CandidateBatch::new(&[BorrowedCandidateTransaction::new(&[], &[])]),
        Err(WalletObservationError::TransactionLength)
    ));
    let oversized_transaction = vec![0; MAX_TRANSACTION_BYTES + 1];
    assert!(matches!(
        CandidateBatch::new(&[BorrowedCandidateTransaction::new(
            &oversized_transaction,
            &[],
        )]),
        Err(WalletObservationError::TransactionLength)
    ));
    let malformed_bytes = [1, 2, 3];
    let malformed =
        CandidateBatch::new(&[BorrowedCandidateTransaction::new(&malformed_bytes, &[])]).unwrap();
    let catalog = test_catalog(0);
    let slip77 = synthetic_material(b"wallet-facts correct blinding material");
    assert!(matches!(
        observe_owned_outputs(&catalog, BorrowedSlip77::new(&slip77), &malformed,),
        Err(WalletObservationError::InvalidTransactionEncoding)
    ));
    assert_eq!(
        WalletObservationError::OwnedOutputOpening.to_string(),
        "wallet observation owned output opening failed"
    );
    assert!(
        !WalletObservationError::OwnedOutputOpening
            .to_string()
            .contains("blinding")
    );
    for error in [
        WalletObservationError::SelectedOutputIndex,
        WalletObservationError::DuplicateSelectedOutpoint,
        WalletObservationError::SelectedOutputExpectation,
        WalletObservationError::SelectedOutputNotOwned,
    ] {
        assert!(std::error::Error::source(&error).is_none());
        let text = format!("{error} {error:?}").to_lowercase();
        for forbidden in [
            "txid=",
            "outpoint=",
            "vout=",
            "script=",
            "asset=",
            "value=",
            "amount=",
            "transaction=",
            "proof=",
            "key=",
            "address=",
            &"ab".repeat(32),
        ] {
            assert!(!text.contains(forbidden));
        }
    }

    let one_byte = [1];
    let oversized_count = (0..=MAX_CANDIDATE_TRANSACTIONS)
        .map(|_| BorrowedCandidateTransaction::new(&one_byte, &[]))
        .collect::<Vec<_>>();
    let clones_before = candidate_payload_clone_count();
    assert!(matches!(
        CandidateBatch::new(&oversized_count),
        Err(WalletObservationError::BatchLimit)
    ));
    assert_eq!(candidate_payload_clone_count(), clones_before);

    let maximum_candidate = vec![0; MAX_TRANSACTION_BYTES];
    let oversized_aggregate = (0..=(MAX_BATCH_BYTES / MAX_TRANSACTION_BYTES))
        .map(|_| BorrowedCandidateTransaction::new(&maximum_candidate, &[]))
        .collect::<Vec<_>>();
    assert!(matches!(
        CandidateBatch::new(&oversized_aggregate),
        Err(WalletObservationError::BatchLimit)
    ));
    assert_eq!(candidate_payload_clone_count(), clones_before);

    let too_many_previous = (0..=MAX_PREVIOUS_TRANSACTIONS_PER_BATCH)
        .map(|_| vec![1])
        .collect::<Vec<_>>();
    assert!(matches!(
        CandidateBatch::new(&[BorrowedCandidateTransaction::new(
            &one_byte,
            &too_many_previous,
        )]),
        Err(WalletObservationError::PreviousTransactionSet)
    ));
    assert_eq!(candidate_payload_clone_count(), clones_before);

    let exact_candidate_count = (0..MAX_CANDIDATE_TRANSACTIONS)
        .map(|_| BorrowedCandidateTransaction::new(&one_byte, &[]))
        .collect::<Vec<_>>();
    let clones_before_exact = candidate_payload_clone_count();
    let exact_candidate_batch = CandidateBatch::new(&exact_candidate_count).unwrap();
    assert_eq!(
        candidate_payload_clone_count() - clones_before_exact,
        MAX_CANDIDATE_TRANSACTIONS
    );
    drop(exact_candidate_batch);

    let exact_transaction = vec![0; MAX_TRANSACTION_BYTES];
    let clones_before_exact = candidate_payload_clone_count();
    let exact_transaction_batch =
        CandidateBatch::new(&[BorrowedCandidateTransaction::new(&exact_transaction, &[])]).unwrap();
    assert_eq!(candidate_payload_clone_count() - clones_before_exact, 1);
    drop(exact_transaction_batch);

    let exact_aggregate_payloads = (0..(MAX_BATCH_BYTES / MAX_TRANSACTION_BYTES))
        .map(|_| vec![0; MAX_TRANSACTION_BYTES])
        .collect::<Vec<_>>();
    let exact_aggregate_candidates = exact_aggregate_payloads
        .iter()
        .map(|payload| BorrowedCandidateTransaction::new(payload, &[]))
        .collect::<Vec<_>>();
    let clones_before_exact = candidate_payload_clone_count();
    let exact_aggregate_batch = CandidateBatch::new(&exact_aggregate_candidates).unwrap();
    assert_eq!(
        candidate_payload_clone_count() - clones_before_exact,
        MAX_BATCH_BYTES / MAX_TRANSACTION_BYTES
    );
    drop(exact_aggregate_batch);

    let exact_previous_count = (0..MAX_PREVIOUS_TRANSACTIONS_PER_BATCH)
        .map(|_| vec![1])
        .collect::<Vec<_>>();
    let clones_before_exact = candidate_payload_clone_count();
    let exact_previous_batch = CandidateBatch::new(&[BorrowedCandidateTransaction::new(
        &one_byte,
        &exact_previous_count,
    )])
    .unwrap();
    assert_eq!(
        candidate_payload_clone_count() - clones_before_exact,
        MAX_PREVIOUS_TRANSACTIONS_PER_BATCH + 1
    );
    drop(exact_previous_batch);
}

struct ConfidentialFixture {
    transaction: Transaction,
    transaction_bytes: Vec<u8>,
    previous_transaction_bytes: Vec<u8>,
    first_asset: AssetId,
    second_asset: AssetId,
}

struct SelectedExpectation {
    outpoint: OutPoint,
    asset: AssetId,
    value: u64,
}

impl ConfidentialFixture {
    fn borrowed(&self) -> BorrowedCandidateTransaction<'_> {
        BorrowedCandidateTransaction::new(
            &self.transaction_bytes,
            std::slice::from_ref(&self.previous_transaction_bytes),
        )
    }

    fn candidate_batch(&self) -> CandidateBatch {
        CandidateBatch::new(&[self.borrowed()]).unwrap()
    }

    fn selected_expectation(&self, output_index: u32) -> SelectedExpectation {
        let (asset, value) = match output_index {
            0 => (self.first_asset, 900),
            1 => (self.second_asset, 2_000),
            2 => (self.first_asset, 100),
            _ => (self.first_asset, 1),
        };
        SelectedExpectation {
            outpoint: OutPoint::new(self.transaction.txid(), output_index),
            asset,
            value,
        }
    }
}

fn borrowed_selected_outputs<'fixture>(
    fixture: &'fixture ConfidentialFixture,
    expectations: &'fixture [SelectedExpectation],
) -> Vec<BorrowedSelectedOutput<'fixture>> {
    let previous = std::slice::from_ref(&fixture.previous_transaction_bytes);
    expectations
        .iter()
        .map(|expectation| {
            BorrowedSelectedOutput::new(
                &expectation.outpoint,
                &expectation.asset,
                &expectation.value,
                &fixture.transaction_bytes,
                previous,
            )
        })
        .collect()
}

fn assert_selected_preflight_rejects(
    fixture: &ConfidentialFixture,
    expectation: &SelectedExpectation,
) {
    let request = [BorrowedSelectedOutput::new(
        &expectation.outpoint,
        &expectation.asset,
        &expectation.value,
        &fixture.transaction_bytes,
        std::slice::from_ref(&fixture.previous_transaction_bytes),
    )];
    let clones_before = candidate_payload_clone_count();
    let candidate_decodes_before = candidate_transaction_decode_count();
    let expectation_drops_before = selected_output_expectation_drop_count();
    assert!(matches!(
        SelectedOutputBatch::new(&request),
        Err(WalletObservationError::SelectedOutputExpectation)
    ));
    assert_eq!(candidate_payload_clone_count(), clones_before);
    assert_eq!(
        candidate_transaction_decode_count(),
        candidate_decodes_before
    );
    assert_eq!(
        selected_output_expectation_drop_count(),
        expectation_drops_before
    );
}

struct ConfidentialActualZeroFixture {
    transaction: Transaction,
    transaction_bytes: Vec<u8>,
    previous_transaction_bytes: Vec<u8>,
}

impl ConfidentialActualZeroFixture {
    fn borrowed(&self) -> BorrowedCandidateTransaction<'_> {
        BorrowedCandidateTransaction::new(
            &self.transaction_bytes,
            std::slice::from_ref(&self.previous_transaction_bytes),
        )
    }
}

fn test_catalog(last_index: u32) -> DescriptorCatalog {
    DescriptorCatalog::derive(TEST_PUBLIC_DESCRIPTOR, DescriptorNetwork::Test, last_index).unwrap()
}

fn observe_owned_outputs(
    catalog: &DescriptorCatalog,
    slip77_master_key: BorrowedSlip77<'_>,
    candidates: &CandidateBatch,
) -> Result<ObservedWalletBatch, WalletObservationError> {
    let mut rng = StdRng::from_seed(synthetic_material(
        b"wallet-facts observation context randomness",
    ));
    super::observe_owned_outputs(catalog, slip77_master_key, candidates, &mut rng)
}

fn synthetic_material(label: &[u8]) -> [u8; 32] {
    sha256::Hash::hash(label).to_byte_array()
}

fn confidential_fixture(catalog: &DescriptorCatalog, slip77: &[u8; 32]) -> ConfidentialFixture {
    confidential_fixture_with_second_blinder_and_input_order(catalog, slip77, slip77, [0, 1])
}

fn confidential_fixture_with_input_order(
    catalog: &DescriptorCatalog,
    slip77: &[u8; 32],
    input_order: [u32; 2],
) -> ConfidentialFixture {
    confidential_fixture_with_second_blinder_and_input_order(catalog, slip77, slip77, input_order)
}

fn confidential_fixture_with_second_blinder(
    catalog: &DescriptorCatalog,
    slip77: &[u8; 32],
    second_output_slip77: &[u8; 32],
) -> ConfidentialFixture {
    confidential_fixture_with_second_blinder_and_input_order(
        catalog,
        slip77,
        second_output_slip77,
        [0, 1],
    )
}

fn confidential_fixture_with_second_blinder_and_input_order(
    catalog: &DescriptorCatalog,
    slip77: &[u8; 32],
    second_output_slip77: &[u8; 32],
    input_order: [u32; 2],
) -> ConfidentialFixture {
    let first_asset = AssetId::from_byte_array(std::array::from_fn(|index| index as u8));
    let second_asset = AssetId::from_byte_array(std::array::from_fn(|index| 0x80_u8 + index as u8));
    let previous = Transaction {
        version: 2,
        lock_time: LockTime::ZERO,
        input: vec![],
        output: vec![
            explicit_output(first_asset, 1_000, Script::from(vec![0x51])),
            explicit_output(second_asset, 2_000, Script::from(vec![0x51])),
        ],
    };
    let previous_txid = previous.txid();
    let spent_secrets = input_order.map(|output_index| match output_index {
        0 => TxOutSecrets::new(
            first_asset,
            AssetBlindingFactor::zero(),
            1_000,
            ValueBlindingFactor::zero(),
        ),
        1 => TxOutSecrets::new(
            second_asset,
            AssetBlindingFactor::zero(),
            2_000,
            ValueBlindingFactor::zero(),
        ),
        _ => unreachable!("test input order must reference the two fixture outputs"),
    });
    let external = catalog_entry(catalog, DescriptorBranch::External, 0);
    let internal = catalog_entry(catalog, DescriptorBranch::Internal, 1);
    let secp = Secp256k1::new();
    let external_blinder = derived_blinding_key(external, slip77);
    let internal_blinder = derived_blinding_key(internal, second_output_slip77);
    let external_address = Address::from_script(
        &Script::from(external.script_pubkey.clone()),
        Some(external_blinder.0.public_key(&secp)),
        &AddressParams::ELEMENTS,
    )
    .unwrap();
    let mut rng = StdRng::from_seed(synthetic_material(
        b"wallet-facts public fixture randomness",
    ));
    let (first_output, first_abf, first_vbf, _) = TxOut::new_not_last_confidential(
        &mut rng,
        &secp,
        900,
        &external_address,
        first_asset,
        &spent_secrets,
    )
    .unwrap();
    let first_output_secrets = TxOutSecrets::new(first_asset, first_abf, 900, first_vbf);
    let fee_secrets = TxOutSecrets::new(
        first_asset,
        AssetBlindingFactor::zero(),
        100,
        ValueBlindingFactor::zero(),
    );
    let (second_output, _, _, _) = TxOut::new_last_confidential(
        &mut rng,
        &secp,
        2_000,
        second_asset,
        Script::from(internal.script_pubkey.clone()),
        internal_blinder.0.public_key(&secp),
        &spent_secrets,
        &[&first_output_secrets, &fee_secrets],
    )
    .unwrap();
    let transaction = Transaction {
        version: 2,
        lock_time: LockTime::ZERO,
        input: input_order
            .map(|output_index| input(OutPoint::new(previous_txid, output_index)))
            .to_vec(),
        output: vec![
            first_output,
            second_output,
            TxOut::new_fee(100, first_asset),
        ],
    };

    ConfidentialFixture {
        transaction_bytes: serialize(&transaction),
        previous_transaction_bytes: serialize(&previous),
        transaction,
        first_asset,
        second_asset,
    }
}

fn confidential_actual_zero_fixture(
    catalog: &DescriptorCatalog,
    slip77: &[u8; 32],
) -> ConfidentialActualZeroFixture {
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
    let entry = catalog_entry(catalog, DescriptorBranch::External, 0);
    let owned_blinding_key = derived_blinding_key(entry, slip77);
    let mut rng = StdRng::from_seed(synthetic_material(
        b"wallet-facts confidential actual zero fixture randomness",
    ));
    let zero_abf = AssetBlindingFactor::new(&mut rng);
    let zero_vbf = ValueBlindingFactor::new(&mut rng);
    let zero_secrets = TxOutSecrets::new(asset, zero_abf, 0, zero_vbf);
    let fee_secrets = TxOutSecrets::new(
        asset,
        AssetBlindingFactor::zero(),
        100,
        ValueBlindingFactor::zero(),
    );
    let balancing_abf = AssetBlindingFactor::new(&mut rng);
    let balancing_vbf = ValueBlindingFactor::last(
        &secp,
        900,
        balancing_abf,
        &[spent_secrets[0].value_blind_inputs()],
        &[
            zero_secrets.value_blind_inputs(),
            fee_secrets.value_blind_inputs(),
        ],
    );
    let balancing_secrets = TxOutSecrets::new(asset, balancing_abf, 900, balancing_vbf);
    let zero_output = confidential_output_with_range_minimum(
        &mut rng,
        &secp,
        Script::from(entry.script_pubkey.clone()),
        owned_blinding_key.0.public_key(&secp),
        zero_secrets,
        &spent_secrets,
        0,
    );
    let balancing_receiver = SecretKey::new(&mut rng);
    let balancing_output = confidential_output_with_range_minimum(
        &mut rng,
        &secp,
        Script::from(vec![0x51]),
        balancing_receiver.public_key(&secp),
        balancing_secrets,
        &spent_secrets,
        1,
    );
    let transaction = Transaction {
        version: 2,
        lock_time: LockTime::from_consensus(7),
        input: vec![input(OutPoint::new(previous.txid(), 0))],
        output: vec![zero_output, balancing_output, TxOut::new_fee(100, asset)],
    };

    ConfidentialActualZeroFixture {
        transaction_bytes: serialize(&transaction),
        previous_transaction_bytes: serialize(&previous),
        transaction,
    }
}

#[allow(clippy::too_many_arguments)]
fn confidential_output_with_range_minimum(
    rng: &mut StdRng,
    secp: &Secp256k1<elements::secp256k1_zkp::All>,
    script_pubkey: Script,
    receiver_blinding_public_key: elements::secp256k1_zkp::PublicKey,
    secrets: TxOutSecrets,
    spent_secrets: &[TxOutSecrets],
    range_minimum: u64,
) -> TxOut {
    let (asset, surjection_proof) = Asset::Explicit(secrets.asset)
        .blind(rng, secp, secrets.asset_bf, spent_secrets)
        .unwrap();
    let message = RangeProofMessage::new(secrets.asset, secrets.asset_bf);
    let asset_generator = message.commitment(secp);
    let value = Value::new_confidential(secp, secrets.value, asset_generator, secrets.value_bf);
    let value_commitment = value.commitment().unwrap();
    let (nonce, shared_secret) = Nonce::new_confidential(rng, secp, &receiver_blinding_public_key);
    let rangeproof = RangeProof::new(
        secp,
        range_minimum,
        value_commitment,
        secrets.value,
        secrets.value_bf.into_inner(),
        &message.to_byte_array(),
        script_pubkey.as_bytes(),
        shared_secret,
        0,
        52,
        asset_generator,
    )
    .unwrap();

    TxOut {
        asset,
        value,
        nonce,
        script_pubkey,
        witness: TxOutWitness {
            surjection_proof,
            rangeproof,
        },
    }
}

fn output_value_commitment(
    secp: &Secp256k1<elements::secp256k1_zkp::All>,
    output: &TxOut,
) -> PedersenCommitment {
    match output.value {
        Value::Explicit(value) => PedersenCommitment::new_unblinded(
            secp,
            value,
            output.asset.into_asset_gen(secp).unwrap(),
        ),
        Value::Confidential(commitment) => commitment,
        Value::Null => unreachable!("the fixture has no null output values"),
    }
}

fn explicit_owned_fixture(
    catalog: &DescriptorCatalog,
    fixture: &ConfidentialFixture,
) -> CandidateBatch {
    let owned = catalog_entry(catalog, DescriptorBranch::External, 0);
    let previous: Transaction = deserialize(&fixture.previous_transaction_bytes).unwrap();
    let transaction = Transaction {
        version: 2,
        lock_time: LockTime::from_consensus(2),
        input: vec![input(OutPoint::new(previous.txid(), 0))],
        output: vec![
            explicit_output(
                fixture.first_asset,
                900,
                Script::from(owned.script_pubkey.clone()),
            ),
            TxOut::new_fee(100, fixture.first_asset),
        ],
    };
    let transaction_bytes = serialize(&transaction);
    CandidateBatch::new(&[BorrowedCandidateTransaction::new(
        &transaction_bytes,
        std::slice::from_ref(&fixture.previous_transaction_bytes),
    )])
    .unwrap()
}

fn derived_blinding_key(entry: &CatalogEntry, slip77: &[u8; 32]) -> ScopedSecretKey {
    derive_blinding_key(slip77, &entry.script_pubkey).unwrap()
}

fn catalog_entry(
    catalog: &DescriptorCatalog,
    branch: DescriptorBranch,
    index: u32,
) -> &CatalogEntry {
    catalog
        .entries
        .values()
        .find(|entry| entry.branch == branch && entry.index == index)
        .unwrap()
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
