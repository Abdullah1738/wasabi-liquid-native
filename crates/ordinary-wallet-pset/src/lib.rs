#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Export-free composition of validated wallet outputs into a blinded ordinary PSET
//! or a locally finalized ordinary transaction.
//!
//! The operation independently randomizes input and confidential-output layout before
//! construction. Caller-authorized signing remains behind a caller-owned signer that
//! never gives this crate custody of a secret key. Successful local finalization yields
//! an opaque broadcast-form transaction capability. This crate does not establish node
//! or chain authenticity, current unspentness, fee policy, change classification,
//! reservation, broadcast submission, acceptance, or confirmation authority.

use core::fmt;
use core::hint::black_box;

use elements::LockTime;
use elements::secp256k1_zkp::Secp256k1;
use elements::secp256k1_zkp::rand::{CryptoRng, Error as RandomnessError, RngCore};
use wasabi_liquid_native_ordinary_pset::{
    BlindedOrdinaryPset, ConfidentialOutput, ExplicitFee, FinalizedOrdinaryTransaction,
    MAX_CONFIDENTIAL_OUTPUTS, OrdinaryP2wpkhSigner, OrdinaryPsetBlindingError,
    OrdinarySigningError, PsetConstructionError, prepare_ordinary_pset,
};
use wasabi_liquid_native_wallet_facts::{
    BorrowedSlip77, DescriptorCatalog, SelectedOutputBatch, WalletObservationError,
    validate_selected_owned_inputs,
};

const MAX_UNIFORM_DRAW_ATTEMPTS: usize = 128;

/// A privacy-redacted ordinary-wallet PSET orchestration failure.
///
/// Variants retain no dependency error, transaction identifier, script, asset,
/// amount, address, proof, key, or serialized payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum OrdinaryWalletPsetError {
    /// The selected-output request failed its public count or byte boundary.
    InvalidSelection,
    /// A selected funding transaction or its exact previous set was invalid.
    InvalidFundingTransaction,
    /// A selected output was absent, repeated, unsupported, or not descriptor-owned.
    InvalidSelectedOutput,
    /// The caller's cryptographically secure random source failed.
    RandomnessUnavailable,
    /// Inputs, outputs, and fee did not form a valid ordinary multiasset plan.
    InvalidPlan,
    /// The validated ordinary plan could not be blinded or failed postconditions.
    BlindingFailed,
}

impl fmt::Display for OrdinaryWalletPsetError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidSelection => "ordinary wallet selection is invalid",
            Self::InvalidFundingTransaction => "ordinary wallet funding transaction is invalid",
            Self::InvalidSelectedOutput => "ordinary wallet selected output is invalid",
            Self::RandomnessUnavailable => "ordinary wallet randomness is unavailable",
            Self::InvalidPlan => "ordinary wallet PSET plan is invalid",
            Self::BlindingFailed => "ordinary wallet PSET blinding failed",
        })
    }
}

impl std::error::Error for OrdinaryWalletPsetError {}

/// The privacy-redacted stage and reason for ordinary-wallet transaction failure.
///
/// Variants retain no transaction identifier, outpoint, script, address, asset,
/// amount, proof, key, signature, digest, serialized PSET, or dependency source.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum OrdinaryWalletTransactionReason {
    /// Selection, validation, construction, layout, or blinding failed.
    Preparation(OrdinaryWalletPsetError),
    /// Caller-owned signing or local finalization failed.
    Signing(OrdinarySigningError),
}

impl fmt::Display for OrdinaryWalletTransactionReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Preparation(reason) => write!(
                formatter,
                "ordinary transaction preparation failed: {reason}"
            ),
            Self::Signing(reason) => {
                write!(formatter, "ordinary transaction signing failed: {reason}")
            }
        }
    }
}

impl std::error::Error for OrdinaryWalletTransactionReason {}

/// An opaque ordinary-wallet transaction failure capability.
///
/// This type deliberately does not implement `Debug`, `Clone`, or `Copy`.
/// A signing failure retains the exact randomized and blinded PSET for an
/// explicit caller decision to retry or discard. A preparation failure retains
/// no PSET.
pub struct OrdinaryWalletTransactionFailure {
    reason: OrdinaryWalletTransactionReason,
    retryable_blinded: Option<Box<BlindedOrdinaryPset>>,
}

impl OrdinaryWalletTransactionFailure {
    fn preparation(reason: OrdinaryWalletPsetError) -> Self {
        Self {
            reason: OrdinaryWalletTransactionReason::Preparation(reason),
            retryable_blinded: None,
        }
    }

    fn signing(reason: OrdinarySigningError, blinded: BlindedOrdinaryPset) -> Self {
        Self {
            reason: OrdinaryWalletTransactionReason::Signing(reason),
            retryable_blinded: Some(Box::new(blinded)),
        }
    }

    /// Borrows the privacy-redacted failure reason.
    pub const fn reason(&self) -> &OrdinaryWalletTransactionReason {
        &self.reason
    }

    /// Consumes the failure and recovers its exact retryable blinded PSET, if any.
    ///
    /// Signing requests already made through the caller-owned signer cannot be
    /// rolled back. A retry starts the complete key and signature request
    /// sequence again and therefore requires a fresh or duplicate-tolerant
    /// signer.
    pub fn into_retryable_blinded(self) -> Option<BlindedOrdinaryPset> {
        self.retryable_blinded.map(|blinded| *blinded)
    }
}

/// Builds, blinds, signs, and locally finalizes an ordinary wallet transaction.
///
/// Selection validation, layout randomization, construction, and blinding are
/// identical to [`build_blinded_ordinary_wallet_pset`]. The caller-owned signer
/// supplies only public keys and signatures through [`OrdinaryP2wpkhSigner`];
/// this function never receives or stores a secret key. Every public key and
/// signature is validated by the canonical ordinary-PSET transition before the
/// signed PSET is immediately consumed into the opaque finalized transaction.
/// No intermediate unblinded or signed PSET is exported.
///
/// This function performs no node access, chain authentication, unspentness or
/// reservation check, fee-policy decision, broadcast submission, acceptance
/// check, or confirmation tracking.
pub fn build_sign_and_finalize_ordinary_wallet_transaction<R, S>(
    catalog: &DescriptorCatalog,
    slip77_master_key: BorrowedSlip77<'_>,
    selected_outputs: SelectedOutputBatch,
    outputs: Vec<ConfidentialOutput>,
    fee: ExplicitFee,
    rng: &mut R,
    signer: &mut S,
) -> Result<FinalizedOrdinaryTransaction, OrdinaryWalletTransactionFailure>
where
    R: RngCore + CryptoRng,
    S: OrdinaryP2wpkhSigner,
{
    let blinded = build_blinded_ordinary_wallet_pset(
        catalog,
        slip77_master_key,
        selected_outputs,
        outputs,
        fee,
        rng,
    )
    .map_err(OrdinaryWalletTransactionFailure::preparation)?;

    let secp = Secp256k1::new();
    match blinded.sign_and_finalize(&secp, signer) {
        Ok(signed) => Ok(signed.into_finalized_transaction()),
        Err(failure) => {
            let reason = failure.reason();
            Err(OrdinaryWalletTransactionFailure::signing(
                reason,
                failure.into_blinded(),
            ))
        }
    }
}

/// Consumes exact selected wallet outputs and returns only a blinded ordinary PSET.
///
/// Every selected funding transaction is canonically decoded and amount-proof
/// validated, every selected output is descriptor-owned and privately opened,
/// and every opaque input capability is consumed before construction. Inputs
/// already carry final sequence; construction uses zero locktime and is followed
/// immediately by blinding with the same caller-owned random source.
///
/// Validated inputs and supplied confidential outputs are independently shuffled
/// immediately before construction. The mandatory explicit fee remains last.
pub fn build_blinded_ordinary_wallet_pset<R: RngCore + CryptoRng>(
    catalog: &DescriptorCatalog,
    slip77_master_key: BorrowedSlip77<'_>,
    selected_outputs: SelectedOutputBatch,
    outputs: Vec<ConfidentialOutput>,
    fee: ExplicitFee,
    rng: &mut R,
) -> Result<BlindedOrdinaryPset, OrdinaryWalletPsetError> {
    let selected_outputs = ScopedSelectedOutputs(selected_outputs);
    if outputs.is_empty() || outputs.len() > MAX_CONFIDENTIAL_OUTPUTS {
        return Err(OrdinaryWalletPsetError::InvalidPlan);
    }
    let mut secp = Secp256k1::new();
    let validated_inputs = validate_selected_owned_inputs(
        catalog,
        slip77_master_key,
        &selected_outputs.0,
        &mut secp,
        rng,
    )
    .map_err(map_wallet_observation_error)?;
    drop(selected_outputs);
    let spendable_inputs = validated_inputs
        .into_iter()
        .map(|input| input.into_spendable())
        .collect::<Vec<_>>();
    let (spendable_inputs, outputs) = randomize_layout(spendable_inputs, outputs, rng)?;
    let prepared = prepare_ordinary_pset(spendable_inputs, outputs, fee, LockTime::ZERO)
        .map_err(map_construction_error)?;
    blind_immediately(prepared, rng, &secp)
}

struct ScopedSelectedOutputs(SelectedOutputBatch);

impl Drop for ScopedSelectedOutputs {
    fn drop(&mut self) {
        #[cfg(test)]
        SELECTED_OUTPUT_OWNER_DROPS.with(|count| count.set(count.get() + 1));
    }
}

fn randomize_layout<Input, Output, R: RngCore>(
    mut inputs: Vec<Input>,
    mut outputs: Vec<Output>,
    rng: &mut R,
) -> Result<(Vec<Input>, Vec<Output>), OrdinaryWalletPsetError> {
    shuffle_in_place(&mut inputs, rng)?;
    shuffle_in_place(&mut outputs, rng)?;
    Ok((inputs, outputs))
}

fn shuffle_in_place<T, R: RngCore>(
    values: &mut [T],
    rng: &mut R,
) -> Result<(), OrdinaryWalletPsetError> {
    for index in (1..values.len()).rev() {
        let swap_index = sample_uniform_index(index + 1, rng)?;
        values.swap(index, swap_index.0);
        drop(swap_index);
    }
    Ok(())
}

fn sample_uniform_index<R: RngCore>(
    exclusive_upper_bound: usize,
    rng: &mut R,
) -> Result<ScopedSwapIndex, OrdinaryWalletPsetError> {
    let upper_bound = u64::try_from(exclusive_upper_bound)
        .map_err(|_| OrdinaryWalletPsetError::RandomnessUnavailable)?;
    if !(2..=MAX_CONFIDENTIAL_OUTPUTS as u64).contains(&upper_bound) {
        return Err(OrdinaryWalletPsetError::RandomnessUnavailable);
    }
    let threshold = upper_bound.wrapping_neg() % upper_bound;

    for _ in 0..MAX_UNIFORM_DRAW_ATTEMPTS {
        let mut draw_bytes = ScopedDrawBytes([0; 8]);
        let mut draw = ScopedDrawValue(0);
        rng.try_fill_bytes(&mut draw_bytes.0)
            .map_err(|_| OrdinaryWalletPsetError::RandomnessUnavailable)?;
        draw.0 = u64::from_le_bytes(draw_bytes.0);
        if draw.0 >= threshold {
            return Ok(ScopedSwapIndex((draw.0 % upper_bound) as usize));
        }
    }

    Err(OrdinaryWalletPsetError::RandomnessUnavailable)
}

struct ScopedDrawBytes([u8; 8]);
struct ScopedDrawValue(u64);
struct ScopedSwapIndex(usize);

#[cfg(test)]
thread_local! {
    static CLEARED_DRAW_BUFFERS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static CLEARED_DRAW_VALUES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static CLEARED_SWAP_INDICES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static SELECTED_OUTPUT_OWNER_DROPS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

impl Drop for ScopedDrawBytes {
    fn drop(&mut self) {
        self.0.fill(0);
        black_box(&self.0);
        #[cfg(test)]
        {
            assert!(self.0.iter().all(|byte| *byte == 0));
            CLEARED_DRAW_BUFFERS.with(|count| count.set(count.get() + 1));
        }
    }
}

impl Drop for ScopedDrawValue {
    fn drop(&mut self) {
        self.0 = 0;
        black_box(&self.0);
        #[cfg(test)]
        {
            assert_eq!(self.0, 0);
            CLEARED_DRAW_VALUES.with(|count| count.set(count.get() + 1));
        }
    }
}

impl Drop for ScopedSwapIndex {
    fn drop(&mut self) {
        self.0 = 0;
        black_box(&self.0);
        #[cfg(test)]
        {
            assert_eq!(self.0, 0);
            CLEARED_SWAP_INDICES.with(|count| count.set(count.get() + 1));
        }
    }
}

fn blind_immediately<R: RngCore + CryptoRng>(
    prepared: wasabi_liquid_native_ordinary_pset::PreparedOrdinaryPset,
    rng: &mut R,
    secp: &Secp256k1<elements::secp256k1_zkp::All>,
) -> Result<BlindedOrdinaryPset, OrdinaryWalletPsetError> {
    // Pinned blinding consumes infallible `RngCore` methods. This adapter calls
    // only the source's fallible method. After the first source failure it
    // supplies discard-only valid scalar-shaped bytes so the dependency can
    // return normally, then the complete result is destroyed and rejected.
    let mut fallible_rng = FallibleBlindingRng::new(rng);
    let result = prepared.blind(&mut fallible_rng, secp);
    if fallible_rng.source_failed() {
        drop(result);
        return Err(OrdinaryWalletPsetError::BlindingFailed);
    }
    result.map_err(map_blinding_error)
}

struct FallibleBlindingRng<'source, R> {
    source: &'source mut R,
    source_failed: bool,
    fallback_counter: u8,
}

impl<'source, R: RngCore> FallibleBlindingRng<'source, R> {
    fn new(source: &'source mut R) -> Self {
        Self {
            source,
            source_failed: false,
            fallback_counter: 0,
        }
    }

    const fn source_failed(&self) -> bool {
        self.source_failed
    }

    fn fill_from_source(&mut self, destination: &mut [u8]) {
        if !self.source_failed && self.source.try_fill_bytes(destination).is_ok() {
            return;
        }

        self.source_failed = true;
        destination.fill(0);
        if let Some(last) = destination.last_mut() {
            self.fallback_counter = self.fallback_counter.wrapping_add(1).max(1);
            *last = self.fallback_counter;
        }
    }
}

impl<R: RngCore> RngCore for FallibleBlindingRng<'_, R> {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0; 4];
        self.fill_from_source(&mut bytes);
        u32::from_le_bytes(bytes)
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0; 8];
        self.fill_from_source(&mut bytes);
        u64::from_le_bytes(bytes)
    }

    fn fill_bytes(&mut self, destination: &mut [u8]) {
        self.fill_from_source(destination);
    }

    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), RandomnessError> {
        self.fill_from_source(destination);
        Ok(())
    }
}

impl<R: CryptoRng> CryptoRng for FallibleBlindingRng<'_, R> {}

fn map_construction_error(_: PsetConstructionError) -> OrdinaryWalletPsetError {
    OrdinaryWalletPsetError::InvalidPlan
}

fn map_blinding_error(_: OrdinaryPsetBlindingError) -> OrdinaryWalletPsetError {
    OrdinaryWalletPsetError::BlindingFailed
}

fn map_wallet_observation_error(error: WalletObservationError) -> OrdinaryWalletPsetError {
    match error {
        WalletObservationError::BatchLimit | WalletObservationError::TransactionLength => {
            OrdinaryWalletPsetError::InvalidSelection
        }
        WalletObservationError::ContextRandomnessUnavailable => {
            OrdinaryWalletPsetError::RandomnessUnavailable
        }
        WalletObservationError::PreviousTransactionSet
        | WalletObservationError::InvalidTransactionEncoding
        | WalletObservationError::PreviousTransactionMismatch
        | WalletObservationError::DuplicateTransaction
        | WalletObservationError::TransactionValidation => {
            OrdinaryWalletPsetError::InvalidFundingTransaction
        }
        WalletObservationError::ExplicitOwnedOutput
        | WalletObservationError::OwnedOutputOpening
        | WalletObservationError::DuplicateOwnedOutpoint
        | WalletObservationError::SelectedOutputIndex
        | WalletObservationError::DuplicateSelectedOutpoint
        | WalletObservationError::SelectedOutputExpectation
        | WalletObservationError::SelectedOutputNotOwned => {
            OrdinaryWalletPsetError::InvalidSelectedOutput
        }
        _ => OrdinaryWalletPsetError::InvalidSelection,
    }
}

#[cfg(test)]
#[path = "../tests/common/mod.rs"]
mod orchestration_test_common;

#[cfg(test)]
mod tests {
    use super::*;

    use rand::SeedableRng;
    use rand::rngs::StdRng;
    use wasabi_liquid_native_ordinary_pset::ExplicitFee;
    use wasabi_liquid_native_wallet_facts::BorrowedSlip77;

    use super::orchestration_test_common as common;

    struct ScriptedDrawRng {
        draws: std::collections::VecDeque<u64>,
        fill_calls: usize,
    }

    impl ScriptedDrawRng {
        fn new(draws: impl IntoIterator<Item = u64>) -> Self {
            Self {
                draws: draws.into_iter().collect(),
                fill_calls: 0,
            }
        }
    }

    impl RngCore for ScriptedDrawRng {
        fn next_u32(&mut self) -> u32 {
            panic!("uniform sampler used infallible randomness")
        }

        fn next_u64(&mut self) -> u64 {
            panic!("uniform sampler used infallible randomness")
        }

        fn fill_bytes(&mut self, _: &mut [u8]) {
            panic!("uniform sampler used infallible randomness")
        }

        fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), RandomnessError> {
            self.fill_calls += 1;
            assert_eq!(destination.len(), 8);
            let draw = self.draws.pop_front().expect("scripted draw available");
            destination.copy_from_slice(&draw.to_le_bytes());
            Ok(())
        }
    }

    struct RejectingDrawRng {
        fill_calls: usize,
    }

    impl RngCore for RejectingDrawRng {
        fn next_u32(&mut self) -> u32 {
            panic!("uniform sampler used infallible randomness")
        }

        fn next_u64(&mut self) -> u64 {
            panic!("uniform sampler used infallible randomness")
        }

        fn fill_bytes(&mut self, _: &mut [u8]) {
            panic!("uniform sampler used infallible randomness")
        }

        fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), RandomnessError> {
            self.fill_calls += 1;
            destination.fill(0);
            Ok(())
        }
    }

    struct PartialFailureRng;

    struct PanicOnRandomness;

    impl RngCore for PanicOnRandomness {
        fn next_u32(&mut self) -> u32 {
            panic!("test-only orchestration randomness unwind")
        }

        fn next_u64(&mut self) -> u64 {
            panic!("test-only orchestration randomness unwind")
        }

        fn fill_bytes(&mut self, _: &mut [u8]) {
            panic!("test-only orchestration randomness unwind")
        }

        fn try_fill_bytes(&mut self, _: &mut [u8]) -> Result<(), RandomnessError> {
            panic!("test-only orchestration randomness unwind")
        }
    }

    impl CryptoRng for PanicOnRandomness {}

    impl RngCore for PartialFailureRng {
        fn next_u32(&mut self) -> u32 {
            panic!("uniform sampler used infallible randomness")
        }

        fn next_u64(&mut self) -> u64 {
            panic!("uniform sampler used infallible randomness")
        }

        fn fill_bytes(&mut self, _: &mut [u8]) {
            panic!("uniform sampler used infallible randomness")
        }

        fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), RandomnessError> {
            destination[..4].fill(0xa5);
            Err(RandomnessError::new(std::io::Error::other(
                "test random source unavailable",
            )))
        }
    }

    struct FailAfterOneDrawRng {
        calls: usize,
    }

    impl RngCore for FailAfterOneDrawRng {
        fn next_u32(&mut self) -> u32 {
            panic!("layout randomizer used infallible randomness")
        }

        fn next_u64(&mut self) -> u64 {
            panic!("layout randomizer used infallible randomness")
        }

        fn fill_bytes(&mut self, _: &mut [u8]) {
            panic!("layout randomizer used infallible randomness")
        }

        fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), RandomnessError> {
            self.calls += 1;
            if self.calls == 1 {
                destination.copy_from_slice(&0_u64.to_le_bytes());
                return Ok(());
            }
            destination[..4].fill(0x5a);
            Err(RandomnessError::new(std::io::Error::other(
                "test random source unavailable",
            )))
        }
    }

    struct InputDropProbe;
    struct OutputDropProbe;

    thread_local! {
        static INPUT_DROP_PROBES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
        static OUTPUT_DROP_PROBES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    }

    impl Drop for InputDropProbe {
        fn drop(&mut self) {
            INPUT_DROP_PROBES.with(|count| count.set(count.get() + 1));
        }
    }

    impl Drop for OutputDropProbe {
        fn drop(&mut self) {
            OUTPUT_DROP_PROBES.with(|count| count.set(count.get() + 1));
        }
    }

    #[test]
    fn selected_output_expectation_maps_to_invalid_selected_output() {
        assert_eq!(
            map_wallet_observation_error(WalletObservationError::SelectedOutputExpectation),
            OrdinaryWalletPsetError::InvalidSelectedOutput
        );
    }

    #[test]
    fn consuming_orchestration_destroys_selected_owner_on_success_error_and_unwind() {
        let catalog = common::catalog();
        let fixture = common::funding_fixture();
        let fee = ExplicitFee::new(fixture.fee_asset, 100).unwrap();
        let drops_before = SELECTED_OUTPUT_OWNER_DROPS.with(std::cell::Cell::get);
        let mut rng = StdRng::from_seed(common::synthetic_material(
            b"ordinary wallet selected owner success",
        ));

        let blinded = build_blinded_ordinary_wallet_pset(
            &catalog,
            BorrowedSlip77::new(&fixture.slip77),
            common::selected_batch(&fixture, &[1, 0]),
            common::planned_outputs(&fixture),
            fee,
            &mut rng,
        )
        .unwrap();
        assert_eq!(
            SELECTED_OUTPUT_OWNER_DROPS.with(std::cell::Cell::get) - drops_before,
            1
        );
        drop(blinded);

        assert!(matches!(
            build_blinded_ordinary_wallet_pset(
                &catalog,
                BorrowedSlip77::new(&fixture.slip77),
                common::selected_batch(&fixture, &[1, 0]),
                Vec::new(),
                fee,
                &mut PanicOnRandomness,
            ),
            Err(OrdinaryWalletPsetError::InvalidPlan)
        ));
        assert_eq!(
            SELECTED_OUTPUT_OWNER_DROPS.with(std::cell::Cell::get) - drops_before,
            2
        );

        let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = build_blinded_ordinary_wallet_pset(
                &catalog,
                BorrowedSlip77::new(&fixture.slip77),
                common::selected_batch(&fixture, &[1, 0]),
                common::planned_outputs(&fixture),
                fee,
                &mut PanicOnRandomness,
            );
        }));
        assert!(unwind.is_err());
        assert_eq!(
            SELECTED_OUTPUT_OWNER_DROPS.with(std::cell::Cell::get) - drops_before,
            3
        );
    }

    #[test]
    fn rejection_sampler_is_unbiased_at_small_and_maximum_bounds() {
        let buffer_clears_before = CLEARED_DRAW_BUFFERS.with(std::cell::Cell::get);
        let value_clears_before = CLEARED_DRAW_VALUES.with(std::cell::Cell::get);
        let index_clears_before = CLEARED_SWAP_INDICES.with(std::cell::Cell::get);
        let mut small = ScriptedDrawRng::new([0, 4]);
        assert_eq!(sample_uniform_index(3, &mut small).unwrap().0, 1);
        assert_eq!(small.fill_calls, 2);

        let mut maximum = ScriptedDrawRng::new([0, 254]);
        assert_eq!(
            sample_uniform_index(MAX_CONFIDENTIAL_OUTPUTS, &mut maximum)
                .unwrap()
                .0,
            254
        );
        assert_eq!(maximum.fill_calls, 2);
        assert_eq!(
            CLEARED_DRAW_BUFFERS.with(std::cell::Cell::get) - buffer_clears_before,
            4
        );
        assert_eq!(
            CLEARED_DRAW_VALUES.with(std::cell::Cell::get) - value_clears_before,
            4
        );
        assert_eq!(
            CLEARED_SWAP_INDICES.with(std::cell::Cell::get) - index_clears_before,
            2
        );
    }

    #[test]
    fn rejection_sampler_exhaustion_is_bounded_and_fallible() {
        let buffer_clears_before = CLEARED_DRAW_BUFFERS.with(std::cell::Cell::get);
        let value_clears_before = CLEARED_DRAW_VALUES.with(std::cell::Cell::get);
        let index_clears_before = CLEARED_SWAP_INDICES.with(std::cell::Cell::get);
        let mut rng = RejectingDrawRng { fill_calls: 0 };

        assert!(matches!(
            sample_uniform_index(3, &mut rng),
            Err(OrdinaryWalletPsetError::RandomnessUnavailable)
        ));
        assert_eq!(rng.fill_calls, MAX_UNIFORM_DRAW_ATTEMPTS);
        assert_eq!(
            CLEARED_DRAW_BUFFERS.with(std::cell::Cell::get) - buffer_clears_before,
            MAX_UNIFORM_DRAW_ATTEMPTS
        );
        assert_eq!(
            CLEARED_DRAW_VALUES.with(std::cell::Cell::get) - value_clears_before,
            MAX_UNIFORM_DRAW_ATTEMPTS
        );
        assert_eq!(
            CLEARED_SWAP_INDICES.with(std::cell::Cell::get) - index_clears_before,
            0
        );
    }

    #[test]
    fn source_failure_clears_a_partially_filled_draw() {
        let buffer_clears_before = CLEARED_DRAW_BUFFERS.with(std::cell::Cell::get);
        let value_clears_before = CLEARED_DRAW_VALUES.with(std::cell::Cell::get);
        let index_clears_before = CLEARED_SWAP_INDICES.with(std::cell::Cell::get);

        assert!(matches!(
            sample_uniform_index(3, &mut PartialFailureRng),
            Err(OrdinaryWalletPsetError::RandomnessUnavailable)
        ));
        assert_eq!(
            CLEARED_DRAW_BUFFERS.with(std::cell::Cell::get) - buffer_clears_before,
            1
        );
        assert_eq!(
            CLEARED_DRAW_VALUES.with(std::cell::Cell::get) - value_clears_before,
            1
        );
        assert_eq!(
            CLEARED_SWAP_INDICES.with(std::cell::Cell::get) - index_clears_before,
            0
        );
    }

    #[test]
    fn empty_and_singleton_shuffles_consume_no_randomness() {
        let mut empty: [u8; 0] = [];
        let mut singleton = [7_u8];
        let mut rng = ScriptedDrawRng::new([]);

        shuffle_in_place(&mut empty, &mut rng).unwrap();
        shuffle_in_place(&mut singleton, &mut rng).unwrap();

        assert_eq!(singleton, [7]);
        assert_eq!(rng.fill_calls, 0);
    }

    #[test]
    fn late_layout_failure_drops_every_owned_input_and_output() {
        let input_drops_before = INPUT_DROP_PROBES.with(std::cell::Cell::get);
        let output_drops_before = OUTPUT_DROP_PROBES.with(std::cell::Cell::get);
        let mut rng = FailAfterOneDrawRng { calls: 0 };

        let result = randomize_layout(
            vec![InputDropProbe, InputDropProbe],
            vec![OutputDropProbe, OutputDropProbe],
            &mut rng,
        );

        assert!(matches!(
            result,
            Err(OrdinaryWalletPsetError::RandomnessUnavailable)
        ));
        assert_eq!(rng.calls, 2);
        assert_eq!(
            INPUT_DROP_PROBES.with(std::cell::Cell::get) - input_drops_before,
            2
        );
        assert_eq!(
            OUTPUT_DROP_PROBES.with(std::cell::Cell::get) - output_drops_before,
            2
        );
    }

    #[test]
    fn dependency_failures_collapse_without_sources() {
        for error in [
            PsetConstructionError::NoInputs,
            PsetConstructionError::AssetBalanceMismatch,
            PsetConstructionError::PsetInvariant,
        ] {
            assert_eq!(
                map_construction_error(error),
                OrdinaryWalletPsetError::InvalidPlan
            );
        }
        for error in [
            OrdinaryPsetBlindingError::InvalidRetainedOpening,
            OrdinaryPsetBlindingError::BlindingFailed,
            OrdinaryPsetBlindingError::PostconditionFailed,
        ] {
            assert_eq!(
                map_blinding_error(error),
                OrdinaryWalletPsetError::BlindingFailed
            );
        }
    }
}
