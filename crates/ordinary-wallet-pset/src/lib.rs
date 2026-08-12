#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Export-free composition of validated wallet outputs into a blinded ordinary PSET.
//!
//! The operation preserves caller-selected input and output order. That deterministic
//! layout is not privacy-safe for production use; layout randomization remains a
//! required follow-up. This crate does not establish chain state, fee policy, change
//! reservation, signing authority, finalization, or broadcast readiness.

use core::fmt;

use elements::LockTime;
use elements::secp256k1_zkp::Secp256k1;
use elements::secp256k1_zkp::rand::{CryptoRng, Error as RandomnessError, RngCore};
use wasabi_liquid_native_ordinary_pset::{
    BlindedOrdinaryPset, ConfidentialOutput, ExplicitFee, MAX_CONFIDENTIAL_OUTPUTS,
    OrdinaryPsetBlindingError, PsetConstructionError, prepare_ordinary_pset,
};
use wasabi_liquid_native_wallet_facts::{
    BorrowedSlip77, DescriptorCatalog, SelectedOutputBatch, WalletObservationError,
    validate_selected_owned_inputs,
};

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

/// Consumes exact selected wallet outputs and returns only a blinded ordinary PSET.
///
/// Every selected funding transaction is canonically decoded and amount-proof
/// validated, every selected output is descriptor-owned and privately opened,
/// and every opaque input capability is consumed before construction. Inputs
/// already carry final sequence; construction uses zero locktime and is followed
/// immediately by blinding with the same caller-owned random source.
///
/// Input and output order is preserved exactly and is not production privacy policy.
pub fn build_blinded_ordinary_wallet_pset<R: RngCore + CryptoRng>(
    catalog: &DescriptorCatalog,
    slip77_master_key: BorrowedSlip77<'_>,
    selected_outputs: SelectedOutputBatch,
    outputs: Vec<ConfidentialOutput>,
    fee: ExplicitFee,
    rng: &mut R,
) -> Result<BlindedOrdinaryPset, OrdinaryWalletPsetError> {
    if outputs.is_empty() || outputs.len() > MAX_CONFIDENTIAL_OUTPUTS {
        return Err(OrdinaryWalletPsetError::InvalidPlan);
    }
    let mut secp = Secp256k1::new();
    let validated_inputs = validate_selected_owned_inputs(
        catalog,
        slip77_master_key,
        &selected_outputs,
        &mut secp,
        rng,
    )
    .map_err(map_wallet_observation_error)?;
    let spendable_inputs = validated_inputs
        .into_iter()
        .map(|input| input.into_spendable())
        .collect();
    let prepared = prepare_ordinary_pset(spendable_inputs, outputs, fee, LockTime::ZERO)
        .map_err(map_construction_error)?;
    blind_immediately(prepared, rng, &secp)
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
        | WalletObservationError::SelectedOutputNotOwned => {
            OrdinaryWalletPsetError::InvalidSelectedOutput
        }
        _ => OrdinaryWalletPsetError::InvalidSelection,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
