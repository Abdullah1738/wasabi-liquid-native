#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Canonical source-only ordinary-wallet plan request preparation and PSET composition.
//!
//! This internal Rust `rlib` accepts only caller-owned public plan declarations
//! and exact funding transaction bytes. It performs no native loading, C ABI,
//! node access, signing, persistence, reservation, or currentness check. The
//! caller must generate a fresh, unpredictable source epoch for each wallet
//! session and must never reuse it: epoch reuse links otherwise separate
//! requests. The frame is plaintext, unauthenticated, and provides no replay
//! protection. Parsing and validation have variable timing. Public preparation
//! leaves the selected confidential output's committed asset and value unopened;
//! one consuming transition delegates to the existing provider-authorized,
//! randomized ordinary-wallet PSET construction and blinding operation.

mod reader;
mod writer;

#[cfg(test)]
mod tests;

use core::cmp::Ordering;
use core::fmt;
use core::str;

use elements::secp256k1_zkp::rand::{CryptoRng, RngCore};
use elements::secp256k1_zkp::{All, Secp256k1};
use elements::{AssetId, OutPoint, Txid};
use wasabi_liquid_native_address::{ConfidentialLiquidAddress, LiquidAddressProfile};
use wasabi_liquid_native_ordinary_pset::{BlindedOrdinaryPset, ConfidentialOutput, ExplicitFee};
use wasabi_liquid_native_ordinary_wallet_pset::{
    OrdinaryWalletPsetError, build_blinded_ordinary_wallet_pset,
};
use wasabi_liquid_native_wallet_facts::{
    BorrowedSelectedOutput, DescriptorCatalog, DescriptorNetwork, SelectedOutputBatch,
    SelectedOutputOpeningProvider, prepare_selected_owned_inputs,
};
use zeroize::Zeroize;

use reader::Reader;
use writer::Writer;

const REQUEST_MAGIC: &[u8; 4] = b"WLPQ";
const WIRE_VERSION: u16 = 1;
const HEADER_BYTES: usize = 152;
const SELECTED_FIXED_BYTES: usize = 88;
const DESTINATION_FIXED_BYTES: usize = 48;
const LENGTH_PREFIX_BYTES: usize = 4;
const ZERO_IDENTIFIER: [u8; 32] = [0; 32];

const MAX_REQUEST_FRAME_BYTES: usize = 268_435_456;
const MAX_REACHABLE_REQUEST_BYTES: usize = 67_260_872;
const MAX_SELECTED_INPUTS: usize = 100;
const MAX_CONFIDENTIAL_DESTINATIONS: usize = 255;
const MAX_DESTINATION_ADDRESS_BYTES: usize = 256;
const MAX_TRANSACTION_PAYLOAD_BYTES: usize = 4_194_304;
const MAX_PREVIOUS_TRANSACTION_ENTRIES: usize = 16_384;
const MAX_AGGREGATE_TRANSACTION_BYTES: usize = 67_108_864;
const MAX_PLAN_VALUE: u64 = 2_100_000_000_000_000;
const MAX_SPENDABLE_OUTPUT_INDEX: u32 = 0x3fff_ffff;

const MAINNET_MANIFEST: [u8; 32] = [
    0xb8, 0x82, 0x44, 0xf8, 0x1d, 0xaf, 0x14, 0xb2, 0xf4, 0x79, 0x15, 0xd4, 0x30, 0xec, 0x41, 0xe5,
    0x40, 0x2d, 0xe5, 0x38, 0x02, 0x0f, 0x1e, 0x48, 0x47, 0xe8, 0xdd, 0xbd, 0x6f, 0x23, 0x8e, 0x5b,
];
const TESTNET_MANIFEST: [u8; 32] = [
    0xe4, 0xe7, 0xec, 0x03, 0xe1, 0x9c, 0xe5, 0xf8, 0x3f, 0xd0, 0x4c, 0x58, 0x67, 0x88, 0xb7, 0x24,
    0xd8, 0x80, 0x52, 0xb6, 0x5e, 0xf2, 0x48, 0x0c, 0xc9, 0x3b, 0xcd, 0x50, 0x32, 0x4f, 0x6b, 0x20,
];
const MAINNET_PEGGED_ASSET: [u8; 32] = [
    0x6d, 0x52, 0x1c, 0x38, 0xec, 0x1e, 0xa1, 0x57, 0x34, 0xae, 0x22, 0xb7, 0xc4, 0x60, 0x64, 0x41,
    0x28, 0x29, 0xc0, 0xd0, 0x57, 0x9f, 0x0a, 0x71, 0x3d, 0x1c, 0x04, 0xed, 0xe9, 0x79, 0x02, 0x6f,
];
const TESTNET_PEGGED_ASSET: [u8; 32] = [
    0x49, 0x9a, 0x81, 0x85, 0x45, 0xf6, 0xba, 0xe3, 0x9f, 0xc0, 0x3b, 0x63, 0x7f, 0x2a, 0x4e, 0x1e,
    0x64, 0xe5, 0x90, 0xca, 0xc1, 0xbc, 0x3a, 0x6f, 0x6d, 0x71, 0xaa, 0x44, 0x43, 0x65, 0x4c, 0x14,
];

/// A stable, privacy-redacted plan-request failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum OrdinaryWalletPlanWireError {
    /// A caller-owned encoder or expected-binding input is invalid.
    InvalidArgument,
    /// The magic, version, or header length is unsupported.
    VersionMismatch,
    /// The request is malformed or noncanonical.
    InvalidEncoding,
    /// A numeric, component, aggregate, arithmetic, or frame limit was exceeded.
    LimitExceeded,
    /// The frame source epoch differs from the expected source epoch.
    SourceBindingMismatch,
    /// The reviewed manifest, pegged asset, or catalog network was rejected.
    ContextRejected,
    /// A destination, output, or declared exact balance was rejected.
    PlanRejected,
    /// The existing transaction and selected-output validators rejected funding.
    FundingRejected,
}

impl OrdinaryWalletPlanWireError {
    /// Returns the frozen numeric error code.
    pub const fn code(self) -> u32 {
        match self {
            Self::InvalidArgument => 1,
            Self::VersionMismatch => 2,
            Self::InvalidEncoding => 3,
            Self::LimitExceeded => 4,
            Self::SourceBindingMismatch => 5,
            Self::ContextRejected => 6,
            Self::PlanRejected => 7,
            Self::FundingRejected => 8,
        }
    }
}

impl fmt::Display for OrdinaryWalletPlanWireError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidArgument => "ordinary wallet plan wire argument is invalid",
            Self::VersionMismatch => "ordinary wallet plan wire version is unsupported",
            Self::InvalidEncoding => "ordinary wallet plan wire encoding is invalid",
            Self::LimitExceeded => "ordinary wallet plan wire limit exceeded",
            Self::SourceBindingMismatch => {
                "ordinary wallet plan wire source binding does not match"
            }
            Self::ContextRejected => "ordinary wallet plan wire context was rejected",
            Self::PlanRejected => "ordinary wallet plan wire plan was rejected",
            Self::FundingRejected => "ordinary wallet plan wire funding was rejected",
        })
    }
}

impl std::error::Error for OrdinaryWalletPlanWireError {}

/// One borrow-only selected-input declaration and its exact funding material.
pub struct OrdinaryWalletPlanSelectedRef<'selected> {
    expected_transaction_id: &'selected [u8; 32],
    expected_output_index: u32,
    expected_asset: &'selected [u8; 32],
    expected_value: u64,
    candidate_transaction: &'selected [u8],
    previous_transactions: &'selected [Vec<u8>],
}

impl<'selected> OrdinaryWalletPlanSelectedRef<'selected> {
    /// Creates one borrow-only selected-input declaration.
    pub const fn new(
        expected_transaction_id: &'selected [u8; 32],
        expected_output_index: u32,
        expected_asset: &'selected [u8; 32],
        expected_value: u64,
        candidate_transaction: &'selected [u8],
        previous_transactions: &'selected [Vec<u8>],
    ) -> Self {
        Self {
            expected_transaction_id,
            expected_output_index,
            expected_asset,
            expected_value,
            candidate_transaction,
            previous_transactions,
        }
    }
}

impl Drop for OrdinaryWalletPlanSelectedRef<'_> {
    fn drop(&mut self) {
        self.expected_output_index.zeroize();
        self.expected_value.zeroize();
        #[cfg(test)]
        note_zeroized_drop(
            DropKind::BorrowedScalar,
            self.expected_output_index == 0 && self.expected_value == 0,
        );
    }
}

/// One borrow-only confidential destination declaration.
pub struct OrdinaryWalletPlanDestinationRef<'destination> {
    asset: &'destination [u8; 32],
    value: u64,
    address: &'destination str,
}

impl<'destination> OrdinaryWalletPlanDestinationRef<'destination> {
    /// Creates one borrow-only confidential destination declaration.
    pub const fn new(
        asset: &'destination [u8; 32],
        value: u64,
        address: &'destination str,
    ) -> Self {
        Self {
            asset,
            value,
            address,
        }
    }
}

impl Drop for OrdinaryWalletPlanDestinationRef<'_> {
    fn drop(&mut self) {
        self.value.zeroize();
        #[cfg(test)]
        note_zeroized_drop(DropKind::BorrowedScalar, self.value == 0);
    }
}

/// A borrow-only ordinary-wallet plan request accepted by [`encode_request`].
///
/// `source_epoch` must be freshly and unpredictably generated for one wallet
/// session and never reused. Reuse is linkable. The epoch is a binding tag, not
/// authentication or replay protection; the complete frame remains plaintext.
pub struct OrdinaryWalletPlanRequestRef<'request> {
    source_epoch: &'request [u8; 32],
    source_revision: u64,
    manifest_id: &'request [u8; 32],
    pegged_asset: &'request [u8; 32],
    selected_inputs: &'request [OrdinaryWalletPlanSelectedRef<'request>],
    destinations: &'request [OrdinaryWalletPlanDestinationRef<'request>],
    explicit_fee_value: u64,
}

impl<'request> OrdinaryWalletPlanRequestRef<'request> {
    /// Creates one borrow-only ordinary-wallet plan request.
    pub const fn new(
        source_epoch: &'request [u8; 32],
        source_revision: u64,
        manifest_id: &'request [u8; 32],
        pegged_asset: &'request [u8; 32],
        selected_inputs: &'request [OrdinaryWalletPlanSelectedRef<'request>],
        destinations: &'request [OrdinaryWalletPlanDestinationRef<'request>],
        explicit_fee_value: u64,
    ) -> Self {
        Self {
            source_epoch,
            source_revision,
            manifest_id,
            pegged_asset,
            selected_inputs,
            destinations,
            explicit_fee_value,
        }
    }
}

impl Drop for OrdinaryWalletPlanRequestRef<'_> {
    fn drop(&mut self) {
        self.source_revision.zeroize();
        self.explicit_fee_value.zeroize();
        #[cfg(test)]
        note_zeroized_drop(
            DropKind::BorrowedScalar,
            self.source_revision == 0 && self.explicit_fee_value == 0,
        );
    }
}

/// A canonical encoded ordinary-wallet plan request.
pub struct EncodedOrdinaryWalletPlanRequest {
    bytes: Vec<u8>,
}

impl EncodedOrdinaryWalletPlanRequest {
    /// Borrows the complete canonical frame.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl Drop for EncodedOrdinaryWalletPlanRequest {
    fn drop(&mut self) {
        self.bytes.zeroize();
        #[cfg(test)]
        note_zeroized_drop(DropKind::Encoded, self.bytes.iter().all(|byte| *byte == 0));
    }
}

struct ParsedSelected {
    expected_transaction_id: [u8; 32],
    expected_output_index: u32,
    expected_asset: [u8; 32],
    expected_value: u64,
    candidate_transaction: Vec<u8>,
    previous_transactions: Vec<Vec<u8>>,
}

impl Drop for ParsedSelected {
    fn drop(&mut self) {
        self.expected_transaction_id.zeroize();
        self.expected_output_index.zeroize();
        self.expected_asset.zeroize();
        self.expected_value.zeroize();
        self.candidate_transaction.zeroize();
        for previous in &mut self.previous_transactions {
            previous.zeroize();
        }
        self.previous_transactions.clear();
        #[cfg(test)]
        note_zeroized_drop(
            DropKind::Selected,
            self.expected_transaction_id.iter().all(|byte| *byte == 0)
                && self.expected_output_index == 0
                && self.expected_asset.iter().all(|byte| *byte == 0)
                && self.expected_value == 0
                && self.candidate_transaction.iter().all(|byte| *byte == 0)
                && self.previous_transactions.is_empty(),
        );
    }
}

struct ParsedDestination {
    asset: [u8; 32],
    value: u64,
    address: Vec<u8>,
}

impl Drop for ParsedDestination {
    fn drop(&mut self) {
        self.asset.zeroize();
        self.value.zeroize();
        self.address.zeroize();
        #[cfg(test)]
        note_zeroized_drop(
            DropKind::Destination,
            self.asset.iter().all(|byte| *byte == 0)
                && self.value == 0
                && self.address.iter().all(|byte| *byte == 0),
        );
    }
}

/// A structurally accepted request whose exact raw fields remain owned.
pub struct ParsedOrdinaryWalletPlanRequest {
    source_epoch: [u8; 32],
    source_revision: u64,
    manifest_id: [u8; 32],
    pegged_asset: [u8; 32],
    selected_inputs: Vec<ParsedSelected>,
    destinations: Vec<ParsedDestination>,
    explicit_fee_value: u64,
}

impl ParsedOrdinaryWalletPlanRequest {
    /// Re-emits the exact canonical structural representation.
    pub fn reencode(
        &self,
    ) -> Result<EncodedOrdinaryWalletPlanRequest, OrdinaryWalletPlanWireError> {
        reencode_view(self)
    }

    /// Consumes raw storage and performs reviewed context, plan, and complete
    /// public selected-output validation without invoking an opening provider.
    ///
    /// This transition checks the candidate identifier and output index,
    /// canonical transactions, the exact previous-transaction set, amount
    /// proofs, descriptor ownership, and confidential public shape. It cannot
    /// observe whether the selected confidential commitment opens to the
    /// declared asset or value; that check belongs to the later provider-bound
    /// transition. Validation has variable timing.
    pub fn prepare<'catalog>(
        mut self,
        catalog: &'catalog DescriptorCatalog,
        secp: &Secp256k1<All>,
    ) -> Result<PubliclyPreparedOrdinaryWalletPlanRequest<'catalog>, OrdinaryWalletPlanWireError>
    {
        let context = reviewed_context(&self.manifest_id, &self.pegged_asset)
            .ok_or(OrdinaryWalletPlanWireError::ContextRejected)?;
        if catalog.network() != context.descriptor_network {
            return Err(OrdinaryWalletPlanWireError::ContextRejected);
        }

        let mut outputs = StagedOutputs(Vec::with_capacity(self.destinations.len()));
        for destination in &self.destinations {
            let address_text = str::from_utf8(&destination.address)
                .map_err(|_| OrdinaryWalletPlanWireError::PlanRejected)?;
            let address = ConfidentialLiquidAddress::parse(address_text, context.address_profile)
                .map_err(|_| OrdinaryWalletPlanWireError::PlanRejected)?;
            if address.as_parsed().canonical_address().as_bytes() != destination.address {
                return Err(OrdinaryWalletPlanWireError::PlanRejected);
            }
            let asset = ScopedAssetId(AssetId::from_byte_array(destination.asset));
            outputs.0.push(
                ConfidentialOutput::from_address(asset.0, destination.value, &address)
                    .map_err(|_| OrdinaryWalletPlanWireError::PlanRejected)?,
            );
            #[cfg(test)]
            maybe_panic_at(StagingPoint::PreparedOutput);
        }
        let fee_asset = ScopedAssetId(AssetId::from_byte_array(self.pegged_asset));
        let mut fee = StagedFee::new(
            ExplicitFee::new(fee_asset.0, self.explicit_fee_value)
                .map_err(|_| OrdinaryWalletPlanWireError::PlanRejected)?,
        );

        let mut expectations = StagedExpectations(Vec::with_capacity(self.selected_inputs.len()));
        for selected in &self.selected_inputs {
            expectations.0.push(StagedExpectation {
                outpoint: OutPoint::new(
                    Txid::from_byte_array(selected.expected_transaction_id),
                    selected.expected_output_index,
                ),
                asset: AssetId::from_byte_array(selected.expected_asset),
                value: selected.expected_value,
            });
            #[cfg(test)]
            maybe_panic_at(StagingPoint::PreparedExpectation);
        }
        let borrowed = StagedBorrowedBatch(
            self.selected_inputs
                .iter()
                .zip(&expectations.0)
                .map(|(selected, expectation)| {
                    BorrowedSelectedOutput::new(
                        &expectation.outpoint,
                        &expectation.asset,
                        &expectation.value,
                        &selected.candidate_transaction,
                        &selected.previous_transactions,
                    )
                })
                .collect::<Vec<_>>(),
        );
        #[cfg(test)]
        maybe_panic_at(StagingPoint::PreparedBorrowedBatch);
        let mut selected_inputs = StagedSelectedBatch(Some(
            SelectedOutputBatch::new(&borrowed.0)
                .map_err(|_| OrdinaryWalletPlanWireError::FundingRejected)?,
        ));
        #[cfg(test)]
        maybe_panic_at(StagingPoint::PreparedSelectedBatch);
        if !selected_inputs
            .0
            .as_ref()
            .expect("selected batch is present during preparation")
            .expected_ordinary_plan_is_balanced(&outputs.0, fee.value())
        {
            return Err(OrdinaryWalletPlanWireError::PlanRejected);
        }
        {
            let publicly_prepared = prepare_selected_owned_inputs(
                catalog,
                selected_inputs
                    .0
                    .as_ref()
                    .expect("selected batch is present during preparation"),
                secp,
            )
            .map_err(|_| OrdinaryWalletPlanWireError::FundingRejected)?;
            drop(publicly_prepared);
        }

        let source_revision = ScopedU64(core::mem::take(&mut self.source_revision));
        let manifest_id = ScopedArray(core::mem::take(&mut self.manifest_id));
        let pegged_asset = ScopedArray(core::mem::take(&mut self.pegged_asset));
        let selected_input_count = ScopedUsize(self.selected_inputs.len());
        let destination_count = ScopedUsize(self.destinations.len());
        assemble_prepared(
            catalog,
            selected_inputs
                .0
                .take()
                .expect("selected batch is present during final assembly"),
            core::mem::take(&mut outputs.0),
            fee.transfer(),
            source_revision,
            manifest_id,
            pegged_asset,
            selected_input_count,
            destination_count,
        )
    }
}

impl Drop for ParsedOrdinaryWalletPlanRequest {
    fn drop(&mut self) {
        self.source_epoch.zeroize();
        self.source_revision.zeroize();
        self.manifest_id.zeroize();
        self.pegged_asset.zeroize();
        self.selected_inputs.clear();
        self.destinations.clear();
        self.explicit_fee_value.zeroize();
        #[cfg(test)]
        note_zeroized_drop(
            DropKind::Parsed,
            self.source_epoch.iter().all(|byte| *byte == 0)
                && self.source_revision == 0
                && self.manifest_id.iter().all(|byte| *byte == 0)
                && self.pegged_asset.iter().all(|byte| *byte == 0)
                && self.selected_inputs.is_empty()
                && self.destinations.is_empty()
                && self.explicit_fee_value == 0,
        );
    }
}

/// A linear request that completed all public preparation.
///
/// This owner proves only public preparation. It does not open or expose the
/// selected confidential asset or value, authenticate the plaintext request,
/// prevent replay, establish epoch freshness, or make variable-time validation
/// safe for secret-bearing inputs. A reused epoch remains linkable.
pub struct PubliclyPreparedOrdinaryWalletPlanRequest<'catalog> {
    _catalog: &'catalog DescriptorCatalog,
    selected_inputs: Option<SelectedOutputBatch>,
    outputs: Option<Vec<ConfidentialOutput>>,
    fee: PreparedFee,
    source_revision: u64,
    manifest_id: [u8; 32],
    pegged_asset: [u8; 32],
    selected_input_count: usize,
    destination_count: usize,
}

impl PubliclyPreparedOrdinaryWalletPlanRequest<'_> {
    /// Returns the exact managed observation revision carried by the request.
    pub const fn source_revision(&self) -> u64 {
        self.source_revision
    }

    /// Returns the number of publicly prepared selected inputs.
    pub const fn selected_input_count(&self) -> usize {
        self.selected_input_count
    }

    /// Returns the number of confidential destinations.
    pub const fn confidential_destination_count(&self) -> usize {
        self.destination_count
    }

    /// Consumes this publicly prepared request into a blinded ordinary-wallet PSET.
    ///
    /// The exact retained catalog, selected-output batch, confidential
    /// destinations, and explicit fee are transferred without exposing their
    /// parts. The existing ordinary-wallet orchestration independently repeats
    /// balance and public selected-output validation, creates both randomized
    /// layouts, opens every selected confidential commitment through the
    /// caller-owned provider, binds the actual asset and value to the declared
    /// expectation, constructs the PSET, and blinds it immediately.
    ///
    /// Provider calls are nontransactional. Calls completed before a later
    /// refusal, opening mismatch, construction failure, blinding failure, or
    /// unwind are not rolled back. A complete retry requires a newly prepared
    /// request and starts provider calls again at row zero.
    ///
    /// The caller must authenticate source-revision currentness and obtain any
    /// required reservation before invoking this method. This transition does
    /// not establish node or chain authenticity, current unspentness, fee
    /// policy, reservation, broadcast acceptance, or confirmation authority.
    pub fn into_blinded_ordinary_wallet_pset<R, P>(
        mut self,
        provider: &mut P,
        rng: &mut R,
    ) -> Result<BlindedOrdinaryPset, OrdinaryWalletPsetError>
    where
        R: RngCore + CryptoRng,
        P: SelectedOutputOpeningProvider + ?Sized,
    {
        let selected_inputs = self
            .selected_inputs
            .take()
            .ok_or(OrdinaryWalletPsetError::InvalidPlan)?;
        let outputs = self
            .outputs
            .take()
            .ok_or(OrdinaryWalletPsetError::InvalidPlan)?;
        let fee = self.fee.transfer();
        #[cfg(test)]
        maybe_panic_at(StagingPoint::PreparedCompositionTransfer);
        build_blinded_ordinary_wallet_pset(
            self._catalog,
            provider,
            selected_inputs,
            outputs,
            fee,
            rng,
        )
    }
}

impl Drop for PubliclyPreparedOrdinaryWalletPlanRequest<'_> {
    fn drop(&mut self) {
        self.source_revision.zeroize();
        self.manifest_id.zeroize();
        self.pegged_asset.zeroize();
        self.selected_input_count.zeroize();
        self.destination_count.zeroize();
        self.selected_inputs.take();
        if let Some(mut outputs) = self.outputs.take() {
            outputs.clear();
        }
        self.fee.zeroize();
        #[cfg(test)]
        note_zeroized_drop(
            DropKind::Prepared,
            self.source_revision == 0
                && self.manifest_id.iter().all(|byte| *byte == 0)
                && self.pegged_asset.iter().all(|byte| *byte == 0)
                && self.selected_input_count == 0
                && self.destination_count == 0
                && self.selected_inputs.is_none()
                && self.outputs.is_none()
                && self.fee.is_zeroized(),
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn assemble_prepared<'catalog>(
    catalog: &'catalog DescriptorCatalog,
    selected_inputs: SelectedOutputBatch,
    outputs: Vec<ConfidentialOutput>,
    fee: PreparedFee,
    mut source_revision: ScopedU64,
    mut manifest_id: ScopedArray<32>,
    mut pegged_asset: ScopedArray<32>,
    mut selected_input_count: ScopedUsize,
    mut destination_count: ScopedUsize,
) -> Result<PubliclyPreparedOrdinaryWalletPlanRequest<'catalog>, OrdinaryWalletPlanWireError> {
    let prepared = PubliclyPreparedOrdinaryWalletPlanRequest {
        _catalog: catalog,
        selected_inputs: Some(selected_inputs),
        outputs: Some(outputs),
        fee,
        source_revision: core::mem::take(&mut source_revision.0),
        manifest_id: core::mem::take(&mut manifest_id.0),
        pegged_asset: core::mem::take(&mut pegged_asset.0),
        selected_input_count: core::mem::take(&mut selected_input_count.0),
        destination_count: core::mem::take(&mut destination_count.0),
    };
    #[cfg(test)]
    maybe_panic_at(StagingPoint::FinalPreparedAssembly);
    Ok(prepared)
}

struct StagedExpectation {
    outpoint: OutPoint,
    asset: AssetId,
    value: u64,
}

struct StagedOutputs(Vec<ConfidentialOutput>);

impl Drop for StagedOutputs {
    fn drop(&mut self) {
        self.0.clear();
        #[cfg(test)]
        note_zeroized_drop(DropKind::PreparedOutputBatch, self.0.is_empty());
    }
}

struct StagedFee {
    value: ExplicitFee,
}

impl StagedFee {
    fn new(value: ExplicitFee) -> Self {
        Self { value }
    }

    fn value(&self) -> ExplicitFee {
        self.value
    }

    fn transfer(&mut self) -> PreparedFee {
        let prepared = PreparedFee { value: self.value };
        self.value.zeroize();
        #[cfg(test)]
        note_zeroized_drop(DropKind::FeeTransfer, fee_is_zeroized(&self.value));
        #[cfg(test)]
        maybe_panic_at(StagingPoint::FeeTransferCleared);
        prepared
    }
}

impl Drop for StagedFee {
    fn drop(&mut self) {
        self.value.zeroize();
        #[cfg(test)]
        note_zeroized_drop(DropKind::StagedFee, fee_is_zeroized(&self.value));
    }
}

struct PreparedFee {
    value: ExplicitFee,
}

impl PreparedFee {
    fn transfer(&mut self) -> ExplicitFee {
        let fee = self.value;
        self.value.zeroize();
        #[cfg(test)]
        note_zeroized_drop(DropKind::PreparedFeeTransferClear, self.is_zeroized());
        fee
    }

    fn zeroize(&mut self) {
        self.value.zeroize();
    }

    #[cfg(test)]
    fn is_zeroized(&self) -> bool {
        fee_is_zeroized(&self.value)
    }
}

impl Drop for PreparedFee {
    fn drop(&mut self) {
        self.zeroize();
        #[cfg(test)]
        note_zeroized_drop(DropKind::PreparedFee, self.is_zeroized());
    }
}

#[cfg(test)]
fn fee_is_zeroized(fee: &ExplicitFee) -> bool {
    let mut asset = fee.asset().to_byte_array();
    let mut value = fee.value();
    let is_zeroized = asset == ZERO_IDENTIFIER && value == 0;
    asset.zeroize();
    value.zeroize();
    is_zeroized
}

struct StagedExpectations(Vec<StagedExpectation>);

impl Drop for StagedExpectations {
    fn drop(&mut self) {
        self.0.clear();
        #[cfg(test)]
        note_zeroized_drop(DropKind::PreparedExpectationBatch, self.0.is_empty());
    }
}

struct StagedSelectedBatch(Option<SelectedOutputBatch>);

impl Drop for StagedSelectedBatch {
    fn drop(&mut self) {
        self.0.take();
        #[cfg(test)]
        note_zeroized_drop(DropKind::PreparedSelectedBatch, self.0.is_none());
    }
}

struct StagedBorrowedBatch<'borrowed>(Vec<BorrowedSelectedOutput<'borrowed>>);

impl Drop for StagedBorrowedBatch<'_> {
    fn drop(&mut self) {
        self.0.clear();
        #[cfg(test)]
        note_zeroized_drop(DropKind::PreparedBorrowedBatch, self.0.is_empty());
    }
}

impl Drop for StagedExpectation {
    fn drop(&mut self) {
        self.outpoint = OutPoint::new(Txid::from_byte_array([0; 32]), 0);
        self.asset = AssetId::from_byte_array([0; 32]);
        self.value.zeroize();
        #[cfg(test)]
        note_zeroized_drop(
            DropKind::Expectation,
            self.outpoint
                .txid
                .to_byte_array()
                .iter()
                .all(|byte| *byte == 0)
                && self.outpoint.vout == 0
                && self.asset.to_byte_array().iter().all(|byte| *byte == 0)
                && self.value == 0,
        );
    }
}

/// Encodes one raw borrowed request after complete structural and declared-plan validation.
pub fn encode_request(
    request: &OrdinaryWalletPlanRequestRef<'_>,
) -> Result<EncodedOrdinaryWalletPlanRequest, OrdinaryWalletPlanWireError> {
    encode_view(request)
}

/// Structurally decodes one frame and binds its opaque source epoch.
pub fn decode_request(
    frame: &[u8],
    expected_source_epoch: &[u8; 32],
) -> Result<ParsedOrdinaryWalletPlanRequest, OrdinaryWalletPlanWireError> {
    drop(preflight_frame(frame, expected_source_epoch)?);
    let header = preflight_frame(frame, expected_source_epoch)?;
    parse_owned(frame, header)
}

trait SelectedView {
    fn transaction_id(&self) -> &[u8; 32];
    fn output_index(&self) -> &u32;
    fn asset(&self) -> &[u8; 32];
    fn value(&self) -> &u64;
    fn candidate(&self) -> &[u8];
    fn previous(&self) -> &[Vec<u8>];
}

impl SelectedView for OrdinaryWalletPlanSelectedRef<'_> {
    fn transaction_id(&self) -> &[u8; 32] {
        self.expected_transaction_id
    }
    fn output_index(&self) -> &u32 {
        &self.expected_output_index
    }
    fn asset(&self) -> &[u8; 32] {
        self.expected_asset
    }
    fn value(&self) -> &u64 {
        &self.expected_value
    }
    fn candidate(&self) -> &[u8] {
        self.candidate_transaction
    }
    fn previous(&self) -> &[Vec<u8>] {
        self.previous_transactions
    }
}

impl SelectedView for ParsedSelected {
    fn transaction_id(&self) -> &[u8; 32] {
        &self.expected_transaction_id
    }
    fn output_index(&self) -> &u32 {
        &self.expected_output_index
    }
    fn asset(&self) -> &[u8; 32] {
        &self.expected_asset
    }
    fn value(&self) -> &u64 {
        &self.expected_value
    }
    fn candidate(&self) -> &[u8] {
        &self.candidate_transaction
    }
    fn previous(&self) -> &[Vec<u8>] {
        &self.previous_transactions
    }
}

trait DestinationView {
    fn asset(&self) -> &[u8; 32];
    fn value(&self) -> &u64;
    fn address(&self) -> &[u8];
}

impl DestinationView for OrdinaryWalletPlanDestinationRef<'_> {
    fn asset(&self) -> &[u8; 32] {
        self.asset
    }
    fn value(&self) -> &u64 {
        &self.value
    }
    fn address(&self) -> &[u8] {
        self.address.as_bytes()
    }
}

impl DestinationView for ParsedDestination {
    fn asset(&self) -> &[u8; 32] {
        &self.asset
    }
    fn value(&self) -> &u64 {
        &self.value
    }
    fn address(&self) -> &[u8] {
        &self.address
    }
}

trait RequestView {
    type Selected: SelectedView;
    type Destination: DestinationView;

    fn source_epoch(&self) -> &[u8; 32];
    fn source_revision(&self) -> &u64;
    fn manifest_id(&self) -> &[u8; 32];
    fn pegged_asset(&self) -> &[u8; 32];
    fn selected_inputs(&self) -> &[Self::Selected];
    fn destinations(&self) -> &[Self::Destination];
    fn explicit_fee_value(&self) -> &u64;
}

impl<'request> RequestView for OrdinaryWalletPlanRequestRef<'request> {
    type Selected = OrdinaryWalletPlanSelectedRef<'request>;
    type Destination = OrdinaryWalletPlanDestinationRef<'request>;

    fn source_epoch(&self) -> &[u8; 32] {
        self.source_epoch
    }
    fn source_revision(&self) -> &u64 {
        &self.source_revision
    }
    fn manifest_id(&self) -> &[u8; 32] {
        self.manifest_id
    }
    fn pegged_asset(&self) -> &[u8; 32] {
        self.pegged_asset
    }
    fn selected_inputs(&self) -> &[Self::Selected] {
        self.selected_inputs
    }
    fn destinations(&self) -> &[Self::Destination] {
        self.destinations
    }
    fn explicit_fee_value(&self) -> &u64 {
        &self.explicit_fee_value
    }
}

impl RequestView for ParsedOrdinaryWalletPlanRequest {
    type Selected = ParsedSelected;
    type Destination = ParsedDestination;

    fn source_epoch(&self) -> &[u8; 32] {
        &self.source_epoch
    }
    fn source_revision(&self) -> &u64 {
        &self.source_revision
    }
    fn manifest_id(&self) -> &[u8; 32] {
        &self.manifest_id
    }
    fn pegged_asset(&self) -> &[u8; 32] {
        &self.pegged_asset
    }
    fn selected_inputs(&self) -> &[Self::Selected] {
        &self.selected_inputs
    }
    fn destinations(&self) -> &[Self::Destination] {
        &self.destinations
    }
    fn explicit_fee_value(&self) -> &u64 {
        &self.explicit_fee_value
    }
}

struct ReviewedContext {
    address_profile: LiquidAddressProfile,
    descriptor_network: DescriptorNetwork,
}

fn reviewed_context(manifest: &[u8; 32], pegged_asset: &[u8; 32]) -> Option<ReviewedContext> {
    match (manifest, pegged_asset) {
        (&MAINNET_MANIFEST, &MAINNET_PEGGED_ASSET) => Some(ReviewedContext {
            address_profile: LiquidAddressProfile::LiquidMainnet,
            descriptor_network: DescriptorNetwork::Mainnet,
        }),
        (&TESTNET_MANIFEST, &TESTNET_PEGGED_ASSET) => Some(ReviewedContext {
            address_profile: LiquidAddressProfile::LiquidTestnet,
            descriptor_network: DescriptorNetwork::Test,
        }),
        _ => None,
    }
}

fn encode_view<R: RequestView>(
    request: &R,
) -> Result<EncodedOrdinaryWalletPlanRequest, OrdinaryWalletPlanWireError> {
    let facts = validate_structural_view(request)?;
    validate_plan_view(request)?;
    encode_validated_view(request, &facts)
}

fn reencode_view<R: RequestView>(
    request: &R,
) -> Result<EncodedOrdinaryWalletPlanRequest, OrdinaryWalletPlanWireError> {
    let facts = validate_structural_view(request)?;
    encode_validated_view(request, &facts)
}

fn encode_validated_view<R: RequestView>(
    request: &R,
    facts: &ViewFacts,
) -> Result<EncodedOrdinaryWalletPlanRequest, OrdinaryWalletPlanWireError> {
    let mut writer = Writer::new(facts.total_length);
    let total_length = ScopedU64(facts.total_length as u64);
    let selected_count = ScopedU32(request.selected_inputs().len() as u32);
    let destination_count = ScopedU32(request.destinations().len() as u32);
    let previous_count = ScopedU32(facts.aggregate_previous_count as u32);
    writer.write(REQUEST_MAGIC);
    writer.write_u16(WIRE_VERSION);
    writer.write_u16(HEADER_BYTES as u16);
    writer.write_u64(total_length.0);
    writer.write_u32(0);
    writer.write_u32(0);
    writer.write(request.source_epoch());
    writer.write_u64(*request.source_revision());
    writer.write(request.manifest_id());
    writer.write(request.pegged_asset());
    writer.write_u32(selected_count.0);
    writer.write_u32(destination_count.0);
    writer.write_u32(previous_count.0);
    writer.write_u32(0);
    writer.write_u64(*request.explicit_fee_value());
    for selected in request.selected_inputs() {
        let candidate_length = ScopedU32(selected.candidate().len() as u32);
        let row_previous_count = ScopedU32(selected.previous().len() as u32);
        writer.write(selected.transaction_id());
        writer.write_u32(*selected.output_index());
        writer.write(selected.asset());
        writer.write_u64(*selected.value());
        writer.write_u32(candidate_length.0);
        writer.write_u32(row_previous_count.0);
        writer.write_u32(0);
        writer.write(selected.candidate());
        for previous in selected.previous() {
            let previous_length = ScopedU32(previous.len() as u32);
            writer.write_u32(previous_length.0);
            writer.write(previous);
        }
        #[cfg(test)]
        maybe_panic_at(StagingPoint::EncodedSelectedRow);
    }
    for destination in request.destinations() {
        let address_length = ScopedU32(destination.address().len() as u32);
        writer.write(destination.asset());
        writer.write_u64(*destination.value());
        writer.write_u32(address_length.0);
        writer.write_u32(0);
        writer.write(destination.address());
        #[cfg(test)]
        maybe_panic_at(StagingPoint::EncodedDestinationRow);
    }
    #[cfg(test)]
    maybe_panic_at(StagingPoint::EncodedWriterComplete);
    Ok(EncodedOrdinaryWalletPlanRequest {
        bytes: writer.finish()?,
    })
}

struct ViewFacts {
    total_length: usize,
    aggregate_previous_count: usize,
}

impl Drop for ViewFacts {
    fn drop(&mut self) {
        self.total_length.zeroize();
        self.aggregate_previous_count.zeroize();
        #[cfg(test)]
        note_zeroized_drop(
            DropKind::ViewFacts,
            self.total_length == 0 && self.aggregate_previous_count == 0,
        );
    }
}

struct ScopedUsize(usize);

impl Drop for ScopedUsize {
    fn drop(&mut self) {
        self.0.zeroize();
        #[cfg(test)]
        note_zeroized_drop(DropKind::Scalar, self.0 == 0);
    }
}

struct ScopedU16(u16);

impl Drop for ScopedU16 {
    fn drop(&mut self) {
        self.0.zeroize();
        #[cfg(test)]
        note_zeroized_drop(DropKind::Scalar, self.0 == 0);
    }
}

struct ScopedU32(u32);

impl Drop for ScopedU32 {
    fn drop(&mut self) {
        self.0.zeroize();
        #[cfg(test)]
        note_zeroized_drop(DropKind::Scalar, self.0 == 0);
    }
}

struct ScopedU64(u64);

impl Drop for ScopedU64 {
    fn drop(&mut self) {
        self.0.zeroize();
        #[cfg(test)]
        note_zeroized_drop(DropKind::Scalar, self.0 == 0);
    }
}

struct ScopedArray<const LENGTH: usize>([u8; LENGTH]);

impl<const LENGTH: usize> Drop for ScopedArray<LENGTH> {
    fn drop(&mut self) {
        self.0.zeroize();
        #[cfg(test)]
        note_zeroized_drop(DropKind::Identifier, self.0.iter().all(|byte| *byte == 0));
    }
}

struct ScopedPayload(Vec<u8>);

impl Drop for ScopedPayload {
    fn drop(&mut self) {
        self.0.zeroize();
        #[cfg(test)]
        note_zeroized_drop(DropKind::Temporary, self.0.iter().all(|byte| *byte == 0));
    }
}

struct ScopedAssetId(AssetId);

impl Drop for ScopedAssetId {
    fn drop(&mut self) {
        self.0 = AssetId::from_byte_array([0; 32]);
        #[cfg(test)]
        note_zeroized_drop(
            DropKind::Identifier,
            self.0.to_byte_array().iter().all(|byte| *byte == 0),
        );
    }
}

struct ScopedSelectedOrder {
    transaction_id: [u8; 32],
    output_index: u32,
}

impl Drop for ScopedSelectedOrder {
    fn drop(&mut self) {
        self.transaction_id.zeroize();
        self.output_index.zeroize();
    }
}

fn validate_structural_view<R: RequestView>(
    request: &R,
) -> Result<ViewFacts, OrdinaryWalletPlanWireError> {
    if !is_nonzero(request.source_epoch()) {
        return Err(OrdinaryWalletPlanWireError::InvalidArgument);
    }
    let selected_count = ScopedUsize(request.selected_inputs().len());
    let destination_count = ScopedUsize(request.destinations().len());
    if !(1..=MAX_SELECTED_INPUTS).contains(&selected_count.0)
        || !(1..=MAX_CONFIDENTIAL_DESTINATIONS).contains(&destination_count.0)
        || !(1..=MAX_PLAN_VALUE).contains(request.explicit_fee_value())
    {
        return Err(OrdinaryWalletPlanWireError::LimitExceeded);
    }

    let mut total_length = ScopedUsize(
        HEADER_BYTES
            .checked_add(
                selected_count
                    .0
                    .checked_mul(SELECTED_FIXED_BYTES)
                    .ok_or(OrdinaryWalletPlanWireError::LimitExceeded)?,
            )
            .and_then(|value| {
                value.checked_add(destination_count.0.checked_mul(DESTINATION_FIXED_BYTES)?)
            })
            .ok_or(OrdinaryWalletPlanWireError::LimitExceeded)?,
    );
    let mut aggregate_previous_count = ScopedUsize(0);
    let mut aggregate_transaction_bytes = ScopedUsize(0);
    let mut invalid_encoding =
        !is_nonzero(request.manifest_id()) || !is_nonzero(request.pegged_asset());
    let mut previous_selected: Option<(&[u8; 32], &u32)> = None;

    for selected in request.selected_inputs() {
        if *selected.output_index() > MAX_SPENDABLE_OUTPUT_INDEX
            || !(1..=MAX_PLAN_VALUE).contains(selected.value())
            || selected.candidate().is_empty()
            || selected.candidate().len() > MAX_TRANSACTION_PAYLOAD_BYTES
            || selected.previous().len() > MAX_PREVIOUS_TRANSACTION_ENTRIES
        {
            return Err(OrdinaryWalletPlanWireError::LimitExceeded);
        }
        aggregate_previous_count.0 = aggregate_previous_count
            .0
            .checked_add(selected.previous().len())
            .ok_or(OrdinaryWalletPlanWireError::LimitExceeded)?;
        if aggregate_previous_count.0 > MAX_PREVIOUS_TRANSACTION_ENTRIES {
            return Err(OrdinaryWalletPlanWireError::LimitExceeded);
        }
        aggregate_transaction_bytes.0 = aggregate_transaction_bytes
            .0
            .checked_add(selected.candidate().len())
            .ok_or(OrdinaryWalletPlanWireError::LimitExceeded)?;
        total_length.0 = total_length
            .0
            .checked_add(selected.candidate().len())
            .ok_or(OrdinaryWalletPlanWireError::LimitExceeded)?;
        for previous in selected.previous() {
            if previous.is_empty() || previous.len() > MAX_TRANSACTION_PAYLOAD_BYTES {
                return Err(OrdinaryWalletPlanWireError::LimitExceeded);
            }
            aggregate_transaction_bytes.0 = aggregate_transaction_bytes
                .0
                .checked_add(previous.len())
                .ok_or(OrdinaryWalletPlanWireError::LimitExceeded)?;
            total_length.0 = total_length
                .0
                .checked_add(LENGTH_PREFIX_BYTES)
                .and_then(|value| value.checked_add(previous.len()))
                .ok_or(OrdinaryWalletPlanWireError::LimitExceeded)?;
        }
        if aggregate_transaction_bytes.0 > MAX_AGGREGATE_TRANSACTION_BYTES {
            return Err(OrdinaryWalletPlanWireError::LimitExceeded);
        }
        invalid_encoding |= !is_nonzero(selected.transaction_id()) || !is_nonzero(selected.asset());
        if let Some((transaction_id, output_index)) = previous_selected {
            invalid_encoding |= selected_order(
                transaction_id,
                output_index,
                selected.transaction_id(),
                selected.output_index(),
            ) != Ordering::Less;
        }
        previous_selected = Some((selected.transaction_id(), selected.output_index()));
        invalid_encoding |= selected
            .previous()
            .windows(2)
            .any(|pair| pair[0] >= pair[1]);
    }
    if aggregate_transaction_bytes.0 == 0 {
        return Err(OrdinaryWalletPlanWireError::LimitExceeded);
    }

    for destination in request.destinations() {
        let address_length = ScopedUsize(destination.address().len());
        if !(1..=MAX_DESTINATION_ADDRESS_BYTES).contains(&address_length.0)
            || !(1..=MAX_PLAN_VALUE).contains(destination.value())
        {
            return Err(OrdinaryWalletPlanWireError::LimitExceeded);
        }
        total_length.0 = total_length
            .0
            .checked_add(address_length.0)
            .ok_or(OrdinaryWalletPlanWireError::LimitExceeded)?;
        invalid_encoding |= !is_nonzero(destination.asset()) || !destination.address().is_ascii();
    }
    validate_accumulator_arithmetic(request)?;
    if total_length.0 > MAX_REACHABLE_REQUEST_BYTES {
        return Err(OrdinaryWalletPlanWireError::LimitExceeded);
    }
    if invalid_encoding {
        return Err(OrdinaryWalletPlanWireError::InvalidEncoding);
    }

    let facts = ViewFacts {
        total_length: core::mem::take(&mut total_length.0),
        aggregate_previous_count: core::mem::take(&mut aggregate_previous_count.0),
    };
    #[cfg(test)]
    maybe_panic_at(StagingPoint::ValidatedTotals);
    Ok(facts)
}

fn validate_plan_view<R: RequestView>(request: &R) -> Result<(), OrdinaryWalletPlanWireError> {
    let context = reviewed_context(request.manifest_id(), request.pegged_asset())
        .ok_or(OrdinaryWalletPlanWireError::ContextRejected)?;
    for destination in request.destinations() {
        let address_text = str::from_utf8(destination.address())
            .map_err(|_| OrdinaryWalletPlanWireError::PlanRejected)?;
        let address = ConfidentialLiquidAddress::parse(address_text, context.address_profile)
            .map_err(|_| OrdinaryWalletPlanWireError::PlanRejected)?;
        if address.as_parsed().canonical_address().as_bytes() != destination.address() {
            return Err(OrdinaryWalletPlanWireError::PlanRejected);
        }
        let asset = ScopedAssetId(AssetId::from_byte_array(*destination.asset()));
        ConfidentialOutput::from_address(asset.0, *destination.value(), &address)
            .map_err(|_| OrdinaryWalletPlanWireError::PlanRejected)?;
    }
    let fee_asset = ScopedAssetId(AssetId::from_byte_array(*request.pegged_asset()));
    ExplicitFee::new(fee_asset.0, *request.explicit_fee_value())
        .map_err(|_| OrdinaryWalletPlanWireError::PlanRejected)?;
    if !declared_plan_is_balanced(request) {
        return Err(OrdinaryWalletPlanWireError::PlanRejected);
    }

    Ok(())
}

fn validate_accumulator_arithmetic<R: RequestView>(
    request: &R,
) -> Result<(), OrdinaryWalletPlanWireError> {
    for selected in request.selected_inputs() {
        let mut total = ScopedU64(0);
        for candidate in request.selected_inputs() {
            if candidate.asset() == selected.asset() {
                total.0 = total
                    .0
                    .checked_add(*candidate.value())
                    .ok_or(OrdinaryWalletPlanWireError::LimitExceeded)?;
            }
        }
    }
    for destination in request.destinations() {
        let mut total = ScopedU64(0);
        for candidate in request.destinations() {
            if candidate.asset() == destination.asset() {
                total.0 = total
                    .0
                    .checked_add(*candidate.value())
                    .ok_or(OrdinaryWalletPlanWireError::LimitExceeded)?;
            }
        }
        if destination.asset() == request.pegged_asset() {
            total.0 = total
                .0
                .checked_add(*request.explicit_fee_value())
                .ok_or(OrdinaryWalletPlanWireError::LimitExceeded)?;
        }
    }
    Ok(())
}

fn declared_plan_is_balanced<R: RequestView>(request: &R) -> bool {
    for (index, selected) in request.selected_inputs().iter().enumerate() {
        if request.selected_inputs()[..index]
            .iter()
            .any(|earlier| earlier.asset() == selected.asset())
        {
            continue;
        }
        let mut selected_total = ScopedU64(0);
        for candidate in request
            .selected_inputs()
            .iter()
            .filter(|candidate| candidate.asset() == selected.asset())
        {
            let Some(total) = selected_total.0.checked_add(*candidate.value()) else {
                return false;
            };
            let mut next_total = ScopedU64(total);
            selected_total.0 = core::mem::take(&mut next_total.0);
        }
        let mut planned_total = ScopedU64(0);
        for destination in request
            .destinations()
            .iter()
            .filter(|destination| destination.asset() == selected.asset())
        {
            let Some(total) = planned_total.0.checked_add(*destination.value()) else {
                return false;
            };
            let mut next_total = ScopedU64(total);
            planned_total.0 = core::mem::take(&mut next_total.0);
        }
        if selected.asset() == request.pegged_asset() {
            let Some(total) = planned_total.0.checked_add(*request.explicit_fee_value()) else {
                return false;
            };
            let mut next_total = ScopedU64(total);
            planned_total.0 = core::mem::take(&mut next_total.0);
        }
        if selected_total.0 != planned_total.0 {
            return false;
        }
    }
    for destination in request.destinations() {
        if !request
            .selected_inputs()
            .iter()
            .any(|selected| selected.asset() == destination.asset())
        {
            return false;
        }
    }
    request
        .selected_inputs()
        .iter()
        .any(|selected| selected.asset() == request.pegged_asset())
}

fn selected_order(
    left_id: &[u8; 32],
    left_index: &u32,
    right_id: &[u8; 32],
    right_index: &u32,
) -> Ordering {
    left_id
        .iter()
        .rev()
        .cmp(right_id.iter().rev())
        .then(left_index.cmp(right_index))
}

struct HeaderFacts {
    source_epoch: [u8; 32],
    source_revision: u64,
    manifest_id: [u8; 32],
    pegged_asset: [u8; 32],
    selected_count: usize,
    destination_count: usize,
    aggregate_previous_count: usize,
    explicit_fee_value: u64,
}

impl Drop for HeaderFacts {
    fn drop(&mut self) {
        self.source_epoch.zeroize();
        self.source_revision.zeroize();
        self.manifest_id.zeroize();
        self.pegged_asset.zeroize();
        self.selected_count.zeroize();
        self.destination_count.zeroize();
        self.aggregate_previous_count.zeroize();
        self.explicit_fee_value.zeroize();
        #[cfg(test)]
        note_zeroized_drop(
            DropKind::Header,
            self.source_epoch.iter().all(|byte| *byte == 0)
                && self.source_revision == 0
                && self.manifest_id.iter().all(|byte| *byte == 0)
                && self.pegged_asset.iter().all(|byte| *byte == 0)
                && self.selected_count == 0
                && self.destination_count == 0
                && self.aggregate_previous_count == 0
                && self.explicit_fee_value == 0,
        );
    }
}

fn preflight_frame(
    frame: &[u8],
    expected_source_epoch: &[u8; 32],
) -> Result<HeaderFacts, OrdinaryWalletPlanWireError> {
    if !is_nonzero(expected_source_epoch) {
        return Err(OrdinaryWalletPlanWireError::InvalidArgument);
    }
    if frame.len() > MAX_REQUEST_FRAME_BYTES {
        return Err(OrdinaryWalletPlanWireError::LimitExceeded);
    }
    if frame.len() < 8 {
        return Err(OrdinaryWalletPlanWireError::InvalidEncoding);
    }
    let mut discriminator = Reader::new(frame);
    let magic = ScopedArray(discriminator.read_array::<4>()?);
    let version = ScopedU16(discriminator.read_u16()?);
    let header_length = ScopedU16(discriminator.read_u16()?);
    if magic.0 != *REQUEST_MAGIC
        || version.0 != WIRE_VERSION
        || header_length.0 as usize != HEADER_BYTES
    {
        return Err(OrdinaryWalletPlanWireError::VersionMismatch);
    }
    if frame.len() < HEADER_BYTES {
        return Err(OrdinaryWalletPlanWireError::InvalidEncoding);
    }
    let mut reader = Reader::new(frame);
    reader.take(8)?;
    let declared_length = ScopedU64(reader.read_u64()?);
    let flags = ScopedU32(reader.read_u32()?);
    let reserved = ScopedU32(reader.read_u32()?);
    let source_epoch = ScopedArray(reader.read_array::<32>()?);
    let mut source_revision = ScopedU64(reader.read_u64()?);
    let manifest_id = ScopedArray(reader.read_array::<32>()?);
    let pegged_asset = ScopedArray(reader.read_array::<32>()?);
    let mut selected_count = ScopedUsize(reader.read_u32()? as usize);
    let mut destination_count = ScopedUsize(reader.read_u32()? as usize);
    let mut aggregate_previous_count = ScopedUsize(reader.read_u32()? as usize);
    let tail_reserved = ScopedU32(reader.read_u32()?);
    let mut explicit_fee_value = ScopedU64(reader.read_u64()?);
    if declared_length.0 != frame.len() as u64
        || flags.0 != 0
        || reserved.0 != 0
        || tail_reserved.0 != 0
        || !is_nonzero(&source_epoch.0)
        || !is_nonzero(&manifest_id.0)
        || !is_nonzero(&pegged_asset.0)
    {
        return Err(OrdinaryWalletPlanWireError::InvalidEncoding);
    }
    if source_epoch.0 != *expected_source_epoch {
        return Err(OrdinaryWalletPlanWireError::SourceBindingMismatch);
    }
    if frame.len() > MAX_REACHABLE_REQUEST_BYTES
        || !(1..=MAX_SELECTED_INPUTS).contains(&selected_count.0)
        || !(1..=MAX_CONFIDENTIAL_DESTINATIONS).contains(&destination_count.0)
        || aggregate_previous_count.0 > MAX_PREVIOUS_TRANSACTION_ENTRIES
        || !(1..=MAX_PLAN_VALUE).contains(&explicit_fee_value.0)
    {
        return Err(OrdinaryWalletPlanWireError::LimitExceeded);
    }
    let mut source_epoch = source_epoch;
    let mut manifest_id = manifest_id;
    let mut pegged_asset = pegged_asset;
    let header = HeaderFacts {
        source_epoch: core::mem::take(&mut source_epoch.0),
        source_revision: core::mem::take(&mut source_revision.0),
        manifest_id: core::mem::take(&mut manifest_id.0),
        pegged_asset: core::mem::take(&mut pegged_asset.0),
        selected_count: core::mem::take(&mut selected_count.0),
        destination_count: core::mem::take(&mut destination_count.0),
        aggregate_previous_count: core::mem::take(&mut aggregate_previous_count.0),
        explicit_fee_value: core::mem::take(&mut explicit_fee_value.0),
    };
    #[cfg(test)]
    maybe_panic_at(StagingPoint::HeaderComplete);
    scan_body(frame, &header)?;
    Ok(header)
}

fn scan_body(frame: &[u8], header: &HeaderFacts) -> Result<(), OrdinaryWalletPlanWireError> {
    let mut reader = Reader::new(frame);
    reader.take(HEADER_BYTES)?;
    let mut invalid_encoding = false;
    let mut previous_selected: Option<ScopedSelectedOrder> = None;
    let mut aggregate_previous_count = ScopedUsize(0);
    let mut aggregate_transaction_bytes = ScopedUsize(0);
    for _ in 0..header.selected_count {
        let current_selected = ScopedSelectedOrder {
            transaction_id: reader.read_array::<32>()?,
            output_index: reader.read_u32()?,
        };
        if current_selected.output_index > MAX_SPENDABLE_OUTPUT_INDEX {
            return Err(OrdinaryWalletPlanWireError::LimitExceeded);
        }
        invalid_encoding |= current_selected.transaction_id == ZERO_IDENTIFIER;
        let asset = ScopedArray(reader.read_array::<32>()?);
        invalid_encoding |= asset.0 == ZERO_IDENTIFIER;
        let value = ScopedU64(reader.read_u64()?);
        if !(1..=MAX_PLAN_VALUE).contains(&value.0) {
            return Err(OrdinaryWalletPlanWireError::LimitExceeded);
        }
        let candidate_length = ScopedUsize(reader.read_u32()? as usize);
        if !(1..=MAX_TRANSACTION_PAYLOAD_BYTES).contains(&candidate_length.0) {
            return Err(OrdinaryWalletPlanWireError::LimitExceeded);
        }
        aggregate_transaction_bytes.0 = aggregate_transaction_bytes
            .0
            .checked_add(candidate_length.0)
            .ok_or(OrdinaryWalletPlanWireError::LimitExceeded)?;
        if aggregate_transaction_bytes.0 > MAX_AGGREGATE_TRANSACTION_BYTES {
            return Err(OrdinaryWalletPlanWireError::LimitExceeded);
        }
        let previous_count = ScopedUsize(reader.read_u32()? as usize);
        if previous_count.0 > MAX_PREVIOUS_TRANSACTION_ENTRIES {
            return Err(OrdinaryWalletPlanWireError::LimitExceeded);
        }
        aggregate_previous_count.0 = aggregate_previous_count
            .0
            .checked_add(previous_count.0)
            .ok_or(OrdinaryWalletPlanWireError::LimitExceeded)?;
        if aggregate_previous_count.0 > MAX_PREVIOUS_TRANSACTION_ENTRIES {
            return Err(OrdinaryWalletPlanWireError::LimitExceeded);
        }
        let reserved = ScopedU32(reader.read_u32()?);
        invalid_encoding |= reserved.0 != 0;
        if let Some(previous) = previous_selected.as_ref() {
            invalid_encoding |= selected_order(
                &previous.transaction_id,
                &previous.output_index,
                &current_selected.transaction_id,
                &current_selected.output_index,
            ) != Ordering::Less;
        }
        previous_selected = Some(current_selected);
        reader.take(candidate_length.0)?;
        let mut previous_payload: Option<&[u8]> = None;
        for _ in 0..previous_count.0 {
            let length = ScopedUsize(reader.read_u32()? as usize);
            if !(1..=MAX_TRANSACTION_PAYLOAD_BYTES).contains(&length.0) {
                return Err(OrdinaryWalletPlanWireError::LimitExceeded);
            }
            aggregate_transaction_bytes.0 = aggregate_transaction_bytes
                .0
                .checked_add(length.0)
                .ok_or(OrdinaryWalletPlanWireError::LimitExceeded)?;
            if aggregate_transaction_bytes.0 > MAX_AGGREGATE_TRANSACTION_BYTES {
                return Err(OrdinaryWalletPlanWireError::LimitExceeded);
            }
            let payload = reader.take(length.0)?;
            if previous_payload.is_some_and(|previous| previous >= payload) {
                invalid_encoding = true;
            }
            previous_payload = Some(payload);
        }
    }
    if aggregate_previous_count.0 != header.aggregate_previous_count {
        invalid_encoding = true;
    }
    for _ in 0..header.destination_count {
        let asset = ScopedArray(reader.read_array::<32>()?);
        invalid_encoding |= asset.0 == ZERO_IDENTIFIER;
        let value = ScopedU64(reader.read_u64()?);
        if !(1..=MAX_PLAN_VALUE).contains(&value.0) {
            return Err(OrdinaryWalletPlanWireError::LimitExceeded);
        }
        let address_length = ScopedUsize(reader.read_u32()? as usize);
        if !(1..=MAX_DESTINATION_ADDRESS_BYTES).contains(&address_length.0) {
            return Err(OrdinaryWalletPlanWireError::LimitExceeded);
        }
        let reserved = ScopedU32(reader.read_u32()?);
        invalid_encoding |= reserved.0 != 0;
        let address = reader.take(address_length.0)?;
        invalid_encoding |= !address.is_ascii();
    }
    #[cfg(test)]
    maybe_panic_at(StagingPoint::ScannedTotals);
    if reader.require_end().is_err() {
        invalid_encoding = true;
    }
    if invalid_encoding {
        Err(OrdinaryWalletPlanWireError::InvalidEncoding)
    } else {
        Ok(())
    }
}

fn parse_owned(
    frame: &[u8],
    mut header: HeaderFacts,
) -> Result<ParsedOrdinaryWalletPlanRequest, OrdinaryWalletPlanWireError> {
    let mut reader = Reader::new(frame);
    reader.take(HEADER_BYTES)?;
    let mut selected_inputs = Vec::with_capacity(header.selected_count);
    for _ in 0..header.selected_count {
        let mut expected_transaction_id = ScopedArray(reader.read_array::<32>()?);
        let mut expected_output_index = ScopedU32(reader.read_u32()?);
        let mut expected_asset = ScopedArray(reader.read_array::<32>()?);
        let mut expected_value = ScopedU64(reader.read_u64()?);
        let mut selected = ParsedSelected {
            expected_transaction_id: core::mem::take(&mut expected_transaction_id.0),
            expected_output_index: core::mem::take(&mut expected_output_index.0),
            expected_asset: core::mem::take(&mut expected_asset.0),
            expected_value: core::mem::take(&mut expected_value.0),
            candidate_transaction: Vec::new(),
            previous_transactions: Vec::new(),
        };
        let candidate_length = ScopedUsize(reader.read_u32()? as usize);
        let previous_count = ScopedUsize(reader.read_u32()? as usize);
        drop(ScopedU32(reader.read_u32()?));
        selected
            .candidate_transaction
            .extend_from_slice(reader.take(candidate_length.0)?);
        #[cfg(test)]
        maybe_panic_at(StagingPoint::ParsedCandidate);
        selected
            .previous_transactions
            .reserve_exact(previous_count.0);
        for _ in 0..previous_count.0 {
            let length = ScopedUsize(reader.read_u32()? as usize);
            let mut previous = ScopedPayload(Vec::with_capacity(length.0));
            previous.0.extend_from_slice(reader.take(length.0)?);
            #[cfg(test)]
            maybe_panic_at(StagingPoint::ParsedPrevious);
            selected
                .previous_transactions
                .push(core::mem::take(&mut previous.0));
            #[cfg(test)]
            maybe_panic_at(StagingPoint::ParsedPreviousRow);
        }
        selected_inputs.push(selected);
        #[cfg(test)]
        maybe_panic_at(StagingPoint::ParsedSelectedRow);
    }
    let mut destinations = Vec::with_capacity(header.destination_count);
    for _ in 0..header.destination_count {
        let mut asset = ScopedArray(reader.read_array::<32>()?);
        let mut value = ScopedU64(reader.read_u64()?);
        let mut destination = ParsedDestination {
            asset: core::mem::take(&mut asset.0),
            value: core::mem::take(&mut value.0),
            address: Vec::new(),
        };
        let length = ScopedUsize(reader.read_u32()? as usize);
        drop(ScopedU32(reader.read_u32()?));
        destination
            .address
            .extend_from_slice(reader.take(length.0)?);
        #[cfg(test)]
        maybe_panic_at(StagingPoint::ParsedAddress);
        destinations.push(destination);
        #[cfg(test)]
        maybe_panic_at(StagingPoint::ParsedDestinationRow);
    }
    reader.require_end()?;
    let parsed = ParsedOrdinaryWalletPlanRequest {
        source_epoch: core::mem::take(&mut header.source_epoch),
        source_revision: core::mem::take(&mut header.source_revision),
        manifest_id: core::mem::take(&mut header.manifest_id),
        pegged_asset: core::mem::take(&mut header.pegged_asset),
        selected_inputs,
        destinations,
        explicit_fee_value: core::mem::take(&mut header.explicit_fee_value),
    };
    #[cfg(test)]
    maybe_panic_at(StagingPoint::ParsedFinalAssembly);
    Ok(parsed)
}

fn is_nonzero(bytes: &[u8]) -> bool {
    bytes.iter().any(|byte| *byte != 0)
}

#[cfg(test)]
#[derive(Clone, Copy)]
enum DropKind {
    Encoded,
    BorrowedScalar,
    Scalar,
    Identifier,
    Header,
    ViewFacts,
    Selected,
    Destination,
    Parsed,
    Prepared,
    Expectation,
    Writer,
    Temporary,
    PreparedOutputBatch,
    StagedFee,
    PreparedFee,
    FeeTransfer,
    PreparedFeeTransferClear,
    PreparedExpectationBatch,
    PreparedSelectedBatch,
    PreparedBorrowedBatch,
}

#[cfg(test)]
#[derive(Clone, Copy, Eq, PartialEq)]
enum StagingPoint {
    ValidatedTotals,
    EncodedSelectedRow,
    EncodedDestinationRow,
    EncodedWriterComplete,
    WriterTransfer,
    HeaderComplete,
    ScannedTotals,
    ParsedCandidate,
    ParsedPrevious,
    ParsedPreviousRow,
    ParsedSelectedRow,
    ParsedAddress,
    ParsedDestinationRow,
    ParsedFinalAssembly,
    PreparedOutput,
    PreparedExpectation,
    PreparedBorrowedBatch,
    PreparedSelectedBatch,
    FeeTransferCleared,
    FinalPreparedAssembly,
    PreparedCompositionTransfer,
}

#[cfg(test)]
#[derive(Clone, Copy, Default)]
struct DropAudit {
    encoded: usize,
    borrowed_scalar: usize,
    scalar: usize,
    identifier: usize,
    header: usize,
    view_facts: usize,
    selected: usize,
    destination: usize,
    parsed: usize,
    prepared: usize,
    expectation: usize,
    writer: usize,
    temporary: usize,
    prepared_output_batch: usize,
    staged_fee: usize,
    prepared_fee: usize,
    fee_transfer: usize,
    prepared_fee_transfer_clear: usize,
    prepared_expectation_batch: usize,
    prepared_selected_batch: usize,
    prepared_borrowed_batch: usize,
    all_zeroized: bool,
}

#[cfg(test)]
thread_local! {
    static DROP_AUDIT: std::cell::RefCell<DropAudit> = const { std::cell::RefCell::new(DropAudit { encoded: 0, borrowed_scalar: 0, scalar: 0, identifier: 0, header: 0, view_facts: 0, selected: 0, destination: 0, parsed: 0, prepared: 0, expectation: 0, writer: 0, temporary: 0, prepared_output_batch: 0, staged_fee: 0, prepared_fee: 0, fee_transfer: 0, prepared_fee_transfer_clear: 0, prepared_expectation_batch: 0, prepared_selected_batch: 0, prepared_borrowed_batch: 0, all_zeroized: true }) };
    static PANIC_AT: std::cell::Cell<Option<StagingPoint>> = const { std::cell::Cell::new(None) };
    static PANIC_AFTER: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
fn maybe_panic_at(point: StagingPoint) {
    PANIC_AT.with(|configured| {
        if configured.get() == Some(point) {
            let should_panic = PANIC_AFTER.with(|remaining| {
                if remaining.get() == 0 {
                    true
                } else {
                    remaining.set(remaining.get() - 1);
                    false
                }
            });
            if !should_panic {
                return;
            }
            configured.set(None);
            panic!("test-only ordinary-wallet plan staging unwind");
        }
    });
}

#[cfg(test)]
fn note_zeroized_drop(kind: DropKind, zeroized: bool) {
    DROP_AUDIT.with(|audit| {
        let mut audit = audit.borrow_mut();
        match kind {
            DropKind::Encoded => audit.encoded += 1,
            DropKind::BorrowedScalar => audit.borrowed_scalar += 1,
            DropKind::Scalar => audit.scalar += 1,
            DropKind::Identifier => audit.identifier += 1,
            DropKind::Header => audit.header += 1,
            DropKind::ViewFacts => audit.view_facts += 1,
            DropKind::Selected => audit.selected += 1,
            DropKind::Destination => audit.destination += 1,
            DropKind::Parsed => audit.parsed += 1,
            DropKind::Prepared => audit.prepared += 1,
            DropKind::Expectation => audit.expectation += 1,
            DropKind::Writer => audit.writer += 1,
            DropKind::Temporary => audit.temporary += 1,
            DropKind::PreparedOutputBatch => audit.prepared_output_batch += 1,
            DropKind::StagedFee => audit.staged_fee += 1,
            DropKind::PreparedFee => audit.prepared_fee += 1,
            DropKind::FeeTransfer => audit.fee_transfer += 1,
            DropKind::PreparedFeeTransferClear => audit.prepared_fee_transfer_clear += 1,
            DropKind::PreparedExpectationBatch => audit.prepared_expectation_batch += 1,
            DropKind::PreparedSelectedBatch => audit.prepared_selected_batch += 1,
            DropKind::PreparedBorrowedBatch => audit.prepared_borrowed_batch += 1,
        }
        audit.all_zeroized &= zeroized;
    });
}
