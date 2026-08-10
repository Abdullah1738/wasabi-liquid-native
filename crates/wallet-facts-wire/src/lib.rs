#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Canonical, bounded, export-free request and response frames for the
//! ordinary Liquid wallet-facts boundary.
//!
//! This crate is an internal Rust `rlib`. It defines no C ABI, native symbol,
//! dynamic-library loader, key-provider boundary, wallet invocation, or chain
//! authority.

mod reader;
mod request;
mod response;
mod writer;

#[cfg(test)]
mod tests;

use core::fmt;
use zeroize::Zeroize;

pub use request::{
    EncodedWalletFactsRequest, ParsedWalletFactsRequest, PreparedWalletFactsRequest,
    WalletFactsCandidateRef, WalletFactsRequestRef, decode_request, encode_request,
};
pub use response::{
    DecodedOwnedOutput, DecodedTransactionInput, DecodedWalletFactsResponse,
    DecodedWalletTransaction, EncodedWalletFactsResponse, decode_response, encode_response,
};
pub use wasabi_liquid_native_wallet_facts::{DescriptorBranch, DescriptorNetwork};

/// Maximum byte length accepted before request structure is inspected.
pub const MAX_REQUEST_FRAME_BYTES: usize = 268_435_456;
/// Maximum byte length accepted before response structure is inspected.
pub const MAX_RESPONSE_FRAME_BYTES: usize = 268_435_456;
/// Largest request reachable under every component limit.
pub const MAX_REACHABLE_REQUEST_BYTES: usize = 67_240_012;
/// Largest response reachable under every component limit.
pub const MAX_REACHABLE_RESPONSE_BYTES: usize = 80_599_492;
/// Maximum aggregate observed inputs in one response.
pub const MAX_AGGREGATE_INPUTS: usize = 1_636_801;
/// Maximum aggregate owned outputs in one response.
pub const MAX_AGGREGATE_OWNED_OUTPUTS: usize = 148_470;
/// Maximum observed inputs in one transaction.
pub const MAX_INPUTS_PER_TRANSACTION: usize = 102_298;
/// Maximum observed owned outputs in one transaction.
pub const MAX_OWNED_OUTPUTS_PER_TRANSACTION: usize = 9_279;
/// Maximum accepted positive owned-output value.
pub const MAX_OWNED_OUTPUT_VALUE: u64 = 0x7fff_ffff_ffff_ffff;
/// Maximum accepted spendable output index.
pub const MAX_SPENDABLE_OUTPUT_INDEX: u32 = 0x3fff_ffff;
/// Exact native P2WPKH script length in a response.
pub const NATIVE_P2WPKH_SCRIPT_BYTES: usize = 22;

/// A stable, privacy-redacted wallet-facts wire failure.
#[derive(Clone, Copy, Eq, PartialEq)]
#[non_exhaustive]
pub enum WalletFactsWireError {
    /// An API argument cannot represent a valid operation.
    InvalidArgument,
    /// The frame magic, version, or header length is unsupported.
    VersionMismatch,
    /// The frame is malformed or noncanonical.
    InvalidEncoding,
    /// A fixed, aggregate, or arithmetic limit was exceeded.
    LimitExceeded,
    /// The existing descriptor catalog rejected the descriptor.
    DescriptorRejected,
    /// The existing candidate batch rejected the transaction set.
    CandidateRejected,
    /// A native observation cannot be represented canonically.
    ObservationRejected,
    /// A response binding differs from the expected request binding.
    SourceBindingMismatch,
}

impl WalletFactsWireError {
    /// Returns the frozen numeric error code.
    pub const fn code(self) -> u32 {
        match self {
            Self::InvalidArgument => 1,
            Self::VersionMismatch => 2,
            Self::InvalidEncoding => 3,
            Self::LimitExceeded => 4,
            Self::DescriptorRejected => 5,
            Self::CandidateRejected => 6,
            Self::ObservationRejected => 7,
            Self::SourceBindingMismatch => 8,
        }
    }
}

impl fmt::Display for WalletFactsWireError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidArgument => "wallet facts wire argument is invalid",
            Self::VersionMismatch => "wallet facts wire version is unsupported",
            Self::InvalidEncoding => "wallet facts wire encoding is invalid",
            Self::LimitExceeded => "wallet facts wire limit exceeded",
            Self::DescriptorRejected => "wallet facts descriptor was rejected",
            Self::CandidateRejected => "wallet facts candidate batch was rejected",
            Self::ObservationRejected => "wallet facts observation was rejected",
            Self::SourceBindingMismatch => "wallet facts source binding does not match",
        })
    }
}

impl fmt::Debug for WalletFactsWireError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidArgument => "InvalidArgument",
            Self::VersionMismatch => "VersionMismatch",
            Self::InvalidEncoding => "InvalidEncoding",
            Self::LimitExceeded => "LimitExceeded",
            Self::DescriptorRejected => "DescriptorRejected",
            Self::CandidateRejected => "CandidateRejected",
            Self::ObservationRejected => "ObservationRejected",
            Self::SourceBindingMismatch => "SourceBindingMismatch",
        })
    }
}

impl std::error::Error for WalletFactsWireError {}

fn is_nonzero(bytes: &[u8]) -> bool {
    bytes.iter().any(|byte| *byte != 0)
}

struct ScopedWireBytes<const LENGTH: usize>([u8; LENGTH]);

impl<const LENGTH: usize> Drop for ScopedWireBytes<LENGTH> {
    fn drop(&mut self) {
        self.0.zeroize();
        #[cfg(test)]
        note_drop(DropKind::Temporary, self.0.iter().all(|byte| *byte == 0));
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Default)]
struct DropAudit {
    encoded_request: usize,
    encoded_response: usize,
    parsed_candidate: usize,
    parsed_request: usize,
    prepared_request: usize,
    decoded_input: usize,
    decoded_output: usize,
    decoded_transaction: usize,
    decoded_response: usize,
    writer: usize,
    temporary: usize,
    all_zeroized: bool,
}

#[cfg(test)]
enum DropKind {
    EncodedRequest,
    EncodedResponse,
    ParsedCandidate,
    ParsedRequest,
    PreparedRequest,
    DecodedInput,
    DecodedOutput,
    DecodedTransaction,
    DecodedResponse,
    Writer,
    Temporary,
}

#[cfg(test)]
thread_local! {
    static DROP_AUDIT: std::cell::RefCell<DropAudit> = const {
        std::cell::RefCell::new(DropAudit {
            encoded_request: 0,
            encoded_response: 0,
            parsed_candidate: 0,
            parsed_request: 0,
            prepared_request: 0,
            decoded_input: 0,
            decoded_output: 0,
            decoded_transaction: 0,
            decoded_response: 0,
            writer: 0,
            temporary: 0,
            all_zeroized: true,
        })
    };
}

#[cfg(test)]
fn note_drop(kind: DropKind, zeroized: bool) {
    DROP_AUDIT.with(|audit| {
        let mut audit = audit.borrow_mut();
        match kind {
            DropKind::EncodedRequest => audit.encoded_request += 1,
            DropKind::EncodedResponse => audit.encoded_response += 1,
            DropKind::ParsedCandidate => audit.parsed_candidate += 1,
            DropKind::ParsedRequest => audit.parsed_request += 1,
            DropKind::PreparedRequest => audit.prepared_request += 1,
            DropKind::DecodedInput => audit.decoded_input += 1,
            DropKind::DecodedOutput => audit.decoded_output += 1,
            DropKind::DecodedTransaction => audit.decoded_transaction += 1,
            DropKind::DecodedResponse => audit.decoded_response += 1,
            DropKind::Writer => audit.writer += 1,
            DropKind::Temporary => audit.temporary += 1,
        }
        audit.all_zeroized &= zeroized;
    });
}

#[cfg(test)]
fn reset_drop_audit() {
    DROP_AUDIT.with(|audit| {
        *audit.borrow_mut() = DropAudit {
            all_zeroized: true,
            ..DropAudit::default()
        };
    });
}

#[cfg(test)]
fn drop_audit() -> DropAudit {
    DROP_AUDIT.with(|audit| *audit.borrow())
}
