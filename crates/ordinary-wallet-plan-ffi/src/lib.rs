#![deny(missing_docs)]
#![deny(unsafe_op_in_unsafe_fn)]

//! Minimal C ABI for canonical WLPQ v1 frame validation.
//!
//! This crate deliberately exposes one stateless operation. It has no handle,
//! callback, allocator, provider, signer, PSET, transaction, node, reservation,
//! currentness, broadcast, or release authority.

use core::{ptr, slice};
use std::panic::{AssertUnwindSafe, catch_unwind};

use wasabi_liquid_native_ordinary_wallet_plan::{OrdinaryWalletPlanWireError, decode_request};
use zeroize::Zeroize;

/// The frozen WLPQ FFI version.
pub const WLN_WLPQ_ABI_VERSION_V1: u32 = 1;
/// The WLPQ outer frame cap enforced before borrowed memory is read.
pub const WLN_WLPQ_MAX_FRAME_BYTES_V1: u64 = 268_435_456;

/// Successful canonical validation.
pub const WLN_WLPQ_STATUS_OK_V1: i32 = 0;
/// A null pointer, empty frame, or nonrepresentable length.
pub const WLN_WLPQ_STATUS_INVALID_ARGUMENT_V1: i32 = -1;
/// An unsupported WLPQ magic, version, or header length.
pub const WLN_WLPQ_STATUS_VERSION_MISMATCH_V1: i32 = -2;
/// A malformed or noncanonical WLPQ frame.
pub const WLN_WLPQ_STATUS_INVALID_ENCODING_V1: i32 = -3;
/// A numeric, component, aggregate, arithmetic, or frame limit was exceeded.
pub const WLN_WLPQ_STATUS_LIMIT_EXCEEDED_V1: i32 = -4;
/// The encoded source epoch did not match the expected epoch.
pub const WLN_WLPQ_STATUS_SOURCE_BINDING_MISMATCH_V1: i32 = -5;
/// The reviewed manifest or pegged asset was rejected during re-encoding.
pub const WLN_WLPQ_STATUS_CONTEXT_REJECTED_V1: i32 = -6;
/// A destination or declared exact balance was rejected during re-encoding.
pub const WLN_WLPQ_STATUS_PLAN_REJECTED_V1: i32 = -7;
/// Public funding validation was rejected.
pub const WLN_WLPQ_STATUS_FUNDING_REJECTED_V1: i32 = -8;
/// Native validation panicked or violated its decode/re-encode invariant.
pub const WLN_WLPQ_STATUS_INTERNAL_ERROR_V1: i32 = -9;

struct ScopedFrame(Vec<u8>);

impl Drop for ScopedFrame {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

struct ScopedEpoch([u8; 32]);

impl Drop for ScopedEpoch {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Validates one canonical WLPQ v1 frame against an exact source epoch.
///
/// Success means the existing native decoder accepted the frame and its owned
/// representation re-encoded to the exact same bytes. Native frame and epoch
/// copies are cleared on ordinary return and unwind. This operation retains no
/// state and invokes no caller callback.
///
/// # Safety
///
/// `frame` must reference `frame_length` readable bytes and
/// `expected_source_epoch` must reference 32 readable bytes. Both regions must
/// remain immutable and valid until the function returns. A null pointer is
/// rejected before dereference, but no C ABI can validate arbitrary non-null
/// pointer provenance.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wln_wlpq_validate_impl_v1(
    frame: *const u8,
    frame_length: u64,
    expected_source_epoch: *const u8,
) -> i32 {
    if frame.is_null() || expected_source_epoch.is_null() || frame_length == 0 {
        return WLN_WLPQ_STATUS_INVALID_ARGUMENT_V1;
    }
    if frame_length > WLN_WLPQ_MAX_FRAME_BYTES_V1 {
        return WLN_WLPQ_STATUS_LIMIT_EXCEEDED_V1;
    }
    let Ok(frame_length) = usize::try_from(frame_length) else {
        return WLN_WLPQ_STATUS_INVALID_ARGUMENT_V1;
    };

    let outcome = catch_unwind(AssertUnwindSafe(|| {
        let mut epoch = ScopedEpoch([0; 32]);
        // SAFETY: The caller contract requires a readable 32-byte epoch for
        // the duration of this call; null was rejected before this copy.
        unsafe {
            ptr::copy_nonoverlapping(expected_source_epoch, epoch.0.as_mut_ptr(), epoch.0.len());
        }
        // SAFETY: The caller contract requires `frame_length` readable bytes
        // for the duration of this call; null and the outer cap were checked.
        let frame = ScopedFrame(unsafe { slice::from_raw_parts(frame, frame_length) }.to_vec());
        maybe_inject_test_panic();

        let decoded = decode_request(&frame.0, &epoch.0).map_err(wire_status)?;
        let reencoded = decoded.reencode().map_err(wire_status)?;
        if reencoded.as_bytes() != frame.0 {
            return Err(WLN_WLPQ_STATUS_INTERNAL_ERROR_V1);
        }
        Ok(WLN_WLPQ_STATUS_OK_V1)
    }));

    match outcome {
        Ok(Ok(status)) | Ok(Err(status)) => status,
        Err(_) => WLN_WLPQ_STATUS_INTERNAL_ERROR_V1,
    }
}

fn wire_status(error: OrdinaryWalletPlanWireError) -> i32 {
    -(error.code() as i32)
}

#[cfg(test)]
std::thread_local! {
    static INJECT_TEST_PANIC: core::cell::Cell<bool> = const { core::cell::Cell::new(false) };
}

#[cfg(test)]
fn maybe_inject_test_panic() {
    INJECT_TEST_PANIC.with(|armed| {
        if armed.replace(false) {
            panic!("WLPQ FFI validation test panic");
        }
    });
}

#[cfg(not(test))]
const fn maybe_inject_test_panic() {}

#[cfg(test)]
mod tests {
    use core::ptr;

    use super::*;

    const VALID_FRAME_HEX: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../contracts/ordinary-wallet-plan/v1/nonlinkable-reference/vectors/frames/frame-test-toy-single.hex"
    ));
    const LIMIT_FRAME_HEX: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../contracts/ordinary-wallet-plan/v1/nonlinkable-reference/vectors/frames/frame-candidate-length-plus-one.hex"
    ));
    const INVALID_FRAME_HEX: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../contracts/ordinary-wallet-plan/v1/nonlinkable-reference/vectors/frames/frame-truncated-body.hex"
    ));
    const VERSION_FRAME_HEX: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../contracts/ordinary-wallet-plan/v1/nonlinkable-reference/vectors/frames/frame-wrong-magic.hex"
    ));
    const SOURCE_EPOCH: [u8; 32] = [0x41; 32];

    #[test]
    fn frozen_statuses_match_native_wire_codes() {
        let rows = [
            (OrdinaryWalletPlanWireError::InvalidArgument, -1),
            (OrdinaryWalletPlanWireError::VersionMismatch, -2),
            (OrdinaryWalletPlanWireError::InvalidEncoding, -3),
            (OrdinaryWalletPlanWireError::LimitExceeded, -4),
            (OrdinaryWalletPlanWireError::SourceBindingMismatch, -5),
            (OrdinaryWalletPlanWireError::ContextRejected, -6),
            (OrdinaryWalletPlanWireError::PlanRejected, -7),
            (OrdinaryWalletPlanWireError::FundingRejected, -8),
        ];
        for (error, expected) in rows {
            assert_eq!(wire_status(error), expected);
        }
        assert_eq!(WLN_WLPQ_ABI_VERSION_V1, 1);
        assert_eq!(WLN_WLPQ_MAX_FRAME_BYTES_V1, 268_435_456);
    }

    #[test]
    fn canonical_corpus_frame_crosses_the_ffi_byte_identically() {
        let frame = decode_hex(VALID_FRAME_HEX);
        // SAFETY: Both borrowed buffers remain immutable and valid for the call.
        let status = unsafe {
            wln_wlpq_validate_impl_v1(frame.as_ptr(), frame.len() as u64, SOURCE_EPOCH.as_ptr())
        };
        assert_eq!(status, WLN_WLPQ_STATUS_OK_V1);
    }

    #[test]
    fn ffi_rejects_every_structural_boundary_without_diagnostics() {
        for (hex, expected) in [
            (VERSION_FRAME_HEX, WLN_WLPQ_STATUS_VERSION_MISMATCH_V1),
            (INVALID_FRAME_HEX, WLN_WLPQ_STATUS_INVALID_ENCODING_V1),
            (LIMIT_FRAME_HEX, WLN_WLPQ_STATUS_LIMIT_EXCEEDED_V1),
        ] {
            let frame = decode_hex(hex);
            // SAFETY: Both borrowed buffers remain immutable and valid for the call.
            let actual = unsafe {
                wln_wlpq_validate_impl_v1(frame.as_ptr(), frame.len() as u64, SOURCE_EPOCH.as_ptr())
            };
            assert_eq!(actual, expected);
        }

        let frame = decode_hex(VALID_FRAME_HEX);
        let wrong_epoch = [0x42; 32];
        // SAFETY: Both borrowed buffers remain immutable and valid for the call.
        let actual = unsafe {
            wln_wlpq_validate_impl_v1(frame.as_ptr(), frame.len() as u64, wrong_epoch.as_ptr())
        };
        assert_eq!(actual, WLN_WLPQ_STATUS_SOURCE_BINDING_MISMATCH_V1);
    }

    #[test]
    fn pointer_and_length_checks_precede_every_borrow() {
        let byte = 0_u8;
        assert_eq!(
            // SAFETY: Null is intentionally supplied to exercise pre-dereference validation.
            unsafe { wln_wlpq_validate_impl_v1(ptr::null(), 1, SOURCE_EPOCH.as_ptr()) },
            WLN_WLPQ_STATUS_INVALID_ARGUMENT_V1
        );
        assert_eq!(
            // SAFETY: Null is intentionally supplied to exercise pre-dereference validation.
            unsafe { wln_wlpq_validate_impl_v1(&byte, 1, ptr::null()) },
            WLN_WLPQ_STATUS_INVALID_ARGUMENT_V1
        );
        assert_eq!(
            // SAFETY: Zero length is rejected before the non-null pointer is read.
            unsafe { wln_wlpq_validate_impl_v1(&byte, 0, SOURCE_EPOCH.as_ptr()) },
            WLN_WLPQ_STATUS_INVALID_ARGUMENT_V1
        );
        assert_eq!(
            // SAFETY: The oversized length is rejected before the one-byte pointer is read.
            unsafe {
                wln_wlpq_validate_impl_v1(
                    &byte,
                    WLN_WLPQ_MAX_FRAME_BYTES_V1 + 1,
                    SOURCE_EPOCH.as_ptr(),
                )
            },
            WLN_WLPQ_STATUS_LIMIT_EXCEEDED_V1
        );
    }

    #[test]
    fn panic_is_contained_as_a_redacted_internal_error() {
        let frame = decode_hex(VALID_FRAME_HEX);
        INJECT_TEST_PANIC.with(|armed| armed.set(true));
        // SAFETY: Both borrowed buffers remain immutable and valid for the call.
        let actual = unsafe {
            wln_wlpq_validate_impl_v1(frame.as_ptr(), frame.len() as u64, SOURCE_EPOCH.as_ptr())
        };
        assert_eq!(actual, WLN_WLPQ_STATUS_INTERNAL_ERROR_V1);
        INJECT_TEST_PANIC.with(|armed| assert!(!armed.get()));
    }

    fn decode_hex(text: &str) -> Vec<u8> {
        let text = text
            .strip_suffix('\n')
            .expect("fixture has one terminal LF");
        assert_eq!(text.len() % 2, 0);
        text.as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let pair = core::str::from_utf8(pair).expect("fixture hex is ASCII");
                u8::from_str_radix(pair, 16).expect("fixture hex is canonical")
            })
            .collect()
    }
}
