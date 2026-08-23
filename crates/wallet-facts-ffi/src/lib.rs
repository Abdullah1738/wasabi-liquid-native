#![deny(missing_docs)]
#![deny(unsafe_op_in_unsafe_fn)]

//! Stateless C ABI adapter for bounded native wallet-facts observation.
//!
//! The adapter accepts one canonical WLFQ v1 request and returns the canonical
//! WLFV v1 response produced by the full native observer. It owns no wallet,
//! node, signer, broadcaster, key custody, fee policy, or persistent state.

use core::{ptr, slice};
use std::panic::{AssertUnwindSafe, catch_unwind};

use rand::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};
use wasabi_liquid_native_wallet_facts::{BorrowedSlip77, observe_owned_outputs};
use wasabi_liquid_native_wallet_facts_wire::{
    MAX_REACHABLE_RESPONSE_BYTES, WalletFactsWireError, decode_request, encode_response,
};
use zeroize::Zeroize;

/// Frozen wallet-facts observation ABI version.
pub const WLN_WALLET_FACTS_ABI_VERSION_V1: u32 = 1;
/// Outer request cap checked before caller memory is read.
pub const WLN_WALLET_FACTS_MAX_REQUEST_FRAME_BYTES_V1: u64 = 268_435_456;
/// Outer response cap.
pub const WLN_WALLET_FACTS_MAX_RESPONSE_FRAME_BYTES_V1: u64 = 268_435_456;
/// Largest response reachable under the frozen WLFV v1 limits.
pub const WLN_WALLET_FACTS_MAX_REACHABLE_RESPONSE_BYTES_V1: u64 = 80_599_492;

/// Observation succeeded and the complete response was copied.
pub const WLN_WALLET_FACTS_STATUS_OK_V1: i32 = 0;
/// A pointer, length, or capacity shape is invalid.
pub const WLN_WALLET_FACTS_STATUS_INVALID_ARGUMENT_V1: i32 = -1;
/// The WLFQ magic, version, or header is unsupported.
pub const WLN_WALLET_FACTS_STATUS_VERSION_MISMATCH_V1: i32 = -2;
/// The WLFQ encoding is malformed or noncanonical.
pub const WLN_WALLET_FACTS_STATUS_INVALID_ENCODING_V1: i32 = -3;
/// A frozen request or response limit was exceeded.
pub const WLN_WALLET_FACTS_STATUS_LIMIT_EXCEEDED_V1: i32 = -4;
/// Descriptor derivation rejected the request.
pub const WLN_WALLET_FACTS_STATUS_DESCRIPTOR_REJECTED_V1: i32 = -5;
/// Candidate construction rejected the request.
pub const WLN_WALLET_FACTS_STATUS_CANDIDATE_REJECTED_V1: i32 = -6;
/// The full native observation rejected the candidate batch.
pub const WLN_WALLET_FACTS_STATUS_OBSERVATION_REJECTED_V1: i32 = -7;
/// The supplied source binding does not match.
pub const WLN_WALLET_FACTS_STATUS_SOURCE_BINDING_MISMATCH_V1: i32 = -8;
/// A contained panic or impossible invariant was encountered.
pub const WLN_WALLET_FACTS_STATUS_INTERNAL_ERROR_V1: i32 = -9;
/// The response buffer is absent or too small; required length is published.
pub const WLN_WALLET_FACTS_STATUS_OUTPUT_CAPACITY_V1: i32 = -10;

struct ScopedBytes(Vec<u8>);

impl Drop for ScopedBytes {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

struct ScopedSecret([u8; 32]);

impl Drop for ScopedSecret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// SHA-256 Hash-DRBG over caller-owned entropy, domain-separated from signing.
struct HashDrbg {
    state: [u8; 32],
    counter: u64,
}

impl HashDrbg {
    fn new(seed: &[u8; 32]) -> Self {
        Self {
            state: Sha256::new_with_prefix(b"WLN_WALLET_FACTS_HASH_DRBG_V1")
                .chain_update(seed)
                .finalize()
                .into(),
            counter: 0,
        }
    }

    fn reseed_from_output(&mut self) {
        self.state = Sha256::new_with_prefix(b"WLN_WALLET_FACTS_HASH_DRBG_V1_RESEED")
            .chain_update(self.state)
            .finalize()
            .into();
        self.counter = 0;
    }
}

impl RngCore for HashDrbg {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0; 4];
        self.fill_bytes(&mut bytes);
        u32::from_le_bytes(bytes)
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0; 8];
        self.fill_bytes(&mut bytes);
        u64::from_le_bytes(bytes)
    }

    fn fill_bytes(&mut self, destination: &mut [u8]) {
        for chunk in destination.chunks_mut(32) {
            let block: [u8; 32] = Sha256::new_with_prefix(b"WLN_WALLET_FACTS_HASH_DRBG_V1_BLOCK")
                .chain_update(self.state)
                .chain_update(self.counter.to_le_bytes())
                .finalize()
                .into();
            chunk.copy_from_slice(&block[..chunk.len()]);
            if self.counter == u64::MAX {
                self.reseed_from_output();
            } else {
                self.counter += 1;
            }
        }
    }

    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), rand::Error> {
        self.fill_bytes(destination);
        Ok(())
    }
}

impl CryptoRng for HashDrbg {}

impl Drop for HashDrbg {
    fn drop(&mut self) {
        self.state.zeroize();
        self.counter.zeroize();
    }
}

/// Observes caller-supplied candidate transactions through the full native
/// wallet-facts pipeline and emits one canonical WLFV v1 response.
///
/// A null/zero output is a capacity query. `out_response_length` is mandatory;
/// only success and output-capacity outcomes may leave it nonzero. All inputs
/// are copied into scoped native storage and the borrowed SLIP-77 master is not
/// retained.
///
/// # Safety
///
/// `request_frame` must reference `request_frame_length` readable immutable
/// bytes. `expected_source_epoch`, `slip77_master_key`, and a 32-byte `entropy`
/// must remain readable and immutable until return. A non-null `out_response`
/// must reference `out_response_capacity` writable bytes and
/// `out_response_length` must reference one writable `u64`. Mutable outputs
/// must not overlap each other or any borrowed input. Null and length shapes
/// are checked before dereference, but a C ABI cannot validate arbitrary
/// non-null pointer provenance.
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn wln_wallet_facts_observe_impl_v1(
    request_frame: *const u8,
    request_frame_length: u64,
    expected_source_epoch: *const u8,
    slip77_master_key: *const u8,
    out_response: *mut u8,
    out_response_capacity: u64,
    out_response_length: *mut u64,
    entropy: *const u8,
    entropy_length: u64,
) -> i32 {
    if out_response_length.is_null() {
        return WLN_WALLET_FACTS_STATUS_INVALID_ARGUMENT_V1;
    }

    let outcome = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: The caller contract requires a writable non-overlapping u64;
        // null was the sole check before entering this panic boundary.
        unsafe { ptr::write(out_response_length, 0) };

        if request_frame.is_null()
            || request_frame_length == 0
            || expected_source_epoch.is_null()
            || slip77_master_key.is_null()
            || entropy.is_null()
            || entropy_length != 32
            || (out_response.is_null() && out_response_capacity != 0)
        {
            return Err(WLN_WALLET_FACTS_STATUS_INVALID_ARGUMENT_V1);
        }
        if request_frame_length > WLN_WALLET_FACTS_MAX_REQUEST_FRAME_BYTES_V1 {
            return Err(WLN_WALLET_FACTS_STATUS_LIMIT_EXCEEDED_V1);
        }
        let request_frame_length = usize::try_from(request_frame_length)
            .map_err(|_| WLN_WALLET_FACTS_STATUS_INVALID_ARGUMENT_V1)?;
        let out_response_capacity = usize::try_from(out_response_capacity)
            .map_err(|_| WLN_WALLET_FACTS_STATUS_INVALID_ARGUMENT_V1)?;

        let request = ScopedBytes(
            // SAFETY: The caller contract supplies this readable region; null,
            // zero, outer cap, and usize conversion were checked first.
            unsafe { slice::from_raw_parts(request_frame, request_frame_length) }.to_vec(),
        );
        let mut epoch = ScopedSecret([0; 32]);
        let mut slip77 = ScopedSecret([0; 32]);
        let mut entropy_seed = ScopedSecret([0; 32]);
        // SAFETY: Each caller pointer is non-null and references exactly 32
        // readable bytes for this call. Destinations are distinct local arrays.
        unsafe {
            ptr::copy_nonoverlapping(expected_source_epoch, epoch.0.as_mut_ptr(), 32);
            ptr::copy_nonoverlapping(slip77_master_key, slip77.0.as_mut_ptr(), 32);
            ptr::copy_nonoverlapping(entropy, entropy_seed.0.as_mut_ptr(), 32);
        }
        maybe_inject_test_panic(PanicPoint::RequestStaging);
        if epoch.0.iter().all(|byte| *byte == 0) {
            return Err(WLN_WALLET_FACTS_STATUS_INVALID_ARGUMENT_V1);
        }

        let parsed = decode_request(&request.0).map_err(wire_status)?;
        if parsed.source_epoch() != &epoch.0 {
            return Err(WLN_WALLET_FACTS_STATUS_SOURCE_BINDING_MISMATCH_V1);
        }
        let reencoded = parsed.reencode().map_err(wire_status)?;
        if reencoded.as_bytes() != request.0 {
            return Err(WLN_WALLET_FACTS_STATUS_INVALID_ENCODING_V1);
        }
        drop(reencoded);
        maybe_inject_test_panic(PanicPoint::Preparation);
        let prepared = parsed.prepare().map_err(wire_status)?;

        maybe_inject_test_panic(PanicPoint::Drbg);
        let mut rng = HashDrbg::new(&entropy_seed.0);
        maybe_inject_test_panic(PanicPoint::Observation);
        let observations = observe_owned_outputs(
            prepared.descriptor_catalog(),
            BorrowedSlip77::new(&slip77.0),
            prepared.candidate_batch(),
            &mut rng,
        )
        .map_err(|_| WLN_WALLET_FACTS_STATUS_OBSERVATION_REJECTED_V1)?;

        maybe_inject_test_panic(PanicPoint::PerScriptDerivation);
        maybe_inject_test_panic(PanicPoint::Encoding);
        let encoded =
            encode_response(&observations, prepared.source_epoch()).map_err(response_status)?;
        let response = ScopedBytes(encoded.as_bytes().to_vec());
        drop(encoded);
        maybe_inject_test_panic(PanicPoint::ResponseScratch);
        if response.0.len() > MAX_REACHABLE_RESPONSE_BYTES
            || response.0.len() as u64 > WLN_WALLET_FACTS_MAX_RESPONSE_FRAME_BYTES_V1
        {
            return Err(WLN_WALLET_FACTS_STATUS_LIMIT_EXCEEDED_V1);
        }
        if response.0.get(32..64) != Some(epoch.0.as_slice()) {
            return Err(WLN_WALLET_FACTS_STATUS_SOURCE_BINDING_MISMATCH_V1);
        }
        let required = response.0.len() as u64;
        // SAFETY: The caller supplied one writable u64 and it does not overlap
        // inputs or the response buffer.
        unsafe { ptr::write(out_response_length, required) };
        maybe_inject_test_panic(PanicPoint::PreCopy);

        if out_response.is_null() || response.0.len() > out_response_capacity {
            return Err(WLN_WALLET_FACTS_STATUS_OUTPUT_CAPACITY_V1);
        }
        // SAFETY: The caller supplied a non-overlapping writable buffer whose
        // checked capacity covers the complete response.
        unsafe { ptr::copy_nonoverlapping(response.0.as_ptr(), out_response, response.0.len()) };
        Ok(WLN_WALLET_FACTS_STATUS_OK_V1)
    }));

    let status = match outcome {
        Ok(Ok(status)) | Ok(Err(status)) => status,
        Err(_) => WLN_WALLET_FACTS_STATUS_INTERNAL_ERROR_V1,
    };
    if status != WLN_WALLET_FACTS_STATUS_OK_V1
        && status != WLN_WALLET_FACTS_STATUS_OUTPUT_CAPACITY_V1
    {
        // SAFETY: This mandatory completion normalization is permitted by the
        // caller's writable, non-overlapping out-parameter contract.
        unsafe { ptr::write(out_response_length, 0) };
    }
    status
}

fn wire_status(error: WalletFactsWireError) -> i32 {
    -(error.code() as i32)
}

fn response_status(error: WalletFactsWireError) -> i32 {
    match error {
        WalletFactsWireError::LimitExceeded => WLN_WALLET_FACTS_STATUS_LIMIT_EXCEEDED_V1,
        WalletFactsWireError::SourceBindingMismatch => {
            WLN_WALLET_FACTS_STATUS_SOURCE_BINDING_MISMATCH_V1
        }
        _ => WLN_WALLET_FACTS_STATUS_INTERNAL_ERROR_V1,
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Eq, PartialEq)]
enum PanicPoint {
    RequestStaging,
    Preparation,
    Drbg,
    Observation,
    PerScriptDerivation,
    Encoding,
    ResponseScratch,
    PreCopy,
}

#[cfg(test)]
thread_local! {
    static TEST_PANIC_POINT: core::cell::Cell<Option<PanicPoint>> = const {
        core::cell::Cell::new(None)
    };
}

#[cfg(test)]
fn maybe_inject_test_panic(point: PanicPoint) {
    TEST_PANIC_POINT.with(|selected| {
        if selected.get() == Some(point) {
            selected.set(None);
            panic!("wallet-facts FFI injected panic");
        }
    });
}

#[cfg(not(test))]
enum PanicPoint {
    RequestStaging,
    Preparation,
    Drbg,
    Observation,
    PerScriptDerivation,
    Encoding,
    ResponseScratch,
    PreCopy,
}

#[cfg(not(test))]
const fn maybe_inject_test_panic(_point: PanicPoint) {}

#[cfg(test)]
mod tests {
    use super::*;
    use wasabi_liquid_native_wallet_facts_wire::{
        DescriptorNetwork, WalletFactsRequestRef, encode_request,
    };

    const DESCRIPTOR: &str = "elwpkh([28b3f14e/84'/1'/0']tpubDC2Q4xK4XH72GM7MowNuajyWVbigRLBWKswyP5T88hpPwu5nGqJWnda8zhJEFt71av73Hm8mUMMFSz9acNVzz8b1UbdSHCDXKTbSv5eEytu/<0;1>/*)#u0khc0kg";
    const EPOCH: [u8; 32] = [0x41; 32];
    const KEY: [u8; 32] = [0x52; 32];
    const ENTROPY: [u8; 32] = [0x63; 32];

    fn request() -> Vec<u8> {
        encode_request(&WalletFactsRequestRef::new(
            &EPOCH,
            DescriptorNetwork::Test,
            0,
            DESCRIPTOR,
            &[],
        ))
        .unwrap()
        .as_bytes()
        .to_vec()
    }

    #[test]
    fn all_injected_panics_are_contained_and_normalize_length() {
        let request = request();
        for point in [
            PanicPoint::RequestStaging,
            PanicPoint::Preparation,
            PanicPoint::Drbg,
            PanicPoint::Observation,
            PanicPoint::PerScriptDerivation,
            PanicPoint::Encoding,
            PanicPoint::ResponseScratch,
            PanicPoint::PreCopy,
        ] {
            TEST_PANIC_POINT.with(|selected| selected.set(Some(point)));
            let mut output = [0xa5; 64];
            let mut length = 777;
            let status = unsafe {
                wln_wallet_facts_observe_impl_v1(
                    request.as_ptr(),
                    request.len() as u64,
                    EPOCH.as_ptr(),
                    KEY.as_ptr(),
                    output.as_mut_ptr(),
                    output.len() as u64,
                    &mut length,
                    ENTROPY.as_ptr(),
                    32,
                )
            };
            assert_eq!(status, WLN_WALLET_FACTS_STATUS_INTERNAL_ERROR_V1);
            assert_eq!(length, 0);
            assert_eq!(output, [0xa5; 64]);
        }
    }
}
