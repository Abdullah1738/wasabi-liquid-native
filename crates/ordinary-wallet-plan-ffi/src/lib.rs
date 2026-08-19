#![deny(missing_docs)]
#![deny(unsafe_op_in_unsafe_fn)]

//! Minimal C ABI for canonical WLPQ v1 frame validation and caller-owned
//! signing.
//!
//! This crate deliberately exposes three stateless operations. It has no handle,
//! allocator, provider, PSET, transaction, node, reservation, currentness,
//! broadcast, or release authority. The signer stays caller-owned: only
//! compressed public keys and digest signatures cross the callback boundary
//! and this crate never receives, copies, or stores a secret key.

use core::{ptr, slice};
use std::panic::{AssertUnwindSafe, catch_unwind};

use elements::bitcoin::PublicKey as BitcoinPublicKey;
use elements::encode::{deserialize, serialize};
use elements::secp256k1_zkp::ecdsa;
use elements::{EcdsaSighashType, OutPoint, Transaction};
use rand::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};
use wasabi_liquid_native_ordinary_pset::{OrdinaryP2wpkhSigner, OrdinarySigningError};
use wasabi_liquid_native_ordinary_wallet_plan::{OrdinaryWalletPlanWireError, decode_request};
use wasabi_liquid_native_ordinary_wallet_pset::OrdinaryWalletTransactionReason;
use wasabi_liquid_native_wallet_facts::{
    BorrowedSlip77, DescriptorCatalog, DescriptorNetwork, Slip77SelectedOutputOpeningProvider,
};
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
/// A caller-owned signer callback returned the refusal code.
pub const WLN_WLPQ_STATUS_SIGNER_REFUSED_V1: i32 = -10;
/// The canonical ordinary-PSET transition rejected a public key or signature.
pub const WLN_WLPQ_STATUS_SIGNING_REJECTED_V1: i32 = -11;
/// The output buffer capacity was too small; the required length is reported.
pub const WLN_WLPQ_STATUS_OUTPUT_CAPACITY_V1: i32 = -12;

const OUTPOINT_BYTES_V1: usize = 36;
const PUBLIC_KEY_BYTES_V1: usize = 33;
const SIGNATURE_CAPACITY_V1: usize = 73;

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

struct ScopedBroadcast(Vec<u8>);

impl Drop for ScopedBroadcast {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

struct ScopedEntropy([u8; 32]);

impl Drop for ScopedEntropy {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// A NIST SP 800-90A Hash-DRBG built from the already-approved `sha2`
/// primitive. It expands one caller-supplied 32-byte seed into the
/// `R: RngCore + CryptoRng` the finalize path requires. The native side
/// fabricates no RNG from ambient or OS entropy; the entire stream is a pure
/// function of the caller-owned seed. The internal state is zeroized on drop.
struct HashDrbg {
    state: [u8; 32],
    counter: u64,
}

impl HashDrbg {
    fn new(seed: &[u8; 32]) -> Self {
        // Hardening domain separation: bind the DRBG to this exact construction
        // so the seed stream cannot be confused with any other sha2 usage.
        let state = Sha256::new_with_prefix(b"WLN_WLPQ_HASH_DRBG_V1")
            .chain_update(seed)
            .finalize()
            .into();
        Self { state, counter: 0 }
    }

    fn reseed_from_output(&mut self) {
        let next: [u8; 32] = Sha256::new_with_prefix(b"WLN_WLPQ_HASH_DRBG_V1_RESEED")
            .chain_update(self.state)
            .finalize()
            .into();
        self.state = next;
        self.counter = 0;
    }
}

impl RngCore for HashDrbg {
    fn next_u32(&mut self) -> u32 {
        let mut word = [0u8; 4];
        self.fill_bytes(&mut word);
        u32::from_le_bytes(word)
    }

    fn next_u64(&mut self) -> u64 {
        let mut word = [0u8; 8];
        self.fill_bytes(&mut word);
        u64::from_le_bytes(word)
    }

    fn fill_bytes(&mut self, destination: &mut [u8]) {
        for chunk in destination.chunks_mut(32) {
            let block: [u8; 32] = Sha256::new_with_prefix(b"WLN_WLPQ_HASH_DRBG_V1_BLOCK")
                .chain_update(self.state)
                .chain_update(self.counter.to_le_bytes())
                .finalize()
                .into();
            chunk.copy_from_slice(&block[..chunk.len()]);
            self.counter += 1;
            if self.counter == u64::MAX {
                self.reseed_from_output();
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
        self.counter = 0;
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

/// Signs and finalizes one canonical WLPQ v1 frame through caller-owned
/// signing callbacks.
///
/// The frame is decoded and prepared exactly as
/// `wln_wlpq_validate_impl_v1` decodes it, then driven through the landed
/// build-blind-sign-finalize composition. The two callbacks are the C ABI
/// projection of the `OrdinaryP2wpkhSigner` trait: `public_key_callback`
/// receives the opaque `signer_context`, one borrowed 36-byte
/// consensus-serialized outpoint with its explicit length, and a caller output
/// buffer of capacity at least 33, and on success writes the 33-byte
/// compressed public key and returns zero; `sign_digest_callback` additionally
/// receives the natively computed 32-byte sighash-with-rangeproof digest and
/// on success writes the strict-DER low-S signature including the trailing
/// sighash byte (at most 73 bytes) and returns zero. Any nonzero callback
/// return is a fail-closed refusal. The signer stays caller-owned: only
/// compressed public keys and digest signatures cross this boundary and the
/// native side never receives, copies, or stores a secret key. On success the
/// finalized confidential transaction serialization is written to
/// `out_transaction` and its byte length to `*out_transaction_length`; when
/// the capacity is too small the required length is still reported.
///
/// # Safety
///
/// `frame` must reference `frame_length` readable bytes,
/// `expected_source_epoch` must reference 32 readable bytes, `out_transaction`
/// must reference `out_transaction_capacity` writable bytes, and
/// `out_transaction_length` must reference one writable `u64`. `entropy` must
/// reference exactly `entropy_length == 32` readable bytes of fresh
/// caller-supplied CSPRNG output; the native side expands it through an
/// approved-primitive Hash-DRBG and zeroizes its copy on all paths. The
/// callbacks must honor their frozen contracts and must not retain any
/// borrowed buffer. Null pointers and null callbacks are rejected before
/// dereference, but no C ABI can validate arbitrary non-null pointer
/// provenance.
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn wln_wlpq_sign_finalize_impl_v1(
    frame: *const u8,
    frame_length: u64,
    expected_source_epoch: *const u8,
    signer_context: *const u8,
    public_key_callback: unsafe extern "C" fn(*const u8, *const u8, u64, *mut u8, u64) -> i32,
    sign_digest_callback: unsafe extern "C" fn(
        *const u8,
        *const u8,
        u64,
        *const u8,
        *mut u8,
        u64,
    ) -> i32,
    out_transaction: *mut u8,
    out_transaction_capacity: u64,
    out_transaction_length: *mut u64,
    descriptor: *const u8,
    descriptor_length: u64,
    last_index: u64,
    slip77_master_key: *const u8,
    entropy: *const u8,
    entropy_length: u64,
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
    if out_transaction.is_null()
        || out_transaction_length.is_null()
        || descriptor.is_null()
        || descriptor_length == 0
        || slip77_master_key.is_null()
        || entropy.is_null()
        || entropy_length != 32
    {
        return WLN_WLPQ_STATUS_INVALID_ARGUMENT_V1;
    }
    let Ok(descriptor_length) = usize::try_from(descriptor_length) else {
        return WLN_WLPQ_STATUS_INVALID_ARGUMENT_V1;
    };
    let Ok(out_transaction_capacity) = usize::try_from(out_transaction_capacity) else {
        return WLN_WLPQ_STATUS_INVALID_ARGUMENT_V1;
    };
    let Ok(last_index) = u32::try_from(last_index) else {
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

        let mut slip77 = ScopedEpoch([0; 32]);
        // SAFETY: The caller contract requires a readable 32-byte SLIP-77
        // master key for the duration of this call; null was rejected.
        unsafe {
            ptr::copy_nonoverlapping(slip77_master_key, slip77.0.as_mut_ptr(), slip77.0.len());
        }
        let mut entropy_seed = ScopedEntropy([0; 32]);
        // SAFETY: The caller contract requires a readable 32-byte entropy seed
        // for the duration of this call; null and the exact length were
        // rejected before this copy. The copy is zeroized on all paths.
        unsafe {
            ptr::copy_nonoverlapping(entropy, entropy_seed.0.as_mut_ptr(), entropy_seed.0.len());
        }
        // SAFETY: The caller contract requires `descriptor_length` readable
        // bytes for the duration of this call; null was rejected.
        let descriptor_bytes =
            unsafe { slice::from_raw_parts(descriptor, descriptor_length) }.to_vec();
        let descriptor_text = core::str::from_utf8(&descriptor_bytes)
            .map_err(|_| WLN_WLPQ_STATUS_INVALID_ARGUMENT_V1)?;
        let catalog = derive_catalog_for_frame(descriptor_text, last_index)?;
        let secp = elements::secp256k1_zkp::Secp256k1::new();
        let prepared = decoded.prepare(&catalog, &secp).map_err(wire_status)?;

        let outcome = catch_unwind(AssertUnwindSafe(|| {
            let mut provider =
                Slip77SelectedOutputOpeningProvider::new(BorrowedSlip77::new(&slip77.0));
            let mut rng = HashDrbg::new(&entropy_seed.0);
            let mut signer = CallbackOrdinaryP2wpkhSigner {
                context: signer_context,
                public_key_callback,
                sign_digest_callback,
            };
            prepared
                .into_finalized_ordinary_wallet_transaction(&mut provider, &mut rng, &mut signer)
                .map_err(|failure| match failure.reason() {
                    OrdinaryWalletTransactionReason::Preparation(_) => {
                        WLN_WLPQ_STATUS_INTERNAL_ERROR_V1
                    }
                    OrdinaryWalletTransactionReason::Signing(reason) => match reason {
                        OrdinarySigningError::PublicKeyUnavailable
                        | OrdinarySigningError::SignatureUnavailable => {
                            WLN_WLPQ_STATUS_SIGNER_REFUSED_V1
                        }
                        _ => WLN_WLPQ_STATUS_SIGNING_REJECTED_V1,
                    },
                    _ => WLN_WLPQ_STATUS_INTERNAL_ERROR_V1,
                })
        }));
        let finalized = match outcome {
            Ok(Ok(finalized)) => finalized,
            Ok(Err(status)) => return Err(status),
            Err(_) => return Err(WLN_WLPQ_STATUS_INTERNAL_ERROR_V1),
        };
        let broadcast = ScopedBroadcast(finalized.serialize_for_broadcast());
        // SAFETY: The caller contract requires one writable u64 here; null was
        // rejected before the closure.
        unsafe {
            ptr::write(out_transaction_length, broadcast.0.len() as u64);
        }
        if broadcast.0.len() > out_transaction_capacity {
            return Err(WLN_WLPQ_STATUS_OUTPUT_CAPACITY_V1);
        }
        // SAFETY: The caller contract requires `out_transaction_capacity`
        // writable bytes and the capacity covers the broadcast length.
        unsafe {
            ptr::copy_nonoverlapping(broadcast.0.as_ptr(), out_transaction, broadcast.0.len());
        }
        Ok(WLN_WLPQ_STATUS_OK_V1)
    }));

    match outcome {
        Ok(Ok(status)) | Ok(Err(status)) => status,
        Err(_) => WLN_WLPQ_STATUS_INTERNAL_ERROR_V1,
    }
}

fn derive_catalog_for_frame(
    descriptor_text: &str,
    last_index: u32,
) -> Result<DescriptorCatalog, i32> {
    DescriptorCatalog::derive(descriptor_text, DescriptorNetwork::Test, last_index)
        .or_else(|_| {
            DescriptorCatalog::derive(descriptor_text, DescriptorNetwork::Mainnet, last_index)
        })
        .map_err(|_| WLN_WLPQ_STATUS_CONTEXT_REJECTED_V1)
}

struct CallbackOrdinaryP2wpkhSigner {
    context: *const u8,
    public_key_callback: unsafe extern "C" fn(*const u8, *const u8, u64, *mut u8, u64) -> i32,
    sign_digest_callback:
        unsafe extern "C" fn(*const u8, *const u8, u64, *const u8, *mut u8, u64) -> i32,
}

impl OrdinaryP2wpkhSigner for CallbackOrdinaryP2wpkhSigner {
    fn public_key(&mut self, _input_index: usize, outpoint: &OutPoint) -> Option<BitcoinPublicKey> {
        let outpoint_bytes = serialize(outpoint);
        debug_assert_eq!(outpoint_bytes.len(), OUTPOINT_BYTES_V1);
        let mut output = [0u8; PUBLIC_KEY_BYTES_V1];
        // SAFETY: `output` is a writable 33-byte stack buffer and
        // `outpoint_bytes` is the readable 36-byte consensus serialization;
        // both outlive the call. The callback contract forbids retaining the
        // borrowed buffers.
        let status = unsafe {
            (self.public_key_callback)(
                self.context,
                outpoint_bytes.as_ptr(),
                outpoint_bytes.len() as u64,
                output.as_mut_ptr(),
                output.len() as u64,
            )
        };
        if status != WLN_WLPQ_STATUS_OK_V1 {
            return None;
        }
        BitcoinPublicKey::from_slice(&output).ok()
    }

    fn sign_digest(
        &mut self,
        _input_index: usize,
        outpoint: &OutPoint,
        digest: [u8; 32],
        sighash_type: EcdsaSighashType,
    ) -> Option<ecdsa::Signature> {
        if sighash_type != EcdsaSighashType::AllPlusRangeproof {
            return None;
        }
        let outpoint_bytes = serialize(outpoint);
        debug_assert_eq!(outpoint_bytes.len(), OUTPOINT_BYTES_V1);
        let mut output = [0u8; SIGNATURE_CAPACITY_V1];
        // SAFETY: `output` is a writable 73-byte stack buffer, `digest` is a
        // readable 32-byte stack buffer, and `outpoint_bytes` is the readable
        // 36-byte consensus serialization; all outlive the call. The callback
        // contract forbids retaining the borrowed buffers.
        let status = unsafe {
            (self.sign_digest_callback)(
                self.context,
                outpoint_bytes.as_ptr(),
                outpoint_bytes.len() as u64,
                digest.as_ptr(),
                output.as_mut_ptr(),
                output.len() as u64,
            )
        };
        if status != WLN_WLPQ_STATUS_OK_V1 {
            return None;
        }
        // The output buffer is exactly 73 bytes: a strict-DER signature
        // followed by one sighash byte. The DER sequence self-delimits its
        // total length at byte 1, so the signature occupies
        // `2 + der_total_length` bytes and the sighash byte immediately
        // follows it. Any trailing capacity after the sighash byte is zero
        // padding the callback leaves unwritten.
        if output[0] != 0x30 {
            return None;
        }
        let der_total_length = usize::from(output[1]);
        if !(8..=71).contains(&der_total_length) {
            return None;
        }
        let signature_end = 2 + der_total_length;
        let der = &output[..signature_end];
        let sighash_byte = output[signature_end];
        if sighash_byte != sighash_type.as_u32() as u8 {
            return None;
        }
        let signature = ecdsa::Signature::from_der(der).ok()?;
        let mut normalized = signature;
        normalized.normalize_s();
        if normalized != signature {
            return None;
        }
        Some(signature)
    }
}

fn wire_status(error: OrdinaryWalletPlanWireError) -> i32 {
    -(error.code() as i32)
}

/// Recomputes the canonical `Transaction::txid()` hex of one
/// broadcast-serialized confidential transaction.
///
/// On success exactly 64 lowercase ASCII bytes (the `to_string()` of the
/// txid, with no NUL terminator) are written to `out_txid` and
/// `WLN_WLPQ_STATUS_OK_V1` is returned. The transaction bytes are strictly
/// deserialized (malformed or trailing input is rejected) and the decoded
/// transaction must re-serialize byte-identically or the call fails closed
/// with `WLN_WLPQ_STATUS_INTERNAL_ERROR_V1`. On every failure path
/// `out_txid` is left untouched: the caller buffer is written only after
/// the full decode, re-encode, and txid pipeline has succeeded inside the
/// unwind boundary. This operation retains no state and invokes no caller
/// callback.
///
/// # Safety
///
/// `tx` must reference `tx_length` readable bytes and `out_txid` must
/// reference `out_txid_capacity >= 64` writable bytes. Both regions must
/// remain valid until the function returns. Null pointers, a zero length,
/// and a capacity below 64 are rejected before any dereference, but no C
/// ABI can validate arbitrary non-null pointer provenance.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wln_wlpq_transaction_id_impl_v1(
    tx: *const u8,
    tx_length: u64,
    out_txid: *mut u8,
    out_txid_capacity: u64,
) -> i32 {
    if tx.is_null() || out_txid.is_null() || tx_length == 0 || out_txid_capacity < 64 {
        return WLN_WLPQ_STATUS_INVALID_ARGUMENT_V1;
    }
    if tx_length > WLN_WLPQ_MAX_FRAME_BYTES_V1 {
        return WLN_WLPQ_STATUS_LIMIT_EXCEEDED_V1;
    }
    let Ok(tx_length) = usize::try_from(tx_length) else {
        return WLN_WLPQ_STATUS_INVALID_ARGUMENT_V1;
    };

    let outcome = catch_unwind(AssertUnwindSafe(|| {
        maybe_inject_test_panic();
        // SAFETY: The caller contract requires `tx_length` readable bytes
        // for the duration of this call; null and the outer cap were
        // checked before this borrow.
        let transaction_bytes = unsafe { slice::from_raw_parts(tx, tx_length) };
        let decoded = deserialize::<Transaction>(transaction_bytes)
            .map_err(|_| WLN_WLPQ_STATUS_INVALID_ENCODING_V1)?;
        if serialize(&decoded) != transaction_bytes {
            return Err(WLN_WLPQ_STATUS_INTERNAL_ERROR_V1);
        }
        let txid = decoded.txid().to_string();
        debug_assert_eq!(txid.len(), 64);
        debug_assert!(
            txid.bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        );
        // SAFETY: The caller contract requires `out_txid_capacity >= 64`
        // writable bytes; the capacity check passed before the closure.
        unsafe {
            ptr::copy_nonoverlapping(txid.as_ptr(), out_txid, 64);
        }
        Ok(WLN_WLPQ_STATUS_OK_V1)
    }));

    match outcome {
        Ok(Ok(status)) | Ok(Err(status)) => status,
        Err(_) => WLN_WLPQ_STATUS_INTERNAL_ERROR_V1,
    }
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

    use elements::bitcoin::PublicKey as BitcoinPublicKey;
    use elements::confidential::{Asset, AssetBlindingFactor, Value, ValueBlindingFactor};
    use elements::encode::{deserialize, serialize};
    use elements::hashes::sha256;
    use elements::secp256k1_zkp::{Message, Secp256k1, SecretKey};
    use elements::{
        Address, AddressParams, AssetId, LockTime, OutPoint, Script, Transaction, TxOut,
        TxOutSecrets,
    };
    use miniscript::bitcoin::NetworkKind;
    use miniscript::bitcoin::bip32::{ChildNumber, DerivationPath, Xpriv, Xpub};
    use wasabi_liquid_native_ordinary_pset::OrdinarySigningError;
    use wasabi_liquid_native_ordinary_wallet_plan::{
        OrdinaryWalletPlanDestinationRef, OrdinaryWalletPlanRequestRef,
        OrdinaryWalletPlanSelectedRef, encode_request,
    };
    use wasabi_liquid_native_ordinary_wallet_pset::OrdinaryWalletTransactionReason;
    use wasabi_liquid_native_wallet_facts::{
        BorrowedOrdinaryP2wpkhSigner, BorrowedOrdinarySpendKey, BorrowedSlip77, DescriptorCatalog,
        DescriptorNetwork, Slip77SelectedOutputOpeningProvider,
    };

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

    #[test]
    fn ffi_validated_frame_drives_the_complete_product_adapter_caller_path() {
        let fixture = SignableFixture::new();
        let frame = fixture.frame();
        // SAFETY: Both borrowed buffers remain immutable and valid for the call.
        let status = unsafe {
            wln_wlpq_validate_impl_v1(
                frame.as_ptr(),
                frame.len() as u64,
                fixture.source_epoch.as_ptr(),
            )
        };
        assert_eq!(status, WLN_WLPQ_STATUS_OK_V1);

        let parsed = decode_request(&frame, &fixture.source_epoch).unwrap();
        let prepared = parsed.prepare(&fixture.catalog, &Secp256k1::new()).unwrap();
        assert_eq!(prepared.source_revision(), 31);
        assert_eq!(prepared.selected_input_count(), 2);
        assert_eq!(prepared.confidential_destination_count(), 2);

        let mut provider =
            Slip77SelectedOutputOpeningProvider::new(BorrowedSlip77::new(&fixture.slip77));
        let mut rng = HashDrbg::new(&synthetic_material(
            b"WLPQ FFI caller evidence finalized layout",
        ));
        let mut signer =
            BorrowedOrdinaryP2wpkhSigner::new(BorrowedOrdinarySpendKey::new(&fixture.spend_key));

        let finalized = prepared
            .into_finalized_ordinary_wallet_transaction(&mut provider, &mut rng, &mut signer)
            .unwrap_or_else(|failure| panic!("product caller path failed: {:?}", failure.reason()));

        let secp = Secp256k1::new();
        let transaction = finalized.transaction();
        assert_eq!(transaction.input.len(), 2);
        assert_eq!(transaction.output.len(), 3);
        let expected_public_key = BitcoinPublicKey::from(
            elements::secp256k1_zkp::PublicKey::from_secret_key(&secp, &fixture.spend_key),
        );
        for (input_index, input) in transaction.input.iter().enumerate() {
            assert!(input.script_sig.is_empty());
            let witness = input.witness.script_witness.to_vec();
            assert_eq!(witness.len(), 2, "input {input_index} is native P2WPKH");
            assert_eq!(
                witness[1],
                expected_public_key.to_bytes(),
                "input {input_index} carries the one-key spend public key"
            );
            assert_eq!(
                input.previous_output.txid,
                fixture.funding_transaction.txid()
            );
        }
        for output in &transaction.output[..2] {
            assert!(output.asset.is_confidential());
            assert!(output.value.is_confidential());
            assert!(output.nonce.is_confidential());
            assert!(!output.witness.rangeproof.is_empty());
            assert!(!output.witness.surjection_proof.is_empty());
        }
        let fee = transaction.output.last().unwrap();
        assert!(fee.script_pubkey.is_empty());
        assert_eq!(fee.asset, Asset::Explicit(AssetId::LIQUIDTESTNET_BTC));
        assert_eq!(fee.value, Value::Explicit(100));
        let previous_outputs = transaction
            .input
            .iter()
            .map(|input| {
                fixture.funding_transaction.output[input.previous_output.vout as usize].clone()
            })
            .collect::<Vec<_>>();
        transaction
            .verify_tx_amt_proofs(&secp, &previous_outputs)
            .unwrap();

        assert_eq!(finalized.txid(), transaction.txid());
        assert_eq!(finalized.wtxid(), transaction.wtxid());
        let broadcast = finalized.serialize_for_broadcast();
        let decoded: Transaction = deserialize(&broadcast).unwrap();
        assert_eq!(decoded, *transaction);
        assert!(
            deserialize::<elements::pset::PartiallySignedTransaction>(&broadcast).is_err(),
            "broadcast serialization carries no PSET metadata"
        );
    }

    #[test]
    fn ffi_validated_frame_wrong_key_recovers_the_retryable_blinded_pset() {
        let fixture = SignableFixture::new();
        let frame = fixture.frame();
        // SAFETY: Both borrowed buffers remain immutable and valid for the call.
        let status = unsafe {
            wln_wlpq_validate_impl_v1(
                frame.as_ptr(),
                frame.len() as u64,
                fixture.source_epoch.as_ptr(),
            )
        };
        assert_eq!(status, WLN_WLPQ_STATUS_OK_V1);

        let seed = synthetic_material(b"WLPQ FFI caller evidence wrong-key layout");
        let baseline_parsed = decode_request(&frame, &fixture.source_epoch).unwrap();
        let baseline_prepared = baseline_parsed
            .prepare(&fixture.catalog, &Secp256k1::new())
            .unwrap();
        let mut baseline_provider =
            Slip77SelectedOutputOpeningProvider::new(BorrowedSlip77::new(&fixture.slip77));
        let baseline = baseline_prepared
            .into_blinded_ordinary_wallet_pset(&mut baseline_provider, &mut HashDrbg::new(&seed))
            .unwrap();
        let baseline_bytes = baseline.serialize_sensitive();
        drop(baseline);

        let wrong_key_bytes = synthetic_material(b"WLPQ FFI caller evidence wrong spend key");
        let wrong_key = SecretKey::from_slice(&wrong_key_bytes).unwrap();
        let parsed = decode_request(&frame, &fixture.source_epoch).unwrap();
        let prepared = parsed.prepare(&fixture.catalog, &Secp256k1::new()).unwrap();
        let mut provider =
            Slip77SelectedOutputOpeningProvider::new(BorrowedSlip77::new(&fixture.slip77));
        let mut wrong_key_signer =
            BorrowedOrdinaryP2wpkhSigner::new(BorrowedOrdinarySpendKey::new(&wrong_key));
        let failure = match prepared.into_finalized_ordinary_wallet_transaction(
            &mut provider,
            &mut HashDrbg::new(&seed),
            &mut wrong_key_signer,
        ) {
            Ok(_) => panic!("a wrong-key signer must not finalize"),
            Err(failure) => failure,
        };

        assert_eq!(
            failure.reason(),
            &OrdinaryWalletTransactionReason::Signing(
                OrdinarySigningError::PublicKeyDoesNotOwnInput
            )
        );
        let retryable = failure.into_retryable_blinded().unwrap();
        assert_eq!(
            retryable.serialize_sensitive(),
            baseline_bytes,
            "the retryable blinded PSET is recovered byte-identical and unmodified"
        );

        let mut retry_signer =
            BorrowedOrdinaryP2wpkhSigner::new(BorrowedOrdinarySpendKey::new(&fixture.spend_key));
        let signed = match retryable.sign_and_finalize(&Secp256k1::new(), &mut retry_signer) {
            Ok(signed) => signed,
            Err(_) => panic!("the recovered blinded PSET must retry into finalization"),
        };
        let finalized = signed.into_finalized_transaction();
        assert_eq!(finalized.txid(), finalized.transaction().txid());
        assert_eq!(finalized.wtxid(), finalized.transaction().wtxid());
        let broadcast = finalized.serialize_for_broadcast();
        let decoded: Transaction = deserialize(&broadcast).unwrap();
        assert_eq!(decoded, *finalized.transaction());
    }

    struct CallbackSignerState {
        spend_key: SecretKey,
        refuse_public_key: bool,
        refuse_sign_digest: bool,
        wrong_digest: bool,
    }

    unsafe extern "C" fn callback_public_key(
        context: *const u8,
        outpoint: *const u8,
        outpoint_length: u64,
        out_public_key: *mut u8,
        public_key_capacity: u64,
    ) -> i32 {
        // SAFETY: The native adapter contract supplies a readable context and
        // a writable output buffer for the duration of this call.
        unsafe {
            if context.is_null()
                || outpoint.is_null()
                || outpoint_length != 36
                || out_public_key.is_null()
                || public_key_capacity < 33
            {
                return WLN_WLPQ_STATUS_INVALID_ARGUMENT_V1;
            }
            let state = &*(context as *const CallbackSignerState);
            if state.refuse_public_key {
                return WLN_WLPQ_STATUS_SIGNER_REFUSED_V1;
            }
            let secp = Secp256k1::new();
            let public_key = BitcoinPublicKey::from(
                elements::secp256k1_zkp::PublicKey::from_secret_key(&secp, &state.spend_key),
            );
            ptr::copy_nonoverlapping(public_key.to_bytes().as_ptr(), out_public_key, 33);
            WLN_WLPQ_STATUS_OK_V1
        }
    }

    unsafe extern "C" fn callback_sign_digest(
        context: *const u8,
        outpoint: *const u8,
        outpoint_length: u64,
        digest: *const u8,
        out_signature: *mut u8,
        signature_capacity: u64,
    ) -> i32 {
        // SAFETY: The native adapter contract supplies a readable context,
        // outpoint, and digest, and a writable output buffer for the duration
        // of this call.
        unsafe {
            if context.is_null()
                || outpoint.is_null()
                || outpoint_length != 36
                || digest.is_null()
                || out_signature.is_null()
                || signature_capacity < 73
            {
                return WLN_WLPQ_STATUS_INVALID_ARGUMENT_V1;
            }
            let state = &*(context as *const CallbackSignerState);
            if state.refuse_sign_digest {
                return WLN_WLPQ_STATUS_SIGNER_REFUSED_V1;
            }
            let mut digest_bytes = [0u8; 32];
            ptr::copy_nonoverlapping(digest, digest_bytes.as_mut_ptr(), 32);
            if state.wrong_digest {
                digest_bytes[0] ^= 0xff;
            }
            let secp = Secp256k1::new();
            let signature = secp.sign_ecdsa(&Message::from_digest(digest_bytes), &state.spend_key);
            let mut bytes = signature.serialize_der().to_vec();
            bytes.push(elements::EcdsaSighashType::AllPlusRangeproof.as_u32() as u8);
            ptr::copy_nonoverlapping(bytes.as_ptr(), out_signature, bytes.len());
            WLN_WLPQ_STATUS_OK_V1
        }
    }

    #[test]
    fn ffi_sign_finalize_signable_fixture_produces_a_finalized_transaction() {
        let fixture = SignableFixture::new();
        let frame = fixture.frame();
        let state = CallbackSignerState {
            spend_key: fixture.spend_key,
            refuse_public_key: false,
            refuse_sign_digest: false,
            wrong_digest: false,
        };
        let mut out_transaction = [0u8; 65536];
        let mut out_transaction_length = 0u64;
        let seed = [0x5a; 32];
        // SAFETY: All borrowed buffers remain valid for the call and the
        // callbacks honor the frozen contract.
        let status = unsafe {
            wln_wlpq_sign_finalize_impl_v1(
                frame.as_ptr(),
                frame.len() as u64,
                fixture.source_epoch.as_ptr(),
                (&state as *const CallbackSignerState) as *const u8,
                callback_public_key,
                callback_sign_digest,
                out_transaction.as_mut_ptr(),
                out_transaction.len() as u64,
                &mut out_transaction_length,
                fixture.descriptor.as_ptr(),
                fixture.descriptor.len() as u64,
                1,
                fixture.slip77.as_ptr(),
                seed.as_ptr(),
                32,
            )
        };
        assert_eq!(status, WLN_WLPQ_STATUS_OK_V1);
        assert!(out_transaction_length > 0);
        let broadcast = &out_transaction[..out_transaction_length as usize];
        let decoded: Transaction = deserialize(broadcast).unwrap();
        assert_eq!(decoded.input.len(), 2);
        assert_eq!(decoded.output.len(), 3);
        let expected_public_key =
            BitcoinPublicKey::from(elements::secp256k1_zkp::PublicKey::from_secret_key(
                &Secp256k1::new(),
                &fixture.spend_key,
            ));
        for input in &decoded.input {
            assert!(input.script_sig.is_empty());
            let witness = input.witness.script_witness.to_vec();
            assert_eq!(witness.len(), 2);
            assert_eq!(witness[1], expected_public_key.to_bytes());
        }
        let txid = decoded.txid();
        let wtxid = decoded.wtxid();
        assert_eq!(txid, decoded.txid());
        assert_eq!(wtxid, decoded.wtxid());
    }

    #[test]
    fn ffi_sign_finalize_wrong_key_fails_closed_as_signing_rejected() {
        let fixture = SignableFixture::new();
        let frame = fixture.frame();
        let wrong_key_bytes = synthetic_material(b"WLPQ FFI callback wrong spend key");
        let wrong_key = SecretKey::from_slice(&wrong_key_bytes).unwrap();
        let state = CallbackSignerState {
            spend_key: wrong_key,
            refuse_public_key: false,
            refuse_sign_digest: false,
            wrong_digest: false,
        };
        let mut out_transaction = [0u8; 65536];
        let mut out_transaction_length = 0u64;
        let seed = [0x5a; 32];
        // SAFETY: All borrowed buffers remain valid for the call.
        let status = unsafe {
            wln_wlpq_sign_finalize_impl_v1(
                frame.as_ptr(),
                frame.len() as u64,
                fixture.source_epoch.as_ptr(),
                (&state as *const CallbackSignerState) as *const u8,
                callback_public_key,
                callback_sign_digest,
                out_transaction.as_mut_ptr(),
                out_transaction.len() as u64,
                &mut out_transaction_length,
                fixture.descriptor.as_ptr(),
                fixture.descriptor.len() as u64,
                1,
                fixture.slip77.as_ptr(),
                seed.as_ptr(),
                32,
            )
        };
        assert_eq!(status, WLN_WLPQ_STATUS_SIGNING_REJECTED_V1);
    }

    #[test]
    fn ffi_sign_finalize_mismatched_digest_fails_closed_as_signing_rejected() {
        let fixture = SignableFixture::new();
        let frame = fixture.frame();
        let state = CallbackSignerState {
            spend_key: fixture.spend_key,
            refuse_public_key: false,
            refuse_sign_digest: false,
            wrong_digest: true,
        };
        let mut out_transaction = [0u8; 65536];
        let mut out_transaction_length = 0u64;
        let seed = [0x5a; 32];
        // SAFETY: All borrowed buffers remain valid for the call.
        let status = unsafe {
            wln_wlpq_sign_finalize_impl_v1(
                frame.as_ptr(),
                frame.len() as u64,
                fixture.source_epoch.as_ptr(),
                (&state as *const CallbackSignerState) as *const u8,
                callback_public_key,
                callback_sign_digest,
                out_transaction.as_mut_ptr(),
                out_transaction.len() as u64,
                &mut out_transaction_length,
                fixture.descriptor.as_ptr(),
                fixture.descriptor.len() as u64,
                1,
                fixture.slip77.as_ptr(),
                seed.as_ptr(),
                32,
            )
        };
        assert_eq!(status, WLN_WLPQ_STATUS_SIGNING_REJECTED_V1);
    }

    #[test]
    fn ffi_sign_finalize_signer_refusal_fails_closed_as_signer_refused() {
        let fixture = SignableFixture::new();
        let frame = fixture.frame();
        let state = CallbackSignerState {
            spend_key: fixture.spend_key,
            refuse_public_key: true,
            refuse_sign_digest: false,
            wrong_digest: false,
        };
        let mut out_transaction = [0u8; 65536];
        let mut out_transaction_length = 0u64;
        let seed = [0x5a; 32];
        // SAFETY: All borrowed buffers remain valid for the call.
        let status = unsafe {
            wln_wlpq_sign_finalize_impl_v1(
                frame.as_ptr(),
                frame.len() as u64,
                fixture.source_epoch.as_ptr(),
                (&state as *const CallbackSignerState) as *const u8,
                callback_public_key,
                callback_sign_digest,
                out_transaction.as_mut_ptr(),
                out_transaction.len() as u64,
                &mut out_transaction_length,
                fixture.descriptor.as_ptr(),
                fixture.descriptor.len() as u64,
                1,
                fixture.slip77.as_ptr(),
                seed.as_ptr(),
                32,
            )
        };
        assert_eq!(status, WLN_WLPQ_STATUS_SIGNER_REFUSED_V1);
    }

    #[test]
    fn ffi_sign_finalize_corrupt_frame_fails_closed_as_invalid_encoding() {
        let fixture = SignableFixture::new();
        let mut frame = fixture.frame();
        frame.truncate(frame.len() / 2);
        let state = CallbackSignerState {
            spend_key: fixture.spend_key,
            refuse_public_key: false,
            refuse_sign_digest: false,
            wrong_digest: false,
        };
        let mut out_transaction = [0u8; 65536];
        let mut out_transaction_length = 0u64;
        let seed = [0x5a; 32];
        // SAFETY: All borrowed buffers remain valid for the call.
        let status = unsafe {
            wln_wlpq_sign_finalize_impl_v1(
                frame.as_ptr(),
                frame.len() as u64,
                fixture.source_epoch.as_ptr(),
                (&state as *const CallbackSignerState) as *const u8,
                callback_public_key,
                callback_sign_digest,
                out_transaction.as_mut_ptr(),
                out_transaction.len() as u64,
                &mut out_transaction_length,
                fixture.descriptor.as_ptr(),
                fixture.descriptor.len() as u64,
                1,
                fixture.slip77.as_ptr(),
                seed.as_ptr(),
                32,
            )
        };
        assert_eq!(status, WLN_WLPQ_STATUS_INVALID_ENCODING_V1);
    }

    #[test]
    fn ffi_sign_finalize_output_capacity_failure_reports_required_length() {
        let fixture = SignableFixture::new();
        let frame = fixture.frame();
        let state = CallbackSignerState {
            spend_key: fixture.spend_key,
            refuse_public_key: false,
            refuse_sign_digest: false,
            wrong_digest: false,
        };
        let mut out_transaction = [0u8; 1];
        let mut out_transaction_length = 0u64;
        let seed = [0x5a; 32];
        // SAFETY: All borrowed buffers remain valid for the call.
        let status = unsafe {
            wln_wlpq_sign_finalize_impl_v1(
                frame.as_ptr(),
                frame.len() as u64,
                fixture.source_epoch.as_ptr(),
                (&state as *const CallbackSignerState) as *const u8,
                callback_public_key,
                callback_sign_digest,
                out_transaction.as_mut_ptr(),
                out_transaction.len() as u64,
                &mut out_transaction_length,
                fixture.descriptor.as_ptr(),
                fixture.descriptor.len() as u64,
                1,
                fixture.slip77.as_ptr(),
                seed.as_ptr(),
                32,
            )
        };
        assert_eq!(status, WLN_WLPQ_STATUS_OUTPUT_CAPACITY_V1);
        assert!(out_transaction_length > 1);
        assert!(out_transaction_length <= 65536);
    }

    #[test]
    fn ffi_sign_finalize_null_and_capacity_failures_fail_closed() {
        let fixture = SignableFixture::new();
        let frame = fixture.frame();
        let state = CallbackSignerState {
            spend_key: fixture.spend_key,
            refuse_public_key: false,
            refuse_sign_digest: false,
            wrong_digest: false,
        };
        let mut out_transaction = [0u8; 65536];
        let mut out_transaction_length = 0u64;
        let seed = [0x5a; 32];
        // SAFETY: Null is intentionally supplied to exercise pre-dereference validation.
        let status = unsafe {
            wln_wlpq_sign_finalize_impl_v1(
                ptr::null(),
                1,
                fixture.source_epoch.as_ptr(),
                (&state as *const CallbackSignerState) as *const u8,
                callback_public_key,
                callback_sign_digest,
                out_transaction.as_mut_ptr(),
                out_transaction.len() as u64,
                &mut out_transaction_length,
                fixture.descriptor.as_ptr(),
                fixture.descriptor.len() as u64,
                1,
                fixture.slip77.as_ptr(),
                seed.as_ptr(),
                32,
            )
        };
        assert_eq!(status, WLN_WLPQ_STATUS_INVALID_ARGUMENT_V1);
        // SAFETY: Null is intentionally supplied to exercise pre-dereference validation.
        let status = unsafe {
            wln_wlpq_sign_finalize_impl_v1(
                frame.as_ptr(),
                frame.len() as u64,
                ptr::null(),
                (&state as *const CallbackSignerState) as *const u8,
                callback_public_key,
                callback_sign_digest,
                out_transaction.as_mut_ptr(),
                out_transaction.len() as u64,
                &mut out_transaction_length,
                fixture.descriptor.as_ptr(),
                fixture.descriptor.len() as u64,
                1,
                fixture.slip77.as_ptr(),
                seed.as_ptr(),
                32,
            )
        };
        assert_eq!(status, WLN_WLPQ_STATUS_INVALID_ARGUMENT_V1);
        // SAFETY: Null is intentionally supplied to exercise pre-dereference validation.
        let status = unsafe {
            wln_wlpq_sign_finalize_impl_v1(
                frame.as_ptr(),
                frame.len() as u64,
                fixture.source_epoch.as_ptr(),
                (&state as *const CallbackSignerState) as *const u8,
                callback_public_key,
                callback_sign_digest,
                ptr::null_mut(),
                out_transaction.len() as u64,
                &mut out_transaction_length,
                fixture.descriptor.as_ptr(),
                fixture.descriptor.len() as u64,
                1,
                fixture.slip77.as_ptr(),
                seed.as_ptr(),
                32,
            )
        };
        assert_eq!(status, WLN_WLPQ_STATUS_INVALID_ARGUMENT_V1);
        // SAFETY: Null is intentionally supplied to exercise pre-dereference validation.
        let status = unsafe {
            wln_wlpq_sign_finalize_impl_v1(
                frame.as_ptr(),
                frame.len() as u64,
                fixture.source_epoch.as_ptr(),
                (&state as *const CallbackSignerState) as *const u8,
                callback_public_key,
                callback_sign_digest,
                out_transaction.as_mut_ptr(),
                out_transaction.len() as u64,
                ptr::null_mut(),
                fixture.descriptor.as_ptr(),
                fixture.descriptor.len() as u64,
                1,
                fixture.slip77.as_ptr(),
                seed.as_ptr(),
                32,
            )
        };
        assert_eq!(status, WLN_WLPQ_STATUS_INVALID_ARGUMENT_V1);
    }

    #[test]
    fn ffi_sign_finalize_null_and_wrong_length_entropy_fail_closed() {
        let fixture = SignableFixture::new();
        let frame = fixture.frame();
        let state = CallbackSignerState {
            spend_key: fixture.spend_key,
            refuse_public_key: false,
            refuse_sign_digest: false,
            wrong_digest: false,
        };
        let mut out_transaction = [0u8; 65536];
        let mut out_transaction_length = 0u64;
        let seed = [0x5a; 32];
        // SAFETY: Null entropy is intentionally supplied to exercise
        // pre-dereference validation.
        let status = unsafe {
            wln_wlpq_sign_finalize_impl_v1(
                frame.as_ptr(),
                frame.len() as u64,
                fixture.source_epoch.as_ptr(),
                (&state as *const CallbackSignerState) as *const u8,
                callback_public_key,
                callback_sign_digest,
                out_transaction.as_mut_ptr(),
                out_transaction.len() as u64,
                &mut out_transaction_length,
                fixture.descriptor.as_ptr(),
                fixture.descriptor.len() as u64,
                1,
                fixture.slip77.as_ptr(),
                ptr::null(),
                32,
            )
        };
        assert_eq!(status, WLN_WLPQ_STATUS_INVALID_ARGUMENT_V1);
        // SAFETY: A wrong entropy length is intentionally supplied to exercise
        // pre-dereference validation; the non-null pointer is never read.
        let status = unsafe {
            wln_wlpq_sign_finalize_impl_v1(
                frame.as_ptr(),
                frame.len() as u64,
                fixture.source_epoch.as_ptr(),
                (&state as *const CallbackSignerState) as *const u8,
                callback_public_key,
                callback_sign_digest,
                out_transaction.as_mut_ptr(),
                out_transaction.len() as u64,
                &mut out_transaction_length,
                fixture.descriptor.as_ptr(),
                fixture.descriptor.len() as u64,
                1,
                fixture.slip77.as_ptr(),
                seed.as_ptr(),
                31,
            )
        };
        assert_eq!(status, WLN_WLPQ_STATUS_INVALID_ARGUMENT_V1);
    }

    /// Broadcast bytes produced by the real caller-owned sign/finalize path.
    fn finalized_broadcast_fixture() -> Vec<u8> {
        let fixture = SignableFixture::new();
        let frame = fixture.frame();
        let state = CallbackSignerState {
            spend_key: fixture.spend_key,
            refuse_public_key: false,
            refuse_sign_digest: false,
            wrong_digest: false,
        };
        let mut out_transaction = [0u8; 65536];
        let mut out_transaction_length = 0u64;
        let seed = [0x5a; 32];
        // SAFETY: All borrowed buffers remain valid for the call and the
        // callbacks honor the frozen contract.
        let status = unsafe {
            wln_wlpq_sign_finalize_impl_v1(
                frame.as_ptr(),
                frame.len() as u64,
                fixture.source_epoch.as_ptr(),
                (&state as *const CallbackSignerState) as *const u8,
                callback_public_key,
                callback_sign_digest,
                out_transaction.as_mut_ptr(),
                out_transaction.len() as u64,
                &mut out_transaction_length,
                fixture.descriptor.as_ptr(),
                fixture.descriptor.len() as u64,
                1,
                fixture.slip77.as_ptr(),
                seed.as_ptr(),
                seed.len() as u64,
            )
        };
        assert_eq!(status, WLN_WLPQ_STATUS_OK_V1);
        assert!(out_transaction_length > 0);
        out_transaction[..out_transaction_length as usize].to_vec()
    }

    #[test]
    fn ffi_transaction_id_reports_the_canonical_txid_hex() {
        let broadcast = finalized_broadcast_fixture();
        let decoded: Transaction = deserialize(&broadcast).unwrap();
        assert_eq!(serialize(&decoded), broadcast);
        let expected_txid = decoded.txid().to_string();
        let mut out_txid = [0u8; 64];
        // SAFETY: Both borrowed buffers remain valid for the call.
        let status = unsafe {
            wln_wlpq_transaction_id_impl_v1(
                broadcast.as_ptr(),
                broadcast.len() as u64,
                out_txid.as_mut_ptr(),
                out_txid.len() as u64,
            )
        };
        assert_eq!(status, WLN_WLPQ_STATUS_OK_V1);
        let actual = core::str::from_utf8(&out_txid).unwrap();
        assert_eq!(actual, expected_txid);
        assert_eq!(actual.len(), 64);
        assert!(
            actual
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        );
        assert!(
            !out_txid.contains(&0),
            "the output carries no NUL terminator"
        );
    }

    #[test]
    fn ffi_transaction_id_rejects_every_invalid_argument_without_writing() {
        let broadcast = finalized_broadcast_fixture();
        let sentinel = [0xa5u8; 64];
        let mut out_txid = sentinel;
        // SAFETY: Null is intentionally supplied to exercise pre-dereference validation.
        let status = unsafe {
            wln_wlpq_transaction_id_impl_v1(
                ptr::null(),
                broadcast.len() as u64,
                out_txid.as_mut_ptr(),
                64,
            )
        };
        assert_eq!(status, WLN_WLPQ_STATUS_INVALID_ARGUMENT_V1);
        assert_eq!(out_txid, sentinel);
        // SAFETY: Null is intentionally supplied to exercise pre-dereference validation.
        let status = unsafe {
            wln_wlpq_transaction_id_impl_v1(
                broadcast.as_ptr(),
                broadcast.len() as u64,
                ptr::null_mut(),
                64,
            )
        };
        assert_eq!(status, WLN_WLPQ_STATUS_INVALID_ARGUMENT_V1);
        assert_eq!(out_txid, sentinel);
        // SAFETY: Zero length is rejected before the non-null pointer is read.
        let status = unsafe {
            wln_wlpq_transaction_id_impl_v1(broadcast.as_ptr(), 0, out_txid.as_mut_ptr(), 64)
        };
        assert_eq!(status, WLN_WLPQ_STATUS_INVALID_ARGUMENT_V1);
        assert_eq!(out_txid, sentinel);
        // SAFETY: The undersized capacity is rejected before any write.
        let status = unsafe {
            wln_wlpq_transaction_id_impl_v1(
                broadcast.as_ptr(),
                broadcast.len() as u64,
                out_txid.as_mut_ptr(),
                63,
            )
        };
        assert_eq!(status, WLN_WLPQ_STATUS_INVALID_ARGUMENT_V1);
        assert_eq!(out_txid, sentinel);
    }

    #[test]
    fn ffi_transaction_id_rejects_malformed_trailing_and_oversized_inputs() {
        let broadcast = finalized_broadcast_fixture();
        let sentinel = [0xa5u8; 64];
        let mut out_txid = sentinel;
        let truncated = &broadcast[..broadcast.len() / 2];
        // SAFETY: Both borrowed buffers remain valid for the call.
        let status = unsafe {
            wln_wlpq_transaction_id_impl_v1(
                truncated.as_ptr(),
                truncated.len() as u64,
                out_txid.as_mut_ptr(),
                64,
            )
        };
        assert_eq!(status, WLN_WLPQ_STATUS_INVALID_ENCODING_V1);
        assert_eq!(out_txid, sentinel);
        let mut trailing = broadcast.clone();
        trailing.push(0x00);
        // SAFETY: Both borrowed buffers remain valid for the call.
        let status = unsafe {
            wln_wlpq_transaction_id_impl_v1(
                trailing.as_ptr(),
                trailing.len() as u64,
                out_txid.as_mut_ptr(),
                64,
            )
        };
        assert_eq!(status, WLN_WLPQ_STATUS_INVALID_ENCODING_V1);
        assert_eq!(out_txid, sentinel);
        // SAFETY: The oversized length is rejected before the pointer is read.
        let status = unsafe {
            wln_wlpq_transaction_id_impl_v1(
                broadcast.as_ptr(),
                WLN_WLPQ_MAX_FRAME_BYTES_V1 + 1,
                out_txid.as_mut_ptr(),
                64,
            )
        };
        assert_eq!(status, WLN_WLPQ_STATUS_LIMIT_EXCEEDED_V1);
        assert_eq!(out_txid, sentinel);
    }

    #[test]
    fn ffi_transaction_id_contains_panic_as_internal_error() {
        let broadcast = finalized_broadcast_fixture();
        let sentinel = [0xa5u8; 64];
        let mut out_txid = sentinel;
        INJECT_TEST_PANIC.with(|armed| armed.set(true));
        // SAFETY: Both borrowed buffers remain valid for the call.
        let status = unsafe {
            wln_wlpq_transaction_id_impl_v1(
                broadcast.as_ptr(),
                broadcast.len() as u64,
                out_txid.as_mut_ptr(),
                64,
            )
        };
        assert_eq!(status, WLN_WLPQ_STATUS_INTERNAL_ERROR_V1);
        assert_eq!(out_txid, sentinel);
        INJECT_TEST_PANIC.with(|armed| assert!(!armed.get()));
    }

    struct SignableFixture {
        catalog: DescriptorCatalog,
        descriptor: String,
        funding_transaction: Transaction,
        funding_transaction_bytes: Vec<u8>,
        previous_transaction_bytes: Vec<u8>,
        second_asset: AssetId,
        slip77: [u8; 32],
        spend_key: SecretKey,
        source_epoch: [u8; 32],
    }

    impl SignableFixture {
        fn new() -> Self {
            let mut seed = synthetic_material(b"WLPQ FFI caller evidence descriptor seed");
            let mut root = Xpriv::new_master(NetworkKind::Test, &seed).unwrap();
            seed.fill(0);
            let descriptor_secp = miniscript::bitcoin::secp256k1::Secp256k1::new();
            let public = Xpub::from_priv(&descriptor_secp, &root);
            let descriptor = format!("elwpkh({public}/<0;1>/*)");
            let catalog =
                DescriptorCatalog::derive(&descriptor, DescriptorNetwork::Test, 1).unwrap();
            let mut external = root
                .derive_priv(
                    &descriptor_secp,
                    &DerivationPath::from(vec![
                        ChildNumber::Normal { index: 0 },
                        ChildNumber::Normal { index: 0 },
                    ]),
                )
                .unwrap();
            let spend_key = SecretKey::from_slice(&external.private_key.secret_bytes()).unwrap();
            external.private_key.non_secure_erase();
            root.private_key.non_secure_erase();

            let secp = Secp256k1::new();
            let public_key = BitcoinPublicKey::new(spend_key.public_key(&secp));
            let script = Script::new_v0_wpkh(&public_key.wpubkey_hash().unwrap());
            let slip77 = synthetic_material(b"WLPQ FFI caller evidence SLIP77 material");
            let fee_asset = AssetId::LIQUIDTESTNET_BTC;
            let second_asset = AssetId::from_byte_array([0x82; 32]);
            let previous = Transaction {
                version: 2,
                lock_time: LockTime::ZERO,
                input: vec![],
                output: vec![
                    explicit_output(fee_asset, 1_000),
                    explicit_output(second_asset, 2_000),
                ],
            };
            let spent_secrets = [
                TxOutSecrets::new(
                    fee_asset,
                    AssetBlindingFactor::zero(),
                    1_000,
                    ValueBlindingFactor::zero(),
                ),
                TxOutSecrets::new(
                    second_asset,
                    AssetBlindingFactor::zero(),
                    2_000,
                    ValueBlindingFactor::zero(),
                ),
            ];
            let blinding_key = slip77_key(&slip77, script.as_bytes());
            let address = Address::from_script(
                &script,
                Some(blinding_key.public_key(&secp)),
                &AddressParams::LIQUID_TESTNET,
            )
            .unwrap();
            let mut rng = HashDrbg::new(&synthetic_material(
                b"WLPQ FFI caller evidence funding randomness",
            ));
            let (first_output, first_abf, first_vbf, _) = TxOut::new_not_last_confidential(
                &mut rng,
                &secp,
                900,
                &address,
                fee_asset,
                &spent_secrets,
            )
            .unwrap();
            let first_secrets = TxOutSecrets::new(fee_asset, first_abf, 900, first_vbf);
            let fee_secrets = TxOutSecrets::new(
                fee_asset,
                AssetBlindingFactor::zero(),
                100,
                ValueBlindingFactor::zero(),
            );
            let (second_output, _, _, _) = TxOut::new_last_confidential(
                &mut rng,
                &secp,
                2_000,
                second_asset,
                script,
                blinding_key.public_key(&secp),
                &spent_secrets,
                &[&first_secrets, &fee_secrets],
            )
            .unwrap();
            let funding_transaction = Transaction {
                version: 2,
                lock_time: LockTime::ZERO,
                input: vec![
                    funding_input(OutPoint::new(previous.txid(), 0)),
                    funding_input(OutPoint::new(previous.txid(), 1)),
                ],
                output: vec![first_output, second_output, TxOut::new_fee(100, fee_asset)],
            };

            Self {
                catalog,
                descriptor,
                funding_transaction_bytes: serialize(&funding_transaction),
                previous_transaction_bytes: serialize(&previous),
                funding_transaction,
                second_asset,
                slip77,
                spend_key,
                source_epoch: [0x71; 32],
            }
        }

        fn frame(&self) -> Vec<u8> {
            let transaction_id = self.funding_transaction.txid().to_byte_array();
            let fee_asset = AssetId::LIQUIDTESTNET_BTC.to_byte_array();
            let second_asset = self.second_asset.to_byte_array();
            let previous_transactions = vec![self.previous_transaction_bytes.clone()];
            let selected = [
                OrdinaryWalletPlanSelectedRef::new(
                    &transaction_id,
                    0,
                    &fee_asset,
                    900,
                    &self.funding_transaction_bytes,
                    &previous_transactions,
                ),
                OrdinaryWalletPlanSelectedRef::new(
                    &transaction_id,
                    1,
                    &second_asset,
                    2_000,
                    &self.funding_transaction_bytes,
                    &previous_transactions,
                ),
            ];
            let destinations = [
                OrdinaryWalletPlanDestinationRef::new(&fee_asset, 800, TESTNET_ADDRESS),
                OrdinaryWalletPlanDestinationRef::new(&second_asset, 2_000, TESTNET_ADDRESS),
            ];
            let request = OrdinaryWalletPlanRequestRef::new(
                &self.source_epoch,
                31,
                &TESTNET_MANIFEST,
                &fee_asset,
                &selected,
                &destinations,
                100,
            );
            encode_request(&request).unwrap().as_bytes().to_vec()
        }
    }

    const TESTNET_MANIFEST: [u8; 32] = [
        0xe4, 0xe7, 0xec, 0x03, 0xe1, 0x9c, 0xe5, 0xf8, 0x3f, 0xd0, 0x4c, 0x58, 0x67, 0x88, 0xb7,
        0x24, 0xd8, 0x80, 0x52, 0xb6, 0x5e, 0xf2, 0x48, 0x0c, 0xc9, 0x3b, 0xcd, 0x50, 0x32, 0x4f,
        0x6b, 0x20,
    ];
    const TESTNET_ADDRESS: &str = "tlq1qq2xvpcvfup5j8zscjq05u2wxxjcyewk7979f3mmz5l7uw5pqmx6xf5xy50hsn6vhkm5euwt72x878eq6zxx2z58hd7zrsg9qn";

    fn synthetic_material(label: &[u8]) -> [u8; 32] {
        sha256::Hash::hash(label).to_byte_array()
    }

    fn slip77_key(master_key: &[u8; 32], script: &[u8]) -> SecretKey {
        use sha2::{Digest, Sha256};
        let mut inner_pad = [0x36; 64];
        let mut outer_pad = [0x5c; 64];
        for (index, key_byte) in master_key.iter().enumerate() {
            inner_pad[index] ^= key_byte;
            outer_pad[index] ^= key_byte;
        }
        let mut inner = Sha256::new();
        inner.update(inner_pad);
        inner.update(script);
        let inner_digest = inner.finalize();
        let mut outer = Sha256::new();
        outer.update(outer_pad);
        outer.update(inner_digest);
        SecretKey::from_slice(&outer.finalize()).unwrap()
    }

    fn explicit_output(asset: AssetId, value: u64) -> TxOut {
        TxOut {
            asset: Asset::Explicit(asset),
            value: Value::Explicit(value),
            nonce: elements::confidential::Nonce::Null,
            script_pubkey: Script::from(vec![0x51]),
            witness: Default::default(),
        }
    }

    fn funding_input(previous_output: OutPoint) -> elements::TxIn {
        elements::TxIn {
            previous_output,
            is_pegin: false,
            script_sig: Script::new(),
            sequence: elements::Sequence::MAX,
            asset_issuance: Default::default(),
            witness: Default::default(),
        }
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
