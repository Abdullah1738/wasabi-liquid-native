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

    use elements::bitcoin::PublicKey as BitcoinPublicKey;
    use elements::confidential::{Asset, AssetBlindingFactor, Value, ValueBlindingFactor};
    use elements::encode::{deserialize, serialize};
    use elements::hashes::sha256;
    use elements::secp256k1_zkp::{Secp256k1, SecretKey};
    use elements::{
        Address, AddressParams, AssetId, LockTime, OutPoint, Script, Transaction, TxOut,
        TxOutSecrets,
    };
    use miniscript::bitcoin::NetworkKind;
    use miniscript::bitcoin::bip32::{ChildNumber, DerivationPath, Xpriv, Xpub};
    use rand::SeedableRng;
    use rand::rngs::StdRng;
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
        let mut rng = StdRng::from_seed(synthetic_material(
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
            .into_blinded_ordinary_wallet_pset(&mut baseline_provider, &mut StdRng::from_seed(seed))
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
            &mut StdRng::from_seed(seed),
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

    struct SignableFixture {
        catalog: DescriptorCatalog,
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
            let mut rng = StdRng::from_seed(synthetic_material(
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
