use super::*;

use elements::confidential::{Asset, AssetBlindingFactor, Nonce, Value, ValueBlindingFactor};
use elements::{
    Address, AddressParams, AssetId, LockTime, RangeProof, Script, Sequence, Transaction, TxIn,
    TxOut, TxOutSecrets, TxOutWitness,
};
use rand::SeedableRng;
use rand::rngs::StdRng;

const TEST_PUBLIC_DESCRIPTOR: &str = "elwpkh([28b3f14e/84'/1'/0']tpubDC2Q4xK4XH72GM7MowNuajyWVbigRLBWKswyP5T88hpPwu5nGqJWnda8zhJEFt71av73Hm8mUMMFSz9acNVzz8b1UbdSHCDXKTbSv5eEytu/<0;1>/*)";
const TEST_PUBLIC_DESCRIPTOR_CHECKSUM: &str = "u0khc0kg";
const MAINNET_PUBLIC_DESCRIPTOR: &str = "elwpkh([73c5da0a/84'/1776'/0']xpub6CRFzUgHFDaiDAQFNX7VeV9JNPDRabq6NYSpzVZ8zW8ANUCiDdenkb1gBoEZuXNZb3wPc1SVcDXgD2ww5UBtTb8s8ArAbTkoRQ8qn34KgcY/<0;1>/*)";

static_assertions::assert_not_impl_any!(BorrowedSlip77<'static>: Copy, Clone, std::fmt::Debug);
static_assertions::assert_not_impl_any!(BorrowedCandidateTransaction<'static>: Copy, Clone, std::fmt::Debug);
static_assertions::assert_not_impl_any!(ScopedSecretKey: Copy, Clone, std::fmt::Debug);
static_assertions::assert_not_impl_any!(ScopedContextRandomizationSeed: Copy, Clone, std::fmt::Debug);
static_assertions::assert_not_impl_any!(PreparedCandidate: Copy, Clone, std::fmt::Debug);
static_assertions::assert_not_impl_any!(PreparedTransactionId: Copy, Clone, std::fmt::Debug);
static_assertions::assert_not_impl_any!(PreparedCandidateOrder: Copy, Clone, std::fmt::Debug);
static_assertions::assert_not_impl_any!(DescriptorCatalog: Copy, Clone, std::fmt::Debug);
static_assertions::assert_not_impl_any!(CandidateBatch: Copy, Clone, std::fmt::Debug);
static_assertions::assert_not_impl_any!(ObservedOwnedOutput: Copy, Clone, std::fmt::Debug);
static_assertions::assert_not_impl_any!(ObservedWalletBatch: Copy, Clone, std::fmt::Debug);

#[test]
fn derives_only_the_expected_public_branches() {
    let catalog = test_catalog(2);

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
    assert_eq!(batch.outputs().len(), 2);
    assert!(!batch.is_empty());
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
    let prepared_drops_before = prepared_candidate_drop_count();

    assert!(matches!(
        observe_owned_outputs(&catalog, BorrowedSlip77::new(&slip77), &candidate),
        Err(WalletObservationError::OwnedOutputOpening)
    ));
    assert_eq!(scoped_secret_key_drop_count() - key_drops_before, 2);
    assert_eq!(observed_owned_output_drop_count() - output_drops_before, 1);
    assert_eq!(prepared_candidate_drop_count() - prepared_drops_before, 1);
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

    let drops_before = context_randomization_seed_drop_count();
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
    assert!(matches!(
        observe_owned_outputs(&catalog, BorrowedSlip77::new(&slip77), &candidates,),
        Err(WalletObservationError::TransactionValidation)
    ));
    assert_eq!(derivation_call_count(), derivations_before);
    assert_eq!(prepared_candidate_drop_count() - prepared_drops_before, 1);

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
}

struct ConfidentialFixture {
    transaction: Transaction,
    transaction_bytes: Vec<u8>,
    previous_transaction_bytes: Vec<u8>,
    first_asset: AssetId,
    second_asset: AssetId,
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
    confidential_fixture_with_second_blinder(catalog, slip77, slip77)
}

fn confidential_fixture_with_second_blinder(
    catalog: &DescriptorCatalog,
    slip77: &[u8; 32],
    second_output_slip77: &[u8; 32],
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
    let spent_secrets = [
        TxOutSecrets::new(
            first_asset,
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
        input: vec![
            input(OutPoint::new(previous_txid, 0)),
            input(OutPoint::new(previous_txid, 1)),
        ],
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
