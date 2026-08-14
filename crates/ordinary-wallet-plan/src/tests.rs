use static_assertions::assert_not_impl_any;
use wasabi_liquid_native_wallet_facts::{DescriptorCatalog, DescriptorNetwork};

use super::*;

mod conformance;

const SOURCE_A: [u8; 32] = [0x41; 32];
const SOURCE_B: [u8; 32] = [0x42; 32];
const TXID: [u8; 32] = [0x31; 32];
const TEST_DESCRIPTOR: &str = "elwpkh([28b3f14e/84'/1'/0']tpubDC2Q4xK4XH72GM7MowNuajyWVbigRLBWKswyP5T88hpPwu5nGqJWnda8zhJEFt71av73Hm8mUMMFSz9acNVzz8b1UbdSHCDXKTbSv5eEytu/<0;1>/*)#u0khc0kg";
const MAINNET_DESCRIPTOR: &str = "elwpkh([73c5da0a/84'/1776'/0']xpub6CRFzUgHFDaiDAQFNX7VeV9JNPDRabq6NYSpzVZ8zW8ANUCiDdenkb1gBoEZuXNZb3wPc1SVcDXgD2ww5UBtTb8s8ArAbTkoRQ8qn34KgcY/<0;1>/*)";
const TESTNET_ADDRESS: &str = "tlq1qq2xvpcvfup5j8zscjq05u2wxxjcyewk7979f3mmz5l7uw5pqmx6xf5xy50hsn6vhkm5euwt72x878eq6zxx2z58hd7zrsg9qn";
const MAINNET_ADDRESS: &str = "lq1qqf8er278e6nyvuwtgf39e6ewvdcnjupn9a86rzpx655y5lhkt0walu3djf9cklkxd3ryld97hu8h3xepw7sh2rlu7q45dcew5";

assert_not_impl_any!(OrdinaryWalletPlanSelectedRef<'static>: std::fmt::Debug, Clone, Copy);
assert_not_impl_any!(OrdinaryWalletPlanDestinationRef<'static>: std::fmt::Debug, Clone, Copy);
assert_not_impl_any!(OrdinaryWalletPlanRequestRef<'static>: std::fmt::Debug, Clone, Copy);
assert_not_impl_any!(EncodedOrdinaryWalletPlanRequest: std::fmt::Debug, Clone, Copy, std::fmt::Display, Eq, std::hash::Hash, IntoIterator);
assert_not_impl_any!(ParsedOrdinaryWalletPlanRequest: std::fmt::Debug, Clone, Copy, std::fmt::Display, Eq, std::hash::Hash, IntoIterator);
assert_not_impl_any!(PubliclyPreparedOrdinaryWalletPlanRequest<'static>: std::fmt::Debug, Clone, Copy, std::fmt::Display, Eq, std::hash::Hash, IntoIterator);
const _: () = assert!(MAX_REACHABLE_REQUEST_BYTES < MAX_REQUEST_FRAME_BYTES);

fn base_frame() -> Vec<u8> {
    let candidate = [0x01];
    let previous = Vec::new();
    let selected = [OrdinaryWalletPlanSelectedRef::new(
        &TXID,
        0,
        &TESTNET_PEGGED_ASSET,
        10,
        &candidate,
        &previous,
    )];
    let destinations = [OrdinaryWalletPlanDestinationRef::new(
        &TESTNET_PEGGED_ASSET,
        9,
        TESTNET_ADDRESS,
    )];
    let request = OrdinaryWalletPlanRequestRef::new(
        &SOURCE_A,
        7,
        &TESTNET_MANIFEST,
        &TESTNET_PEGGED_ASSET,
        &selected,
        &destinations,
        1,
    );
    encode_request(&request).unwrap().as_bytes().to_vec()
}

fn multi_row_frame() -> Vec<u8> {
    let first_candidate = [0x01];
    let second_candidate = [0x02];
    let previous = vec![vec![0x01], vec![0x02]];
    let first_id = [0x31; 32];
    let second_id = [0x32; 32];
    let selected = [
        OrdinaryWalletPlanSelectedRef::new(
            &first_id,
            0,
            &TESTNET_PEGGED_ASSET,
            5,
            &first_candidate,
            &previous,
        ),
        OrdinaryWalletPlanSelectedRef::new(
            &second_id,
            0,
            &TESTNET_PEGGED_ASSET,
            5,
            &second_candidate,
            &previous,
        ),
    ];
    let destinations = [
        OrdinaryWalletPlanDestinationRef::new(&TESTNET_PEGGED_ASSET, 4, TESTNET_ADDRESS),
        OrdinaryWalletPlanDestinationRef::new(&TESTNET_PEGGED_ASSET, 5, TESTNET_ADDRESS),
    ];
    let request = OrdinaryWalletPlanRequestRef::new(
        &SOURCE_A,
        7,
        &TESTNET_MANIFEST,
        &TESTNET_PEGGED_ASSET,
        &selected,
        &destinations,
        1,
    );
    encode_request(&request).unwrap().as_bytes().to_vec()
}

fn reset_drop_audit() {
    DROP_AUDIT.with(|audit| {
        *audit.borrow_mut() = DropAudit {
            all_zeroized: true,
            ..DropAudit::default()
        }
    });
}

fn configure_panic(point: StagingPoint, completed_before_panic: usize) {
    PANIC_AFTER.with(|remaining| remaining.set(completed_before_panic));
    PANIC_AT.with(|configured| configured.set(Some(point)));
}

fn clear_panic() {
    PANIC_AT.with(|configured| configured.set(None));
    PANIC_AFTER.with(|remaining| remaining.set(0));
}

fn truncate_and_bind_declared_length(frame: &mut Vec<u8>, length: usize) {
    frame.truncate(length);
    frame[8..16].copy_from_slice(&(length as u64).to_le_bytes());
}

#[test]
fn stable_error_map_is_unique_and_privacy_redacted() {
    let cases = [
        (
            OrdinaryWalletPlanWireError::InvalidArgument,
            1,
            "ordinary wallet plan wire argument is invalid",
        ),
        (
            OrdinaryWalletPlanWireError::VersionMismatch,
            2,
            "ordinary wallet plan wire version is unsupported",
        ),
        (
            OrdinaryWalletPlanWireError::InvalidEncoding,
            3,
            "ordinary wallet plan wire encoding is invalid",
        ),
        (
            OrdinaryWalletPlanWireError::LimitExceeded,
            4,
            "ordinary wallet plan wire limit exceeded",
        ),
        (
            OrdinaryWalletPlanWireError::SourceBindingMismatch,
            5,
            "ordinary wallet plan wire source binding does not match",
        ),
        (
            OrdinaryWalletPlanWireError::ContextRejected,
            6,
            "ordinary wallet plan wire context was rejected",
        ),
        (
            OrdinaryWalletPlanWireError::PlanRejected,
            7,
            "ordinary wallet plan wire plan was rejected",
        ),
        (
            OrdinaryWalletPlanWireError::FundingRejected,
            8,
            "ordinary wallet plan wire funding was rejected",
        ),
    ];
    for (error, code, text) in cases {
        assert_eq!(error.code(), code);
        assert_eq!(error.to_string(), text);
        assert!(!text.contains(':'), "error text must not carry details");
    }
}

#[test]
fn encodes_decodes_and_reencodes_exact_bytes() {
    let frame = base_frame();
    assert_eq!(
        frame.len(),
        HEADER_BYTES + SELECTED_FIXED_BYTES + 1 + DESTINATION_FIXED_BYTES + TESTNET_ADDRESS.len()
    );
    assert_eq!(&frame[..4], REQUEST_MAGIC);
    assert_eq!(
        u64::from_le_bytes(frame[8..16].try_into().unwrap()) as usize,
        frame.len()
    );
    let parsed = decode_request(&frame, &SOURCE_A).unwrap();
    assert_eq!(parsed.reencode().unwrap().as_bytes(), frame);

    let mut structurally_valid_unknown_context = frame.clone();
    structurally_valid_unknown_context[64..96].fill(0x99);
    let parsed = decode_request(&structurally_valid_unknown_context, &SOURCE_A).unwrap();
    assert_eq!(
        parsed.reencode().unwrap().as_bytes(),
        structurally_valid_unknown_context
    );
}

#[test]
fn decoder_applies_frozen_error_precedence() {
    let frame = base_frame();
    assert_eq!(
        decode_request(&frame, &[0; 32]).err().unwrap(),
        OrdinaryWalletPlanWireError::InvalidArgument
    );
    assert_eq!(
        decode_request(&frame[..7], &SOURCE_A).err().unwrap(),
        OrdinaryWalletPlanWireError::InvalidEncoding
    );

    let mut wrong_magic = frame.clone();
    wrong_magic[0] ^= 1;
    assert_eq!(
        decode_request(&wrong_magic, &SOURCE_A).err().unwrap(),
        OrdinaryWalletPlanWireError::VersionMismatch
    );

    let mut combined = frame.clone();
    combined[HEADER_BYTES..HEADER_BYTES + 32].fill(0);
    combined[HEADER_BYTES + 76..HEADER_BYTES + 80].fill(0);
    assert_eq!(
        decode_request(&combined, &SOURCE_B).err().unwrap(),
        OrdinaryWalletPlanWireError::SourceBindingMismatch
    );
    assert_eq!(
        decode_request(&combined, &SOURCE_A).err().unwrap(),
        OrdinaryWalletPlanWireError::LimitExceeded
    );

    let mut aggregate_mismatch = frame.clone();
    aggregate_mismatch[136..140].copy_from_slice(&1u32.to_le_bytes());
    assert_eq!(
        decode_request(&aggregate_mismatch, &SOURCE_A)
            .err()
            .unwrap(),
        OrdinaryWalletPlanWireError::InvalidEncoding
    );
}

#[test]
fn each_readable_body_number_precedes_later_same_row_truncation() {
    let selected_start = HEADER_BYTES;
    let destination_start = HEADER_BYTES + SELECTED_FIXED_BYTES + 1;
    let cases = [
        (selected_start + 32, 0x4000_0000_u32.to_le_bytes().to_vec()),
        (
            selected_start + 68,
            (MAX_PLAN_VALUE + 1).to_le_bytes().to_vec(),
        ),
        (
            selected_start + 76,
            ((MAX_TRANSACTION_PAYLOAD_BYTES + 1) as u32)
                .to_le_bytes()
                .to_vec(),
        ),
        (
            selected_start + 80,
            ((MAX_PREVIOUS_TRANSACTION_ENTRIES + 1) as u32)
                .to_le_bytes()
                .to_vec(),
        ),
        (
            destination_start + 32,
            (MAX_PLAN_VALUE + 1).to_le_bytes().to_vec(),
        ),
        (
            destination_start + 40,
            ((MAX_DESTINATION_ADDRESS_BYTES + 1) as u32)
                .to_le_bytes()
                .to_vec(),
        ),
    ];

    for (offset, replacement) in cases {
        let mut frame = base_frame();
        frame[selected_start..selected_start + 32].fill(0);
        if offset >= destination_start {
            frame[selected_start..selected_start + 32].fill(0x31);
            frame[destination_start..destination_start + 32].fill(0);
        }
        frame[offset..offset + replacement.len()].copy_from_slice(&replacement);
        truncate_and_bind_declared_length(&mut frame, offset + replacement.len());
        assert_eq!(
            decode_request(&frame, &SOURCE_A).err().unwrap(),
            OrdinaryWalletPlanWireError::LimitExceeded,
            "numeric field at offset {offset} was masked by later truncation",
        );
    }
}

#[test]
fn accumulated_nonnumeric_body_errors_do_not_mask_later_numeric_limits() {
    let mut previous_length = multi_row_frame();
    previous_length[HEADER_BYTES + 84..HEADER_BYTES + 88].copy_from_slice(&1_u32.to_le_bytes());
    let length_offset = HEADER_BYTES + SELECTED_FIXED_BYTES + 1;
    previous_length[length_offset..length_offset + 4]
        .copy_from_slice(&((MAX_TRANSACTION_PAYLOAD_BYTES + 1) as u32).to_le_bytes());
    truncate_and_bind_declared_length(&mut previous_length, length_offset + 4);
    assert_eq!(
        decode_request(&previous_length, &SOURCE_A).err().unwrap(),
        OrdinaryWalletPlanWireError::LimitExceeded
    );

    let mut header_invalid = base_frame();
    header_invalid[16..20].copy_from_slice(&1_u32.to_le_bytes());
    header_invalid[HEADER_BYTES + 32..HEADER_BYTES + 36]
        .copy_from_slice(&0x4000_0000_u32.to_le_bytes());
    assert_eq!(
        decode_request(&header_invalid, &SOURCE_A).err().unwrap(),
        OrdinaryWalletPlanWireError::InvalidEncoding,
        "fixed-header canonical rejection must precede body limits",
    );
}

#[test]
fn header_and_body_canonical_fields_are_all_enforced() {
    let frame = base_frame();
    let mutations: &[(usize, &[u8], OrdinaryWalletPlanWireError)] = &[
        (
            4,
            &2u16.to_le_bytes(),
            OrdinaryWalletPlanWireError::VersionMismatch,
        ),
        (
            6,
            &151u16.to_le_bytes(),
            OrdinaryWalletPlanWireError::VersionMismatch,
        ),
        (
            16,
            &1u32.to_le_bytes(),
            OrdinaryWalletPlanWireError::InvalidEncoding,
        ),
        (
            20,
            &1u32.to_le_bytes(),
            OrdinaryWalletPlanWireError::InvalidEncoding,
        ),
        (
            140,
            &1u32.to_le_bytes(),
            OrdinaryWalletPlanWireError::InvalidEncoding,
        ),
        (
            HEADER_BYTES + 84,
            &1u32.to_le_bytes(),
            OrdinaryWalletPlanWireError::InvalidEncoding,
        ),
        (
            HEADER_BYTES + SELECTED_FIXED_BYTES + 1 + 44,
            &1u32.to_le_bytes(),
            OrdinaryWalletPlanWireError::InvalidEncoding,
        ),
    ];
    for (offset, replacement, expected) in mutations {
        let mut mutated = frame.clone();
        mutated[*offset..*offset + replacement.len()].copy_from_slice(replacement);
        assert_eq!(
            decode_request(&mutated, &SOURCE_A).err().unwrap(),
            *expected
        );
    }

    let mut trailing = frame.clone();
    trailing.push(0);
    let trailing_length = trailing.len() as u64;
    trailing[8..16].copy_from_slice(&trailing_length.to_le_bytes());
    assert_eq!(
        decode_request(&trailing, &SOURCE_A).err().unwrap(),
        OrdinaryWalletPlanWireError::InvalidEncoding
    );
}

#[test]
fn reachable_maximum_is_the_exact_symbolic_sum() {
    assert_eq!(
        HEADER_BYTES
            + MAX_SELECTED_INPUTS * SELECTED_FIXED_BYTES
            + MAX_CONFIDENTIAL_DESTINATIONS * DESTINATION_FIXED_BYTES
            + MAX_CONFIDENTIAL_DESTINATIONS * MAX_DESTINATION_ADDRESS_BYTES
            + MAX_PREVIOUS_TRANSACTION_ENTRIES * LENGTH_PREFIX_BYTES
            + MAX_AGGREGATE_TRANSACTION_BYTES,
        MAX_REACHABLE_REQUEST_BYTES
    );
    assert_eq!(
        MAX_SELECTED_INPUTS,
        wasabi_liquid_native_wallet_facts::MAX_SELECTED_OUTPUTS
    );
    assert_eq!(
        MAX_DESTINATION_ADDRESS_BYTES,
        wasabi_liquid_native_address::MAX_ADDRESS_BYTES
    );
    assert_eq!(
        MAX_TRANSACTION_PAYLOAD_BYTES,
        wasabi_liquid_native_wallet_facts::MAX_TRANSACTION_BYTES
    );
    assert_eq!(
        MAX_PREVIOUS_TRANSACTION_ENTRIES,
        wasabi_liquid_native_wallet_facts::MAX_PREVIOUS_TRANSACTIONS_PER_BATCH
    );
    assert_eq!(
        MAX_AGGREGATE_TRANSACTION_BYTES,
        wasabi_liquid_native_wallet_facts::MAX_BATCH_BYTES
    );
    assert_eq!(
        MAX_PLAN_VALUE,
        wasabi_liquid_native_ordinary_pset::MAX_ORDINARY_VALUE
    );
}

#[test]
fn encoder_separates_context_plan_and_structural_rejections() {
    let candidate = [0x01];
    let previous = Vec::new();
    let selected = [OrdinaryWalletPlanSelectedRef::new(
        &TXID,
        0,
        &TESTNET_PEGGED_ASSET,
        10,
        &candidate,
        &previous,
    )];
    let destinations = [OrdinaryWalletPlanDestinationRef::new(
        &TESTNET_PEGGED_ASSET,
        9,
        TESTNET_ADDRESS,
    )];

    let unknown_manifest = [0x99; 32];
    let request = OrdinaryWalletPlanRequestRef::new(
        &SOURCE_A,
        7,
        &unknown_manifest,
        &TESTNET_PEGGED_ASSET,
        &selected,
        &destinations,
        1,
    );
    assert_eq!(
        encode_request(&request).err().unwrap(),
        OrdinaryWalletPlanWireError::ContextRejected
    );

    let wrong_profile = "lq1qqf8er278e6nyvuwtgf39e6ewvdcnjupn9a86rzpx655y5lhkt0walu3djf9cklkxd3ryld97hu8h3xepw7sh2rlu7q45dcew5";
    let wrong_destinations = [OrdinaryWalletPlanDestinationRef::new(
        &TESTNET_PEGGED_ASSET,
        9,
        wrong_profile,
    )];
    let request = OrdinaryWalletPlanRequestRef::new(
        &SOURCE_A,
        7,
        &TESTNET_MANIFEST,
        &TESTNET_PEGGED_ASSET,
        &selected,
        &wrong_destinations,
        1,
    );
    assert_eq!(
        encode_request(&request).err().unwrap(),
        OrdinaryWalletPlanWireError::PlanRejected
    );

    let zero_txid = [0; 32];
    let invalid_selected = [OrdinaryWalletPlanSelectedRef::new(
        &zero_txid,
        0,
        &TESTNET_PEGGED_ASSET,
        10,
        &candidate,
        &previous,
    )];
    let request = OrdinaryWalletPlanRequestRef::new(
        &SOURCE_A,
        7,
        &TESTNET_MANIFEST,
        &TESTNET_PEGGED_ASSET,
        &invalid_selected,
        &destinations,
        1,
    );
    assert_eq!(
        encode_request(&request).err().unwrap(),
        OrdinaryWalletPlanWireError::InvalidEncoding
    );

    let request = OrdinaryWalletPlanRequestRef::new(
        &[0; 32],
        7,
        &TESTNET_MANIFEST,
        &TESTNET_PEGGED_ASSET,
        &selected,
        &destinations,
        1,
    );
    assert_eq!(
        encode_request(&request).err().unwrap(),
        OrdinaryWalletPlanWireError::InvalidArgument
    );
}

#[test]
fn both_reviewed_contexts_bind_exact_consensus_asset_bytes() {
    assert_eq!(AssetId::LIQUID_BTC.to_byte_array(), MAINNET_PEGGED_ASSET);
    assert_eq!(
        AssetId::LIQUIDTESTNET_BTC.to_byte_array(),
        TESTNET_PEGGED_ASSET
    );

    let candidate = [0x01];
    let previous = Vec::new();
    let selected = [OrdinaryWalletPlanSelectedRef::new(
        &TXID,
        0,
        &MAINNET_PEGGED_ASSET,
        10,
        &candidate,
        &previous,
    )];
    let destinations = [OrdinaryWalletPlanDestinationRef::new(
        &MAINNET_PEGGED_ASSET,
        9,
        MAINNET_ADDRESS,
    )];
    let request = OrdinaryWalletPlanRequestRef::new(
        &SOURCE_A,
        7,
        &MAINNET_MANIFEST,
        &MAINNET_PEGGED_ASSET,
        &selected,
        &destinations,
        1,
    );
    assert!(encode_request(&request).is_ok());
}

#[test]
fn reviewed_context_is_exactly_two_armed_and_never_elements_default() {
    let main = reviewed_context(&MAINNET_MANIFEST, &MAINNET_PEGGED_ASSET).unwrap();
    assert!(matches!(
        main.address_profile,
        LiquidAddressProfile::LiquidMainnet
    ));
    assert_eq!(main.descriptor_network, DescriptorNetwork::Mainnet);

    let test = reviewed_context(&TESTNET_MANIFEST, &TESTNET_PEGGED_ASSET).unwrap();
    assert!(matches!(
        test.address_profile,
        LiquidAddressProfile::LiquidTestnet
    ));
    assert_eq!(test.descriptor_network, DescriptorNetwork::Test);

    assert!(reviewed_context(&MAINNET_MANIFEST, &TESTNET_PEGGED_ASSET).is_none());
    assert!(reviewed_context(&TESTNET_MANIFEST, &MAINNET_PEGGED_ASSET).is_none());
    assert!(reviewed_context(&[0x55; 32], &[0x66; 32]).is_none());
}

#[test]
fn selected_and_previous_wire_order_is_strict_and_never_sorted() {
    let candidate = [0x01];
    let previous = Vec::new();
    let mut display_first = [0; 32];
    display_first[0] = 2;
    display_first[31] = 1;
    let mut display_second = [0; 32];
    display_second[0] = 1;
    display_second[31] = 2;
    let selected = [
        OrdinaryWalletPlanSelectedRef::new(
            &display_first,
            0,
            &TESTNET_PEGGED_ASSET,
            10,
            &candidate,
            &previous,
        ),
        OrdinaryWalletPlanSelectedRef::new(
            &display_second,
            0,
            &TESTNET_PEGGED_ASSET,
            10,
            &candidate,
            &previous,
        ),
    ];
    let destinations = [OrdinaryWalletPlanDestinationRef::new(
        &TESTNET_PEGGED_ASSET,
        19,
        TESTNET_ADDRESS,
    )];
    let request = OrdinaryWalletPlanRequestRef::new(
        &SOURCE_A,
        7,
        &TESTNET_MANIFEST,
        &TESTNET_PEGGED_ASSET,
        &selected,
        &destinations,
        1,
    );
    assert!(encode_request(&request).is_ok());

    let reversed = [
        OrdinaryWalletPlanSelectedRef::new(
            &display_second,
            0,
            &TESTNET_PEGGED_ASSET,
            10,
            &candidate,
            &previous,
        ),
        OrdinaryWalletPlanSelectedRef::new(
            &display_first,
            0,
            &TESTNET_PEGGED_ASSET,
            10,
            &candidate,
            &previous,
        ),
    ];
    let request = OrdinaryWalletPlanRequestRef::new(
        &SOURCE_A,
        7,
        &TESTNET_MANIFEST,
        &TESTNET_PEGGED_ASSET,
        &reversed,
        &destinations,
        1,
    );
    assert_eq!(
        encode_request(&request).err().unwrap(),
        OrdinaryWalletPlanWireError::InvalidEncoding
    );

    let duplicate_previous = vec![vec![1], vec![1]];
    let selected = [OrdinaryWalletPlanSelectedRef::new(
        &TXID,
        0,
        &TESTNET_PEGGED_ASSET,
        10,
        &candidate,
        &duplicate_previous,
    )];
    let destinations = [OrdinaryWalletPlanDestinationRef::new(
        &TESTNET_PEGGED_ASSET,
        9,
        TESTNET_ADDRESS,
    )];
    let request = OrdinaryWalletPlanRequestRef::new(
        &SOURCE_A,
        7,
        &TESTNET_MANIFEST,
        &TESTNET_PEGGED_ASSET,
        &selected,
        &destinations,
        1,
    );
    assert_eq!(
        encode_request(&request).err().unwrap(),
        OrdinaryWalletPlanWireError::InvalidEncoding
    );
}

#[test]
fn prepare_binds_catalog_before_rejecting_invalid_funding() {
    let frame = base_frame();
    let secp = Secp256k1::new();
    let test_catalog =
        DescriptorCatalog::derive(TEST_DESCRIPTOR, DescriptorNetwork::Test, 0).unwrap();
    assert_eq!(
        decode_request(&frame, &SOURCE_A)
            .unwrap()
            .prepare(&test_catalog, &secp)
            .err()
            .unwrap(),
        OrdinaryWalletPlanWireError::FundingRejected
    );

    let mainnet_catalog =
        DescriptorCatalog::derive(MAINNET_DESCRIPTOR, DescriptorNetwork::Mainnet, 0).unwrap();
    assert_eq!(
        decode_request(&frame, &SOURCE_A)
            .unwrap()
            .prepare(&mainnet_catalog, &secp)
            .err()
            .unwrap(),
        OrdinaryWalletPlanWireError::ContextRejected
    );
}

#[test]
fn prepare_distinguishes_context_plan_and_funding_phases() {
    let frame = base_frame();
    let catalog = DescriptorCatalog::derive(TEST_DESCRIPTOR, DescriptorNetwork::Test, 0).unwrap();
    let secp = Secp256k1::new();

    let mut wrong_context = frame.clone();
    wrong_context[96] ^= 1;
    assert_eq!(
        decode_request(&wrong_context, &SOURCE_A)
            .unwrap()
            .prepare(&catalog, &secp)
            .err()
            .unwrap(),
        OrdinaryWalletPlanWireError::ContextRejected
    );

    let mut unbalanced = frame.clone();
    let destination_value = HEADER_BYTES + SELECTED_FIXED_BYTES + 1 + 32;
    unbalanced[destination_value..destination_value + 8].copy_from_slice(&8u64.to_le_bytes());
    assert_eq!(
        decode_request(&unbalanced, &SOURCE_A)
            .unwrap()
            .prepare(&catalog, &secp)
            .err()
            .unwrap(),
        OrdinaryWalletPlanWireError::PlanRejected
    );

    assert_eq!(
        decode_request(&frame, &SOURCE_A)
            .unwrap()
            .prepare(&catalog, &secp)
            .err()
            .unwrap(),
        OrdinaryWalletPlanWireError::FundingRejected
    );
}

#[test]
fn owned_storage_drop_paths_report_zeroization() {
    reset_drop_audit();
    let frame = base_frame();
    drop(decode_request(&frame, &SOURCE_A).unwrap());
    let audit = DROP_AUDIT.with(|audit| *audit.borrow());
    assert!(audit.encoded >= 1);
    assert!(audit.borrowed_scalar >= 3);
    assert!(audit.scalar >= 1);
    assert!(audit.identifier >= 1);
    assert!(audit.header >= 2);
    assert!(audit.view_facts >= 1);
    assert_eq!(audit.parsed, 1);
    assert_eq!(audit.selected, 1);
    assert_eq!(audit.destination, 1);
    assert!(audit.writer >= 1);
    assert!(audit.all_zeroized);
}

#[test]
fn parsed_staging_unwinds_clear_every_owned_raw_buffer() {
    let candidate = [0x02];
    let previous = vec![vec![0x01]];
    let selected = [OrdinaryWalletPlanSelectedRef::new(
        &TXID,
        0,
        &TESTNET_PEGGED_ASSET,
        10,
        &candidate,
        &previous,
    )];
    let destinations = [OrdinaryWalletPlanDestinationRef::new(
        &TESTNET_PEGGED_ASSET,
        9,
        TESTNET_ADDRESS,
    )];
    let request = OrdinaryWalletPlanRequestRef::new(
        &SOURCE_A,
        7,
        &TESTNET_MANIFEST,
        &TESTNET_PEGGED_ASSET,
        &selected,
        &destinations,
        1,
    );
    let frame = encode_request(&request).unwrap().as_bytes().to_vec();

    for point in [
        StagingPoint::ParsedCandidate,
        StagingPoint::ParsedPrevious,
        StagingPoint::ParsedAddress,
    ] {
        reset_drop_audit();
        configure_panic(point, 0);
        assert!(std::panic::catch_unwind(|| decode_request(&frame, &SOURCE_A)).is_err());
        clear_panic();
        let audit = DROP_AUDIT.with(|audit| *audit.borrow());
        assert!(audit.all_zeroized);
        if point == StagingPoint::ParsedPrevious {
            assert_eq!(audit.temporary, 1);
        }
    }
}

#[test]
fn preparation_staging_unwinds_clear_new_crate_owned_storage() {
    let frame = base_frame();
    let catalog = DescriptorCatalog::derive(TEST_DESCRIPTOR, DescriptorNetwork::Test, 0).unwrap();
    let secp = Secp256k1::new();
    for point in [
        StagingPoint::PreparedOutput,
        StagingPoint::PreparedExpectation,
        StagingPoint::PreparedBorrowedBatch,
        StagingPoint::PreparedSelectedBatch,
    ] {
        reset_drop_audit();
        configure_panic(point, 0);
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let parsed = decode_request(&frame, &SOURCE_A).unwrap();
                let _ = parsed.prepare(&catalog, &secp);
            }))
            .is_err()
        );
        clear_panic();
        let audit = DROP_AUDIT.with(|audit| *audit.borrow());
        assert!(audit.all_zeroized);
        assert_eq!(audit.parsed, 1);
        assert_eq!(audit.selected, 1);
        assert_eq!(audit.destination, 1);
        if point == StagingPoint::PreparedExpectation {
            assert_eq!(audit.expectation, 1);
        }
        if matches!(
            point,
            StagingPoint::PreparedBorrowedBatch | StagingPoint::PreparedSelectedBatch
        ) {
            assert_eq!(audit.prepared_borrowed_batch, 1);
        }
        if point == StagingPoint::PreparedSelectedBatch {
            assert_eq!(audit.prepared_selected_batch, 1);
        }
        assert_eq!(
            audit.staged_fee,
            usize::from(point != StagingPoint::PreparedOutput)
        );
    }
}

#[test]
fn fee_staging_clears_asset_and_value_on_drop_transfer_and_unwind() {
    let asset = AssetId::LIQUIDTESTNET_BTC;

    reset_drop_audit();
    drop(StagedFee::new(ExplicitFee::new(asset, 17).unwrap()));
    let dropped = DROP_AUDIT.with(|audit| *audit.borrow());
    assert!(dropped.all_zeroized);
    assert_eq!(dropped.staged_fee, 1);

    reset_drop_audit();
    let mut staged = StagedFee::new(ExplicitFee::new(asset, 17).unwrap());
    let prepared = staged.transfer();
    let transferred = DROP_AUDIT.with(|audit| *audit.borrow());
    assert!(transferred.all_zeroized);
    assert_eq!(transferred.fee_transfer, 1);
    drop(prepared);
    drop(staged);
    let completed = DROP_AUDIT.with(|audit| *audit.borrow());
    assert!(completed.all_zeroized);
    assert_eq!(completed.prepared_fee, 1);
    assert_eq!(completed.staged_fee, 1);

    reset_drop_audit();
    configure_panic(StagingPoint::FeeTransferCleared, 0);
    assert!(
        std::panic::catch_unwind(|| {
            let mut staged = StagedFee::new(ExplicitFee::new(asset, 17).unwrap());
            let _ = staged.transfer();
        })
        .is_err()
    );
    clear_panic();
    let unwind = DROP_AUDIT.with(|audit| *audit.borrow());
    assert!(unwind.all_zeroized);
    assert_eq!(unwind.fee_transfer, 1);
    assert_eq!(unwind.prepared_fee, 1);
    assert_eq!(unwind.staged_fee, 1);
}

#[test]
fn every_encoding_and_completed_multi_row_transfer_unwinds_cleanly() {
    for (point, completed_before_panic) in [
        (StagingPoint::ValidatedTotals, 0),
        (StagingPoint::EncodedSelectedRow, 1),
        (StagingPoint::EncodedDestinationRow, 1),
        (StagingPoint::EncodedWriterComplete, 0),
        (StagingPoint::WriterTransfer, 0),
    ] {
        reset_drop_audit();
        configure_panic(point, completed_before_panic);
        assert!(
            std::panic::catch_unwind(|| {
                let _ = multi_row_frame();
            })
            .is_err()
        );
        clear_panic();
        let audit = DROP_AUDIT.with(|audit| *audit.borrow());
        assert!(audit.all_zeroized);
        assert!(audit.scalar > 0);
        assert!(audit.view_facts > 0 || point == StagingPoint::ValidatedTotals);
        if point != StagingPoint::ValidatedTotals {
            assert_eq!(audit.writer, 1);
        }
    }
}

#[test]
fn every_header_body_and_completed_owned_row_transfer_unwinds_cleanly() {
    let frame = multi_row_frame();
    for (point, completed_before_panic) in [
        (StagingPoint::HeaderComplete, 0),
        (StagingPoint::ScannedTotals, 0),
        (StagingPoint::ParsedPreviousRow, 1),
        (StagingPoint::ParsedSelectedRow, 1),
        (StagingPoint::ParsedDestinationRow, 1),
        (StagingPoint::ParsedFinalAssembly, 0),
    ] {
        reset_drop_audit();
        configure_panic(point, completed_before_panic);
        assert!(std::panic::catch_unwind(|| decode_request(&frame, &SOURCE_A)).is_err());
        clear_panic();
        let audit = DROP_AUDIT.with(|audit| *audit.borrow());
        assert!(audit.all_zeroized);
        assert!(audit.scalar > 0);
        assert!(audit.identifier > 0);
        assert!(audit.header > 0);
        if matches!(
            point,
            StagingPoint::ParsedPreviousRow
                | StagingPoint::ParsedSelectedRow
                | StagingPoint::ParsedDestinationRow
                | StagingPoint::ParsedFinalAssembly
        ) {
            assert!(audit.selected > 0);
        }
        if matches!(
            point,
            StagingPoint::ParsedDestinationRow | StagingPoint::ParsedFinalAssembly
        ) {
            assert!(audit.destination > 0);
        }
    }
}

#[test]
fn scalar_and_identifier_cleanup_covers_success_error_and_unwind() {
    reset_drop_audit();
    let frame = multi_row_frame();
    drop(decode_request(&frame, &SOURCE_A).unwrap());
    let success = DROP_AUDIT.with(|audit| *audit.borrow());
    assert!(success.all_zeroized);
    assert!(success.scalar > 0);
    assert!(success.identifier > 0);
    assert!(success.header >= 2);

    reset_drop_audit();
    let mut malformed = frame.clone();
    malformed[140] = 1;
    assert_eq!(
        decode_request(&malformed, &SOURCE_A).err().unwrap(),
        OrdinaryWalletPlanWireError::InvalidEncoding
    );
    let error = DROP_AUDIT.with(|audit| *audit.borrow());
    assert!(error.all_zeroized);
    assert!(error.scalar > 0);
    assert!(error.identifier > 0);

    reset_drop_audit();
    configure_panic(StagingPoint::ScannedTotals, 0);
    assert!(std::panic::catch_unwind(|| decode_request(&frame, &SOURCE_A)).is_err());
    clear_panic();
    let unwind = DROP_AUDIT.with(|audit| *audit.borrow());
    assert!(unwind.all_zeroized);
    assert!(unwind.scalar > 0);
    assert!(unwind.identifier > 0);
    assert!(unwind.header > 0);
}

#[test]
fn final_prepared_assembly_unwind_destroys_the_completed_owner() {
    let catalog = DescriptorCatalog::derive(TEST_DESCRIPTOR, DescriptorNetwork::Test, 0).unwrap();
    let outpoint = OutPoint::new(Txid::from_byte_array(TXID), 0);
    let asset = AssetId::LIQUIDTESTNET_BTC;
    let value = 10_u64;
    let candidate = [0x01];
    let previous = Vec::new();
    let borrowed = [BorrowedSelectedOutput::new(
        &outpoint, &asset, &value, &candidate, &previous,
    )];
    let selected = SelectedOutputBatch::new(&borrowed).unwrap();
    let address =
        ConfidentialLiquidAddress::parse(TESTNET_ADDRESS, LiquidAddressProfile::LiquidTestnet)
            .unwrap();
    let outputs = vec![ConfidentialOutput::from_address(asset, 9, &address).unwrap()];
    let fee = PreparedFee {
        value: ExplicitFee::new(asset, 1).unwrap(),
    };

    reset_drop_audit();
    configure_panic(StagingPoint::FinalPreparedAssembly, 0);
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = assemble_prepared(
                &catalog,
                selected,
                outputs,
                fee,
                ScopedU64(7),
                ScopedArray(TESTNET_MANIFEST),
                ScopedArray(TESTNET_PEGGED_ASSET),
                ScopedUsize(1),
                ScopedUsize(1),
            );
        }))
        .is_err()
    );
    clear_panic();
    let audit = DROP_AUDIT.with(|audit| *audit.borrow());
    assert!(audit.all_zeroized);
    assert_eq!(audit.prepared, 1);
    assert_eq!(audit.prepared_fee, 1);
}
