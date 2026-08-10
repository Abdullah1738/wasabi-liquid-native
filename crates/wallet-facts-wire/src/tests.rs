use std::panic::{AssertUnwindSafe, catch_unwind};

use static_assertions::assert_not_impl_any;

use super::*;
use crate::reader::Reader;
use crate::request::{panic_during_request_staging, validate_outer_length};
use crate::response::{
    InputSource, OutputSource, ResponseSource, TransactionSource, encode_source,
    panic_after_scratch_fill, panic_during_response_staging, scratch_last_capacity,
    scratch_pass_invocation_count, scratch_point_drop_count,
};
use crate::writer::{Writer, checked_add, checked_multiply};

const TEST_DESCRIPTOR: &str = "elwpkh([28b3f14e/84'/1'/0']tpubDC2Q4xK4XH72GM7MowNuajyWVbigRLBWKswyP5T88hpPwu5nGqJWnda8zhJEFt71av73Hm8mUMMFSz9acNVzz8b1UbdSHCDXKTbSv5eEytu/<0;1>/*)#u0khc0kg";
const SOURCE_A: [u8; 32] = [0x41; 32];
const SOURCE_B: [u8; 32] = [0x42; 32];
const GENERATOR_PUBLIC_KEY: [u8; 33] = [
    0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b,
    0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17,
    0x98,
];
const GENERATOR_P2WPKH_SCRIPT: [u8; 22] = [
    0x00, 0x14, 0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54, 0x94, 0x1c, 0x45, 0xd1, 0xb3,
    0xa3, 0x23, 0xf1, 0x43, 0x3b, 0xd6,
];

assert_not_impl_any!(EncodedWalletFactsRequest: std::fmt::Debug, Clone, Copy);
assert_not_impl_any!(EncodedWalletFactsResponse: std::fmt::Debug, Clone, Copy);
assert_not_impl_any!(ParsedWalletFactsRequest: std::fmt::Debug, Clone, Copy);
assert_not_impl_any!(PreparedWalletFactsRequest: std::fmt::Debug, Clone, Copy);
assert_not_impl_any!(DecodedWalletFactsResponse: std::fmt::Debug, Clone, Copy, std::fmt::Display);
assert_not_impl_any!(DecodedWalletTransaction: std::fmt::Debug, Clone, Copy, std::fmt::Display);
assert_not_impl_any!(DecodedTransactionInput: std::fmt::Debug, Clone, Copy, std::fmt::Display);
assert_not_impl_any!(DecodedOwnedOutput: std::fmt::Debug, Clone, Copy, std::fmt::Display);

struct TestInput {
    previous_transaction_id: [u8; 32],
    previous_output_index: u32,
}

impl InputSource for TestInput {
    fn previous_transaction_id(&self) -> &[u8; 32] {
        &self.previous_transaction_id
    }

    fn previous_output_index(&self) -> u32 {
        self.previous_output_index
    }
}

struct TestTransaction {
    transaction_id: [u8; 32],
    binding: [u8; 32],
    inputs: Vec<TestInput>,
}

impl TransactionSource for TestTransaction {
    type Input = TestInput;

    fn transaction_id(&self) -> &[u8; 32] {
        &self.transaction_id
    }

    fn transaction_witness_binding(&self) -> &[u8; 32] {
        &self.binding
    }

    fn inputs(&self) -> &[Self::Input] {
        &self.inputs
    }
}

struct TestOutput {
    transaction_id: [u8; 32],
    output_index: u32,
    binding: [u8; 32],
    script_pubkey: Vec<u8>,
    spend_public_key: [u8; 33],
    blinding_public_key: [u8; 33],
    branch: DescriptorBranch,
    derivation_index: u32,
    asset_id: [u8; 32],
    value: u64,
}

impl OutputSource for TestOutput {
    fn transaction_id(&self) -> &[u8; 32] {
        &self.transaction_id
    }

    fn output_index(&self) -> u32 {
        self.output_index
    }

    fn transaction_witness_binding(&self) -> &[u8; 32] {
        &self.binding
    }

    fn script_pubkey(&self) -> &[u8] {
        &self.script_pubkey
    }

    fn spend_public_key(&self) -> &[u8; 33] {
        &self.spend_public_key
    }

    fn blinding_public_key(&self) -> &[u8; 33] {
        &self.blinding_public_key
    }

    fn branch(&self) -> DescriptorBranch {
        self.branch
    }

    fn derivation_index(&self) -> u32 {
        self.derivation_index
    }

    fn asset_id(&self) -> &[u8; 32] {
        &self.asset_id
    }

    fn value(&self) -> u64 {
        self.value
    }
}

struct TestBatch {
    transactions: Vec<TestTransaction>,
    outputs: Vec<TestOutput>,
}

struct CompactInput(u32);

impl InputSource for CompactInput {
    fn previous_transaction_id(&self) -> &[u8; 32] {
        static PREVIOUS_TRANSACTION_ID: [u8; 32] = [0x31; 32];
        &PREVIOUS_TRANSACTION_ID
    }

    fn previous_output_index(&self) -> u32 {
        self.0
    }
}

struct CompactTransaction {
    transaction_id: [u8; 32],
    binding: [u8; 32],
    inputs: Vec<CompactInput>,
}

impl TransactionSource for CompactTransaction {
    type Input = CompactInput;

    fn transaction_id(&self) -> &[u8; 32] {
        &self.transaction_id
    }

    fn transaction_witness_binding(&self) -> &[u8; 32] {
        &self.binding
    }

    fn inputs(&self) -> &[Self::Input] {
        &self.inputs
    }
}

struct CompactOutput {
    transaction_id: [u8; 32],
    binding: [u8; 32],
    output_index: u32,
}

impl OutputSource for CompactOutput {
    fn transaction_id(&self) -> &[u8; 32] {
        &self.transaction_id
    }

    fn output_index(&self) -> u32 {
        self.output_index
    }

    fn transaction_witness_binding(&self) -> &[u8; 32] {
        &self.binding
    }

    fn script_pubkey(&self) -> &[u8] {
        &GENERATOR_P2WPKH_SCRIPT
    }

    fn spend_public_key(&self) -> &[u8; 33] {
        &GENERATOR_PUBLIC_KEY
    }

    fn blinding_public_key(&self) -> &[u8; 33] {
        &GENERATOR_PUBLIC_KEY
    }

    fn branch(&self) -> DescriptorBranch {
        DescriptorBranch::External
    }

    fn derivation_index(&self) -> u32 {
        0
    }

    fn asset_id(&self) -> &[u8; 32] {
        static ASSET_ID: [u8; 32] = [0x71; 32];
        &ASSET_ID
    }

    fn value(&self) -> u64 {
        1
    }
}

struct CompactBatch {
    transactions: Vec<CompactTransaction>,
    outputs: Vec<CompactOutput>,
}

impl ResponseSource for CompactBatch {
    type Transaction = CompactTransaction;
    type Output = CompactOutput;

    fn transactions(&self) -> &[Self::Transaction] {
        &self.transactions
    }

    fn outputs(&self) -> &[Self::Output] {
        &self.outputs
    }
}

impl ResponseSource for TestBatch {
    type Transaction = TestTransaction;
    type Output = TestOutput;

    fn transactions(&self) -> &[Self::Transaction] {
        &self.transactions
    }

    fn outputs(&self) -> &[Self::Output] {
        &self.outputs
    }
}

#[test]
fn stable_error_map_is_unique_and_privacy_redacted() {
    let cases = [
        (
            WalletFactsWireError::InvalidArgument,
            1,
            "wallet facts wire argument is invalid",
        ),
        (
            WalletFactsWireError::VersionMismatch,
            2,
            "wallet facts wire version is unsupported",
        ),
        (
            WalletFactsWireError::InvalidEncoding,
            3,
            "wallet facts wire encoding is invalid",
        ),
        (
            WalletFactsWireError::LimitExceeded,
            4,
            "wallet facts wire limit exceeded",
        ),
        (
            WalletFactsWireError::DescriptorRejected,
            5,
            "wallet facts descriptor was rejected",
        ),
        (
            WalletFactsWireError::CandidateRejected,
            6,
            "wallet facts candidate batch was rejected",
        ),
        (
            WalletFactsWireError::ObservationRejected,
            7,
            "wallet facts observation was rejected",
        ),
        (
            WalletFactsWireError::SourceBindingMismatch,
            8,
            "wallet facts source binding does not match",
        ),
    ];
    for (index, (error, code, text)) in cases.iter().enumerate() {
        assert_eq!(error.code(), *code);
        assert_eq!(error.to_string(), *text);
        assert!(cases[index + 1..].iter().all(|(_, other, _)| other != code));
        assert!(!text.contains(TEST_DESCRIPTOR));
        assert!(!text.contains("41"));
        assert!(std::error::Error::source(error).is_none());
    }
}

#[test]
fn exact_empty_request_bytes_round_trip_and_prepare() {
    let candidates = [];
    let request = WalletFactsRequestRef::new(
        &SOURCE_A,
        DescriptorNetwork::Test,
        0,
        TEST_DESCRIPTOR,
        &candidates,
    );
    let encoded = encode_request(&request).unwrap();
    let expected = raw_empty_request(TEST_DESCRIPTOR.as_bytes(), &SOURCE_A, 1, 0);
    assert_eq!(encoded.as_bytes(), expected);

    let parsed = decode_request(encoded.as_bytes()).unwrap();
    assert_eq!(parsed.source_epoch(), &SOURCE_A);
    assert_eq!(parsed.descriptor_network(), DescriptorNetwork::Test);
    assert_eq!(parsed.last_derivation_index(), 0);
    assert_eq!(parsed.public_descriptor(), TEST_DESCRIPTOR);
    let reencoded = parsed.reencode().unwrap();
    assert_eq!(reencoded.as_bytes(), encoded.as_bytes());
    let prepared = parsed.prepare().unwrap();
    assert_eq!(prepared.source_epoch(), &SOURCE_A);
    assert_eq!(prepared.descriptor_catalog().script_count(), 2);
    let _ = prepared.candidate_batch();
}

#[test]
fn valid_nonempty_request_encode_parse_reencode_and_prepare() {
    let previous_transactions = vec![vec![4_u8], vec![5_u8, 6]];
    let candidate = WalletFactsCandidateRef::new(&[1, 2, 3], &previous_transactions);
    let candidates = [candidate];
    let request = WalletFactsRequestRef::new(
        &SOURCE_A,
        DescriptorNetwork::Test,
        0,
        TEST_DESCRIPTOR,
        &candidates,
    );
    let encoded = encode_request(&request).unwrap();
    let parsed = decode_request(encoded.as_bytes()).unwrap();
    assert_eq!(parsed.reencode().unwrap().as_bytes(), encoded.as_bytes());
    let prepared = parsed.prepare().unwrap();
    assert_eq!(prepared.source_epoch(), &SOURCE_A);
    assert_eq!(prepared.descriptor_catalog().script_count(), 2);
    let _ = prepared.candidate_batch();
}

#[test]
fn exact_empty_response_bytes_round_trip_and_binding() {
    let batch = TestBatch {
        transactions: vec![],
        outputs: vec![],
    };
    let encoded = encode_source(&batch, &SOURCE_A).unwrap();
    let mut expected = Vec::new();
    expected.extend_from_slice(b"WLFV");
    expected.extend_from_slice(&1_u16.to_le_bytes());
    expected.extend_from_slice(&64_u16.to_le_bytes());
    expected.extend_from_slice(&64_u64.to_le_bytes());
    expected.extend_from_slice(&[0; 16]);
    expected.extend_from_slice(&SOURCE_A);
    assert_eq!(encoded.as_bytes(), expected);
    let decoded = decode_response(encoded.as_bytes(), &SOURCE_A).unwrap();
    assert!(decoded.is_empty());
    assert_eq!(decoded.source_epoch(), &SOURCE_A);
    assert!(matches!(
        decode_response(encoded.as_bytes(), &[0; 32]),
        Err(WalletFactsWireError::InvalidArgument)
    ));
    assert!(matches!(
        decode_response(encoded.as_bytes(), &SOURCE_B),
        Err(WalletFactsWireError::SourceBindingMismatch)
    ));
}

#[test]
fn request_structural_rules_and_late_semantic_rejection_are_distinct() {
    for descriptor in [
        TEST_DESCRIPTOR.trim_end_matches("#u0khc0kg"),
        "#u0khc0kg",
        "elwpkh(x)#u0khc0kG",
        "elwpkh(x)#bbbbbbbb",
        "elwpkh(x)#u0khc0kg#u0khc0kg",
        "elwpkh( x)#u0khc0kg",
        "elwpkh(\tx)#u0khc0kg",
        "elwpkh(\nx)#u0khc0kg",
        "elwpkh(\rx)#u0khc0kg",
        "elwpkh(\u{000b}x)#u0khc0kg",
        "elwpkh(\u{000c}x)#u0khc0kg",
        "elwpkh(\0x)#u0khc0kg",
    ] {
        let frame = raw_empty_request(descriptor.as_bytes(), &SOURCE_A, 1, 0);
        assert!(
            matches!(
                decode_request(&frame),
                Err(WalletFactsWireError::InvalidEncoding)
                    | Err(WalletFactsWireError::LimitExceeded)
            ),
            "accepted malformed descriptor bytes: {descriptor:?}"
        );
    }

    let semantic = "elwpkh(x)#u0khc0kg";
    let frame = raw_empty_request(semantic.as_bytes(), &SOURCE_A, 1, 0);
    let parsed = decode_request(&frame).unwrap();
    assert_eq!(parsed.reencode().unwrap().as_bytes(), frame);
    assert!(matches!(
        parsed.prepare(),
        Err(WalletFactsWireError::DescriptorRejected)
    ));

    let mut non_ascii = raw_empty_request(TEST_DESCRIPTOR.as_bytes(), &SOURCE_A, 1, 0);
    non_ascii[76] = 0x80;
    assert!(matches!(
        decode_request(&non_ascii),
        Err(WalletFactsWireError::InvalidEncoding)
    ));

    assert!(matches!(
        decode_request(&raw_empty_request(&[], &SOURCE_A, 1, 0)),
        Err(WalletFactsWireError::InvalidEncoding)
    ));
}

#[test]
fn request_header_reserved_counts_lengths_and_full_consumption_are_frozen() {
    let canonical = raw_empty_request(TEST_DESCRIPTOR.as_bytes(), &SOURCE_A, 1, 0);
    for offset in [16, 17, 18, 19, 21, 22, 23, 72, 73, 74, 75] {
        let mut frame = canonical.clone();
        frame[offset] = 1;
        assert!(decode_request(&frame).is_err());
    }
    for (offset, value) in [(0, b'X'), (4, 2), (6, 75), (20, 2)] {
        let mut frame = canonical.clone();
        frame[offset] = value;
        assert!(decode_request(&frame).is_err());
    }
    let mut zero_source = canonical.clone();
    zero_source[28..60].fill(0);
    assert!(decode_request(&zero_source).is_err());
    let mut wrong_total = canonical.clone();
    wrong_total[8..16].copy_from_slice(&((canonical.len() as u64) + 1).to_le_bytes());
    assert!(decode_request(&wrong_total).is_err());
    let mut trailing = canonical.clone();
    trailing.push(0);
    let trailing_length = trailing.len() as u64;
    trailing[8..16].copy_from_slice(&trailing_length.to_le_bytes());
    assert!(decode_request(&trailing).is_err());
    let mut concatenated = canonical.clone();
    concatenated.extend_from_slice(&canonical);
    let concatenated_length = concatenated.len() as u64;
    concatenated[8..16].copy_from_slice(&concatenated_length.to_le_bytes());
    assert!(decode_request(&concatenated).is_err());
    for length in 0..canonical.len() {
        assert!(decode_request(&canonical[..length]).is_err());
    }
}

#[test]
fn request_candidate_layout_round_trips_before_preparation() {
    let mut frame = raw_request_prefix(TEST_DESCRIPTOR.as_bytes(), &SOURCE_A, 1, 0, 1, 2);
    frame.extend_from_slice(&3_u32.to_le_bytes());
    frame.extend_from_slice(&2_u32.to_le_bytes());
    frame.extend_from_slice(&0_u32.to_le_bytes());
    frame.extend_from_slice(&[1, 2, 3]);
    frame.extend_from_slice(&1_u32.to_le_bytes());
    frame.push(4);
    frame.extend_from_slice(&2_u32.to_le_bytes());
    frame.extend_from_slice(&[5, 6]);
    let length = frame.len() as u64;
    frame[8..16].copy_from_slice(&length.to_le_bytes());
    let parsed = decode_request(&frame).unwrap();
    assert_eq!(parsed.reencode().unwrap().as_bytes(), frame);

    let mut bad_previous_count = frame.clone();
    bad_previous_count[68..72].copy_from_slice(&1_u32.to_le_bytes());
    assert!(decode_request(&bad_previous_count).is_err());
    let mut zero_transaction = frame;
    let transaction_length_offset = 76 + TEST_DESCRIPTOR.len();
    zero_transaction[transaction_length_offset..transaction_length_offset + 4]
        .copy_from_slice(&0_u32.to_le_bytes());
    assert!(decode_request(&zero_transaction).is_err());
}

#[test]
fn request_component_boundaries_and_plus_one_are_enforced() {
    let boundary_descriptor = format!("{}#u0khc0kg", "a".repeat(16_375));
    assert_eq!(boundary_descriptor.len(), 16_384);
    assert!(
        decode_request(&raw_empty_request(
            boundary_descriptor.as_bytes(),
            &SOURCE_A,
            1,
            100_000,
        ))
        .is_ok()
    );
    let over_descriptor = format!("{}#u0khc0kg", "a".repeat(16_376));
    assert!(matches!(
        decode_request(&raw_empty_request(
            over_descriptor.as_bytes(),
            &SOURCE_A,
            1,
            0,
        )),
        Err(WalletFactsWireError::LimitExceeded)
    ));
    assert!(matches!(
        decode_request(&raw_empty_request(
            TEST_DESCRIPTOR.as_bytes(),
            &SOURCE_A,
            1,
            100_001,
        )),
        Err(WalletFactsWireError::LimitExceeded)
    ));

    let mut candidates = raw_request_prefix(TEST_DESCRIPTOR.as_bytes(), &SOURCE_A, 1, 0, 4_096, 0);
    for byte in 1_u32..=4_096 {
        candidates.extend_from_slice(&1_u32.to_le_bytes());
        candidates.extend_from_slice(&0_u32.to_le_bytes());
        candidates.extend_from_slice(&0_u32.to_le_bytes());
        candidates.push((byte & 0xff) as u8);
    }
    let candidates_length = candidates.len() as u64;
    candidates[8..16].copy_from_slice(&candidates_length.to_le_bytes());
    assert!(decode_request(&candidates).is_ok());
    let mut too_many_candidates = candidates;
    too_many_candidates[64..68].copy_from_slice(&4_097_u32.to_le_bytes());
    assert!(matches!(
        decode_request(&too_many_candidates),
        Err(WalletFactsWireError::LimitExceeded)
    ));

    let mut previous = raw_request_prefix(TEST_DESCRIPTOR.as_bytes(), &SOURCE_A, 1, 0, 1, 16_384);
    previous.extend_from_slice(&1_u32.to_le_bytes());
    previous.extend_from_slice(&16_384_u32.to_le_bytes());
    previous.extend_from_slice(&0_u32.to_le_bytes());
    previous.push(1);
    for _ in 0..16_384 {
        previous.extend_from_slice(&1_u32.to_le_bytes());
        previous.push(2);
    }
    let previous_length = previous.len() as u64;
    previous[8..16].copy_from_slice(&previous_length.to_le_bytes());
    assert!(decode_request(&previous).is_ok());
    previous[68..72].copy_from_slice(&16_385_u32.to_le_bytes());
    assert!(matches!(
        decode_request(&previous),
        Err(WalletFactsWireError::LimitExceeded)
    ));

    let max_transaction = vec![1_u8; 4_194_304];
    let mut maximum = raw_request_prefix(TEST_DESCRIPTOR.as_bytes(), &SOURCE_A, 1, 0, 1, 0);
    maximum.extend_from_slice(&(max_transaction.len() as u32).to_le_bytes());
    maximum.extend_from_slice(&0_u32.to_le_bytes());
    maximum.extend_from_slice(&0_u32.to_le_bytes());
    maximum.extend_from_slice(&max_transaction);
    let maximum_length = maximum.len() as u64;
    maximum[8..16].copy_from_slice(&maximum_length.to_le_bytes());
    assert!(decode_request(&maximum).is_ok());
    let transaction_length_offset = 76 + TEST_DESCRIPTOR.len();
    maximum[transaction_length_offset..transaction_length_offset + 4]
        .copy_from_slice(&4_194_305_u32.to_le_bytes());
    assert!(matches!(
        decode_request(&maximum),
        Err(WalletFactsWireError::LimitExceeded)
    ));
    drop(maximum);
    drop(max_transaction);

    let transaction_chunk = vec![3_u8; 4_194_304];
    let mut aggregate = raw_request_prefix(TEST_DESCRIPTOR.as_bytes(), &SOURCE_A, 1, 0, 1, 15);
    aggregate.extend_from_slice(&(transaction_chunk.len() as u32).to_le_bytes());
    aggregate.extend_from_slice(&15_u32.to_le_bytes());
    aggregate.extend_from_slice(&0_u32.to_le_bytes());
    aggregate.extend_from_slice(&transaction_chunk);
    for _ in 0..15 {
        aggregate.extend_from_slice(&(transaction_chunk.len() as u32).to_le_bytes());
        aggregate.extend_from_slice(&transaction_chunk);
    }
    let aggregate_length = aggregate.len() as u64;
    aggregate[8..16].copy_from_slice(&aggregate_length.to_le_bytes());
    assert!(decode_request(&aggregate).is_ok());

    aggregate[68..72].copy_from_slice(&16_u32.to_le_bytes());
    let previous_count_offset = 76 + TEST_DESCRIPTOR.len() + 4;
    aggregate[previous_count_offset..previous_count_offset + 4]
        .copy_from_slice(&16_u32.to_le_bytes());
    aggregate.extend_from_slice(&1_u32.to_le_bytes());
    aggregate.push(4);
    let aggregate_plus_one_length = aggregate.len() as u64;
    aggregate[8..16].copy_from_slice(&aggregate_plus_one_length.to_le_bytes());
    assert!(matches!(
        decode_request(&aggregate),
        Err(WalletFactsWireError::LimitExceeded)
    ));

    let empty_previous = Vec::<Vec<u8>>::new();
    let invalid_candidate = WalletFactsCandidateRef::new(&[], &empty_previous);
    let candidate_refs = [invalid_candidate];
    let request = WalletFactsRequestRef::new(
        &SOURCE_A,
        DescriptorNetwork::Test,
        0,
        TEST_DESCRIPTOR,
        &candidate_refs,
    );
    assert!(matches!(
        encode_request(&request),
        Err(WalletFactsWireError::CandidateRejected)
    ));
}

#[test]
fn request_preparation_maps_each_descriptor_failure_class() {
    let descriptor_body = TEST_DESCRIPTOR
        .strip_suffix("#u0khc0kg")
        .expect("test descriptor checksum suffix");
    let branch_shape = format!("{}#ap60a8j2", descriptor_body.replacen("<0;1>", "0", 1));
    let hardened_wildcard = format!("{}#ht60nhyt", descriptor_body.replacen("/*)", "/*h)", 1));
    let hardened_derivation = format!("{}#dpwdnr23", descriptor_body.replacen("/*)", "/0'/*)", 1));
    let cases = [
        (
            "checksum",
            format!("{descriptor_body}#qqqqqqqq"),
            DescriptorNetwork::Test,
            1,
        ),
        (
            "grammar",
            "elwpkh(x)#h8gzrzdf".to_owned(),
            DescriptorNetwork::Test,
            1,
        ),
        (
            "network",
            TEST_DESCRIPTOR.to_owned(),
            DescriptorNetwork::Mainnet,
            0,
        ),
        ("branch", branch_shape, DescriptorNetwork::Test, 1),
        ("wildcard", hardened_wildcard, DescriptorNetwork::Test, 1),
        (
            "derivation",
            hardened_derivation,
            DescriptorNetwork::Test,
            1,
        ),
    ];

    for (failure_class, descriptor, network, network_byte) in cases {
        let frame = raw_empty_request(descriptor.as_bytes(), &SOURCE_A, network_byte, 0);
        let parsed = decode_request(&frame).unwrap();
        assert_eq!(parsed.descriptor_network(), network);
        assert_eq!(parsed.reencode().unwrap().as_bytes(), frame);
        assert!(
            matches!(
                parsed.prepare(),
                Err(WalletFactsWireError::DescriptorRejected)
            ),
            "descriptor failure class mapped incorrectly: {failure_class}"
        );
    }
}

#[test]
fn response_round_trip_preserves_input_order_and_canonical_output_grouping() {
    let mut batch = one_output_batch();
    batch.transactions[0].inputs = vec![test_input(0x31, 7), test_input(0x30, 5)];
    let encoded = encode_source(&batch, &SOURCE_A).unwrap();
    let decoded = decode_response(encoded.as_bytes(), &SOURCE_A).unwrap();
    let transaction = &decoded.transactions()[0];
    assert_eq!(
        transaction.inputs()[0].previous_transaction_id(),
        &[0x31; 32]
    );
    assert_eq!(transaction.inputs()[0].previous_output_index(), 7);
    assert_eq!(
        transaction.inputs()[1].previous_transaction_id(),
        &[0x30; 32]
    );
    assert_eq!(transaction.outputs().len(), 1);
    let output = &transaction.outputs()[0];
    assert_eq!(output.output_index(), 3);
    assert_eq!(output.script_pubkey(), &GENERATOR_P2WPKH_SCRIPT);
    assert_eq!(output.spend_public_key(), &GENERATOR_PUBLIC_KEY);
    assert_eq!(output.asset_id(), &[0x71; 32]);
    assert_eq!(output.value(), 1);

    let copied = copied_batch(&decoded);
    assert_eq!(
        encode_source(&copied, &SOURCE_A).unwrap().as_bytes(),
        encoded.as_bytes()
    );
}

#[test]
fn unsigned_transaction_order_is_checked_at_every_byte() {
    for position in 0..32 {
        let mut left_id = [0x40; 32];
        let mut right_id = [0x40; 32];
        left_id[position] = 0x7f;
        right_id[position] = 0x80;
        let left = test_transaction(left_id, 0x11);
        let right = test_transaction(right_id, 0x12);
        let batch = TestBatch {
            transactions: vec![left, right],
            outputs: vec![],
        };
        let frame = encode_source(&batch, &SOURCE_A).unwrap();
        assert_eq!(
            decode_response(frame.as_bytes(), &SOURCE_A)
                .unwrap()
                .transactions()
                .len(),
            2
        );

        let reversed = TestBatch {
            transactions: vec![
                test_transaction(right_id, 0x12),
                test_transaction(left_id, 0x11),
            ],
            outputs: vec![],
        };
        assert!(matches!(
            encode_source(&reversed, &SOURCE_A),
            Err(WalletFactsWireError::ObservationRejected)
        ));
    }
}

#[test]
fn input_uniqueness_is_scoped_deterministic_and_cleared() {
    let before = scratch_point_drop_count();
    let duplicate = TestBatch {
        transactions: vec![TestTransaction {
            transaction_id: [0x21; 32],
            binding: [0x51; 32],
            inputs: vec![test_input(0x31, 0), test_input(0x31, 0)],
        }],
        outputs: vec![],
    };
    assert!(matches!(
        encode_source(&duplicate, &SOURCE_A),
        Err(WalletFactsWireError::ObservationRejected)
    ));
    assert_eq!(scratch_point_drop_count() - before, 2);
    assert_eq!(scratch_last_capacity(), 2);

    let shared_outpoint = TestBatch {
        transactions: vec![
            TestTransaction {
                transaction_id: [0x21; 32],
                binding: [0x51; 32],
                inputs: vec![test_input(0x31, 0)],
            },
            TestTransaction {
                transaction_id: [0x22; 32],
                binding: [0x52; 32],
                inputs: vec![test_input(0x31, 0)],
            },
        ],
        outputs: vec![],
    };
    assert!(encode_source(&shared_outpoint, &SOURCE_A).is_ok());

    let before_unwind = scratch_point_drop_count();
    panic_after_scratch_fill();
    assert!(
        catch_unwind(AssertUnwindSafe(|| {
            let _ = encode_source(&shared_outpoint, &SOURCE_A);
        }))
        .is_err()
    );
    assert_eq!(scratch_point_drop_count() - before_unwind, 1);
}

#[test]
fn structural_rejection_precedes_the_uniqueness_pass() {
    let passes_before = scratch_pass_invocation_count();
    let batch = TestBatch {
        transactions: vec![
            test_transaction([0x21; 32], 0x51),
            test_transaction([0; 32], 0x52),
        ],
        outputs: vec![],
    };
    assert!(matches!(
        encode_source(&batch, &SOURCE_A),
        Err(WalletFactsWireError::ObservationRejected)
    ));
    assert_eq!(scratch_pass_invocation_count(), passes_before);
}

#[test]
fn maximum_per_transaction_input_uniqueness_uses_exact_capacity() {
    let mut inputs = Vec::with_capacity(MAX_INPUTS_PER_TRANSACTION);
    for index in 0..MAX_INPUTS_PER_TRANSACTION {
        let mut transaction_id = [0x33; 32];
        transaction_id[..8].copy_from_slice(&(index as u64).to_le_bytes());
        if index == 0 {
            transaction_id[8] = 1;
        }
        inputs.push(TestInput {
            previous_transaction_id: transaction_id,
            previous_output_index: (index as u32) & MAX_SPENDABLE_OUTPUT_INDEX,
        });
    }
    let batch = TestBatch {
        transactions: vec![TestTransaction {
            transaction_id: [0x21; 32],
            binding: [0x51; 32],
            inputs,
        }],
        outputs: vec![],
    };
    let encoded = encode_source(&batch, &SOURCE_A).unwrap();
    assert_eq!(scratch_last_capacity(), MAX_INPUTS_PER_TRANSACTION);
    assert_eq!(
        encoded.as_bytes().len(),
        64 + 72 + MAX_INPUTS_PER_TRANSACTION * 36
    );

    let mut too_many = batch;
    too_many.transactions[0]
        .inputs
        .push(test_input(0x7f, MAX_SPENDABLE_OUTPUT_INDEX));
    assert!(matches!(
        encode_source(&too_many, &SOURCE_A),
        Err(WalletFactsWireError::ObservationRejected)
    ));
}

#[test]
fn response_rejects_identifier_index_value_key_script_and_binding_violations() {
    let mut cases = Vec::new();

    let mut zero_txid = one_output_batch();
    zero_txid.transactions[0].transaction_id.fill(0);
    cases.push(zero_txid);
    let mut zero_previous = one_output_batch();
    zero_previous.transactions[0].inputs[0]
        .previous_transaction_id
        .fill(0);
    cases.push(zero_previous);
    let mut large_input_index = one_output_batch();
    large_input_index.transactions[0].inputs[0].previous_output_index = 0x4000_0000;
    cases.push(large_input_index);
    let mut orphan = one_output_batch();
    orphan.outputs[0].transaction_id = [0x20; 32];
    cases.push(orphan);
    let mut wrong_binding = one_output_batch();
    wrong_binding.outputs[0].binding[0] ^= 1;
    cases.push(wrong_binding);
    let mut zero_asset = one_output_batch();
    zero_asset.outputs[0].asset_id.fill(0);
    cases.push(zero_asset);
    let mut zero_value = one_output_batch();
    zero_value.outputs[0].value = 0;
    cases.push(zero_value);
    let mut large_value = one_output_batch();
    large_value.outputs[0].value = MAX_OWNED_OUTPUT_VALUE + 1;
    cases.push(large_value);
    let mut large_vout = one_output_batch();
    large_vout.outputs[0].output_index = 0x4000_0000;
    cases.push(large_vout);
    let mut high_bit_vout = one_output_batch();
    high_bit_vout.outputs[0].output_index = 0x8000_0000;
    cases.push(high_bit_vout);
    let mut maximum_vout = one_output_batch();
    maximum_vout.outputs[0].output_index = 0xffff_ffff;
    cases.push(maximum_vout);
    let mut large_derivation = one_output_batch();
    large_derivation.outputs[0].derivation_index = 100_001;
    cases.push(large_derivation);
    let mut wrong_script_length = one_output_batch();
    wrong_script_length.outputs[0].script_pubkey.pop();
    cases.push(wrong_script_length);
    let mut wrong_script = one_output_batch();
    wrong_script.outputs[0].script_pubkey[2] ^= 1;
    cases.push(wrong_script);
    let mut wrong_spend_key = one_output_batch();
    wrong_spend_key.outputs[0].spend_public_key.fill(0);
    cases.push(wrong_spend_key);
    let mut wrong_blinding_key = one_output_batch();
    wrong_blinding_key.outputs[0].blinding_public_key.fill(0);
    cases.push(wrong_blinding_key);

    for batch in cases {
        assert!(matches!(
            encode_source(&batch, &SOURCE_A),
            Err(WalletFactsWireError::ObservationRejected)
        ));
    }

    for (index, accepted) in [0x3fff_ffff, 0].iter().enumerate() {
        let mut batch = one_output_batch();
        batch.outputs[0].output_index = *accepted;
        batch.transactions[0].inputs[0].previous_output_index = *accepted;
        batch.outputs[0].value = if index == 0 {
            MAX_OWNED_OUTPUT_VALUE
        } else {
            1
        };
        assert!(encode_source(&batch, &SOURCE_A).is_ok());
    }
}

#[test]
fn maximum_per_transaction_output_count_and_plus_one_are_enforced() {
    let mut batch = one_output_batch();
    batch.outputs.clear();
    batch.outputs.reserve(MAX_OWNED_OUTPUTS_PER_TRANSACTION);
    for output_index in 0..MAX_OWNED_OUTPUTS_PER_TRANSACTION {
        let mut output = test_output([0x21; 32], [0x51; 32]);
        output.output_index = output_index as u32;
        batch.outputs.push(output);
    }
    let encoded = encode_source(&batch, &SOURCE_A).unwrap();
    assert_eq!(
        encoded.as_bytes().len(),
        64 + 72 + 36 + MAX_OWNED_OUTPUTS_PER_TRANSACTION * 144
    );
    let mut extra = test_output([0x21; 32], [0x51; 32]);
    extra.output_index = MAX_OWNED_OUTPUTS_PER_TRANSACTION as u32;
    batch.outputs.push(extra);
    assert!(matches!(
        encode_source(&batch, &SOURCE_A),
        Err(WalletFactsWireError::ObservationRejected)
    ));
}

#[test]
fn aggregate_input_and_output_boundaries_and_plus_one_are_enforced() {
    let mut input_transactions = Vec::new();
    let mut remaining_inputs = MAX_AGGREGATE_INPUTS;
    let mut transaction_number = 1_u8;
    while remaining_inputs != 0 {
        let count = remaining_inputs.min(MAX_INPUTS_PER_TRANSACTION);
        input_transactions.push(CompactTransaction {
            transaction_id: [transaction_number; 32],
            binding: [transaction_number.wrapping_add(0x40); 32],
            inputs: (0..count).map(|index| CompactInput(index as u32)).collect(),
        });
        remaining_inputs -= count;
        transaction_number += 1;
    }
    let mut input_batch = CompactBatch {
        transactions: input_transactions,
        outputs: vec![],
    };
    let encoded_inputs = encode_source(&input_batch, &SOURCE_A).unwrap();
    assert_eq!(
        encoded_inputs.as_bytes().len(),
        64 + input_batch.transactions.len() * 72 + MAX_AGGREGATE_INPUTS * 36
    );
    assert_eq!(
        decode_response(encoded_inputs.as_bytes(), &SOURCE_A)
            .unwrap()
            .transactions()
            .len(),
        input_batch.transactions.len()
    );
    input_batch
        .transactions
        .last_mut()
        .unwrap()
        .inputs
        .push(CompactInput(1_000_000));
    assert!(matches!(
        encode_source(&input_batch, &SOURCE_A),
        Err(WalletFactsWireError::ObservationRejected)
    ));

    let mut output_transactions = Vec::new();
    let mut outputs = Vec::with_capacity(MAX_AGGREGATE_OWNED_OUTPUTS);
    let mut remaining_outputs = MAX_AGGREGATE_OWNED_OUTPUTS;
    let mut transaction_number = 1_u8;
    while remaining_outputs != 0 {
        let count = remaining_outputs.min(MAX_OWNED_OUTPUTS_PER_TRANSACTION);
        let transaction_id = [transaction_number; 32];
        let binding = [transaction_number.wrapping_add(0x40); 32];
        output_transactions.push(CompactTransaction {
            transaction_id,
            binding,
            inputs: vec![CompactInput(0)],
        });
        outputs.extend((0..count).map(|index| CompactOutput {
            transaction_id,
            binding,
            output_index: index as u32,
        }));
        remaining_outputs -= count;
        transaction_number += 1;
    }
    let mut output_batch = CompactBatch {
        transactions: output_transactions,
        outputs,
    };
    let encoded_outputs = encode_source(&output_batch, &SOURCE_A).unwrap();
    assert_eq!(
        encoded_outputs.as_bytes().len(),
        64 + output_batch.transactions.len() * (72 + 36) + MAX_AGGREGATE_OWNED_OUTPUTS * 144
    );
    assert_eq!(
        decode_response(encoded_outputs.as_bytes(), &SOURCE_A)
            .unwrap()
            .transactions()
            .iter()
            .map(|transaction| transaction.outputs().len())
            .sum::<usize>(),
        MAX_AGGREGATE_OWNED_OUTPUTS
    );
    let last_transaction = output_batch.transactions.last().unwrap();
    let last_output_index = output_batch
        .outputs
        .last()
        .unwrap()
        .output_index
        .checked_add(1)
        .unwrap();
    output_batch.outputs.push(CompactOutput {
        transaction_id: last_transaction.transaction_id,
        binding: last_transaction.binding,
        output_index: last_output_index,
    });
    assert!(matches!(
        encode_source(&output_batch, &SOURCE_A),
        Err(WalletFactsWireError::ObservationRejected)
    ));
}

#[test]
fn response_transaction_count_boundary_and_plus_one_are_enforced() {
    let mut transactions = Vec::with_capacity(4_097);
    for index in 1_u32..=4_096 {
        let mut transaction_id = [0x20; 32];
        transaction_id[28..].copy_from_slice(&index.to_be_bytes());
        transactions.push(CompactTransaction {
            transaction_id,
            binding: [0x51; 32],
            inputs: vec![CompactInput(0)],
        });
    }
    let mut batch = CompactBatch {
        transactions,
        outputs: vec![],
    };
    let encoded = encode_source(&batch, &SOURCE_A).unwrap();
    assert_eq!(
        decode_response(encoded.as_bytes(), &SOURCE_A)
            .unwrap()
            .transactions()
            .len(),
        4_096
    );
    let mut transaction_id = [0x20; 32];
    transaction_id[28..].copy_from_slice(&4_097_u32.to_be_bytes());
    batch.transactions.push(CompactTransaction {
        transaction_id,
        binding: [0x51; 32],
        inputs: vec![CompactInput(0)],
    });
    assert!(matches!(
        encode_source(&batch, &SOURCE_A),
        Err(WalletFactsWireError::ObservationRejected)
    ));
}

#[test]
fn zeroizing_owners_are_audited_on_success_error_and_unwind() {
    reset_drop_audit();
    let previous_transactions = vec![vec![4_u8]];
    let candidate = WalletFactsCandidateRef::new(&[1, 2, 3], &previous_transactions);
    let candidates = [candidate];
    let request = WalletFactsRequestRef::new(
        &SOURCE_A,
        DescriptorNetwork::Test,
        0,
        TEST_DESCRIPTOR,
        &candidates,
    );
    let encoded_request = encode_request(&request).unwrap();
    let parsed = decode_request(encoded_request.as_bytes()).unwrap();
    let prepared = parsed.prepare().unwrap();
    let encoded_response = encode_source(&one_output_batch(), &SOURCE_A).unwrap();
    let decoded = decode_response(encoded_response.as_bytes(), &SOURCE_A).unwrap();
    drop(decoded);
    drop(encoded_response);
    drop(prepared);
    drop(encoded_request);
    let success = drop_audit();
    assert!(success.all_zeroized);
    assert_eq!(success.encoded_request, 1);
    assert_eq!(success.encoded_response, 1);
    assert_eq!(success.parsed_candidate, 1);
    assert_eq!(success.parsed_request, 1);
    assert_eq!(success.prepared_request, 1);
    assert_eq!(success.decoded_input, 1);
    assert_eq!(success.decoded_output, 1);
    assert_eq!(success.decoded_transaction, 1);
    assert_eq!(success.decoded_response, 1);
    assert!(success.writer >= 2);
    assert!(success.temporary > 0);

    reset_drop_audit();
    let invalid = raw_empty_request(b"elwpkh(x)#u0khc0kg", &SOURCE_A, 1, 0);
    let parsed = decode_request(&invalid).unwrap();
    assert!(matches!(
        parsed.prepare(),
        Err(WalletFactsWireError::DescriptorRejected)
    ));
    let mut overflowing_writer = Writer::new(1);
    overflowing_writer.write(&[1, 2]);
    assert!(overflowing_writer.finish().is_err());
    let mut invalid_response = encode_source(&one_output_batch(), &SOURCE_A)
        .unwrap()
        .as_bytes()
        .to_vec();
    invalid_response[254..286].fill(0);
    assert!(decode_response(&invalid_response, &SOURCE_A).is_err());
    let ordinary_error = drop_audit();
    assert!(ordinary_error.all_zeroized);
    assert_eq!(ordinary_error.parsed_request, 1);
    assert!(ordinary_error.writer >= 2);
    assert!(ordinary_error.temporary > 0);

    reset_drop_audit();
    assert!(
        catch_unwind(AssertUnwindSafe(|| {
            let encoded_request = encode_request(&request).unwrap();
            let parsed = decode_request(encoded_request.as_bytes()).unwrap();
            let prepared = parsed.prepare().unwrap();
            let encoded_response = encode_source(&one_output_batch(), &SOURCE_A).unwrap();
            let decoded = decode_response(encoded_response.as_bytes(), &SOURCE_A).unwrap();
            let _owners = (encoded_request, prepared, encoded_response, decoded);
            panic!("test-only owner unwind");
        }))
        .is_err()
    );
    let unwind = drop_audit();
    assert!(unwind.all_zeroized);
    assert_eq!(unwind.encoded_request, 1);
    assert_eq!(unwind.encoded_response, 1);
    assert_eq!(unwind.parsed_candidate, 1);
    assert_eq!(unwind.parsed_request, 1);
    assert_eq!(unwind.prepared_request, 1);
    assert_eq!(unwind.decoded_input, 1);
    assert_eq!(unwind.decoded_output, 1);
    assert_eq!(unwind.decoded_transaction, 1);
    assert_eq!(unwind.decoded_response, 1);
}

#[test]
fn parse_and_construct_staging_are_zeroized_on_controlled_unwind() {
    let previous_transactions = vec![vec![4_u8]];
    let candidate = WalletFactsCandidateRef::new(&[1, 2, 3], &previous_transactions);
    let candidates = [candidate];
    let request = WalletFactsRequestRef::new(
        &SOURCE_A,
        DescriptorNetwork::Test,
        0,
        TEST_DESCRIPTOR,
        &candidates,
    );
    let request_frame = encode_request(&request).unwrap().as_bytes().to_vec();
    for point in 1..=3 {
        reset_drop_audit();
        panic_during_request_staging(point);
        assert!(
            catch_unwind(AssertUnwindSafe(|| decode_request(&request_frame))).is_err(),
            "request staging point {point} did not unwind"
        );
        let audit = drop_audit();
        assert!(audit.all_zeroized);
        assert_eq!(audit.parsed_request, 1);
        assert_eq!(audit.parsed_candidate, usize::from(point >= 2));
        assert!(audit.temporary > 0);
    }

    let response_frame = encode_source(&one_output_batch(), &SOURCE_A)
        .unwrap()
        .as_bytes()
        .to_vec();
    for point in 1..=3 {
        reset_drop_audit();
        panic_during_response_staging(point);
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                decode_response(&response_frame, &SOURCE_A)
            }))
            .is_err(),
            "response staging point {point} did not unwind"
        );
        let audit = drop_audit();
        assert!(audit.all_zeroized);
        assert_eq!(audit.decoded_response, 1);
        assert_eq!(audit.decoded_transaction, 1);
        assert_eq!(audit.decoded_input, usize::from(point >= 2));
        assert_eq!(audit.decoded_output, usize::from(point >= 3));
        assert!(audit.temporary > 0);
    }
}

#[test]
fn response_decoder_rejects_every_record_mutation_and_truncation() {
    let canonical = encode_source(&one_output_batch(), &SOURCE_A)
        .unwrap()
        .as_bytes()
        .to_vec();
    for length in 0..canonical.len() {
        assert!(decode_response(&canonical[..length], &SOURCE_A).is_err());
    }
    for (offset, value) in [(0, b'X'), (4, 2), (6, 63), (246, 2)] {
        let mut frame = canonical.clone();
        frame[offset] = value;
        assert!(decode_response(&frame, &SOURCE_A).is_err());
    }
    let mut zero_source = canonical.clone();
    zero_source[32..64].fill(0);
    assert!(decode_response(&zero_source, &SOURCE_A).is_err());
    let mut trailing = canonical.clone();
    trailing.push(0);
    let trailing_length = trailing.len() as u64;
    trailing[8..16].copy_from_slice(&trailing_length.to_le_bytes());
    assert!(decode_response(&trailing, &SOURCE_A).is_err());

    for offset in [16, 17, 18, 19, 28, 29, 30, 31, 247, 248, 249] {
        let mut frame = canonical.clone();
        frame[offset] = 1;
        assert!(decode_response(&frame, &SOURCE_A).is_err());
    }
    for (offset, bytes) in [
        (128, 0_u32.to_le_bytes()),
        (168, 0x4000_0000_u32.to_le_bytes()),
        (172, 0x4000_0000_u32.to_le_bytes()),
        (176, 21_u32.to_le_bytes()),
        (250, 100_001_u32.to_le_bytes()),
    ] {
        let mut frame = canonical.clone();
        frame[offset..offset + 4].copy_from_slice(&bytes);
        assert!(decode_response(&frame, &SOURCE_A).is_err());
    }
    for range in [64..96, 136..168, 180..213, 213..246, 254..286] {
        let mut frame = canonical.clone();
        frame[range].fill(0);
        assert!(decode_response(&frame, &SOURCE_A).is_err());
    }
    for value in [0, MAX_OWNED_OUTPUT_VALUE + 1] {
        let mut frame = canonical.clone();
        frame[286..294].copy_from_slice(&value.to_le_bytes());
        assert!(decode_response(&frame, &SOURCE_A).is_err());
    }
    let mut script_mismatch = canonical;
    script_mismatch[294] ^= 1;
    assert!(decode_response(&script_mismatch, &SOURCE_A).is_err());
}

#[test]
fn response_decoder_rejects_duplicate_input_first_and_last() {
    let mut batch = one_output_batch();
    batch.transactions[0].inputs = vec![
        test_input(0x31, 0),
        test_input(0x32, 1),
        test_input(0x33, 2),
    ];
    let canonical = encode_source(&batch, &SOURCE_A)
        .unwrap()
        .as_bytes()
        .to_vec();
    let first_input = 136;
    let second_input = first_input + 36;
    let third_input = second_input + 36;

    let mut duplicate_first = canonical.clone();
    let first_key = duplicate_first[first_input..first_input + 36].to_vec();
    duplicate_first[second_input..second_input + 36].copy_from_slice(&first_key);
    reset_drop_audit();
    assert!(matches!(
        decode_response(&duplicate_first, &SOURCE_A),
        Err(WalletFactsWireError::InvalidEncoding)
    ));
    let duplicate_audit = drop_audit();
    assert_eq!(duplicate_audit.decoded_input, 0);
    assert_eq!(duplicate_audit.decoded_output, 0);
    assert_eq!(duplicate_audit.decoded_transaction, 0);
    assert_eq!(duplicate_audit.decoded_response, 0);
    assert!(duplicate_audit.temporary > 0);
    assert!(duplicate_audit.all_zeroized);

    let mut duplicate_last = canonical;
    let last_key = duplicate_last[third_input..third_input + 36].to_vec();
    duplicate_last[second_input..second_input + 36].copy_from_slice(&last_key);
    assert!(matches!(
        decode_response(&duplicate_last, &SOURCE_A),
        Err(WalletFactsWireError::InvalidEncoding)
    ));
}

#[test]
fn response_output_order_duplicate_and_count_underflow_reject_atomically() {
    let mut batch = one_output_batch();
    let mut second = test_output([0x21; 32], [0x51; 32]);
    second.output_index = 4;
    batch.outputs.push(second);
    let canonical = encode_source(&batch, &SOURCE_A).unwrap();

    batch.outputs.swap(0, 1);
    assert!(encode_source(&batch, &SOURCE_A).is_err());
    batch.outputs[0].output_index = 3;
    batch.outputs[1].output_index = 3;
    assert!(encode_source(&batch, &SOURCE_A).is_err());

    let mut underflow = canonical.as_bytes().to_vec();
    underflow[132..136].copy_from_slice(&1_u32.to_le_bytes());
    assert!(decode_response(&underflow, &SOURCE_A).is_err());
    let mut header_mismatch = canonical.as_bytes().to_vec();
    header_mismatch[24..28].copy_from_slice(&1_u32.to_le_bytes());
    assert!(decode_response(&header_mismatch, &SOURCE_A).is_err());
}

#[test]
fn source_binding_prevents_cross_request_response_swaps() {
    let batch = one_output_batch();
    let first = encode_source(&batch, &SOURCE_A).unwrap();
    let second = encode_source(&batch, &SOURCE_B).unwrap();
    assert!(decode_response(first.as_bytes(), &SOURCE_A).is_ok());
    assert!(decode_response(second.as_bytes(), &SOURCE_B).is_ok());
    assert!(matches!(
        decode_response(first.as_bytes(), &SOURCE_B),
        Err(WalletFactsWireError::SourceBindingMismatch)
    ));
    assert!(matches!(
        decode_response(second.as_bytes(), &SOURCE_A),
        Err(WalletFactsWireError::SourceBindingMismatch)
    ));
}

#[test]
fn limits_and_layout_maxima_are_derived_without_giant_frames() {
    assert_eq!(
        76 + 16_384 + 4_096 * 12 + 16_384 * 4 + 67_108_864,
        MAX_REACHABLE_REQUEST_BYTES
    );
    assert_eq!(
        64 + 4_096 * 72 + 1_636_801 * 36 + 148_470 * 144,
        MAX_REACHABLE_RESPONSE_BYTES
    );
    assert!(validate_outer_length(MAX_REQUEST_FRAME_BYTES, MAX_REQUEST_FRAME_BYTES).is_ok());
    assert!(matches!(
        validate_outer_length(MAX_REQUEST_FRAME_BYTES + 1, MAX_REQUEST_FRAME_BYTES),
        Err(WalletFactsWireError::LimitExceeded)
    ));
    assert!(matches!(
        validate_outer_length(MAX_RESPONSE_FRAME_BYTES + 1, MAX_RESPONSE_FRAME_BYTES),
        Err(WalletFactsWireError::LimitExceeded)
    ));
    assert!(matches!(
        checked_add(usize::MAX, 1),
        Err(WalletFactsWireError::LimitExceeded)
    ));
    assert!(matches!(
        checked_multiply(usize::MAX, 2),
        Err(WalletFactsWireError::LimitExceeded)
    ));
    let mut synthetic = Reader::at_position(&[], usize::MAX);
    assert!(matches!(
        synthetic.take(1),
        Err(WalletFactsWireError::LimitExceeded)
    ));
    let mut overflowing_writer = Writer::new(1);
    overflowing_writer.write(&[1, 2]);
    assert!(matches!(
        overflowing_writer.finish(),
        Err(WalletFactsWireError::InvalidEncoding)
    ));
}

#[test]
fn source_and_call_surfaces_remain_narrow_and_export_free() {
    let library = include_str!("lib.rs");
    let request = include_str!("request.rs");
    let response = include_str!("response.rs");
    let manifest = include_str!("../Cargo.toml");
    let wallet_facts = include_str!("../../wallet-facts/src/lib.rs");
    let wire_sources = [library, request, response].join("\n");
    for forbidden in [
        "use elements::",
        "use secp256k1",
        "use sha2",
        "use bitcoin_hashes",
        "SecretKey",
        "Pset",
        "HashMap",
        "HashSet",
        ".sort(",
        ".sort_by(",
        "rand::",
        "getrandom",
        "no_mangle",
        "export_name",
        "extern \"C\"",
    ] {
        assert!(
            !wire_sources.contains(forbidden),
            "forbidden surface: {forbidden}"
        );
    }
    assert!(response.contains(".sort_unstable_by(|left, right| left.bytes.cmp(&right.bytes))"));
    assert_eq!(
        response
            .matches("validates_observed_public_output(")
            .count(),
        2
    );
    assert!(manifest.contains("crate-type = [\"rlib\"]"));
    assert!(!manifest.contains("cdylib"));

    let helper = wallet_facts
        .split("pub fn validates_observed_public_output")
        .nth(1)
        .unwrap()
        .split("/// The public derivation branch")
        .next()
        .unwrap();
    for forbidden in [
        "Vec",
        "Box",
        "format!",
        "SecretKey",
        "Transaction",
        "Pset",
        "rand",
        "std::",
    ] {
        assert!(!helper.contains(forbidden), "helper surface: {forbidden}");
    }
    assert!(helper.contains("PublicKey::from_slice(spend_public_key)"));
    assert!(helper.contains("PublicKey::from_slice(blinding_public_key)"));
    assert!(helper.contains("hash160::Hash::hash(spend_public_key)"));
}

fn raw_empty_request(
    descriptor: &[u8],
    source: &[u8; 32],
    network: u8,
    last_index: u32,
) -> Vec<u8> {
    let mut frame = raw_request_prefix(descriptor, source, network, last_index, 0, 0);
    let length = frame.len() as u64;
    frame[8..16].copy_from_slice(&length.to_le_bytes());
    frame
}

fn raw_request_prefix(
    descriptor: &[u8],
    source: &[u8; 32],
    network: u8,
    last_index: u32,
    candidates: u32,
    previous: u32,
) -> Vec<u8> {
    let mut frame = Vec::new();
    frame.extend_from_slice(b"WLFQ");
    frame.extend_from_slice(&1_u16.to_le_bytes());
    frame.extend_from_slice(&76_u16.to_le_bytes());
    frame.extend_from_slice(&0_u64.to_le_bytes());
    frame.extend_from_slice(&0_u32.to_le_bytes());
    frame.push(network);
    frame.extend_from_slice(&[0; 3]);
    frame.extend_from_slice(&last_index.to_le_bytes());
    frame.extend_from_slice(source);
    frame.extend_from_slice(&(descriptor.len() as u32).to_le_bytes());
    frame.extend_from_slice(&candidates.to_le_bytes());
    frame.extend_from_slice(&previous.to_le_bytes());
    frame.extend_from_slice(&0_u32.to_le_bytes());
    frame.extend_from_slice(descriptor);
    frame
}

fn test_input(id: u8, index: u32) -> TestInput {
    TestInput {
        previous_transaction_id: [id; 32],
        previous_output_index: index,
    }
}

fn test_transaction(transaction_id: [u8; 32], input_id: u8) -> TestTransaction {
    TestTransaction {
        transaction_id,
        binding: [transaction_id[0].wrapping_add(0x30); 32],
        inputs: vec![test_input(input_id, 0)],
    }
}

fn test_output(transaction_id: [u8; 32], binding: [u8; 32]) -> TestOutput {
    TestOutput {
        transaction_id,
        output_index: 3,
        binding,
        script_pubkey: GENERATOR_P2WPKH_SCRIPT.to_vec(),
        spend_public_key: GENERATOR_PUBLIC_KEY,
        blinding_public_key: GENERATOR_PUBLIC_KEY,
        branch: DescriptorBranch::External,
        derivation_index: 0,
        asset_id: [0x71; 32],
        value: 1,
    }
}

fn one_output_batch() -> TestBatch {
    let transaction = TestTransaction {
        transaction_id: [0x21; 32],
        binding: [0x51; 32],
        inputs: vec![test_input(0x31, 0)],
    };
    let output = test_output(transaction.transaction_id, transaction.binding);
    TestBatch {
        transactions: vec![transaction],
        outputs: vec![output],
    }
}

fn copied_batch(decoded: &DecodedWalletFactsResponse) -> TestBatch {
    let mut transactions = Vec::new();
    let mut outputs = Vec::new();
    for transaction in decoded.transactions() {
        transactions.push(TestTransaction {
            transaction_id: *transaction.transaction_id(),
            binding: *transaction.transaction_witness_binding(),
            inputs: transaction
                .inputs()
                .iter()
                .map(|input| TestInput {
                    previous_transaction_id: *input.previous_transaction_id(),
                    previous_output_index: input.previous_output_index(),
                })
                .collect(),
        });
        outputs.extend(transaction.outputs().iter().map(|output| TestOutput {
            transaction_id: *transaction.transaction_id(),
            output_index: output.output_index(),
            binding: *transaction.transaction_witness_binding(),
            script_pubkey: output.script_pubkey().to_vec(),
            spend_public_key: *output.spend_public_key(),
            blinding_public_key: *output.blinding_public_key(),
            branch: output.branch(),
            derivation_index: output.derivation_index(),
            asset_id: *output.asset_id(),
            value: output.value(),
        }));
    }
    TestBatch {
        transactions,
        outputs,
    }
}
