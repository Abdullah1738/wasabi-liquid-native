use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use wasabi_liquid_native_wallet_facts::{
    MAX_BATCH_BYTES, MAX_CANDIDATE_TRANSACTIONS, MAX_DERIVATION_INDEX,
    MAX_PREVIOUS_TRANSACTIONS_PER_BATCH, MAX_PUBLIC_DESCRIPTOR_BYTES, MAX_TRANSACTION_BYTES,
};

use super::*;
use crate::request::validate_outer_length;
use crate::response::{
    InputSource, OutputSource, ResponseSource, TransactionSource, encode_source,
};
use crate::writer::{checked_add, checked_multiply};

const CORPUS_ID: &str = "wallet-facts-wire-v1-conformance-1";
const TEST_DESCRIPTOR: &str = "elwpkh([28b3f14e/84'/1'/0']tpubDC2Q4xK4XH72GM7MowNuajyWVbigRLBWKswyP5T88hpPwu5nGqJWnda8zhJEFt71av73Hm8mUMMFSz9acNVzz8b1UbdSHCDXKTbSv5eEytu/<0;1>/*)#u0khc0kg";
const SEMANTIC_REJECT_DESCRIPTOR: &str = "elwpkh(x)#u0khc0kg";
const SOURCE_A: [u8; 32] = [0x41; 32];
const SOURCE_B: [u8; 32] = [0x42; 32];
const CANONICAL_LENGTH_CASES: [(&str, &str); 6] = [
    (
        "request-25-trailing-byte-decode",
        "request-25a-trailing-byte-canonical-length",
    ),
    (
        "request-26-concatenated-decode",
        "request-26a-concatenated-canonical-length",
    ),
    (
        "request-body-truncated-decode",
        "request-09a-body-truncated-canonical-length",
    ),
    (
        "response-21-trailing-byte-decode",
        "response-21a-trailing-byte-canonical-length",
    ),
    (
        "response-22-concatenated-decode",
        "response-22a-concatenated-canonical-length",
    ),
    (
        "response-body-truncated-decode",
        "response-10b-body-truncated-canonical-length",
    ),
];
const GENERATOR_PUBLIC_KEY: [u8; 33] = [
    0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b,
    0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17,
    0x98,
];
const GENERATOR_P2WPKH_SCRIPT: [u8; 22] = [
    0x00, 0x14, 0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54, 0x94, 0x1c, 0x45, 0xd1, 0xb3,
    0xa3, 0x23, 0xf1, 0x43, 0x3b, 0xd6,
];

#[derive(Clone)]
struct FrameRow {
    id: String,
    kind: String,
    relative_path: String,
    decoded_length: usize,
    decoded_sha256: String,
    parent: String,
    mutation: String,
    offset: String,
    old_hex: String,
    new_hex: String,
}

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
    branch: DescriptorBranch,
    derivation_index: u32,
    asset_id: [u8; 32],
    value: u64,
    spend_public_key: [u8; 33],
    blinding_public_key: [u8; 33],
    script_pubkey: Vec<u8>,
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

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf()
}

fn vector_root() -> PathBuf {
    root().join("contracts/wallet-facts/v1/nonlinkable-reference/vectors")
}

fn canonical_text(path: &Path) -> String {
    let bytes = fs::read(path).expect("read corpus text");
    assert!(
        !bytes.starts_with(&[0xef, 0xbb, 0xbf]),
        "BOM: {}",
        path.display()
    );
    assert!(!bytes.contains(&b'\r'), "CR: {}", path.display());
    assert_eq!(
        bytes.last(),
        Some(&b'\n'),
        "terminal LF: {}",
        path.display()
    );
    String::from_utf8(bytes).expect("UTF-8 corpus text")
}

fn rows(path: &Path, header: &[&str]) -> Vec<Vec<String>> {
    let text = canonical_text(path);
    let mut lines = text.trim_end_matches('\n').split('\n');
    assert_eq!(
        lines
            .next()
            .expect("TSV header")
            .split('\t')
            .collect::<Vec<_>>(),
        header
    );
    let mut result = Vec::new();
    let mut previous: Option<Vec<u8>> = None;
    for line in lines {
        assert!(!line.is_empty());
        let fields = line.split('\t').map(str::to_owned).collect::<Vec<_>>();
        assert_eq!(fields.len(), header.len());
        if header[0] != "code" {
            assert_identifier(&fields[0]);
        } else {
            assert!(fields[0].parse::<u32>().is_ok());
        }
        let id = fields[0].as_bytes().to_vec();
        assert!(previous.as_ref().is_none_or(|item| item < &id));
        previous = Some(id);
        result.push(fields);
    }
    assert!(!result.is_empty());
    result
}

fn assert_identifier(value: &str) {
    let mut bytes = value.bytes();
    assert!(bytes.next().is_some_and(|byte| byte.is_ascii_lowercase()));
    assert!(bytes.all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'));
}

fn decode_hex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0);
    assert!(
        value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    );
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let digit = |byte: u8| match byte {
                b'0'..=b'9' => byte - b'0',
                b'a'..=b'f' => byte - b'a' + 10,
                _ => unreachable!(),
            };
            digit(pair[0]) * 16 + digit(pair[1])
        })
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    output
}

fn sha256(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

fn load_frames() -> (Vec<FrameRow>, BTreeMap<String, Vec<u8>>) {
    let vectors = vector_root();
    let fields = rows(
        &vectors.join("FRAMES_V1.tsv"),
        &[
            "frame_id",
            "frame_kind",
            "relative_path",
            "decoded_length",
            "decoded_sha256",
            "parent_frame_id",
            "mutation_kind",
            "mutation_offset",
            "old_hex",
            "new_hex",
        ],
    );
    let mut frame_rows = Vec::new();
    let mut decoded: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut paths = BTreeSet::new();
    let mut digests = BTreeSet::new();
    for item in fields {
        let row = FrameRow {
            id: item[0].clone(),
            kind: item[1].clone(),
            relative_path: item[2].clone(),
            decoded_length: item[3].parse().expect("frame length"),
            decoded_sha256: item[4].clone(),
            parent: item[5].clone(),
            mutation: item[6].clone(),
            offset: item[7].clone(),
            old_hex: item[8].clone(),
            new_hex: item[9].clone(),
        };
        assert!(matches!(row.kind.as_str(), "request" | "response"));
        assert!(!row.relative_path.contains('\\'));
        assert!(row.relative_path.starts_with("frames/") && row.relative_path.ends_with(".hex"));
        assert_eq!(Path::new(&row.relative_path).components().count(), 2);
        assert!(
            !row.relative_path
                .split('/')
                .any(|part| part.is_empty() || matches!(part, "." | ".."))
        );
        assert!(paths.insert(row.relative_path.clone()));
        let text = canonical_text(&vectors.join(&row.relative_path));
        assert_eq!(text.matches('\n').count(), 1);
        let frame = decode_hex(text.strip_suffix('\n').expect("frame LF"));
        assert_eq!(frame.len(), row.decoded_length);
        assert_eq!(sha256(&frame), row.decoded_sha256);
        assert!(digests.insert(row.decoded_sha256.clone()));
        match row.mutation.as_str() {
            "base" => assert_eq!(
                (&*row.parent, &*row.offset, &*row.old_hex, &*row.new_hex),
                ("-", "-", "-", "-")
            ),
            "replace" => {
                let parent = decoded.get(&row.parent).expect("earlier mutation parent");
                let offset: usize = row.offset.parse().expect("replacement offset");
                let old = decode_hex(&row.old_hex);
                let new = decode_hex(&row.new_hex);
                assert!(!old.is_empty() && old.len() == new.len());
                assert_eq!(&parent[offset..offset + old.len()], old);
                let mut rebuilt = parent.clone();
                rebuilt[offset..offset + new.len()].copy_from_slice(&new);
                assert_eq!(rebuilt, frame);
            }
            "append" => {
                let parent = decoded.get(&row.parent).expect("earlier mutation parent");
                let offset: usize = row.offset.parse().expect("append offset");
                let new = decode_hex(&row.new_hex);
                assert_eq!(offset, parent.len());
                assert_eq!(row.old_hex, "-");
                assert!(!new.is_empty());
                assert_eq!([parent.as_slice(), new.as_slice()].concat(), frame);
            }
            "truncate" => {
                let parent = decoded.get(&row.parent).expect("earlier mutation parent");
                let offset: usize = row.offset.parse().expect("truncate offset");
                assert_eq!(offset, frame.len());
                assert_eq!((&*row.old_hex, &*row.new_hex), ("-", "-"));
                assert_eq!(&parent[..offset], frame);
            }
            _ => panic!("unknown mutation"),
        }
        decoded.insert(row.id.clone(), frame);
        frame_rows.push(row);
    }
    let frame_directory = vectors.join("frames");
    let frame_directory_kind = fs::symlink_metadata(&frame_directory)
        .expect("frame directory metadata")
        .file_type();
    assert!(!frame_directory_kind.is_symlink());
    assert!(frame_directory_kind.is_dir());
    let mut actual_paths = BTreeSet::new();
    for entry in fs::read_dir(frame_directory).expect("read frame directory") {
        let entry = entry.expect("frame directory entry");
        let kind = entry.file_type().expect("frame entry type");
        assert!(!kind.is_symlink());
        assert!(kind.is_file());
        let name = entry.file_name().into_string().expect("UTF-8 frame name");
        actual_paths.insert(format!("frames/{name}"));
    }
    assert_eq!(paths, actual_paths);
    (frame_rows, decoded)
}

fn take<'a>(frame: &'a [u8], cursor: &mut usize, length: usize) -> &'a [u8] {
    let end = cursor
        .checked_add(length)
        .expect("independent offset overflow");
    let value = frame.get(*cursor..end).expect("independent field boundary");
    *cursor = end;
    value
}

fn u16_le(frame: &[u8], cursor: &mut usize) -> u16 {
    u16::from_le_bytes(take(frame, cursor, 2).try_into().expect("u16"))
}

fn u32_le(frame: &[u8], cursor: &mut usize) -> u32 {
    u32::from_le_bytes(take(frame, cursor, 4).try_into().expect("u32"))
}

fn u64_le(frame: &[u8], cursor: &mut usize) -> u64 {
    u64::from_le_bytes(take(frame, cursor, 8).try_into().expect("u64"))
}

fn independently_parse_request(frame: &[u8]) {
    let mut cursor = 0;
    assert_eq!(take(frame, &mut cursor, 4), b"WLFQ");
    assert_eq!(u16_le(frame, &mut cursor), 1);
    assert_eq!(u16_le(frame, &mut cursor), 76);
    assert_eq!(u64_le(frame, &mut cursor) as usize, frame.len());
    assert_eq!(u32_le(frame, &mut cursor), 0);
    assert!(matches!(take(frame, &mut cursor, 1), [0] | [1]));
    assert_eq!(take(frame, &mut cursor, 3), [0; 3]);
    assert!(u32_le(frame, &mut cursor) <= MAX_DERIVATION_INDEX);
    assert!(take(frame, &mut cursor, 32).iter().any(|byte| *byte != 0));
    let descriptor_length = u32_le(frame, &mut cursor) as usize;
    let candidate_count = u32_le(frame, &mut cursor) as usize;
    let previous_count = u32_le(frame, &mut cursor) as usize;
    assert_eq!(u32_le(frame, &mut cursor), 0);
    assert!((1..=MAX_PUBLIC_DESCRIPTOR_BYTES).contains(&descriptor_length));
    assert!(candidate_count <= MAX_CANDIDATE_TRANSACTIONS);
    let descriptor = take(frame, &mut cursor, descriptor_length);
    assert!(descriptor.is_ascii() && !descriptor.contains(&0));
    let mut observed_previous = 0;
    for _ in 0..candidate_count {
        let transaction_length = u32_le(frame, &mut cursor) as usize;
        let candidate_previous = u32_le(frame, &mut cursor) as usize;
        assert_eq!(u32_le(frame, &mut cursor), 0);
        assert!(transaction_length > 0);
        take(frame, &mut cursor, transaction_length);
        observed_previous += candidate_previous;
        for _ in 0..candidate_previous {
            let length = u32_le(frame, &mut cursor) as usize;
            assert!(length > 0);
            take(frame, &mut cursor, length);
        }
    }
    assert_eq!(observed_previous, previous_count);
    assert_eq!(cursor, frame.len());
}

fn independently_parse_response(frame: &[u8], expected_source: &[u8; 32]) {
    let mut cursor = 0;
    assert_eq!(take(frame, &mut cursor, 4), b"WLFV");
    assert_eq!(u16_le(frame, &mut cursor), 1);
    assert_eq!(u16_le(frame, &mut cursor), 64);
    assert_eq!(u64_le(frame, &mut cursor) as usize, frame.len());
    assert_eq!(u32_le(frame, &mut cursor), 0);
    let transactions = u32_le(frame, &mut cursor) as usize;
    let aggregate_outputs = u32_le(frame, &mut cursor) as usize;
    assert_eq!(u32_le(frame, &mut cursor), 0);
    assert_eq!(take(frame, &mut cursor, 32), expected_source);
    let mut prior_transaction: Option<[u8; 32]> = None;
    let mut observed_outputs = 0;
    for _ in 0..transactions {
        let transaction_id: [u8; 32] = take(frame, &mut cursor, 32)
            .try_into()
            .expect("transaction ID");
        assert!(transaction_id.iter().any(|byte| *byte != 0));
        assert!(prior_transaction.is_none_or(|prior| prior < transaction_id));
        prior_transaction = Some(transaction_id);
        take(frame, &mut cursor, 32);
        let inputs = u32_le(frame, &mut cursor) as usize;
        let outputs = u32_le(frame, &mut cursor) as usize;
        assert!(inputs > 0);
        for _ in 0..inputs {
            assert!(take(frame, &mut cursor, 32).iter().any(|byte| *byte != 0));
            assert!(u32_le(frame, &mut cursor) <= MAX_SPENDABLE_OUTPUT_INDEX);
        }
        let mut prior_output = None;
        for _ in 0..outputs {
            let output_index = u32_le(frame, &mut cursor);
            assert!(prior_output.is_none_or(|prior| prior < output_index));
            prior_output = Some(output_index);
            assert_eq!(u32_le(frame, &mut cursor), 22);
            assert_eq!(take(frame, &mut cursor, 33), GENERATOR_PUBLIC_KEY);
            assert_eq!(take(frame, &mut cursor, 33), GENERATOR_PUBLIC_KEY);
            assert!(matches!(take(frame, &mut cursor, 1), [0] | [1]));
            assert_eq!(take(frame, &mut cursor, 3), [0; 3]);
            assert!(u32_le(frame, &mut cursor) <= MAX_DERIVATION_INDEX);
            assert!(take(frame, &mut cursor, 32).iter().any(|byte| *byte != 0));
            assert!((1..=MAX_OWNED_OUTPUT_VALUE).contains(&u64_le(frame, &mut cursor)));
            assert_eq!(take(frame, &mut cursor, 22), GENERATOR_P2WPKH_SCRIPT);
            observed_outputs += 1;
        }
    }
    assert_eq!(observed_outputs, aggregate_outputs);
    assert_eq!(cursor, frame.len());
}

fn outcome<T>(result: Result<T, WalletFactsWireError>) -> u32 {
    match result {
        Ok(_) => 0,
        Err(error) => error.code(),
    }
}

fn replay_cases(frames: &BTreeMap<String, Vec<u8>>) -> BTreeSet<u32> {
    let cases = rows(
        &vector_root().join("CASES_V1.tsv"),
        &[
            "case_id",
            "frame_id",
            "operation",
            "expected_source_epoch_hex",
            "expected_status",
            "expected_error_code",
            "canonical_reencode",
        ],
    );
    let mut codes = BTreeSet::new();
    let mut canonical_length_cases = BTreeSet::new();
    for item in cases {
        let frame = frames.get(&item[1]).expect("case frame");
        if let Some((_, expected_frame)) = CANONICAL_LENGTH_CASES
            .iter()
            .find(|(case, _)| *case == item[0])
        {
            assert_eq!(&item[1], expected_frame);
            let declared_length = u64::from_le_bytes(
                frame[8..16]
                    .try_into()
                    .expect("canonical declared-length field"),
            );
            assert_eq!(declared_length as usize, frame.len());
            canonical_length_cases.insert(item[0].clone());
        }
        let expected: u32 = item[5].parse().expect("case error code");
        let actual = match item[2].as_str() {
            "request-decode" => match decode_request(frame) {
                Ok(parsed) => {
                    independently_parse_request(frame);
                    if item[6] == "yes" {
                        assert_eq!(
                            parsed.reencode().expect("canonical request").as_bytes(),
                            frame
                        );
                    }
                    0
                }
                Err(error) => error.code(),
            },
            "request-prepare" => match decode_request(frame) {
                Ok(parsed) => {
                    independently_parse_request(frame);
                    outcome(parsed.prepare())
                }
                Err(error) => error.code(),
            },
            "request-reencode" => match decode_request(frame) {
                Ok(parsed) => {
                    independently_parse_request(frame);
                    let encoded = parsed.reencode();
                    if item[6] == "yes" {
                        assert_eq!(
                            encoded.as_ref().expect("canonical request").as_bytes(),
                            frame
                        );
                    }
                    outcome(encoded)
                }
                Err(error) => error.code(),
            },
            "response-decode" => {
                let epoch: [u8; 32] = decode_hex(&item[3]).try_into().expect("source epoch");
                match decode_response(frame, &epoch) {
                    Ok(response) => {
                        independently_parse_response(frame, &epoch);
                        drop(response);
                        0
                    }
                    Err(error) => error.code(),
                }
            }
            _ => panic!("unknown replay operation"),
        };
        assert_eq!(actual, expected, "case {}", item[0]);
        assert_eq!(item[4] == "ok", expected == 0);
        codes.insert(expected);
    }
    assert_eq!(
        canonical_length_cases,
        CANONICAL_LENGTH_CASES
            .iter()
            .map(|(case, _)| (*case).to_owned())
            .collect()
    );
    codes
}

struct RecipeCandidate {
    transaction: Vec<u8>,
    previous: Vec<Vec<u8>>,
}

struct Recipe {
    id: String,
    kind: String,
    source_epoch: [u8; 32],
    descriptor_network: Option<DescriptorNetwork>,
    last_derivation_index: Option<u32>,
    descriptor: Option<String>,
    candidates: Vec<RecipeCandidate>,
    batch: TestBatch,
    candidate_text: String,
    transaction_text: String,
    output_text: String,
    property: String,
}

fn fixed_hex<const LENGTH: usize>(value: &str) -> [u8; LENGTH] {
    decode_hex(value).try_into().expect("fixed hex width")
}

fn assert_canonical_unsigned_decimal(value: &str, field: &str) {
    assert!(!value.is_empty(), "empty decimal: {field}");
    assert!(
        value.bytes().all(|byte| byte.is_ascii_digit()),
        "non-decimal byte: {field}"
    );
    assert!(
        value == "0" || !value.starts_with('0'),
        "noncanonical decimal: {field}"
    );
}

fn canonical_u32(value: &str, field: &str) -> u32 {
    assert_canonical_unsigned_decimal(value, field);
    value
        .parse()
        .unwrap_or_else(|_| panic!("u32 range: {field}"))
}

fn canonical_u64(value: &str, field: &str) -> u64 {
    assert_canonical_unsigned_decimal(value, field);
    value
        .parse()
        .unwrap_or_else(|_| panic!("u64 range: {field}"))
}

fn parse_candidates(value: &str) -> Vec<RecipeCandidate> {
    if value == "-" {
        return vec![];
    }
    value
        .split(';')
        .map(|record| {
            let (transaction, previous) = record.split_once(':').expect("candidate grammar");
            RecipeCandidate {
                transaction: if transaction == "_" {
                    vec![]
                } else {
                    assert!(
                        !transaction.is_empty(),
                        "candidate transaction must be nonempty hex or underscore"
                    );
                    decode_hex(transaction)
                },
                previous: if previous == "-" {
                    vec![]
                } else {
                    previous
                        .split(',')
                        .map(|item| {
                            assert!(!item.is_empty(), "empty previous transaction");
                            decode_hex(item)
                        })
                        .collect()
                },
            }
        })
        .collect()
}

fn parse_transactions(value: &str) -> Vec<TestTransaction> {
    if value == "-" {
        return vec![];
    }
    value
        .split(';')
        .map(|record| {
            let fields = record.split('/').collect::<Vec<_>>();
            assert_eq!(fields.len(), 3);
            TestTransaction {
                transaction_id: fixed_hex(fields[0]),
                binding: fixed_hex(fields[1]),
                inputs: if fields[2] == "-" {
                    vec![]
                } else {
                    fields[2]
                        .split(',')
                        .map(|input| {
                            let (previous, index) = input.split_once(':').expect("input grammar");
                            TestInput {
                                previous_transaction_id: fixed_hex(previous),
                                previous_output_index: canonical_u32(index, "input index"),
                            }
                        })
                        .collect()
                },
            }
        })
        .collect()
}

fn parse_outputs(value: &str) -> Vec<TestOutput> {
    if value == "-" {
        return vec![];
    }
    value
        .split(';')
        .map(|record| {
            let fields = record.split('/').collect::<Vec<_>>();
            assert_eq!(fields.len(), 10);
            TestOutput {
                transaction_id: fixed_hex(fields[0]),
                output_index: canonical_u32(fields[1], "output index"),
                binding: fixed_hex(fields[2]),
                spend_public_key: fixed_hex(fields[3]),
                blinding_public_key: fixed_hex(fields[4]),
                branch: match fields[5] {
                    "external" => DescriptorBranch::External,
                    "internal" => DescriptorBranch::Internal,
                    _ => panic!("branch grammar"),
                },
                derivation_index: canonical_u32(fields[6], "derivation index"),
                asset_id: fixed_hex(fields[7]),
                value: canonical_u64(fields[8], "output value"),
                script_pubkey: decode_hex(fields[9]),
            }
        })
        .collect()
}

fn recipe_is_request(item: &[String]) -> bool {
    let request = item[1] == "request";
    assert!(request || item[1] == "response");
    if request {
        assert_eq!((&*item[7], &*item[8]), ("-", "-"));
    } else {
        assert_eq!(
            (&*item[3], &*item[4], &*item[5], &*item[6]),
            ("-", "-", "-", "-")
        );
    }
    request
}

fn parse_recipes() -> BTreeMap<String, Recipe> {
    let fields = rows(
        &vector_root().join("RECIPES_V1.tsv"),
        &[
            "recipe_id",
            "recipe_kind",
            "source_epoch_hex",
            "descriptor_network",
            "last_derivation_index",
            "public_descriptor_hex",
            "candidates",
            "transactions",
            "outputs",
            "expected_property",
        ],
    );
    let mut recipes = BTreeMap::new();
    for item in fields {
        let request = recipe_is_request(&item);
        let descriptor_network = if request {
            Some(match item[3].as_str() {
                "mainnet" => DescriptorNetwork::Mainnet,
                "test" => DescriptorNetwork::Test,
                _ => panic!("descriptor network grammar"),
            })
        } else {
            None
        };
        let recipe = Recipe {
            id: item[0].clone(),
            kind: item[1].clone(),
            source_epoch: fixed_hex(&item[2]),
            descriptor_network,
            last_derivation_index: request
                .then(|| canonical_u32(&item[4], "last derivation index")),
            descriptor: request
                .then(|| String::from_utf8(decode_hex(&item[5])).expect("descriptor UTF-8")),
            candidates: if request {
                parse_candidates(&item[6])
            } else {
                vec![]
            },
            batch: TestBatch {
                transactions: if request {
                    vec![]
                } else {
                    parse_transactions(&item[7])
                },
                outputs: if request {
                    vec![]
                } else {
                    parse_outputs(&item[8])
                },
            },
            candidate_text: item[6].clone(),
            transaction_text: item[7].clone(),
            output_text: item[8].clone(),
            property: item[9].clone(),
        };
        assert!(recipes.insert(item[0].clone(), recipe).is_none());
    }
    recipes
}

fn verify_recipe_parser_rejections() {
    let fields = rows(
        &vector_root().join("RECIPES_V1.tsv"),
        &[
            "recipe_id",
            "recipe_kind",
            "source_epoch_hex",
            "descriptor_network",
            "last_derivation_index",
            "public_descriptor_hex",
            "candidates",
            "transactions",
            "outputs",
            "expected_property",
        ],
    );
    let request = fields
        .iter()
        .find(|item| item[0] == "empty-accepted-request-source")
        .expect("request recipe row");
    assert!(recipe_is_request(request));
    for index in [7, 8] {
        let mut ignored_response_field = request.clone();
        ignored_response_field[index] = "ignored".to_owned();
        assert!(std::panic::catch_unwind(|| recipe_is_request(&ignored_response_field)).is_err());
    }

    let response = fields
        .iter()
        .find(|item| item[0] == "empty-accepted-response-source")
        .expect("response recipe row");
    assert!(!recipe_is_request(response));
    let mut ignored_request_field = response.clone();
    ignored_request_field[3] = "test".to_owned();
    assert!(std::panic::catch_unwind(|| recipe_is_request(&ignored_request_field)).is_err());

    assert_eq!(canonical_u32("0", "u32 zero"), 0);
    assert_eq!(canonical_u64("0", "u64 zero"), 0);
    for value in ["00", "01", "+1", "-1", ""] {
        assert!(std::panic::catch_unwind(|| canonical_u32(value, "invalid u32")).is_err());
        assert!(std::panic::catch_unwind(|| canonical_u64(value, "invalid u64")).is_err());
    }
}

fn source_violations(recipe: &Recipe) -> Vec<&'static str> {
    let mut violations = Vec::new();
    let mut prior_transaction = None;
    for transaction in &recipe.batch.transactions {
        if transaction.transaction_id.iter().all(|byte| *byte == 0) {
            violations.push("transaction-id-zero");
        }
        if prior_transaction.is_some_and(|prior| prior >= transaction.transaction_id) {
            violations.push("transaction-order");
        }
        prior_transaction = Some(transaction.transaction_id);
        if transaction.inputs.is_empty() {
            violations.push("transaction-inputs-empty");
        }
        let mut inputs = BTreeSet::new();
        for input in &transaction.inputs {
            assert!(input.previous_transaction_id.iter().any(|byte| *byte != 0));
            assert!(input.previous_output_index <= MAX_SPENDABLE_OUTPUT_INDEX);
            assert!(inputs.insert((input.previous_transaction_id, input.previous_output_index)));
        }
    }
    let mut prior_outputs: BTreeMap<[u8; 32], u32> = BTreeMap::new();
    for output in &recipe.batch.outputs {
        assert!(output.output_index <= MAX_SPENDABLE_OUTPUT_INDEX);
        assert!(output.derivation_index <= MAX_DERIVATION_INDEX);
        assert_eq!(output.spend_public_key, GENERATOR_PUBLIC_KEY);
        assert_eq!(output.blinding_public_key, GENERATOR_PUBLIC_KEY);
        assert_eq!(output.script_pubkey, GENERATOR_P2WPKH_SCRIPT);
        assert!(output.asset_id.iter().any(|byte| *byte != 0));
        assert!((1..=MAX_OWNED_OUTPUT_VALUE).contains(&output.value));
        let parent = recipe
            .batch
            .transactions
            .iter()
            .find(|transaction| transaction.transaction_id == output.transaction_id);
        let Some(parent) = parent else {
            violations.push("output-orphan");
            continue;
        };
        if parent.binding != output.binding {
            violations.push("output-binding-mismatch");
        }
        if prior_outputs
            .insert(output.transaction_id, output.output_index)
            .is_some_and(|prior| prior >= output.output_index)
        {
            violations.push("output-order");
        }
    }
    violations
}

fn repeat_hex(byte: &str) -> String {
    byte.repeat(32)
}

fn assert_recipe_property(recipe: &Recipe) {
    let valid_candidate = "010203:04,0506";
    let transaction = |id: &str, binding: &str, inputs: &str| {
        format!("{}/{}/{}", repeat_hex(id), repeat_hex(binding), inputs)
    };
    let input = |id: &str, index: u32| format!("{}:{index}", repeat_hex(id));
    let output = |id: &str,
                  index: u32,
                  binding: &str,
                  asset: &str,
                  value: u64,
                  branch: &str,
                  derivation: u32| {
        format!(
            "{}/{index}/{}/{}/{}/{branch}/{derivation}/{}/{value}/{}",
            repeat_hex(id),
            repeat_hex(binding),
            hex(&GENERATOR_PUBLIC_KEY),
            hex(&GENERATOR_PUBLIC_KEY),
            repeat_hex(asset),
            hex(&GENERATOR_P2WPKH_SCRIPT)
        )
    };
    if recipe.kind == "request" {
        assert!(matches!(
            recipe.descriptor_network,
            Some(DescriptorNetwork::Test)
        ));
        assert_eq!(recipe.last_derivation_index, Some(0));
        assert_eq!(
            (&*recipe.transaction_text, &*recipe.output_text),
            ("-", "-")
        );
    }
    match recipe.property.as_str() {
        "accepted-empty-request" => {
            assert_eq!(recipe.source_epoch, SOURCE_A);
            assert_eq!(recipe.descriptor.as_deref(), Some(TEST_DESCRIPTOR));
            assert_eq!(recipe.candidate_text, "-");
            assert!(recipe.candidates.is_empty());
        }
        "accepted-nonempty-request" => {
            assert_eq!(recipe.source_epoch, SOURCE_A);
            assert_eq!(recipe.descriptor.as_deref(), Some(TEST_DESCRIPTOR));
            assert_eq!(recipe.candidate_text, valid_candidate);
            assert_eq!(recipe.candidates.len(), 1);
            assert_eq!(recipe.candidates[0].transaction, [1, 2, 3]);
            assert_eq!(recipe.candidates[0].previous, [vec![4], vec![5, 6]]);
        }
        "candidate-transaction-empty" => {
            assert_eq!(recipe.source_epoch, SOURCE_A);
            assert_eq!(recipe.descriptor.as_deref(), Some(TEST_DESCRIPTOR));
            assert_eq!(recipe.candidate_text, "_:-");
            assert_eq!(recipe.candidates.len(), 1);
            assert!(recipe.candidates[0].transaction.is_empty());
            assert!(recipe.candidates[0].previous.is_empty());
        }
        "descriptor-semantic-and-candidate-empty" => {
            assert_eq!(recipe.source_epoch, SOURCE_A);
            assert_eq!(
                recipe.descriptor.as_deref(),
                Some(SEMANTIC_REJECT_DESCRIPTOR)
            );
            assert_eq!(recipe.candidate_text, "_:-");
            assert_eq!(recipe.candidates.len(), 1);
            assert!(recipe.candidates[0].transaction.is_empty());
            assert!(recipe.candidates[0].previous.is_empty());
        }
        "zero-epoch-and-combined-invalid-request" => {
            assert_eq!(recipe.source_epoch, [0; 32]);
            assert_eq!(
                recipe.descriptor.as_deref(),
                Some(SEMANTIC_REJECT_DESCRIPTOR)
            );
            assert_eq!(recipe.candidate_text, "_:-");
            assert_eq!(recipe.candidates.len(), 1);
            assert!(recipe.candidates[0].transaction.is_empty());
            assert!(recipe.candidates[0].previous.is_empty());
        }
        "accepted-empty-a-response" | "accepted-empty-b-response" => {
            assert_eq!(
                recipe.source_epoch,
                if recipe.property.contains("-b-") {
                    SOURCE_B
                } else {
                    SOURCE_A
                }
            );
            assert_eq!(
                (&*recipe.transaction_text, &*recipe.output_text),
                ("-", "-")
            );
            assert!(source_violations(recipe).is_empty());
        }
        "accepted-spend-only-response"
        | "accepted-one-output-response"
        | "accepted-two-output-response"
        | "accepted-three-input-response" => {
            assert_eq!(recipe.source_epoch, SOURCE_A);
            let inputs = if recipe.property == "accepted-three-input-response" {
                format!("{},{},{}", input("31", 0), input("32", 1), input("33", 2))
            } else {
                input("31", 0)
            };
            assert_eq!(recipe.transaction_text, transaction("21", "51", &inputs));
            let expected_outputs = match recipe.property.as_str() {
                "accepted-spend-only-response" | "accepted-three-input-response" => "-".to_owned(),
                "accepted-one-output-response" => output("21", 3, "51", "71", 1, "external", 0),
                _ => format!(
                    "{};{}",
                    output("21", 3, "51", "71", 1, "external", 0),
                    output("21", 4, "51", "72", 2, "internal", 1)
                ),
            };
            assert_eq!(recipe.output_text, expected_outputs);
            assert!(source_violations(recipe).is_empty());
        }
        "accepted-multi-asset-response" => {
            assert_eq!(recipe.source_epoch, SOURCE_A);
            assert_eq!(
                recipe.transaction_text,
                format!(
                    "{};{}",
                    transaction(
                        "21",
                        "51",
                        &format!("{},{}", input("33", 1), input("31", 0))
                    ),
                    transaction(
                        "22",
                        "52",
                        &format!("{},{}", input("33", 1), input("34", 2))
                    )
                )
            );
            assert_eq!(
                recipe.output_text,
                format!(
                    "{};{}",
                    output("21", 3, "51", "71", 1, "external", 0),
                    output(
                        "22",
                        4,
                        "52",
                        "72",
                        MAX_OWNED_OUTPUT_VALUE,
                        "internal",
                        MAX_DERIVATION_INDEX
                    )
                )
            );
            assert!(source_violations(recipe).is_empty());
        }
        "transaction-inputs-empty" => {
            assert_eq!(source_violations(recipe), ["transaction-inputs-empty"])
        }
        "transaction-id-zero" => assert_eq!(source_violations(recipe), ["transaction-id-zero"]),
        "output-orphan" => assert_eq!(source_violations(recipe), ["output-orphan"]),
        "output-binding-mismatch" => {
            assert_eq!(source_violations(recipe), ["output-binding-mismatch"])
        }
        "output-order" => assert_eq!(source_violations(recipe), ["output-order"]),
        "zero-epoch-and-transaction-inputs-empty" => {
            assert_eq!(recipe.source_epoch, [0; 32]);
            assert_eq!(source_violations(recipe), ["transaction-inputs-empty"]);
        }
        _ => panic!("unknown recipe property"),
    }
}

fn recipe_contract(recipe: &Recipe) -> (&'static str, &'static str, u32) {
    match recipe.property.as_str() {
        "accepted-empty-request" | "accepted-nonempty-request" => ("request-encode", "ok", 0),
        "candidate-transaction-empty" => ("request-encode", "error", 6),
        "descriptor-semantic-and-candidate-empty" => ("request-encode", "error", 5),
        "zero-epoch-and-combined-invalid-request" => ("request-encode", "error", 1),
        "accepted-empty-a-response"
        | "accepted-empty-b-response"
        | "accepted-spend-only-response"
        | "accepted-one-output-response"
        | "accepted-two-output-response"
        | "accepted-three-input-response"
        | "accepted-multi-asset-response" => ("response-encode", "ok", 0),
        "zero-epoch-and-transaction-inputs-empty" => ("response-encode", "error", 1),
        "transaction-inputs-empty"
        | "transaction-id-zero"
        | "output-orphan"
        | "output-binding-mismatch"
        | "output-order" => ("response-source-validation", "error", 7),
        _ => panic!("unknown recipe contract"),
    }
}

fn encode_request_recipe(
    recipe: &Recipe,
) -> Result<EncodedWalletFactsRequest, WalletFactsWireError> {
    let candidates = recipe
        .candidates
        .iter()
        .map(|candidate| WalletFactsCandidateRef::new(&candidate.transaction, &candidate.previous))
        .collect::<Vec<_>>();
    encode_request(&WalletFactsRequestRef::new(
        &recipe.source_epoch,
        recipe.descriptor_network.expect("request network"),
        recipe
            .last_derivation_index
            .expect("request derivation index"),
        recipe.descriptor.as_deref().expect("request descriptor"),
        &candidates,
    ))
}

fn replay_api_cases(frames: &BTreeMap<String, Vec<u8>>) -> BTreeSet<u32> {
    let recipe_map = parse_recipes();
    let cases = rows(
        &vector_root().join("API_CASES_V1.tsv"),
        &[
            "case_id",
            "operation",
            "fixture_recipe",
            "expected_status",
            "expected_error_code",
            "expected_frame_id",
        ],
    );
    let mut codes = BTreeSet::new();
    let mut recipes = BTreeSet::new();
    for item in cases {
        assert!(recipes.insert(item[2].clone()));
        let recipe = recipe_map.get(&item[2]).expect("API recipe");
        assert_eq!(recipe.id, item[2]);
        assert_recipe_property(recipe);
        let expected: u32 = item[4].parse().expect("API error code");
        let contract = recipe_contract(recipe);
        assert_eq!((&*item[1], &*item[3], expected), contract);
        let (actual, encoded) = if recipe.kind == "request" {
            match encode_request_recipe(recipe) {
                Ok(value) => (0, Some(value.as_bytes().to_vec())),
                Err(error) => (error.code(), None),
            }
        } else {
            match encode_source(&recipe.batch, &recipe.source_epoch) {
                Ok(value) => (0, Some(value.as_bytes().to_vec())),
                Err(error) => (error.code(), None),
            }
        };
        assert_eq!(actual, expected, "API case {}", item[0]);
        assert_eq!(item[3] == "ok", expected == 0);
        if expected == 0 {
            assert_eq!(
                encoded.as_deref(),
                Some(frames.get(&item[5]).expect("API frame").as_slice())
            );
        } else {
            assert_eq!(item[5], "-");
            assert!(encoded.is_none());
        }
        codes.insert(expected);
    }
    assert_eq!(recipes, recipe_map.keys().cloned().collect());
    assert_eq!(recipes.len(), 18);
    codes
}

fn evaluate_formula(formula: &str) -> Option<u64> {
    assert!(!formula.is_empty() && !formula.contains(char::is_whitespace));
    let mut total = 0_u64;
    for term in formula.split('+') {
        let mut product = 1_u64;
        for factor in term.split('*') {
            assert!(!factor.is_empty() && (factor == "0" || !factor.starts_with('0')));
            product = product.checked_mul(factor.parse::<u64>().ok()?)?;
        }
        total = total.checked_add(product)?;
    }
    Some(total)
}

fn constant(token: &str) -> (u64, &'static str, &'static str, &'static str) {
    match token {
        "max-public-descriptor-bytes" => (
            MAX_PUBLIC_DESCRIPTOR_BYTES as u64,
            "u32",
            "MAX_PUBLIC_DESCRIPTOR_BYTES",
            "Public descriptor bytes",
        ),
        "max-derivation-index" => (
            MAX_DERIVATION_INDEX as u64,
            "u32",
            "MAX_DERIVATION_INDEX",
            "Last derivation index",
        ),
        "max-candidate-transactions" => (
            MAX_CANDIDATE_TRANSACTIONS as u64,
            "u32",
            "MAX_CANDIDATE_TRANSACTIONS",
            "Candidate transactions",
        ),
        "max-previous-transactions-per-batch" => (
            MAX_PREVIOUS_TRANSACTIONS_PER_BATCH as u64,
            "u32",
            "MAX_PREVIOUS_TRANSACTIONS_PER_BATCH",
            "Previous transactions in one batch",
        ),
        "max-transaction-bytes" => (
            MAX_TRANSACTION_BYTES as u64,
            "u32",
            "MAX_TRANSACTION_BYTES",
            "One serialized transaction",
        ),
        "max-batch-bytes" => (
            MAX_BATCH_BYTES as u64,
            "usize64",
            "MAX_BATCH_BYTES",
            "Aggregate candidate and previous-transaction bytes",
        ),
        "max-request-frame-bytes" => (
            MAX_REQUEST_FRAME_BYTES as u64,
            "usize64",
            "MAX_REQUEST_FRAME_BYTES",
            "Outer request rejection ceiling",
        ),
        "max-reachable-request-bytes" => (
            MAX_REACHABLE_REQUEST_BYTES as u64,
            "usize64",
            "MAX_REACHABLE_REQUEST_BYTES",
            "Maximum structurally reachable request",
        ),
        "max-response-frame-bytes" => (
            MAX_RESPONSE_FRAME_BYTES as u64,
            "usize64",
            "MAX_RESPONSE_FRAME_BYTES",
            "Outer response rejection ceiling",
        ),
        "max-reachable-response-bytes" => (
            MAX_REACHABLE_RESPONSE_BYTES as u64,
            "usize64",
            "MAX_REACHABLE_RESPONSE_BYTES",
            "Maximum structurally reachable response",
        ),
        "max-aggregate-inputs" => (
            MAX_AGGREGATE_INPUTS as u64,
            "usize64",
            "MAX_AGGREGATE_INPUTS",
            "Aggregate observed inputs",
        ),
        "max-aggregate-owned-outputs" => (
            MAX_AGGREGATE_OWNED_OUTPUTS as u64,
            "usize64",
            "MAX_AGGREGATE_OWNED_OUTPUTS",
            "Aggregate owned outputs",
        ),
        "max-inputs-per-transaction" => (
            MAX_INPUTS_PER_TRANSACTION as u64,
            "usize64",
            "MAX_INPUTS_PER_TRANSACTION",
            "Inputs in one observed transaction",
        ),
        "max-owned-outputs-per-transaction" => (
            MAX_OWNED_OUTPUTS_PER_TRANSACTION as u64,
            "usize64",
            "MAX_OWNED_OUTPUTS_PER_TRANSACTION",
            "Owned outputs in one observed transaction",
        ),
        "max-owned-output-value" => (
            MAX_OWNED_OUTPUT_VALUE,
            "u64",
            "MAX_OWNED_OUTPUT_VALUE",
            "Maximum owned-output value",
        ),
        "max-spendable-output-index" => (
            MAX_SPENDABLE_OUTPUT_INDEX as u64,
            "u32",
            "MAX_SPENDABLE_OUTPUT_INDEX",
            "Maximum spendable output index",
        ),
        _ => panic!("unknown production constant"),
    }
}

fn expected_boundary(identifier: &str) -> Vec<String> {
    let fixed = match identifier {
        "arithmetic-add-overflow" => Some([
            "checked-arithmetic",
            "arithmetic-rejection",
            "none",
            "u64",
            "18446744073709551615+1",
            "overflow",
            "-",
            "4",
        ]),
        "arithmetic-multiply-overflow" => Some([
            "checked-arithmetic",
            "arithmetic-rejection",
            "none",
            "u64",
            "18446744073709551615*2",
            "overflow",
            "-",
            "4",
        ]),
        "reachable-request-bytes" => Some([
            "checked-arithmetic",
            "reachable-maximum",
            "max-reachable-request-bytes",
            "usize64",
            "76+16384+4096*12+16384*4+67108864",
            "ok",
            "67240012",
            "0",
        ]),
        "reachable-response-bytes" => Some([
            "checked-arithmetic",
            "reachable-maximum",
            "max-reachable-response-bytes",
            "usize64",
            "64+4096*72+1636801*36+148470*144",
            "ok",
            "80599492",
            "0",
        ]),
        "request-outer-ceiling" => Some([
            "request-outer-length-check",
            "outer-ceiling",
            "max-request-frame-bytes",
            "usize64",
            "268435456",
            "ok",
            "268435456",
            "0",
        ]),
        "request-outer-plus-one" => Some([
            "request-outer-length-check",
            "outer-ceiling",
            "max-request-frame-bytes",
            "usize64",
            "268435456+1",
            "rejected",
            "268435457",
            "4",
        ]),
        "response-outer-ceiling" => Some([
            "response-outer-length-check",
            "outer-ceiling",
            "max-response-frame-bytes",
            "usize64",
            "268435456",
            "ok",
            "268435456",
            "0",
        ]),
        "response-outer-plus-one" => Some([
            "response-outer-length-check",
            "outer-ceiling",
            "max-response-frame-bytes",
            "usize64",
            "268435456+1",
            "rejected",
            "268435457",
            "4",
        ]),
        _ => None,
    };
    if let Some(row) = fixed {
        return row.into_iter().map(str::to_owned).collect();
    }
    let (prefix, plus_one) = identifier
        .strip_suffix("-maximum")
        .map(|prefix| (prefix, false))
        .or_else(|| {
            identifier
                .strip_suffix("-plus-one")
                .map(|prefix| (prefix, true))
        })
        .expect("exact boundary identifier");
    let (operation, token, error_code) = match prefix {
        "aggregate-inputs" => ("response-decode", "max-aggregate-inputs", 4),
        "aggregate-owned-outputs" => ("response-decode", "max-aggregate-owned-outputs", 4),
        "batch-bytes" => ("request-decode", "max-batch-bytes", 4),
        "candidate-transactions" => ("request-decode", "max-candidate-transactions", 4),
        "derivation-index" => ("request-decode", "max-derivation-index", 4),
        "inputs-per-transaction" => ("response-decode", "max-inputs-per-transaction", 4),
        "owned-output-value" => ("response-decode", "max-owned-output-value", 3),
        "owned-outputs-per-transaction" => {
            ("response-decode", "max-owned-outputs-per-transaction", 4)
        }
        "previous-transactions" => ("request-decode", "max-previous-transactions-per-batch", 4),
        "public-descriptor-bytes" => ("request-decode", "max-public-descriptor-bytes", 4),
        "spendable-output-index" => ("response-decode", "max-spendable-output-index", 3),
        "transaction-bytes" => ("request-decode", "max-transaction-bytes", 4),
        _ => panic!("unknown component boundary"),
    };
    let (maximum, domain, _, _) = constant(token);
    vec![
        operation.to_owned(),
        "component-limit".to_owned(),
        token.to_owned(),
        domain.to_owned(),
        if plus_one {
            format!("{maximum}+1")
        } else {
            maximum.to_string()
        },
        if plus_one { "rejected" } else { "ok" }.to_owned(),
        (maximum + u64::from(plus_one)).to_string(),
        if plus_one {
            error_code.to_string()
        } else {
            "0".to_owned()
        },
    ]
}

fn verify_boundaries() {
    assert_eq!(usize::BITS, 64);
    let corpus = canonical_text(&vector_root().join("CORPUS_V1.md"));
    assert!(corpus.contains(&format!("Corpus ID: {CORPUS_ID}\n")));
    let boundary_rows = rows(
        &vector_root().join("BOUNDARIES_V1.tsv"),
        &[
            "boundary_id",
            "operation",
            "boundary_kind",
            "production_constant",
            "numeric_domain",
            "formula",
            "expected_status",
            "expected_value",
            "expected_error_code",
        ],
    );
    assert_eq!(boundary_rows.len(), 32);
    let expected_mapping = [
        "max-public-descriptor-bytes",
        "max-derivation-index",
        "max-candidate-transactions",
        "max-previous-transactions-per-batch",
        "max-transaction-bytes",
        "max-batch-bytes",
        "max-request-frame-bytes",
        "max-reachable-request-bytes",
        "max-response-frame-bytes",
        "max-reachable-response-bytes",
        "max-aggregate-inputs",
        "max-aggregate-owned-outputs",
        "max-inputs-per-transaction",
        "max-owned-outputs-per-transaction",
        "max-owned-output-value",
        "max-spendable-output-index",
    ]
    .into_iter()
    .map(|token| {
        let (_, _, rust_name, contract_row) = constant(token);
        format!("| {token} | {rust_name} | {contract_row} |")
    })
    .collect::<BTreeSet<_>>();
    let actual_mapping = corpus
        .lines()
        .filter(|line| line.starts_with("| max-"))
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    assert_eq!(actual_mapping, expected_mapping);
    let mut constants = BTreeSet::new();
    for item in boundary_rows {
        assert_eq!(item[1..], expected_boundary(&item[0]));
        let result = evaluate_formula(&item[5]);
        let code: u32 = item[8].parse().expect("boundary error code");
        if item[6] == "overflow" {
            assert_eq!(result, None);
            assert_eq!((&*item[3], &*item[7], code), ("none", "-", 4));
            continue;
        }
        let value = result.expect("non-overflow boundary");
        assert_eq!(value, item[7].parse::<u64>().expect("boundary value"));
        let (maximum, domain, _, _) = constant(&item[3]);
        assert_eq!(item[4], domain);
        assert!(corpus.contains(&item[3]));
        if item[2] == "reachable-maximum" {
            assert_eq!(value, maximum);
        } else if item[6] == "ok" {
            assert_eq!(value, maximum);
            assert_eq!(code, 0);
        } else {
            assert_eq!(value, maximum + 1);
            assert_ne!(code, 0);
        }
        match item[1].as_str() {
            "request-outer-length-check" => assert_eq!(
                outcome(validate_outer_length(
                    value as usize,
                    MAX_REQUEST_FRAME_BYTES
                )),
                code
            ),
            "response-outer-length-check" => assert_eq!(
                outcome(validate_outer_length(
                    value as usize,
                    MAX_RESPONSE_FRAME_BYTES
                )),
                code
            ),
            "checked-arithmetic" if item[5].contains('+') => assert_eq!(
                checked_add(0, value as usize).expect("reachable addition"),
                value as usize
            ),
            "checked-arithmetic" if item[5].contains('*') => assert_eq!(
                checked_multiply(1, value as usize).expect("reachable multiplication"),
                value as usize
            ),
            _ => {}
        }
        constants.insert(item[3].clone());
    }
    assert_eq!(constants.len(), 16);
    assert!(matches!(
        checked_add(usize::MAX, 1),
        Err(WalletFactsWireError::LimitExceeded)
    ));
    assert!(matches!(
        checked_multiply(usize::MAX, 2),
        Err(WalletFactsWireError::LimitExceeded)
    ));
}

fn parse_checksum(path: &Path) -> BTreeMap<String, String> {
    let mut result = BTreeMap::new();
    let mut previous: Option<Vec<u8>> = None;
    for line in canonical_text(path).trim_end_matches('\n').split('\n') {
        let (digest, relative) = line.split_once("  ").expect("checksum separator");
        assert_eq!(digest.len(), 64);
        assert!(
            digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        );
        assert!(!relative.contains('\\'));
        let bytes = relative.as_bytes().to_vec();
        assert!(previous.as_ref().is_none_or(|value| value < &bytes));
        previous = Some(bytes);
        assert!(
            result
                .insert(relative.to_owned(), digest.to_owned())
                .is_none()
        );
    }
    result
}

fn enumerate_files(root: &Path, current: &Path, output: &mut BTreeSet<String>) {
    for entry in fs::read_dir(current).expect("read checksum directory") {
        let entry = entry.expect("checksum directory entry");
        let kind = entry.file_type().expect("checksum file type");
        assert!(!kind.is_symlink());
        let path = entry.path();
        if kind.is_dir() {
            enumerate_files(root, &path, output);
        } else {
            assert!(kind.is_file());
            let relative = path.strip_prefix(root).expect("checksum relative path");
            if relative != Path::new("SHA256SUMS") {
                output.insert(relative.to_string_lossy().replace('\\', "/"));
            }
        }
    }
}

fn verify_checksum_closure() {
    let vectors = vector_root();
    let reference = vectors.parent().expect("reference directory");
    let reference_kind = fs::symlink_metadata(reference)
        .expect("reference metadata")
        .file_type();
    assert!(!reference_kind.is_symlink());
    assert!(reference_kind.is_dir());
    let mut actual_topology = BTreeSet::new();
    for entry in fs::read_dir(reference).expect("read reference directory") {
        let entry = entry.expect("reference directory entry");
        let kind = entry.file_type().expect("reference entry type");
        assert!(!kind.is_symlink());
        let name = entry
            .file_name()
            .into_string()
            .expect("UTF-8 reference entry");
        match name.as_str() {
            "vectors" => assert!(kind.is_dir()),
            "ERROR_MAPPING_V1.tsv" | "SHA256SUMS" | "WIRE_FORMAT_V1.md" => {
                assert!(kind.is_file());
            }
            _ => panic!("unexpected reference entry: {name}"),
        }
        assert!(actual_topology.insert(name));
    }
    assert_eq!(
        actual_topology,
        BTreeSet::from([
            "ERROR_MAPPING_V1.tsv".to_owned(),
            "SHA256SUMS".to_owned(),
            "WIRE_FORMAT_V1.md".to_owned(),
            "vectors".to_owned(),
        ])
    );
    let vectors_kind = fs::symlink_metadata(&vectors)
        .expect("vector root metadata")
        .file_type();
    assert!(!vectors_kind.is_symlink());
    assert!(vectors_kind.is_dir());
    let nested = parse_checksum(&vectors.join("SHA256SUMS"));
    let mut actual = BTreeSet::new();
    enumerate_files(&vectors, &vectors, &mut actual);
    assert_eq!(nested.keys().cloned().collect::<BTreeSet<_>>(), actual);
    for (relative, expected) in nested {
        assert_eq!(
            sha256(&fs::read(vectors.join(relative)).expect("nested checksum file")),
            expected
        );
    }
    let parent = parse_checksum(&reference.join("SHA256SUMS"));
    assert_eq!(
        parent.keys().cloned().collect::<BTreeSet<_>>(),
        BTreeSet::from([
            "ERROR_MAPPING_V1.tsv".to_owned(),
            "WIRE_FORMAT_V1.md".to_owned(),
            "vectors/SHA256SUMS".to_owned(),
        ])
    );
    for (relative, expected) in parent {
        assert_eq!(
            sha256(&fs::read(reference.join(relative)).expect("parent checksum file")),
            expected
        );
    }
}

fn verify_error_map() {
    let mapping = rows(
        &vector_root()
            .parent()
            .expect("reference directory")
            .join("ERROR_MAPPING_V1.tsv"),
        &["code", "variant", "text"],
    );
    let expected = [
        (
            1,
            "InvalidArgument",
            "wallet facts wire argument is invalid",
        ),
        (
            2,
            "VersionMismatch",
            "wallet facts wire version is unsupported",
        ),
        (
            3,
            "InvalidEncoding",
            "wallet facts wire encoding is invalid",
        ),
        (4, "LimitExceeded", "wallet facts wire limit exceeded"),
        (
            5,
            "DescriptorRejected",
            "wallet facts descriptor was rejected",
        ),
        (
            6,
            "CandidateRejected",
            "wallet facts candidate batch was rejected",
        ),
        (
            7,
            "ObservationRejected",
            "wallet facts observation was rejected",
        ),
        (
            8,
            "SourceBindingMismatch",
            "wallet facts source binding does not match",
        ),
    ];
    assert_eq!(mapping.len(), expected.len());
    for (row, (code, variant, text)) in mapping.iter().zip(expected) {
        assert_eq!(
            row,
            &[code.to_string(), variant.to_owned(), text.to_owned()]
        );
    }
}

fn verify_source_binding_order_without_giant_frame() {
    let source = include_str!("response.rs");
    let decode = source
        .split("pub fn decode_response")
        .nth(1)
        .expect("response decoder source")
        .split("fn validate_source")
        .next()
        .expect("response decoder boundary");
    let parse = decode
        .find("let header = parse_header")
        .expect("header parse call");
    let zero_expected = decode
        .find("if !is_nonzero(expected_source_epoch)")
        .expect("zero expected-source predicate");
    let outer_length = decode
        .find("validate_outer_length(frame.len(), MAX_RESPONSE_FRAME_BYTES)")
        .expect("outer response length predicate");
    let reachable = decode
        .find("if frame.len() > MAX_REACHABLE_RESPONSE_BYTES")
        .expect("reachable response predicate");
    assert!(zero_expected < outer_length && outer_length < parse && parse < reachable);

    let request_source = include_str!("request.rs");
    let request_decode = request_source
        .split("pub fn decode_request")
        .nth(1)
        .expect("request decoder source")
        .split("fn parse_header")
        .next()
        .expect("request decoder boundary");
    let request_outer = request_decode
        .find("validate_outer_length(frame.len(), MAX_REQUEST_FRAME_BYTES)")
        .expect("outer request length predicate");
    let request_parse = request_decode
        .find("let header = parse_header")
        .expect("request header parse call");
    let request_reachable = request_decode
        .find("if frame.len() > MAX_REACHABLE_REQUEST_BYTES")
        .expect("reachable request predicate");
    assert!(request_outer < request_parse && request_parse < request_reachable);

    let header = source
        .split("fn parse_header(")
        .nth(1)
        .expect("response header source")
        .split("fn validate_response_layout")
        .next()
        .expect("response header boundary");
    let mismatch = header
        .find("if source_epoch.0 != *expected_source_epoch")
        .expect("source mismatch predicate");
    let component_limits = header
        .find("if transaction_count > MAX_CANDIDATE_TRANSACTIONS")
        .expect("response count predicates");
    assert!(mismatch < component_limits);
}

#[test]
fn wallet_facts_wire_v1_conformance_corpus() {
    verify_checksum_closure();
    let (_rows, frames) = load_frames();
    let mut codes = replay_cases(&frames);
    verify_recipe_parser_rejections();
    codes.extend(replay_api_cases(&frames));
    assert_eq!(codes, BTreeSet::from_iter(0..=8));
    verify_boundaries();
    verify_source_binding_order_without_giant_frame();
    verify_error_map();
}
