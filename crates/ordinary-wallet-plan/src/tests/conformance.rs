use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::str;

use elements::secp256k1_zkp::Secp256k1;
use sha2::{Digest, Sha256};
use wasabi_liquid_native_wallet_facts::{DescriptorCatalog, DescriptorNetwork};

use crate::{
    DestinationView, OrdinaryWalletPlanDestinationRef, OrdinaryWalletPlanRequestRef,
    OrdinaryWalletPlanSelectedRef, OrdinaryWalletPlanWireError, RequestView, SelectedView,
    decode_request, encode_request, encode_view,
};

const CORPUS_ID: &str = "ordinary-wallet-plan-wire-v1-conformance-1";
const PARENT_ROOT_SHA256: &str = "45265732edffe658cb7925ad536c4c8372219cc415d4b185d67f8230dde113c7";
const NESTED_ROOT_SHA256: &str = "c0cdf0e1353b32a941fb7fa34ceb5ab682c76c1f5d01e892578ea8a800a25014";
const CASES_SHA256: &str = "2cf40a89f2c4fc50306a309f16c36899aca1827bb74a475a5122b49aa22d520c";
const OUTER_LIMIT_PLUS_ONE: usize = 268_435_457;

const CASES_HEADER: &[&str] = &[
    "case_id",
    "partition",
    "operation",
    "implementation",
    "execution_class",
    "frame_id",
    "source_model_id",
    "expected_source_epoch_hex",
    "catalog_fixture_id",
    "expected_result",
    "expected_error_code",
    "expected_reencode_frame_id",
    "combined_precedence",
    "coverage_tags",
    "input_identity_sha256",
    "expected_output_sha256",
    "case_binding_sha256",
];
const FRAMES_HEADER: &[&str] = &[
    "frame_id",
    "execution_class",
    "relative_path",
    "decoded_length",
    "decoded_sha256",
    "structural_result",
    "structural_error_code",
    "parent_frame_id",
    "mutation_id",
    "source_epoch_hex",
    "source_revision",
    "manifest_id_hex",
    "pegged_asset_consensus_hex",
    "selected_count",
    "destination_count",
    "aggregate_previous_count",
    "fee_value",
    "selected_txids_consensus_hex",
    "selected_txids_display_hex",
    "destination_assets_consensus_hex",
    "destination_addresses_hex",
    "payload_hash_manifest",
];
const SOURCE_MODELS_HEADER: &[&str] = &[
    "source_model_id",
    "partition",
    "operation",
    "execution_class",
    "relative_path",
    "decoded_length",
    "decoded_sha256",
    "expected_result",
    "expected_error_code",
    "precedence",
];
const FIXTURES_HEADER: &[&str] = &[
    "fixture_id",
    "fixture_kind",
    "network",
    "relative_path",
    "decoded_length",
    "decoded_sha256",
    "txid_consensus_hex",
    "txid_display_hex",
    "public_property",
];
const CATALOGS_HEADER: &[&str] = &[
    "catalog_fixture_id",
    "context_id",
    "descriptor_network",
    "inclusive_last_derivation_index",
    "checksummed_public_descriptor",
];

#[derive(Clone)]
struct SelectedModel {
    transaction_id: [u8; 32],
    output_index: u32,
    asset: [u8; 32],
    value: u64,
    candidate: Vec<u8>,
    previous: Vec<Vec<u8>>,
}

#[derive(Clone)]
struct DestinationModel {
    asset: [u8; 32],
    value: u64,
    address: Vec<u8>,
}

#[derive(Clone)]
struct RequestModel {
    source_epoch: [u8; 32],
    source_revision: u64,
    manifest_id: [u8; 32],
    pegged_asset: [u8; 32],
    selected: Vec<SelectedModel>,
    destinations: Vec<DestinationModel>,
    explicit_fee_value: u64,
}

impl SelectedView for SelectedModel {
    fn transaction_id(&self) -> &[u8; 32] {
        &self.transaction_id
    }

    fn output_index(&self) -> &u32 {
        &self.output_index
    }

    fn asset(&self) -> &[u8; 32] {
        &self.asset
    }

    fn value(&self) -> &u64 {
        &self.value
    }

    fn candidate(&self) -> &[u8] {
        &self.candidate
    }

    fn previous(&self) -> &[Vec<u8>] {
        &self.previous
    }
}

impl DestinationView for DestinationModel {
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

impl RequestView for RequestModel {
    type Selected = SelectedModel;
    type Destination = DestinationModel;

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
        &self.selected
    }

    fn destinations(&self) -> &[Self::Destination] {
        &self.destinations
    }

    fn explicit_fee_value(&self) -> &u64 {
        &self.explicit_fee_value
    }
}

struct Table {
    rows: Vec<Vec<String>>,
}

#[derive(Clone)]
struct Case {
    case_id: String,
    partition: String,
    operation: String,
    implementation: String,
    execution_class: String,
    frame_id: Option<String>,
    source_model_id: Option<String>,
    expected_source_epoch: [u8; 32],
    catalog_fixture_id: Option<String>,
    expected_result: String,
    expected_error_code: u32,
    expected_reencode_frame_id: Option<String>,
    expected_output_sha256: Option<String>,
}

struct FrameEntry {
    relative_path: String,
    decoded_length: usize,
    decoded_sha256: String,
}

struct SourceModelEntry {
    partition: String,
    operation: String,
    execution_class: String,
    relative_path: String,
    decoded_length: usize,
    decoded_sha256: String,
    expected_result: String,
    expected_error_code: u32,
}

struct FixtureEntry {
    relative_path: String,
    decoded_length: usize,
    decoded_sha256: String,
}

struct CatalogEntry {
    network: DescriptorNetwork,
    last_index: u32,
    descriptor: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum JsonValue {
    Null,
    Bool(bool),
    Number(u64),
    String(String),
    Array(Vec<JsonValue>),
    Object(Vec<(String, JsonValue)>),
}

struct JsonParser<'source> {
    source: &'source [u8],
    cursor: usize,
}

impl<'source> JsonParser<'source> {
    fn new(source: &'source str) -> Self {
        Self {
            source: source.as_bytes(),
            cursor: 0,
        }
    }

    fn parse(mut self) -> JsonValue {
        let value = self.value();
        assert_eq!(self.cursor, self.source.len(), "JSON has trailing bytes");
        value
    }

    fn value(&mut self) -> JsonValue {
        match self.peek() {
            Some(b'n') => {
                self.literal(b"null");
                JsonValue::Null
            }
            Some(b't') => {
                self.literal(b"true");
                JsonValue::Bool(true)
            }
            Some(b'f') => {
                self.literal(b"false");
                JsonValue::Bool(false)
            }
            Some(b'0'..=b'9') => JsonValue::Number(self.number()),
            Some(b'"') => JsonValue::String(self.string()),
            Some(b'[') => self.array(),
            Some(b'{') => self.object(),
            _ => panic!("JSON value is not canonical"),
        }
    }

    fn peek(&self) -> Option<u8> {
        self.source.get(self.cursor).copied()
    }

    fn take(&mut self, expected: u8) {
        assert_eq!(self.peek(), Some(expected), "JSON token mismatch");
        self.cursor += 1;
    }

    fn literal(&mut self, expected: &[u8]) {
        assert_eq!(
            self.source.get(self.cursor..self.cursor + expected.len()),
            Some(expected),
            "JSON literal mismatch"
        );
        self.cursor += expected.len();
    }

    fn number(&mut self) -> u64 {
        let start = self.cursor;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.cursor += 1;
        }
        let raw = str::from_utf8(&self.source[start..self.cursor]).expect("JSON number is ASCII");
        assert!(
            raw == "0" || !raw.starts_with('0'),
            "JSON number has a leading zero"
        );
        raw.parse::<u64>().expect("JSON number exceeds u64")
    }

    fn string(&mut self) -> String {
        self.take(b'"');
        let mut value = String::new();
        loop {
            let byte = self.peek().expect("JSON string is unterminated");
            self.cursor += 1;
            match byte {
                b'"' => return value,
                b'\\' => {
                    let escaped = self.peek().expect("JSON escape is unterminated");
                    self.cursor += 1;
                    value.push(match escaped {
                        b'"' => '"',
                        b'\\' => '\\',
                        b'/' => '/',
                        b'b' => '\u{0008}',
                        b'f' => '\u{000c}',
                        b'n' => '\n',
                        b'r' => '\r',
                        b't' => '\t',
                        _ => panic!("unsupported JSON escape"),
                    });
                }
                0x00..=0x1f | 0x80..=0xff => panic!("JSON string is not canonical ASCII"),
                _ => value.push(char::from(byte)),
            }
        }
    }

    fn array(&mut self) -> JsonValue {
        self.take(b'[');
        let mut values = Vec::new();
        if self.peek() == Some(b']') {
            self.cursor += 1;
            return JsonValue::Array(values);
        }
        loop {
            values.push(self.value());
            match self.peek() {
                Some(b',') => self.cursor += 1,
                Some(b']') => {
                    self.cursor += 1;
                    return JsonValue::Array(values);
                }
                _ => panic!("JSON array delimiter mismatch"),
            }
        }
    }

    fn object(&mut self) -> JsonValue {
        self.take(b'{');
        let mut values = Vec::new();
        let mut prior: Option<String> = None;
        if self.peek() == Some(b'}') {
            self.cursor += 1;
            return JsonValue::Object(values);
        }
        loop {
            let key = self.string();
            if let Some(previous) = &prior {
                assert!(previous < &key, "JSON object keys are not strictly ordered");
            }
            prior = Some(key.clone());
            self.take(b':');
            values.push((key, self.value()));
            match self.peek() {
                Some(b',') => self.cursor += 1,
                Some(b'}') => {
                    self.cursor += 1;
                    return JsonValue::Object(values);
                }
                _ => panic!("JSON object delimiter mismatch"),
            }
        }
    }
}

impl JsonValue {
    fn object(&self, expected_keys: &[&str]) -> &[(String, JsonValue)] {
        let Self::Object(values) = self else {
            panic!("expected JSON object")
        };
        assert_eq!(
            values
                .iter()
                .map(|(key, _)| key.as_str())
                .collect::<Vec<_>>(),
            expected_keys,
            "JSON object schema mismatch"
        );
        values
    }

    fn get<'value>(values: &'value [(String, JsonValue)], key: &str) -> &'value JsonValue {
        &values
            .iter()
            .find(|(candidate, _)| candidate == key)
            .unwrap_or_else(|| panic!("missing JSON field {key}"))
            .1
    }

    fn as_str(&self) -> &str {
        let Self::String(value) = self else {
            panic!("expected JSON string")
        };
        value
    }

    fn as_u64(&self) -> u64 {
        let Self::Number(value) = self else {
            panic!("expected JSON integer")
        };
        *value
    }

    fn as_bool(&self) -> bool {
        let Self::Bool(value) = self else {
            panic!("expected JSON boolean")
        };
        *value
    }

    fn as_array(&self) -> &[JsonValue] {
        let Self::Array(values) = self else {
            panic!("expected JSON array")
        };
        values
    }
}

fn corpus_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../contracts/ordinary-wallet-plan/v1/nonlinkable-reference")
}

fn sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn is_lower_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.as_bytes()[0].is_ascii_lowercase()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn strict_usize(value: &str) -> usize {
    assert!(
        value == "0" || (!value.is_empty() && !value.starts_with('0')),
        "decimal is not canonical"
    );
    assert!(value.bytes().all(|byte| byte.is_ascii_digit()));
    value.parse().expect("decimal exceeds usize")
}

fn strict_u32(value: &str) -> u32 {
    u32::try_from(strict_usize(value)).expect("decimal exceeds u32")
}

fn read_text(path: &Path) -> String {
    let bytes =
        fs::read(path).unwrap_or_else(|_| panic!("corpus text is absent: {}", path.display()));
    assert!(!bytes.is_empty(), "corpus text is empty");
    assert!(
        !bytes.starts_with(&[0xef, 0xbb, 0xbf]),
        "corpus text has a BOM"
    );
    assert!(!bytes.contains(&b'\r'), "corpus text contains CR");
    assert_eq!(bytes.last(), Some(&b'\n'), "corpus text lacks terminal LF");
    String::from_utf8(bytes).expect("corpus text is not UTF-8")
}

fn safe_relative(value: &str) {
    assert!(!value.is_empty() && !value.starts_with('/'));
    assert!(!value.contains('\\'));
    assert!(
        value
            .split('/')
            .all(|component| !component.is_empty() && component != "." && component != "..")
    );
}

fn decode_hex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0, "hex length is odd");
    assert!(
        value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "hex is not lowercase"
    );
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let nibble = |byte: u8| match byte {
                b'0'..=b'9' => byte - b'0',
                b'a'..=b'f' => byte - b'a' + 10,
                _ => unreachable!(),
            };
            (nibble(pair[0]) << 4) | nibble(pair[1])
        })
        .collect()
}

fn decode_array_32(value: &str) -> [u8; 32] {
    decode_hex(value)
        .try_into()
        .expect("expected exactly 32 decoded bytes")
}

fn read_hex_file(path: &Path) -> Vec<u8> {
    let text = read_text(path);
    decode_hex(text.strip_suffix('\n').expect("hex file lacks terminal LF"))
}

fn parse_table(path: &Path, expected_header: &[&str]) -> Table {
    let text = read_text(path);
    let mut lines = text.lines();
    let header = lines.next().expect("table has no header");
    assert_eq!(header.split('\t').collect::<Vec<_>>(), expected_header);
    let mut rows = Vec::new();
    let mut prior_id: Option<String> = None;
    for line in lines {
        assert!(!line.is_empty(), "table contains an empty row");
        let fields = line.split('\t').map(str::to_owned).collect::<Vec<_>>();
        assert_eq!(
            fields.len(),
            expected_header.len(),
            "table row arity mismatch"
        );
        assert!(fields.iter().all(|field| !field.is_empty()));
        assert!(
            is_identifier(&fields[0]),
            "table identifier is not canonical"
        );
        if let Some(prior) = &prior_id {
            assert!(
                prior < &fields[0],
                "table identifiers are not strictly ordered"
            );
        }
        prior_id = Some(fields[0].clone());
        rows.push(fields);
    }
    assert!(!rows.is_empty(), "table has no rows");
    Table { rows }
}

fn parse_checksums(path: &Path) -> BTreeMap<String, String> {
    let text = read_text(path);
    let mut entries = BTreeMap::new();
    let mut prior: Option<String> = None;
    for line in text.lines() {
        assert!(line.len() >= 67 && &line[64..66] == "  ");
        let digest = &line[..64];
        let relative = &line[66..];
        assert!(is_lower_hash(digest));
        safe_relative(relative);
        assert_ne!(relative, "SHA256SUMS");
        if let Some(previous) = &prior {
            assert!(
                previous.as_str() < relative,
                "checksum paths are not ordered"
            );
        }
        prior = Some(relative.to_owned());
        assert!(
            entries
                .insert(relative.to_owned(), digest.to_owned())
                .is_none()
        );
    }
    assert!(!entries.is_empty());
    entries
}

fn collect_files(root: &Path, current: &Path, result: &mut BTreeSet<String>) {
    let mut entries = fs::read_dir(current)
        .unwrap_or_else(|_| panic!("corpus directory is absent: {}", current.display()))
        .collect::<Result<Vec<_>, _>>()
        .expect("corpus directory cannot be read");
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path).expect("corpus metadata is absent");
        assert!(
            !metadata.file_type().is_symlink(),
            "corpus contains a symlink"
        );
        if metadata.is_dir() {
            collect_files(root, &path, result);
        } else {
            assert!(metadata.is_file(), "corpus contains a non-file leaf");
            let relative = path
                .strip_prefix(root)
                .expect("corpus leaf escaped its root")
                .to_str()
                .expect("corpus path is not UTF-8")
                .replace(std::path::MAIN_SEPARATOR, "/");
            safe_relative(&relative);
            assert!(result.insert(relative), "duplicate corpus leaf");
        }
    }
}

fn validate_corpus_authority(root: &Path) {
    let id = read_text(&root.join("CORPUS_ID"));
    assert_eq!(id, format!("{CORPUS_ID}\n"));
    let parent_bytes = fs::read(root.join("SHA256SUMS")).expect("parent inventory is absent");
    let nested_bytes =
        fs::read(root.join("vectors/SHA256SUMS")).expect("nested inventory is absent");
    assert_eq!(sha256(&parent_bytes), PARENT_ROOT_SHA256);
    assert_eq!(sha256(&nested_bytes), NESTED_ROOT_SHA256);
    assert_eq!(
        read_text(&root.join("CORPUS_ROOT_SHA256")),
        format!("{PARENT_ROOT_SHA256}\n")
    );

    let parent = parse_checksums(&root.join("SHA256SUMS"));
    let nested = parse_checksums(&root.join("vectors/SHA256SUMS"));
    assert_eq!(parent.len(), 6);
    assert_eq!(nested.len(), 227);
    for (relative, expected) in &parent {
        assert_eq!(
            sha256(&fs::read(root.join(relative)).expect("parent corpus file is absent")),
            *expected
        );
    }
    for (relative, expected) in &nested {
        assert_eq!(
            sha256(
                &fs::read(root.join("vectors").join(relative))
                    .expect("nested corpus file is absent")
            ),
            *expected
        );
    }

    let mut expected_files = BTreeSet::new();
    expected_files.insert("SHA256SUMS".to_owned());
    expected_files.insert("CORPUS_ROOT_SHA256".to_owned());
    for relative in parent.keys() {
        expected_files.insert(relative.clone());
    }
    for relative in nested.keys() {
        expected_files.insert(format!("vectors/{relative}"));
    }
    let mut actual_files = BTreeSet::new();
    collect_files(root, root, &mut actual_files);
    assert_eq!(actual_files.len(), 235);
    assert_eq!(actual_files, expected_files);
    assert_eq!(
        sha256(&fs::read(root.join("vectors/CASES_V1.tsv")).expect("case table is absent")),
        CASES_SHA256
    );
}

fn optional_identifier(value: &str) -> Option<String> {
    if value == "-" {
        None
    } else {
        assert!(is_identifier(value));
        Some(value.to_owned())
    }
}

fn parse_cases(root: &Path) -> Vec<Case> {
    let table = parse_table(&root.join("vectors/CASES_V1.tsv"), CASES_HEADER);
    let mut cases = Vec::new();
    for row in table.rows {
        assert!(matches!(row[9].as_str(), "ok" | "error" | "lifecycle"));
        let expected_error_code = strict_u32(&row[10]);
        assert_eq!(row[9] == "error", expected_error_code != 0);
        assert!(is_lower_hash(&row[14]));
        assert!(is_lower_hash(&row[16]));
        let expected_output_sha256 = if row[15] == "-" {
            None
        } else {
            assert!(is_lower_hash(&row[15]));
            Some(row[15].clone())
        };
        let expected_source_epoch = decode_array_32(&row[7]);
        cases.push(Case {
            case_id: row[0].clone(),
            partition: row[1].clone(),
            operation: row[2].clone(),
            implementation: row[3].clone(),
            execution_class: row[4].clone(),
            frame_id: optional_identifier(&row[5]),
            source_model_id: optional_identifier(&row[6]),
            expected_source_epoch,
            catalog_fixture_id: optional_identifier(&row[8]),
            expected_result: row[9].clone(),
            expected_error_code,
            expected_reencode_frame_id: optional_identifier(&row[11]),
            expected_output_sha256,
        });
    }
    assert_eq!(cases.len(), 227);
    cases
}

fn parse_frames(root: &Path) -> BTreeMap<String, FrameEntry> {
    let table = parse_table(&root.join("vectors/FRAMES_V1.tsv"), FRAMES_HEADER);
    let mut frames = BTreeMap::new();
    for row in table.rows {
        safe_relative(&row[2]);
        assert!(row[2].starts_with("frames/") && row[2].ends_with(".hex"));
        assert!(is_lower_hash(&row[4]));
        assert!(
            frames
                .insert(
                    row[0].clone(),
                    FrameEntry {
                        relative_path: row[2].clone(),
                        decoded_length: strict_usize(&row[3]),
                        decoded_sha256: row[4].clone(),
                    },
                )
                .is_none()
        );
    }
    frames
}

fn parse_source_models(root: &Path) -> BTreeMap<String, SourceModelEntry> {
    let table = parse_table(
        &root.join("vectors/SOURCE_MODELS_V1.tsv"),
        SOURCE_MODELS_HEADER,
    );
    let mut models = BTreeMap::new();
    for row in table.rows {
        safe_relative(&row[4]);
        assert!(row[4].starts_with("source-models/") && row[4].ends_with(".json"));
        assert!(is_lower_hash(&row[6]));
        assert!(
            models
                .insert(
                    row[0].clone(),
                    SourceModelEntry {
                        partition: row[1].clone(),
                        operation: row[2].clone(),
                        execution_class: row[3].clone(),
                        relative_path: row[4].clone(),
                        decoded_length: strict_usize(&row[5]),
                        decoded_sha256: row[6].clone(),
                        expected_result: row[7].clone(),
                        expected_error_code: strict_u32(&row[8]),
                    },
                )
                .is_none()
        );
    }
    models
}

fn parse_fixtures(root: &Path) -> BTreeMap<String, FixtureEntry> {
    let table = parse_table(&root.join("vectors/FIXTURES_V1.tsv"), FIXTURES_HEADER);
    let mut fixtures = BTreeMap::new();
    for row in table.rows {
        safe_relative(&row[3]);
        assert!(row[3].starts_with("public/") && row[3].ends_with(".hex"));
        assert!(is_lower_hash(&row[5]));
        assert!(
            fixtures
                .insert(
                    row[0].clone(),
                    FixtureEntry {
                        relative_path: row[3].clone(),
                        decoded_length: strict_usize(&row[4]),
                        decoded_sha256: row[5].clone(),
                    },
                )
                .is_none()
        );
    }
    fixtures
}

fn parse_catalogs(root: &Path) -> BTreeMap<String, CatalogEntry> {
    let table = parse_table(&root.join("CATALOG_FIXTURES_V1.tsv"), CATALOGS_HEADER);
    let mut catalogs = BTreeMap::new();
    for row in table.rows {
        let network = match row[2].as_str() {
            "mainnet" => DescriptorNetwork::Mainnet,
            "test" => DescriptorNetwork::Test,
            _ => panic!("catalog network is not reviewed"),
        };
        assert!(
            catalogs
                .insert(
                    row[0].clone(),
                    CatalogEntry {
                        network,
                        last_index: strict_u32(&row[3]),
                        descriptor: row[4].clone(),
                    },
                )
                .is_none()
        );
    }
    assert_eq!(catalogs.len(), 2);
    catalogs
}

fn load_frame(root: &Path, frames: &BTreeMap<String, FrameEntry>, frame_id: &str) -> Vec<u8> {
    let entry = frames
        .get(frame_id)
        .unwrap_or_else(|| panic!("unknown frame {frame_id}"));
    let bytes = read_hex_file(&root.join("vectors").join(&entry.relative_path));
    assert_eq!(bytes.len(), entry.decoded_length);
    assert_eq!(sha256(&bytes), entry.decoded_sha256);
    bytes
}

fn load_fixture(
    root: &Path,
    fixtures: &BTreeMap<String, FixtureEntry>,
    fixture_id: &str,
) -> Vec<u8> {
    let entry = fixtures
        .get(fixture_id)
        .unwrap_or_else(|| panic!("unknown fixture {fixture_id}"));
    let bytes = read_hex_file(&root.join("vectors").join(&entry.relative_path));
    assert_eq!(bytes.len(), entry.decoded_length);
    assert_eq!(sha256(&bytes), entry.decoded_sha256);
    bytes
}

struct FrameScanner<'frame> {
    frame: &'frame [u8],
    cursor: usize,
}

impl<'frame> FrameScanner<'frame> {
    fn new(frame: &'frame [u8]) -> Self {
        Self { frame, cursor: 0 }
    }

    fn take(&mut self, length: usize) -> &'frame [u8] {
        let end = self
            .cursor
            .checked_add(length)
            .expect("frame offset overflow");
        let value = self
            .frame
            .get(self.cursor..end)
            .expect("frame is shorter than its independent scan");
        self.cursor = end;
        value
    }

    fn array<const LENGTH: usize>(&mut self) -> [u8; LENGTH] {
        self.take(LENGTH)
            .try_into()
            .expect("independent array width mismatch")
    }

    fn u16(&mut self) -> u16 {
        u16::from_le_bytes(self.array())
    }

    fn u32(&mut self) -> u32 {
        u32::from_le_bytes(self.array())
    }

    fn u64(&mut self) -> u64 {
        u64::from_le_bytes(self.array())
    }

    fn finish(self) {
        assert_eq!(
            self.cursor,
            self.frame.len(),
            "frame has an unscanned suffix"
        );
    }
}

fn scan_request(frame: &[u8]) -> RequestModel {
    let mut scanner = FrameScanner::new(frame);
    assert_eq!(scanner.take(4), b"WLPQ");
    assert_eq!(scanner.u16(), 1);
    assert_eq!(scanner.u16(), 152);
    assert_eq!(scanner.u64(), frame.len() as u64);
    assert_eq!(scanner.u32(), 0);
    assert_eq!(scanner.u32(), 0);
    let source_epoch = scanner.array();
    let source_revision = scanner.u64();
    let manifest_id = scanner.array();
    let pegged_asset = scanner.array();
    let selected_count = scanner.u32() as usize;
    let destination_count = scanner.u32() as usize;
    let aggregate_previous_count = scanner.u32() as usize;
    assert_eq!(scanner.u32(), 0);
    let explicit_fee_value = scanner.u64();

    let mut selected = Vec::with_capacity(selected_count);
    let mut observed_previous = 0usize;
    for _ in 0..selected_count {
        let transaction_id = scanner.array();
        let output_index = scanner.u32();
        let asset = scanner.array();
        let value = scanner.u64();
        let candidate_length = scanner.u32() as usize;
        let previous_count = scanner.u32() as usize;
        assert_eq!(scanner.u32(), 0);
        let candidate = scanner.take(candidate_length).to_vec();
        let mut previous = Vec::with_capacity(previous_count);
        for _ in 0..previous_count {
            let length = scanner.u32() as usize;
            previous.push(scanner.take(length).to_vec());
        }
        observed_previous = observed_previous
            .checked_add(previous.len())
            .expect("independent previous count overflow");
        selected.push(SelectedModel {
            transaction_id,
            output_index,
            asset,
            value,
            candidate,
            previous,
        });
    }

    let mut destinations = Vec::with_capacity(destination_count);
    for _ in 0..destination_count {
        let asset = scanner.array();
        let value = scanner.u64();
        let address_length = scanner.u32() as usize;
        assert_eq!(scanner.u32(), 0);
        destinations.push(DestinationModel {
            asset,
            value,
            address: scanner.take(address_length).to_vec(),
        });
    }
    scanner.finish();
    assert_eq!(observed_previous, aggregate_previous_count);
    RequestModel {
        source_epoch,
        source_revision,
        manifest_id,
        pegged_asset,
        selected,
        destinations,
        explicit_fee_value,
    }
}

fn read_source_model(
    root: &Path,
    models: &BTreeMap<String, SourceModelEntry>,
    model_id: &str,
) -> JsonValue {
    let entry = models
        .get(model_id)
        .unwrap_or_else(|| panic!("unknown source model {model_id}"));
    let bytes =
        fs::read(root.join("vectors").join(&entry.relative_path)).expect("source model is absent");
    assert_eq!(bytes.len(), entry.decoded_length);
    assert_eq!(sha256(&bytes), entry.decoded_sha256);
    assert_eq!(bytes.last(), Some(&b'\n'));
    assert!(!bytes.contains(&b'\r') && !bytes.starts_with(&[0xef, 0xbb, 0xbf]));
    let text = str::from_utf8(&bytes[..bytes.len() - 1]).expect("source model is not UTF-8");
    JsonParser::new(text).parse()
}

fn strict_json_usize(value: &JsonValue) -> usize {
    usize::try_from(value.as_u64()).expect("JSON integer exceeds usize")
}

fn bytes_value(value: &JsonValue) -> Vec<u8> {
    let JsonValue::Object(fields) = value else {
        panic!("byte source is not an object")
    };
    match JsonValue::get(fields, "kind").as_str() {
        "literal" => {
            value.object(&["hex", "kind"]);
            decode_hex(JsonValue::get(fields, "hex").as_str())
        }
        "repeat" => {
            value.object(&["byte_hex", "kind", "length"]);
            let byte = decode_hex(JsonValue::get(fields, "byte_hex").as_str());
            assert_eq!(byte.len(), 1, "repeat source is not one byte");
            vec![byte[0]; strict_json_usize(JsonValue::get(fields, "length"))]
        }
        _ => panic!("byte source kind is not reviewed"),
    }
}

fn fixed_bytes<const LENGTH: usize>(value: &JsonValue) -> [u8; LENGTH] {
    bytes_value(value)
        .try_into()
        .unwrap_or_else(|_| panic!("byte source has the wrong fixed width"))
}

fn indexed_mut<'model, T>(values: &'model mut [T], index: usize, path: &str) -> &'model mut T {
    values
        .get_mut(index)
        .unwrap_or_else(|| panic!("source-model path is out of range: {path}"))
}

fn apply_set_bytes(model: &mut RequestModel, path: &str, value: &JsonValue) {
    match path {
        "request.source_epoch" => model.source_epoch = fixed_bytes(value),
        "request.manifest" => model.manifest_id = fixed_bytes(value),
        "request.pegged_asset" => model.pegged_asset = fixed_bytes(value),
        "request.selected[0].txid" => {
            indexed_mut(&mut model.selected, 0, path).transaction_id = fixed_bytes(value);
        }
        "request.selected[0].asset" => {
            indexed_mut(&mut model.selected, 0, path).asset = fixed_bytes(value);
        }
        "request.selected[0].candidate" => {
            indexed_mut(&mut model.selected, 0, path).candidate = bytes_value(value);
        }
        "request.selected[1].candidate" => {
            indexed_mut(&mut model.selected, 1, path).candidate = bytes_value(value);
        }
        "request.selected[1].previous[7]" => {
            *indexed_mut(
                &mut indexed_mut(&mut model.selected, 1, path).previous,
                7,
                path,
            ) = bytes_value(value);
        }
        "request.destinations[0].asset" => {
            indexed_mut(&mut model.destinations, 0, path).asset = fixed_bytes(value);
        }
        "request.destinations[0].address" => {
            indexed_mut(&mut model.destinations, 0, path).address = bytes_value(value);
        }
        _ => panic!("set-bytes path is not reviewed: {path}"),
    }
}

fn apply_set_u64(model: &mut RequestModel, path: &str, value: u64) {
    match path {
        "request.selected[0].value" => {
            indexed_mut(&mut model.selected, 0, path).value = value;
        }
        "request.selected[0].vout" => {
            indexed_mut(&mut model.selected, 0, path).output_index =
                u32::try_from(value).expect("source-model vout exceeds u32");
        }
        "request.destinations[0].value" => {
            indexed_mut(&mut model.destinations, 0, path).value = value;
        }
        _ => panic!("set-u64 path is not reviewed: {path}"),
    }
}

fn apply_clear_list(model: &mut RequestModel, path: &str) {
    match path {
        "request.selected" => model.selected.clear(),
        "request.destinations" => model.destinations.clear(),
        "request.selected[0].previous" => {
            indexed_mut(&mut model.selected, 0, path).previous.clear();
        }
        "request.selected[1].previous" => {
            indexed_mut(&mut model.selected, 1, path).previous.clear();
        }
        _ => panic!("clear-list path is not reviewed: {path}"),
    }
}

fn fill_previous(
    root: &Path,
    fixtures: &BTreeMap<String, FixtureEntry>,
    fill: &JsonValue,
) -> Vec<u8> {
    let JsonValue::Object(fields) = fill else {
        panic!("previous-list fill is not an object")
    };
    match JsonValue::get(fields, "kind").as_str() {
        "fixture" => {
            fill.object(&["fixture_id", "kind"]);
            load_fixture(
                root,
                fixtures,
                JsonValue::get(fields, "fixture_id").as_str(),
            )
        }
        "repeat" => bytes_value(fill),
        _ => panic!("previous-list fill kind is not reviewed"),
    }
}

fn apply_resize_list(
    root: &Path,
    fixtures: &BTreeMap<String, FixtureEntry>,
    model: &mut RequestModel,
    path: &str,
    length: usize,
    fill: &JsonValue,
) {
    match path {
        "request.selected" => {
            let fields = fill.object(&["index", "kind"]);
            assert_eq!(JsonValue::get(fields, "kind").as_str(), "selected-copy");
            let index = strict_json_usize(JsonValue::get(fields, "index"));
            let source = indexed_mut(&mut model.selected, index, path).clone();
            model.selected.resize(length, source);
        }
        "request.destinations" => {
            let fields = fill.object(&["index", "kind"]);
            assert_eq!(JsonValue::get(fields, "kind").as_str(), "destination-copy");
            let index = strict_json_usize(JsonValue::get(fields, "index"));
            let source = indexed_mut(&mut model.destinations, index, path).clone();
            model.destinations.resize(length, source);
        }
        "request.selected[0].previous" => {
            let source = fill_previous(root, fixtures, fill);
            indexed_mut(&mut model.selected, 0, path)
                .previous
                .resize(length, source);
        }
        "request.selected[1].previous" => {
            let source = fill_previous(root, fixtures, fill);
            indexed_mut(&mut model.selected, 1, path)
                .previous
                .resize(length, source);
        }
        _ => panic!("resize-list path is not reviewed: {path}"),
    }
}

fn materialize_request(
    root: &Path,
    frames: &BTreeMap<String, FrameEntry>,
    models: &BTreeMap<String, SourceModelEntry>,
    fixtures: &BTreeMap<String, FixtureEntry>,
    model_id: &str,
) -> RequestModel {
    let source = read_source_model(root, models, model_id);
    let fields = source.object(&["operations", "root", "schema"]);
    assert_eq!(
        JsonValue::get(fields, "schema").as_str(),
        "wlpq-source-object-v1"
    );
    let root_fields = JsonValue::get(fields, "root").object(&["frame_id", "kind"]);
    assert_eq!(
        JsonValue::get(root_fields, "kind").as_str(),
        "request-from-frame"
    );
    let frame_id = JsonValue::get(root_fields, "frame_id").as_str();
    let mut model = scan_request(&load_frame(root, frames, frame_id));

    for operation in JsonValue::get(fields, "operations").as_array() {
        let JsonValue::Object(operation_fields) = operation else {
            panic!("source-model operation is not an object")
        };
        match JsonValue::get(operation_fields, "op").as_str() {
            "clear-list" => {
                operation.object(&["op", "path"]);
                apply_clear_list(
                    &mut model,
                    JsonValue::get(operation_fields, "path").as_str(),
                );
            }
            "set-bytes" => {
                operation.object(&["op", "path", "value"]);
                apply_set_bytes(
                    &mut model,
                    JsonValue::get(operation_fields, "path").as_str(),
                    JsonValue::get(operation_fields, "value"),
                );
            }
            "set-u64" => {
                operation.object(&["op", "path", "value"]);
                apply_set_u64(
                    &mut model,
                    JsonValue::get(operation_fields, "path").as_str(),
                    JsonValue::get(operation_fields, "value").as_u64(),
                );
            }
            "resize-list" => {
                operation.object(&["fill", "length", "op", "path"]);
                apply_resize_list(
                    root,
                    fixtures,
                    &mut model,
                    JsonValue::get(operation_fields, "path").as_str(),
                    strict_json_usize(JsonValue::get(operation_fields, "length")),
                    JsonValue::get(operation_fields, "fill"),
                );
            }
            _ => panic!("source-model operation is not reviewed"),
        }
    }
    model
}

fn encode_public(model: &RequestModel) -> Result<Vec<u8>, OrdinaryWalletPlanWireError> {
    let selected = model
        .selected
        .iter()
        .map(|entry| {
            OrdinaryWalletPlanSelectedRef::new(
                &entry.transaction_id,
                entry.output_index,
                &entry.asset,
                entry.value,
                &entry.candidate,
                &entry.previous,
            )
        })
        .collect::<Vec<_>>();
    let address_text = model
        .destinations
        .iter()
        .map(|entry| str::from_utf8(&entry.address).expect("public encode address is not UTF-8"))
        .collect::<Vec<_>>();
    let destinations = model
        .destinations
        .iter()
        .zip(address_text)
        .map(|(entry, address)| {
            OrdinaryWalletPlanDestinationRef::new(&entry.asset, entry.value, address)
        })
        .collect::<Vec<_>>();
    let request = OrdinaryWalletPlanRequestRef::new(
        &model.source_epoch,
        model.source_revision,
        &model.manifest_id,
        &model.pegged_asset,
        &selected,
        &destinations,
        model.explicit_fee_value,
    );
    encode_request(&request).map(|encoded| encoded.as_bytes().to_vec())
}

fn encode_private(model: &RequestModel) -> Result<Vec<u8>, OrdinaryWalletPlanWireError> {
    encode_view(model).map(|encoded| encoded.as_bytes().to_vec())
}

fn assert_expected_error<T>(result: Result<T, OrdinaryWalletPlanWireError>, case: &Case) {
    match result {
        Ok(_) => panic!("case unexpectedly succeeded: {}", case.case_id),
        Err(error) => assert_eq!(
            error.code(),
            case.expected_error_code,
            "wrong error code for {}",
            case.case_id
        ),
    }
}

fn validate_source_metadata(
    models: &BTreeMap<String, SourceModelEntry>,
    case: &Case,
    model_id: &str,
) {
    let model = models
        .get(model_id)
        .unwrap_or_else(|| panic!("unknown source model {model_id}"));
    assert_eq!(model.partition, case.partition);
    assert_eq!(model.operation, case.operation);
    assert_eq!(model.execution_class, case.execution_class);
    assert_eq!(model.expected_result, case.expected_result);
    assert_eq!(model.expected_error_code, case.expected_error_code);
}

fn replay_encode(
    root: &Path,
    frames: &BTreeMap<String, FrameEntry>,
    models: &BTreeMap<String, SourceModelEntry>,
    fixtures: &BTreeMap<String, FixtureEntry>,
    case: &Case,
    public_count: &mut usize,
    private_count: &mut usize,
) {
    let model_id = case
        .source_model_id
        .as_deref()
        .expect("encode case has no source model");
    validate_source_metadata(models, case, model_id);
    let model = materialize_request(root, frames, models, fixtures, model_id);
    let result = if case.case_id == "native-encode-non-ascii-address" {
        assert_eq!(*private_count, 0);
        assert!(
            model
                .destinations
                .iter()
                .any(|entry| str::from_utf8(&entry.address).is_err())
        );
        *private_count += 1;
        encode_private(&model)
    } else {
        assert!(
            model
                .destinations
                .iter()
                .all(|entry| str::from_utf8(&entry.address).is_ok())
        );
        *public_count += 1;
        encode_public(&model)
    };

    if case.expected_result == "error" {
        assert!(case.expected_output_sha256.is_none());
        assert!(case.expected_reencode_frame_id.is_none());
        assert_expected_error(result, case);
        return;
    }
    let encoded = result.unwrap_or_else(|error| {
        panic!(
            "case unexpectedly failed with code {}: {}",
            error.code(),
            case.case_id
        )
    });
    let expected_frame_id = case
        .expected_reencode_frame_id
        .as_deref()
        .expect("successful encode case has no expected frame");
    assert_eq!(encoded, load_frame(root, frames, expected_frame_id));
    assert_eq!(
        sha256(&encoded),
        case.expected_output_sha256
            .as_deref()
            .expect("successful encode case has no output hash")
    );
}

fn validate_outer_source_model(
    root: &Path,
    models: &BTreeMap<String, SourceModelEntry>,
    case: &Case,
) {
    let model_id = case
        .source_model_id
        .as_deref()
        .expect("generated decode case has no source model");
    validate_source_metadata(models, case, model_id);
    let source = read_source_model(root, models, model_id);
    let fields = source.object(&["operations", "root", "schema"]);
    assert!(JsonValue::get(fields, "operations").as_array().is_empty());
    assert_eq!(
        JsonValue::get(fields, "schema").as_str(),
        "wlpq-source-object-v1"
    );
    let root_fields = JsonValue::get(fields, "root").object(&[
        "frame_id",
        "kind",
        "read_poison",
        "virtual_length",
    ]);
    assert_eq!(
        JsonValue::get(root_fields, "frame_id").as_str(),
        "frame-test-toy-single"
    );
    assert_eq!(
        JsonValue::get(root_fields, "kind").as_str(),
        "decoder-input-from-frame"
    );
    assert!(JsonValue::get(root_fields, "read_poison").as_bool());
    assert_eq!(
        strict_json_usize(JsonValue::get(root_fields, "virtual_length")),
        OUTER_LIMIT_PLUS_ONE
    );
}

fn replay_decode(
    root: &Path,
    frames: &BTreeMap<String, FrameEntry>,
    models: &BTreeMap<String, SourceModelEntry>,
    case: &Case,
) {
    if case.execution_class == "deterministic-generated" {
        assert!(case.frame_id.is_none());
        validate_outer_source_model(root, models, case);
        let oversized = vec![0_u8; OUTER_LIMIT_PLUS_ONE];
        assert_expected_error(
            decode_request(&oversized, &case.expected_source_epoch),
            case,
        );
        return;
    }
    assert_eq!(case.execution_class, "concrete-frame");
    assert!(case.source_model_id.is_none());
    let frame = load_frame(
        root,
        frames,
        case.frame_id.as_deref().expect("decode case has no frame"),
    );
    let result = decode_request(&frame, &case.expected_source_epoch);
    if case.expected_result == "error" {
        assert_expected_error(result, case);
    } else {
        assert!(
            result.is_ok(),
            "decode case unexpectedly failed: {}",
            case.case_id
        );
    }
}

fn replay_reencode(root: &Path, frames: &BTreeMap<String, FrameEntry>, case: &Case) {
    let frame_id = case
        .frame_id
        .as_deref()
        .expect("reencode case has no frame");
    let frame = load_frame(root, frames, frame_id);
    let parsed = decode_request(&frame, &case.expected_source_epoch)
        .unwrap_or_else(|error| panic!("reencode decode failed with code {}", error.code()));
    let encoded = parsed
        .reencode()
        .unwrap_or_else(|error| panic!("reencode failed with code {}", error.code()));
    let expected = load_frame(
        root,
        frames,
        case.expected_reencode_frame_id
            .as_deref()
            .expect("reencode case has no expected frame"),
    );
    assert_eq!(encoded.as_bytes(), expected);
    assert_eq!(
        sha256(encoded.as_bytes()),
        case.expected_output_sha256
            .as_deref()
            .expect("reencode case has no output hash")
    );
}

fn replay_prepare(
    root: &Path,
    frames: &BTreeMap<String, FrameEntry>,
    catalogs: &BTreeMap<String, CatalogEntry>,
    secp: &Secp256k1<elements::secp256k1_zkp::All>,
    case: &Case,
) {
    let frame = load_frame(
        root,
        frames,
        case.frame_id.as_deref().expect("prepare case has no frame"),
    );
    let scanned = scan_request(&frame);
    let parsed = decode_request(&frame, &case.expected_source_epoch)
        .unwrap_or_else(|error| panic!("prepare decode failed with code {}", error.code()));
    let catalog_entry = catalogs
        .get(
            case.catalog_fixture_id
                .as_deref()
                .expect("prepare case has no catalog"),
        )
        .expect("prepare catalog is unknown");
    let catalog = DescriptorCatalog::derive(
        &catalog_entry.descriptor,
        catalog_entry.network,
        catalog_entry.last_index,
    )
    .expect("reviewed descriptor catalog is invalid");
    let result = parsed.prepare(&catalog, secp);
    if case.expected_result == "error" {
        assert_expected_error(result, case);
    } else {
        let prepared = result.unwrap_or_else(|error| {
            panic!(
                "prepare failed with code {}: {}",
                error.code(),
                case.case_id
            )
        });
        assert_eq!(prepared.source_revision(), scanned.source_revision);
        assert_eq!(prepared.selected_input_count(), scanned.selected.len());
        assert_eq!(
            prepared.confidential_destination_count(),
            scanned.destinations.len()
        );
    }
}

#[test]
fn production_corpus_replays_every_native_and_shared_case() {
    let root = corpus_root();
    validate_corpus_authority(&root);
    let cases = parse_cases(&root);
    let frames = parse_frames(&root);
    let models = parse_source_models(&root);
    let fixtures = parse_fixtures(&root);
    let catalogs = parse_catalogs(&root);
    let selected_partitions = BTreeMap::from([
        ("native-decoder", ("decode", "native", 99_usize)),
        ("native-prepare", ("prepare", "native", 26_usize)),
        ("native-raw-encoder", ("encode", "native", 34_usize)),
        ("native-reencode", ("reencode", "native", 28_usize)),
        ("shared-encoder", ("encode", "managed+native", 8_usize)),
    ]);
    let mut observed_counts = BTreeMap::<&str, usize>::new();
    let mut executed = BTreeSet::new();
    let mut public_encode_count = 0usize;
    let mut private_encode_count = 0usize;
    let secp = Secp256k1::new();

    for case in &cases {
        let Some((expected_operation, expected_implementation, _)) =
            selected_partitions.get(case.partition.as_str())
        else {
            continue;
        };
        assert_eq!(&case.operation, expected_operation);
        assert_eq!(&case.implementation, expected_implementation);
        assert!(executed.insert(case.case_id.clone()));
        *observed_counts.entry(&case.partition).or_default() += 1;
        match case.operation.as_str() {
            "encode" => replay_encode(
                &root,
                &frames,
                &models,
                &fixtures,
                case,
                &mut public_encode_count,
                &mut private_encode_count,
            ),
            "decode" => replay_decode(&root, &frames, &models, case),
            "reencode" => replay_reencode(&root, &frames, case),
            "prepare" => replay_prepare(&root, &frames, &catalogs, &secp, case),
            _ => unreachable!(),
        }
    }

    assert_eq!(executed.len(), 195);
    assert_eq!(public_encode_count, 41);
    assert_eq!(private_encode_count, 1);
    for (partition, (_, _, expected_count)) in selected_partitions {
        assert_eq!(observed_counts.get(partition), Some(&expected_count));
    }
}
