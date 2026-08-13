#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs::{self, File, Metadata};
use std::io::Read;
use std::path::{Path, PathBuf};

use elements::confidential::{RangeProof, SurjectionProof, Value};
use elements::encode::{deserialize, serialize};
use elements::hashes::sha256;
use elements::secp256k1_zkp::Secp256k1;
use elements::{Transaction, TxOut, VerificationError};

const CASES: [(&str, &str, &str, &str); 6] = [
    (
        "main-valid",
        "main-candidate-valid",
        "main-previous-valid",
        "ok",
    ),
    (
        "test-damaged-range-proof",
        "test-candidate-damaged-proof",
        "test-previous-valid",
        "range-proof-missing-0",
    ),
    (
        "test-explicit-selected-amount-proof-valid",
        "test-candidate-explicit",
        "test-previous-valid",
        "ok",
    ),
    (
        "test-shared-previous-valid",
        "test-candidate-shared-previous-valid",
        "test-previous-shared-valid",
        "ok",
    ),
    (
        "test-unowned-selected-amount-proof-valid",
        "test-candidate-unowned",
        "test-previous-valid",
        "ok",
    ),
    (
        "test-valid",
        "test-candidate-valid",
        "test-previous-valid",
        "ok",
    ),
];
const MAX_FIXTURE_BYTES: usize = 16 * 1024 * 1024;
const MAX_FIXTURE_TEXT_BYTES: usize = MAX_FIXTURE_BYTES * 2 + 1;

fn fail(message: &str) -> ! {
    eprintln!("ordinary-wallet-plan public proof verification failed: {message}");
    std::process::exit(1)
}

#[cfg(unix)]
fn same_file(left: &Metadata, right: &Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;

    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.mode() == right.mode()
        && left.len() == right.len()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
}

#[cfg(not(unix))]
fn same_file(left: &Metadata, right: &Metadata) -> bool {
    left.file_type() == right.file_type()
        && left.len() == right.len()
        && left.modified().ok() == right.modified().ok()
}

fn read_bounded_regular_with_hook<F: FnOnce()>(
    root: &Path,
    path: &Path,
    maximum: usize,
    after_open: F,
) -> Result<Vec<u8>, ()> {
    if !root.is_absolute() || !path.is_absolute() || !path.starts_with(root) {
        return Err(());
    }
    for ancestor in path.ancestors() {
        if ancestor == path {
            continue;
        }
        let metadata = fs::symlink_metadata(ancestor).map_err(|_| ())?;
        if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
            return Err(());
        }
        if ancestor == root {
            break;
        }
    }
    let before = fs::symlink_metadata(path).map_err(|_| ())?;
    if !before.file_type().is_file()
        || before.file_type().is_symlink()
        || before.len() > maximum as u64
    {
        return Err(());
    }
    let mut file = File::open(path).map_err(|_| ())?;
    let opened = file.metadata().map_err(|_| ())?;
    if !opened.file_type().is_file() || !same_file(&before, &opened) {
        return Err(());
    }
    after_open();
    let mut bytes = Vec::with_capacity(opened.len() as usize);
    file.by_ref()
        .take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ())?;
    let after_handle = file.metadata().map_err(|_| ())?;
    let after_path = fs::symlink_metadata(path).map_err(|_| ())?;
    if bytes.len() > maximum
        || bytes.len() as u64 != opened.len()
        || !same_file(&opened, &after_handle)
        || !same_file(&opened, &after_path)
    {
        return Err(());
    }
    Ok(bytes)
}

fn read_bounded_regular(root: &Path, path: &Path, maximum: usize) -> Result<Vec<u8>, ()> {
    read_bounded_regular_with_hook(root, path, maximum, || {})
}

fn expected_fixture(fixture_id: &str) -> (usize, &'static str) {
    match fixture_id {
        "main-candidate-valid" => (
            4469,
            "f291d881656e2de6936ebe0b1cac2040da2aa088120b5ad700498fbb024fe34b",
        ),
        "main-previous-valid" => (
            56,
            "cdf49000ca25b1a40510b3794436b1cf0d7719049811195c80908dfb90a596c4",
        ),
        "test-candidate-damaged-proof" => (
            293,
            "9f7e91ec80d8ad974815799d56368e59bd824a5544d5076d7f0f774a1024c26d",
        ),
        "test-candidate-explicit" => (
            162,
            "5004e84efc55b2b3e8e25f78e9e437982321733419eed90bc6724dd268852160",
        ),
        "test-candidate-shared-previous-valid" => (
            4546,
            "63cb436487c562edd2084af3d1fa4093c169606740639534405707daab216adf",
        ),
        "test-candidate-unowned" => (
            4469,
            "4703f1c23c4ca005f2b765de08afdbd7a9e4000d9c769bc429926567ad1b6252",
        ),
        "test-candidate-valid" => (
            4469,
            "c6c96d3455902b91dbe2dbfe0029946a7a80ca45148b29564026df849416ab6b",
        ),
        "test-previous-shared-valid" => (
            101,
            "4c51a49ec419b32695a7334dd1e523592d577ecfd013a3a67427660d629ed84a",
        ),
        "test-previous-unrelated" => (
            56,
            "6ae4041c8395b5ed17e54af5b7b7219f3a4358afe89fb53832b0c1c2f568c049",
        ),
        "test-previous-valid" => (
            56,
            "4850b5ae65f9edd5a054e8dc6ba1e405bb5bee67905cbc6af2e4ec6f2cc96cb2",
        ),
        _ => fail("fixture identifier is outside exact verifier authority"),
    }
}

fn parse_hex_fixture(root: &Path, path: &Path, fixture_id: &str) -> Transaction {
    let (expected_length, expected_digest) = expected_fixture(fixture_id);
    let bytes = read_bounded_regular(root, path, MAX_FIXTURE_TEXT_BYTES)
        .unwrap_or_else(|_| fail("fixture bounded regular-file read failed"));
    let text = std::str::from_utf8(&bytes).unwrap_or_else(|_| fail("fixture text is not UTF-8"));
    if text.starts_with('\u{feff}')
        || text.contains('\r')
        || !text.ends_with('\n')
        || text.matches('\n').count() != 1
    {
        fail("fixture text is not canonical LF");
    }
    let hex = &text[..text.len() - 1];
    if hex.is_empty()
        || !hex.len().is_multiple_of(2)
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        fail("fixture is not canonical lowercase hex");
    }
    if hex.len() / 2 > MAX_FIXTURE_BYTES {
        fail("fixture exceeds public verifier bound");
    }
    let bytes = hex
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect::<Vec<_>>();
    if bytes.len() != expected_length || sha256::Hash::hash(&bytes).to_string() != expected_digest {
        fail("fixture length or digest differs from exact verifier authority");
    }
    let transaction: Transaction =
        deserialize(&bytes).unwrap_or_else(|_| fail("fixture transaction decode failed"));
    if serialize(&transaction) != bytes {
        fail("fixture transaction is not a canonical roundtrip");
    }
    transaction
}

fn ordered_previous_outputs(
    candidate: &Transaction,
    previous: &[Transaction],
) -> Result<Vec<TxOut>, &'static str> {
    if candidate.input.is_empty()
        || candidate
            .input
            .iter()
            .any(|input| input.previous_output.is_null())
    {
        return Err("empty or coinbase candidate");
    }
    if candidate.input.iter().any(elements::TxIn::has_issuance)
        || candidate.input.iter().any(elements::TxIn::is_pegin)
    {
        return Err("issuance or peg-in candidate");
    }
    let mut input_outpoints = BTreeSet::new();
    if candidate
        .input
        .iter()
        .any(|input| !input_outpoints.insert(input.previous_output))
    {
        return Err("duplicate candidate input");
    }
    let mut by_txid = BTreeMap::new();
    for transaction in previous {
        if by_txid.insert(transaction.txid(), transaction).is_some() {
            return Err("duplicate previous transaction identity");
        }
    }
    let needed_txids = candidate
        .input
        .iter()
        .map(|input| input.previous_output.txid)
        .collect::<BTreeSet<_>>();
    if by_txid.keys().copied().collect::<BTreeSet<_>>() != needed_txids {
        return Err("missing, unrelated, or surplus previous transaction");
    }
    let mut used = BTreeSet::new();
    let mut outputs = Vec::with_capacity(candidate.input.len());
    for input in &candidate.input {
        let transaction = by_txid
            .get(&input.previous_output.txid)
            .ok_or("unrelated previous transaction")?;
        let output = transaction
            .output
            .get(input.previous_output.vout as usize)
            .ok_or("previous output index out of range")?;
        used.insert(input.previous_output.txid);
        outputs.push(output.clone());
    }
    if used != needed_txids {
        return Err("surplus previous transaction");
    }
    Ok(outputs)
}

fn verify(candidate: &Transaction, previous: &[Transaction]) -> Result<(), VerificationError> {
    let previous_outputs = ordered_previous_outputs(candidate, previous)
        .map_err(|_| VerificationError::UtxoInputLenMismatch)?;
    candidate.verify_tx_amt_proofs(&Secp256k1::new(), &previous_outputs)
}

fn validate_case_table(root: &Path, vectors: &Path) {
    let expected = format!(
        "proof_case_id\tcandidate_fixture_id\tprevious_fixture_id\texpected_result\n{}",
        CASES
            .iter()
            .map(|row| format!("{}\t{}\t{}\t{}\n", row.0, row.1, row.2, row.3))
            .collect::<String>()
    );
    let bytes = read_bounded_regular(
        root,
        &vectors.join("PUBLIC_PROOF_CASES_V1.tsv"),
        expected.len(),
    )
    .unwrap_or_else(|_| fail("proof case table bounded regular-file read failed"));
    if bytes != expected.as_bytes() {
        fail("proof case table differs from exact verifier authority");
    }
}

fn verify_mutations(
    valid: &Transaction,
    previous: &Transaction,
    unrelated: &Transaction,
    foreign: &Transaction,
    shared: &Transaction,
    shared_previous: &Transaction,
) {
    let mut missing_range = valid.clone();
    missing_range.output[0].witness.rangeproof = RangeProof::EMPTY;
    assert!(matches!(
        verify(&missing_range, std::slice::from_ref(previous)),
        Err(VerificationError::RangeProofMissing(0))
    ));

    let mut missing_surjection = valid.clone();
    missing_surjection.output[0].witness.surjection_proof = SurjectionProof::EMPTY;
    assert!(matches!(
        verify(&missing_surjection, std::slice::from_ref(previous)),
        Err(VerificationError::SurjectionProofMissing(0))
    ));

    let mut substituted_range = valid.clone();
    substituted_range.output[0].witness.rangeproof = foreign.output[0].witness.rangeproof.clone();
    assert!(verify(&substituted_range, std::slice::from_ref(previous)).is_err());

    let mut substituted_surjection = valid.clone();
    substituted_surjection.output[0].witness.surjection_proof =
        foreign.output[0].witness.surjection_proof.clone();
    assert!(verify(&substituted_surjection, std::slice::from_ref(previous)).is_err());

    let mut script = valid.clone();
    let mut script_bytes = script.output[0].script_pubkey.as_bytes().to_vec();
    script_bytes.push(elements::opcodes::all::OP_NOP.into_u8());
    script.output[0].script_pubkey = elements::Script::from(script_bytes);
    assert!(verify(&script, std::slice::from_ref(previous)).is_err());

    let mut fee = valid.clone();
    let Value::Explicit(value) = fee.output[1].value else {
        fail("reviewed fee output is not explicit")
    };
    fee.output[1].value = Value::Explicit(value + 1);
    assert!(verify(&fee, std::slice::from_ref(previous)).is_err());

    assert!(ordered_previous_outputs(valid, &[]).is_err());
    assert!(ordered_previous_outputs(valid, &[previous.clone(), unrelated.clone()]).is_err());
    assert!(ordered_previous_outputs(valid, std::slice::from_ref(unrelated)).is_err());
    assert!(ordered_previous_outputs(valid, &[previous.clone(), previous.clone()]).is_err());

    assert!(verify(shared, std::slice::from_ref(shared_previous)).is_ok());
    assert!(
        ordered_previous_outputs(shared, &[shared_previous.clone(), shared_previous.clone()])
            .is_err()
    );
    assert!(ordered_previous_outputs(shared, &[]).is_err());
    assert!(
        ordered_previous_outputs(shared, &[shared_previous.clone(), unrelated.clone()]).is_err()
    );
    let mut missing_vout = shared.clone();
    missing_vout.input[1].previous_output.vout = shared_previous.output.len() as u32;
    assert!(
        ordered_previous_outputs(&missing_vout, std::slice::from_ref(shared_previous)).is_err()
    );
    let mut duplicate_outpoint = shared.clone();
    duplicate_outpoint.input[1].previous_output = duplicate_outpoint.input[0].previous_output;
    assert!(
        ordered_previous_outputs(&duplicate_outpoint, std::slice::from_ref(shared_previous))
            .is_err()
    );

    let mut two_input = valid.clone();
    let mut second_input = valid.input[0].clone();
    second_input.previous_output.txid = unrelated.txid();
    second_input.previous_output.vout = 0;
    two_input.input.push(second_input);
    let canonical = ordered_previous_outputs(&two_input, &[previous.clone(), unrelated.clone()])
        .expect("two-input resolver fixture is valid");
    let reordered = ordered_previous_outputs(&two_input, &[unrelated.clone(), previous.clone()])
        .expect("previous transaction order must not affect input-order resolution");
    assert_eq!(serialize(&canonical), serialize(&reordered));

    let mut corrupted = valid.output[0].witness.rangeproof.to_vec();
    let mut observed_invalid = false;
    for offset in (0..corrupted.len()).rev().take(64) {
        corrupted[offset] ^= 1;
        if let Ok(proof) = RangeProof::from_slice(&corrupted) {
            let mut candidate = valid.clone();
            candidate.output[0].witness.rangeproof = proof;
            if verify(&candidate, std::slice::from_ref(previous)).is_err() {
                observed_invalid = true;
                break;
            }
        }
        corrupted[offset] ^= 1;
    }
    assert!(
        observed_invalid,
        "length-preserving proof corruption was not rejected"
    );
}

fn main() {
    let mut arguments = env::args_os();
    let _program = arguments.next();
    let root = arguments
        .next()
        .map(PathBuf::from)
        .unwrap_or_else(|| fail("absolute repository root argument is required"));
    if arguments.next().is_some() || !root.is_absolute() {
        fail("exactly one absolute repository root argument is required");
    }
    let vectors = root.join("contracts/ordinary-wallet-plan/v1/nonlinkable-reference/vectors");
    validate_case_table(&root, &vectors);
    let public = vectors.join("public");
    for (_, candidate_id, previous_id, expected) in CASES {
        let candidate = parse_hex_fixture(
            &root,
            &public.join(format!("{candidate_id}.hex")),
            candidate_id,
        );
        let previous = parse_hex_fixture(
            &root,
            &public.join(format!("{previous_id}.hex")),
            previous_id,
        );
        let result = verify(&candidate, std::slice::from_ref(&previous));
        match expected {
            "ok" if result.is_ok() => {}
            "range-proof-missing-0"
                if matches!(result, Err(VerificationError::RangeProofMissing(0))) => {}
            _ => fail("public proof case result mismatch"),
        }
    }
    let valid = parse_hex_fixture(
        &root,
        &public.join("test-candidate-valid.hex"),
        "test-candidate-valid",
    );
    let damaged = parse_hex_fixture(
        &root,
        &public.join("test-candidate-damaged-proof.hex"),
        "test-candidate-damaged-proof",
    );
    if valid.txid() != damaged.txid() || serialize(&valid) == serialize(&damaged) {
        fail("valid and damaged fixture identity relation mismatch");
    }
    let previous = parse_hex_fixture(
        &root,
        &public.join("test-previous-valid.hex"),
        "test-previous-valid",
    );
    let unrelated = parse_hex_fixture(
        &root,
        &public.join("test-previous-unrelated.hex"),
        "test-previous-unrelated",
    );
    let foreign = parse_hex_fixture(
        &root,
        &public.join("main-candidate-valid.hex"),
        "main-candidate-valid",
    );
    let shared = parse_hex_fixture(
        &root,
        &public.join("test-candidate-shared-previous-valid.hex"),
        "test-candidate-shared-previous-valid",
    );
    let shared_previous = parse_hex_fixture(
        &root,
        &public.join("test-previous-shared-valid.hex"),
        "test-previous-shared-valid",
    );
    verify_mutations(
        &valid,
        &previous,
        &unrelated,
        &foreign,
        &shared,
        &shared_previous,
    );
    println!("ordinary-wallet-plan public proof fixtures accepted: 6");
}

#[cfg(test)]
mod tests {
    use super::read_bounded_regular_with_hook;
    use std::fs::{self, OpenOptions};
    use std::io::Write;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static SCRATCH_ID: AtomicUsize = AtomicUsize::new(0);

    struct Scratch(PathBuf);

    impl Scratch {
        fn new() -> Self {
            let id = SCRATCH_ID.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "ordinary-wallet-plan-proof-reader-{}-{id}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("scratch directory");
            Self(path)
        }

        fn path(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).expect("scratch cleanup");
        }
    }

    fn write(path: &Path, bytes: &[u8]) {
        fs::write(path, bytes).expect("scratch fixture write");
    }

    #[test]
    fn bounded_reader_rejects_oversize_and_nonregular_inputs() {
        let scratch = Scratch::new();
        let oversized = scratch.path("oversized");
        write(&oversized, b"12345");
        assert!(read_bounded_regular_with_hook(&scratch.0, &oversized, 4, || {}).is_err());

        let directory = scratch.path("directory");
        fs::create_dir(&directory).expect("nonregular fixture");
        assert!(read_bounded_regular_with_hook(&scratch.0, &directory, 4, || {}).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn bounded_reader_rejects_symlinks() {
        use std::os::unix::fs::symlink;

        let scratch = Scratch::new();
        let target = scratch.path("target");
        let link = scratch.path("link");
        write(&target, b"data");
        symlink(&target, &link).expect("fixture symlink");
        assert!(read_bounded_regular_with_hook(&scratch.0, &link, 4, || {}).is_err());

        let directory = scratch.path("directory");
        let directory_target = scratch.path("directory-target");
        fs::create_dir(&directory_target).expect("ancestor target");
        let nested = directory_target.join("fixture");
        write(&nested, b"data");
        symlink(&directory_target, &directory).expect("ancestor symlink");
        assert!(
            read_bounded_regular_with_hook(&scratch.0, &directory.join("fixture"), 4, || {})
                .is_err()
        );
    }

    #[test]
    fn bounded_reader_rejects_growth_after_open() {
        let scratch = Scratch::new();
        let path = scratch.path("growing");
        write(&path, b"data");
        assert!(
            read_bounded_regular_with_hook(&scratch.0, &path, 8, || {
                OpenOptions::new()
                    .append(true)
                    .open(&path)
                    .and_then(|mut file| file.write_all(b"more"))
                    .expect("grow fixture after open");
            })
            .is_err()
        );
    }
}
