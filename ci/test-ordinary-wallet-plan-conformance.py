#!/usr/bin/env python3
"""Mutation-test the read-only WLPQ v1 corpus checker."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CHECKER = ROOT / "ci/check-ordinary-wallet-plan-conformance.py"
REFERENCE = Path("contracts/ordinary-wallet-plan/v1/nonlinkable-reference")
VECTORS = REFERENCE / "vectors"


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(root: Path, success: bool, *, semantic: bool = False) -> subprocess.CompletedProcess[str]:
    if semantic:
        program = (
            "import importlib.util,pathlib,sys;"
            f"p=pathlib.Path({str(CHECKER)!r});"
            "s=importlib.util.spec_from_file_location('wlpq_checker',p);"
            "m=importlib.util.module_from_spec(s);s.loader.exec_module(m);"
            "m.run(pathlib.Path(sys.argv[1]).absolute(),enforce_reviewed_roots=False)"
        )
        command = [sys.executable, "-c", program, str(root.absolute())]
    else:
        command = [sys.executable, str(CHECKER), str(root.absolute())]
    result = subprocess.run(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
        env={"PATH": os.environ.get("PATH", "")},
    )
    if (result.returncode == 0) != success:
        raise AssertionError(
            f"unexpected checker result {result.returncode}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    return result


def reclose(root: Path) -> None:
    reference = root / REFERENCE
    vectors = root / VECTORS
    nested_files = sorted(path for path in vectors.rglob("*") if path.is_file() and path.name != "SHA256SUMS")
    (vectors / "SHA256SUMS").write_text(
        "".join(f"{sha(path)}  {path.relative_to(vectors).as_posix()}\n" for path in nested_files),
        encoding="utf-8",
        newline="\n",
    )
    parent_files = sorted(
        path
        for path in reference.iterdir()
        if path.is_file() and path.name not in ("SHA256SUMS", "CORPUS_ROOT_SHA256")
    )
    rows = [(path.name, sha(path)) for path in parent_files]
    rows.append(("vectors/SHA256SUMS", sha(vectors / "SHA256SUMS")))
    (reference / "SHA256SUMS").write_text(
        "".join(f"{checksum}  {relative}\n" for relative, checksum in sorted(rows)),
        encoding="utf-8",
        newline="\n",
    )
    (reference / "CORPUS_ROOT_SHA256").write_text(
        sha(reference / "SHA256SUMS") + "\n",
        encoding="utf-8",
        newline="\n",
    )


def replace(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    if text.count(old) != 1:
        raise AssertionError(f"mutation source is not singular: {old}")
    path.write_text(text.replace(old, new), encoding="utf-8", newline="\n")


def replace_tsv_cell(path: Path, row_id: str, column: str, value: str) -> None:
    lines = path.read_text(encoding="utf-8").splitlines()
    header = lines[0].split("\t")
    index = header.index(column)
    matches = 0
    for line_index in range(1, len(lines)):
        fields = lines[line_index].split("\t")
        if fields[0] == row_id:
            fields[index] = value
            lines[line_index] = "\t".join(fields)
            matches += 1
    if matches != 1:
        raise AssertionError(f"TSV mutation row is not singular: {row_id}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")


def replace_tsv_cell_where(path: Path, matches: dict[str, str], column: str, value: str) -> None:
    lines = path.read_text(encoding="utf-8").splitlines()
    header = lines[0].split("\t")
    index = header.index(column)
    match_indexes = {header.index(name): expected for name, expected in matches.items()}
    count = 0
    for line_index in range(1, len(lines)):
        fields = lines[line_index].split("\t")
        if all(fields[field_index] == expected for field_index, expected in match_indexes.items()):
            fields[index] = value
            lines[line_index] = "\t".join(fields)
            count += 1
    if count != 1:
        raise AssertionError(f"TSV mutation selector is not singular: {matches}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")


def replace_tsv_cells(path: Path, row_id: str, replacements: dict[str, str]) -> None:
    lines = path.read_text(encoding="utf-8").splitlines()
    header = lines[0].split("\t")
    indexes = {header.index(column): value for column, value in replacements.items()}
    matches = 0
    for line_index in range(1, len(lines)):
        fields = lines[line_index].split("\t")
        if fields[0] == row_id:
            for index, value in indexes.items():
                fields[index] = value
            lines[line_index] = "\t".join(fields)
            matches += 1
    if matches != 1:
        raise AssertionError(f"TSV mutation row is not singular: {row_id}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")


def swap_tsv_cells(path: Path, left_id: str, right_id: str, column: str) -> None:
    lines = path.read_text(encoding="utf-8").splitlines()
    header = lines[0].split("\t")
    index = header.index(column)
    positions = {fields[0]: line_index for line_index, line in enumerate(lines[1:], 1) if (fields := line.split("\t"))[0] in (left_id, right_id)}
    if set(positions) != {left_id, right_id}:
        raise AssertionError("TSV swap rows are not singular")
    left = lines[positions[left_id]].split("\t"); right = lines[positions[right_id]].split("\t")
    left[index], right[index] = right[index], left[index]
    lines[positions[left_id]] = "\t".join(left); lines[positions[right_id]] = "\t".join(right)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")


def mutate_json(path: Path, action) -> None:
    value = json.loads(path.read_text(encoding="utf-8"))
    action(value)
    path.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8", newline="\n")


def mutate_source_object(root: Path, model_id: str, action) -> None:
    path = root / VECTORS / f"source-models/{model_id}.json"
    mutate_json(path, action)
    replace_tsv_cells(
        root / VECTORS / "SOURCE_MODELS_V1.tsv",
        model_id,
        {"decoded_length": str(path.stat().st_size), "decoded_sha256": sha(path)},
    )


def swap_source_objects(root: Path, left_id: str, right_id: str) -> None:
    left = root / VECTORS / f"source-models/{left_id}.json"
    right = root / VECTORS / f"source-models/{right_id}.json"
    left_data, right_data = left.read_bytes(), right.read_bytes()
    left.write_bytes(right_data); right.write_bytes(left_data)
    replace_tsv_cells(root / VECTORS / "SOURCE_MODELS_V1.tsv", left_id, {"decoded_length": str(len(right_data)), "decoded_sha256": hashlib.sha256(right_data).hexdigest()})
    replace_tsv_cells(root / VECTORS / "SOURCE_MODELS_V1.tsv", right_id, {"decoded_length": str(len(left_data)), "decoded_sha256": hashlib.sha256(left_data).hexdigest()})


def copy_frame_payload_and_metadata(root: Path, source_id: str, target_id: str) -> None:
    vectors = root / VECTORS
    source_path = vectors / f"frames/{source_id}.hex"
    target_path = vectors / f"frames/{target_id}.hex"
    target_path.write_bytes(source_path.read_bytes())
    table = vectors / "FRAMES_V1.tsv"
    lines = table.read_text(encoding="utf-8").splitlines()
    header = lines[0].split("\t")
    source = next(line.split("\t") for line in lines[1:] if line.split("\t")[0] == source_id)
    target_index = next(index for index, line in enumerate(lines[1:], 1) if line.split("\t")[0] == target_id)
    target = lines[target_index].split("\t")
    preserved = {"frame_id", "relative_path"}
    for index, name in enumerate(header):
        if name not in preserved:
            target[index] = source[index]
    lines[target_index] = "\t".join(target)
    table.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")


def add_orphan_frame(root: Path) -> None:
    vectors = root / VECTORS
    shutil.copyfile(vectors / "frames/frame-test-toy-single.hex", vectors / "frames/frame-orphan.hex")
    duplicate_tsv_row(vectors / "FRAMES_V1.tsv", "frame-test-toy-single", "frame-orphan")
    replace_tsv_cell(vectors / "FRAMES_V1.tsv", "frame-orphan", "relative_path", "frames/frame-orphan.hex")


def remove_tsv_row(path: Path, row_id: str) -> None:
    lines = path.read_text(encoding="utf-8").splitlines()
    kept = [lines[0], *(line for line in lines[1:] if line.split("\t", 1)[0] != row_id)]
    if len(kept) != len(lines) - 1:
        raise AssertionError(f"TSV removal row is not singular: {row_id}")
    path.write_text("\n".join(kept) + "\n", encoding="utf-8", newline="\n")


def duplicate_tsv_row(path: Path, row_id: str, new_id: str) -> None:
    lines = path.read_text(encoding="utf-8").splitlines()
    row = next((line for line in lines[1:] if line.split("\t", 1)[0] == row_id), None)
    if row is None:
        raise AssertionError(f"TSV duplicate row is absent: {row_id}")
    lines.append(new_id + "\t" + row.split("\t", 1)[1])
    header = lines[0]
    lines = [header, *sorted(lines[1:])]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")


def flip_first_byte(path: Path) -> None:
    data = bytearray(path.read_bytes())
    data[0] = ord("1") if data[0] != ord("1") else ord("0")
    path.write_bytes(data)


def replace_intermediate_corpus_directory_with_symlink(root: Path) -> None:
    path = root / "contracts/ordinary-wallet-plan"
    target = root / "external-ordinary-wallet-plan"
    path.rename(target)
    os.symlink(target, path, target_is_directory=True)


def replace_repository_root_with_symlink(root: Path) -> None:
    target = root.with_name(f"{root.name}-target")
    root.rename(target)
    os.symlink(target, root, target_is_directory=True)


def copy_mutable_tree(source: Path, destination: Path) -> None:
    source_metadata = os.lstat(source)
    if stat.S_ISLNK(source_metadata.st_mode) or not stat.S_ISDIR(source_metadata.st_mode):
        raise AssertionError("mutable corpus copy source root is linked or not a directory")
    shutil.copytree(source, destination, symlinks=True)
    for directory, directories, files in os.walk(
        destination,
        topdown=False,
        followlinks=False,
    ):
        directory_path = Path(directory)
        for name in files:
            path = directory_path / name
            metadata = os.lstat(path)
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
                raise AssertionError("mutable corpus copy contains a linked or special file")
            os.chmod(path, 0o600)
        for name in directories:
            path = directory_path / name
            metadata = os.lstat(path)
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
                raise AssertionError("mutable corpus copy contains a linked or non-directory entry")
            os.chmod(path, 0o700)
        os.chmod(directory_path, 0o700)


def copy_mutable_contracts(target: Path) -> None:
    copy_mutable_tree(ROOT / "contracts", target / "contracts")


def test_mutable_copy_modes(scratch: Path) -> None:
    source = scratch / "mutable-copy-source"
    nested = source / "nested"
    nested.mkdir(parents=True)
    source_file = nested / "fixture"
    source_file.write_text("sealed\n", encoding="utf-8", newline="\n")
    os.chmod(source_file, 0o444)
    os.chmod(nested, 0o555)
    os.chmod(source, 0o555)
    try:
        destination = scratch / "mutable-copy-destination"
        copy_mutable_tree(source, destination)
        destination_file = destination / "nested/fixture"
        if (
            stat.S_IMODE(os.lstat(source).st_mode) != 0o555
            or stat.S_IMODE(os.lstat(nested).st_mode) != 0o555
            or stat.S_IMODE(os.lstat(source_file).st_mode) != 0o444
            or stat.S_IMODE(os.lstat(destination).st_mode) != 0o700
            or stat.S_IMODE(os.lstat(destination / "nested").st_mode) != 0o700
            or stat.S_IMODE(os.lstat(destination_file).st_mode) != 0o600
        ):
            raise AssertionError("mutable corpus copy modes differ from exact authority")
        destination_file.write_text("changed\n", encoding="utf-8", newline="\n")
        created = destination / "nested/created"
        created.write_text("created\n", encoding="utf-8", newline="\n")
        created.unlink()

        for name, directory_link in (("file-link", False), ("directory-link", True)):
            linked_source = scratch / f"mutable-copy-{name}-source"
            linked_source.mkdir()
            linked_target = linked_source / "target"
            if directory_link:
                linked_target.mkdir()
            else:
                linked_target.write_text("target\n", encoding="utf-8", newline="\n")
            os.symlink(linked_target, linked_source / "linked", target_is_directory=directory_link)
            try:
                copy_mutable_tree(linked_source, scratch / f"mutable-copy-{name}-destination")
            except AssertionError as error:
                if "mutable corpus copy contains a linked" not in str(error):
                    raise
            else:
                raise AssertionError(f"mutable corpus copy accepted a {name}")
    finally:
        os.chmod(source, 0o700)
        os.chmod(nested, 0o700)


def mutate(scratch: Path, name: str, action, *, close: bool = True, expected_error: str | None = None) -> None:
    target = scratch / name
    copy_mutable_contracts(target)
    action(target)
    if close:
        reclose(target)
    result = run(target, False, semantic=True)
    if expected_error is not None and expected_error not in result.stderr:
        raise AssertionError(
            f"mutation {name} did not reach its semantic validator\nstderr:\n{result.stderr}"
        )


def load_checker():
    specification = importlib.util.spec_from_file_location("wlpq_checker_tests", CHECKER)
    if specification is None or specification.loader is None:
        raise AssertionError("ordinary-wallet-plan checker import failed")
    checker = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(checker)
    return checker


def expect_scanner_error(checker, data: bytes, expected: str) -> None:
    for entrypoint in (checker.elements_txid, checker.parse_public_transaction):
        try:
            entrypoint(data)
        except checker.CorpusError as error:
            if expected not in str(error):
                raise AssertionError(f"unexpected scanner error: {error}") from error
        else:
            raise AssertionError(f"transaction scanner accepted {expected}")


def test_transaction_scanner_guards(checker) -> None:
    fixture = bytes.fromhex(
        (ROOT / VECTORS / "public/test-candidate-valid.hex").read_text(encoding="utf-8").strip()
    )
    if fixture[4:6] != b"\x01\x01" or int.from_bytes(fixture[38:42], "little") != 0:
        raise AssertionError("scanner mutation fixture layout changed")

    for name, flag, expected in (
        ("issuance", 0x80000000, "asset issuance"),
        ("peg-in", 0x40000000, "peg-in input"),
    ):
        mutated = bytearray(fixture)
        mutated[38:42] = flag.to_bytes(4, "little")
        expect_scanner_error(checker, bytes(mutated), expected)

    coinbase = bytearray(fixture)
    coinbase[6:38] = bytes(32)
    coinbase[38:42] = (0xFFFFFFFF).to_bytes(4, "little")
    expect_scanner_error(checker, bytes(coinbase), "coinbase input")

    null_index = bytearray(fixture)
    null_index[38:42] = (0xFFFFFFFF).to_bytes(4, "little")
    expect_scanner_error(checker, bytes(null_index), "null output index")

    noncanonical_count = fixture[:5] + b"\xfd\x01\x00" + fixture[6:]
    expect_scanner_error(checker, noncanonical_count, "noncanonical Elements compact-size integer")

    oversized_count = bytearray(fixture)
    oversized_count[5] = 0xFC
    expect_scanner_error(checker, bytes(oversized_count), "input count exceeds remaining transaction bytes")
    expect_scanner_error(checker, fixture + b"\x00", "trailing bytes")

    empty_witness = b"".join(
        (
            (2).to_bytes(4, "little"),
            b"\x01\x01",
            bytes.fromhex("11" * 32),
            (0).to_bytes(4, "little"),
            b"\x00",
            (0xFFFFFFFF).to_bytes(4, "little"),
            b"\x01",
            b"\x01" + bytes.fromhex("22" * 32),
            b"\x01" + (1).to_bytes(8, "big"),
            b"\x00\x00",
            (0).to_bytes(4, "little"),
            b"\x00\x00\x00\x00",
            b"\x00\x00",
        )
    )
    expect_scanner_error(checker, empty_witness, "superfluous empty public transaction witness flag")


def main() -> int:
    test_transaction_scanner_guards(load_checker())
    with tempfile.TemporaryDirectory(prefix="wlpq-corpus-mutations-") as directory:
        scratch = Path(directory)
        test_mutable_copy_modes(scratch)
        valid = scratch / "valid"
        copy_mutable_contracts(valid)
        run(valid, True)

        mutate(scratch, "frame-content", lambda root: replace(root / VECTORS / "frames/frame-test-toy-single.hex", "574c5051", "584c5051"), close=False)
        mutate(scratch, "orphan-file", lambda root: (root / VECTORS / "frames/orphan.hex").write_text("00\n"))
        mutate(scratch, "missing-file", lambda root: (root / VECTORS / "frames/frame-test-toy-single.hex").unlink())
        mutate(scratch, "crlf", lambda root: (root / VECTORS / "CORPUS_V1.md").write_bytes((root / VECTORS / "CORPUS_V1.md").read_bytes().replace(b"\n", b"\r\n")))
        mutate(scratch, "bom", lambda root: (root / REFERENCE / "WIRE_FORMAT_V1.md").write_bytes(b"\xef\xbb\xbf" + (root / REFERENCE / "WIRE_FORMAT_V1.md").read_bytes()))
        mutate(scratch, "uppercase-hex", lambda root: (root / VECTORS / "frames/frame-test-toy-single.hex").write_text((root / VECTORS / "frames/frame-test-toy-single.hex").read_text().upper()))
        mutate(scratch, "error-text", lambda root: replace(root / REFERENCE / "ERROR_MAPPING_V1.tsv", "ordinary wallet plan wire plan was rejected", "ordinary wallet plan wire request was rejected"))
        mutate(scratch, "context-manifest", lambda root: replace(root / REFERENCE / "CONTEXTS_V1.tsv", "b88244f81daf14b2f47915d430ec41e5402de538020f1e4847e8ddbd6f238e5b", "a88244f81daf14b2f47915d430ec41e5402de538020f1e4847e8ddbd6f238e5b"))
        mutate(scratch, "catalog-checksum", lambda root: replace(root / REFERENCE / "CATALOG_FIXTURES_V1.tsv", "#csxkmyvv", "#csxkmyvw"))
        mutate(scratch, "catalog-old-body-new-suffix", lambda root: replace(root / REFERENCE / "CATALOG_FIXTURES_V1.tsv", "73c5da0a/84'/1776'/0'", "73c5da0b/84'/1776'/0'"))
        mutate(scratch, "catalog-valid-alternative", lambda root: replace(root / REFERENCE / "CATALOG_FIXTURES_V1.tsv", "elwpkh([73c5da0a/84'/1776'/0']xpub6CRFzUgHFDaiDAQFNX7VeV9JNPDRabq6NYSpzVZ8zW8ANUCiDdenkb1gBoEZuXNZb3wPc1SVcDXgD2ww5UBtTb8s8ArAbTkoRQ8qn34KgcY/<0;1>/*)#csxkmyvv", "elwpkh([28b3f14e/84'/1'/0']tpubDC2Q4xK4XH72GM7MowNuajyWVbigRLBWKswyP5T88hpPwu5nGqJWnda8zhJEFt71av73Hm8mUMMFSz9acNVzz8b1UbdSHCDXKTbSv5eEytu/<0;1>/*)#u0khc0kg"))
        mutate(scratch, "fixture-arbitrary-reversed-txid", lambda root: replace_tsv_cells(root / VECTORS / "FIXTURES_V1.tsv", "test-candidate-valid", {"txid_consensus_hex": "00" + "11" * 31, "txid_display_hex": "11" * 31 + "00"}), expected_error="public fixture table differs from its exact reviewed authority")
        def drift_fixture_witness(root: Path) -> None:
            path = root / VECTORS / "public/test-candidate-valid.hex"
            data = bytearray.fromhex(path.read_text(encoding="utf-8").strip())
            data[1000] ^= 1
            path.write_text(data.hex() + "\n", encoding="utf-8", newline="\n")
            replace_tsv_cell(root / VECTORS / "FIXTURES_V1.tsv", "test-candidate-valid", "decoded_sha256", hashlib.sha256(data).hexdigest())
        mutate(scratch, "fixture-witness-byte-drift", drift_fixture_witness, expected_error="public fixture table differs from its exact reviewed authority")
        mutate(scratch, "fixture-frame-divergence", lambda root: copy_frame_payload_and_metadata(root, "frame-descriptor-nonownership", "frame-amount-proof-failure"), expected_error="frame payload binding is not a closed bijection")
        mutate(scratch, "payload-binding-removed", lambda root: remove_tsv_row(root / VECTORS / "FRAME_PAYLOAD_BINDINGS_V1.tsv", "binding-amount-proof-failure-candidate-0"), expected_error="frame payload binding is not a closed bijection")
        mutate(scratch, "payload-binding-duplicated", lambda root: duplicate_tsv_row(root / VECTORS / "FRAME_PAYLOAD_BINDINGS_V1.tsv", "binding-amount-proof-failure-candidate-0", "binding-zz-duplicate"), expected_error="frame payload binding is not a closed bijection")
        mutate(scratch, "payload-binding-wrong-fixture", lambda root: replace_tsv_cell(root / VECTORS / "FRAME_PAYLOAD_BINDINGS_V1.tsv", "binding-amount-proof-failure-candidate-0", "fixture_id", "test-candidate-valid"), expected_error="frame payload binding is not a closed bijection")
        mutate(scratch, "fixture-assertion-removed", lambda root: remove_tsv_row(root / VECTORS / "FIXTURE_ASSERTIONS_V1.tsv", "assertion-test-candidate-damaged-proof-output-witness-vector-lengths-0"), expected_error="fixture parsed property coverage mismatch")
        mutate(scratch, "fixture-witness-role-swap", lambda root: replace_tsv_cell(root / VECTORS / "FIXTURE_ASSERTIONS_V1.tsv", "assertion-test-candidate-valid-input-witness-vector-lengths-0", "expected_value", "67,4174"), expected_error="fixture assertion contradicts parsed public bytes")
        mutate(scratch, "fixture-relation-rebound", lambda root: replace_tsv_cell(root / VECTORS / "FIXTURE_ASSERTIONS_V1.tsv", "assertion-test-candidate-damaged-proof-same-txid-0", "related_fixture_id", "test-candidate-damaged-proof"), expected_error="fixture relation assertion coverage mismatch")
        mutate(scratch, "public-proof-case-removed", lambda root: remove_tsv_row(root / VECTORS / "PUBLIC_PROOF_CASES_V1.tsv", "test-valid"), expected_error="public proof cases differ from exact verifier authority")
        mutate(scratch, "public-proof-expectation-drift", lambda root: replace_tsv_cell(root / VECTORS / "PUBLIC_PROOF_CASES_V1.tsv", "test-damaged-range-proof", "expected_result", "ok"), expected_error="public proof cases differ from exact verifier authority")
        mutate(scratch, "public-proof-fixture-substitution", lambda root: replace_tsv_cell(root / VECTORS / "PUBLIC_PROOF_CASES_V1.tsv", "test-valid", "previous_fixture_id", "test-previous-unrelated"), expected_error="public proof cases differ from exact verifier authority")
        mutate(scratch, "public-proof-explicit-case-removed", lambda root: remove_tsv_row(root / VECTORS / "PUBLIC_PROOF_CASES_V1.tsv", "test-explicit-selected-amount-proof-valid"), expected_error="public proof cases differ from exact verifier authority")
        mutate(scratch, "public-proof-unowned-fixture-substitution", lambda root: replace_tsv_cell(root / VECTORS / "PUBLIC_PROOF_CASES_V1.tsv", "test-unowned-selected-amount-proof-valid", "candidate_fixture_id", "test-candidate-valid"), expected_error="public proof cases differ from exact verifier authority")
        mutate(scratch, "public-proof-explicit-expectation-substitution", lambda root: replace_tsv_cell(root / VECTORS / "PUBLIC_PROOF_CASES_V1.tsv", "test-explicit-selected-amount-proof-valid", "expected_result", "range-proof-missing-0"), expected_error="public proof cases differ from exact verifier authority")
        mutate(scratch, "public-proof-unowned-label-misbinding", lambda root: replace_tsv_cell(root / VECTORS / "PUBLIC_PROOF_CASES_V1.tsv", "test-unowned-selected-amount-proof-valid", "proof_case_id", "test-unowned-selected-amount-proof-valid-misbound"), expected_error="public proof cases differ from exact verifier authority")
        mutate(scratch, "case-partition", lambda root: replace(root / VECTORS / "CASES_V1.tsv", "managed-batch-accepted\tmanaged-funding-batch\tfunding-batch-create\tmanaged", "managed-batch-accepted\tmanaged-encoder\tfunding-batch-create\tmanaged"))
        mutate(scratch, "case-frame-foreign-key", lambda root: replace(root / VECTORS / "CASES_V1.tsv", "decode-test-public-valid\tnative-decoder\tdecode\tnative\tconcrete-frame\tframe-test-public-valid\t-\t", "decode-test-public-valid\tnative-decoder\tdecode\tnative\tconcrete-frame\tframe-not-present\t-\t"))
        mutate(scratch, "case-model-foreign-key", lambda root: replace_tsv_cell(root / VECTORS / "CASES_V1.tsv", "shared-encode-main-public", "source_model_id", "model-not-present"))
        mutate(scratch, "reencode-row-removed", lambda root: remove_tsv_row(root / VECTORS / "CASES_V1.tsv", "reencode-amount-proof-failure"), expected_error="native reencode coverage does not exactly match structurally accepted frames")
        mutate(scratch, "native-structural-row-removed", lambda root: remove_tsv_row(root / VECTORS / "CASES_V1.tsv", "native-encode-zero-manifest"), expected_error="native raw encoder structural coverage differs from production predicates")
        mutate(scratch, "orphan-concrete-frame", add_orphan_frame, expected_error="concrete frame topology has an unconsumed frame")
        mutate(scratch, "source-model-kind", lambda root: mutate_source_object(root, "model-main-public", lambda value: value["root"].update(kind="generate-golden")), expected_error="source root kind is unknown")
        mutate(scratch, "source-model-root-scalar", lambda root: mutate_source_object(root, "model-main-public", lambda value: value.update(root=1)), expected_error="source root object schema mismatch")
        mutate(scratch, "source-model-operations-scalar", lambda root: mutate_source_object(root, "model-main-public", lambda value: value.update(operations={})), expected_error="source object operations are not a list")
        mutate(scratch, "source-model-missing-field", lambda root: mutate_source_object(root, "model-main-public", lambda value: value["root"].pop("frame_id")), expected_error="source root object schema mismatch")
        mutate(scratch, "source-model-unused-field", lambda root: mutate_source_object(root, "model-main-public", lambda value: value["root"].update(unused=1)), expected_error="source root object schema mismatch")
        mutate(scratch, "source-model-shared-root-mismatch", lambda root: mutate_source_object(root, "model-main-public", lambda value: value["root"].update(frame_id="frame-test-public-valid")), expected_error="source object root frame does not match its case frame")
        mutate(scratch, "source-model-same-code-swap", lambda root: swap_source_objects(root, "model-native-encode-value-zero", "model-native-encode-address-length-zero"), expected_error="case identity or output binding mismatch")
        mutate(scratch, "native-structural-same-code-source-swap", lambda root: swap_source_objects(root, "model-native-encode-zero-manifest", "model-native-encode-zero-pegged-asset"), expected_error="case identity or output binding mismatch")
        mutate(scratch, "source-model-wrong-path", lambda root: mutate_source_object(root, "model-native-encode-zero-epoch", lambda value: value["operations"][0].update(path="request.selected[*].value")), expected_error="source operation path is noncanonical or undeclared")
        mutate(scratch, "source-model-wrong-type", lambda root: mutate_source_object(root, "model-native-encode-value-zero", lambda value: value["operations"][0].update(op="set-bytes")), expected_error="source operation type, fields, or target mismatch")
        mutate(scratch, "source-model-unknown-operation", lambda root: mutate_source_object(root, "model-native-encode-value-zero", lambda value: value["operations"][0].update(op="set-number")), expected_error="source operation schema mismatch")
        mutate(scratch, "source-model-null-number", lambda root: mutate_source_object(root, "model-native-encode-value-zero", lambda value: value["operations"][0].__setitem__("op", "set-null")), expected_error="source operation type, fields, or target mismatch")
        mutate(scratch, "source-model-bool-u64", lambda root: mutate_source_object(root, "model-native-encode-value-zero", lambda value: value["operations"][0].update(value=True)), expected_error="source operation type, fields, or target mismatch")
        mutate(scratch, "source-model-bool-list-length", lambda root: mutate_source_object(root, "model-native-encode-selected-count-plus-one", lambda value: value["operations"][0].update(length=True)), expected_error="source operation type, fields, or target mismatch")
        mutate(scratch, "source-model-bool-byte-length", lambda root: mutate_source_object(root, "model-native-encode-zero-epoch", lambda value: value["operations"][0]["value"].update(length=True)), expected_error="unsupported or noncanonical byte view")
        mutate(scratch, "source-model-bool-selected-index", lambda root: mutate_source_object(root, "model-managed-row-empty-previous", lambda value: value["root"].update(selected_index=True)), expected_error="funding row selected index mismatch")
        mutate(scratch, "source-model-negative-u64", lambda root: mutate_source_object(root, "model-native-encode-value-zero", lambda value: value["operations"][0].update(value=-1)), expected_error="source operation type, fields, or target mismatch")
        mutate(scratch, "source-model-huge-byte-view", lambda root: mutate_source_object(root, "model-native-encode-zero-epoch", lambda value: value["operations"][0].update(value={"kind": "repeat", "byte_hex": "00", "length": 67_108_865})), expected_error="unsupported or noncanonical byte view")
        mutate(scratch, "source-model-oversized-fixed-field", lambda root: mutate_source_object(root, "model-native-encode-value-zero", lambda value: value.update(operations=[{"op": "set-bytes", "path": "request.selected[0].txid", "value": {"kind": "repeat", "byte_hex": "00", "length": 67_108_864}}])), expected_error="unsupported or noncanonical byte view")
        mutate(scratch, "source-model-huge-list-view", lambda root: mutate_source_object(root, "model-native-encode-selected-count-plus-one", lambda value: value["operations"][0].update(length=67_108_865)), expected_error="source operation type, fields, or target mismatch")
        mutate(scratch, "source-model-list-fill-type", lambda root: mutate_source_object(root, "model-native-encode-selected-count-plus-one", lambda value: value["operations"][0].update(fill={"kind": "repeat", "byte_hex": "00", "length": 1})), expected_error="source list fill recipe mismatch")
        mutate(scratch, "source-model-huge-path-index", lambda root: mutate_source_object(root, "model-native-encode-value-zero", lambda value: value["operations"][0].update(path="request.selected[67108863].value")), expected_error="list view index out of range")
        mutate(scratch, "source-model-copy-type", lambda root: mutate_source_object(root, "model-native-encode-value-zero", lambda value: value["operations"].__setitem__(0, {"op": "copy", "path": "request.selected[0].value", "from": "request.selected[0].candidate"})), expected_error="copy source and target types differ")
        mutate(scratch, "source-model-null-copy-type", lambda root: mutate_source_object(root, "model-native-encode-value-zero", lambda value: value.update(operations=[{"op": "set-null", "path": "request.selected[0].candidate"}, {"op": "copy", "path": "request.selected[0].candidate", "from": "request.selected[0].previous"}])), expected_error="copy source and target types differ")
        mutate(scratch, "source-model-swap-no-op", lambda root: mutate_source_object(root, "model-native-encode-value-zero", lambda value: value["operations"].__setitem__(0, {"op": "swap", "path": "request.selected[0].value", "with": "request.selected[0].value"})), expected_error="source operation is a no-op")
        mutate(scratch, "source-model-reference-type", lambda root: mutate_source_object(root, "model-native-encode-value-zero", lambda value: value["operations"].__setitem__(0, {"op": "set-reference", "path": "request.selected[0]", "from": "request.destinations[0]"})), expected_error="set-reference requires identity-bearing objects")
        mutate(scratch, "source-model-no-op", lambda root: mutate_source_object(root, "model-native-encode-value-zero", lambda value: value["operations"][0].update(value=900)), expected_error="source operation is a no-op")
        mutate(scratch, "source-model-root-swap", lambda root: mutate_source_object(root, "model-managed-row-empty-previous", lambda value: value["root"].update(frame_id="frame-main-public-valid")), expected_error="case identity or output binding mismatch")
        mutate(scratch, "source-model-plan-reference", lambda root: mutate_source_object(root, "model-managed-encoder-plan-batch-identity", lambda value: value.update(operations=[])), expected_error="source object independently derived outcome mismatch")
        mutate(scratch, "source-model-successful-byte-drift", lambda root: mutate_source_object(root, "model-main-public", lambda value: value.update(operations=[{"op": "set-u64", "path": "request.revision", "value": 24}])), expected_error="successful source object does not independently pack to its expected frame")
        def alter_reachable_distribution(value: dict) -> None:
            value["root"]["virtual_frame"]["previous_counts"]["parts"][0]["count"] = 83
        mutate(scratch, "source-model-reachable-distribution", lambda root: mutate_source_object(root, "model-boundary-reachable-frame-maximum", alter_reachable_distribution), expected_error="virtual reachable-frame recipe mismatch")
        mutate(scratch, "source-model-reachable-endian", lambda root: mutate_source_object(root, "model-boundary-reachable-frame-maximum", lambda value: value["root"]["virtual_frame"]["previous_payloads"].update(prefix="u32le")), expected_error="virtual reachable-frame recipe mismatch")
        mutate(scratch, "source-model-expression-operator", lambda root: mutate_source_object(root, "model-boundary-checked-add-overflow", lambda value: value["root"].update(operator="multiply")), expected_error="checked expression does not bind boundary")
        mutate(scratch, "source-model-expression-operand", lambda root: mutate_source_object(root, "model-boundary-checked-add-overflow", lambda value: value["root"].update(right={"operator": "literal", "left": 2, "right": None})), expected_error="checked expression does not bind boundary")
        mutate(scratch, "source-model-expression-bool", lambda root: mutate_source_object(root, "model-boundary-address-bytes-minimum", lambda value: value["root"].update(left=True)), expected_error="checked expression does not bind boundary")
        mutate(scratch, "source-model-outer-read-poison", lambda root: mutate_source_object(root, "model-outer-before-discriminator", lambda value: value["root"].update(read_poison=False)), expected_error="decoder root mismatch")
        mutate(scratch, "source-model-orphan-object", lambda root: (root / VECTORS / "source-models/orphan.json").write_text('{"operations":[],"root":{"frame_id":"frame-test-toy-single","kind":"request-from-frame"},"schema":"wlpq-source-object-v1"}\n', encoding="utf-8"), expected_error="vector topology contains an unreferenced or missing file")
        mutate(scratch, "prepare-result-relabel", lambda root: replace_tsv_cells(root / VECTORS / "CASES_V1.tsv", "prepare-amount-proof", {"expected_result": "ok", "expected_error_code": "0"}), expected_error="prepare case result contradicts independent semantic classification")
        mutate(scratch, "prepare-coverage-tag-relabel", lambda root: swap_tsv_cells(root / VECTORS / "CASES_V1.tsv", "prepare-amount-proof", "prepare-test-public-valid", "coverage_tags"), expected_error="case table differs from its exact reviewed authority")
        mutate(scratch, "prepare-same-code-frame-swap", lambda root: replace_tsv_cell(root / VECTORS / "CASES_V1.tsv", "prepare-amount-proof", "frame_id", "frame-descriptor-nonownership"), expected_error="prepare frame fixture-binding authority is incomplete")
        mutate(scratch, "decode-same-code-frame-swap", lambda root: swap_tsv_cells(root / VECTORS / "CASES_V1.tsv", "decode-fee-zero", "decode-selected-value-zero", "frame_id"), expected_error="case identity or output binding mismatch")
        mutate(scratch, "case-input-identity", lambda root: replace_tsv_cell(root / VECTORS / "CASES_V1.tsv", "decode-fee-zero", "input_identity_sha256", "00" * 32), expected_error="case identity or output binding mismatch")
        mutate(scratch, "case-output-identity", lambda root: replace_tsv_cell(root / VECTORS / "CASES_V1.tsv", "managed-encoder-accepted", "expected_output_sha256", "00" * 32), expected_error="case identity or output binding mismatch")
        mutate(scratch, "boundary-formula", lambda root: replace(root / VECTORS / "BOUNDARIES_V1.tsv", "152+100*88+255*48+255*256+16384*4+67108864", "152+100*88+255*48+255*256+16384*4+67108863"))
        mutate(scratch, "boundary-status-contradiction", lambda root: replace_tsv_cell(root / VECTORS / "BOUNDARIES_V1.tsv", "address-bytes-plus-one", "expected_status", "ok"), expected_error="boundary row differs from its exact derived authority")
        mutate(scratch, "boundary-code-contradiction", lambda root: replace_tsv_cell(root / VECTORS / "BOUNDARIES_V1.tsv", "address-bytes-maximum", "expected_error_code", "4"), expected_error="boundary row differs from its exact derived authority")
        mutate(scratch, "frame-field-manifest", lambda root: replace_tsv_cell(root / VECTORS / "FRAMES_V1.tsv", "frame-test-public-valid", "source_epoch_hex", "42" + "41" * 31))
        mutate(scratch, "same-code-frame-swap", lambda root: replace(root / VECTORS / "frames/frame-fee-zero.hex", (root / VECTORS / "frames/frame-fee-zero.hex").read_text(), (root / VECTORS / "frames/frame-selected-value-zero.hex").read_text()))
        mutate(scratch, "mutation-child", lambda root: replace(root / VECTORS / "MUTATIONS_V1.tsv", "\tframe-address-length-plus-one\treplace\t", "\tframe-address-length-zero\treplace\t"))
        mutate(scratch, "mutation-target", lambda root: replace(root / VECTORS / "MUTATIONS_V1.tsv", "mutation-frame-malformed-address\tframe-test-public-valid\tframe-malformed-address\tlogical-repack\tdestination.0.address", "mutation-frame-malformed-address\tframe-test-public-valid\tframe-malformed-address\tlogical-repack\tdestination.0.value"))
        mutate(scratch, "corpus-id", lambda root: replace(root / REFERENCE / "CORPUS_ID", "ordinary-wallet-plan-wire-v1-conformance-1", "ordinary-wallet-plan-wire-v1-conformance-2"))
        mutate(scratch, "declared-root", lambda root: flip_first_byte(root / REFERENCE / "CORPUS_ROOT_SHA256"), close=False)
        mutate(scratch, "parent-checksum", lambda root: flip_first_byte(root / REFERENCE / "SHA256SUMS"), close=False)
        mutate(scratch, "malformed-checksum", lambda root: (root / VECTORS / "SHA256SUMS").write_text("invalid\n"), close=False)
        mutate(scratch, "path-traversal", lambda root: (root / VECTORS / "SHA256SUMS").write_text((root / VECTORS / "SHA256SUMS").read_text().replace("  BOUNDARIES_V1.tsv", "  ../BOUNDARIES_V1.tsv", 1)), close=False)
        mutate(scratch, "reordered-checksum", lambda root: (root / VECTORS / "SHA256SUMS").write_text("\n".join(reversed((root / VECTORS / "SHA256SUMS").read_text().splitlines())) + "\n"), close=False)
        mutate(scratch, "nested-checksum-name", lambda root: (root / VECTORS / "frames/SHA256SUMS").write_text("00\n"))
        mutate(
            scratch,
            "intermediate-corpus-directory-symlink",
            replace_intermediate_corpus_directory_with_symlink,
            close=False,
            expected_error="corpus path ancestry is linked or non-directory",
        )
        mutate(
            scratch,
            "repository-root-symlink",
            replace_repository_root_with_symlink,
            close=False,
            expected_error="corpus path ancestry is linked or non-directory",
        )

        def symlink(root: Path) -> None:
            path = root / VECTORS / "frames/frame-test-toy-single.hex"
            path.unlink()
            path.symlink_to(root / VECTORS / "frames/frame-test-public-valid.hex")

        mutate(scratch, "symlink", symlink, close=False)

    print("ordinary-wallet-plan conformance checker mutations accepted")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
