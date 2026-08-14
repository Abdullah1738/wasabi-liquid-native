#!/usr/bin/env python3
"""Validate the closed public-only WLPQ v1 conformance corpus."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import struct
import sys
from pathlib import Path


CORPUS_ID = "ordinary-wallet-plan-wire-v1-conformance-2"
REFERENCE = Path("contracts/ordinary-wallet-plan/v1/nonlinkable-reference")
VECTORS = REFERENCE / "vectors"
LOWER_HASH = re.compile(r"[0-9a-f]{64}\Z")
LOWER_HEX = re.compile(r"[0-9a-f]*\Z")
IDENTIFIER = re.compile(r"[a-z][a-z0-9-]*\Z")
DECIMAL = re.compile(r"(?:0|[1-9][0-9]*)\Z")
FORMULA = re.compile(r"(?:0|[1-9][0-9]*)(?:[+*](?:0|[1-9][0-9]*))*\Z")

HEADER_BYTES = 152
SELECTED_FIXED_BYTES = 88
DESTINATION_FIXED_BYTES = 48
MAX_FRAME = 268_435_456
MAX_REACHABLE = 67_260_872
MAX_SELECTED = 100
MAX_DESTINATIONS = 255
MAX_ADDRESS = 256
MAX_TRANSACTION = 4_194_304
MAX_PREVIOUS = 16_384
MAX_TRANSACTION_BYTES = 67_108_864
MAX_OUTPUT_INDEX = 1_073_741_823
MAX_VALUE = 2_100_000_000_000_000
TEST_SOURCE_EPOCH = "41" * 32
CASE_TABLE_SHA256 = "a7759a0a0650f7729bc02f4e978cf12f7aadf7b166758f2e762bcde0e7018110"
FIXTURE_ASSERTIONS_TABLE_SHA256 = "6e57397cf38c7b3a7bedb51e0b98995761342e8b5daf3122c67254a476ca0c28"
REVIEWED_PARENT_ROOT_SHA256 = "a1e1db8cba234d5154e947a32539c0ac461ddbaa812a0dd4e7c4e007a9541600"
REVIEWED_NESTED_ROOT_SHA256 = "a4aaa0e0b13b5544fd8e53f703a685fc56f4ec95f1e1c052f19bf50365ce2f6c"

TEST_MANIFEST = "e4e7ec03e19ce5f83fd04c586788b724d88052b65ef2480cc93bcd50324f6b20"
MAIN_MANIFEST = "b88244f81daf14b2f47915d430ec41e5402de538020f1e4847e8ddbd6f238e5b"
TEST_ASSET_RPC = "144c654344aa716d6f3abcc1ca90e5641e4e2a7f633bc09fe3baf64585819a49"
MAIN_ASSET_RPC = "6f0279e9ed041c3d710a9f57d0c02928416460c4b722ae3457a11eec381c526d"
MAIN_DESCRIPTOR = "elwpkh([73c5da0a/84'/1776'/0']xpub6CRFzUgHFDaiDAQFNX7VeV9JNPDRabq6NYSpzVZ8zW8ANUCiDdenkb1gBoEZuXNZb3wPc1SVcDXgD2ww5UBtTb8s8ArAbTkoRQ8qn34KgcY/<0;1>/*)#csxkmyvv"
TEST_DESCRIPTOR = "elwpkh([28b3f14e/84'/1'/0']tpubDC2Q4xK4XH72GM7MowNuajyWVbigRLBWKswyP5T88hpPwu5nGqJWnda8zhJEFt71av73Hm8mUMMFSz9acNVzz8b1UbdSHCDXKTbSv5eEytu/<0;1>/*)#u0khc0kg"
TEST_SHARED_ADDRESS = b"tlq1qqv6hrj79lvcc4n3kvpqa4q62sv2hqj9vwte2xy77dcm5f8z6v3aua5mr65utagfxglmpcc6tm4a8j8t8dpgwj3cppcwj8dp8x"
PUBLIC_FIXTURE_ROWS = {
    "main-candidate-valid": ("candidate", "mainnet", "public/main-candidate-valid.hex", "4469", "f291d881656e2de6936ebe0b1cac2040da2aa088120b5ad700498fbb024fe34b", "60fa18f40da2d6fb6bfb7aec220767ff0182e17d7634c99889b5e32fd314804c", "4c8014d32fe3b58998c934767de18201ff670722ec7afb6bfbd6a20df418fa60", "canonical-confidential-owned-output"),
    "main-previous-valid": ("previous", "mainnet", "public/main-previous-valid.hex", "56", "cdf49000ca25b1a40510b3794436b1cf0d7719049811195c80908dfb90a596c4", "1ff52e33156d7bea012c8c4454f39c06d82d0f01aa0b5991e8560799fcbf98dc", "dc98bffc990756e891590baa010f2dd8069cf354448c2c01ea7b6d15332ef51f", "canonical-direct-previous"),
    "test-candidate-damaged-proof": ("candidate", "test", "public/test-candidate-damaged-proof.hex", "293", "9f7e91ec80d8ad974815799d56368e59bd824a5544d5076d7f0f774a1024c26d", "c04f8699c87fdbe9386b8b39e64c629ecadd0392d476668fb6b2dfb9c2e61dc7", "c71de6c2b9dfb2b68f6676d49203ddca9e624ce6398b6b38e9db7fc899864fc0", "empty-amount-proof"),
    "test-candidate-explicit": ("candidate", "test", "public/test-candidate-explicit.hex", "162", "5004e84efc55b2b3e8e25f78e9e437982321733419eed90bc6724dd268852160", "9f18e8f28190f30123ef3736ac2bf79d0908ae5b57908f12a54693086a2a7f9e", "9e7f2a6a089346a5128f90575bae08099df72bac3637ef2301f39081f2e8189f", "explicit-selected-output"),
    "test-candidate-unowned": ("candidate", "test", "public/test-candidate-unowned.hex", "4469", "4703f1c23c4ca005f2b765de08afdbd7a9e4000d9c769bc429926567ad1b6252", "b929d20ce49c5c0edce9f0432ef75707f4f1a6ca67fb57ecf1bcb749bda500a4", "a400a5bd49b7bcf1ec57fb67caa6f1f40757f72e43f0e9dc0e5c9ce40cd229b9", "confidential-unowned-output"),
    "test-candidate-shared-previous-valid": ("candidate", "test", "public/test-candidate-shared-previous-valid.hex", "4546", "63cb436487c562edd2084af3d1fa4093c169606740639534405707daab216adf", "bd12a32101979396a037fe09e180c9fbb3302145a22fef57c60f528e00ac1681", "8116ac008e520fc657ef2fa2452130b3fbc980e109fe37a09693970121a312bd", "two-inputs-one-previous-transaction"),
    "test-candidate-valid": ("candidate", "test", "public/test-candidate-valid.hex", "4469", "c6c96d3455902b91dbe2dbfe0029946a7a80ca45148b29564026df849416ab6b", "c04f8699c87fdbe9386b8b39e64c629ecadd0392d476668fb6b2dfb9c2e61dc7", "c71de6c2b9dfb2b68f6676d49203ddca9e624ce6398b6b38e9db7fc899864fc0", "canonical-confidential-owned-output"),
    "test-previous-unrelated": ("previous", "test", "public/test-previous-unrelated.hex", "56", "6ae4041c8395b5ed17e54af5b7b7219f3a4358afe89fb53832b0c1c2f568c049", "80d54c82ed5b9c187e405b0491cdbe65e338aec2611a4b887e56781b409a6aef", "ef6a9a401b78567e884b1a61c2ae38e365becd91045b407e189c5bed824cd580", "unrelated-previous"),
    "test-previous-shared-valid": ("previous", "test", "public/test-previous-shared-valid.hex", "101", "4c51a49ec419b32695a7334dd1e523592d577ecfd013a3a67427660d629ed84a", "2f3383531fb52dea5495f7e96aed8cef2d10e6ee25fcd8b7e381d78cdc07963e", "3e9607dc8cd781e3b7d8fc25eee6102def8ced6ae9f79554ea2db51f5383332f", "two-distinct-spendable-outputs"),
    "test-previous-valid": ("previous", "test", "public/test-previous-valid.hex", "56", "4850b5ae65f9edd5a054e8dc6ba1e405bb5bee67905cbc6af2e4ec6f2cc96cb2", "e1cabb3bf384e4e40ef87a78f9eb329f65ae97b955da7dbcbf162293d21e251c", "1c251ed2932216bfbc7dda55b997ae659f32ebf9787af80ee4e484f33bbbcae1", "canonical-direct-previous"),
    "test-previous-witness-variant": ("previous", "test", "public/test-previous-witness-variant.hex", "4234", "34542b9dc38dec2c66c54f8169842116f226d7aafa28d80ae6711941a262ef0b", "e1cabb3bf384e4e40ef87a78f9eb329f65ae97b955da7dbcbf162293d21e251c", "1c251ed2932216bfbc7dda55b997ae659f32ebf9787af80ee4e484f33bbbcae1", "same-identity-distinct-witness"),
}

TABLES = {
    "ERROR_MAPPING_V1.tsv": ("code", "name", "text"),
    "CONTEXTS_V1.tsv": ("context_id", "manifest_id_hex", "address_profile", "descriptor_network", "pegged_asset_rpc_hex", "pegged_asset_consensus_hex", "confidential_address_prefix"),
    "CATALOG_FIXTURES_V1.tsv": ("catalog_fixture_id", "context_id", "descriptor_network", "inclusive_last_derivation_index", "checksummed_public_descriptor"),
    "vectors/FIXTURES_V1.tsv": ("fixture_id", "fixture_kind", "network", "relative_path", "decoded_length", "decoded_sha256", "txid_consensus_hex", "txid_display_hex", "public_property"),
    "vectors/FIXTURE_ASSERTIONS_V1.tsv": ("assertion_id", "fixture_id", "predicate", "subject_index", "expected_value", "related_fixture_id"),
    "vectors/CATALOG_OUTPUT_SCRIPTS_V1.tsv": ("catalog_fixture_id", "branch", "derivation_index", "script_sha256"),
    "vectors/FRAME_PAYLOAD_BINDINGS_V1.tsv": ("binding_id", "frame_id", "selected_index", "payload_role", "previous_index", "fixture_id", "transform"),
    "vectors/PUBLIC_PROOF_CASES_V1.tsv": ("proof_case_id", "candidate_fixture_id", "previous_fixture_id", "expected_result"),
    "vectors/FRAMES_V1.tsv": ("frame_id", "execution_class", "relative_path", "decoded_length", "decoded_sha256", "structural_result", "structural_error_code", "parent_frame_id", "mutation_id", "source_epoch_hex", "source_revision", "manifest_id_hex", "pegged_asset_consensus_hex", "selected_count", "destination_count", "aggregate_previous_count", "fee_value", "selected_txids_consensus_hex", "selected_txids_display_hex", "destination_assets_consensus_hex", "destination_addresses_hex", "payload_hash_manifest"),
    "vectors/MUTATIONS_V1.tsv": ("mutation_id", "parent_frame_id", "child_frame_id", "mutation_kind", "target", "offset", "old_hex", "new_hex"),
    "vectors/CASES_V1.tsv": ("case_id", "partition", "operation", "implementation", "execution_class", "frame_id", "source_model_id", "expected_source_epoch_hex", "catalog_fixture_id", "expected_result", "expected_error_code", "expected_reencode_frame_id", "combined_precedence", "coverage_tags", "input_identity_sha256", "expected_output_sha256", "case_binding_sha256"),
    "vectors/SOURCE_MODELS_V1.tsv": ("source_model_id", "partition", "operation", "execution_class", "relative_path", "decoded_length", "decoded_sha256", "expected_result", "expected_error_code", "precedence"),
    "vectors/BOUNDARIES_V1.tsv": ("boundary_id", "source_model_id", "operation", "boundary_kind", "production_constant", "numeric_domain", "formula", "execution_class", "expected_status", "expected_value", "expected_error_code", "coverage"),
}


class CorpusError(Exception):
    pass


def reject(message: str) -> None:
    raise CorpusError(message)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def exact_text(path: Path) -> str:
    data = path.read_bytes()
    if not data or data.startswith(b"\xef\xbb\xbf") or b"\r" in data or not data.endswith(b"\n"):
        reject(f"noncanonical LF text: {path}")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        reject(f"non-UTF-8 text: {path}")


def parse_table(root: Path, relative: str) -> list[dict[str, str]]:
    text = exact_text(root / REFERENCE / relative)
    lines = text.splitlines()
    header = tuple(lines[0].split("\t"))
    if header != TABLES[relative]:
        reject(f"table schema mismatch: {relative}")
    rows = []
    for line in lines[1:]:
        fields = line.split("\t")
        if len(fields) != len(header) or any(field == "" for field in fields):
            reject(f"malformed table row: {relative}")
        rows.append(dict(zip(header, fields, strict=True)))
    if not rows:
        reject(f"empty table: {relative}")
    first = header[0]
    ids = [row[first] for row in rows]
    if relative == "vectors/CATALOG_OUTPUT_SCRIPTS_V1.tsv":
        compound = [(row["catalog_fixture_id"], int(row["branch"]), int(row["derivation_index"])) for row in rows if DECIMAL.fullmatch(row["branch"]) and DECIMAL.fullmatch(row["derivation_index"])]
        if len(compound) != len(rows) or compound != sorted(compound) or len(compound) != len(set(compound)) or not all(IDENTIFIER.fullmatch(value) for value in ids):
            reject(f"noncanonical table identifiers: {relative}")
        return rows
    identifier_ok = all(DECIMAL.fullmatch(value) for value in ids) if relative == "ERROR_MAPPING_V1.tsv" else all(IDENTIFIER.fullmatch(value) for value in ids)
    ordered = sorted(ids, key=int) if relative == "ERROR_MAPPING_V1.tsv" else sorted(ids)
    if ids != ordered or len(ids) != len(set(ids)) or not identifier_ok:
        reject(f"noncanonical table identifiers: {relative}")
    return rows


def safe_relative(value: str) -> Path:
    if not value or value.startswith("/") or "\\" in value:
        reject("unsafe relative path")
    path = Path(value)
    if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
        reject("unsafe relative path")
    return path


def parse_checksums(path: Path) -> dict[str, str]:
    lines = exact_text(path).splitlines()
    result: dict[str, str] = {}
    prior = ""
    for line in lines:
        if len(line) < 67 or line[64:66] != "  ":
            reject(f"malformed checksum line: {path}")
        checksum, relative = line[:64], line[66:]
        if not LOWER_HASH.fullmatch(checksum):
            reject(f"noncanonical checksum: {path}")
        safe_relative(relative)
        if relative <= prior or relative in result or relative == "SHA256SUMS":
            reject(f"checksum ordering or recursion: {path}")
        prior = relative
        result[relative] = checksum
    if not result:
        reject(f"empty checksum inventory: {path}")
    return result


def validate_topology(root: Path) -> tuple[dict[str, str], dict[str, str]]:
    reference = root / REFERENCE
    vectors = root / VECTORS
    ancestry = [root]
    current = root
    for part in REFERENCE.parts:
        current /= part
        ancestry.append(current)
    ancestry.append(vectors)
    for path in ancestry:
        metadata = os.lstat(path)
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            reject("corpus path ancestry is linked or non-directory")
    if not reference.is_dir() or reference.is_symlink() or not vectors.is_dir() or vectors.is_symlink():
        reject("invalid corpus directory")
    if any(path.is_file() and path.stat().st_size > 16 * 1024 * 1024 for path in reference.iterdir()):
        reject("oversized parent corpus file")
    if (vectors / "SHA256SUMS").stat().st_size > 16 * 1024 * 1024:
        reject("oversized nested checksum inventory")
    for path in reference.rglob("*"):
        if path.is_symlink():
            reject("symlink in corpus topology")
    expected_parent_files = {"CATALOG_FIXTURES_V1.tsv", "CONTEXTS_V1.tsv", "CORPUS_ID", "CORPUS_ROOT_SHA256", "ERROR_MAPPING_V1.tsv", "SHA256SUMS", "WIRE_FORMAT_V1.md"}
    parent_entries = {path.name for path in reference.iterdir()}
    if parent_entries != expected_parent_files | {"vectors"}:
        reject("parent corpus topology is not exact")
    nested = parse_checksums(vectors / "SHA256SUMS")
    actual_nested = {
        path.relative_to(vectors).as_posix()
        for path in vectors.rglob("*")
        if path.is_file() and path.relative_to(vectors).as_posix() != "SHA256SUMS"
    }
    if set(nested) != actual_nested:
        reject("nested checksum topology is not exact")
    for relative, expected in nested.items():
        path = vectors / safe_relative(relative)
        if path.name == "SHA256SUMS" or path.stat().st_size > 16 * 1024 * 1024:
            reject("nested checksum recursion or oversized tracked fixture")
        if digest(path.read_bytes()) != expected:
            reject(f"nested checksum mismatch: {relative}")
    parent = parse_checksums(reference / "SHA256SUMS")
    expected_parent = (expected_parent_files - {"SHA256SUMS", "CORPUS_ROOT_SHA256"}) | {"vectors/SHA256SUMS"}
    if set(parent) != expected_parent:
        reject("parent checksum topology is not exact")
    for relative, expected in parent.items():
        if digest((reference / safe_relative(relative)).read_bytes()) != expected:
            reject(f"parent checksum mismatch: {relative}")
    declared_root = exact_text(reference / "CORPUS_ROOT_SHA256").strip()
    if not LOWER_HASH.fullmatch(declared_root) or declared_root != digest((reference / "SHA256SUMS").read_bytes()):
        reject("declared corpus parent root mismatch")
    return parent, nested


def validate_reviewed_roots(root: Path) -> None:
    reference = root / REFERENCE
    parent = reference / "SHA256SUMS"
    nested = reference / "vectors/SHA256SUMS"
    declared = reference / "CORPUS_ROOT_SHA256"
    for path in (parent, nested, declared):
        if not path.is_file() or path.is_symlink() or path.stat().st_size > 16 * 1024 * 1024:
            reject("reviewed corpus root file is missing, linked, or oversized")
    if digest(parent.read_bytes()) != REVIEWED_PARENT_ROOT_SHA256 or digest(nested.read_bytes()) != REVIEWED_NESTED_ROOT_SHA256:
        reject("reviewed corpus roots do not match")
    if declared.read_bytes() != (REVIEWED_PARENT_ROOT_SHA256 + "\n").encode():
        reject("reviewed declared corpus root does not match")


def parse_hex_file(path: Path) -> bytes:
    text = exact_text(path)
    if text.count("\n") != 1:
        reject(f"hex file must contain one LF-terminated line: {path}")
    value = text[:-1]
    if not value or len(value) % 2 or not LOWER_HEX.fullmatch(value):
        reject(f"noncanonical lowercase hex: {path}")
    return bytes.fromhex(value)


def compact_size(data: bytes, cursor: int) -> tuple[int, int]:
    if cursor >= len(data):
        reject("truncated Elements compact-size integer")
    marker = data[cursor]
    cursor += 1
    if marker < 0xFD:
        return marker, cursor
    widths = {0xFD: 2, 0xFE: 4, 0xFF: 8}
    width = widths[marker]
    if cursor + width > len(data):
        reject("truncated Elements compact-size integer")
    value = int.from_bytes(data[cursor : cursor + width], "little")
    if value < (0xFD if width == 2 else 0x10000 if width == 4 else 0x100000000):
        reject("noncanonical Elements compact-size integer")
    return value, cursor + width


def skip_confidential(data: bytes, cursor: int, explicit_width: int, commitments: tuple[int, ...]) -> int:
    if cursor >= len(data):
        reject("truncated Elements confidential field")
    prefix = data[cursor]
    if prefix == 0:
        return cursor + 1
    if prefix == 1:
        end = cursor + 1 + explicit_width
    elif prefix in commitments:
        end = cursor + 33
    else:
        reject("invalid Elements confidential prefix")
    if end > len(data):
        reject("truncated Elements confidential field")
    return end


def skip_bytes(data: bytes, cursor: int) -> tuple[int, bytes]:
    length, cursor = compact_size(data, cursor)
    end = cursor + length
    if end > len(data):
        reject("truncated Elements byte vector")
    return end, data[cursor:end]


def bounded_count(data: bytes, cursor: int, count: int, minimum_item_bytes: int, label: str) -> None:
    if count > (len(data) - cursor) // minimum_item_bytes:
        reject(f"{label} count exceeds remaining transaction bytes")


def scan_public_transaction(data: bytes) -> dict:
    """Scan the issuance-free, peg-in-free public transaction corpus surface."""
    if len(data) < 9:
        reject("public transaction fixture is too short")
    cursor = 0
    base = bytearray(data[:4])
    cursor = 4
    flags = data[cursor]
    had_witness = bool(flags & 1)
    cursor += 1
    if flags & ~1:
        reject("unsupported Elements transaction flag")
    base.append(0)
    count, after_count = compact_size(data, cursor)
    base += data[cursor:after_count]
    cursor = after_count
    input_count = count
    bounded_count(data, cursor, input_count, 41, "public transaction input")
    inputs = []
    for _ in range(input_count):
        if cursor + 37 > len(data):
            reject("truncated Elements input")
        start = cursor
        previous_txid = data[cursor : cursor + 32]
        previous_vout = int.from_bytes(data[cursor + 32 : cursor + 36], "little")
        if previous_vout == 0xFFFFFFFF:
            if previous_txid == bytes(32):
                reject("coinbase input is outside the public fixture surface")
            reject("null output index is outside the public fixture surface")
        if previous_vout & 0x80000000:
            reject("asset issuance is outside the public fixture surface")
        if previous_vout & 0x40000000:
            reject("peg-in input is outside the public fixture surface")
        cursor += 36
        cursor, _ = skip_bytes(data, cursor)
        if cursor + 4 > len(data):
            reject("truncated Elements input sequence")
        cursor += 4
        base += data[start:cursor]
        inputs.append({"txid": previous_txid.hex(), "vout": previous_vout})
    count_start = cursor
    output_count, cursor = compact_size(data, cursor)
    base += data[count_start:cursor]
    bounded_count(data, cursor, output_count, 4, "public transaction output")
    outputs = []
    for _ in range(output_count):
        start = cursor
        prefixes = []
        for width, commitments in ((32, (0x0A, 0x0B)), (8, (0x08, 0x09)), (32, (0x02, 0x03))):
            if cursor >= len(data):
                reject("truncated Elements output")
            prefixes.append(data[cursor])
            cursor = skip_confidential(data, cursor, width, commitments)
        cursor, script = skip_bytes(data, cursor)
        base += data[start:cursor]
        outputs.append({"prefixes": ",".join(f"{prefix:02x}" for prefix in prefixes), "script_sha256": digest(script)})
    if cursor + 4 > len(data):
        reject("public transaction fixture truncates locktime")
    base += data[cursor : cursor + 4]
    cursor += 4
    output_witness = []
    input_witness = []
    witness_nonempty = False
    if had_witness:
        for _ in range(input_count):
            cursor, amount_proof = skip_bytes(data, cursor)
            cursor, inflation_proof = skip_bytes(data, cursor)
            witness_nonempty |= bool(amount_proof or inflation_proof)
            stack_count, cursor = compact_size(data, cursor)
            bounded_count(data, cursor, stack_count, 1, "script witness item")
            witness_nonempty |= stack_count != 0
            for _ in range(stack_count):
                cursor, _ = skip_bytes(data, cursor)
            pegin_count, cursor = compact_size(data, cursor)
            bounded_count(data, cursor, pegin_count, 1, "peg-in witness item")
            witness_nonempty |= pegin_count != 0
            for _ in range(pegin_count):
                cursor, _ = skip_bytes(data, cursor)
            input_witness.append((len(amount_proof), len(inflation_proof)))
        for _ in range(output_count):
            cursor, surjection = skip_bytes(data, cursor)
            cursor, rangeproof = skip_bytes(data, cursor)
            witness_nonempty |= bool(surjection or rangeproof)
            output_witness.append((len(surjection), len(rangeproof)))
        if not witness_nonempty:
            reject("superfluous empty public transaction witness flag")
    if cursor != len(data):
        reject("public transaction fixture has trailing bytes")
    return {
        "txid": hashlib.sha256(hashlib.sha256(base).digest()).digest().hex(),
        "flags": flags,
        "inputs": inputs,
        "outputs": outputs,
        "input_witness": input_witness,
        "output_witness": output_witness,
    }


def elements_txid(data: bytes) -> str:
    return scan_public_transaction(data)["txid"]


def parse_public_transaction(data: bytes) -> dict:
    return scan_public_transaction(data)


def u16(data: bytes, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def u64(data: bytes, offset: int) -> int:
    return struct.unpack_from("<Q", data, offset)[0]


def raw_unpack(data: bytes) -> dict:
    """Unpack a length-consistent frame without canonical semantic checks."""
    if len(data) < HEADER_BYTES or data[:4] != b"WLPQ" or u16(data, 4) != 1 or u16(data, 6) != HEADER_BYTES or u64(data, 8) != len(data):
        reject("logical mutation does not use a length-consistent WLPQ frame")
    selected_count, destination_count = u32(data, 128), u32(data, 132)
    cursor = HEADER_BYTES
    selected = []
    for _ in range(selected_count):
        if cursor + SELECTED_FIXED_BYTES > len(data):
            reject("logical mutation frame truncates selected fixed bytes")
        txid = data[cursor : cursor + 32]
        vout = u32(data, cursor + 32)
        asset = data[cursor + 36 : cursor + 68]
        value = u64(data, cursor + 68)
        candidate_length = u32(data, cursor + 76)
        previous_count = u32(data, cursor + 80)
        cursor += SELECTED_FIXED_BYTES
        if cursor + candidate_length > len(data):
            reject("logical mutation frame truncates candidate")
        candidate = data[cursor : cursor + candidate_length]
        cursor += candidate_length
        previous = []
        for _ in range(previous_count):
            if cursor + 4 > len(data):
                reject("logical mutation frame truncates previous length")
            length = u32(data, cursor)
            cursor += 4
            if cursor + length > len(data):
                reject("logical mutation frame truncates previous payload")
            previous.append(data[cursor : cursor + length])
            cursor += length
        selected.append({"txid": txid, "vout": vout, "asset": asset, "value": value, "candidate": candidate, "previous": previous})
    destinations = []
    for _ in range(destination_count):
        if cursor + DESTINATION_FIXED_BYTES > len(data):
            reject("logical mutation frame truncates destination fixed bytes")
        asset = data[cursor : cursor + 32]
        value = u64(data, cursor + 32)
        length = u32(data, cursor + 40)
        cursor += DESTINATION_FIXED_BYTES
        if cursor + length > len(data):
            reject("logical mutation frame truncates address")
        address = data[cursor : cursor + length]
        cursor += length
        destinations.append({"asset": asset, "value": value, "address": address})
    if cursor != len(data):
        reject("logical mutation frame has trailing bytes")
    return {
        "source": data[24:56], "revision": u64(data, 56), "manifest": data[64:96], "pegged": data[96:128],
        "aggregate": u32(data, 136), "fee": u64(data, 144), "selected": selected, "destinations": destinations,
    }


def scan(data: bytes, expected_source: bytes) -> tuple[int, dict | None]:
    if expected_source == bytes(32):
        return 1, None
    if len(data) > MAX_FRAME:
        return 4, None
    if len(data) < 8:
        return 3, None
    if data[:4] != b"WLPQ" or u16(data, 4) != 1 or u16(data, 6) != HEADER_BYTES:
        return 2, None
    if len(data) < HEADER_BYTES:
        return 3, None
    if u64(data, 8) != len(data) or u32(data, 16) != 0 or u32(data, 20) != 0 or u32(data, 140) != 0:
        return 3, None
    if data[24:56] == bytes(32) or data[64:96] == bytes(32) or data[96:128] == bytes(32):
        return 3, None
    if data[24:56] != expected_source:
        return 5, None
    selected_count, destination_count, aggregate_declared = u32(data, 128), u32(data, 132), u32(data, 136)
    fee = u64(data, 144)
    if not 1 <= selected_count <= MAX_SELECTED or not 1 <= destination_count <= MAX_DESTINATIONS or aggregate_declared > MAX_PREVIOUS or not 1 <= fee <= MAX_VALUE or len(data) > MAX_REACHABLE:
        return 4, None
    cursor = HEADER_BYTES
    total_previous = 0
    total_transaction_bytes = 0
    invalid_encoding = False
    selected = []
    for _ in range(selected_count):
        if cursor + SELECTED_FIXED_BYTES > len(data):
            return 3, None
        txid = data[cursor : cursor + 32]
        vout = u32(data, cursor + 32)
        asset = data[cursor + 36 : cursor + 68]
        value = u64(data, cursor + 68)
        candidate_length = u32(data, cursor + 76)
        previous_count = u32(data, cursor + 80)
        reserved = u32(data, cursor + 84)
        invalid_encoding |= txid == bytes(32) or asset == bytes(32)
        if vout > MAX_OUTPUT_INDEX or not 1 <= value <= MAX_VALUE or not 1 <= candidate_length <= MAX_TRANSACTION or previous_count > MAX_PREVIOUS:
            return 4, None
        total_transaction_bytes += candidate_length
        if total_transaction_bytes > MAX_TRANSACTION_BYTES:
            return 4, None
        total_previous += previous_count
        if total_previous > MAX_PREVIOUS:
            return 4, None
        invalid_encoding |= reserved != 0
        cursor += SELECTED_FIXED_BYTES
        if cursor + candidate_length > len(data):
            return 3, None
        candidate = data[cursor : cursor + candidate_length]
        cursor += candidate_length
        previous = []
        for _ in range(previous_count):
            if cursor + 4 > len(data):
                return 3, None
            length = u32(data, cursor)
            if not 1 <= length <= MAX_TRANSACTION:
                return 4, None
            total_transaction_bytes += length
            if total_transaction_bytes > MAX_TRANSACTION_BYTES:
                return 4, None
            cursor += 4
            if cursor + length > len(data):
                return 3, None
            previous.append(data[cursor : cursor + length])
            cursor += length
        invalid_encoding |= any(left >= right for left, right in zip(previous, previous[1:]))
        selected.append({"txid": txid, "vout": vout, "asset": asset, "value": value, "candidate": candidate, "previous": previous})
    destinations = []
    for _ in range(destination_count):
        if cursor + DESTINATION_FIXED_BYTES > len(data):
            return 3, None
        asset = data[cursor : cursor + 32]
        value = u64(data, cursor + 32)
        length = u32(data, cursor + 40)
        reserved = u32(data, cursor + 44)
        invalid_encoding |= asset == bytes(32)
        if not 1 <= value <= MAX_VALUE or not 1 <= length <= MAX_ADDRESS:
            return 4, None
        invalid_encoding |= reserved != 0
        cursor += DESTINATION_FIXED_BYTES
        if cursor + length > len(data):
            return 3, None
        address = data[cursor : cursor + length]
        cursor += length
        invalid_encoding |= any(byte > 0x7F for byte in address)
        destinations.append({"asset": asset, "value": value, "address": address})
    invalid_encoding |= total_previous != aggregate_declared
    selected_keys = [(row["txid"][::-1], row["vout"]) for row in selected]
    invalid_encoding |= any(left >= right for left, right in zip(selected_keys, selected_keys[1:]))
    invalid_encoding |= cursor != len(data)
    if invalid_encoding:
        return 3, None
    return 0, {
        "source": data[24:56], "revision": u64(data, 56), "manifest": data[64:96], "pegged": data[96:128],
        "aggregate": aggregate_declared, "fee": fee, "selected": selected, "destinations": destinations,
    }


def pack_manual(value: dict) -> bytes:
    body = bytearray()
    for row in value["selected"]:
        body += row["txid"] + struct.pack("<I", row["vout"]) + row["asset"] + struct.pack("<Q", row["value"])
        body += struct.pack("<III", len(row["candidate"]), len(row["previous"]), 0) + row["candidate"]
        for previous in row["previous"]:
            body += struct.pack("<I", len(previous)) + previous
    for row in value["destinations"]:
        body += row["asset"] + struct.pack("<QI", row["value"], len(row["address"])) + bytes(4) + row["address"]
    aggregate = sum(len(row["previous"]) for row in value["selected"])
    header = b"WLPQ" + struct.pack("<HHQII", 1, HEADER_BYTES, HEADER_BYTES + len(body), 0, 0)
    header += value["source"] + struct.pack("<Q", value["revision"]) + value["manifest"] + value["pegged"]
    header += struct.pack("<IIIIQ", len(value["selected"]), len(value["destinations"]), aggregate, 0, value["fee"])
    if len(header) != HEADER_BYTES:
        reject("independent packer header size mismatch")
    return header + body


def validate_constants(root: Path, tables: dict[str, list[dict[str, str]]]) -> None:
    if exact_text(root / REFERENCE / "CORPUS_ID") != CORPUS_ID + "\n":
        reject("corpus identity mismatch")
    error_rows = tables["ERROR_MAPPING_V1.tsv"]
    expected_errors = [
        ("1", "InvalidArgument", "ordinary wallet plan wire argument is invalid"),
        ("2", "VersionMismatch", "ordinary wallet plan wire version is unsupported"),
        ("3", "InvalidEncoding", "ordinary wallet plan wire encoding is invalid"),
        ("4", "LimitExceeded", "ordinary wallet plan wire limit exceeded"),
        ("5", "SourceBindingMismatch", "ordinary wallet plan wire source binding does not match"),
        ("6", "ContextRejected", "ordinary wallet plan wire context was rejected"),
        ("7", "PlanRejected", "ordinary wallet plan wire plan was rejected"),
        ("8", "FundingRejected", "ordinary wallet plan wire funding was rejected"),
    ]
    if [(r["code"], r["name"], r["text"]) for r in error_rows] != expected_errors:
        reject("stable error mapping mismatch")
    contexts = tables["CONTEXTS_V1.tsv"]
    expected_contexts = [
        ("liquid-mainnet", MAIN_MANIFEST, "liquid-mainnet", "mainnet", MAIN_ASSET_RPC, bytes.fromhex(MAIN_ASSET_RPC)[::-1].hex(), "lq1"),
        ("liquid-testnet", TEST_MANIFEST, "liquid-testnet", "test", TEST_ASSET_RPC, bytes.fromhex(TEST_ASSET_RPC)[::-1].hex(), "tlq1"),
    ]
    if [tuple(r.values()) for r in contexts] != expected_contexts:
        reject("reviewed context table mismatch")
    catalogs = tables["CATALOG_FIXTURES_V1.tsv"]
    if [(r["catalog_fixture_id"], r["context_id"], r["descriptor_network"], r["inclusive_last_derivation_index"], r["checksummed_public_descriptor"]) for r in catalogs] != [
        ("catalog-main-0", "liquid-mainnet", "mainnet", "0", MAIN_DESCRIPTOR),
        ("catalog-test-0", "liquid-testnet", "test", "0", TEST_DESCRIPTOR),
    ]:
        reject("catalog fixture mapping mismatch")
    for row in catalogs:
        descriptor = row["checksummed_public_descriptor"]
        if any(marker in descriptor.lower() for marker in ("xprv", "tprv", "prv", "private")):
            reject("catalog contains non-public descriptor material")
        body, separator, checksum = descriptor.rpartition("#")
        if separator != "#" or checksum != descriptor_checksum(body):
            reject("catalog descriptor checksum mismatch")


DESCRIPTOR_INPUT_CHARSET = "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\"\\ "
DESCRIPTOR_CHECKSUM_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def descriptor_polymod(checksum: int, value: int) -> int:
    top = checksum >> 35
    checksum = ((checksum & 0x7FFFFFFFF) << 5) ^ value
    generators = (0xF5DEE51989, 0xA9FDCA3312, 0x1BAB10E32D, 0x3706B1677A, 0x644D626FFD)
    for index, generator in enumerate(generators):
        if (top >> index) & 1:
            checksum ^= generator
    return checksum


def descriptor_checksum(body: str) -> str:
    checksum = 1
    classes = 0
    count = 0
    for character in body:
        position = DESCRIPTOR_INPUT_CHARSET.find(character)
        if position < 0:
            reject("descriptor contains unsupported checksum character")
        checksum = descriptor_polymod(checksum, position & 31)
        classes = classes * 3 + (position >> 5)
        count += 1
        if count == 3:
            checksum = descriptor_polymod(checksum, classes)
            classes = 0
            count = 0
    if count:
        checksum = descriptor_polymod(checksum, classes)
    for _ in range(8):
        checksum = descriptor_polymod(checksum, 0)
    checksum ^= 1
    return "".join(DESCRIPTOR_CHECKSUM_CHARSET[(checksum >> (5 * (7 - index))) & 31] for index in range(8))


def validate_fixtures(root: Path, rows: list[dict[str, str]]) -> dict[str, bytes]:
    result = {}
    properties = {row["public_property"] for row in rows}
    required = {"canonical-confidential-owned-output", "canonical-direct-previous", "empty-amount-proof", "same-identity-distinct-witness", "unrelated-previous", "explicit-selected-output", "confidential-unowned-output"}
    if not required <= properties:
        reject("public fixture semantic coverage incomplete")
    actual_public_rows = {
        row["fixture_id"]: tuple(row[field] for field in (
            "fixture_kind", "network", "relative_path", "decoded_length", "decoded_sha256",
            "txid_consensus_hex", "txid_display_hex", "public_property",
        ))
        for row in rows
    }
    if actual_public_rows != PUBLIC_FIXTURE_ROWS:
        reject("public fixture table differs from its exact reviewed authority")
    for row in rows:
        if row["fixture_kind"] not in ("candidate", "previous") or row["network"] not in ("mainnet", "test"):
            reject("invalid public fixture classification")
        relative = safe_relative(row["relative_path"])
        if relative.parts[0] != "public" or relative.suffix != ".hex":
            reject("public fixture path escaped its partition")
        data = parse_hex_file(root / VECTORS / relative)
        if str(len(data)) != row["decoded_length"] or digest(data) != row["decoded_sha256"]:
            reject("public fixture digest metadata mismatch")
        raw, display = row["txid_consensus_hex"], row["txid_display_hex"]
        if raw != "-":
            computed = elements_txid(data)
            if not LOWER_HASH.fullmatch(raw) or not LOWER_HASH.fullmatch(display) or bytes.fromhex(raw)[::-1].hex() != display or raw != computed:
                reject("public fixture transaction identifier reversal mismatch")
        elif display != "-":
            reject("partial public fixture transaction identifier")
        result[row["fixture_id"]] = data
    return result


def validate_prepare_fixture_bindings(cases: list[dict[str, str]], frames: dict[str, bytes], fixtures: dict[str, bytes]) -> None:
    test_default = {
        "frame-candidate-id-mismatch", "frame-conservation-asset-mismatch", "frame-conservation-value-mismatch",
        "frame-malformed-address", "frame-noncanonical-address", "frame-nonconfidential-address",
        "frame-output-index-mismatch", "frame-test-public-valid", "frame-unknown-manifest",
        "frame-wrong-pegged-asset", "frame-wrong-profile-address",
    }
    main_default = {"frame-main-public-valid", "frame-main-wrong-pegged-asset", "frame-main-wrong-profile-address"}
    special = {
        "frame-amount-proof-failure": ("test-candidate-damaged-proof", ("test-previous-valid",), False),
        "frame-candidate-noncanonical": ("test-candidate-valid", ("test-previous-valid",), True),
        "frame-combined-plan-funding": ("test-candidate-valid", ("test-previous-valid",), True),
        "frame-combined-context-plan-funding": ("test-candidate-valid", ("test-previous-valid",), True),
        "frame-descriptor-nonownership": ("test-candidate-unowned", ("test-previous-valid",), False),
        "frame-duplicate-previous-identity": ("test-candidate-valid", ("test-previous-valid", "test-previous-witness-variant"), False),
        "frame-extra-previous": ("test-candidate-valid", ("test-previous-valid", "test-previous-unrelated"), False),
        "frame-missing-previous": ("test-candidate-valid", (), False),
        "frame-public-output-shape": ("test-candidate-explicit", ("test-previous-valid",), False),
        "frame-test-shared-previous-valid": ("test-candidate-shared-previous-valid", ("test-previous-shared-valid",), False),
    }
    bindings = {frame_id: ("test-candidate-valid", ("test-previous-valid",), False) for frame_id in test_default}
    bindings.update({frame_id: ("main-candidate-valid", ("main-previous-valid",), False) for frame_id in main_default})
    bindings.update(special)
    prepare_frames = {row["frame_id"] for row in cases if row["partition"] == "native-prepare"}
    if prepare_frames != set(bindings):
        reject("prepare frame fixture-binding authority is incomplete")
    for frame_id, (candidate_id, previous_ids, append_zero) in bindings.items():
        value = raw_unpack(frames[frame_id])
        if len(value["selected"]) != 1:
            reject("prepare fixture binding requires one selected row")
        row = value["selected"][0]
        expected_candidate = fixtures[candidate_id] + (b"\0" if append_zero else b"")
        expected_previous = sorted(fixtures[fixture_id] for fixture_id in previous_ids)
        if row["candidate"] != expected_candidate or row["previous"] != expected_previous:
            reject(f"prepare frame diverges from exact public fixtures: {frame_id}")


def validate_fixture_assertions(rows: list[dict[str, str]], fixtures: dict[str, bytes], fixture_rows: list[dict[str, str]]) -> None:
    properties = {row["fixture_id"]: row for row in fixture_rows}
    parsed = {fixture_id: parse_public_transaction(data) for fixture_id, data in fixtures.items()}
    allowed = {"flags", "input-count", "output-count", "input-previous-txid", "input-previous-vout", "output-prefixes", "output-script-sha256", "input-witness-vector-lengths", "output-witness-vector-lengths", "same-txid", "different-txid", "different-full-sha256"}
    required_relations = {
        ("test-candidate-damaged-proof", "same-txid", "test-candidate-valid"),
        ("test-candidate-damaged-proof", "different-full-sha256", "test-candidate-valid"),
        ("test-previous-witness-variant", "same-txid", "test-previous-valid"),
        ("test-previous-witness-variant", "different-full-sha256", "test-previous-valid"),
        ("test-previous-unrelated", "different-txid", "test-previous-valid"),
    }
    actual_relations = set()
    for row in rows:
        fixture_id, predicate = row["fixture_id"], row["predicate"]
        if fixture_id not in fixtures or predicate not in allowed or not DECIMAL.fullmatch(row["subject_index"]):
            reject("fixture assertion schema or foreign key mismatch")
        index = int(row["subject_index"]); transaction = parsed[fixture_id]; related = row["related_fixture_id"]
        if predicate == "flags": actual = str(transaction["flags"])
        elif predicate == "input-count": actual = str(len(transaction["inputs"]))
        elif predicate == "output-count": actual = str(len(transaction["outputs"]))
        elif predicate == "input-previous-txid": actual = transaction["inputs"][index]["txid"]
        elif predicate == "input-previous-vout": actual = str(transaction["inputs"][index]["vout"])
        elif predicate == "output-prefixes": actual = transaction["outputs"][index]["prefixes"]
        elif predicate == "output-script-sha256": actual = transaction["outputs"][index]["script_sha256"]
        elif predicate == "input-witness-vector-lengths": actual = ",".join(map(str, transaction["input_witness"][index]))
        elif predicate == "output-witness-vector-lengths": actual = ",".join(map(str, transaction["output_witness"][index]))
        else:
            if related not in fixtures: reject("fixture relation foreign key mismatch")
            left_txid, right_txid = properties[fixture_id]["txid_consensus_hex"], properties[related]["txid_consensus_hex"]
            actual = str(left_txid == right_txid if predicate == "same-txid" else left_txid != right_txid if predicate == "different-txid" else digest(fixtures[fixture_id]) != digest(fixtures[related])).lower()
            actual_relations.add((fixture_id, predicate, related))
        if actual != row["expected_value"] or (predicate in ("same-txid", "different-txid", "different-full-sha256")) != (related != "-"):
            reject("fixture assertion contradicts parsed public bytes")
    if actual_relations != required_relations:
        reject("fixture relation assertion coverage mismatch")
    required_properties = {
        ("test-candidate-damaged-proof", "input-witness-vector-lengths", "0,0"),
        ("test-candidate-damaged-proof", "output-witness-vector-lengths", "67,0"),
        ("test-candidate-valid", "input-witness-vector-lengths", "0,0"),
        ("test-candidate-valid", "output-witness-vector-lengths", "67,4174"),
        ("test-candidate-shared-previous-valid", "input-count", "2"),
        ("test-candidate-shared-previous-valid", "input-previous-vout", "1"),
        ("test-candidate-shared-previous-valid", "input-witness-vector-lengths", "0,0"),
        ("test-candidate-shared-previous-valid", "output-witness-vector-lengths", "99,4174"),
        ("test-previous-shared-valid", "output-count", "2"),
        ("test-candidate-explicit", "output-prefixes", "01,01,00"),
        ("test-candidate-unowned", "output-prefixes", "0a,08,03"),
        ("test-previous-witness-variant", "output-witness-vector-lengths", "0,4174"),
    }
    assertion_tuples = {(row["fixture_id"], row["predicate"], row["expected_value"]) for row in rows}
    if not required_properties <= assertion_tuples:
        reject("fixture parsed property coverage mismatch")


def validate_catalog_scripts(rows: list[dict[str, str]], catalogs: list[dict[str, str]]) -> None:
    expected = [
        ("catalog-main-0", "0", "0", "b29260f831b9fb678f1d429471d4fa37bdae7498a8ab04dc26fb0e6d116cc99a"),
        ("catalog-main-0", "1", "0", "3c6a2528e8f02f7fb8e761327ea6322223ba656b16c3075fcbf097ce78c39061"),
        ("catalog-test-0", "0", "0", "e0ad850821f9c4a6c60e064323c656b1323a2d3e79dec545da63fe64fb1afafe"),
        ("catalog-test-0", "1", "0", "3708b4a2b4d9947a01f84c6b51bcc638bef5d1b825d978f2c826a32ac7c4de2e"),
    ]
    if [tuple(row.values()) for row in rows] != expected or {row["catalog_fixture_id"] for row in rows} != {row["catalog_fixture_id"] for row in catalogs}:
        reject("catalog output script authority mismatch")


def validate_public_proof_cases(rows: list[dict[str, str]], fixture_rows: list[dict[str, str]]) -> None:
    expected = [
        ("main-valid", "main-candidate-valid", "main-previous-valid", "ok"),
        ("test-damaged-range-proof", "test-candidate-damaged-proof", "test-previous-valid", "range-proof-missing-0"),
        ("test-explicit-selected-amount-proof-valid", "test-candidate-explicit", "test-previous-valid", "ok"),
        ("test-shared-previous-valid", "test-candidate-shared-previous-valid", "test-previous-shared-valid", "ok"),
        ("test-unowned-selected-amount-proof-valid", "test-candidate-unowned", "test-previous-valid", "ok"),
        ("test-valid", "test-candidate-valid", "test-previous-valid", "ok"),
    ]
    fixture_ids = {row["fixture_id"] for row in fixture_rows}
    if [tuple(row.values()) for row in rows] != expected or any(row[1] not in fixture_ids or row[2] not in fixture_ids for row in expected):
        reject("public proof cases differ from exact verifier authority")


def validate_payload_bindings(rows: list[dict[str, str]], frames: dict[str, bytes], fixtures: dict[str, bytes], fixture_rows: list[dict[str, str]]) -> None:
    kinds = {row["fixture_id"]: row["fixture_kind"] for row in fixture_rows}
    expected = set()
    for frame_id, data in frames.items():
        try:
            value = raw_unpack(data)
        except CorpusError:
            continue
        for selected_index, selected in enumerate(value["selected"]):
            for fixture_id, fixture in fixtures.items():
                if kinds[fixture_id] == "candidate" and selected["candidate"] == fixture:
                    expected.add((frame_id, str(selected_index), "candidate", "-", fixture_id, "identity"))
                if kinds[fixture_id] == "candidate" and selected["candidate"] == fixture + b"\0":
                    expected.add((frame_id, str(selected_index), "candidate", "-", fixture_id, "append-zero"))
            for previous_index, previous in enumerate(selected["previous"]):
                for fixture_id, fixture in fixtures.items():
                    if kinds[fixture_id] == "previous" and previous == fixture:
                        expected.add((frame_id, str(selected_index), "previous", str(previous_index), fixture_id, "identity"))
    actual = {(row["frame_id"], row["selected_index"], row["payload_role"], row["previous_index"], row["fixture_id"], row["transform"]) for row in rows}
    if actual != expected or len(actual) != len(rows):
        reject("frame payload binding is not a closed bijection")
    for row in rows:
        if row["frame_id"] not in frames or row["fixture_id"] not in fixtures or row["payload_role"] not in ("candidate", "previous") or row["transform"] not in ("identity", "append-zero"):
            reject("frame payload binding schema mismatch")


def validate_frame_metadata(row: dict[str, str], value: dict) -> None:
    expected = [
        value["source"].hex(), str(value["revision"]), value["manifest"].hex(), value["pegged"].hex(),
        str(len(value["selected"])), str(len(value["destinations"])), str(value["aggregate"]), str(value["fee"]),
        ",".join(item["txid"].hex() for item in value["selected"]),
        ",".join(item["txid"][::-1].hex() for item in value["selected"]),
        ",".join(item["asset"].hex() for item in value["destinations"]),
        ",".join(item["address"].hex() for item in value["destinations"]),
        ",".join(digest(item["candidate"]) for item in value["selected"]) + "/" + ";".join(",".join(digest(previous) for previous in item["previous"]) or "-" for item in value["selected"]),
    ]
    keys = ["source_epoch_hex", "source_revision", "manifest_id_hex", "pegged_asset_consensus_hex", "selected_count", "destination_count", "aggregate_previous_count", "fee_value", "selected_txids_consensus_hex", "selected_txids_display_hex", "destination_assets_consensus_hex", "destination_addresses_hex", "payload_hash_manifest"]
    if [row[key] for key in keys] != expected:
        reject(f"exact frame field metadata mismatch: {row['frame_id']}")


def validate_frames(root: Path, rows: list[dict[str, str]]) -> tuple[dict[str, bytes], dict[str, dict | None]]:
    frame_bytes, unpacked = {}, {}
    for row in rows:
        if row["execution_class"] != "concrete-frame":
            reject("tracked frame has non-concrete execution class")
        relative = safe_relative(row["relative_path"])
        if relative.parts[0] != "frames" or relative.suffix != ".hex" or relative.stem != row["frame_id"]:
            reject("frame path does not bind frame identifier")
        data = parse_hex_file(root / VECTORS / relative)
        if str(len(data)) != row["decoded_length"] or digest(data) != row["decoded_sha256"]:
            reject(f"frame digest metadata mismatch: {row['frame_id']}")
        expected_source = bytes.fromhex(row["source_epoch_hex"]) if row["source_epoch_hex"] != "-" else bytes.fromhex("41" * 32)
        code, value = scan(data, expected_source)
        result = "ok" if code == 0 else "error"
        if result != row["structural_result"] or str(code) != row["structural_error_code"]:
            reject(f"independent structural result mismatch: {row['frame_id']}")
        fields = [row[key] for key in ("source_epoch_hex", "source_revision", "manifest_id_hex", "pegged_asset_consensus_hex", "selected_count", "destination_count", "aggregate_previous_count", "fee_value", "selected_txids_consensus_hex", "selected_txids_display_hex", "destination_assets_consensus_hex", "destination_addresses_hex", "payload_hash_manifest")]
        if value is None and any(field != "-" for field in fields):
            value = raw_unpack(data)
        if value is not None:
            if pack_manual(value) != data:
                reject(f"independent re-pack mismatch: {row['frame_id']}")
            validate_frame_metadata(row, value)
        frame_bytes[row["frame_id"]] = data
        unpacked[row["frame_id"]] = value
    return frame_bytes, unpacked


def logical_diff(left: dict, right: dict) -> set[str]:
    changes = set()
    for key in ("source", "revision", "manifest", "pegged", "fee"):
        if left[key] != right[key]:
            changes.add(f"header.{key}")
    if len(left["selected"]) != len(right["selected"]):
        changes.add("selected.count")
    elif left["selected"] != right["selected"]:
        if left["selected"] == list(reversed(right["selected"])):
            changes.add("selected.order")
        else:
            for index, (a, b) in enumerate(zip(left["selected"], right["selected"])):
                for key in ("txid", "vout", "asset", "value", "candidate", "previous"):
                    if a[key] != b[key]:
                        changes.add(f"selected.{index}.{key}")
    if len(left["destinations"]) != len(right["destinations"]):
        changes.add("destination.count")
    else:
        for index, (a, b) in enumerate(zip(left["destinations"], right["destinations"])):
            for key in ("asset", "value", "address"):
                if a[key] != b[key]:
                    changes.add(f"destination.{index}.{key}")
    return changes


def validate_mutations(rows: list[dict[str, str]], frames: dict[str, bytes], frame_rows: list[dict[str, str]]) -> None:
    by_frame = {row["frame_id"]: row for row in frame_rows}
    by_mutation = {row["mutation_id"]: row for row in rows}
    derived = {row["frame_id"] for row in frame_rows if row["parent_frame_id"] != "-"}
    if derived != {row["child_frame_id"] for row in rows} or set(by_mutation) != {row["mutation_id"] for row in frame_rows if row["mutation_id"] != "-"}:
        reject("mutation/frame lineage is not bijective")
    for row in frame_rows:
        if (row["parent_frame_id"] == "-") != (row["mutation_id"] == "-"):
            reject("partial mutation lineage")
    for row in rows:
        parent_id, child_id = row["parent_frame_id"], row["child_frame_id"]
        if parent_id not in frames or child_id not in frames or by_frame[child_id]["parent_frame_id"] != parent_id or by_frame[child_id]["mutation_id"] != row["mutation_id"]:
            reject("mutation foreign-key mismatch")
        parent, child = frames[parent_id], frames[child_id]
        kind = row["mutation_kind"]
        if kind == "replace":
            if row["target"] != "bytes" or not DECIMAL.fullmatch(row["offset"]) or not LOWER_HEX.fullmatch(row["old_hex"]) or not LOWER_HEX.fullmatch(row["new_hex"]):
                reject("malformed replace mutation")
            old, new, offset = bytes.fromhex(row["old_hex"]), bytes.fromhex(row["new_hex"]), int(row["offset"])
            if len(old) != len(new) or parent[offset : offset + len(old)] != old or parent[:offset] + new + parent[offset + len(old) :] != child:
                reject("replace mutation lineage mismatch")
        elif kind == "append":
            if row["old_hex"] != "-" or not LOWER_HEX.fullmatch(row["new_hex"]) or row["offset"] != str(len(parent)) or parent + bytes.fromhex(row["new_hex"]) != child:
                reject("append mutation lineage mismatch")
        elif kind == "truncate":
            if row["new_hex"] != "-" or not DECIMAL.fullmatch(row["offset"]) or not LOWER_HEX.fullmatch(row["old_hex"]):
                reject("malformed truncate mutation")
            offset = int(row["offset"])
            if child != parent[:offset] or bytes.fromhex(row["old_hex"]) != parent[offset:]:
                reject("truncate mutation lineage mismatch")
        elif kind == "logical-repack":
            if row["offset"] != row["old_hex"] != row["new_hex"] or row["offset"] != "-":
                reject("logical mutation must not carry byte edit fields")
            left, right = raw_unpack(parent), raw_unpack(child)
            changes = logical_diff(left, right)
            target = row["target"]
            aliases = {
                "header.manifest": {"header.manifest"}, "header.pegged": {"header.pegged"},
                "selected.1.txid": {"selected.1.txid"}, "selected.order": {"selected.order"},
                "selected.0.previous": {"selected.0.previous"}, "selected.0.value": {"selected.0.value"},
                "selected.0.txid": {"selected.0.txid"}, "selected.0.output-index": {"selected.0.vout"},
                "selected.0.candidate": {"selected.0.candidate"},
                "selected.0.candidate-and-txid": {"selected.0.candidate", "selected.0.txid"},
                "destination.0.address": {"destination.0.address"}, "destination.0.asset": {"destination.0.asset"},
                "destination.0.value": {"destination.0.value"},
            }
            if target not in aliases or not changes or not changes <= aliases[target] or (target == "selected.0.candidate-and-txid" and "selected.0.candidate" not in changes):
                reject(f"logical mutation target mismatch: {row['mutation_id']}")
            if pack_manual(right) != child:
                reject("logical mutation child is not independently packable")
        else:
            reject("unknown mutation kind")


def evaluate_formula(value: str) -> tuple[str, int | None]:
    if not FORMULA.fullmatch(value):
        reject("noncanonical boundary formula")
    total = 0
    for term in value.split("+"):
        product = 1
        for factor in term.split("*"):
            product *= int(factor)
            if product > (1 << 64) - 1:
                return "overflow", None
        total += product
        if total > (1 << 64) - 1:
            return "overflow", None
    return "value", total


def boundary_outcome(row: dict[str, str]) -> tuple[str, int | None, str, int, str]:
    kind, value = evaluate_formula(row["formula"])
    boundary_kind = row["boundary_kind"]
    limits = {
        "selected-count": ("max-selected-inputs", 1, MAX_SELECTED),
        "destination-count": ("max-confidential-destinations", 1, MAX_DESTINATIONS),
        "address-length": ("max-destination-address-bytes", 1, MAX_ADDRESS),
        "candidate-transaction-length": ("max-transaction-payload-bytes", 1, MAX_TRANSACTION),
        "previous-transaction-length": ("max-transaction-payload-bytes", 1, MAX_TRANSACTION),
        "row-previous-count": ("max-previous-transaction-entries", 0, MAX_PREVIOUS),
        "aggregate-previous-count": ("max-previous-transaction-entries", 0, MAX_PREVIOUS),
        "aggregate-transaction-bytes": ("max-aggregate-transaction-bytes", 1, MAX_TRANSACTION_BYTES),
        "output-index": ("max-spendable-output-index", 0, MAX_OUTPUT_INDEX),
        "selected-value": ("max-plan-value", 1, MAX_VALUE),
        "destination-value": ("max-plan-value", 1, MAX_VALUE),
        "fee-value": ("max-plan-value", 1, MAX_VALUE),
    }
    if boundary_kind in limits:
        production_constant, minimum, maximum = limits[boundary_kind]
        if row["production_constant"] != production_constant or kind != "value" or value is None:
            reject("boundary limit recipe mismatch")
        result, code = ("ok", 0) if minimum <= value <= maximum else ("error", 4)
        return kind, value, result, code, "deterministic-generated"
    if boundary_kind == "required-numeric":
        if row["production_constant"] != "none" or kind != "value" or value != 0:
            reject("required-numeric boundary recipe mismatch")
        return kind, value, "error", 4, "concrete-frame"
    if boundary_kind == "aggregate-equality":
        if row["production_constant"] != "max-previous-transaction-entries" or kind != "value":
            reject("aggregate-equality boundary recipe mismatch")
        return kind, value, "error", 3, "concrete-frame"
    if boundary_kind == "reachable-maximum":
        if row["production_constant"] != "max-reachable-request-bytes" or kind != "value" or value != MAX_REACHABLE:
            reject("reachable-maximum boundary recipe mismatch")
        return kind, value, "ok", 0, "symbolic-only"
    if boundary_kind == "outer-ceiling":
        if row["production_constant"] != "max-request-frame-bytes" or kind != "value" or value is None:
            reject("outer-ceiling boundary recipe mismatch")
        result, code = ("ok", 0) if value <= MAX_FRAME else ("error", 4)
        return kind, value, result, code, "symbolic-only"
    if boundary_kind == "overflow":
        if row["production_constant"] != "none" or kind != "overflow":
            reject("overflow boundary recipe mismatch")
        return kind, None, "overflow", 4, "symbolic-only"
    reject("unknown boundary kind")


def boundary_authority() -> dict[str, tuple[str, ...]]:
    result: dict[str, tuple[str, ...]] = {}
    limits = (
        ("selected-inputs", "selected-count", "max-selected-inputs", 1, MAX_SELECTED),
        ("destinations", "destination-count", "max-confidential-destinations", 1, MAX_DESTINATIONS),
        ("address-bytes", "address-length", "max-destination-address-bytes", 1, MAX_ADDRESS),
        ("candidate-transaction-bytes", "candidate-transaction-length", "max-transaction-payload-bytes", 1, MAX_TRANSACTION),
        ("previous-transaction-bytes", "previous-transaction-length", "max-transaction-payload-bytes", 1, MAX_TRANSACTION),
        ("row-previous-entries", "row-previous-count", "max-previous-transaction-entries", 0, MAX_PREVIOUS),
        ("aggregate-previous-entries", "aggregate-previous-count", "max-previous-transaction-entries", 0, MAX_PREVIOUS),
        ("expanded-transaction-bytes", "aggregate-transaction-bytes", "max-aggregate-transaction-bytes", 1, MAX_TRANSACTION_BYTES),
        ("output-index", "output-index", "max-spendable-output-index", 0, MAX_OUTPUT_INDEX),
        ("selected-value", "selected-value", "max-plan-value", 1, MAX_VALUE),
        ("destination-value", "destination-value", "max-plan-value", 1, MAX_VALUE),
        ("fee-value", "fee-value", "max-plan-value", 1, MAX_VALUE),
    )
    for prefix, kind, production_constant, minimum, maximum in limits:
        for suffix, formula, coverage in (
            ("minimum", str(minimum), "minimum"),
            ("maximum", str(maximum), "maximum"),
            ("plus-one", f"{maximum}+1", "plus-one"),
        ):
            identifier = f"{prefix}-{suffix}"
            value = minimum if suffix == "minimum" else maximum if suffix == "maximum" else maximum + 1
            status, code = ("error", "4") if suffix == "plus-one" else ("ok", "0")
            result[identifier] = ("decode", kind, production_constant, "u64", formula, "deterministic-generated", status, str(value), code, coverage)
    result.update({
        "required-numeric-zero": ("decode", "required-numeric", "none", "u64", "0", "concrete-frame", "error", "0", "4", "count-length-value"),
        "aggregate-in-range-undercount": ("decode", "aggregate-equality", "max-previous-transaction-entries", "u32", "3", "concrete-frame", "error", "3", "3", "undercount"),
        "aggregate-in-range-overcount": ("decode", "aggregate-equality", "max-previous-transaction-entries", "u32", "0+1", "concrete-frame", "error", "1", "3", "overcount"),
        "reachable-frame-maximum": ("checked-arithmetic", "reachable-maximum", "max-reachable-request-bytes", "usize64", "152+100*88+255*48+255*256+16384*4+67108864", "symbolic-only", "ok", str(MAX_REACHABLE), "0", "exact-formula"),
        "outer-rejection-ceiling": ("outer-length", "outer-ceiling", "max-request-frame-bytes", "usize64", str(MAX_FRAME), "symbolic-only", "ok", str(MAX_FRAME), "0", "rejection-only"),
        "outer-rejection-plus-one": ("outer-length", "outer-ceiling", "max-request-frame-bytes", "usize64", f"{MAX_FRAME}+1", "symbolic-only", "error", str(MAX_FRAME + 1), "4", "plus-one"),
        "checked-add-overflow": ("checked-arithmetic", "overflow", "none", "u64", "18446744073709551615+1", "symbolic-only", "overflow", "-", "4", "addition"),
        "checked-multiply-overflow": ("checked-arithmetic", "overflow", "none", "u64", "18446744073709551615*2", "symbolic-only", "overflow", "-", "4", "multiplication"),
    })
    return result


def validate_boundaries(rows: list[dict[str, str]]) -> None:
    authority = boundary_authority()
    if {row["boundary_id"] for row in rows} != set(authority):
        reject("boundary identifier coverage mismatch")
    required_constants = {"max-selected-inputs", "max-confidential-destinations", "max-destination-address-bytes", "max-transaction-payload-bytes", "max-previous-transaction-entries", "max-aggregate-transaction-bytes", "max-spendable-output-index", "max-plan-value", "max-reachable-request-bytes", "max-request-frame-bytes", "none"}
    if {row["production_constant"] for row in rows} != required_constants:
        reject("boundary constant coverage mismatch")
    required_classes = {"concrete-frame", "deterministic-generated", "symbolic-only"}
    if {row["execution_class"] for row in rows} != required_classes:
        reject("boundary execution classes incomplete")
    for row in rows:
        if row["source_model_id"] != f"model-boundary-{row['boundary_id']}":
            reject("boundary source-model foreign key is not canonical")
        actual = tuple(row[field] for field in (
            "operation", "boundary_kind", "production_constant", "numeric_domain", "formula",
            "execution_class", "expected_status", "expected_value", "expected_error_code", "coverage",
        ))
        if actual != authority[row["boundary_id"]]:
            reject("boundary row differs from its exact derived authority")
        kind, value, result, code, execution = boundary_outcome(row)
        expected_value = "-" if value is None else str(value)
        if (row["expected_status"], row["expected_value"], row["expected_error_code"], row["execution_class"]) != (result, expected_value, str(code), execution):
            reject("boundary contradicts independently derived outcome")
    reachable = next(row for row in rows if row["boundary_id"] == "reachable-frame-maximum")
    if reachable["expected_value"] != str(MAX_REACHABLE) or reachable["formula"] != "152+100*88+255*48+255*256+16384*4+67108864":
        reject("reachable maximum arithmetic mismatch")


def validate_cases(rows: list[dict[str, str]], frames: dict[str, bytes], frame_rows: list[dict[str, str]], catalogs: list[dict[str, str]]) -> None:
    partitions = {
        "shared-encoder": ("encode", "managed+native"),
        "managed-funding-row": ("funding-row-create", "managed"),
        "managed-funding-batch": ("funding-batch-create", "managed"),
        "managed-encoder": ("encode", "managed"),
        "native-raw-encoder": ("encode", "native"),
        "native-decoder": ("decode", "native"),
        "native-reencode": ("reencode", "native"),
        "native-prepare": ("prepare", "native"),
    }
    if {row["partition"] for row in rows} != set(partitions):
        reject("operation partitions incomplete")
    if {row["frame_id"] for row in rows if row["frame_id"] != "-"} != set(frames):
        reject("concrete frame topology has an unconsumed frame")
    accepted_frame_ids = {
        row["frame_id"] for row in frame_rows if row["structural_result"] == "ok"
    }
    reencode_frame_ids = [
        row["frame_id"] for row in rows if row["partition"] == "native-reencode"
    ]
    if (
        len(reencode_frame_ids) != len(set(reencode_frame_ids))
        or set(reencode_frame_ids) != accepted_frame_ids
    ):
        reject("native reencode coverage does not exactly match structurally accepted frames")
    required_native_structural = {
        "native-encode-non-ascii-address": "model-native-encode-non-ascii-address",
        "native-encode-ordering-unknown-context": "model-native-encode-ordering-unknown-context",
        "native-encode-previous-out-of-order": "model-native-encode-previous-out-of-order",
        "native-encode-selected-duplicate": "model-native-encode-selected-duplicate",
        "native-encode-zero-destination-asset": "model-native-encode-zero-destination-asset",
        "native-encode-zero-manifest": "model-native-encode-zero-manifest",
        "native-encode-zero-pegged-asset": "model-native-encode-zero-pegged-asset",
        "native-encode-zero-selected-asset": "model-native-encode-zero-selected-asset",
        "native-encode-zero-selected-txid": "model-native-encode-zero-selected-txid",
    }
    actual_native_structural = {
        row["case_id"]: row["source_model_id"]
        for row in rows
        if row["partition"] == "native-raw-encoder" and row["expected_error_code"] == "3"
    }
    if actual_native_structural != required_native_structural:
        reject("native raw encoder structural coverage differs from production predicates")
    catalog_ids = {row["catalog_fixture_id"] for row in catalogs}
    for row in rows:
        if row["partition"] not in partitions or (row["operation"], row["implementation"]) != partitions[row["partition"]]:
            reject("case escaped its operation partition")
        if row["execution_class"] not in ("concrete-frame", "deterministic-generated", "symbolic-only"):
            reject("invalid case execution class")
        if row["partition"] in ("shared-encoder", "managed-funding-row", "managed-funding-batch", "managed-encoder", "native-raw-encoder"):
            if not LOWER_HASH.fullmatch(row["expected_source_epoch_hex"]):
                reject("source-only encoder/factory case lacks exact epoch bytes")
            if row["source_model_id"] == "model-zero-epoch" and row["expected_source_epoch_hex"] != "00" * 32:
                reject("zero-epoch source model does not carry exact zero bytes")
            if row["partition"] == "shared-encoder" and row["frame_id"] != "-" and row["expected_source_epoch_hex"] != frames[row["frame_id"]][24:56].hex():
                reject("shared encoder case epoch does not match projected frame")
            if row["partition"] in ("managed-funding-row", "managed-funding-batch", "managed-encoder", "native-raw-encoder") and row["expected_source_epoch_hex"] != TEST_SOURCE_EPOCH:
                reject("canonical source-only model epoch mismatch")
        if row["expected_result"] not in ("ok", "error", "lifecycle") or not DECIMAL.fullmatch(row["expected_error_code"]):
            reject("invalid case result")
        code = int(row["expected_error_code"])
        if (row["expected_result"] == "error") != (code != 0) or row["expected_result"] == "lifecycle" and code != 0:
            reject("case error code/result mismatch")
        if row["frame_id"] != "-" and row["frame_id"] not in frames:
            reject("case frame foreign key mismatch")
        if row["expected_reencode_frame_id"] != "-" and row["expected_reencode_frame_id"] not in frames:
            reject("case reencode frame foreign key mismatch")
        if row["catalog_fixture_id"] != "-" and row["catalog_fixture_id"] not in catalog_ids:
            reject("case catalog foreign key mismatch")
        if row["partition"] == "native-prepare":
            if row["frame_id"] == "-" or row["catalog_fixture_id"] == "-" or row["expected_source_epoch_hex"] == "-":
                reject("prepare case lacks exact frame, epoch, or catalog")
            if row["expected_source_epoch_hex"] != frames[row["frame_id"]][24:56].hex():
                reject("prepare case epoch does not match its frame")
        elif row["catalog_fixture_id"] != "-":
            reject("catalog assigned outside prepare")
        if row["partition"] == "native-reencode":
            if (
                row["expected_result"] != "ok"
                or row["expected_reencode_frame_id"] != row["frame_id"]
                or row["expected_source_epoch_hex"] != frames[row["frame_id"]][24:56].hex()
            ):
                reject("reencode partition is not success-only byte identity")
        if row["partition"] == "shared-encoder" and row["expected_result"] == "error" and not (row["case_id"] == "shared-encode-zero-epoch" and code == 1):
            reject("shared encoder has an unauthorized negative")
        if row["partition"] in ("managed-funding-row", "managed-funding-batch", "managed-encoder", "native-raw-encoder") and row["source_model_id"] == "-":
            reject("source-only case lacks model identity")
        if row["partition"] == "native-decoder":
            expected = bytes.fromhex(row["expected_source_epoch_hex"])
            if row["frame_id"] != "-":
                actual, _ = scan(frames[row["frame_id"]], expected)
            elif row["source_model_id"] == "model-outer-before-discriminator":
                actual = 4 if 268_435_457 > MAX_FRAME else 2
            else:
                reject("decoder case has neither concrete nor reviewed generated source")
            if actual != code:
                reject(f"decoder case does not match independent scanner: {row['case_id']}")
    tags = ",".join(row["coverage_tags"] for row in rows)
    required_tags = {
        "mainnet", "testnet", "multiasset-exact-balance", "repeated-candidate-payload", "empty-previous",
        "display-txid-order", "previous-byte-order", "destination-caller-order", "source-binding", "combined-defect",
        "unknown-manifest", "pegged-asset-mismatch", "catalog-network-mismatch", "wrong-address-profile",
        "malformed-address", "nonconfidential-address", "noncanonical-address", "declared-asset-conservation",
        "declared-value-conservation", "candidate-id-mismatch", "public-output-index-mismatch", "missing-previous",
        "extra-previous", "duplicate-previous-identity", "candidate-noncanonical", "amount-proof-failure",
        "descriptor-nonownership", "public-output-shape",
    }
    if not all(tag in tags for tag in required_tags):
        reject("case semantic coverage incomplete")
    if any(term in tags.lower() for term in ("confidential-selected-mismatch", "provider-opening", "regtest", "sponsor", "usdt-coinjoin")):
        reject("deferred semantic surface entered corpus cases")


def validate_case_bindings(rows: list[dict[str, str]], frames: dict[str, bytes], catalogs: list[dict[str, str]], models: list[dict[str, str]], source_outputs: dict[str, str]) -> None:
    model_by_id = {row["source_model_id"]: row for row in models}
    catalog_by_id = {row["catalog_fixture_id"]: row for row in catalogs}
    for row in rows:
        if row["frame_id"] != "-" and row["source_model_id"] != "-":
            input_identity = digest(("wlpq-frame-model-input-v1\0" + digest(frames[row["frame_id"]]) + "\0" + model_by_id[row["source_model_id"]]["decoded_sha256"]).encode())
        elif row["frame_id"] != "-":
            input_identity = digest(frames[row["frame_id"]])
        else:
            input_identity = model_by_id[row["source_model_id"]]["decoded_sha256"]
        output_identity = "-"
        if row["source_model_id"] in source_outputs:
            output_identity = source_outputs[row["source_model_id"]]
        elif row["expected_reencode_frame_id"] != "-":
            output_identity = digest(frames[row["expected_reencode_frame_id"]])
        if row["catalog_fixture_id"] == "-":
            catalog_identity = "-"
        else:
            catalog = catalog_by_id[row["catalog_fixture_id"]]
            catalog_identity = digest(("wlpq-catalog-v1\0" + row["catalog_fixture_id"] + "\0" + "\0".join((catalog["context_id"], catalog["descriptor_network"], catalog["inclusive_last_derivation_index"], catalog["checksummed_public_descriptor"]))).encode())
        fields = (
            "wlpq-case-binding-v1", row["case_id"], row["partition"], row["operation"], row["implementation"], row["execution_class"],
            input_identity, row["expected_source_epoch_hex"], catalog_identity, row["expected_result"], row["expected_error_code"], output_identity,
        )
        binding = digest("\0".join(fields).encode())
        if (row["input_identity_sha256"], row["expected_output_sha256"], row["case_binding_sha256"]) != (input_identity, output_identity, binding):
            reject("case identity or output binding mismatch")


def canonical_model_object(root: Path, row: dict[str, str]) -> dict:
    relative = safe_relative(row["relative_path"])
    if relative.parts[0] != "source-models" or relative.suffix != ".json" or relative.stem != row["source_model_id"]:
        reject("source model path does not bind its identifier")
    data = (root / VECTORS / relative).read_bytes()
    if str(len(data)) != row["decoded_length"] or digest(data) != row["decoded_sha256"]:
        reject("source model object digest metadata mismatch")
    if data.startswith(b"\xef\xbb\xbf") or b"\r" in data or not data.endswith(b"\n"):
        reject("source model object is not canonical LF JSON")
    try:
        value = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError):
        reject("source model object is invalid JSON")
    if not isinstance(value, dict) or (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode() != data:
        reject("source model object is not canonical JSON")
    return value


def exact_keys(value: dict, keys: set[str], label: str) -> None:
    if not isinstance(value, dict) or set(value) != keys:
        reject(f"{label} object schema mismatch")


def strict_value_equal(left, right) -> bool:
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return set(left) == set(right) and all(strict_value_equal(left[key], right[key]) for key in left)
    if isinstance(left, list):
        return len(left) == len(right) and all(strict_value_equal(a, b) for a, b in zip(left, right))
    return left == right


class ByteView:
    def __init__(self, length: int, literal: bytes | None = None, fill: int = 0):
        if type(length) is not int or length < 0 or type(fill) is not int or fill not in range(256):
            reject("invalid sparse byte view")
        self.length = length
        self.literal = literal
        self.fill = fill
        if literal is not None and len(literal) != length:
            reject("literal byte view length mismatch")

    @classmethod
    def from_bytes(cls, value: bytes) -> "ByteView":
        return cls(len(value), bytes(value))

    def byte_at(self, index: int) -> int:
        if not 0 <= index < self.length:
            reject("byte view index out of range")
        return self.literal[index] if self.literal is not None else self.fill

    def compare(self, other: "ByteView") -> int:
        common = min(self.length, other.length)
        if self.literal is None and other.literal is None:
            if self.fill != other.fill and common:
                return -1 if self.fill < other.fill else 1
        else:
            for index in range(common):
                left, right = self.byte_at(index), other.byte_at(index)
                if left != right:
                    return -1 if left < right else 1
        return (self.length > other.length) - (self.length < other.length)

    def identity(self) -> tuple:
        return (self.length, self.literal, self.fill)

    def materialize(self, maximum_length: int) -> bytes:
        if self.length > maximum_length:
            reject("byte view exceeds bounded materialization")
        return self.literal if self.literal is not None else bytes([self.fill]) * self.length


class IndexedU32BeFill:
    def get(self, index: int) -> ByteView:
        if type(index) is not int or not 0 <= index <= (1 << 32) - 1:
            reject("indexed u32be fill index is out of range")
        return ByteView.from_bytes(index.to_bytes(4, "big"))

    def identity(self) -> tuple[str]:
        return ("indexed-u32be",)


class ListView:
    def __init__(self, items: list, length: int | None = None, fill=None, overrides: dict[int, object] | None = None):
        if not isinstance(items, list) or length is not None and type(length) is not int:
            reject("invalid sparse list view")
        self.items = list(items)
        self.length = len(items) if length is None else length
        self.fill = fill
        self.overrides = dict(overrides or {})
        if self.length < 0 or self.length < len(self.items) or self.length > len(self.items) and fill is None:
            reject("invalid sparse list view")
        if any(type(index) is not int or index < len(self.items) or index >= self.length for index in self.overrides):
            reject("invalid sparse list override")

    def get(self, index: int):
        if not 0 <= index < self.length:
            reject("list view index out of range")
        if index < len(self.items):
            return self.items[index]
        if index in self.overrides:
            return self.overrides[index]
        if isinstance(self.fill, IndexedU32BeFill):
            return self.fill.get(index)
        return clone_value(self.fill)

    def set(self, index: int, value) -> None:
        if not 0 <= index < self.length:
            reject("list view index out of range")
        if index < len(self.items):
            self.items[index] = value
        else:
            self.overrides[index] = value

    def resize(self, length: int, fill) -> None:
        if not isinstance(length, int) or length < 0 or length == self.length:
            reject("invalid or no-op list resize")
        if length < len(self.items):
            self.items = self.items[:length]
        self.overrides = {index: value for index, value in self.overrides.items() if index < length}
        self.length, self.fill = length, clone_value(fill)

    def identity(self) -> tuple:
        return (self.length, tuple(value_identity(item) for item in self.items), tuple((index, value_identity(value)) for index, value in sorted(self.overrides.items())), value_identity(self.fill))


class VirtualFrame:
    def __init__(self, length: int, poison: bool):
        if type(length) is not int or length < 0 or type(poison) is not bool:
            reject("invalid virtual decoder frame")
        self.length, self.poison, self.reads = length, poison, 0

    def read_at(self, _offset: int, _length: int) -> bytes:
        self.reads += 1
        if self.poison:
            reject("outer-limit decoder read poisoned bytes")
        return b""


def clone_value(value):
    if isinstance(value, ByteView):
        return ByteView(value.length, value.literal, value.fill)
    if isinstance(value, ListView):
        return ListView([clone_value(item) for item in value.items], value.length, clone_value(value.fill), {index: clone_value(item) for index, item in value.overrides.items()})
    if isinstance(value, IndexedU32BeFill):
        return IndexedU32BeFill()
    if isinstance(value, dict):
        return {key: clone_value(item) for key, item in value.items()}
    return value


def value_identity(value):
    if isinstance(value, (ByteView, IndexedU32BeFill, ListView)):
        return value.identity()
    if isinstance(value, dict):
        return tuple((key, value_identity(item)) for key, item in sorted(value.items()))
    return value


def bytes_from_spec(spec: dict, fixtures: dict[str, bytes], maximum_length: int) -> ByteView:
    if not isinstance(spec, dict) or "kind" not in spec:
        reject("byte operation lacks a typed byte view")
    if spec["kind"] == "literal" and set(spec) == {"kind", "hex"} and isinstance(spec["hex"], str) and LOWER_HEX.fullmatch(spec["hex"]) and len(spec["hex"]) % 2 == 0:
        value = bytes.fromhex(spec["hex"])
        if len(value) > maximum_length: reject("typed byte view exceeds its field limit")
        return ByteView.from_bytes(value)
    if spec["kind"] == "fixture" and set(spec) == {"kind", "fixture_id"} and isinstance(spec["fixture_id"], str) and spec["fixture_id"] in fixtures:
        value = fixtures[spec["fixture_id"]]
        if len(value) > maximum_length: reject("typed byte view exceeds its field limit")
        return ByteView.from_bytes(value)
    if spec["kind"] == "repeat" and set(spec) == {"kind", "byte_hex", "length"} and isinstance(spec["byte_hex"], str) and re.fullmatch(r"[0-9a-f]{2}", spec["byte_hex"]) and type(spec["length"]) is int and 0 <= spec["length"] <= maximum_length:
        return ByteView(spec["length"], fill=int(spec["byte_hex"], 16))
    reject("unsupported or noncanonical byte view")


def request_from_frame(data: bytes) -> dict:
    value = raw_unpack(data)
    return {
        "source_epoch": ByteView.from_bytes(value["source"]), "revision": value["revision"],
        "manifest": ByteView.from_bytes(value["manifest"]), "pegged_asset": ByteView.from_bytes(value["pegged"]),
        "fee": value["fee"],
        "selected": ListView([{
            "txid": ByteView.from_bytes(row["txid"]), "vout": row["vout"], "asset": ByteView.from_bytes(row["asset"]),
            "value": row["value"], "candidate": ByteView.from_bytes(row["candidate"]),
            "previous": ListView([ByteView.from_bytes(item) for item in row["previous"]]), "lifecycle": "active",
        } for row in value["selected"]]),
        "destinations": ListView([{"asset": ByteView.from_bytes(row["asset"]), "value": row["value"], "address": ByteView.from_bytes(row["address"])} for row in value["destinations"]]),
    }


def pack_request_view(request: dict) -> bytes:
    if request["selected"].length > MAX_SELECTED or request["destinations"].length > MAX_DESTINATIONS:
        reject("request view exceeds bounded packing")
    selected = []
    for index in range(request["selected"].length):
        row = request["selected"].get(index)
        if row["previous"].length > MAX_PREVIOUS:
            reject("request previous list exceeds bounded packing")
        selected.append({
            "txid": row["txid"].materialize(32), "vout": row["vout"], "asset": row["asset"].materialize(32),
            "value": row["value"], "candidate": row["candidate"].materialize(MAX_TRANSACTION),
            "previous": [row["previous"].get(item).materialize(MAX_TRANSACTION) for item in range(row["previous"].length)],
        })
    destinations = []
    for index in range(request["destinations"].length):
        row = request["destinations"].get(index)
        destinations.append({
            "asset": row["asset"].materialize(32), "value": row["value"],
            "address": row["address"].materialize(MAX_ADDRESS),
        })
    return pack_manual({
        "source": request["source_epoch"].materialize(32), "revision": request["revision"],
        "manifest": request["manifest"].materialize(32), "pegged": request["pegged_asset"].materialize(32),
        "fee": request["fee"], "selected": selected, "destinations": destinations,
    })


PATH = re.compile(r"(?:request\.(?:source_epoch|revision|manifest|pegged_asset|fee|selected|destinations)|request\.selected\[(?:0|[1-9][0-9]*)\](?:\.(?:txid|vout|asset|value|candidate|previous)(?:\[(?:0|[1-9][0-9]*)\])?)?|request\.destinations\[(?:0|[1-9][0-9]*)\](?:\.(?:asset|value|address))?|row\.(?:candidate|previous)(?:\[(?:0|[1-9][0-9]*)\])?|batch\.(?:plan|rows)(?:\[(?:0|[1-9][0-9]*)\](?:\.(?:candidate|previous)(?:\[(?:0|[1-9][0-9]*)\])?)?)?|call\.(?:source_epoch|plan|batch))\Z")


def declared_path_type(path: str) -> str:
    if re.fullmatch(r"(?:request\.(?:source_epoch|manifest|pegged_asset)|request\.selected\[[0-9]+\]\.(?:txid|asset|candidate)|request\.selected\[[0-9]+\]\.previous\[[0-9]+\]|request\.destinations\[[0-9]+\]\.(?:asset|address)|row\.candidate|row\.previous\[[0-9]+\]|batch\.rows\[[0-9]+\]\.(?:candidate)|batch\.rows\[[0-9]+\]\.previous\[[0-9]+\]|call\.source_epoch)", path):
        return "bytes"
    if re.fullmatch(r"request\.(?:revision|fee)|request\.selected\[[0-9]+\]\.(?:vout|value)|request\.destinations\[[0-9]+\]\.value", path):
        return "u64"
    if re.fullmatch(r"request\.(?:selected|destinations)|request\.selected\[[0-9]+\]\.previous|row\.previous|batch\.rows|batch\.rows\[[0-9]+\]\.previous", path):
        return "list"
    if re.fullmatch(r"request\.selected\[[0-9]+\]|batch\.rows\[[0-9]+\]", path):
        return "row"
    if re.fullmatch(r"request\.destinations\[[0-9]+\]", path):
        return "destination"
    if path in ("batch.plan", "call.plan"):
        return "plan"
    if path == "call.batch":
        return "batch"
    reject("source operation path has no declared type")


def list_path_limit(path: str) -> int:
    if path == "request.selected" or path == "batch.rows":
        return MAX_SELECTED + 1
    if path == "request.destinations":
        return MAX_DESTINATIONS + 1
    if path == "row.previous" or re.fullmatch(r"(?:request\.selected|batch\.rows)\[[0-9]+\]\.previous", path):
        return MAX_PREVIOUS + 1
    reject("source list path has no allocation limit")


def byte_path_limit(path: str) -> tuple[int, int]:
    if path in ("request.manifest", "request.pegged_asset") or re.fullmatch(r"request\.selected\[[0-9]+\]\.(?:txid|asset)|request\.destinations\[[0-9]+\]\.asset", path):
        return 32, 32
    if path in ("request.source_epoch", "call.source_epoch"):
        return 0, 33
    if path in ("row.candidate",) or re.fullmatch(r"(?:request\.selected|batch\.rows)\[[0-9]+\]\.candidate", path):
        return 0, MAX_TRANSACTION + 1
    if re.fullmatch(r"(?:row\.previous|request\.selected\[[0-9]+\]\.previous|batch\.rows\[[0-9]+\]\.previous)\[[0-9]+\]", path):
        return 0, MAX_TRANSACTION + 1
    if re.fullmatch(r"request\.destinations\[[0-9]+\]\.address", path):
        return 0, MAX_ADDRESS + 1
    reject("source byte path has no field limit")


def resolve_path(state: dict, path: str) -> tuple[object, str | int]:
    if not isinstance(path, str) or len(path) > 256 or not PATH.fullmatch(path):
        reject("source operation path is noncanonical or undeclared")
    parts = re.findall(r"[a-z_]+|\[(\d+)\]", path)
    tokens: list[str | int] = []
    cursor = 0
    for match in re.finditer(r"[a-z_]+|\[(\d+)\]", path):
        tokens.append(int(match.group(1)) if match.group(1) is not None else match.group(0))
        cursor = match.end()
    if cursor != len(path):
        reject("source operation path parsing mismatch")
    current: object = state
    for token in tokens[:-1]:
        if isinstance(token, int):
            if not isinstance(current, ListView): reject("source path indexes a non-list")
            item = current.get(token)
            if token >= len(current.items):
                current.set(token, item)
            current = item
        else:
            if not isinstance(current, dict) or token not in current: reject("source path field is absent")
            current = current[token]
        if current is None:
            reject("source path traverses null")
    return current, tokens[-1]


def get_child(parent, key):
    if isinstance(key, int):
        if not isinstance(parent, ListView): reject("source path final index is not a list")
        return parent.get(key)
    if not isinstance(parent, dict) or key not in parent: reject("source path final field is absent")
    return parent[key]


def set_child(parent, key, value) -> None:
    if isinstance(key, int):
        if not isinstance(parent, ListView): reject("source path final index is not a list")
        parent.set(key, value)
    else:
        if not isinstance(parent, dict) or key not in parent: reject("source path final field is absent")
        parent[key] = value


def apply_source_operations(state: dict, operations: list, fixtures: dict[str, bytes], schema: str, model_id: str) -> None:
    if not isinstance(operations, list) or len(operations) > 1024:
        reject("source object operations are not a list")
    allowed = {"set-null", "set-u64", "set-bytes", "clear-list", "resize-list", "copy", "swap", "set-reference", "clone-instance", "dispose"}
    for operation in operations:
        if not isinstance(operation, dict) or operation.get("op") not in allowed or "path" not in operation:
            reject("source operation schema mismatch")
        before = value_identity(state)
        op, path = operation["op"], operation["path"]
        parent, key = resolve_path(state, path)
        target_type = declared_path_type(path)
        current = get_child(parent, key)
        if op == "set-null" and set(operation) == {"op", "path"} and target_type in ("bytes", "list", "row", "plan", "batch"):
            set_child(parent, key, None)
        elif op == "set-u64" and set(operation) == {"op", "path", "value"} and target_type == "u64" and type(operation["value"]) is int and 0 <= operation["value"] <= (1 << 64) - 1 and type(current) is int:
            set_child(parent, key, operation["value"])
        elif op == "set-bytes" and set(operation) == {"op", "path", "value"} and target_type == "bytes" and isinstance(current, (ByteView, type(None))):
            minimum, maximum = byte_path_limit(path)
            byte_value = bytes_from_spec(operation["value"], fixtures, maximum)
            if byte_value.length < minimum: reject("typed byte view has the wrong fixed width")
            set_child(parent, key, byte_value)
        elif op == "clear-list" and set(operation) == {"op", "path"} and target_type == "list" and isinstance(current, ListView):
            if current.length == 0: reject("source operation is a no-op")
            set_child(parent, key, ListView([]))
        elif op == "resize-list" and set(operation) == {"op", "path", "length", "fill"} and target_type == "list" and isinstance(current, ListView) and type(operation["length"]) is int and 0 <= operation["length"] <= list_path_limit(path):
            fill = operation["fill"]
            if not isinstance(fill, dict): reject("source list fill recipe mismatch")
            if strict_value_equal(fill, {"kind": "indexed-u32be"}):
                if schema != "wlpq-source-object-v2" or model_id != "model-managed-batch-expanded-count-plus-one" or path not in ("batch.rows[0].previous", "batch.rows[1].previous") or current.length != 0:
                    reject("indexed u32be fill is outside its exact empty-list authority")
                fill_value = IndexedU32BeFill()
            elif (path == "row.previous" or re.fullmatch(r"(?:request\.selected|batch\.rows)\[[0-9]+\]\.previous", path)) and fill.get("kind") in ("fixture", "repeat", "literal"):
                fill_value = bytes_from_spec(fill, fixtures, MAX_TRANSACTION)
            elif path == "request.selected" and strict_value_equal(fill, {"kind": "selected-copy", "index": 0}):
                fill_value = current.get(0)
            elif path == "request.destinations" and strict_value_equal(fill, {"kind": "destination-copy", "index": 0}):
                fill_value = current.get(0)
            elif path == "batch.rows" and strict_value_equal(fill, {"kind": "row-copy", "index": 0}):
                fill_value = current.get(0)
            else:
                reject("source list fill recipe mismatch")
            current.resize(operation["length"], fill_value)
        elif op == "copy" and set(operation) == {"op", "path", "from"}:
            source_parent, source_key = resolve_path(state, operation["from"])
            source = get_child(source_parent, source_key)
            if declared_path_type(operation["from"]) != target_type: reject("copy source and target types differ")
            set_child(parent, key, clone_value(source))
        elif op == "swap" and set(operation) == {"op", "path", "with"}:
            other_parent, other_key = resolve_path(state, operation["with"])
            other = get_child(other_parent, other_key)
            if declared_path_type(operation["with"]) != target_type: reject("swap source and target types differ")
            set_child(parent, key, other); set_child(other_parent, other_key, current)
        elif op == "set-reference" and set(operation) == {"op", "path", "from"}:
            source_parent, source_key = resolve_path(state, operation["from"])
            source = get_child(source_parent, source_key)
            if target_type != "plan" or declared_path_type(operation["from"]) != "plan" or not isinstance(current, dict) or not isinstance(source, dict) or set(current) != set(source) or "identity" not in current or "identity" not in source:
                reject("set-reference requires identity-bearing objects")
            set_child(parent, key, source)
        elif op == "clone-instance" and set(operation) == {"op", "path", "from"}:
            source_parent, source_key = resolve_path(state, operation["from"])
            source = get_child(source_parent, source_key)
            if target_type != "plan" or declared_path_type(operation["from"]) != "plan" or not isinstance(source, dict) or "identity" not in source:
                reject("clone-instance source is not an identity-bearing object")
            clone = clone_value(source); clone["identity"] = digest((source["identity"] + ":clone").encode())
            set_child(parent, key, clone)
        elif op == "dispose" and set(operation) == {"op", "path"} and target_type in ("row", "batch") and isinstance(current, dict) and current.get("lifecycle") == "active":
            current["lifecycle"] = "disposed"
            set_child(parent, key, current)
        else:
            reject("source operation type, fields, or target mismatch")
        if before == value_identity(state):
            reject(f"source operation is a no-op: {op} {path}")


def byte_eq(left: ByteView, right: ByteView) -> bool:
    return left.compare(right) == 0


def strict_byte_order(values: ListView) -> bool:
    prior = None
    for index in range(values.length):
        current = values.get(index)
        if not isinstance(current, ByteView) or prior is not None and prior.compare(current) >= 0:
            return False
        prior = current
    return True


def request_numeric_code(request: dict) -> int:
    selected, destinations = request["selected"], request["destinations"]
    if request["manifest"].length != 32 or request["pegged_asset"].length != 32 or not 1 <= selected.length <= MAX_SELECTED or not 1 <= destinations.length <= MAX_DESTINATIONS or not 1 <= request["fee"] <= MAX_VALUE:
        return 4
    previous_count = transaction_bytes = 0
    for index in range(selected.length):
        row = selected.get(index)
        previous_count += row["previous"].length
        transaction_bytes += row["candidate"].length
        if row["txid"].length != 32 or row["asset"].length != 32 or row["vout"] > MAX_OUTPUT_INDEX or not 1 <= row["value"] <= MAX_VALUE or not 1 <= row["candidate"].length <= MAX_TRANSACTION or row["previous"].length > MAX_PREVIOUS:
            return 4
        previous_view = row["previous"]
        for previous in (*previous_view.items, *previous_view.overrides.values()):
            if not 1 <= previous.length <= MAX_TRANSACTION:
                return 4
        if previous_view.fill is not None and not 1 <= previous_view.fill.length <= MAX_TRANSACTION:
            return 4
        transaction_bytes += sum(item.length for item in previous_view.items)
        transaction_bytes += sum(item.length for item in previous_view.overrides.values())
        generated_count = previous_view.length - len(previous_view.items) - len(previous_view.overrides)
        transaction_bytes += generated_count * (previous_view.fill.length if previous_view.fill is not None else 0)
    if previous_count > MAX_PREVIOUS or transaction_bytes > MAX_TRANSACTION_BYTES:
        return 4
    for index in range(destinations.length):
        destination = destinations.get(index)
        if destination["asset"].length != 32 or not 1 <= destination["value"] <= MAX_VALUE or not 1 <= destination["address"].length <= MAX_ADDRESS:
            return 4
    return 0


def request_structural_code(request: dict) -> int:
    def nonzero(value: ByteView) -> bool:
        return any(value.byte_at(index) != 0 for index in range(value.length))

    invalid_encoding = not nonzero(request["manifest"]) or not nonzero(request["pegged_asset"])
    prior_txid = None
    prior_vout = None
    for index in range(request["selected"].length):
        row = request["selected"].get(index)
        txid = row["txid"]
        if txid.length != 32 or row["asset"].length != 32:
            return 3
        invalid_encoding |= not nonzero(txid) or not nonzero(row["asset"])
        if prior_txid is not None:
            comparison = 0
            for offset in range(31, -1, -1):
                left, right = prior_txid.byte_at(offset), txid.byte_at(offset)
                if left != right:
                    comparison = -1 if left < right else 1
                    break
            invalid_encoding |= comparison > 0 or comparison == 0 and prior_vout >= row["vout"]
        prior_txid, prior_vout = txid, row["vout"]
        invalid_encoding |= not strict_byte_order(row["previous"])
    for index in range(request["destinations"].length):
        destination = request["destinations"].get(index)
        asset, address = destination["asset"], destination["address"]
        if asset.length != 32:
            return 3
        invalid_encoding |= not nonzero(asset)
        invalid_encoding |= any(address.byte_at(offset) > 0x7f for offset in range(address.length))
    return 3 if invalid_encoding else 0


def evaluate_request(request: dict, frames: dict[str, bytes]) -> tuple[str, int, str]:
    if request["source_epoch"].length != 32 or all(request["source_epoch"].byte_at(index) == 0 for index in range(32)):
        return "error", 1, "frozen-order"
    code = request_numeric_code(request)
    if code: return "error", code, "frozen-order"
    code = request_structural_code(request)
    if code: return "error", code, "frozen-order"
    manifest = request["manifest"]
    if byte_eq(manifest, ByteView.from_bytes(bytes.fromhex(TEST_MANIFEST))):
        pegged = bytes.fromhex(TEST_ASSET_RPC)[::-1]
        canonical = (
            request_from_frame(frames["frame-test-public-valid"])["destinations"].get(0)["address"],
            ByteView.from_bytes(TEST_SHARED_ADDRESS),
        )
    elif byte_eq(manifest, ByteView.from_bytes(bytes.fromhex(MAIN_MANIFEST))):
        pegged = bytes.fromhex(MAIN_ASSET_RPC)[::-1]
        canonical = (request_from_frame(frames["frame-main-public-valid"])["destinations"].get(0)["address"],)
    else:
        return "error", 6, "frozen-order"
    if not byte_eq(request["pegged_asset"], ByteView.from_bytes(pegged)):
        return "error", 6, "frozen-order"
    if any(not any(byte_eq(request["destinations"].get(index)["address"], address) for address in canonical) for index in range(request["destinations"].length)):
        return "error", 7, "frozen-order"
    inputs: dict[tuple, int] = {}; outputs: dict[tuple, int] = {request["pegged_asset"].identity(): request["fee"]}
    for index in range(request["selected"].length):
        row = request["selected"].get(index); key = row["asset"].identity(); inputs[key] = inputs.get(key, 0) + row["value"]
    for index in range(request["destinations"].length):
        row = request["destinations"].get(index); key = row["asset"].identity(); outputs[key] = outputs.get(key, 0) + row["value"]
    return ("ok", 0, "frozen-order") if inputs == outputs else ("error", 7, "frozen-order")


def build_source_state(root_spec: dict, frames: dict[str, bytes]) -> tuple[dict, str]:
    if not isinstance(root_spec, dict):
        reject("source root object schema mismatch")
    kind = root_spec.get("kind")
    if kind in ("request-from-frame", "funding-row-from-frame", "funding-batch-from-frame", "encoder-call-from-frame"):
        allowed = {"kind", "frame_id"} | ({"selected_index"} if kind == "funding-row-from-frame" else set())
        exact_keys(root_spec, allowed, "source root")
        if root_spec["frame_id"] not in frames:
            reject("source root frame foreign key mismatch")
        request = request_from_frame(frames[root_spec["frame_id"]])
        if kind == "request-from-frame": return {"request": request}, kind
        if kind == "funding-row-from-frame":
            if type(root_spec["selected_index"]) is not int: reject("funding row selected index mismatch")
            return {"row": clone_value(request["selected"].get(root_spec["selected_index"]))}, kind
        plan_identity = digest((root_spec["frame_id"] + ":plan").encode())
        plan = {"identity": plan_identity, "request": clone_value(request)}
        rows = ListView([clone_value(request["selected"].get(index)) for index in range(request["selected"].length)])
        batch = {"identity": digest((root_spec["frame_id"] + ":batch").encode()), "plan": plan, "rows": rows, "lifecycle": "active"}
        if kind == "funding-batch-from-frame": return {"batch": batch}, kind
        return {"call": {"source_epoch": clone_value(request["source_epoch"]), "plan": plan, "batch": batch}}, kind
    if kind == "decoder-input-from-frame":
        exact_keys(root_spec, {"kind", "frame_id", "virtual_length", "read_poison"}, "decoder root")
        if root_spec["frame_id"] != "frame-test-toy-single" or root_spec["frame_id"] not in frames or root_spec["virtual_length"] != MAX_FRAME + 1 or root_spec["read_poison"] is not True:
            reject("decoder root mismatch")
        return {"decoder": VirtualFrame(root_spec["virtual_length"], root_spec["read_poison"])}, kind
    if kind == "checked-expression":
        if set(root_spec) not in ({"kind", "domain", "operator", "left", "right"}, {"kind", "domain", "operator", "left", "right", "virtual_frame"}): reject("checked-expression root schema mismatch")
        return {"expression": root_spec}, kind
    reject("source root kind is unknown")


def evaluate_funding_row(row: dict) -> tuple[tuple[str, int, str], tuple[int, int] | None]:
    if row["candidate"] is None or row["previous"] is None:
        if row["candidate"] is None and isinstance(row["previous"], ListView) and row["previous"].length > MAX_PREVIOUS:
            return ("error", 1, "null-before-limit"), None
        if row["candidate"] is None and isinstance(row["previous"], ListView) and not strict_byte_order(row["previous"]):
            return ("error", 1, "null-before-encoding"), None
        return ("error", 1, "invalid-argument"), None
    if any(row["previous"].get(index) is None for index in range(row["previous"].length)):
        return ("error", 1, "invalid-argument"), None
    if not 1 <= row["candidate"].length <= MAX_TRANSACTION or row["previous"].length > MAX_PREVIOUS:
        return ("error", 4, "limit"), None
    total = row["candidate"].length
    for index in range(row["previous"].length):
        item = row["previous"].get(index)
        if not isinstance(item, ByteView) or not 1 <= item.length <= MAX_TRANSACTION:
            return ("error", 4, "limit"), None
        total += item.length
        if total > MAX_TRANSACTION_BYTES:
            return ("error", 4, "limit"), None
    if not strict_byte_order(row["previous"]):
        return ("error", 3, "encoding"), None
    return ("ok", 0, "-"), (row["previous"].length, total)


def evaluate_source_state(state: dict, kind: str, boundary: dict[str, str] | None, frames: dict[str, bytes]) -> tuple[str, int, str]:
    if kind == "request-from-frame": return evaluate_request(state["request"], frames)
    if kind == "funding-row-from-frame":
        outcome, _ = evaluate_funding_row(state["row"])
        return outcome
    if kind == "funding-batch-from-frame":
        batch = state["batch"]
        if batch["plan"] is None or batch["rows"] is None: return "error", 1, "invalid-argument"
        if any(batch["rows"].get(index) is None for index in range(batch["rows"].length)):
            disposed_present = any(isinstance(batch["rows"].get(index), dict) and batch["rows"].get(index).get("lifecycle") == "disposed" for index in range(batch["rows"].length))
            return "error", 1, "null-before-lifecycle" if disposed_present else "invalid-argument"
        if any(batch["rows"].get(index)["lifecycle"] == "disposed" for index in range(batch["rows"].length)): return "lifecycle", 0, "object-disposed"
        if batch["rows"].length != batch["plan"]["request"]["selected"].length: return "error", 1, "invalid-argument"
        shapes = []
        for index in range(batch["rows"].length):
            outcome, shape = evaluate_funding_row(batch["rows"].get(index))
            if outcome != ("ok", 0, "-"):
                reject("funding batch source contains an invalid funding row")
            assert shape is not None
            shapes.append(shape)
        count = sum(shape[0] for shape in shapes)
        if count > MAX_PREVIOUS:
            return "error", 4, "limit"
        total = sum(shape[1] for shape in shapes)
        return ("error", 4, "limit") if total > MAX_TRANSACTION_BYTES else ("ok", 0, "-")
    if kind == "encoder-call-from-frame":
        call = state["call"]
        if call["plan"] is None or call["batch"] is None: return "error", 1, "null-before-lifecycle" if call["batch"] is not None and call["batch"]["lifecycle"] == "disposed" else "invalid-argument"
        if call["batch"]["lifecycle"] == "disposed": return "lifecycle", 0, "lifecycle-before-epoch" if call["source_epoch"].length != 32 or all(call["source_epoch"].byte_at(i) == 0 for i in range(call["source_epoch"].length)) else "object-disposed"
        if call["source_epoch"].length != 32 or all(call["source_epoch"].byte_at(i) == 0 for i in range(call["source_epoch"].length)): return "error", 1, "epoch-before-identity" if call["plan"]["identity"] != call["batch"]["plan"]["identity"] else "invalid-argument"
        if call["plan"]["identity"] != call["batch"]["plan"]["identity"]: return "error", 1, "identity-after-epoch"
        return "ok", 0, "-"
    if kind == "decoder-input-from-frame":
        decoder = state["decoder"]
        if decoder.length > MAX_FRAME:
            if decoder.reads != 0: reject("outer-limit decoder touched virtual bytes")
            return "error", 4, "outer-before-discriminator"
        reject("unsupported generated decoder root")
    if kind == "checked-expression":
        if boundary is None: reject("checked expression has no boundary")
        expression = state["expression"]
        def tree(formula: str) -> dict:
            terms = []
            for text in formula.split("+"):
                factors = [{"operator": "literal", "left": int(value), "right": None} for value in text.split("*")]
                term = factors[0]
                for factor in factors[1:]: term = {"operator": "multiply", "left": term, "right": factor}
                terms.append(term)
            value = terms[0]
            for term in terms[1:]: value = {"operator": "add", "left": value, "right": term}
            return value
        expression_core = {key: expression[key] for key in ("operator", "left", "right")}
        if expression["domain"] != boundary["numeric_domain"] or not strict_value_equal(expression_core, tree(boundary["formula"])): reject("checked expression does not bind boundary")
        def evaluate(node: dict) -> tuple[str, int | None]:
            if not isinstance(node, dict) or set(node) != {"operator", "left", "right"} or node["operator"] not in ("literal", "add", "multiply"):
                reject("checked expression node schema mismatch")
            if node["operator"] == "literal":
                if type(node["left"]) is not int or node["left"] < 0 or node["right"] is not None: reject("checked literal mismatch")
                return "value", node["left"]
            left_kind, left = evaluate(node["left"]); right_kind, right = evaluate(node["right"])
            if left_kind == "overflow" or right_kind == "overflow": return "overflow", None
            assert left is not None and right is not None
            result = left + right if node["operator"] == "add" else left * right
            return ("overflow", None) if result > (1 << 64) - 1 else ("value", result)
        expression_kind, expression_value = evaluate(expression_core)
        formula_kind, formula_value = evaluate_formula(boundary["formula"])
        if (expression_kind, expression_value) != (formula_kind, formula_value): reject("checked expression evaluation mismatch")
        if "virtual_frame" in expression: validate_virtual_frame(expression["virtual_frame"])
        _, _, result, code, _ = boundary_outcome(boundary)
        return result, code, "boundary-formula"
    reject("source state kind cannot be evaluated")


def validate_virtual_frame(value: dict) -> None:
    expected = {
        "selected_count": 100, "destination_count": 255, "destination_address": {"kind": "repeat", "byte_hex": "61", "length": 256},
        "previous_counts": {"kind": "concat", "parts": [{"kind": "repeat-value", "value": 164, "count": 84}, {"kind": "repeat-value", "value": 163, "count": 16}]},
        "candidate": {"kind": "repeat", "byte_hex": "00", "length": 1},
        "previous_payloads": {"kind": "indexed", "count": 16384, "prefix": "u32be", "lengths": {"kind": "concat", "parts": [{"kind": "repeat-value", "value": 4095, "count": 100}, {"kind": "repeat-value", "value": 4096, "count": 16284}]}},
    }
    if not strict_value_equal(value, expected): reject("virtual reachable-frame recipe mismatch")
    counts = 84 * 164 + 16 * 163; payload = 100 * 4095 + 16284 * 4096
    if counts != MAX_PREVIOUS or 100 + payload != MAX_TRANSACTION_BYTES: reject("virtual reachable-frame distribution mismatch")


def validate_source_objects(root: Path, rows: list[dict[str, str]], cases: list[dict[str, str]], boundaries: list[dict[str, str]], frames: dict[str, bytes], fixtures: dict[str, bytes]) -> dict[str, str]:
    models = {row["source_model_id"]: row for row in rows}
    consumers = [row["source_model_id"] for row in cases if row["source_model_id"] != "-"] + [row["source_model_id"] for row in boundaries]
    if len(consumers) != len(set(consumers)) or set(consumers) != set(models): reject("source object topology is not one-to-one and closed")
    case_by_model = {row["source_model_id"]: row for row in cases if row["source_model_id"] != "-"}; boundary_by_model = {row["source_model_id"]: row for row in boundaries}
    outputs = {}
    for model_id, row in models.items():
        value = canonical_model_object(root, row)
        exact_keys(value, {"schema", "root", "operations"}, "source object")
        expected_schema = "wlpq-source-object-v2" if model_id == "model-managed-batch-expanded-count-plus-one" else "wlpq-source-object-v1"
        if value["schema"] != expected_schema: reject("source object schema identifier mismatch")
        state, kind = build_source_state(value["root"], frames)
        apply_source_operations(state, value["operations"], fixtures, value["schema"], model_id)
        boundary = boundary_by_model.get(model_id)
        outcome = evaluate_source_state(state, kind, boundary, frames)
        if row["partition"] == "shared-encoder":
            outcome = outcome[:2] + ("-" if outcome[:2] == ("ok", 0) else "invalid-argument",)
        declared = (row["expected_result"], int(row["expected_error_code"]), row["precedence"])
        if outcome != declared: reject(f"source object independently derived outcome mismatch: {model_id}: {outcome} != {declared}")
        consumer = case_by_model.get(model_id) or boundary
        if consumer.get("frame_id", "-") != "-" and (kind != "request-from-frame" or value["root"].get("frame_id") != consumer["frame_id"]):
            reject("source object root frame does not match its case frame")
        expected = (consumer["partition"] if "partition" in consumer else "boundary", consumer["operation"], consumer["execution_class"], consumer["expected_result"] if "expected_result" in consumer else consumer["expected_status"], consumer["expected_error_code"], consumer["combined_precedence"] if "combined_precedence" in consumer else "boundary-formula")
        if (row["partition"], row["operation"], row["execution_class"], row["expected_result"], row["expected_error_code"], row["precedence"]) != expected: reject("source object does not exactly bind its consumer")
        if outcome[:2] == ("ok", 0) and row["partition"] in ("shared-encoder", "managed-encoder"):
            request = state["request"] if kind == "request-from-frame" else state["call"]["plan"]["request"]
            encoded = pack_request_view(request)
            expected_frame_id = consumer["expected_reencode_frame_id"] if consumer["expected_reencode_frame_id"] != "-" else "frame-test-public-valid"
            if encoded != frames[expected_frame_id]:
                reject("successful source object does not independently pack to its expected frame")
            outputs[model_id] = digest(encoded)
    return outputs


def prepare_expectation(case: dict[str, str], frames: dict[str, bytes], catalogs: list[dict[str, str]], catalog_scripts: list[dict[str, str]]) -> int:
    request = raw_unpack(frames[case["frame_id"]])
    catalog = next(row for row in catalogs if row["catalog_fixture_id"] == case["catalog_fixture_id"])
    contexts = {
        TEST_MANIFEST: ("liquid-testnet", bytes.fromhex(TEST_ASSET_RPC)[::-1], "catalog-test-0", {raw_unpack(frames["frame-test-public-valid"])["destinations"][0]["address"], TEST_SHARED_ADDRESS}),
        MAIN_MANIFEST: ("liquid-mainnet", bytes.fromhex(MAIN_ASSET_RPC)[::-1], "catalog-main-0", {raw_unpack(frames["frame-main-public-valid"])["destinations"][0]["address"]}),
    }
    context = contexts.get(request["manifest"].hex())
    if context is None or request["pegged"] != context[1] or catalog["context_id"] != context[0] or case["catalog_fixture_id"] != context[2]:
        return 6
    inputs: dict[bytes, int] = {}
    outputs: dict[bytes, int] = {request["pegged"]: request["fee"]}
    for selected in request["selected"]:
        inputs[selected["asset"]] = inputs.get(selected["asset"], 0) + selected["value"]
    for destination in request["destinations"]:
        if destination["address"] not in context[3]:
            return 7
        outputs[destination["asset"]] = outputs.get(destination["asset"], 0) + destination["value"]
    if inputs != outputs:
        return 7
    owned_scripts = {row["script_sha256"] for row in catalog_scripts if row["catalog_fixture_id"] == case["catalog_fixture_id"]}
    for selected in request["selected"]:
        try:
            if elements_txid(selected["candidate"]) != selected["txid"].hex():
                return 8
            candidate = parse_public_transaction(selected["candidate"])
            if selected["vout"] >= len(candidate["outputs"]):
                return 8
            previous_by_txid = {}
            for previous_bytes in selected["previous"]:
                previous_txid = elements_txid(previous_bytes)
                if previous_txid in previous_by_txid:
                    return 8
                previous_by_txid[previous_txid] = parse_public_transaction(previous_bytes)
            input_outpoints = [(item["txid"], item["vout"]) for item in candidate["inputs"]]
            needed_txids = {item["txid"] for item in candidate["inputs"]}
            if len(input_outpoints) != len(set(input_outpoints)) or set(previous_by_txid) != needed_txids:
                return 8
            for transaction_input in candidate["inputs"]:
                previous = previous_by_txid.get(transaction_input["txid"])
                if previous is None or transaction_input["vout"] >= len(previous["outputs"]):
                    return 8
            selected_output = candidate["outputs"][selected["vout"]]
            if selected_output["prefixes"].split(",") not in (["0a", "08", "02"], ["0a", "08", "03"], ["0b", "09", "02"], ["0b", "09", "03"]):
                return 8
            if selected_output["script_sha256"] not in owned_scripts:
                return 8
            if selected["vout"] >= len(candidate["output_witness"]):
                return 8
            surjection_length, rangeproof_length = candidate["output_witness"][selected["vout"]]
            if surjection_length == 0 or rangeproof_length == 0:
                return 8
        except CorpusError:
            return 8
    return 0


def validate_prepare_expectations(cases: list[dict[str, str]], frames: dict[str, bytes], catalogs: list[dict[str, str]], catalog_scripts: list[dict[str, str]]) -> None:
    for row in cases:
        if row["partition"] != "native-prepare":
            continue
        if prepare_expectation(row, frames, catalogs, catalog_scripts) != int(row["expected_error_code"]):
            reject("prepare case result contradicts independent semantic classification")


def validate_documents(root: Path) -> None:
    wire = exact_text(root / REFERENCE / "WIRE_FORMAT_V1.md")
    corpus = exact_text(root / VECTORS / "CORPUS_V1.md")
    required_wire = (CORPUS_ID, "WLPQ", "header length 152", "little-endian", "consensus order", "RPC/display", "read", "no update")
    if not all(term in wire for term in required_wire):
        reject("wire document omits frozen authority")
    required_nonclaims = ("opening-provider", "node", "PSET", "CoinJoin", "sponsor", "USDt CoinJoin", "production-readiness")
    if not all(term in corpus for term in required_nonclaims):
        reject("corpus document omits deferred boundaries")
    required_source_schema = ("exact closed, versioned schema union", "wlpq-source-object-v1", "wlpq-source-object-v2", "indexed-u32be")
    if not all(term in corpus for term in required_source_schema):
        reject("corpus document omits source schema authority")


def run(root: Path, *, enforce_reviewed_roots: bool = True) -> None:
    if not root.is_absolute() or not root.is_dir():
        reject("repository root must be an absolute directory")
    if enforce_reviewed_roots:
        validate_reviewed_roots(root)
    _, nested = validate_topology(root)
    tables = {name: parse_table(root, name) for name in TABLES}
    expected_nested = {
        "BOUNDARIES_V1.tsv", "CASES_V1.tsv", "CATALOG_OUTPUT_SCRIPTS_V1.tsv", "CORPUS_V1.md", "FIXTURES_V1.tsv", "FIXTURE_ASSERTIONS_V1.tsv", "FRAME_PAYLOAD_BINDINGS_V1.tsv", "FRAMES_V1.tsv", "MUTATIONS_V1.tsv", "PUBLIC_PROOF_CASES_V1.tsv", "SOURCE_MODELS_V1.tsv",
        *(row["relative_path"] for row in tables["vectors/FIXTURES_V1.tsv"]),
        *(row["relative_path"] for row in tables["vectors/FRAMES_V1.tsv"]),
        *(row["relative_path"] for row in tables["vectors/SOURCE_MODELS_V1.tsv"]),
    }
    if set(nested) != expected_nested:
        reject("vector topology contains an unreferenced or missing file")
    validate_constants(root, tables)
    validate_documents(root)
    fixtures = validate_fixtures(root, tables["vectors/FIXTURES_V1.tsv"])
    validate_fixture_assertions(tables["vectors/FIXTURE_ASSERTIONS_V1.tsv"], fixtures, tables["vectors/FIXTURES_V1.tsv"])
    if digest((root / VECTORS / "FIXTURE_ASSERTIONS_V1.tsv").read_bytes()) != FIXTURE_ASSERTIONS_TABLE_SHA256:
        reject("fixture assertion table differs from its exact reviewed authority")
    validate_catalog_scripts(tables["vectors/CATALOG_OUTPUT_SCRIPTS_V1.tsv"], tables["CATALOG_FIXTURES_V1.tsv"])
    validate_public_proof_cases(tables["vectors/PUBLIC_PROOF_CASES_V1.tsv"], tables["vectors/FIXTURES_V1.tsv"])
    frames, _ = validate_frames(root, tables["vectors/FRAMES_V1.tsv"])
    validate_payload_bindings(tables["vectors/FRAME_PAYLOAD_BINDINGS_V1.tsv"], frames, fixtures, tables["vectors/FIXTURES_V1.tsv"])
    validate_prepare_fixture_bindings(tables["vectors/CASES_V1.tsv"], frames, fixtures)
    validate_mutations(tables["vectors/MUTATIONS_V1.tsv"], frames, tables["vectors/FRAMES_V1.tsv"])
    validate_boundaries(tables["vectors/BOUNDARIES_V1.tsv"])
    validate_cases(
        tables["vectors/CASES_V1.tsv"],
        frames,
        tables["vectors/FRAMES_V1.tsv"],
        tables["CATALOG_FIXTURES_V1.tsv"],
    )
    source_outputs = validate_source_objects(root, tables["vectors/SOURCE_MODELS_V1.tsv"], tables["vectors/CASES_V1.tsv"], tables["vectors/BOUNDARIES_V1.tsv"], frames, fixtures)
    validate_prepare_expectations(tables["vectors/CASES_V1.tsv"], frames, tables["CATALOG_FIXTURES_V1.tsv"], tables["vectors/CATALOG_OUTPUT_SCRIPTS_V1.tsv"])
    validate_case_bindings(tables["vectors/CASES_V1.tsv"], frames, tables["CATALOG_FIXTURES_V1.tsv"], tables["vectors/SOURCE_MODELS_V1.tsv"], source_outputs)
    if digest((root / VECTORS / "CASES_V1.tsv").read_bytes()) != CASE_TABLE_SHA256:
        reject("case table differs from its exact reviewed authority")


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: check-ordinary-wallet-plan-conformance.py ABSOLUTE_REPOSITORY_ROOT", file=sys.stderr)
        return 2
    try:
        run(Path(os.path.abspath(sys.argv[1])))
    except (CorpusError, OSError, ValueError, OverflowError, RecursionError, TypeError, KeyError, IndexError, AttributeError, struct.error) as error:
        print(f"ordinary-wallet-plan conformance check failed: {error}", file=sys.stderr)
        return 1
    print(f"ordinary-wallet-plan conformance corpus accepted: {CORPUS_ID}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
