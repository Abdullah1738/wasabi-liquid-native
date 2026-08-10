#!/usr/bin/env python3
"""Validate the source-only wallet-facts wire conformance packet."""

from __future__ import annotations

import hashlib
import os
import re
import struct
import sys
from pathlib import Path


CORPUS_ID = "wallet-facts-wire-v1-conformance-1"
REFERENCE = Path("contracts/wallet-facts/v1/nonlinkable-reference")
VECTORS = REFERENCE / "vectors"
IDENTIFIER = re.compile(r"[a-z][a-z0-9-]*\Z")
LOWER_HASH = re.compile(r"[0-9a-f]{64}\Z")
DECIMAL = re.compile(r"(?:0|[1-9][0-9]*)\Z")
HEX = re.compile(r"[0-9a-f]*\Z")
FORMULA = re.compile(r"(?:0|[1-9][0-9]*)(?:[+*](?:0|[1-9][0-9]*))*\Z")
U32_MAX = (1 << 32) - 1
U64_MAX = (1 << 64) - 1

TABLES = {
    "FRAMES_V1.tsv": (
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
    ),
    "CASES_V1.tsv": (
        "case_id",
        "frame_id",
        "operation",
        "expected_source_epoch_hex",
        "expected_status",
        "expected_error_code",
        "canonical_reencode",
    ),
    "API_CASES_V1.tsv": (
        "case_id",
        "operation",
        "fixture_recipe",
        "expected_status",
        "expected_error_code",
        "expected_frame_id",
    ),
    "RECIPES_V1.tsv": (
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
    ),
    "BOUNDARIES_V1.tsv": (
        "boundary_id",
        "operation",
        "boundary_kind",
        "production_constant",
        "numeric_domain",
        "formula",
        "expected_status",
        "expected_value",
        "expected_error_code",
    ),
}

VALID_DESCRIPTOR = b"elwpkh([28b3f14e/84'/1'/0']tpubDC2Q4xK4XH72GM7MowNuajyWVbigRLBWKswyP5T88hpPwu5nGqJWnda8zhJEFt71av73Hm8mUMMFSz9acNVzz8b1UbdSHCDXKTbSv5eEytu/<0;1>/*)#u0khc0kg"
SEMANTIC_REJECT_DESCRIPTOR = b"elwpkh(x)#u0khc0kg"
GENERATOR_PUBLIC_KEY = bytes.fromhex(
    "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
)
GENERATOR_SCRIPT = bytes.fromhex("0014751e76e8199196d454941c45d1b3a323f1433bd6")

RECIPE_PROPERTIES = {
    "candidate-rejected-request": ("request", "candidate-transaction-empty", "request-encode", "error", 6),
    "descriptor-rejected-request": ("request", "descriptor-semantic-and-candidate-empty", "request-encode", "error", 5),
    "empty-accepted-request-source": ("request", "accepted-empty-request", "request-encode", "ok", 0),
    "empty-accepted-response-source": ("response", "accepted-empty-a-response", "response-encode", "ok", 0),
    "empty-b-accepted-response-source": ("response", "accepted-empty-b-response", "response-encode", "ok", 0),
    "multi-asset-accepted-response-source": ("response", "accepted-multi-asset-response", "response-encode", "ok", 0),
    "nonempty-accepted-request-source": ("request", "accepted-nonempty-request", "request-encode", "ok", 0),
    "one-output-accepted-response-source": ("response", "accepted-one-output-response", "response-encode", "ok", 0),
    "orphan-output-response-source": ("response", "output-orphan", "response-source-validation", "error", 7),
    "output-binding-mismatch-response-source": ("response", "output-binding-mismatch", "response-source-validation", "error", 7),
    "output-order-response-source": ("response", "output-order", "response-source-validation", "error", 7),
    "spend-only-accepted-response-source": ("response", "accepted-spend-only-response", "response-encode", "ok", 0),
    "three-input-accepted-response-source": ("response", "accepted-three-input-response", "response-encode", "ok", 0),
    "two-output-accepted-response-source": ("response", "accepted-two-output-response", "response-encode", "ok", 0),
    "zero-input-transaction-response-source": ("response", "transaction-inputs-empty", "response-source-validation", "error", 7),
    "zero-source-request": ("request", "zero-epoch-and-combined-invalid-request", "request-encode", "error", 1),
    "zero-source-response-with-invalid-source": ("response", "zero-epoch-and-transaction-inputs-empty", "response-encode", "error", 1),
    "zero-transaction-id-response-source": ("response", "transaction-id-zero", "response-source-validation", "error", 7),
}

CANONICAL_LENGTH_CASES = {
    "request-25-trailing-byte-decode": "request-25a-trailing-byte-canonical-length",
    "request-26-concatenated-decode": "request-26a-concatenated-canonical-length",
    "request-body-truncated-decode": "request-09a-body-truncated-canonical-length",
    "response-21-trailing-byte-decode": "response-21a-trailing-byte-canonical-length",
    "response-22-concatenated-decode": "response-22a-concatenated-canonical-length",
    "response-body-truncated-decode": "response-10b-body-truncated-canonical-length",
}

EXPECTED_REPLAY_ROWS_SHA256 = "b45bba25b65f0a62348319bcd3c629d4874b7a57500b6bf33fbfe485c0b8551b"

CONSTANTS = {
    "max-public-descriptor-bytes": (16_384, "u32", "MAX_PUBLIC_DESCRIPTOR_BYTES", "Public descriptor bytes"),
    "max-derivation-index": (100_000, "u32", "MAX_DERIVATION_INDEX", "Last derivation index"),
    "max-candidate-transactions": (4_096, "u32", "MAX_CANDIDATE_TRANSACTIONS", "Candidate transactions"),
    "max-previous-transactions-per-batch": (16_384, "u32", "MAX_PREVIOUS_TRANSACTIONS_PER_BATCH", "Previous transactions in one batch"),
    "max-transaction-bytes": (4_194_304, "u32", "MAX_TRANSACTION_BYTES", "One serialized transaction"),
    "max-batch-bytes": (67_108_864, "usize64", "MAX_BATCH_BYTES", "Aggregate candidate and previous-transaction bytes"),
    "max-request-frame-bytes": (268_435_456, "usize64", "MAX_REQUEST_FRAME_BYTES", "Outer request rejection ceiling"),
    "max-reachable-request-bytes": (67_240_012, "usize64", "MAX_REACHABLE_REQUEST_BYTES", "Maximum structurally reachable request"),
    "max-response-frame-bytes": (268_435_456, "usize64", "MAX_RESPONSE_FRAME_BYTES", "Outer response rejection ceiling"),
    "max-reachable-response-bytes": (80_599_492, "usize64", "MAX_REACHABLE_RESPONSE_BYTES", "Maximum structurally reachable response"),
    "max-aggregate-inputs": (1_636_801, "usize64", "MAX_AGGREGATE_INPUTS", "Aggregate observed inputs"),
    "max-aggregate-owned-outputs": (148_470, "usize64", "MAX_AGGREGATE_OWNED_OUTPUTS", "Aggregate owned outputs"),
    "max-inputs-per-transaction": (102_298, "usize64", "MAX_INPUTS_PER_TRANSACTION", "Inputs in one observed transaction"),
    "max-owned-outputs-per-transaction": (9_279, "usize64", "MAX_OWNED_OUTPUTS_PER_TRANSACTION", "Owned outputs in one observed transaction"),
    "max-owned-output-value": (9_223_372_036_854_775_807, "u64", "MAX_OWNED_OUTPUT_VALUE", "Maximum owned-output value"),
    "max-spendable-output-index": (1_073_741_823, "u32", "MAX_SPENDABLE_OUTPUT_INDEX", "Maximum spendable output index"),
}

EXPECTED_BOUNDARIES: dict[str, tuple[str, str, str, str, str, str, str, str]] = {}
for prefix, operation, constant, code in (
    ("aggregate-inputs", "response-decode", "max-aggregate-inputs", 4),
    ("aggregate-owned-outputs", "response-decode", "max-aggregate-owned-outputs", 4),
    ("batch-bytes", "request-decode", "max-batch-bytes", 4),
    ("candidate-transactions", "request-decode", "max-candidate-transactions", 4),
    ("derivation-index", "request-decode", "max-derivation-index", 4),
    ("inputs-per-transaction", "response-decode", "max-inputs-per-transaction", 4),
    ("owned-output-value", "response-decode", "max-owned-output-value", 3),
    ("owned-outputs-per-transaction", "response-decode", "max-owned-outputs-per-transaction", 4),
    ("previous-transactions", "request-decode", "max-previous-transactions-per-batch", 4),
    ("public-descriptor-bytes", "request-decode", "max-public-descriptor-bytes", 4),
    ("spendable-output-index", "response-decode", "max-spendable-output-index", 3),
    ("transaction-bytes", "request-decode", "max-transaction-bytes", 4),
):
    maximum, domain, _, _ = CONSTANTS[constant]
    EXPECTED_BOUNDARIES[prefix + "-maximum"] = (
        operation, "component-limit", constant, domain, str(maximum), "ok", str(maximum), "0"
    )
    EXPECTED_BOUNDARIES[prefix + "-plus-one"] = (
        operation, "component-limit", constant, domain, f"{maximum}+1", "rejected", str(maximum + 1), str(code)
    )
EXPECTED_BOUNDARIES.update(
    {
        "arithmetic-add-overflow": ("checked-arithmetic", "arithmetic-rejection", "none", "u64", "18446744073709551615+1", "overflow", "-", "4"),
        "arithmetic-multiply-overflow": ("checked-arithmetic", "arithmetic-rejection", "none", "u64", "18446744073709551615*2", "overflow", "-", "4"),
        "reachable-request-bytes": ("checked-arithmetic", "reachable-maximum", "max-reachable-request-bytes", "usize64", "76+16384+4096*12+16384*4+67108864", "ok", "67240012", "0"),
        "reachable-response-bytes": ("checked-arithmetic", "reachable-maximum", "max-reachable-response-bytes", "usize64", "64+4096*72+1636801*36+148470*144", "ok", "80599492", "0"),
        "request-outer-ceiling": ("request-outer-length-check", "outer-ceiling", "max-request-frame-bytes", "usize64", "268435456", "ok", "268435456", "0"),
        "request-outer-plus-one": ("request-outer-length-check", "outer-ceiling", "max-request-frame-bytes", "usize64", "268435456+1", "rejected", "268435457", "4"),
        "response-outer-ceiling": ("response-outer-length-check", "outer-ceiling", "max-response-frame-bytes", "usize64", "268435456", "ok", "268435456", "0"),
        "response-outer-plus-one": ("response-outer-length-check", "outer-ceiling", "max-response-frame-bytes", "usize64", "268435456+1", "rejected", "268435457", "4"),
    }
)


def reject(message: str) -> None:
    raise ValueError(message)


def read_text(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        reject(f"not a regular file: {path}")
    if path.stat().st_nlink != 1:
        reject(f"hard-linked file: {path}")
    data = path.read_bytes()
    if data.startswith(b"\xef\xbb\xbf") or b"\r" in data or not data.endswith(b"\n"):
        reject(f"noncanonical text: {path}")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError(f"non-UTF-8 text: {path}") from error


def parse_table(path: Path, header: tuple[str, ...]) -> list[dict[str, str]]:
    text = read_text(path)
    lines = text.removesuffix("\n").split("\n")
    if not lines or tuple(lines[0].split("\t")) != header:
        reject(f"wrong TSV header: {path}")
    rows: list[dict[str, str]] = []
    previous: bytes | None = None
    identifiers: set[str] = set()
    for line in lines[1:]:
        if not line:
            reject(f"blank TSV row: {path}")
        fields = line.split("\t")
        if len(fields) != len(header):
            reject(f"wrong TSV field count: {path}")
        identifier = fields[0]
        if not IDENTIFIER.fullmatch(identifier) or identifier in identifiers:
            reject(f"invalid or duplicate identifier: {path}")
        encoded = identifier.encode("utf-8")
        if previous is not None and previous >= encoded:
            reject(f"TSV rows are not bytewise ascending: {path}")
        previous = encoded
        identifiers.add(identifier)
        rows.append(dict(zip(header, fields, strict=True)))
    if not rows:
        reject(f"empty TSV: {path}")
    return rows


def parse_checksums(path: Path) -> dict[str, str]:
    rows: dict[str, str] = {}
    previous: bytes | None = None
    for line in read_text(path).removesuffix("\n").split("\n"):
        if not re.fullmatch(r"[0-9a-f]{64}  [!-~]+", line):
            reject(f"malformed checksum row: {path}")
        digest, relative = line.split("  ", 1)
        encoded = relative.encode("utf-8")
        if relative in rows or (previous is not None and previous >= encoded):
            reject(f"duplicate or unordered checksum row: {path}")
        pure = Path(relative)
        if (
            "\\" in relative
            or pure.is_absolute()
            or not pure.parts
            or any(part in ("", ".", "..") for part in pure.parts)
        ):
            reject(f"unsafe checksum path: {path}")
        rows[relative] = digest
        previous = encoded
    return rows


def verify_checksums(root: Path) -> None:
    reference = root / REFERENCE
    if reference.is_symlink() or not reference.is_dir():
        reject("invalid parent conformance directory")
    expected_topology = {
        "ERROR_MAPPING_V1.tsv",
        "SHA256SUMS",
        "WIRE_FORMAT_V1.md",
        "vectors",
    }
    actual_topology: set[str] = set()
    for path in reference.iterdir():
        name = path.name
        if path.is_symlink():
            reject(f"symlink in parent conformance topology: {path}")
        if name == "vectors":
            if not path.is_dir():
                reject("vectors entry is not a real directory")
        elif name in expected_topology:
            if not path.is_file() or path.stat().st_nlink != 1:
                reject(f"invalid parent conformance file: {path}")
        else:
            reject(f"unexpected parent conformance entry: {path}")
        actual_topology.add(name)
    if actual_topology != expected_topology:
        reject("parent conformance topology is not exact")

    vectors = reference / "vectors"
    nested = parse_checksums(vectors / "SHA256SUMS")
    actual: set[str] = set()
    for path in vectors.rglob("*"):
        if path.is_symlink():
            reject(f"symlink in vector inventory: {path}")
        if path.is_dir():
            continue
        if not path.is_file() or path.stat().st_nlink != 1:
            reject(f"invalid vector inventory entry: {path}")
        relative = path.relative_to(vectors).as_posix()
        if relative != "SHA256SUMS":
            actual.add(relative)
    if set(nested) != actual:
        reject("nested checksum inventory is not bijective")
    for relative, expected in nested.items():
        path = vectors / relative
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            reject(f"nested checksum mismatch: {relative}")

    parent = parse_checksums(reference / "SHA256SUMS")
    expected_parent = {
        "ERROR_MAPPING_V1.tsv",
        "WIRE_FORMAT_V1.md",
        "vectors/SHA256SUMS",
    }
    if set(parent) != expected_parent:
        reject("parent checksum inventory is not exact")
    for relative, expected in parent.items():
        path = reference / relative
        if path.is_symlink() or not path.is_file() or path.stat().st_nlink != 1:
            reject(f"invalid parent checksum entry: {relative}")
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            reject(f"parent checksum mismatch: {relative}")


def parse_hex(text: str, *, field: str, allow_dash: bool = False) -> bytes | None:
    if allow_dash and text == "-":
        return None
    if not HEX.fullmatch(text) or len(text) % 2:
        reject(f"invalid hexadecimal field: {field}")
    return bytes.fromhex(text)


def decimal(text: str, *, field: str) -> int:
    if not DECIMAL.fullmatch(text):
        reject(f"invalid decimal field: {field}")
    return int(text)


def decimal_u32(text: str, *, field: str) -> int:
    value = decimal(text, field=field)
    if value > U32_MAX:
        reject(f"u32 recipe field overflow: {field}")
    return value


def decimal_u64(text: str, *, field: str) -> int:
    value = decimal(text, field=field)
    if value > U64_MAX:
        reject(f"u64 recipe field overflow: {field}")
    return value


def verify_frames(root: Path, rows: list[dict[str, str]]) -> dict[str, bytes]:
    vectors = root / VECTORS
    frame_directory = vectors / "frames"
    if frame_directory.is_symlink() or not frame_directory.is_dir():
        reject("frames entry is not a real directory")
    actual_paths: set[str] = set()
    for path in frame_directory.iterdir():
        if path.is_symlink() or not path.is_file() or path.stat().st_nlink != 1:
            reject(f"invalid direct frame entry: {path}")
        actual_paths.add(path.relative_to(vectors).as_posix())

    decoded: dict[str, bytes] = {}
    paths: set[str] = set()
    digests: set[str] = set()
    for row in rows:
        frame_id = row["frame_id"]
        kind = row["frame_kind"]
        relative = row["relative_path"]
        if kind not in {"request", "response"}:
            reject(f"invalid frame kind: {frame_id}")
        pure = Path(relative)
        if (
            pure.is_absolute()
            or "\\" in relative
            or not relative.startswith("frames/")
            or not relative.endswith(".hex")
            or len(pure.parts) != 2
            or any(part in ("", ".", "..") for part in pure.parts)
            or relative in paths
        ):
            reject(f"invalid or duplicate frame path: {frame_id}")
        text = read_text(vectors / relative)
        if text.count("\n") != 1:
            reject(f"noncanonical frame text: {frame_id}")
        data = parse_hex(text[:-1], field=frame_id)
        assert data is not None
        length = decimal(row["decoded_length"], field=frame_id)
        digest = row["decoded_sha256"]
        if len(data) != length or not LOWER_HASH.fullmatch(digest):
            reject(f"frame length or digest syntax mismatch: {frame_id}")
        if hashlib.sha256(data).hexdigest() != digest or digest in digests:
            reject(f"frame digest mismatch or alias: {frame_id}")
        paths.add(relative)
        digests.add(digest)

        parent = row["parent_frame_id"]
        mutation = row["mutation_kind"]
        offset = row["mutation_offset"]
        old = row["old_hex"]
        new = row["new_hex"]
        if mutation == "base":
            if (parent, offset, old, new) != ("-", "-", "-", "-"):
                reject(f"invalid base mutation row: {frame_id}")
        else:
            if parent not in decoded or parent >= frame_id:
                reject(f"missing or late mutation parent: {frame_id}")
            parent_data = decoded[parent]
            if kind != next(item["frame_kind"] for item in rows if item["frame_id"] == parent):
                reject(f"cross-kind mutation parent: {frame_id}")
            position = decimal(offset, field=frame_id)
            if mutation == "replace":
                old_data = parse_hex(old, field=frame_id)
                new_data = parse_hex(new, field=frame_id)
                assert old_data is not None and new_data is not None
                if not old_data or len(old_data) != len(new_data):
                    reject(f"invalid replacement width: {frame_id}")
                if parent_data[position : position + len(old_data)] != old_data:
                    reject(f"replacement source mismatch: {frame_id}")
                rebuilt = parent_data[:position] + new_data + parent_data[position + len(old_data) :]
            elif mutation == "append":
                new_data = parse_hex(new, field=frame_id)
                if old != "-" or new_data is None or not new_data or position != len(parent_data):
                    reject(f"invalid append row: {frame_id}")
                rebuilt = parent_data + new_data
            elif mutation == "truncate":
                if old != "-" or new != "-" or position != len(data) or position >= len(parent_data):
                    reject(f"invalid truncate row: {frame_id}")
                rebuilt = parent_data[:position]
            else:
                reject(f"invalid mutation kind: {frame_id}")
            if rebuilt != data:
                reject(f"mutation replay mismatch: {frame_id}")
        decoded[frame_id] = data
    if paths != actual_paths:
        reject("frame manifest paths do not equal direct frame files")
    return decoded


def verify_cases(
    rows: list[dict[str, str]], frames: dict[str, bytes], frame_rows: list[dict[str, str]]
) -> set[str]:
    semantic_rows = "".join(
        "\t".join(row[field] for field in TABLES["CASES_V1.tsv"]) + "\n" for row in rows
    ).encode("utf-8")
    if hashlib.sha256(semantic_rows).hexdigest() != EXPECTED_REPLAY_ROWS_SHA256:
        reject("replay full-row semantic oracle mismatch")
    frame_kinds = {row["frame_id"]: row["frame_kind"] for row in frame_rows}
    references: set[str] = set()
    unique: set[tuple[str, str, str]] = set()
    canonical_length_cases: set[str] = set()
    operations = {"request-decode", "request-prepare", "request-reencode", "response-decode"}
    for row in rows:
        frame = row["frame_id"]
        operation = row["operation"]
        epoch = row["expected_source_epoch_hex"]
        if frame not in frames or operation not in operations:
            reject(f"invalid replay reference: {row['case_id']}")
        expected_length_frame = CANONICAL_LENGTH_CASES.get(row["case_id"])
        if expected_length_frame is not None:
            if frame != expected_length_frame:
                reject(f"canonical-length case frame mismatch: {row['case_id']}")
            data = frames[frame]
            if len(data) < 16 or struct.unpack_from("<Q", data, 8)[0] != len(data):
                reject(f"noncanonical declared length: {row['case_id']}")
            canonical_length_cases.add(row["case_id"])
        request = operation.startswith("request-")
        if request != (frame_kinds[frame] == "request"):
            reject(f"case/frame kind mismatch: {row['case_id']}")
        if request:
            if epoch != "-":
                reject(f"request case has source argument: {row['case_id']}")
        elif not LOWER_HASH.fullmatch(epoch):
            reject(f"response source is not 32 bytes: {row['case_id']}")
        key = (frame, operation, epoch)
        if key in unique:
            reject(f"duplicate replay operation: {row['case_id']}")
        unique.add(key)
        status = row["expected_status"]
        code = decimal(row["expected_error_code"], field=row["case_id"])
        canonical = row["canonical_reencode"]
        if status not in {"ok", "error"} or canonical not in {"yes", "no"}:
            reject(f"invalid replay status: {row['case_id']}")
        if (status == "ok") != (code == 0) or code > 8:
            reject(f"invalid replay result: {row['case_id']}")
        if canonical == "yes" and not (status == "ok" and operation in {"request-decode", "request-reencode"}):
            reject(f"invalid canonical reencode claim: {row['case_id']}")
        if operation == "request-prepare" and code == 6:
            reject(f"candidate rejection is not decode-reachable: {row['case_id']}")
        references.add(frame)
    if canonical_length_cases != set(CANONICAL_LENGTH_CASES):
        reject("canonical-length replay coverage is not exact")
    return references


def fixed_hex(value: str, length: int, field: str) -> bytes:
    decoded = parse_hex(value, field=field)
    if decoded is None or len(decoded) != length:
        reject(f"wrong fixed hexadecimal width: {field}")
    return decoded


def parse_candidates(value: str, recipe_id: str) -> list[tuple[bytes, list[bytes]]]:
    if value == "-":
        return []
    candidates = []
    for record in value.split(";"):
        if record.count(":") != 1:
            reject(f"malformed candidate recipe: {recipe_id}")
        transaction_text, previous_text = record.split(":")
        if transaction_text == "_":
            transaction = b""
        elif not transaction_text:
            reject(f"empty candidate transaction text: {recipe_id}")
        else:
            transaction = parse_hex(transaction_text, field=recipe_id)
        if transaction is None:
            reject(f"malformed candidate bytes: {recipe_id}")
        previous = []
        if previous_text != "-":
            for item in previous_text.split(","):
                decoded = parse_hex(item, field=recipe_id)
                if decoded is None or not decoded:
                    reject(f"malformed previous transaction: {recipe_id}")
                previous.append(decoded)
        candidates.append((transaction, previous))
    return candidates


def parse_transactions(value: str, recipe_id: str) -> list[dict[str, object]]:
    if value == "-":
        return []
    transactions = []
    for record in value.split(";"):
        fields = record.split("/")
        if len(fields) != 3:
            reject(f"malformed transaction recipe: {recipe_id}")
        inputs = []
        if fields[2] != "-":
            for item in fields[2].split(","):
                if item.count(":") != 1:
                    reject(f"malformed input recipe: {recipe_id}")
                previous, index = item.split(":")
                inputs.append(
                    (fixed_hex(previous, 32, recipe_id), decimal_u32(index, field=recipe_id))
                )
        transactions.append(
            {
                "transaction_id": fixed_hex(fields[0], 32, recipe_id),
                "binding": fixed_hex(fields[1], 32, recipe_id),
                "inputs": inputs,
            }
        )
    return transactions


def parse_outputs(value: str, recipe_id: str) -> list[dict[str, object]]:
    if value == "-":
        return []
    outputs = []
    for record in value.split(";"):
        fields = record.split("/")
        if len(fields) != 10 or fields[5] not in {"external", "internal"}:
            reject(f"malformed output recipe: {recipe_id}")
        outputs.append(
            {
                "transaction_id": fixed_hex(fields[0], 32, recipe_id),
                "output_index": decimal_u32(fields[1], field=recipe_id),
                "binding": fixed_hex(fields[2], 32, recipe_id),
                "spend_key": fixed_hex(fields[3], 33, recipe_id),
                "blinding_key": fixed_hex(fields[4], 33, recipe_id),
                "branch": fields[5],
                "derivation_index": decimal_u32(fields[6], field=recipe_id),
                "asset_id": fixed_hex(fields[7], 32, recipe_id),
                "value": decimal_u64(fields[8], field=recipe_id),
                "script": parse_hex(fields[9], field=recipe_id),
            }
        )
    return outputs


def outputs_follow_transaction_order(recipe: dict[str, object]) -> bool:
    transactions = recipe["transactions"]
    outputs = recipe["outputs"]
    assert isinstance(transactions, list) and isinstance(outputs, list)
    positions = {
        transaction["transaction_id"]: position for position, transaction in enumerate(transactions)
    }
    previous_position = -1
    for output in outputs:
        position = positions.get(output["transaction_id"])
        if position is None:
            continue
        if position < previous_position:
            return False
        previous_position = position
    return True


def source_violations(recipe: dict[str, object]) -> list[str]:
    transactions = recipe["transactions"]
    outputs = recipe["outputs"]
    assert isinstance(transactions, list) and isinstance(outputs, list)
    violations = []
    previous_transaction = None
    known = {}
    for transaction in transactions:
        transaction_id = transaction["transaction_id"]
        if not any(transaction_id):
            violations.append("transaction-id-zero")
        if previous_transaction is not None and previous_transaction >= transaction_id:
            violations.append("transaction-order")
        previous_transaction = transaction_id
        known[transaction_id] = transaction
        inputs = transaction["inputs"]
        if not inputs:
            violations.append("transaction-inputs-empty")
        seen_inputs = set()
        for previous_id, index in inputs:
            if not any(previous_id) or index > 1_073_741_823 or (previous_id, index) in seen_inputs:
                violations.append("input-invalid")
            seen_inputs.add((previous_id, index))
    previous_output = {}
    for output in outputs:
        transaction_id = output["transaction_id"]
        if (
            output["output_index"] > 1_073_741_823
            or output["derivation_index"] > 100_000
            or not any(output["asset_id"])
            or not 1 <= output["value"] <= 9_223_372_036_854_775_807
            or output["spend_key"] != GENERATOR_PUBLIC_KEY
            or output["blinding_key"] != GENERATOR_PUBLIC_KEY
            or output["script"] != GENERATOR_SCRIPT
        ):
            violations.append("output-public-fields-invalid")
        parent = known.get(transaction_id)
        if parent is None:
            violations.append("output-orphan")
            continue
        if output["binding"] != parent["binding"]:
            violations.append("output-binding-mismatch")
        index = output["output_index"]
        if transaction_id in previous_output and previous_output[transaction_id] >= index:
            violations.append("output-order")
        previous_output[transaction_id] = index
    return violations


def encode_request_recipe(recipe: dict[str, object]) -> bytes:
    descriptor = recipe["descriptor"]
    candidates = recipe["candidates"]
    source = recipe["source_epoch"]
    assert isinstance(descriptor, bytes) and isinstance(candidates, list) and isinstance(source, bytes)
    body = bytearray(descriptor)
    previous_count = sum(len(previous) for _, previous in candidates)
    for transaction, previous in candidates:
        body += struct.pack("<III", len(transaction), len(previous), 0)
        body += transaction
        for item in previous:
            body += struct.pack("<I", len(item)) + item
    total = 76 + len(body)
    network = 0 if recipe["descriptor_network"] == "mainnet" else 1
    header = (
        b"WLFQ"
        + struct.pack("<HHQI", 1, 76, total, 0)
        + bytes([network])
        + b"\0" * 3
        + struct.pack("<I", recipe["last_derivation_index"])
        + source
        + struct.pack("<IIII", len(descriptor), len(candidates), previous_count, 0)
    )
    return header + body


def encode_response_recipe(recipe: dict[str, object]) -> bytes:
    transactions = recipe["transactions"]
    outputs = recipe["outputs"]
    source = recipe["source_epoch"]
    assert isinstance(transactions, list) and isinstance(outputs, list) and isinstance(source, bytes)
    body = bytearray()
    output_cursor = 0
    for transaction in transactions:
        output_start = output_cursor
        while (
            output_cursor < len(outputs)
            and outputs[output_cursor]["transaction_id"] == transaction["transaction_id"]
        ):
            output_cursor += 1
        grouped = outputs[output_start:output_cursor]
        body += transaction["transaction_id"] + transaction["binding"]
        body += struct.pack("<II", len(transaction["inputs"]), len(grouped))
        for previous_id, index in transaction["inputs"]:
            body += previous_id + struct.pack("<I", index)
        for output in grouped:
            body += struct.pack("<II", output["output_index"], len(output["script"]))
            body += output["spend_key"] + output["blinding_key"]
            body += bytes([0 if output["branch"] == "external" else 1]) + b"\0" * 3
            body += struct.pack("<I", output["derivation_index"])
            body += output["asset_id"] + struct.pack("<Q", output["value"]) + output["script"]
    if output_cursor != len(outputs):
        reject(f"response output order is not canonical: {recipe['recipe_id']}")
    total = 64 + len(body)
    return (
        b"WLFV"
        + struct.pack("<HHQIIII", 1, 64, total, 0, len(transactions), len(outputs), 0)
        + source
        + body
    )


def verify_recipes(rows: list[dict[str, str]]) -> dict[str, dict[str, object]]:
    if {row["recipe_id"] for row in rows} != set(RECIPE_PROPERTIES):
        reject("recipe identity set is not exact")
    parsed = {}
    for row in rows:
        recipe_id = row["recipe_id"]
        kind, property_token, _, _, _ = RECIPE_PROPERTIES[recipe_id]
        if row["recipe_kind"] != kind or row["expected_property"] != property_token:
            reject(f"recipe property relabel: {recipe_id}")
        source = fixed_hex(row["source_epoch_hex"], 32, recipe_id)
        recipe: dict[str, object] = {
            "recipe_id": recipe_id,
            "kind": kind,
            "source_epoch": source,
            "expected_property": property_token,
        }
        if kind == "request":
            if (
                row["descriptor_network"] not in {"mainnet", "test"}
                or row["transactions"] != "-"
                or row["outputs"] != "-"
            ):
                reject(f"request recipe field partition mismatch: {recipe_id}")
            descriptor = parse_hex(row["public_descriptor_hex"], field=recipe_id)
            if descriptor is None:
                reject(f"request descriptor missing: {recipe_id}")
            recipe.update(
                descriptor_network=row["descriptor_network"],
                last_derivation_index=decimal_u32(
                    row["last_derivation_index"], field=recipe_id
                ),
                descriptor=descriptor,
                candidates=parse_candidates(row["candidates"], recipe_id),
                transactions=[],
                outputs=[],
            )
            expected_request_shape = {
                "accepted-empty-request": (source, "test", 0, VALID_DESCRIPTOR, []),
                "accepted-nonempty-request": (
                    source,
                    "test",
                    0,
                    VALID_DESCRIPTOR,
                    [(b"\x01\x02\x03", [b"\x04", b"\x05\x06"])],
                ),
                "candidate-transaction-empty": (source, "test", 0, VALID_DESCRIPTOR, [(b"", [])]),
                "descriptor-semantic-and-candidate-empty": (
                    source,
                    "test",
                    0,
                    SEMANTIC_REJECT_DESCRIPTOR,
                    [(b"", [])],
                ),
                "zero-epoch-and-combined-invalid-request": (
                    bytes(32),
                    "test",
                    0,
                    SEMANTIC_REJECT_DESCRIPTOR,
                    [(b"", [])],
                ),
            }[property_token]
            actual_request_shape = (
                source,
                recipe["descriptor_network"],
                recipe["last_derivation_index"],
                recipe["descriptor"],
                recipe["candidates"],
            )
            if actual_request_shape != expected_request_shape:
                reject(f"request recipe exact shape mismatch: {recipe_id}")
            violations = []
            if not any(source):
                violations.append("epoch-zero")
            if descriptor == SEMANTIC_REJECT_DESCRIPTOR:
                violations.append("descriptor-semantic")
            elif descriptor != VALID_DESCRIPTOR:
                violations.append("descriptor-unexpected")
            if any(not transaction for transaction, _ in recipe["candidates"]):
                violations.append("candidate-empty")
            expected_violations = {
                "accepted-empty-request": [],
                "accepted-nonempty-request": [],
                "candidate-transaction-empty": ["candidate-empty"],
                "descriptor-semantic-and-candidate-empty": ["descriptor-semantic", "candidate-empty"],
                "zero-epoch-and-combined-invalid-request": ["epoch-zero", "descriptor-semantic", "candidate-empty"],
            }[property_token]
            if violations != expected_violations:
                reject(f"request recipe property mismatch: {recipe_id}")
            if property_token == "accepted-empty-request" and recipe["candidates"]:
                reject(f"empty request recipe is not empty: {recipe_id}")
            if property_token == "accepted-nonempty-request" and recipe["candidates"] != [(b"\x01\x02\x03", [b"\x04", b"\x05\x06"])]:
                reject(f"nonempty request shape mismatch: {recipe_id}")
        else:
            if any(row[field] != "-" for field in ("descriptor_network", "last_derivation_index", "public_descriptor_hex", "candidates")):
                reject(f"response recipe field partition mismatch: {recipe_id}")
            recipe.update(
                descriptor_network=None,
                last_derivation_index=None,
                descriptor=None,
                candidates=[],
                transactions=parse_transactions(row["transactions"], recipe_id),
                outputs=parse_outputs(row["outputs"], recipe_id),
            )
            if not outputs_follow_transaction_order(recipe):
                reject(f"response output grouping mismatch: {recipe_id}")
            violations = source_violations(recipe)
            expected_source = {
                "transaction-inputs-empty": ["transaction-inputs-empty"],
                "transaction-id-zero": ["transaction-id-zero"],
                "output-orphan": ["output-orphan"],
                "output-binding-mismatch": ["output-binding-mismatch"],
                "output-order": ["output-order"],
                "zero-epoch-and-transaction-inputs-empty": ["transaction-inputs-empty"],
            }.get(property_token, [])
            if violations != expected_source:
                reject(f"response source property mismatch: {recipe_id}")
            if property_token == "zero-epoch-and-transaction-inputs-empty":
                if any(source):
                    reject(f"zero-source response recipe has nonzero epoch: {recipe_id}")
            elif not any(source):
                reject(f"response recipe has zero epoch: {recipe_id}")
        parsed[recipe_id] = recipe
    return parsed


def verify_api(
    rows: list[dict[str, str]],
    frames: dict[str, bytes],
    frame_rows: list[dict[str, str]],
    recipes: dict[str, dict[str, object]],
) -> tuple[set[str], set[int]]:
    operations = {"request-encode", "response-encode", "response-source-validation"}
    seen_recipes: set[str] = set()
    references: set[str] = set()
    codes: set[int] = set()
    frame_kinds = {row["frame_id"]: row["frame_kind"] for row in frame_rows}
    for row in rows:
        operation = row["operation"]
        recipe = row["fixture_recipe"]
        status = row["expected_status"]
        code = decimal(row["expected_error_code"], field=row["case_id"])
        expected = row["expected_frame_id"]
        if operation not in operations or recipe not in recipes or recipe in seen_recipes:
            reject(f"invalid or duplicate API recipe: {row['case_id']}")
        seen_recipes.add(recipe)
        _, _, expected_operation, expected_status, expected_code = RECIPE_PROPERTIES[recipe]
        if (operation, status, code) != (expected_operation, expected_status, expected_code):
            reject(f"API recipe operation or result relabel: {row['case_id']}")
        if status not in {"ok", "error"} or (status == "ok") != (code == 0) or code > 7:
            reject(f"invalid API result: {row['case_id']}")
        if status == "ok":
            if expected not in frames:
                reject(f"missing API frame: {row['case_id']}")
            expected_kind = "request" if operation == "request-encode" else "response"
            if frame_kinds[expected] != expected_kind:
                reject(f"API frame kind mismatch: {row['case_id']}")
            encoded = (
                encode_request_recipe(recipes[recipe])
                if expected_kind == "request"
                else encode_response_recipe(recipes[recipe])
            )
            if encoded != frames[expected]:
                reject(f"recipe/frame byte mismatch: {row['case_id']}")
            references.add(expected)
        elif expected != "-":
            reject(f"error API case emits a frame: {row['case_id']}")
        if code == 6 and not (operation == "request-encode" and recipe == "candidate-rejected-request"):
            reject(f"candidate rejection on wrong surface: {row['case_id']}")
        if code == 7 and operation != "response-source-validation":
            reject(f"observation rejection on wrong surface: {row['case_id']}")
        codes.add(code)
    if seen_recipes != set(recipes):
        reject("API recipe coverage is incomplete")
    return references, codes


def evaluate_formula(formula: str) -> int | None:
    if not FORMULA.fullmatch(formula):
        reject("invalid boundary formula")
    total = 0
    for term in formula.split("+"):
        product = 1
        for factor in term.split("*"):
            value = int(factor)
            if value > U64_MAX or product > U64_MAX // value if value else False:
                return None
            product *= value
        if total > U64_MAX - product:
            return None
        total += product
    return total


def verify_boundaries(rows: list[dict[str, str]], corpus: str) -> None:
    operations = {
        "request-decode",
        "response-decode",
        "request-source-validation",
        "response-source-validation",
        "request-outer-length-check",
        "response-outer-length-check",
        "checked-arithmetic",
    }
    kinds = {"reachable-maximum", "outer-ceiling", "component-limit", "arithmetic-rejection"}
    actual_rows = {
        row["boundary_id"]: tuple(row[field] for field in TABLES["BOUNDARIES_V1.tsv"][1:])
        for row in rows
    }
    if actual_rows != EXPECTED_BOUNDARIES:
        reject("boundary row set or exact binding changed")
    expected_mapping_lines = {
        f"| {token} | {rust_name} | {contract_row} |"
        for token, (_, _, rust_name, contract_row) in CONSTANTS.items()
    }
    actual_mapping_lines = {
        line
        for line in corpus.splitlines()
        if line.startswith("| max-")
    }
    if actual_mapping_lines != expected_mapping_lines:
        reject("corpus constant mapping is not exact")
    seen_constants: set[str] = set()
    for row in rows:
        identifier = row["boundary_id"]
        operation = row["operation"]
        kind = row["boundary_kind"]
        constant = row["production_constant"]
        domain = row["numeric_domain"]
        status = row["expected_status"]
        code = decimal(row["expected_error_code"], field=identifier)
        if operation not in operations or kind not in kinds or domain not in {"u32", "u64", "usize64"}:
            reject(f"invalid boundary classification: {identifier}")
        value = evaluate_formula(row["formula"])
        if status == "overflow":
            if value is not None or row["expected_value"] != "-" or code != 4 or constant != "none":
                reject(f"invalid overflow row: {identifier}")
        else:
            expected = decimal(row["expected_value"], field=identifier)
            if value != expected or status not in {"ok", "rejected"}:
                reject(f"invalid boundary value: {identifier}")
            if (status == "ok") != (code == 0) or code > 8:
                reject(f"invalid boundary result: {identifier}")
            if constant not in CONSTANTS:
                reject(f"unknown boundary constant: {identifier}")
            maximum, expected_domain, _, _ = CONSTANTS[constant]
            if domain != expected_domain or constant not in corpus:
                reject(f"boundary constant mapping mismatch: {identifier}")
            if kind in {"component-limit", "outer-ceiling"}:
                if status == "ok" and value != maximum:
                    reject(f"maximum row does not equal constant: {identifier}")
                if status == "rejected" and value != maximum + 1:
                    reject(f"plus-one row does not exceed constant exactly: {identifier}")
            if kind == "reachable-maximum" and value != maximum:
                reject(f"reachable-size formula mismatch: {identifier}")
            seen_constants.add(constant)
    if set(CONSTANTS) - seen_constants:
        reject("symbolic constant coverage is incomplete")
    required = {
        "76+16384+4096*12+16384*4+67108864",
        "64+4096*72+1636801*36+148470*144",
        "18446744073709551615+1",
        "18446744073709551615*2",
    }
    if not required.issubset({row["formula"] for row in rows}):
        reject("mandatory boundary formulas are missing")


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: check-wallet-facts-conformance.py REPOSITORY_ROOT")
    root = Path(sys.argv[1]).resolve(strict=True)
    if not root.is_dir():
        reject("repository root is not a directory")
    vectors = root / VECTORS
    corpus = read_text(vectors / "CORPUS_V1.md")
    corpus_lines = corpus.splitlines()
    if corpus_lines.count(f"Corpus ID: {CORPUS_ID}") != 1 or corpus_lines.count("Wire version: 1") != 1:
        reject("corpus identity is not exact")
    tables = {name: parse_table(vectors / name, header) for name, header in TABLES.items()}
    frames = verify_frames(root, tables["FRAMES_V1.tsv"])
    recipes = verify_recipes(tables["RECIPES_V1.tsv"])
    replay_refs = verify_cases(tables["CASES_V1.tsv"], frames, tables["FRAMES_V1.tsv"])
    api_refs, api_codes = verify_api(
        tables["API_CASES_V1.tsv"], frames, tables["FRAMES_V1.tsv"], recipes
    )
    if replay_refs != set(frames):
        reject("every frame must have a replay case")
    if not api_refs.issubset(replay_refs):
        reject("API frame is outside the replay inventory")
    replay_codes = {decimal(row["expected_error_code"], field=row["case_id"]) for row in tables["CASES_V1.tsv"]}
    if (replay_codes | api_codes) != set(range(9)):
        reject("stable error-code coverage is incomplete")
    verify_boundaries(tables["BOUNDARIES_V1.tsv"], corpus)
    verify_checksums(root)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError) as error:
        print(f"wallet-facts conformance check failed: {error}", file=sys.stderr)
        raise SystemExit(1) from error
