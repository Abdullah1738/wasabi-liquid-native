#!/usr/bin/env python3
"""Validate the exact CI-only public-proof verifier source boundary."""

from __future__ import annotations

import hashlib
import os
import re
import stat
import sys
import tomllib
from pathlib import Path


TOOL = Path("tools/ordinary-wallet-plan-public-proof-verifier")
MAIN = TOOL / "src/main.rs"
EXPECTED_FILES = {TOOL / "Cargo.toml", MAIN}
TEST_MARKER = "\n#[cfg(test)]\nmod tests {"
EXPECTED_SOURCE_SHA256 = "3cb9543957fc6d67ebc9c5a46904d7521c045a8596427c78f3eff7c4b40b58f1"
EXPECTED_PRODUCTION_SHA256 = "e745a731c26d86c392a98f2740feb0e3673f6e1b8ea2dcd647a32f794f1c42b7"
MAX_MANIFEST_BYTES = 256 * 1024
MAX_SOURCE_BYTES = 128 * 1024
MAX_DEP_INFO_BYTES = 256 * 1024
VECTORS = Path("contracts/ordinary-wallet-plan/v1/nonlinkable-reference/vectors")
SNAPSHOT_INVENTORY = Path("PROOF_SNAPSHOT_SHA256SUMS")
SNAPSHOT_FILES = {
    Path("Cargo.toml"): (246, "42952b2479c608f073e017410c8fd958150ab0c707775487b10a7c2b4c8ca9e8"),
    Path("Cargo.lock"): (7724, "4ca45ca0dd27b2a545b0d93174e02487cc756b26a34d946de5dcb349ceea7aab"),
    TOOL / "Cargo.toml": (633, "0ed6ccf01a7c8bc3d5efd8c7fa5abf7a702591ab5e84537301f73a314f99dcbb"),
    MAIN: (20139, EXPECTED_SOURCE_SHA256),
    VECTORS / "PUBLIC_PROOF_CASES_V1.tsv": (547, "d414a588c48626f3ad6559d08c06caf119a5a48a062366d873ec4e3f689958b9"),
    VECTORS / "public/main-candidate-valid.hex": (8939, "5ac9af421de6b13c4a46f02cb4f87a9615a94ff870807dc901ce4d17121b117d"),
    VECTORS / "public/main-previous-valid.hex": (113, "c6587f890979d7e1fa98b7ac7377393ad6675da9fbf754f327b505ee6e6a75ba"),
    VECTORS / "public/test-candidate-damaged-proof.hex": (587, "2a9ddd36836310f4de81c5848777572430198f6390145ef6bf02bad48a67e460"),
    VECTORS / "public/test-candidate-explicit.hex": (325, "3b831802fcd1462991fd8367937c83c0b9f152fd5216bb2fa19c0656f64d1dee"),
    VECTORS / "public/test-candidate-shared-previous-valid.hex": (9093, "5ae3c56cb5136bcc4efb02a8e2a50d26d1c5cc3ef323502b92325828dd6c10cb"),
    VECTORS / "public/test-candidate-valid.hex": (8939, "198d9a1333e903eab6ffa84b2de31bdc70870e2ad78b9d285f2458f67273a5b5"),
    VECTORS / "public/test-candidate-unowned.hex": (8939, "68f8e0b111e8ea81f2773f8c56afad88cf734e26dd324a74b8683e328adbf03c"),
    VECTORS / "public/test-previous-shared-valid.hex": (203, "80d7c9cab008c5bb3c4636f7a46ae8a5c574dceeeb50782f15ddbb42b0b97c20"),
    VECTORS / "public/test-previous-unrelated.hex": (113, "9428bb6b2a610cc77022201ec93db1761d454989c35781c418936949b233143b"),
    VECTORS / "public/test-previous-valid.hex": (113, "542e90e1e087b1ec5322195f713d5518584855f039b7247230ef247f949b3b3f"),
}


class SurfaceError(Exception):
    pass


def reject(message: str) -> None:
    raise SurfaceError(message)


def file_identity(value: os.stat_result) -> tuple[int, int, int, int, int]:
    return (value.st_dev, value.st_ino, value.st_mode, value.st_size, value.st_mtime_ns)


def read_bounded_regular(path: Path, maximum: int) -> bytes:
    before = os.lstat(path)
    if not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode) or before.st_size > maximum:
        reject("public proof verifier authority file is linked, nonregular, or oversized")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or file_identity(before) != file_identity(opened):
            reject("public proof verifier authority file changed before open")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            data = stream.read(maximum + 1)
        after_handle = os.fstat(descriptor)
        after_path = os.lstat(path)
        if (
            len(data) > maximum
            or len(data) != opened.st_size
            or file_identity(opened) != file_identity(after_handle)
            or file_identity(opened) != file_identity(after_path)
        ):
            reject("public proof verifier authority file changed during read")
        return data
    finally:
        os.close(descriptor)


def read_bounded_text(path: Path, maximum: int) -> str:
    return read_bounded_regular(path, maximum).decode("utf-8")


def exact_file_topology(root: Path, *, check_ancestor_config: bool = True) -> None:
    files: set[Path] = set()
    tool = root / TOOL
    cargo_configuration = root / ".cargo"
    if os.path.lexists(cargo_configuration):
        reject("repository Cargo configuration is outside exact proof authority")
    if check_ancestor_config:
        for ancestor in (root, *root.parents):
            for name in ("config", "config.toml"):
                if os.path.lexists(ancestor / ".cargo" / name):
                    reject("ancestor Cargo configuration is outside exact proof authority")
    for path in (root, root / TOOL.parts[0], tool, tool / "src", tool / "Cargo.toml", root / MAIN):
        if path.is_symlink():
            reject("public proof verifier path ancestry contains a symlink")
    if not tool.is_dir() or not (tool / "src").is_dir():
        reject("public proof verifier directory topology differs from exact authority")
    for directory, directories, names in os.walk(tool, followlinks=False):
        directory_path = Path(directory)
        for name in [*directories, *names]:
            path = directory_path / name
            if path.is_symlink():
                reject("public proof verifier source topology contains a symlink")
        files.update((directory_path / name).relative_to(root) for name in names)
    if files != EXPECTED_FILES:
        reject("public proof verifier source-file topology differs from exact authority")


def validate_manifest(root: Path, *, snapshot: bool = False) -> None:
    workspace_manifest = tomllib.loads(read_bounded_text(root / "Cargo.toml", MAX_MANIFEST_BYTES))
    workspace = workspace_manifest["workspace"]
    manifest = tomllib.loads(read_bounded_text(root / TOOL / "Cargo.toml", MAX_MANIFEST_BYTES))
    package = manifest.get("package", {})
    expected_package = {
        "name": "wasabi-liquid-native-ordinary-wallet-plan-public-proof-verifier",
        "version": "0.1.0",
        "edition": "2024",
        "rust-version": "1.96",
        "license": "MIT",
        "publish": False,
        "build": False,
        "autolib": False,
        "autobins": False,
        "autoexamples": False,
        "autotests": False,
        "autobenches": False,
        "description": "CI-only public proof verifier for the ordinary wallet plan corpus",
    }
    expected_bin = [{
        "name": "ordinary-wallet-plan-public-proof-verifier",
        "path": "src/main.rs",
        "test": True,
        "bench": False,
    }]
    expected_elements = {
        "git": "https://github.com/Abdullah1738/rust-elements.git",
        "rev": "5b8865f8061459f82dcb8a1cf476b7ba17b14193",
        "default-features": False,
    }
    if (
        set(manifest) != {"package", "bin", "dependencies"}
        or package != expected_package
        or manifest.get("bin") != expected_bin
        or manifest.get("dependencies") != {"elements": expected_elements}
    ):
        reject("public proof verifier manifest or workspace boundary differs from exact authority")
    if snapshot:
        expected_patch = {
            "secp256k1-zkp-sys": {
                "git": "https://github.com/Abdullah1738/rust-secp256k1-zkp.git",
                "rev": "06ea6e06da81d2e3a51733c8d9b5f6c5fa248c2e",
            },
        }
        if workspace_manifest != {
            "workspace": {"members": [TOOL.as_posix()], "resolver": "3"},
            "patch": {"crates-io": expected_patch},
        }:
            reject("private proof snapshot workspace manifest differs from exact authority")
    elif (
        TOOL.as_posix() in workspace["members"]
        or TOOL.as_posix() in workspace["default-members"]
        or workspace.get("exclude", []).count(TOOL.as_posix()) != 1
    ):
        reject("public proof verifier workspace exclusion differs from exact authority")


def rust_block_end(source: str, opening: int) -> int:
    depth = 0
    index = opening
    while index < len(source):
        if source.startswith("//", index):
            newline = source.find("\n", index + 2)
            index = len(source) if newline == -1 else newline + 1
            continue
        if source.startswith("/*", index):
            comment_depth = 1
            index += 2
            while index < len(source) and comment_depth:
                if source.startswith("/*", index):
                    comment_depth += 1
                    index += 2
                elif source.startswith("*/", index):
                    comment_depth -= 1
                    index += 2
                else:
                    index += 1
            if comment_depth:
                reject("public proof verifier has an unterminated block comment")
            continue
        raw = re.match(r'(?:br|r)(#*)"', source[index:])
        if raw:
            terminator = '"' + raw.group(1)
            end = source.find(terminator, index + raw.end())
            if end == -1:
                reject("public proof verifier has an unterminated raw string")
            index = end + len(terminator)
            continue
        if source[index] in ('"', "'"):
            quote = source[index]
            index += 1
            while index < len(source):
                if source[index] == "\\":
                    index += 2
                elif source[index] == quote:
                    index += 1
                    break
                else:
                    index += 1
            else:
                reject("public proof verifier has an unterminated quoted token")
            continue
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return index + 1
            if depth < 0:
                reject("public proof verifier has an unmatched closing brace")
        index += 1
    reject("public proof verifier test module is unterminated")


def validate_source(root: Path) -> None:
    source_bytes = read_bounded_regular(root / MAIN, MAX_SOURCE_BYTES)
    source = source_bytes.decode("utf-8")
    if hashlib.sha256(source_bytes).hexdigest() != EXPECTED_SOURCE_SHA256:
        reject("public proof verifier complete source differs from exact reviewed authority")
    if not source.startswith("#![forbid(unsafe_code)]\n"):
        reject("public proof verifier does not forbid unsafe code")
    if source.count(TEST_MARKER) != 1:
        reject("public proof verifier test boundary is not exact and singular")
    marker = source.index(TEST_MARKER)
    opening = marker + len(TEST_MARKER) - 1
    if rust_block_end(source, opening) != len(source.rstrip()) or not source.endswith("\n"):
        reject("public proof verifier test module is not the final source item")
    production = source[:marker]
    if hashlib.sha256(production.encode()).hexdigest() != EXPECTED_PRODUCTION_SHA256:
        reject("public proof verifier production source differs from exact reviewed authority")
    expected_uses = {
        "use std::collections::{BTreeMap, BTreeSet};",
        "use std::env;",
        "use std::fs::{self, File, Metadata};",
        "use std::io::Read;",
        "use std::path::{Path, PathBuf};",
        "use elements::confidential::{RangeProof, SurjectionProof, Value};",
        "use elements::encode::{deserialize, serialize};",
        "use elements::hashes::sha256;",
        "use elements::secp256k1_zkp::Secp256k1;",
        "use elements::{Transaction, TxOut, VerificationError};",
        "use std::os::unix::fs::MetadataExt;",
    }
    actual_uses = {match.group(0).strip() for match in re.finditer(r"(?m)^\s*use [^;\n]+;", production)}
    if actual_uses != expected_uses:
        reject("public proof verifier import surface differs from exact authority")
    policy_source = production.replace("#![forbid(unsafe_code)]", "", 1)
    forbidden = re.compile(
        r"\b(?:unsafe|extern|macro_rules|mod\s+[A-Za-z_]|include(?:_bytes|_str)?!|"
        r"global_asm!|asm!|env!|option_env!|SecretKey|Keypair|getrandom|OpenOptions|"
        r"Command|std::net|std::thread|fs::write|fs::remove|fs::rename|fs::copy|"
        r"File::create)"
    )
    if forbidden.search(policy_source):
        reject("public proof verifier production source escaped its public read-only boundary")
    filesystem_calls = set(re.findall(r"\b(?:fs|File)::[A-Za-z_][A-Za-z0-9_]*", production))
    if filesystem_calls != {"fs::MetadataExt", "fs::symlink_metadata", "File::open"}:
        reject("public proof verifier filesystem API whitelist differs from exact authority")
    if production.count("std::process::exit(1)") != 1 or production.count("process::") != 1:
        reject("public proof verifier process API whitelist differs from exact authority")
    if production.count("env::args_os()") != 1 or production.count("env::") != 1:
        reject("public proof verifier environment API whitelist differs from exact authority")


def validate_snapshot_inputs(root: Path) -> None:
    expected_inventory = "".join(
        f"{digest}  {relative.as_posix()}\n"
        for relative, (_, digest) in sorted(SNAPSHOT_FILES.items(), key=lambda item: item[0].as_posix().encode())
    )
    if read_bounded_text(root / SNAPSHOT_INVENTORY, 16 * 1024) != expected_inventory:
        reject("private proof snapshot inventory differs from exact authority")
    actual = set()
    for directory, directories, files in os.walk(root, topdown=True, followlinks=False):
        directories.sort()
        files.sort()
        for name in [*directories, *files]:
            metadata = os.lstat(Path(directory) / name)
            if stat.S_ISLNK(metadata.st_mode):
                reject("private proof snapshot topology contains a symlink")
        actual.update((Path(directory) / name).relative_to(root) for name in files)
    if actual != set(SNAPSHOT_FILES) | {SNAPSHOT_INVENTORY}:
        reject("private proof snapshot file topology differs from exact authority")
    for relative, (expected_length, expected_digest) in SNAPSHOT_FILES.items():
        data = read_bounded_regular(root / relative, max(expected_length, 1))
        if len(data) != expected_length or hashlib.sha256(data).hexdigest() != expected_digest:
            reject("private proof snapshot input differs from exact authority")


def validate_dep_info(root: Path, dep_info: Path) -> None:
    text = read_bounded_text(dep_info, MAX_DEP_INFO_BYTES).replace("\\\n", " ")
    dependencies: set[Path] = set()
    for line in text.splitlines():
        _, separator, right = line.partition(":")
        if not separator:
            continue
        for token in right.split():
            path = Path(token.replace("\\ ", " "))
            if path.is_absolute():
                try:
                    path = path.resolve().relative_to(root)
                except ValueError:
                    reject("public proof verifier compiler source closure escaped repository root")
            dependencies.add(path)
    if dependencies != {MAIN}:
        reject("public proof verifier compiler source closure differs from exact authority")


def preflight(root: Path) -> None:
    if not root.is_absolute() or not root.is_dir():
        reject("absolute repository root directory is required")
    exact_file_topology(root)
    validate_manifest(root)
    validate_source(root)


def run(root: Path, dep_info: Path) -> None:
    if not dep_info.is_absolute():
        reject("absolute compiler dep-info path is required")
    preflight(root)
    validate_dep_info(root, dep_info)


def run_snapshot(root: Path, dep_info: Path) -> None:
    if not root.is_absolute() or not root.is_dir() or root.is_symlink() or not dep_info.is_absolute():
        reject("absolute private snapshot root and dep-info paths are required")
    exact_file_topology(root, check_ancestor_config=False)
    validate_snapshot_inputs(root)
    validate_manifest(root, snapshot=True)
    validate_source(root)
    validate_dep_info(root, dep_info)


def main() -> int:
    if len(sys.argv) not in (2, 3, 4):
        print("usage: check-ordinary-wallet-plan-public-proof-surface.py [--snapshot] ABSOLUTE_ROOT [ABSOLUTE_DEP_INFO]", file=sys.stderr)
        return 2
    try:
        if len(sys.argv) == 4 and sys.argv[1] == "--snapshot":
            run_snapshot(Path(sys.argv[2]), Path(sys.argv[3]))
        elif len(sys.argv) == 2:
            root = Path(sys.argv[1])
            preflight(root)
        elif len(sys.argv) == 3:
            root = Path(sys.argv[1])
            run(root, Path(sys.argv[2]))
        else:
            reject("invalid public proof surface checker invocation")
    except (OSError, UnicodeError, KeyError, TypeError, ValueError, tomllib.TOMLDecodeError, SurfaceError) as error:
        print(f"ordinary-wallet-plan public proof surface check failed: {error}", file=sys.stderr)
        return 1
    print("ordinary-wallet-plan public proof source surface accepted")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
