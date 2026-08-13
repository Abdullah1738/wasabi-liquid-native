#!/usr/bin/env python3
"""Copy the exact reviewed public-proof inputs and safe Cargo cache layers."""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import stat
import subprocess
import sys
import tarfile
import tomllib
from pathlib import Path


MAX_FILE_BYTES = 1024 * 1024 * 1024
MAX_CACHE_FILE_BYTES = 32 * 1024 * 1024
MAX_CACHE_TOTAL_BYTES = 96 * 1024 * 1024
MAX_CACHE_FILES = 192
MAX_CACHE_ENTRIES = 512
MAX_SEALED_CACHE_FILES = 20_000
MAX_SEALED_CACHE_ENTRIES = 30_000
MAX_SEALED_CACHE_TOTAL_BYTES = 1024 * 1024 * 1024
MAX_CACHE_AUTHORITY_BYTES = 8 * 1024 * 1024
MAX_SEALED_TREE_TOTAL_BYTES = 2 * 1024 * 1024 * 1024
MAX_PROOF_BINARY_BYTES = 64 * 1024 * 1024
TOOL = Path("tools/ordinary-wallet-plan-public-proof-verifier")
VECTORS = Path("contracts/ordinary-wallet-plan/v1/nonlinkable-reference/vectors")
SNAPSHOT_INVENTORY = Path("PROOF_SNAPSHOT_SHA256SUMS")
WORKSPACE_MANIFEST = b'''[workspace]
members = ["tools/ordinary-wallet-plan-public-proof-verifier"]
resolver = "3"

[patch.crates-io]
secp256k1-zkp-sys = { git = "https://github.com/Abdullah1738/rust-secp256k1-zkp.git", rev = "06ea6e06da81d2e3a51733c8d9b5f6c5fa248c2e" }
'''

FILES = {
    Path("ci/ordinary-wallet-plan-public-proof.Cargo.lock"): (7724, "4ca45ca0dd27b2a545b0d93174e02487cc756b26a34d946de5dcb349ceea7aab"),
    TOOL / "Cargo.toml": (633, "0ed6ccf01a7c8bc3d5efd8c7fa5abf7a702591ab5e84537301f73a314f99dcbb"),
    TOOL / "src/main.rs": (20139, "3cb9543957fc6d67ebc9c5a46904d7521c045a8596427c78f3eff7c4b40b58f1"),
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
GIT_DATABASES = {
    "git+https://github.com/liquid-wasabi/traits.git?rev=113c5ba12876e332335e49d1462a2c96c9928006#113c5ba12876e332335e49d1462a2c96c9928006": (
        "traits-30c7123dc6c55f9f",
        "113c5ba12876e332335e49d1462a2c96c9928006",
    ),
    "git+https://github.com/Abdullah1738/rust-elements.git?rev=5b8865f8061459f82dcb8a1cf476b7ba17b14193#5b8865f8061459f82dcb8a1cf476b7ba17b14193": (
        "rust-elements-6e97e0185cf5614d",
        "5b8865f8061459f82dcb8a1cf476b7ba17b14193",
    ),
    "git+https://github.com/Abdullah1738/rust-secp256k1-zkp.git?rev=06ea6e06da81d2e3a51733c8d9b5f6c5fa248c2e#06ea6e06da81d2e3a51733c8d9b5f6c5fa248c2e": (
        "rust-secp256k1-zkp-b4aef33f599129ea",
        "06ea6e06da81d2e3a51733c8d9b5f6c5fa248c2e",
    ),
}
LOCKED_REGISTRY_RECORD_SHA256 = {
    ("arrayvec", "0.7.8"): "a72c4f764183e93f789ef314855cead5692b44cf58e8ac0eb948ef30e463bc6f",
    ("base58ck", "0.1.101"): "c1e6e3040f9d928d5493a0d0d54058c41101af1247e3ae01a00a3f37cdf34e74",
    ("bech32", "0.11.1"): "08bb1650471f74d0d7b996962450ef732ed33fa3691f7f4955b2da6073e5bdb6",
    ("bitcoin", "0.32.102"): "ce75255f54f2ca24f9c53a2d1195982d7ae7379e8b35e34e661db9475437102d",
    ("bitcoin-consensus-encoding", "1.1.0"): "625d2b4b457b672821b03fe4ccf31519a54443d653711115e727aaf307f71afc",
    ("bitcoin-internals", "0.6.0"): "00b7245e313d2f0603767cef7869946f93ca1e99bbf35335b013b5173822779c",
    ("bitcoin-io", "0.1.101"): "bf9c4c89a2607d663609454c0083154dbbb33b4762d14ab4272666c34bdd8b70",
    ("bitcoin-private", "0.1.0"): "79bc20f216e8dde411d2f285514647885b1682d5895fe5482be319560320cf2b",
    ("bitcoin-units", "0.1.101"): "338290abd96868244cd6197b0f61ad37f09dacc1672a61cb2bb5d66008395579",
    ("bitcoin_hashes", "0.14.101"): "8ddbcf6ba72a94d83123c12be067721f13e4c063b043a8e546a6d0abb22ac1fb",
    ("bitcoin_hashes", "1.2.0"): "6514714a25bd3e0752bc7a11da51f15fadafadc740d4b05cd4a01bac533056dc",
    ("block-buffer", "0.12.1"): "cd790669e6a4cb4fc9ce477eca2a2ff263135e3d092ffbee6305053445aef5ed",
    ("cc", "1.4.2"): "9847c6568b11e080007ae09c9d3820c0d0531cee2655b9d4fb08df1eab90134b",
    ("cfg-if", "1.0.4"): "aaeec487cab298de772ad629cebb8dc4b456a0ddbbc14c20d612d23ae608110b",
    ("cpufeatures", "0.3.0"): "d2221fe3dd2a9e6ebb832d087cb2d7a40edbb1a3ea1c6a49f5e36e1a6b0fb338",
    ("crypto-common", "0.2.2"): "28619a872075826ff2dede4aa148af1359e14a5e4bba79f81ce8db4fd44de817",
    ("find-msvc-tools", "0.1.10"): "43e3f5ff6ec75a30c131263e1567272ea0cb5f67f5108201656d07f20693b917",
    ("getrandom", "0.2.17"): "17f66ab0599189b7ccdfbc808c847e782a93b5085f7518472bfa7249b26fd3d9",
    ("hex-conservative", "0.2.2"): "6b6910fb6b95bf7f099fa08a24651313c8e51abad3a88b10ed3b7fa7c94d28b8",
    ("hex-conservative", "1.2.0"): "a38912824be50676f7c7f4e8d8e0d63f56776085de3599a0baea096120f1dd99",
    ("hex_lit", "0.1.1"): "0054978f49ba703b6954c11de13b4d0c7f8f82e65e01f98553b3e1d62d50ac1f",
    ("hybrid-array", "0.4.14"): "7783a5fd5ebe1f6b7496f0a95ef7639766eaeb304a082a0e75cba43ab1e37b2d",
    ("libc", "0.2.189"): "1284aa9df41937e760dc3d6361129453feb39f880c8973f1e13d5a94d7a257dd",
    ("miniscript", "12.3.7"): "7611d73d4ff8fe27b336c69f94340c59c2720c86ac1e00c84d23fd241c6e3216",
    ("ppv-lite86", "0.2.21"): "1be13a56971c6d491dc8c01782d387ae509114f4b56a3e9e3f883a357c15bc31",
    ("proc-macro2", "1.0.107"): "2daaadb5e2ddd943bee4100b1082d160ec4cd69ebb8f2682712984c6398c275e",
    ("quote", "1.0.47"): "f1dc0ebd9351d3337dd57b499df78540d2230cd1f316a88836db4db1386f98d8",
    ("rand", "0.8.7"): "c997066164c1f368d30eaa82b8febcf975b5aad53bbf1f1fbb1150de48611f59",
    ("rand_chacha", "0.3.1"): "6fedc20ce2e8b189576865f92cab9fe355a56f0ce3f5d8ba185e8b6dfd10db3d",
    ("rand_core", "0.6.4"): "c3d741ce8e7916c1c7cfce8006a921814d05fb7696b29e12dcb156c66c37bb40",
    ("secp256k1", "0.29.1"): "fa2c4a449e16ed3a4bb1858dd86bd58310e145df8d1ea2bf295f4c04d8d41879",
    ("secp256k1-sys", "0.10.1"): "a8c23feeffb5f44bf802a46394a640d2c815861ef2c0942f813f1ce386e52db9",
    ("serde", "1.0.229"): "d9740f50cebe68e45732174d66bbe952be4835a91cb635ea2681802c08df42f6",
    ("serde_core", "1.0.229"): "96fde5cbe11105114c8373b138a74e2217f1cc7f2e838de5840d427b1d2c8803",
    ("serde_derive", "1.0.229"): "1cdde3866abcf3e08e0310b4a76ec5f192af69a446f20c3782b49f438e3e8a74",
    ("sha2", "0.11.0"): "d159ff45f9141c94be2dcdd704737028d7581027bd55287bfe993cf3cc69e09d",
    ("shlex", "2.0.1"): "ccae11eef9204c91a93e5975fbbd0d5b2ea7e84776af0b99b71719571cf45e81",
    ("static_assertions", "1.1.0"): "d1b8e035d19f342effc1a5b1711dacceee4367d67bb13b8fe9fb062eee20424b",
    ("syn", "2.0.119"): "555c62102ce4de76a82024d187257b3bf7d9b2e5c6a48285860069cd375ccef8",
    ("syn", "3.0.3"): "5018710744ddd3f12b5af54b8be9e3b6fe7e23d6e46d5970a2a86d74805db9f2",
    ("typenum", "1.20.1"): "7bf517054cae18d1dc5d8ea6777432bf5ef9c2c301d6e36f954a89d599ac25c3",
    ("unicode-ident", "1.0.24"): "dc45b57c858d1d24e84e2d41db9ce0401560e746ba079e3181f3421d72924d7c",
    ("wasi", "0.11.1+wasi-snapshot-preview1"): "f2a6d7597eff2a3ab123370449232a94940137e1e04ec636e5f7654a96aad0ae",
    ("zerocopy", "0.8.56"): "9020f3aadddcb5dbf4502452728ea8fbff42cc3430cce6cc9bfbdc7b8a541b87",
    ("zerocopy-derive", "0.8.56"): "761ba1aaf4be4cce3550b2d2dcdfd511ff39ff8cacf708d17e93c8e9b47924bb",
    ("zeroize", "1.9.0"): "fb933d9eb5eed435be80093830e1982139b78fc5090a1a10746bcdf226dfa797",
}


class SnapshotError(Exception):
    pass


def reject(message: str) -> None:
    raise SnapshotError(message)


def identity(value: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return value.st_dev, value.st_ino, value.st_mode, value.st_nlink, value.st_size, value.st_mtime_ns


def reject_linked_ancestors(root: Path, path: Path) -> None:
    if not root.is_absolute() or not path.is_absolute() or not path.is_relative_to(root):
        reject("snapshot source path escaped its absolute root")
    for ancestor in path.parents:
        metadata = os.lstat(ancestor)
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            reject("snapshot source ancestry is linked or non-directory")
        if ancestor == root:
            return
    reject("snapshot source root was not reached")


def stable_read(root: Path, path: Path, maximum: int = MAX_FILE_BYTES) -> bytes:
    reject_linked_ancestors(root, path)
    before = os.lstat(path)
    if (
        stat.S_ISLNK(before.st_mode)
        or not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or before.st_size > maximum
    ):
        reject("snapshot source is linked, hardlinked, nonregular, or oversized")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(descriptor)
        if identity(before) != identity(opened):
            reject("snapshot source changed before open")
        digest = hashlib.sha256()
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, maximum + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            digest.update(chunk)
            total += len(chunk)
            if total > maximum:
                reject("snapshot source exceeded its bound")
        after_handle = os.fstat(descriptor)
        after_path = os.lstat(path)
        if total != opened.st_size or identity(opened) != identity(after_handle) or identity(opened) != identity(after_path):
            reject("snapshot source changed during read")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def write_private(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def inventory_bytes(entries: dict[Path, bytes]) -> bytes:
    return "".join(
        f"{hashlib.sha256(data).hexdigest()}  {relative.as_posix()}\n"
        for relative, data in sorted(entries.items(), key=lambda item: item[0].as_posix().encode())
    ).encode("ascii")


def copy_exact_snapshot(source_root: Path, snapshot_root: Path) -> None:
    if os.path.lexists(snapshot_root):
        reject("proof snapshot destination already exists")
    snapshot_root.mkdir(mode=0o700, parents=True)
    copied = {Path("Cargo.toml"): WORKSPACE_MANIFEST}
    write_private(snapshot_root / "Cargo.toml", WORKSPACE_MANIFEST)
    for relative, (expected_length, expected_digest) in FILES.items():
        data = stable_read(source_root, source_root / relative, max(expected_length, 1))
        if len(data) != expected_length or hashlib.sha256(data).hexdigest() != expected_digest:
            reject(f"reviewed proof snapshot input mismatch: {relative}")
        destination = snapshot_root / relative
        if relative == Path("ci/ordinary-wallet-plan-public-proof.Cargo.lock"):
            destination = snapshot_root / "Cargo.lock"
        copied[destination.relative_to(snapshot_root)] = data
        write_private(destination, data)
    write_private(snapshot_root / SNAPSHOT_INVENTORY, inventory_bytes(copied))


def registry_index_path(name: str) -> Path:
    if len(name) == 1:
        return Path("1") / name
    if len(name) == 2:
        return Path("2") / name
    if len(name) == 3:
        return Path("3") / name[0] / name
    return Path(name[:2]) / name[2:4] / name


def validate_registry_config(data: bytes) -> None:
    try:
        value = json.loads(data)
    except (UnicodeError, json.JSONDecodeError):
        reject("crates.io cache configuration is not valid JSON")
    if value != {
        "dl": "https://static.crates.io/crates",
        "api": "https://crates.io",
    }:
        reject("crates.io cache configuration differs from exact authority")


def validate_sparse_entry(data: bytes, package: dict) -> None:
    if not data.startswith(b"\x03\x02\x00\x00\x00"):
        reject("sparse registry cache entry has an unknown format")
    fields = data[5:].split(b"\0")
    if fields and fields[-1] == b"":
        fields.pop()
    if not fields or not fields[0].startswith(b"etag: ") or len(fields[1:]) % 2 != 0:
        reject("sparse registry cache entry is noncanonical")
    matches = 0
    for version, encoded in zip(fields[1::2], fields[2::2], strict=True):
        try:
            record = json.loads(encoded)
        except (UnicodeError, json.JSONDecodeError):
            reject("sparse registry cache entry record is not valid JSON")
        if version.decode("utf-8") != record.get("vers") or record.get("name") != package["name"]:
            reject("sparse registry cache entry record identity mismatch")
        if record["vers"] == package["version"]:
            matches += 1
            if record.get("cksum") != package["checksum"]:
                reject("sparse registry cache entry checksum differs from the proof lock")
            expected_record = LOCKED_REGISTRY_RECORD_SHA256.get(
                (package["name"], package["version"])
            )
            if expected_record is None or hashlib.sha256(encoded).hexdigest() != expected_record:
                reject("sparse registry locked record differs from exact authority")
    if matches != 1:
        reject("sparse registry cache entry lacks the exact locked record")


def validate_git_config(data: bytes) -> None:
    try:
        lines = data.decode("utf-8").splitlines()
    except UnicodeError:
        reject("Git cache configuration is not UTF-8")
    if not lines or lines[0].strip().lower() != "[core]":
        reject("Git cache configuration lacks its exact core section")
    values: dict[str, str] = {}
    for line in lines[1:]:
        if not line.strip():
            continue
        key, separator, value = line.partition("=")
        key = key.strip().lower()
        value = value.strip().lower()
        if separator != "=" or key in values:
            reject("Git cache configuration is noncanonical")
        values[key] = value
    required = {"bare": "true", "repositoryformatversion": "0"}
    if any(values.get(key) != value for key, value in required.items()):
        reject("Git cache configuration changes repository semantics")
    allowed = {"bare", "repositoryformatversion", "filemode", "ignorecase", "precomposeunicode"}
    if not set(values).issubset(allowed) or values.get("filemode") not in {"true", "false"}:
        reject("Git cache configuration contains unreviewed authority")
    if any(values.get(key, "true") not in {"true", "false"} for key in ("ignorecase", "precomposeunicode")):
        reject("Git cache configuration contains a non-boolean platform option")


def validate_git_objects(objects: Path, files: list[Path]) -> None:
    packs: set[str] = set()
    indexes: set[str] = set()
    for path in files:
        relative = path.relative_to(objects)
        name = relative.name
        if len(relative.parts) == 2 and relative.parts[0] == "pack":
            match = re.fullmatch(r"pack-([0-9a-f]{40})\.(pack|idx)", name)
            if match is None:
                reject(
                    "Git object database contains an unreviewed pack sidecar: "
                    f"{relative.as_posix()!r}"
                )
            (packs if match.group(2) == "pack" else indexes).add(match.group(1))
        elif (
            len(relative.parts) == 2
            and re.fullmatch(r"[0-9a-f]{2}", relative.parts[0])
            and re.fullmatch(r"[0-9a-f]{38}", name)
        ):
            continue
        else:
            reject(
                "Git object database contains unreviewed indirection or metadata: "
                f"{relative.as_posix()!r}"
            )
    if packs != indexes:
        reject("Git object database pack and index closure differs")


def bounded_directory_entries(root: Path, directory: Path):
    reject_linked_ancestors(root, directory)
    metadata = os.lstat(directory)
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        reject("proof cache directory is linked or non-directory")
    count = 0
    with os.scandir(directory) as entries:
        for entry in entries:
            count += 1
            if count > MAX_CACHE_ENTRIES:
                reject("proof cache directory-entry bound exceeded")
            entry_metadata = entry.stat(follow_symlinks=False)
            if stat.S_ISLNK(entry_metadata.st_mode):
                reject("proof cache directory contains a symlink")
            yield Path(entry.path), entry_metadata


def bounded_regular_tree(root: Path, tree: Path) -> list[Path]:
    files: list[Path] = []
    pending = [tree]
    count = 0
    while pending:
        directory = pending.pop()
        reject_linked_ancestors(root, directory)
        metadata = os.lstat(directory)
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            reject("proof cache tree contains a linked or non-directory ancestor")
        with os.scandir(directory) as entries:
            for entry in entries:
                count += 1
                if count > MAX_CACHE_ENTRIES:
                    reject("proof cache tree-entry bound exceeded")
                entry_metadata = entry.stat(follow_symlinks=False)
                path = Path(entry.path)
                if stat.S_ISLNK(entry_metadata.st_mode):
                    reject("proof cache tree contains a symlink")
                if stat.S_ISDIR(entry_metadata.st_mode):
                    pending.append(path)
                elif stat.S_ISREG(entry_metadata.st_mode):
                    files.append(path)
                else:
                    reject("proof cache tree contains a special file")
    return sorted(files, key=lambda path: path.relative_to(tree).as_posix().encode())


def select_cache_source(
    selected: dict[Path, tuple[int, str]],
    source_cargo_home: Path,
    path: Path,
    maximum: int,
    data: bytes | None = None,
) -> bytes:
    if data is None:
        data = stable_read(source_cargo_home, path, maximum)
    relative = path.relative_to(source_cargo_home)
    if relative in selected:
        reject("proof cache authority selected a duplicate path")
    selected[relative] = (maximum, hashlib.sha256(data).hexdigest())
    return data


def exact_cache_sources(source_cargo_home: Path, lock_bytes: bytes) -> dict[Path, tuple[int, str]]:
    packages = tomllib.loads(lock_bytes.decode("utf-8"))["package"]
    registry = [package for package in packages if package.get("source", "").startswith("registry+")]
    registry_keys = {(package["name"], package["version"]) for package in registry}
    if not registry_keys or not registry_keys.issubset(LOCKED_REGISTRY_RECORD_SHA256):
        reject("proof cache registry record authority mismatch")
    git_sources = {package["source"] for package in packages if package.get("source", "").startswith("git+")}
    if not git_sources or not git_sources.issubset(GIT_DATABASES):
        reject("proof cache Git source authority mismatch")

    index_roots = []
    registry_index = source_cargo_home / "registry/index"
    for child, metadata in bounded_directory_entries(source_cargo_home, registry_index):
        if not stat.S_ISDIR(metadata.st_mode):
            reject("registry index cache contains a non-directory entry")
        config = child / "config.json"
        try:
            config_data = stable_read(source_cargo_home, config, 16 * 1024)
        except FileNotFoundError:
            continue
        if b"static.crates.io" in config_data:
            index_roots.append(child)
    if len(index_roots) != 1:
        reject("exact crates.io sparse index cache root was not found")
    index_root = index_roots[0]
    cache_root = source_cargo_home / "registry/cache" / index_root.name
    if not cache_root.is_dir():
        reject("matching crates.io archive cache root was not found")

    config = index_root / "config.json"
    registry_config_data = stable_read(source_cargo_home, config, 16 * 1024)
    validate_registry_config(registry_config_data)
    selected: dict[Path, tuple[int, str]] = {}
    select_cache_source(
        selected, source_cargo_home, config, 16 * 1024, registry_config_data
    )
    for package in registry:
        archive = cache_root / f"{package['name']}-{package['version']}.crate"
        archive_data = stable_read(source_cargo_home, archive, MAX_CACHE_FILE_BYTES)
        if hashlib.sha256(archive_data).hexdigest() != package["checksum"]:
            reject("registry archive checksum differs from the proof lock")
        select_cache_source(
            selected,
            source_cargo_home,
            archive,
            MAX_CACHE_FILE_BYTES,
            archive_data,
        )
        index_entry = index_root / ".cache" / registry_index_path(package["name"])
        index_data = stable_read(source_cargo_home, index_entry, MAX_CACHE_FILE_BYTES)
        validate_sparse_entry(index_data, package)
        if index_entry.relative_to(source_cargo_home) not in selected:
            select_cache_source(
                selected,
                source_cargo_home,
                index_entry,
                MAX_CACHE_FILE_BYTES,
                index_data,
            )

    for source in sorted(git_sources):
        database, commit = GIT_DATABASES[source]
        root = source_cargo_home / "git/db" / database
        config_data = stable_read(source_cargo_home, root / "config", 64 * 1024)
        validate_git_config(config_data)
        head_data = stable_read(source_cargo_home, root / "HEAD", 1024)
        if head_data != b"ref: refs/heads/master\n":
            reject("Git object database HEAD differs from exact authority")
        commit_ref = root / "refs/commit" / commit
        commit_data = stable_read(source_cargo_home, commit_ref, 1024)
        if commit_data != (commit + "\n").encode("ascii"):
            reject("Git object database commit reference differs from exact authority")
        objects = root / "objects"
        object_files = bounded_regular_tree(source_cargo_home, objects)
        validate_git_objects(objects, object_files)
        run_git(Path("/usr/bin/git"), ["--git-dir", str(root), "fsck", "--strict", "--no-reflogs", commit])
        git_tree_files(Path("/usr/bin/git"), root, commit)
    return selected


def copy_git_database(source: Path, destination: Path, commit: str, git_bin: Path) -> None:
    run_git(git_bin, ["clone", "--bare", "--no-hardlinks", str(source), str(destination)])
    config = destination / "config"
    os.unlink(config)
    write_private(
        config,
        b"[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = true\n\tignorecase = true\n\tprecomposeunicode = true\n",
    )
    head = destination / "HEAD"
    os.unlink(head)
    write_private(head, b"ref: refs/heads/master\n")
    commit_ref = destination / "refs/commit" / commit
    if os.path.lexists(commit_ref):
        os.unlink(commit_ref)
    write_private(commit_ref, (commit + "\n").encode("ascii"))
    for name in ("FETCH_HEAD", "packed-refs"):
        path = destination / name
        if os.path.lexists(path):
            os.unlink(path)
    object_files = bounded_regular_tree(destination.parent.parent.parent, destination / "objects")
    validate_git_objects(destination / "objects", object_files)
    for path in object_files:
        stable_read(destination.parent.parent.parent, path, MAX_CACHE_FILE_BYTES)
    run_git(git_bin, ["--git-dir", str(destination), "fsck", "--strict", "--no-reflogs", commit])
    git_tree_files(git_bin, destination, commit)


def copy_safe_cargo_cache(
    source_cargo_home: Path,
    destination: Path,
    lock_bytes: bytes,
    git_bin: Path = Path("/usr/bin/git"),
) -> None:
    if os.path.lexists(destination):
        reject("private Cargo home destination already exists")
    destination.mkdir(mode=0o700, parents=True)
    selected = exact_cache_sources(source_cargo_home, lock_bytes)
    if len(selected) > MAX_CACHE_FILES:
        reject("proof Cargo cache file-count bound exceeded")
    copied: dict[Path, bytes] = {}
    total = 0
    for relative, (maximum, expected_digest) in sorted(selected.items(), key=lambda item: item[0].as_posix().encode()):
        data = stable_read(source_cargo_home, source_cargo_home / relative, maximum)
        digest = hashlib.sha256(data).hexdigest()
        if digest != expected_digest:
            reject("proof Cargo cache digest differs from exact authority")
        total += len(data)
        if total > MAX_CACHE_TOTAL_BYTES:
            reject("proof Cargo cache aggregate byte bound exceeded")
        write_private(destination / relative, data)
        copied[relative] = data
    _, git_sources = locked_packages(lock_bytes)
    for source in sorted(git_sources):
        database, commit = GIT_DATABASES[source]
        copy_git_database(
            source_cargo_home / "git/db" / database,
            destination / "git/db" / database,
            commit,
            git_bin,
        )
    copied_authority = exact_cache_sources(destination, lock_bytes)
    copied_digests = {relative: digest for relative, (_, digest) in copied_authority.items()}
    if copied_digests != {relative: hashlib.sha256(data).hexdigest() for relative, data in copied.items()}:
        reject("private proof cache semantic closure differs after copy")


def locked_packages(lock_bytes: bytes) -> tuple[list[dict], set[str]]:
    packages = tomllib.loads(lock_bytes.decode("utf-8"))["package"]
    registry = [package for package in packages if package.get("source", "").startswith("registry+")]
    git_sources = {package["source"] for package in packages if package.get("source", "").startswith("git+")}
    if not registry or not git_sources:
        reject("locked dependency source closure is empty")
    return registry, git_sources


def registry_archive_entries(archive_data: bytes, package: dict) -> tuple[dict[Path, tuple[bytes, int]], set[Path]]:
    package_root = f"{package['name']}-{package['version']}"
    files: dict[Path, tuple[bytes, int]] = {}
    directories: set[Path] = {Path(".")}
    total = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(archive_data), mode="r:gz") as archive:
            for member in archive:
                if member.sparse is not None or member.issym() or member.islnk() or not (member.isfile() or member.isdir()):
                    reject("registry archive contains a link, sparse entry, or special file")
                raw = member.name.removesuffix("/")
                parts = raw.split("/")
                if (
                    not raw
                    or parts[0] != package_root
                    or any(part in ("", ".", "..") for part in parts)
                    or any(character in raw for character in ("\0", "\n", "\r", "\\"))
                ):
                    reject("registry archive path is unsafe or noncanonical")
                relative = Path(*parts[1:])
                if relative == Path("."):
                    if not member.isdir():
                        reject("registry archive root is not a directory")
                    continue
                if relative in files or relative in directories:
                    reject("registry archive contains a duplicate path")
                for parent in relative.parents:
                    if parent != Path("."):
                        directories.add(parent)
                if member.isdir():
                    directories.add(relative)
                    continue
                if member.size > MAX_CACHE_FILE_BYTES:
                    reject("registry archive member exceeds its bound")
                stream = archive.extractfile(member)
                if stream is None:
                    reject("registry archive file body is unavailable")
                data = stream.read(MAX_CACHE_FILE_BYTES + 1)
                if len(data) != member.size or len(data) > MAX_CACHE_FILE_BYTES:
                    reject("registry archive file body differs from its header")
                total += len(data)
                if len(files) >= MAX_SEALED_CACHE_FILES or total > MAX_SEALED_CACHE_TOTAL_BYTES:
                    reject("registry archive expanded closure exceeds its bound")
                files[relative] = (data, 0o755 if member.mode & 0o111 else 0o644)
    except (tarfile.TarError, EOFError, OSError):
        reject("registry archive is malformed")
    if not files or Path(".cargo-ok") in files or Path(".cargo-ok") in directories:
        reject("registry archive source closure is empty or reserves Cargo metadata")
    return files, directories


def exact_regular_source_tree(root: Path, *, ignored_root_directory: str | None = None) -> tuple[dict[Path, tuple[bytes, int]], set[Path]]:
    metadata = os.lstat(root)
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        reject("materialized source root is linked or non-directory")
    files: dict[Path, tuple[bytes, int]] = {}
    directories: set[Path] = {Path(".")}
    pending = [root]
    entries = total = 0
    while pending:
        directory = pending.pop()
        with os.scandir(directory) as children:
            ordered = sorted(children, key=lambda entry: entry.name.encode("utf-8"))
        for entry in ordered:
            relative = Path(entry.path).relative_to(root)
            if relative.parent == Path(".") and relative.name == ignored_root_directory:
                metadata = entry.stat(follow_symlinks=False)
                if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
                    reject("allowed materializer metadata is linked or non-directory")
                continue
            entries += 1
            if entries > MAX_SEALED_CACHE_ENTRIES:
                reject("materialized source topology exceeds its bound")
            metadata = entry.stat(follow_symlinks=False)
            if stat.S_ISLNK(metadata.st_mode):
                reject("materialized source contains a symlink")
            if stat.S_ISDIR(metadata.st_mode):
                directories.add(relative)
                pending.append(Path(entry.path))
            elif stat.S_ISREG(metadata.st_mode):
                if metadata.st_nlink != 1:
                    reject("materialized source contains a hardlinked file")
                data = stable_read(root, Path(entry.path), MAX_CACHE_FILE_BYTES)
                total += len(data)
                if len(files) >= MAX_SEALED_CACHE_FILES or total > MAX_SEALED_CACHE_TOTAL_BYTES:
                    reject("materialized source file closure exceeds its bound")
                files[relative] = (data, stat.S_IMODE(metadata.st_mode))
            else:
                reject("materialized source contains a special file")
    return files, directories


def validate_registry_materialization(materialized: Path, authority_home: Path, lock_bytes: bytes) -> None:
    registry, _ = locked_packages(lock_bytes)
    selected = exact_cache_sources(authority_home, lock_bytes)
    archive_roots = {
        relative.parts[2]
        for relative in selected
        if relative.is_relative_to(Path("registry/cache")) and len(relative.parts) == 4
    }
    if len(archive_roots) != 1:
        reject("materialized registry archive root is not exact")
    archive_root = next(iter(archive_roots))
    source_parent = materialized / "registry/src"
    children = list(bounded_directory_entries(materialized, source_parent))
    if len(children) != 1 or children[0][0].name != archive_root or not stat.S_ISDIR(children[0][1].st_mode):
        reject("materialized registry source root differs from its archive root")
    source_root = children[0][0]
    expected_packages = {f"{package['name']}-{package['version']}" for package in registry}
    actual_packages = {path.name for path, metadata in bounded_directory_entries(materialized, source_root) if stat.S_ISDIR(metadata.st_mode)}
    if actual_packages != expected_packages:
        reject("materialized registry package topology differs from the lock")
    for package in registry:
        name = f"{package['name']}-{package['version']}"
        archive_path = authority_home / "registry/cache" / archive_root / f"{name}.crate"
        archive_data = stable_read(authority_home, archive_path, MAX_CACHE_FILE_BYTES)
        if hashlib.sha256(archive_data).hexdigest() != package["checksum"]:
            reject("materialized registry archive differs from the lock")
        expected_files, expected_directories = registry_archive_entries(archive_data, package)
        actual_files, actual_directories = exact_regular_source_tree(source_root / name)
        marker = actual_files.pop(Path(".cargo-ok"), None)
        if marker != (b'{"v":1}', 0o644):
            reject("materialized registry Cargo marker differs from exact authority")
        if actual_directories != expected_directories or actual_files != expected_files:
            reject("materialized registry source differs from its exact archive")


def run_git(git_bin: Path, arguments: list[str], *, output_limit: int = MAX_SEALED_CACHE_TOTAL_BYTES) -> bytes:
    if not git_bin.is_absolute() or not os.access(git_bin, os.X_OK):
        reject("absolute executable Git path is required")
    environment = {
        "HOME": "/",
        "PATH": "/usr/bin:/bin",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_SYSTEM": "/dev/null",
        "GIT_CONFIG_COUNT": "2",
        "GIT_CONFIG_KEY_0": "pack.writeReverseIndex",
        "GIT_CONFIG_VALUE_0": "false",
        "GIT_CONFIG_KEY_1": "maintenance.auto",
        "GIT_CONFIG_VALUE_1": "false",
        "GIT_TERMINAL_PROMPT": "0",
    }
    result = subprocess.run(
        [str(git_bin), *arguments],
        cwd="/",
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0 or len(result.stdout) > output_limit or len(result.stderr) > 64 * 1024:
        reject("Git source authority command failed or exceeded its bound")
    return result.stdout


def git_tree_files(git_bin: Path, database: Path, commit: str) -> dict[Path, tuple[bytes, int]]:
    raw = run_git(git_bin, ["--git-dir", str(database), "ls-tree", "-rz", "--full-tree", commit])
    files: dict[Path, tuple[bytes, int]] = {}
    for encoded in raw.split(b"\0"):
        if not encoded:
            continue
        header, separator, raw_path = encoded.partition(b"\t")
        fields = header.split(b" ")
        if separator != b"\t" or len(fields) != 3 or fields[0] not in (b"100644", b"100755") or fields[1] != b"blob":
            reject("Git commit contains a symlink, submodule, or non-blob entry")
        try:
            path_text = raw_path.decode("utf-8")
        except UnicodeError:
            reject("Git commit path is not UTF-8")
        relative = Path(path_text)
        if relative.is_absolute() or ".." in relative.parts or relative.as_posix() != path_text or relative in files:
            reject("Git commit path is unsafe, noncanonical, or duplicated")
        data = run_git(git_bin, ["--git-dir", str(database), "cat-file", "blob", fields[2].decode("ascii")], output_limit=MAX_CACHE_FILE_BYTES)
        files[relative] = (data, 0o755 if fields[0] == b"100755" else 0o644)
    if not files:
        reject("Git commit source closure is empty")
    return files


def validate_checkout_git_config(data: bytes, database: Path) -> None:
    try:
        lines = data.decode("utf-8").splitlines()
    except UnicodeError:
        reject("Git checkout configuration is not UTF-8")
    section = ""
    values: dict[tuple[str, str], str] = {}
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("[") and stripped.endswith("]"):
            section = stripped[1:-1].strip().lower()
            if section not in {'core', 'remote "origin"', 'branch "master"'}:
                reject("Git checkout configuration contains an unreviewed section")
            continue
        key, separator, value = stripped.partition("=")
        identity = section, key.strip().lower()
        if not section or separator != "=" or identity in values:
            reject("Git checkout configuration is noncanonical")
        values[identity] = value.strip()
    required = {
        ("core", "repositoryformatversion"): "0",
        ("core", "bare"): "false",
        ('remote "origin"', "fetch"): "+refs/heads/*:refs/remotes/origin/*",
    }
    if any(values.get(key) != value for key, value in required.items()):
        reject("Git checkout configuration changes repository semantics")
    if values.get(("core", "filemode"), "").lower() not in {"true", "false"}:
        reject("Git checkout configuration lacks an exact file-mode policy")
    allowed = {
        ("core", "repositoryformatversion"),
        ("core", "filemode"),
        ("core", "bare"),
        ("core", "logallrefupdates"),
        ("core", "ignorecase"),
        ("core", "precomposeunicode"),
        ("core", "autocrlf"),
        ('remote "origin"', "url"),
        ('remote "origin"', "fetch"),
        ('branch "master"', "remote"),
        ('branch "master"', "merge"),
    }
    if not set(values).issubset(allowed):
        reject("Git checkout configuration contains unreviewed authority")
    for key in (
        ("core", "filemode"),
        ("core", "logallrefupdates"),
        ("core", "ignorecase"),
        ("core", "precomposeunicode"),
        ("core", "autocrlf"),
    ):
        if key in values and values[key].lower() not in {"true", "false"}:
            reject("Git checkout configuration contains a non-boolean platform option")
    origin = values.get(('remote "origin"', "url"))
    if origin not in {str(database), f"file://{database}"}:
        reject("Git checkout origin differs from its private object authority")
    branch_keys = {
        key for key in values if key[0] == 'branch "master"'
    }
    if branch_keys and (
        values.get(('branch "master"', "remote")) != "origin"
        or values.get(('branch "master"', "merge")) != "refs/heads/master"
    ):
        reject("Git checkout branch metadata differs from its private authority")


def validate_checkout_git_metadata(
    checkout: Path,
    database: Path,
    commit: str,
    *,
    allow_templates: bool = True,
) -> None:
    git_directory = checkout / ".git"
    # Cargo may hardlink its disposable checkout object store to git/db. Those
    # objects are never trusted or copied: the final checkout is reconstructed
    # from the separately validated authority database with --no-hardlinks.
    files, _ = exact_regular_source_tree(
        git_directory,
        ignored_root_directory="objects",
    )
    config = files.get(Path("config"))
    head = files.get(Path("HEAD"))
    index = files.get(Path("index"))
    if config is None or head is None or index is None:
        reject("Git checkout lacks required private metadata")
    validate_checkout_git_config(config[0], database)
    if head[0] not in {f"{commit}\n".encode("ascii"), b"ref: refs/heads/master\n"}:
        reject("Git checkout HEAD differs from its pinned commit")
    master = files.get(Path("refs/heads/master"))
    if head[0] == b"ref: refs/heads/master\n" and (
        master is None or master[0] != f"{commit}\n".encode("ascii")
    ):
        reject("Git checkout branch reference differs from its pinned commit")
    if not allow_templates and any(
        relative == Path("description")
        or relative == Path("info/exclude")
        or relative.is_relative_to("hooks")
        for relative in files
    ):
        reject("constructed Git checkout retained optional template metadata")
    allowed_fixed = {
        Path("HEAD"),
        Path("config"),
        Path("description"),
        Path("FETCH_HEAD"),
        Path("index"),
        Path("info/exclude"),
        Path("logs/HEAD"),
        Path("logs/refs/heads/master"),
        Path("refs/heads/master"),
    }
    for relative, (_, mode) in files.items():
        if relative in allowed_fixed:
            expected_mode = 0o644
        elif relative.is_relative_to("hooks") and relative.name.endswith(".sample"):
            expected_mode = 0o755
        else:
            reject("Git checkout contains unreviewed private metadata")
        if mode != expected_mode:
            path_utf8_hex = relative.as_posix().encode("utf-8").hex()
            reject(
                "Git checkout private metadata mode differs from exact authority: "
                f"path_utf8_hex={path_utf8_hex} is {mode:#05o}, "
                f"expected {expected_mode:#05o}"
            )


def copy_git_workspace_snapshot(
    source_root: Path,
    destination: Path,
    git_bin: Path,
    expected_head: str,
) -> None:
    if os.path.lexists(destination) or not re.fullmatch(r"[0-9a-f]{40}", expected_head):
        reject("workspace snapshot destination exists or head is noncanonical")
    git_directory = source_root / ".git"
    head = run_git(
        git_bin,
        ["--git-dir", str(git_directory), "rev-parse", "HEAD"],
        output_limit=1024,
    ).decode("ascii").strip()
    if head != expected_head:
        reject("workspace source head differs from exact CI authority")
    files = git_tree_files(git_bin, git_directory, expected_head)
    destination.mkdir(mode=0o700, parents=True)
    for relative, (expected, mode) in sorted(files.items(), key=lambda item: item[0].as_posix().encode()):
        actual = stable_read(source_root, source_root / relative, MAX_CACHE_FILE_BYTES)
        actual_mode = stat.S_IMODE(os.lstat(source_root / relative).st_mode)
        if actual != expected or actual_mode != mode:
            reject("workspace working source differs from its exact head")
        target = destination / relative
        write_private(target, actual)
        os.chmod(target, mode)


def seal_tree(root: Path, authority: Path) -> str:
    if not root.is_absolute() or not authority.is_absolute() or authority.is_relative_to(root) or os.path.lexists(authority):
        reject("absolute fresh external tree authority is required")
    records = cache_tree_records(root, maximum_file_bytes=MAX_FILE_BYTES, maximum_total_bytes=MAX_SEALED_TREE_TOTAL_BYTES)
    normalize_read_only(root)
    records = cache_tree_records(root, maximum_file_bytes=MAX_FILE_BYTES, maximum_total_bytes=MAX_SEALED_TREE_TOTAL_BYTES)
    encoded = cache_authority_bytes(records)
    write_private(authority, encoded)
    return hashlib.sha256(encoded).hexdigest()


def verify_tree(root: Path, authority: Path, digest: str, owner_uid: int) -> None:
    expected = parse_cache_authority(authority, digest)
    if cache_tree_records(root, maximum_file_bytes=MAX_FILE_BYTES, maximum_total_bytes=MAX_SEALED_TREE_TOTAL_BYTES) != expected:
        reject("sealed tree differs from its external authority")
    verify_owner(root, owner_uid)
    authority_metadata = os.lstat(authority)
    if authority_metadata.st_uid == owner_uid or stat.S_IMODE(authority_metadata.st_mode) != 0o444:
        reject("sealed tree authority ownership or mode differs")


def validate_git_materialization(
    materialized: Path,
    authority_home: Path,
    lock_bytes: bytes,
    git_bin: Path,
    *,
    constructed: bool = False,
) -> None:
    _, git_sources = locked_packages(lock_bytes)
    checkout_parent = materialized / "git/checkouts"
    expected_databases = {GIT_DATABASES[source][0] for source in git_sources}
    actual_databases = {path.name for path, metadata in bounded_directory_entries(materialized, checkout_parent) if stat.S_ISDIR(metadata.st_mode)}
    if actual_databases != expected_databases:
        reject("materialized Git checkout topology differs from the lock")
    for source in sorted(git_sources):
        database_name, commit = GIT_DATABASES[source]
        database = authority_home / "git/db" / database_name
        run_git(git_bin, ["--git-dir", str(database), "fsck", "--strict", "--no-reflogs", commit])
        expected = git_tree_files(git_bin, database, commit)
        checkout_root = materialized / "git/checkouts" / database_name
        children = list(bounded_directory_entries(materialized, checkout_root))
        if len(children) != 1 or not stat.S_ISDIR(children[0][1].st_mode) or not commit.startswith(children[0][0].name):
            reject("materialized Git checkout commit directory differs from the lock")
        checkout = children[0][0]
        actual, _ = exact_regular_source_tree(checkout, ignored_root_directory=".git")
        marker = actual.pop(Path(".cargo-ok"), None)
        if marker != (b"", 0o644) or actual != expected:
            reject("materialized Git checkout differs from its exact commit tree")
        validate_checkout_git_metadata(
            checkout,
            materialized / "git/db" / database_name,
            commit,
            allow_templates=not constructed,
        )


CACHE_TAG = b"Signature: 8a477f597d28d172789f06886806bc55\n# This file is a cache directory tag created by cargo.\n# For information about cache directory tags see https://bford.info/cachedir/\n"


def construct_final_sources(final: Path, lock_bytes: bytes, git_bin: Path) -> None:
    registry, git_sources = locked_packages(lock_bytes)
    selected = exact_cache_sources(final, lock_bytes)
    archive_roots = {relative.parts[2] for relative in selected if relative.is_relative_to(Path("registry/cache")) and len(relative.parts) == 4}
    if len(archive_roots) != 1:
        reject("final registry archive root is not exact")
    archive_root = next(iter(archive_roots))
    write_private(final / ".package-cache", b"")
    write_private(final / "registry/CACHEDIR.TAG", CACHE_TAG)
    write_private(final / "git/CACHEDIR.TAG", CACHE_TAG)
    for package in registry:
        name = f"{package['name']}-{package['version']}"
        archive_data = stable_read(final, final / "registry/cache" / archive_root / f"{name}.crate", MAX_CACHE_FILE_BYTES)
        files, directories = registry_archive_entries(archive_data, package)
        package_root = final / "registry/src" / archive_root / name
        for directory in sorted(directories, key=lambda path: (len(path.parts), path.as_posix().encode())):
            if directory != Path("."):
                (package_root / directory).mkdir(mode=0o700, parents=True, exist_ok=True)
        package_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        for relative, (data, mode) in sorted(files.items(), key=lambda item: item[0].as_posix().encode()):
            path = package_root / relative
            write_private(path, data)
            os.chmod(path, mode)
        write_private(package_root / ".cargo-ok", b'{"v":1}')
        os.chmod(package_root / ".cargo-ok", 0o644)
    empty_template = final / ".empty-git-template"
    empty_template.mkdir(mode=0o700)
    for source in sorted(git_sources):
        database_name, commit = GIT_DATABASES[source]
        checkout = final / "git/checkouts" / database_name / commit[:7]
        checkout.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        run_git(
            git_bin,
            [
                "clone",
                f"--template={empty_template}",
                "--no-hardlinks",
                "--no-checkout",
                str(final / "git/db" / database_name),
                str(checkout),
            ],
        )
        run_git(git_bin, ["--git-dir", str(checkout / ".git"), "--work-tree", str(checkout), "checkout", "--detach", commit])
        write_private(checkout / ".cargo-ok", b"")
        os.chmod(checkout / ".cargo-ok", 0o644)
    if list(os.scandir(empty_template)):
        reject("empty Git template gained an entry during reconstruction")
    empty_template.rmdir()


def finalize_cache_state(
    authority_home: Path,
    materialized: Path,
    final: Path,
    authority: Path,
    lock_bytes: bytes,
    git_bin: Path,
) -> str:
    if os.path.lexists(final):
        reject("final Cargo home destination already exists")
    exact_cache_sources(authority_home, lock_bytes)
    validate_registry_materialization(materialized, authority_home, lock_bytes)
    validate_git_materialization(materialized, authority_home, lock_bytes, git_bin)
    copy_safe_cargo_cache(authority_home, final, lock_bytes)
    construct_final_sources(final, lock_bytes, git_bin)
    validate_registry_materialization(final, final, lock_bytes)
    validate_git_materialization(final, final, lock_bytes, git_bin, constructed=True)
    return seal_cache_state(final, authority)


def cache_tree_records(
    root: Path,
    *,
    maximum_file_bytes: int = MAX_CACHE_FILE_BYTES,
    maximum_total_bytes: int = MAX_SEALED_CACHE_TOTAL_BYTES,
) -> list[dict[str, object]]:
    metadata = os.lstat(root)
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        reject("sealed Cargo source root is linked or non-directory")
    records: list[dict[str, object]] = [
        {"kind": "directory", "mode": stat.S_IMODE(metadata.st_mode), "path": "."}
    ]
    pending = [root]
    entries = files = total = 0
    while pending:
        directory = pending.pop()
        if directory != root:
            reject_linked_ancestors(root, directory)
        with os.scandir(directory) as children:
            ordered = sorted(children, key=lambda entry: entry.name.encode("utf-8"))
        for entry in ordered:
            entries += 1
            if entries > MAX_SEALED_CACHE_ENTRIES:
                reject("sealed Cargo source topology bound exceeded")
            path = Path(entry.path)
            relative = path.relative_to(root).as_posix()
            if any(character in relative for character in ("\0", "\n", "\r")):
                reject("sealed Cargo source path is noncanonical")
            entry_metadata = entry.stat(follow_symlinks=False)
            mode = stat.S_IMODE(entry_metadata.st_mode)
            if stat.S_ISLNK(entry_metadata.st_mode):
                reject("sealed Cargo source topology contains a symlink")
            if stat.S_ISDIR(entry_metadata.st_mode):
                records.append({"kind": "directory", "mode": mode, "path": relative})
                pending.append(path)
            elif stat.S_ISREG(entry_metadata.st_mode):
                files += 1
                if files > MAX_SEALED_CACHE_FILES:
                    reject("sealed Cargo source file-count bound exceeded")
                data = stable_read(root, path, maximum_file_bytes)
                total += len(data)
                if total > maximum_total_bytes:
                    reject("sealed Cargo source aggregate byte bound exceeded")
                records.append(
                    {
                        "kind": "file",
                        "mode": mode,
                        "path": relative,
                        "sha256": hashlib.sha256(data).hexdigest(),
                        "size": len(data),
                    }
                )
            else:
                reject("sealed Cargo source topology contains a special file")
    return sorted(records, key=lambda record: str(record["path"]).encode("utf-8"))


def cache_authority_bytes(records: list[dict[str, object]]) -> bytes:
    return b"".join(
        (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
        for record in records
    )


def require_materialized_source_closure(root: Path, records: list[dict[str, object]]) -> None:
    files = {
        Path(str(record["path"]))
        for record in records
        if record["kind"] == "file"
    }
    for prefix in (Path("registry/src"), Path("git/checkouts")):
        if not any(path.is_relative_to(prefix) for path in files):
            reject("sealed Cargo dependency source closure is not materialized")


def seal_cache_state(private_cargo_home: Path, authority: Path) -> str:
    if not private_cargo_home.is_absolute() or not authority.is_absolute():
        reject("absolute sealed Cargo source and authority paths are required")
    authority_parent = os.lstat(authority.parent)
    if (
        authority.is_relative_to(private_cargo_home)
        or os.path.lexists(authority)
        or stat.S_ISLNK(authority_parent.st_mode)
        or not stat.S_ISDIR(authority_parent.st_mode)
    ):
        reject("sealed Cargo authority must be new and outside its source root")
    for name in ("config", "config.toml", "credentials", "credentials.toml"):
        if os.path.lexists(private_cargo_home / name):
            reject("private Cargo home contains root configuration or credentials")
    records = cache_tree_records(private_cargo_home)
    require_materialized_source_closure(private_cargo_home, records)
    normalize_read_only(private_cargo_home)
    records = cache_tree_records(private_cargo_home)
    authority_bytes = cache_authority_bytes(records)
    write_private(authority, authority_bytes)
    return hashlib.sha256(authority_bytes).hexdigest()


def parse_cache_authority(authority: Path, expected_digest: str) -> list[dict[str, object]]:
    if not re.fullmatch(r"[0-9a-f]{64}", expected_digest):
        reject("sealed Cargo authority digest is noncanonical")
    data = stable_read(authority.parent, authority, MAX_CACHE_AUTHORITY_BYTES)
    if not data or hashlib.sha256(data).hexdigest() != expected_digest:
        reject("sealed Cargo external authority digest mismatch")
    records: list[dict[str, object]] = []
    prior = ""
    for line in data.splitlines():
        try:
            record = json.loads(line)
        except (UnicodeError, json.JSONDecodeError):
            reject("sealed Cargo external authority is invalid JSON")
        if not isinstance(record, dict) or record.get("kind") not in ("directory", "file"):
            reject("sealed Cargo external authority record is invalid")
        expected_keys = {"kind", "mode", "path"} | ({"sha256", "size"} if record["kind"] == "file" else set())
        path = record.get("path")
        if (
            set(record) != expected_keys
            or type(record.get("mode")) is not int
            or not 0 <= record["mode"] <= 0o7777
            or not isinstance(path, str)
            or not path
            or path <= prior
        ):
            reject("sealed Cargo external authority is noncanonical")
        relative = Path(path)
        if relative.is_absolute() or ".." in relative.parts or relative.as_posix() != path:
            reject("sealed Cargo external authority path escaped")
        if record["kind"] == "file" and (
            type(record.get("size")) is not int
            or record["size"] < 0
            or not isinstance(record.get("sha256"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", record["sha256"])
        ):
            reject("sealed Cargo external file authority is invalid")
        canonical = (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
        if canonical != line + b"\n":
            reject("sealed Cargo external authority encoding is noncanonical")
        records.append(record)
        prior = path
    return records


def parse_inventory(root: Path, path: Path) -> dict[Path, str]:
    text = stable_read(root, path, MAX_CACHE_FILES * 256).decode("ascii")
    entries: dict[Path, str] = {}
    for line in text.splitlines():
        digest, separator, name = line.partition("  ")
        relative = Path(name)
        if (
            separator != "  "
            or len(digest) != 64
            or any(byte not in "0123456789abcdef" for byte in digest)
            or relative.is_absolute()
            or ".." in relative.parts
            or relative in entries
        ):
            reject("private proof inventory is noncanonical")
        entries[relative] = digest
    return entries


def verify_inventory(root: Path, inventory: Path) -> None:
    entries = parse_inventory(root, root / inventory)
    for relative, expected_digest in entries.items():
        data = stable_read(root, root / relative, MAX_FILE_BYTES)
        if hashlib.sha256(data).hexdigest() != expected_digest:
            reject("private proof inventory digest mismatch")
    expected = {Path("Cargo.toml"), Path("Cargo.lock"), TOOL / "Cargo.toml", TOOL / "src/main.rs", VECTORS / "PUBLIC_PROOF_CASES_V1.tsv"}
    expected.update(VECTORS / relative for relative in (
        Path("public/main-candidate-valid.hex"), Path("public/main-previous-valid.hex"),
        Path("public/test-candidate-damaged-proof.hex"), Path("public/test-candidate-shared-previous-valid.hex"),
        Path("public/test-candidate-explicit.hex"), Path("public/test-candidate-unowned.hex"),
        Path("public/test-candidate-valid.hex"), Path("public/test-previous-shared-valid.hex"),
        Path("public/test-previous-unrelated.hex"), Path("public/test-previous-valid.hex"),
    ))
    if set(entries) != expected:
        reject("private proof snapshot inventory differs from exact authority")
    actual = set()
    for directory, directories, files in os.walk(root, topdown=True, followlinks=False):
        directories.sort()
        files.sort()
        for name in [*directories, *files]:
            metadata = os.lstat(Path(directory) / name)
            if stat.S_ISLNK(metadata.st_mode):
                reject("private proof snapshot contains a symlink")
        actual.update((Path(directory) / name).relative_to(root) for name in files)
    if actual != expected | {SNAPSHOT_INVENTORY}:
        reject("private proof snapshot file topology differs from exact authority")


def verify_owner(root: Path, expected_uid: int) -> None:
    pending = [root]
    while pending:
        path = pending.pop()
        metadata = os.lstat(path)
        if metadata.st_uid == expected_uid:
            reject("sealed source ownership differs from its enforced authority")
        if stat.S_ISDIR(metadata.st_mode):
            with os.scandir(path) as children:
                pending.extend(Path(child.path) for child in children)


def verify_cache_state(
    private_cargo_home: Path,
    authority: Path,
    expected_authority_digest: str,
    expected_owner_uid: int | None = None,
) -> None:
    for name in ("config", "config.toml", "credentials", "credentials.toml"):
        if os.path.lexists(private_cargo_home / name):
            reject("private Cargo home contains root configuration or credentials")
    expected = parse_cache_authority(authority, expected_authority_digest)
    actual = cache_tree_records(private_cargo_home)
    require_materialized_source_closure(private_cargo_home, actual)
    if actual != expected:
        reject("sealed Cargo source closure differs from external authority")
    if expected_owner_uid is not None:
        verify_owner(private_cargo_home, expected_owner_uid)
        authority_metadata = os.lstat(authority)
        if authority_metadata.st_uid == expected_owner_uid or stat.S_IMODE(authority_metadata.st_mode) != 0o444:
            reject("sealed Cargo external authority ownership or mode differs")


def verify_private_state(
    snapshot_root: Path,
    private_cargo_home: Path,
    authority: Path,
    expected_authority_digest: str,
    expected_owner_uid: int | None = None,
) -> None:
    verify_inventory(snapshot_root, SNAPSHOT_INVENTORY)
    if expected_owner_uid is not None:
        verify_owner(snapshot_root, expected_owner_uid)
    verify_cache_state(private_cargo_home, authority, expected_authority_digest, expected_owner_uid)


def normalize_read_only(root: Path) -> None:
    def fail_traversal(error: OSError) -> None:
        raise error

    for directory, directories, files in os.walk(
        root,
        topdown=False,
        onerror=fail_traversal,
        followlinks=False,
    ):
        for name in files:
            path = Path(directory) / name
            metadata = os.lstat(path)
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
                reject("sealed tree normalization encountered a linked or special file")
            os.chmod(path, 0o555 if stat.S_IMODE(metadata.st_mode) & 0o111 else 0o444)
        for name in directories:
            path = Path(directory) / name
            metadata = os.lstat(path)
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
                reject("sealed tree normalization encountered a linked or non-directory entry")
            os.chmod(path, 0o555)
    os.chmod(root, 0o555)


def main() -> int:
    if len(sys.argv) not in (3, 4, 5, 6, 7, 9):
        print("usage: prepare-ordinary-wallet-plan-proof-snapshot.py [--binary-digest ABSOLUTE_BINARY] | [--snapshot-only SOURCE_ROOT DESTINATION] | [--workspace-snapshot SOURCE_ROOT DESTINATION GIT_BIN HEAD] | [--copy-cache SOURCE_HOME DESTINATION LOCK_FILE LOCK_SHA256] | [--seal-tree ROOT EXTERNAL_AUTHORITY] | [--verify-tree ROOT EXTERNAL_AUTHORITY AUTHORITY_SHA256 BUILD_UID] | [--finalize-cache AUTHORITY_CARGO_HOME MATERIALIZED_CARGO_HOME FINAL_CARGO_HOME EXTERNAL_AUTHORITY LOCK_FILE GIT_BIN LOCK_SHA256] | [--verify-cache PRIVATE_CARGO_HOME EXTERNAL_AUTHORITY AUTHORITY_SHA256 BUILD_UID] | [--verify SNAPSHOT_ROOT PRIVATE_CARGO_HOME EXTERNAL_AUTHORITY AUTHORITY_SHA256 BUILD_UID] | [--workspace-cache SOURCE_ROOT SOURCE_CARGO_HOME PRIVATE_CARGO_HOME] | [SOURCE_ROOT SNAPSHOT_ROOT SOURCE_CARGO_HOME PRIVATE_CARGO_HOME]", file=sys.stderr)
        return 2
    try:
        if len(sys.argv) == 3 and sys.argv[1] == "--binary-digest":
            binary = Path(sys.argv[2])
            if not binary.is_absolute():
                reject("absolute private proof binary path is required")
            print(hashlib.sha256(stable_read(Path(binary.anchor), binary, MAX_PROOF_BINARY_BYTES)).hexdigest())
            return 0
        if len(sys.argv) == 4 and sys.argv[1] == "--snapshot-only":
            source_root, destination = map(lambda value: Path(value).absolute(), sys.argv[2:])
            copy_exact_snapshot(source_root, destination)
            normalize_read_only(destination)
            print("exact public-proof source snapshot accepted")
            return 0
        if len(sys.argv) == 6 and sys.argv[1] == "--workspace-snapshot":
            source_root, destination, git_bin = map(lambda value: Path(value).absolute(), sys.argv[2:5])
            copy_git_workspace_snapshot(source_root, destination, git_bin, sys.argv[5])
            print("exact workspace source snapshot accepted")
            return 0
        if len(sys.argv) == 6 and sys.argv[1] == "--copy-cache":
            source_home, destination, lock_file = map(lambda value: Path(value).absolute(), sys.argv[2:5])
            expected_lock_digest = sys.argv[5]
            if expected_lock_digest not in {
                FILES[Path("ci/ordinary-wallet-plan-public-proof.Cargo.lock")][1],
                "f5e471c6a9664d29e8c30ea44b0c6934d3be98c00d87d5ea45cb5843b717adde",
            }:
                reject("copied Cargo source lock authority is unreviewed")
            lock_bytes = stable_read(lock_file.parent, lock_file, 256 * 1024)
            if hashlib.sha256(lock_bytes).hexdigest() != expected_lock_digest:
                reject("copied Cargo source lock digest mismatch")
            copy_safe_cargo_cache(source_home, destination, lock_bytes)
            print("private Cargo authority copied")
            return 0
        if len(sys.argv) == 4 and sys.argv[1] == "--seal-tree":
            root, authority = map(lambda value: Path(value).absolute(), sys.argv[2:])
            print(seal_tree(root, authority))
            return 0
        if len(sys.argv) == 6 and sys.argv[1] == "--verify-tree":
            root, authority = map(lambda value: Path(value).absolute(), sys.argv[2:4])
            verify_tree(root, authority, sys.argv[4], int(sys.argv[5]))
            print("sealed tree state accepted")
            return 0
        if len(sys.argv) == 9 and sys.argv[1] == "--finalize-cache":
            authority_home, materialized, final, authority, lock_file, git_bin = map(
                lambda value: Path(value).absolute(), sys.argv[2:8]
            )
            expected_lock_digest = sys.argv[8]
            if expected_lock_digest not in {
                FILES[Path("ci/ordinary-wallet-plan-public-proof.Cargo.lock")][1],
                "f5e471c6a9664d29e8c30ea44b0c6934d3be98c00d87d5ea45cb5843b717adde",
            }:
                reject("final Cargo source lock authority is unreviewed")
            lock_bytes = stable_read(lock_file.parent, lock_file, 256 * 1024)
            if hashlib.sha256(lock_bytes).hexdigest() != expected_lock_digest:
                reject("final Cargo source lock digest mismatch")
            print(finalize_cache_state(authority_home, materialized, final, authority, lock_bytes, git_bin))
            return 0
        if len(sys.argv) == 6 and sys.argv[1] == "--verify-cache":
            private_cargo_home = Path(sys.argv[2]).absolute()
            authority = Path(sys.argv[3]).absolute()
            verify_cache_state(private_cargo_home, authority, sys.argv[4], int(sys.argv[5]))
            print("private Cargo cache state accepted")
            return 0
        if len(sys.argv) == 7 and sys.argv[1] == "--verify":
            snapshot_root, private_cargo_home, authority = map(lambda value: Path(value).absolute(), sys.argv[2:5])
            verify_private_state(snapshot_root, private_cargo_home, authority, sys.argv[5], int(sys.argv[6]))
            print("ordinary-wallet-plan private proof state accepted")
            return 0
        if len(sys.argv) == 5 and sys.argv[1] == "--workspace-cache":
            source_root, source_cargo_home, private_cargo_home = map(
                lambda value: Path(value).absolute(), sys.argv[2:]
            )
            lock_bytes = stable_read(source_root, source_root / "Cargo.lock", 256 * 1024)
            if hashlib.sha256(lock_bytes).hexdigest() != "f5e471c6a9664d29e8c30ea44b0c6934d3be98c00d87d5ea45cb5843b717adde":
                reject("workspace cache authority lock mismatch")
            copy_safe_cargo_cache(source_cargo_home, private_cargo_home, lock_bytes)
            print("private workspace Cargo cache copied")
            return 0
        source_root, snapshot_root, source_cargo_home, private_cargo_home = map(lambda value: Path(value).absolute(), sys.argv[1:])
        for path in (source_root, source_cargo_home):
            metadata = os.lstat(path)
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
                reject("snapshot input root is linked or non-directory")
        copy_exact_snapshot(source_root, snapshot_root)
        proof_lock = Path("ci/ordinary-wallet-plan-public-proof.Cargo.lock")
        expected_length, expected_digest = FILES[proof_lock]
        lock_bytes = stable_read(source_root, source_root / proof_lock, expected_length)
        if len(lock_bytes) != expected_length or hashlib.sha256(lock_bytes).hexdigest() != expected_digest:
            reject("proof cache authority lock mismatch")
        copy_safe_cargo_cache(source_cargo_home, private_cargo_home, lock_bytes)
        normalize_read_only(snapshot_root)
    except (OSError, SnapshotError, ValueError) as error:
        print(f"ordinary-wallet-plan proof snapshot failed: {error}", file=sys.stderr)
        return 1
    print("ordinary-wallet-plan private proof snapshot accepted")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
