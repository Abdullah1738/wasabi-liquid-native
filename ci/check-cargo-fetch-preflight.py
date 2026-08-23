#!/usr/bin/env python3
"""Reject workspace authority that could influence the isolated Cargo fetch."""

from __future__ import annotations

import hashlib
import os
import stat
import sys
import tomllib
from pathlib import Path


WORKSPACE_LOCK_SHA256 = "67f5fa8be8d5f932f4a5ea55c43b32cf4961357a17986533f6fbb82432b7d263"
PROOF_LOCK_SHA256 = "4ca45ca0dd27b2a545b0d93174e02487cc756b26a34d946de5dcb349ceea7aab"
PROOF_TOOL = "tools/ordinary-wallet-plan-public-proof-verifier"
DENIED_NAMES = {".gitconfig", ".netrc", "credentials", "credentials.toml"}


def stable_identity(
    metadata: os.stat_result,
) -> tuple[int, int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def read_regular(root: Path, relative: Path, maximum: int = 1024 * 1024) -> bytes:
    path = root / relative
    path_metadata = os.lstat(path)
    if (
        not stat.S_ISREG(path_metadata.st_mode)
        or path_metadata.st_nlink != 1
        or path_metadata.st_size > maximum
    ):
        raise ValueError(
            f"fetch preflight input is linked, hardlinked, nonregular, or oversized: {relative}"
        )
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        metadata = os.fstat(descriptor)
        identity = stable_identity(path_metadata)
        if stable_identity(metadata) != identity:
            raise ValueError(
                f"fetch preflight input is linked, hardlinked, nonregular, or oversized: {relative}"
            )
        expected_size = metadata.st_size
        data = bytearray()
        while len(data) <= maximum:
            chunk = os.read(descriptor, min(64 * 1024, maximum + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        if len(data) != expected_size:
            raise ValueError(f"fetch preflight input changed size during read: {relative}")
        if (
            stable_identity(os.fstat(descriptor)) != identity
            or stable_identity(os.lstat(path)) != identity
        ):
            raise ValueError(f"fetch preflight input changed during read: {relative}")
        return bytes(data)
    finally:
        os.close(descriptor)


def validate(root: Path) -> None:
    if not root.is_absolute() or stat.S_ISLNK(os.lstat(root).st_mode) or not root.is_dir():
        raise ValueError("absolute regular workspace root is required")
    workspace_manifest = tomllib.loads(read_regular(root, Path("Cargo.toml")).decode("utf-8"))
    workspace = workspace_manifest.get("workspace")
    if not isinstance(workspace, dict) or workspace.get("exclude") != [PROOF_TOOL]:
        raise ValueError("workspace public-proof exclusion differs from exact authority")
    locks = {
        Path("Cargo.lock"): WORKSPACE_LOCK_SHA256,
        Path("ci/ordinary-wallet-plan-public-proof.Cargo.lock"): PROOF_LOCK_SHA256,
    }
    for relative, expected in locks.items():
        if hashlib.sha256(read_regular(root, relative)).hexdigest() != expected:
            raise ValueError(f"fetch lock differs from exact authority: {relative}")
    for directory, directories, files in os.walk(root, topdown=True, followlinks=False):
        current = Path(directory)
        if current == root / ".git" or current == root / "tmp":
            directories[:] = []
            continue
        for name in [*directories, *files]:
            path = current / name
            relative = path.relative_to(root)
            metadata = os.lstat(path)
            if stat.S_ISLNK(metadata.st_mode):
                raise ValueError(f"workspace fetch surface contains a symlink: {relative}")
            if name in DENIED_NAMES or ".cargo" in relative.parts:
                raise ValueError(f"workspace fetch surface contains Cargo or credential configuration: {relative}")


def validate_configuration_root(root: Path) -> None:
    if not root.is_absolute():
        raise ValueError("absolute Cargo configuration root is required")
    for relative in (Path(".cargo/config"), Path(".cargo/config.toml")):
        if os.path.lexists(root / relative):
            raise ValueError(f"Cargo configuration exists above fetch manifest: /{relative}")


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: check-cargo-fetch-preflight.py ABSOLUTE_WORKSPACE", file=sys.stderr)
        return 2
    try:
        validate(Path(sys.argv[1]))
        validate_configuration_root(Path("/"))
    except (OSError, UnicodeError, ValueError, tomllib.TOMLDecodeError) as error:
        print(f"Cargo fetch preflight failed: {error}", file=sys.stderr)
        return 1
    print("Cargo fetch authority accepted")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
