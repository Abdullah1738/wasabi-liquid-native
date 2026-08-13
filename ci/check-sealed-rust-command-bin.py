#!/usr/bin/env python3
"""Validate the minimal PATH surface for sealed Rust subcommands."""

from __future__ import annotations

import hashlib
import os
import stat
import sys
from pathlib import Path


RUST_COMMANDS = ("cargo-fmt", "cargo-clippy", "clippy-driver")
DARWIN_COMMANDS = ("cc", "c++", "clang", "clang++", "ar", "as", "ld", "nm", "ranlib", "strip")


def stable_digest(path: Path) -> tuple[os.stat_result, str]:
    before = os.lstat(path)
    if (
        not path.is_absolute()
        or stat.S_ISLNK(before.st_mode)
        or not stat.S_ISREG(before.st_mode)
        or not stat.S_IMODE(before.st_mode) & 0o111
        or stat.S_IMODE(before.st_mode) & 0o022
        or path.resolve(strict=True) != path
    ):
        raise ValueError("sealed Darwin command target is noncanonical")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        opened = os.fstat(descriptor)
        identity = lambda value: (
            value.st_dev,
            value.st_ino,
            value.st_mode,
            value.st_uid,
            value.st_gid,
            value.st_size,
            value.st_mtime_ns,
            value.st_ctime_ns,
        )
        if identity(opened) != identity(before):
            raise ValueError("sealed Darwin command target changed before hashing")
        digest = hashlib.sha256()
        while block := os.read(descriptor, 1024 * 1024):
            digest.update(block)
        after = os.fstat(descriptor)
        if identity(after) != identity(opened) or identity(os.lstat(path)) != identity(opened):
            raise ValueError("sealed Darwin command target changed while hashing")
    finally:
        os.close(descriptor)
    return before, digest.hexdigest()


def validate(
    command_bin: Path,
    toolchain: Path,
    owner: int,
    darwin_targets: dict[str, Path] | None = None,
    darwin_digests: dict[str, str] | None = None,
) -> None:
    metadata = os.lstat(command_bin)
    if (
        not command_bin.is_absolute()
        or not toolchain.is_absolute()
        or stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != owner
        or stat.S_IMODE(metadata.st_mode) != 0o555
    ):
        raise ValueError("sealed Rust command directory authority mismatch")
    if (darwin_targets is None) != (darwin_digests is None) or (
        darwin_targets is not None
        and (tuple(darwin_targets) != DARWIN_COMMANDS or tuple(darwin_digests or {}) != DARWIN_COMMANDS)
    ):
        raise ValueError("sealed Darwin command target topology mismatch")
    commands = RUST_COMMANDS + (() if darwin_targets is None else DARWIN_COMMANDS)
    names = sorted(entry.name for entry in os.scandir(command_bin))
    if names != sorted(commands):
        raise ValueError("sealed Rust command topology mismatch")
    for name in RUST_COMMANDS:
        path = command_bin / name
        link = os.lstat(path)
        expected = toolchain / "bin" / name
        if (
            not stat.S_ISLNK(link.st_mode)
            or link.st_nlink != 1
            or link.st_uid != owner
            or os.readlink(path) != str(expected)
            or path.resolve(strict=True) != expected
        ):
            raise ValueError(f"sealed Rust command authority mismatch: {name}")
    if darwin_targets is not None:
        for name, expected in darwin_targets.items():
            target, digest = stable_digest(expected)
            path = command_bin / name
            link = os.lstat(path)
            if (
                digest != (darwin_digests or {})[name]
                or not stat.S_ISLNK(link.st_mode)
                or link.st_nlink != 1
                or link.st_uid != owner
                or os.readlink(path) != str(expected)
                or path.resolve(strict=True) != expected
            ):
                raise ValueError(f"sealed Darwin command authority mismatch: {name}")


def main() -> int:
    if len(sys.argv) == 3 and sys.argv[1] == "--digest":
        try:
            print(stable_digest(Path(sys.argv[2]))[1])
        except (OSError, ValueError) as error:
            print(f"sealed Darwin command digest failed: {error}", file=sys.stderr)
            return 1
        return 0
    if len(sys.argv) not in (3, 23):
        print(
            "usage: check-sealed-rust-command-bin.py ABSOLUTE_BIN ABSOLUTE_TOOLCHAIN [10 DARWIN TARGETS AND 10 SHA256 DIGESTS]",
            file=sys.stderr,
        )
        return 2
    try:
        darwin_targets = (
            None
            if len(sys.argv) == 3
            else dict(zip(DARWIN_COMMANDS, map(Path, sys.argv[3:13]), strict=True))
        )
        darwin_digests = (
            None
            if len(sys.argv) == 3
            else dict(zip(DARWIN_COMMANDS, sys.argv[13:23], strict=True))
        )
        if darwin_digests is not None and any(
            len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest)
            for digest in darwin_digests.values()
        ):
            raise ValueError("sealed Darwin command digest is noncanonical")
        validate(Path(sys.argv[1]), Path(sys.argv[2]), 0, darwin_targets, darwin_digests)
    except (OSError, ValueError) as error:
        print(f"sealed Rust command check failed: {error}", file=sys.stderr)
        return 1
    print("sealed Rust command authority accepted")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
