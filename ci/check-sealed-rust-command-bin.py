#!/usr/bin/env python3
"""Validate the minimal PATH surface for sealed Rust subcommands."""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path


COMMANDS = ("cargo-fmt", "cargo-clippy", "clippy-driver")


def validate(command_bin: Path, toolchain: Path, owner: int) -> None:
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
    names = sorted(entry.name for entry in os.scandir(command_bin))
    if names != sorted(COMMANDS):
        raise ValueError("sealed Rust command topology mismatch")
    for name in COMMANDS:
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


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: check-sealed-rust-command-bin.py ABSOLUTE_BIN ABSOLUTE_TOOLCHAIN", file=sys.stderr)
        return 2
    try:
        validate(Path(sys.argv[1]), Path(sys.argv[2]), 0)
    except (OSError, ValueError) as error:
        print(f"sealed Rust command check failed: {error}", file=sys.stderr)
        return 1
    print("sealed Rust command authority accepted")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
