#!/usr/bin/env python3
"""Mutation-test the exact sealed Rust subcommand PATH surface."""

from __future__ import annotations

import importlib.util
import os
import tempfile
from pathlib import Path


CHECKER = Path(__file__).with_name("check-sealed-rust-command-bin.py")


def rejected(operation, message: str) -> None:
    try:
        operation()
    except (OSError, ValueError):
        return
    raise AssertionError(message)


def main() -> int:
    spec = importlib.util.spec_from_file_location("sealed_commands", CHECKER)
    if spec is None or spec.loader is None:
        raise AssertionError("sealed Rust command checker import failed")
    checker = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(checker)
    with tempfile.TemporaryDirectory(prefix="wlpq-sealed-commands-") as directory:
        root = Path(directory).resolve()
        toolchain = root / "toolchain"
        command_bin = root / "commands"
        (toolchain / "bin").mkdir(parents=True)
        command_bin.mkdir()
        for name in checker.COMMANDS:
            executable = toolchain / "bin" / name
            executable.write_bytes(b"reviewed command")
            executable.chmod(0o755)
            os.symlink(executable, command_bin / name)
        command_bin.chmod(0o555)
        owner = os.getuid()
        checker.validate(command_bin, toolchain, owner)
        command_bin.chmod(0o755)
        (command_bin / "cargo-fmt").unlink()
        os.symlink(toolchain / "bin/cargo-clippy", command_bin / "cargo-fmt")
        command_bin.chmod(0o555)
        rejected(
            lambda: checker.validate(command_bin, toolchain, owner),
            "misdirected sealed Rust subcommand was accepted",
        )
    print("sealed Rust command mutations accepted")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
