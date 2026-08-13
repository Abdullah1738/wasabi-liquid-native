#!/usr/bin/env python3
"""Mutation-test the exact sealed Rust subcommand PATH surface."""

from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
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
        for name in checker.RUST_COMMANDS:
            executable = toolchain / "bin" / name
            executable.write_bytes(b"reviewed command")
            executable.chmod(0o755)
            os.symlink(executable, command_bin / name)
        command_bin.chmod(0o555)
        owner = os.getuid()
        checker.validate(command_bin, toolchain, owner)
        cli_result = subprocess.run(
            [sys.executable, "-I", str(CHECKER), str(command_bin), str(toolchain)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        if (cli_result.returncode == 0) != (owner == 0):
            raise AssertionError("sealed Rust command production CLI owner boundary differs")
        invalid_arity = subprocess.run(
            [sys.executable, "-I", str(CHECKER)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        if invalid_arity.returncode != 2:
            raise AssertionError("sealed Rust command CLI accepted invalid arity")
        command_bin.chmod(0o755)
        (command_bin / "cargo-fmt").unlink()
        os.symlink(toolchain / "bin/cargo-clippy", command_bin / "cargo-fmt")
        command_bin.chmod(0o555)
        rejected(
            lambda: checker.validate(command_bin, toolchain, owner),
            "misdirected sealed Rust subcommand was accepted",
        )

        command_bin.chmod(0o755)
        (command_bin / "cargo-fmt").unlink()
        os.symlink(toolchain / "bin/cargo-fmt", command_bin / "cargo-fmt")
        darwin_bin = root / "darwin-toolchain"
        darwin_bin.mkdir()
        darwin_targets = {}
        for name in checker.DARWIN_COMMANDS:
            executable = (darwin_bin / name).resolve()
            executable.write_bytes(f"reviewed Darwin command: {name}".encode())
            executable.chmod(0o755)
            darwin_targets[name] = executable
            os.symlink(executable, command_bin / name)
        darwin_digests = {
            name: checker.stable_digest(executable)[1]
            for name, executable in darwin_targets.items()
        }
        digest_result = subprocess.run(
            [sys.executable, "-I", str(CHECKER), "--digest", str(darwin_targets["cc"])],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        if digest_result.returncode != 0 or digest_result.stdout.strip() != darwin_digests["cc"]:
            raise AssertionError("sealed Darwin command digest CLI differs")
        command_bin.chmod(0o555)
        checker.validate(command_bin, toolchain, owner, darwin_targets, darwin_digests)

        command_bin.chmod(0o755)
        (command_bin / "cc").unlink()
        os.symlink(darwin_targets["c++"], command_bin / "cc")
        command_bin.chmod(0o555)
        rejected(
            lambda: checker.validate(
                command_bin, toolchain, owner, darwin_targets, darwin_digests
            ),
            "misdirected sealed Darwin command was accepted",
        )
        rejected(
            lambda: checker.validate(
                command_bin,
                toolchain,
                owner,
                dict(list(darwin_targets.items())[:-1]),
                dict(list(darwin_digests.items())[:-1]),
            ),
            "incomplete sealed Darwin command target map was accepted",
        )
        command_bin.chmod(0o755)
        (command_bin / "cc").unlink()
        os.symlink(darwin_targets["cc"], command_bin / "cc")
        command_bin.chmod(0o555)
        darwin_targets["cc"].write_bytes(b"changed Darwin command")
        rejected(
            lambda: checker.validate(
                command_bin, toolchain, owner, darwin_targets, darwin_digests
            ),
            "changed sealed Darwin command target was accepted",
        )
        darwin_targets["cc"].write_bytes(b"reviewed Darwin command: cc")
        darwin_targets["cc"].chmod(0o644)
        rejected(
            lambda: checker.validate(
                command_bin, toolchain, owner, darwin_targets, darwin_digests
            ),
            "nonexecutable sealed Darwin command target was accepted",
        )
        darwin_targets["cc"].chmod(0o755)
        darwin_targets["cc"].chmod(0o775)
        rejected(
            lambda: checker.validate(
                command_bin, toolchain, owner, darwin_targets, darwin_digests
            ),
            "group-writable sealed Darwin command target was accepted",
        )
        darwin_targets["cc"].chmod(0o755)
        linked_target = darwin_bin / "linked-cc"
        os.symlink(darwin_targets["cc"], linked_target)
        linked_targets = dict(darwin_targets)
        linked_targets["cc"] = linked_target
        rejected(
            lambda: checker.validate(
                command_bin, toolchain, owner, linked_targets, darwin_digests
            ),
            "linked sealed Darwin command target was accepted",
        )
        linked_digest_result = subprocess.run(
            [sys.executable, "-I", str(CHECKER), "--digest", str(linked_target)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        if linked_digest_result.returncode != 1:
            raise AssertionError("sealed Darwin digest CLI accepted a linked target")
        relative_targets = dict(darwin_targets)
        relative_targets["cc"] = Path("darwin-toolchain/cc")
        rejected(
            lambda: checker.validate(
                command_bin, toolchain, owner, relative_targets, darwin_digests
            ),
            "relative sealed Darwin command target was accepted",
        )
        command_bin.chmod(0o755)
        os.symlink(darwin_targets["cc"], command_bin / "unexpected")
        command_bin.chmod(0o555)
        rejected(
            lambda: checker.validate(
                command_bin, toolchain, owner, darwin_targets, darwin_digests
            ),
            "extra sealed Darwin command was accepted",
        )
    print("sealed Rust command mutations accepted")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
