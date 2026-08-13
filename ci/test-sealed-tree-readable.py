#!/usr/bin/env python3
"""Mutation-test fail-closed build-identity sealed-tree traversal."""

from __future__ import annotations

import importlib.util
import os
import tempfile
from pathlib import Path


CHECKER = Path(__file__).with_name("check-sealed-tree-readable.py")


def rejected(operation, message: str) -> None:
    try:
        operation()
    except (OSError, ValueError):
        return
    raise AssertionError(message)


def main() -> int:
    spec = importlib.util.spec_from_file_location("sealed_readable", CHECKER)
    if spec is None or spec.loader is None:
        raise AssertionError("sealed-tree readability checker import failed")
    checker = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(checker)
    with tempfile.TemporaryDirectory(prefix="wlpq-readable-") as directory:
        root = Path(directory).resolve() / "sealed"
        root.mkdir()
        payload = root / "payload"
        payload.write_bytes(b"reviewed bytes")
        payload.chmod(0o444)
        root.chmod(0o555)
        checker.read_tree(root)

        root.chmod(0o755)
        payload.unlink()
        root.chmod(0o555)
        rejected(lambda: checker.read_tree(root), "empty sealed tree was accepted")

        root.chmod(0o755)
        payload.write_bytes(b"reviewed bytes")
        payload.chmod(0o444)
        root.chmod(0o000)
        if os.geteuid() != 0:
            rejected(
                lambda: checker.read_tree(root),
                "unreadable populated sealed tree was accepted",
            )
        root.chmod(0o755)
    print("sealed-tree readability mutations accepted")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
