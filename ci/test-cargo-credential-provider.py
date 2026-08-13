#!/usr/bin/env python3
"""Execute the protocol-correct Cargo credential-provider fixture."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path


PREPARER = Path(__file__).with_name("prepare-cargo-credential-provider.py")


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="wlpq-credential-") as directory:
        root = Path(directory).resolve()
        provider = root / "provider"
        sentinel = root / "sentinel"
        subprocess.run(
            [sys.executable, "-I", str(PREPARER), str(provider), str(sentinel)],
            check=True,
            env={"PATH": "/usr/bin:/bin"},
        )
        request = b'{"v":1,"registry":{"name":"wlpq-positive"},"kind":"login","token":"wlpq-positive-control"}\n'
        result = subprocess.run(
            [str(provider)],
            input=request,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
            env={"PATH": "/usr/bin:/bin"},
        )
        if result.stdout != b'{"v":[1]}\n{"Ok":{"kind":"login"}}\n':
            raise AssertionError(f"credential-provider response is not exact newline-delimited JSON: {result.stdout!r}")
        for line in result.stdout.splitlines():
            json.loads(line)
        if sentinel.read_bytes() != b"provider-ran":
            raise AssertionError("credential-provider positive-control sentinel differs")
        if os.stat(provider).st_mode & 0o777 != 0o700:
            raise AssertionError("credential-provider fixture mode differs")
    print("Cargo credential-provider protocol accepted")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
