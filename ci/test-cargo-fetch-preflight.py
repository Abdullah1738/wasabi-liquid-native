#!/usr/bin/env python3
"""Mutation-test the pre-Cargo workspace fetch authority."""

from __future__ import annotations

import importlib.util
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CHECKER = Path(__file__).with_name("check-cargo-fetch-preflight.py")


def rejected(operation, message: str) -> None:
    try:
        operation()
    except (OSError, ValueError):
        return
    raise AssertionError(message)


def main() -> int:
    spec = importlib.util.spec_from_file_location("fetch_preflight", CHECKER)
    if spec is None or spec.loader is None:
        raise AssertionError("fetch preflight checker import failed")
    checker = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(checker)
    checker.validate(ROOT)
    with tempfile.TemporaryDirectory(prefix="wlpq-fetch-preflight-") as directory:
        test_root = Path(directory).resolve()
        (test_root / "ci").mkdir()
        for relative in (Path("Cargo.toml"), Path("Cargo.lock"), Path("ci/ordinary-wallet-plan-public-proof.Cargo.lock")):
            (test_root / relative).write_bytes((ROOT / relative).read_bytes())
        checker.validate(test_root)
        cargo_config = test_root / ".cargo/config.toml"
        cargo_config.parent.mkdir()
        cargo_config.write_text('[registry]\nglobal-credential-providers = ["cargo:token"]\n', encoding="utf-8")
        rejected(lambda: checker.validate(test_root), "workspace Cargo credential provider was accepted")
        configuration_root = test_root / "configuration-root"
        (configuration_root / ".cargo").mkdir(parents=True)
        (configuration_root / ".cargo/config.toml").write_text("[net]\noffline = true\n", encoding="utf-8")
        rejected(
            lambda: checker.validate_configuration_root(configuration_root),
            "Cargo configuration above the fetch manifest was accepted",
        )
    print("Cargo fetch preflight mutations accepted")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
