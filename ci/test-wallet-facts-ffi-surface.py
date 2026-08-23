#!/usr/bin/env python3
import pathlib
import shutil
import subprocess
import sys
import tempfile


def run(checker: pathlib.Path, root: pathlib.Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run([sys.executable, str(checker), str(root)], text=True, capture_output=True)


def main() -> None:
    root = pathlib.Path(__file__).resolve().parent.parent
    checker = root / "ci/check-wallet-facts-ffi-surface.py"
    baseline = run(checker, root)
    assert baseline.returncode == 0, baseline.stderr
    mutations = [
        ("crates/wallet-facts-ffi/src/lib.rs", "observe_owned_outputs(", "open_confidential_output("),
        ("crates/wallet-facts-ffi/exports/macos.txt", "_wln_wallet_facts_observe_v1", "_wrong"),
        ("crates/wallet-facts-ffi/Cargo.toml", "zeroize =", "tokio ="),
    ]
    for relative, old, new in mutations:
        with tempfile.TemporaryDirectory() as directory:
            copy = pathlib.Path(directory) / "repo"
            shutil.copytree(root, copy, ignore=shutil.ignore_patterns("target", ".git", "tmp"))
            path = copy / relative
            text = path.read_text()
            assert old in text
            path.write_text(text.replace(old, new, 1))
            result = run(copy / "ci/check-wallet-facts-ffi-surface.py", copy)
            assert result.returncode != 0, relative
    print("wallet-facts FFI hostile mutations: OK")


if __name__ == "__main__":
    main()
