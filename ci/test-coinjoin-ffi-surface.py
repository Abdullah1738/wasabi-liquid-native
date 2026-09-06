#!/usr/bin/env python3
"""Hostile-mutation tests for the CoinJoin FFI surface checker.

Each mutation is applied to a hermetic copy of the crate and must make the
surface checker reject with a non-zero exit. The baseline (unmutated) crate
must pass cleanly first.
"""
import pathlib
import shutil
import subprocess
import sys
import tempfile


def run(checker: pathlib.Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(checker), *args], text=True, capture_output=True
    )


def main() -> None:
    root = pathlib.Path(__file__).resolve().parent.parent
    checker = root / "ci/check-coinjoin-ffi-surface.py"
    baseline = run(checker, str(root))
    assert baseline.returncode == 0, baseline.stderr

    crate = "crates/coinjoin-ffi"
    # (path, old, new): each must flip the surface checker to a rejection.
    mutations = [
        (f"{crate}/src/lib.rs", "WLCJ_OP_OPEN_OUTPUT_V1: u32 = 13", "WLCJ_OP_OPEN_OUTPUT_V1: u32 = 12"),
        (f"{crate}/include/wasabi_liquid_coinjoin_v1.h", "WLCJ_OP_OPEN_OUTPUT_V1 UINT32_C(13)", "WLCJ_OP_OPEN_OUTPUT_V1 UINT32_C(12)"),
        (f"{crate}/src/lib.rs", "WLCJ_OP_SIGNING_DIGESTS_V1: u32 = 11", "WLCJ_OP_SIGNING_DIGESTS_V1: u32 = 10"),
        (f"{crate}/include/wasabi_liquid_coinjoin_v1.h", "WLCJ_OP_ASSEMBLE_SIGNATURES_V1 UINT32_C(12)", "WLCJ_OP_ASSEMBLE_SIGNATURES_V1 UINT32_C(10)"),
        (f"{crate}/src/lib.rs", "WLCJ_OP_PROVE_PARTIAL_BALANCE_V1: u32 = 10", "WLCJ_OP_PROVE_PARTIAL_BALANCE_V1: u32 = 7"),
        (f"{crate}/include/wasabi_liquid_coinjoin_v1.h", "WLCJ_OP_PROVE_PARTIAL_BALANCE_V1 UINT32_C(10)", "WLCJ_OP_PROVE_PARTIAL_BALANCE_V1 UINT32_C(7)"),
        (f"{crate}/src/lib.rs", "WLCJ_OP_PROVE_INPUT_REGISTRATION_V1: u32 = 8", "WLCJ_OP_PROVE_INPUT_REGISTRATION_V1: u32 = 2"),
        (f"{crate}/include/wasabi_liquid_coinjoin_v1.h", "WLCJ_OP_PROVE_OUTPUT_REGISTRATION_V1 UINT32_C(9)", "WLCJ_OP_PROVE_OUTPUT_REGISTRATION_V1 UINT32_C(3)"),
        # Extra file escapes the inventory.
        (f"{crate}/src/escape.rs", None, None),
        # A second exported impl entry point.
        (
            f"{crate}/src/lib.rs",
            "pub unsafe extern \"C\" fn wlcj_execute_impl_v1",
            "pub unsafe extern \"C\" fn wlcj_execute_impl_v1"
            "\npub unsafe extern \"C\" fn wlcj_execute_impl_v1",
        ),
        # The single C export is renamed.
        (f"{crate}/src/shim.c", "wlcj_execute_v1(", "wlcj_execute_v2("),
        # The macOS export map adds a symbol.
        (f"{crate}/exports/macos.txt", "_wlcj_execute_v1\n", "_wlcj_execute_v1\n_extra\n"),
        # A dependency is added.
        (f"{crate}/Cargo.toml", 'zeroize = { version = "1.8"', 'libc = "0.2"\nzeroize = { version = "1.8"'),
        # A pinned wire-KAT digest is corrupted.
        (
            f"{crate}/src/tests.rs",
            "aeb70c16b7cae9ec4e7c65600b1ca6d6958b16a8c111fea5ed6f6b9b24404dae",
            "00000c16b7cae9ec4e7c65600b1ca6d6958b16a8c111fea5ed6f6b9b24404dae",
        ),
        # A test is removed from the inventory.
        (
            f"{crate}/src/tests.rs",
            "fn wire_kat_pinned_bytes_per_op(",
            "fn wire_kat_pinned_bytes_per_op_RENAMED(",
        ),
    ]
    for relative, old, new in mutations:
        with tempfile.TemporaryDirectory(prefix="coinjoin-ffi-surface-") as directory:
            copy = pathlib.Path(directory) / "repo"
            shutil.copytree(root, copy, ignore=shutil.ignore_patterns("target", ".git", "tmp"))
            path = copy / relative
            if old is None:
                path.write_text("// hostile extra file\n")
            else:
                text = path.read_text()
                assert old in text, relative
                path.write_text(text.replace(old, new, 1))
            result = run(copy / "ci/check-coinjoin-ffi-surface.py", str(copy))
            assert result.returncode != 0, f"{relative}: {result.stdout}{result.stderr}"

    # The --symbols allowlist mode: an extra exported symbol must reject.
    with tempfile.TemporaryDirectory(prefix="coinjoin-ffi-symbols-") as directory:
        good = pathlib.Path(directory) / "good.symbols"
        good.write_text("_wlcj_execute_v1\n")
        bad = pathlib.Path(directory) / "bad.symbols"
        bad.write_text("_wlcj_execute_v1\n_wlcj_execute_impl_v1\n")
        positive = run(checker, str(root), "--symbols", "Darwin", str(good))
        assert positive.returncode == 0, positive.stderr
        negative = run(checker, str(root), "--symbols", "Darwin", str(bad))
        assert negative.returncode != 0, "extra dynamic symbol must reject"

    print("coinjoin-ffi hostile mutations: OK")


if __name__ == "__main__":
    main()
