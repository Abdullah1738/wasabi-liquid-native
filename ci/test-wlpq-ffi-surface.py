#!/usr/bin/env python3
import hashlib
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CHECKER = Path("ci/check-wlpq-ffi-surface.py")
BUILDER = Path("ci/build-wlpq-ffi-library.sh")
DYNAMIC_TEST = Path("ci/test-wlpq-ffi-dynamic.py")
CRATE_FILES = (
    Path("crates/ordinary-wallet-plan-ffi/Cargo.toml"),
    Path("crates/ordinary-wallet-plan-ffi/exports/linux.map"),
    Path("crates/ordinary-wallet-plan-ffi/exports/macos.txt"),
    Path("crates/ordinary-wallet-plan-ffi/exports/windows.def"),
    Path("crates/ordinary-wallet-plan-ffi/include/wasabi_liquid_wlpq_v1.h"),
    Path("crates/ordinary-wallet-plan-ffi/src/lib.rs"),
    Path("crates/ordinary-wallet-plan-ffi/src/shim.c"),
)


def copy_fixture(destination: Path) -> None:
    for relative in (
        Path("Cargo.toml"),
        Path("Cargo.lock"),
        CHECKER,
        BUILDER,
        DYNAMIC_TEST,
        *CRATE_FILES,
    ):
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / relative, target)


def rebind_hash(root: Path, relative: Path) -> None:
    checker = root / CHECKER
    text = checker.read_text(encoding="utf-8")
    digest = hashlib.sha256((root / relative).read_bytes()).hexdigest()
    if relative.is_relative_to("crates/ordinary-wallet-plan-ffi"):
        pinned_name = relative.relative_to("crates/ordinary-wallet-plan-ffi").as_posix()
        pattern = rf'("{re.escape(pinned_name)}": ")[0-9a-f]{{64}}(")'
    else:
        pinned_name = relative.as_posix()
        pattern = rf'("{re.escape(pinned_name)}": \(\n        ")[0-9a-f]{{64}}(")'
    changed, count = re.subn(pattern, rf"\g<1>{digest}\g<2>", text)
    if count != 1:
        raise AssertionError(f"could not rebind {pinned_name}")
    checker.write_text(changed, encoding="utf-8")


def run_checker(root: Path, expected: str) -> None:
    result = subprocess.run(
        [sys.executable, "-I", str(root / CHECKER), str(root)],
        cwd=root,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode == 0 or expected not in result.stderr:
        raise AssertionError(
            f"mutation did not fail as {expected!r}: status={result.returncode} "
            f"stdout={result.stdout!r} stderr={result.stderr!r}"
        )


def mutate_source(root: Path, old: str, new: str) -> None:
    path = root / "crates/ordinary-wallet-plan-ffi/src/lib.rs"
    text = path.read_text(encoding="utf-8")
    if text.count(old) != 1:
        raise AssertionError(f"source mutation target count changed: {old!r}")
    path.write_text(text.replace(old, new), encoding="utf-8")
    rebind_hash(root, path.relative_to(root))


def mutate_header(root: Path, old: str, new: str) -> None:
    path = root / "crates/ordinary-wallet-plan-ffi/include/wasabi_liquid_wlpq_v1.h"
    text = path.read_text(encoding="utf-8")
    if text.count(old) != 1:
        raise AssertionError(f"header mutation target count changed: {old!r}")
    path.write_text(text.replace(old, new), encoding="utf-8")
    rebind_hash(root, path.relative_to(root))


def exercise_mutation(expected: str, mutation) -> None:
    with tempfile.TemporaryDirectory(prefix="wlpq-ffi-surface-") as directory:
        root = Path(directory)
        copy_fixture(root)
        mutation(root)
        run_checker(root, expected)


def main() -> None:
    subprocess.run(
        [sys.executable, "-I", str(ROOT / CHECKER), str(ROOT)],
        cwd=ROOT,
        check=True,
    )

    exercise_mutation(
        "WLPQ FFI file inventory changed",
        lambda root: (root / "crates/ordinary-wallet-plan-ffi/src/escape.rs").write_text(
            "", encoding="utf-8"
        ),
    )
    exercise_mutation(
        "WLPQ FFI export count changed",
        lambda root: mutate_source(
            root,
            "#[cfg(test)]\nstd::thread_local!",
            "#[unsafe(no_mangle)]\npub extern \"C\" fn wln_wlpq_bypass_impl_v1() -> i32 { 0 }\n\n"
            "#[cfg(test)]\nstd::thread_local!",
        ),
    )
    exercise_mutation(
        "WLPQ FFI panic closure hook changed",
        lambda root: mutate_source(
            root,
            "        let decoded = decode_request(&frame.0, &epoch.0).map_err(wire_status)?;\n"
            "        let reencoded = decoded.reencode().map_err(wire_status)?;",
            "        let decoded = decode_request(&frame.0, &epoch.0).map_err(wire_status)?;\n"
            "        let reencoded = decoded.reencode().map_err(wire_status)?;\n"
            "        maybe_inject_test_panic();\n",
        ),
    )
    exercise_mutation(
        "WLPQ FFI byte-identity check changed",
        lambda root: mutate_source(
            root,
            "if reencoded.as_bytes() != frame.0",
            "if reencoded.as_bytes() == frame.0",
        ),
    )
    exercise_mutation(
        "WLPQ FFI production unsafe surface changed",
        lambda root: mutate_source(
            root,
            "        let reencoded = decoded.reencode().map_err(wire_status)?;",
            "        let _first = unsafe { frame.0.as_ptr().read() };\n"
            "        let reencoded = decoded.reencode().map_err(wire_status)?;",
        ),
    )
    exercise_mutation(
        "WLPQ FFI test inventory changed",
        lambda root: mutate_source(
            root,
            "#[test]\n    fn canonical_corpus_frame_crosses_the_ffi_byte_identically()",
            "#[test]\n    #[cfg(any())]\n    fn canonical_corpus_frame_crosses_the_ffi_byte_identically()",
        ),
    )
    exercise_mutation(
        "WLPQ FFI Rust status table changed",
        lambda root: mutate_source(
            root,
            "pub const WLN_WLPQ_STATUS_INTERNAL_ERROR_V1: i32 = -9;",
            "pub const WLN_WLPQ_STATUS_INTERNAL_ERROR_V1: i32 = -10;",
        ),
    )
    exercise_mutation(
        "WLPQ FFI target kinds changed",
        lambda root: mutate_manifest(root, '["rlib", "staticlib"]', '["rlib"]'),
    )
    exercise_mutation(
        "WLPQ FFI dependency surface changed",
        lambda root: mutate_manifest(
            root,
            '[dependencies]\n',
            '[dependencies]\nlibc = "0.2"\n',
        ),
    )
    exercise_mutation(
        "WLPQ FFI header export changed",
        lambda root: mutate_header(
            root, "int32_t wln_wlpq_validate_v1(", "int32_t wln_wlpq_accept_v1("
        ),
    )
    exercise_mutation(
        "WLPQ FFI shim delegate changed",
        lambda root: mutate_shim(
            root,
            "return wln_wlpq_validate_impl_v1(frame, frame_length, expected_source_epoch);",
            "return WLN_WLPQ_STATUS_OK_V1;",
        ),
    )
    exercise_mutation(
        "WLPQ FFI dynamic-library build path changed",
        lambda root: mutate_builder(
            root,
            '-Wl,-exported_symbols_list,"$crate/exports/macos.txt"',
            '-Wl,-dead_strip',
        ),
    )
    exercise_mutation(
        "WLPQ FFI dynamic-library build path changed",
        lambda root: mutate_builder(
            root,
            "            -Wl,-install_name,@rpath/libwasabi_liquid_wlpq_v1.dylib \\\n",
            "",
        ),
    )
    exercise_mutation(
        "WLPQ FFI dynamic-test authority changed",
        lambda root: mutate_dynamic_test(
            root,
            '("frame-test-toy-single.hex", bytes([0x42]) * 32, -5),\n',
            "",
        ),
    )
    exercise_mutation(
        "WLPQ FFI dynamic-test authority changed",
        lambda root: mutate_dynamic_test(
            root,
            "        library_bytes.count(expected_identity) != 1\n"
            '        or str(library_path).encode("utf-8") + b"\\0" in library_bytes\n',
            "        False\n",
        ),
    )
    exercise_mutation(
        "WLPQ FFI dynamic-test authority changed",
        lambda root: mutate_dynamic_test(
            root,
            "    if read_regular(library_path, 64 * 1024 * 1024) != library_bytes:\n"
            '        reject("WLPQ FFI dynamic library changed during execution")\n',
            "",
        ),
    )

    with tempfile.TemporaryDirectory(prefix="wlpq-ffi-symbols-") as directory:
        root = Path(directory)
        copy_fixture(root)
        symbols = root / "symbols.txt"
        symbols.write_text("wln_wlpq_sign_finalize_v1\nwln_wlpq_validate_v1\n", encoding="utf-8")
        shutil.rmtree(root / "crates")
        subprocess.run(
            [
                sys.executable,
                "-I",
                str(root / CHECKER),
                str(root),
                "--symbols",
                "Linux",
                str(symbols),
            ],
            cwd=root,
            check=True,
        )

    with tempfile.TemporaryDirectory(prefix="wlpq-ffi-symbols-extra-") as directory:
        root = Path(directory)
        copy_fixture(root)
        symbols = root / "symbols.txt"
        symbols.write_text(
            "0000000000000000 T wln_wlpq_validate_v1\n"
            "0000000000000010 T wln_wlpq_bypass_v1\n",
            encoding="utf-8",
        )
        result = subprocess.run(
            [
                sys.executable,
                "-I",
                str(root / CHECKER),
                str(root),
                "--symbols",
                "Linux",
                str(symbols),
            ],
            cwd=root,
            text=True,
            capture_output=True,
            check=False,
        )
        if result.returncode == 0 or "dynamic export allowlist changed" not in result.stderr:
            raise AssertionError("extra dynamic export mutation was not rejected")


def mutate_manifest(root: Path, old: str, new: str) -> None:
    path = root / "crates/ordinary-wallet-plan-ffi/Cargo.toml"
    text = path.read_text(encoding="utf-8")
    if text.count(old) != 1:
        raise AssertionError(f"manifest mutation target count changed: {old!r}")
    path.write_text(text.replace(old, new), encoding="utf-8")
    rebind_hash(root, path.relative_to(root))


def mutate_shim(root: Path, old: str, new: str) -> None:
    path = root / "crates/ordinary-wallet-plan-ffi/src/shim.c"
    text = path.read_text(encoding="utf-8")
    if text.count(old) != 1:
        raise AssertionError(f"shim mutation target count changed: {old!r}")
    path.write_text(text.replace(old, new), encoding="utf-8")
    rebind_hash(root, path.relative_to(root))


def mutate_builder(root: Path, old: str, new: str) -> None:
    path = root / BUILDER
    text = path.read_text(encoding="utf-8")
    if text.count(old) != 1:
        raise AssertionError(f"builder mutation target count changed: {old!r}")
    path.write_text(text.replace(old, new), encoding="utf-8")
    rebind_hash(root, path.relative_to(root))


def mutate_dynamic_test(root: Path, old: str, new: str) -> None:
    path = root / DYNAMIC_TEST
    text = path.read_text(encoding="utf-8")
    if text.count(old) != 1:
        raise AssertionError(f"dynamic-test mutation target count changed: {old!r}")
    path.write_text(text.replace(old, new), encoding="utf-8")
    rebind_hash(root, path.relative_to(root))


if __name__ == "__main__":
    main()
