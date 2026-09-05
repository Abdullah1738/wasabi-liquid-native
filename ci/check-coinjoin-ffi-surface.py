#!/usr/bin/env python3
"""CoinJoin v1 FFI surface checker.

Two modes:
  check-coinjoin-ffi-surface.py ROOT
      Validate the crate's source surface: exact file inventory, manifest
      dependency surface, export maps, the single C export, and the pinned
      wire-KAT digests of the genuine two-participant round.
  check-coinjoin-ffi-surface.py ROOT --symbols PLATFORM FILE
      Validate an `nm`-style dynamic-symbol listing (one symbol per line) so
      the ONLY exported dynamic symbol is the wlcj entry point.
"""
import pathlib
import sys
import tomllib

CRATE = pathlib.Path("crates/coinjoin-ffi")

# The exact files the crate may contain (relative to the crate root).
EXPECTED_FILES = {
    "Cargo.toml",
    "build.rs",
    "include/wasabi_liquid_coinjoin_v1.h",
    "exports/linux.map",
    "exports/macos.txt",
    "exports/windows.def",
    "src/lib.rs",
    "src/shim.c",
    "src/tests.rs",
    "tests/e2e.rs",
}

# Pinned wire-KAT digests of the genuine two-participant round built in
# src/tests.rs. Regenerate only by re-deriving from a real run, never by hand.
KAT_PREBLIND_DIGEST = "ddefd8f23ea433f9a6c8049a54f660530fca40fff3c2c1cfef5421f2d85c7216"
KAT_FINAL_DIGEST = "c8dc56e7cbd537584c2e9de982e116fdc107519baf514a95b44d0dc95b89d459"
KAT_PREBLIND_SHA256 = "aeb70c16b7cae9ec4e7c65600b1ca6d6958b16a8c111fea5ed6f6b9b24404dae"
KAT_INTERMEDIATE_SHA256 = "0409d8678303f4188ea5e84cd5e65a5b79c06164d213aeef76eed0143a8fff8e"
KAT_FINAL_SHA256 = "9be308565a04c192347c97dc84137eb31e6ef12c6f9063bcdd0bb56f8107544b"

ALLOWED_DYNAMIC_SYMBOLS = ["wlcj_execute_v1"]


def reject(message: str) -> "SystemExit":
    raise SystemExit(message)


def validate_symbols(platform: str, path: pathlib.Path) -> None:
    if platform == "Darwin":
        symbols = []
        for line in path.read_text().splitlines():
            token = line.split()[-1] if line.split() else ""
            if not token.startswith("_"):
                reject("CoinJoin FFI dynamic export allowlist changed")
            symbols.append(token[1:])
    elif platform == "Linux":
        symbols = [line.split()[-1] for line in path.read_text().splitlines() if line.split()]
    else:
        reject("CoinJoin FFI dynamic library target is not qualified")
    if sorted(symbols) != ALLOWED_DYNAMIC_SYMBOLS:
        reject("CoinJoin FFI dynamic export allowlist changed")


def validate(root: pathlib.Path) -> None:
    crate = root / CRATE
    inventory = {
        str(path.relative_to(crate))
        for path in crate.rglob("*")
        if path.is_file() or path.is_symlink()
    }
    if inventory != EXPECTED_FILES:
        reject("CoinJoin FFI file inventory changed")

    manifest = tomllib.loads((crate / "Cargo.toml").read_text())
    if manifest["lib"]["crate-type"] != ["rlib", "staticlib"]:
        reject("CoinJoin FFI crate types changed")
    if set(manifest["dependencies"]) != {
        "elements",
        "rand",
        "sha2",
        "wasabi-liquid-native-coinjoin-collab-blinding",
        "wasabi-liquid-native-coinjoin-equality-integration",
        "wasabi-liquid-native-coinjoin-partial-balance",
        "wasabi-liquid-native-coinjoin-pset-state",
        "zeroize",
    }:
        reject("CoinJoin FFI dependency capability surface changed")
    if set(manifest["dev-dependencies"]) != {
        "rand",
        "wasabi-liquid-native-credential-commitment-equality",
    }:
        reject("CoinJoin FFI dev-dependency surface changed")

    source = (crate / "src/lib.rs").read_text()
    for token in (
        "wlcj_execute_impl_v1",
        "catch_unwind(AssertUnwindSafe",
        "WLCJ_HASH_DRBG_V1",
        "WLCJ_STATUS_OUTPUT_CAPACITY_V1",
        "WLCJ_STATUS_INTERNAL_ERROR_V1",
        "fn op_canonicalize_state",
        "fn op_blind_non_last",
        "fn op_blind_last",
        "fn op_validate_signer_view",
        "fn op_verify_partial_balance",
    ):
        if token not in source:
            reject(f"CoinJoin FFI source token missing: {token}")
    if source.count("pub unsafe extern \"C\" fn wlcj_execute_impl_v1") != 1:
        reject("CoinJoin FFI exported impl count changed")
    if "export_name" in source or "link_section" in source:
        reject("CoinJoin FFI forbidden export mechanism present")
    for forbidden in (
        "std::fs", "std::net", "std::process", "dlopen", "dlsym", "LoadLibrary", "GetProcAddress",
    ):
        if forbidden in source:
            reject(f"CoinJoin FFI forbidden capability present: {forbidden}")

    shim = (crate / "src/shim.c").read_text()
    if shim.count("WLCJ_EXPORT_V1 int32_t wlcj_execute_v1(") != 1:
        reject("CoinJoin FFI C export count changed")
    if "wlcj_execute_impl_v1" not in shim:
        reject("CoinJoin FFI shim delegate missing")
    for forbidden in ("malloc", "calloc", "realloc", "free(", "dlopen", "dlsym"):
        if forbidden in shim:
            reject(f"CoinJoin FFI shim forbidden capability present: {forbidden}")

    if (crate / "exports/macos.txt").read_text() != "_wlcj_execute_v1\n":
        reject("CoinJoin FFI macOS export map changed")
    if (crate / "exports/linux.map").read_text() != (
        "{\n    global:\n        wlcj_execute_v1;\n    local:\n        *;\n};\n"
    ):
        reject("CoinJoin FFI Linux export map changed")
    if (crate / "exports/windows.def").read_text() != (
        "LIBRARY wasabi_liquid_coinjoin_v1\nEXPORTS\n    wlcj_execute_v1\n"
    ):
        reject("CoinJoin FFI Windows export map changed")

    tests = (crate / "src/tests.rs").read_text()
    # The two digests are pinned as byte arrays; the three PSET digests as hex.
    for hex_digest in (KAT_PREBLIND_SHA256, KAT_INTERMEDIATE_SHA256, KAT_FINAL_SHA256):
        if hex_digest not in tests:
            reject(f"CoinJoin FFI wire-KAT digest missing: {hex_digest}")
    # The byte arrays may be wrapped across lines; collapse whitespace, `0x`
    # prefixes, and commas so the pinned byte sequence is matched as a hex
    # string regardless of rustfmt line wrapping.
    import re as _re

    stripped = _re.sub(r"[\s,]", "", tests).replace("0x", "")
    for byte_digest in (KAT_PREBLIND_DIGEST, KAT_FINAL_DIGEST):
        if byte_digest not in stripped:
            reject(f"CoinJoin FFI wire-KAT digest missing: {byte_digest}")
    for name in (
        "e2e_two_participant_round_all_ops",
        "wire_kat_pinned_bytes_per_op",
        "determinism_identical_frames_identical_outputs",
        "hostile_malformed_frames_fail_closed",
        "hostile_field_shape_failures_fail_closed",
        "no_secret_bytes_in_any_response",
    ):
        if f"fn {name}(" not in tests:
            reject(f"CoinJoin FFI test inventory changed: {name}")


def main() -> None:
    if len(sys.argv) == 2:
        validate(pathlib.Path(sys.argv[1]).resolve())
        print("coinjoin-ffi surface: OK")
    elif len(sys.argv) == 5 and sys.argv[2] == "--symbols":
        validate_symbols(sys.argv[3], pathlib.Path(sys.argv[4]).resolve())
        print("coinjoin-ffi symbols: OK")
    else:
        raise SystemExit(
            "usage: check-coinjoin-ffi-surface.py REPOSITORY_ROOT [--symbols PLATFORM FILE]"
        )


if __name__ == "__main__":
    main()
