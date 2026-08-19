#!/usr/bin/env python3
import hashlib
import os
import re
import stat
import sys
import tomllib
from pathlib import Path


EXPECTED_FILES = {
    "Cargo.toml": "6b5d3302d8545b09df9adfdc0b134c97cc7b40bf59c35bf245254e662fdb9428",
    "exports/linux.map": "8f5ddf997b081c7922cfbc7c622631468707f69010315700e28e0dcc95df7009",
    "exports/macos.txt": "e63738d2c483aa0ceaacc7ab8263c2b6a4ef2b8005374b63a04a3efdf651058b",
    "exports/windows.def": "dfdb09ca7ab86e697ce1e4108c02d177d5d1a7033a7339bfd7357ac6f0da82fd",
    "include/wasabi_liquid_wlpq_v1.h": "9951aa3ed9ae65bd0753a9c5ba19818c2e5e2ff3ecb64cd7cb222a36f7d28895",
    "src/lib.rs": "89304d3ff1e7ade9b0f7af28da15c5936a1502014cf4b2cd9e2ea254076f0254",
    "src/shim.c": "ea9d090b09c882d11ac37b1998d039fcf06a5134986c982a8e076679e3f7514f",
}

EXPECTED_SUPPORT_FILES = {
    "ci/build-wlpq-ffi-library.sh": (
        "507526231169250bab142debb7c4bdaf96d3e744c47714b61b29862c44246495",
        0o755,
    ),
    "ci/test-wlpq-ffi-dynamic.py": (
        "c5c817155c616247945d4bfd69d8930fc93f815130d04f8f281f5a72d2075f4b",
        0o644,
    ),
}

STATUS_ROWS = {
    "OK": 0,
    "INVALID_ARGUMENT": -1,
    "VERSION_MISMATCH": -2,
    "INVALID_ENCODING": -3,
    "LIMIT_EXCEEDED": -4,
    "SOURCE_BINDING_MISMATCH": -5,
    "CONTEXT_REJECTED": -6,
    "PLAN_REJECTED": -7,
    "FUNDING_REJECTED": -8,
    "INTERNAL_ERROR": -9,
    "SIGNER_REFUSED": -10,
    "SIGNING_REJECTED": -11,
    "OUTPUT_CAPACITY": -12,
}

TEST_NAMES = {
    "frozen_statuses_match_native_wire_codes",
    "canonical_corpus_frame_crosses_the_ffi_byte_identically",
    "ffi_rejects_every_structural_boundary_without_diagnostics",
    "pointer_and_length_checks_precede_every_borrow",
    "panic_is_contained_as_a_redacted_internal_error",
    "ffi_validated_frame_drives_the_complete_product_adapter_caller_path",
    "ffi_validated_frame_wrong_key_recovers_the_retryable_blinded_pset",
    "ffi_sign_finalize_signable_fixture_produces_a_finalized_transaction",
    "ffi_sign_finalize_wrong_key_fails_closed_as_signing_rejected",
    "ffi_sign_finalize_mismatched_digest_fails_closed_as_signing_rejected",
    "ffi_sign_finalize_signer_refusal_fails_closed_as_signer_refused",
    "ffi_sign_finalize_corrupt_frame_fails_closed_as_invalid_encoding",
    "ffi_sign_finalize_output_capacity_failure_reports_required_length",
    "ffi_sign_finalize_null_and_capacity_failures_fail_closed",
    "ffi_sign_finalize_null_and_wrong_length_entropy_fail_closed",
}

CALLBACK_TYPEDEFS = (
    "wln_wlpq_public_key_callback_v1",
    "wln_wlpq_sign_digest_callback_v1",
)


def reject(message: str) -> None:
    raise SystemExit(message)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_exact_file(path: Path, relative: str, expected_mode: int = 0o644) -> bytes:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        reject(f"WLPQ FFI file is missing: {relative}")
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        reject(f"WLPQ FFI file is not a regular file: {relative}")
    if stat.S_IMODE(metadata.st_mode) != expected_mode:
        reject(f"WLPQ FFI file mode changed: {relative}")
    data = path.read_bytes()
    if data.startswith((b"\xef\xbb\xbf", b"\xff\xfe", b"\xfe\xff")):
        reject(f"WLPQ FFI file has a byte-order mark: {relative}")
    if b"\r" in data or not data.endswith(b"\n") or data.endswith(b"\n\n"):
        reject(f"WLPQ FFI file framing changed: {relative}")
    try:
        data.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        reject(f"WLPQ FFI file is not strict UTF-8: {relative}")
    return data


def validate_manifest(root: Path, manifest_text: str) -> None:
    manifest = tomllib.loads(manifest_text)
    if set(manifest) != {"package", "lib", "dependencies", "dev-dependencies"}:
        reject("WLPQ FFI manifest section inventory changed")
    if manifest["package"] != {
        "name": "wasabi-liquid-native-ordinary-wallet-plan-ffi",
        "version": "0.1.0",
        "edition": "2024",
        "rust-version": "1.96",
        "license": "MIT",
        "publish": False,
        "description": "Minimal C ABI for canonical WLPQ v1 frame validation",
    }:
        reject("WLPQ FFI package manifest changed")
    if manifest["lib"] != {"crate-type": ["rlib", "staticlib"]}:
        reject("WLPQ FFI target kinds changed")
    if manifest["dependencies"] != {
        "elements": {
            "git": "https://github.com/Abdullah1738/rust-elements.git",
            "rev": "5b8865f8061459f82dcb8a1cf476b7ba17b14193",
            "default-features": False,
        },
        "rand": {"version": "0.8", "default-features": False},
        "sha2": {"version": "=0.11.0", "default-features": False},
        "wasabi-liquid-native-ordinary-pset": {"path": "../ordinary-pset"},
        "wasabi-liquid-native-ordinary-wallet-plan": {
            "path": "../ordinary-wallet-plan"
        },
        "wasabi-liquid-native-ordinary-wallet-pset": {
            "path": "../ordinary-wallet-pset"
        },
        "wasabi-liquid-native-wallet-facts": {"path": "../wallet-facts"},
        "zeroize": {"version": "1.8", "default-features": False},
    }:
        reject("WLPQ FFI dependency surface changed")
    if manifest["dev-dependencies"] != {
        "elements": {
            "git": "https://github.com/Abdullah1738/rust-elements.git",
            "rev": "5b8865f8061459f82dcb8a1cf476b7ba17b14193",
            "default-features": False,
        },
        "miniscript": {
            "version": "=12.3.7",
            "default-features": False,
            "features": ["no-std"],
        },
        "rand": {"version": "0.8", "default-features": False},
        "sha2": {"version": "=0.11.0", "default-features": False},
        "wasabi-liquid-native-ordinary-pset": {"path": "../ordinary-pset"},
        "wasabi-liquid-native-ordinary-wallet-pset": {
            "path": "../ordinary-wallet-pset"
        },
        "wasabi-liquid-native-wallet-facts": {"path": "../wallet-facts"},
    }:
        reject("WLPQ FFI dev-dependency surface changed")

    workspace = tomllib.loads((root / "Cargo.toml").read_text(encoding="utf-8"))
    member = "crates/ordinary-wallet-plan-ffi"
    if workspace.get("workspace", {}).get("members", []).count(member) != 1:
        reject("WLPQ FFI workspace membership changed")
    if workspace.get("workspace", {}).get("default-members", []).count(member) != 1:
        reject("WLPQ FFI default workspace membership changed")

    lock = tomllib.loads((root / "Cargo.lock").read_text(encoding="utf-8"))
    packages = [
        package
        for package in lock.get("package", [])
        if package.get("name") == "wasabi-liquid-native-ordinary-wallet-plan-ffi"
    ]
    if packages != [
        {
            "name": "wasabi-liquid-native-ordinary-wallet-plan-ffi",
            "version": "0.1.0",
            "dependencies": [
                "elements",
                "miniscript",
                "rand",
                "sha2",
                "wasabi-liquid-native-ordinary-pset",
                "wasabi-liquid-native-ordinary-wallet-plan",
                "wasabi-liquid-native-ordinary-wallet-pset",
                "wasabi-liquid-native-wallet-facts",
                "zeroize",
            ],
        }
    ]:
        reject("WLPQ FFI lockfile package changed")


def validate_rust_source(source: str) -> None:
    if source.count('#[unsafe(no_mangle)]') != 2:
        reject("WLPQ FFI export count changed")
    signature = 'pub unsafe extern "C" fn wln_wlpq_validate_impl_v1('
    if source.count(signature) != 1:
        reject("WLPQ FFI export signature changed")
    sign_signature = 'pub unsafe extern "C" fn wln_wlpq_sign_finalize_impl_v1('
    if source.count(sign_signature) != 1:
        reject("WLPQ FFI sign export signature changed")
    if source.count('extern "C"') != 8 or "export_name" in source or "link_section" in source:
        reject("WLPQ FFI export surface changed")

    product = source.split("#[cfg(test)]", 1)[0]
    if product.count("unsafe {") != 11 or product.count("pub unsafe extern") != 2:
        reject("WLPQ FFI production unsafe surface changed")
    if product.count("ptr::copy_nonoverlapping") != 5:
        reject("WLPQ FFI epoch snapshot changed")
    if product.count("slice::from_raw_parts") != 3:
        reject("WLPQ FFI frame snapshot changed")
    if product.count("catch_unwind") != 4:
        reject("WLPQ FFI unwind containment changed")
    if product.count("decode_request(") != 2 or product.count(".reencode()") != 1:
        reject("WLPQ FFI canonical codec path changed")
    if "if reencoded.as_bytes() != frame.0" not in product:
        reject("WLPQ FFI byte-identity check changed")
    if product.count("self.0.zeroize();") != 4:
        reject("WLPQ FFI native copy clearing changed")
    if product.count("maybe_inject_test_panic();") != 2:
        reject("WLPQ FFI panic closure hook changed")

    validate_region = product.split("/// Signs and finalizes one canonical WLPQ v1 frame", 1)[0]
    ordered = [
        "if frame.is_null() || expected_source_epoch.is_null() || frame_length == 0",
        "if frame_length > WLN_WLPQ_MAX_FRAME_BYTES_V1",
        "let Ok(frame_length) = usize::try_from(frame_length)",
        "let outcome = catch_unwind",
        "ptr::copy_nonoverlapping",
        "slice::from_raw_parts",
        "decode_request(&frame.0, &epoch.0)",
        ".reencode()",
        "if reencoded.as_bytes() != frame.0",
    ]
    positions = [validate_region.find(token) for token in ordered]
    if any(position < 0 for position in positions) or positions != sorted(positions):
        reject("WLPQ FFI validation order changed")

    forbidden = (
        "std::fs",
        "std::net",
        "std::process",
        "Command::",
        "File::",
        "println!",
        "eprintln!",
        "dbg!",
        "global_asm!",
        "asm!",
        "dlopen",
        "dlsym",
        "LoadLibrary",
        "GetProcAddress",
        "libc::",
    )
    if any(token in product for token in forbidden):
        reject("WLPQ FFI production capability surface expanded")

    rust_statuses = {
        name: int(value)
        for name, value in re.findall(
            r"pub const WLN_WLPQ_STATUS_([A-Z_]+)_V1: i32 = (-?[0-9_]+);",
            source,
        )
    }
    if rust_statuses != STATUS_ROWS:
        reject("WLPQ FFI Rust status table changed")
    if "-(error.code() as i32)" not in product:
        reject("WLPQ FFI wire-status mapping changed")

    actual_tests = set(re.findall(r"#\[test\]\n    fn ([a-z0-9_]+)\(", source))
    if actual_tests != TEST_NAMES or source.count("#[test]") != len(TEST_NAMES):
        reject("WLPQ FFI test inventory changed")
    for name in TEST_NAMES:
        if f"#[test]\n    fn {name}()" not in source:
            reject("WLPQ FFI test discovery changed")


def validate_header(header: str) -> None:
    if header.count("int32_t wln_wlpq_validate_v1(") != 1:
        reject("WLPQ FFI header export changed")
    if header.count("int32_t wln_wlpq_sign_finalize_v1(") != 1:
        reject("WLPQ FFI header sign export changed")
    if header.count('extern "C"') != 1:
        reject("WLPQ FFI C++ linkage changed")
    if "#define WLN_WLPQ_ABI_VERSION_V1 UINT32_C(1)" not in header:
        reject("WLPQ FFI header version changed")
    if "#define WLN_WLPQ_MAX_FRAME_BYTES_V1 UINT64_C(268435456)" not in header:
        reject("WLPQ FFI header frame cap changed")
    for name, value in STATUS_ROWS.items():
        encoded = f"INT32_C({abs(value)})"
        expected = (
            f"#define WLN_WLPQ_STATUS_{name}_V1 {encoded}"
            if value >= 0
            else f"#define WLN_WLPQ_STATUS_{name}_V1 (-{encoded})"
        )
        if expected not in header:
            reject("WLPQ FFI header status table changed")
    signature = """int32_t wln_wlpq_validate_v1(
    const uint8_t *frame,
    uint64_t frame_length,
    const uint8_t *expected_source_epoch);"""
    if signature not in header:
        reject("WLPQ FFI header signature changed")

    # The forbidden-capability-token denylist is relaxed ONLY inside the two
    # named function-pointer typedef declarations (a separately-reviewed
    # authority change): the typedef, (*, and wln_callback tokens are admitted
    # only within the exact wln_wlpq_public_key_callback_v1 /
    # wln_wlpq_sign_digest_callback_v1 typedef bodies extracted below. The
    # wln_handle and wln_allocator tokens and every other validate_header rule
    # stay fully intact.
    typedef_bodies = []
    for name in CALLBACK_TYPEDEFS:
        match = re.search(
            r"typedef int32_t \(\*" + name + r"\)\(([^;]*)\);", header, re.DOTALL
        )
        if match is None:
            reject("WLPQ FFI header callback typedef changed")
        typedef_bodies.append(match.group(0))
    scrubbed = header
    for body in typedef_bodies:
        scrubbed = scrubbed.replace(body, "", 1)
    for forbidden in ("(*", "typedef", "wln_handle", "wln_allocator", "wln_callback"):
        if forbidden in scrubbed.lower():
            reject("WLPQ FFI header capability surface expanded")


def validate_shim(shim: str) -> None:
    if shim.count('#include "../include/wasabi_liquid_wlpq_v1.h"') != 1:
        reject("WLPQ FFI shim header binding changed")
    if shim.count("extern int32_t wln_wlpq_validate_impl_v1(") != 1:
        reject("WLPQ FFI shim internal binding changed")
    if shim.count("extern int32_t wln_wlpq_sign_finalize_impl_v1(") != 1:
        reject("WLPQ FFI shim internal sign binding changed")
    if shim.count("WLN_WLPQ_EXPORT_V1 int32_t wln_wlpq_validate_v1(") != 1:
        reject("WLPQ FFI shim export changed")
    if shim.count("WLN_WLPQ_EXPORT_V1 int32_t wln_wlpq_sign_finalize_v1(") != 1:
        reject("WLPQ FFI shim sign export changed")
    delegate = (
        "return wln_wlpq_validate_impl_v1(frame, frame_length, "
        "expected_source_epoch);"
    )
    if shim.count(delegate) != 1:
        reject("WLPQ FFI shim delegate changed")
    sign_delegate = "return wln_wlpq_sign_finalize_impl_v1("
    if shim.count(sign_delegate) != 1:
        reject("WLPQ FFI shim sign delegate changed")
    if shim.count("wln_wlpq_validate_v1(") != 1 or shim.count("wln_wlpq_sign_finalize_v1(") != 1:
        reject("WLPQ FFI shim function inventory changed")
    for forbidden in ("malloc", "calloc", "realloc", "free(", "dlopen", "dlsym", "LoadLibrary"):
        if forbidden in shim:
            reject("WLPQ FFI shim capability surface expanded")


def validate_export_maps(contents: dict[str, str]) -> None:
    if contents["exports/macos.txt"] != (
        "_wln_wlpq_validate_v1\n" "_wln_wlpq_sign_finalize_v1\n"
    ):
        reject("WLPQ FFI macOS export map changed")
    if contents["exports/windows.def"] != (
        "EXPORTS\n" "    wln_wlpq_validate_v1\n" "    wln_wlpq_sign_finalize_v1\n"
    ):
        reject("WLPQ FFI Windows export map changed")
    if contents["exports/linux.map"] != (
        "{\n"
        "    global:\n"
        "        wln_wlpq_validate_v1;\n"
        "        wln_wlpq_sign_finalize_v1;\n"
        "    local:\n"
        "        *;\n"
        "};\n"
    ):
        reject("WLPQ FFI Linux export map changed")


def validate_builder(builder: str) -> None:
    required = (
        "cc -std=c11 -fPIC -fvisibility=hidden -Wall -Wextra -Werror",
        'cc -dynamiclib -Wl,-dead_strip',
        '-Wl,-install_name,@rpath/libwasabi_liquid_wlpq_v1.dylib',
        '-Wl,-compatibility_version,1.0.0',
        '-Wl,-current_version,1.0.0',
        '-Wl,-force_load,"$archive"',
        '-Wl,-exported_symbols_list,"$crate/exports/macos.txt"',
        'cc -shared -Wl,--no-undefined -Wl,--gc-sections',
        '-Wl,-soname,libwasabi_liquid_wlpq_v1.so',
        '-Wl,--whole-archive "$archive" -Wl,--no-whole-archive',
        '-Wl,--version-script="$crate/exports/linux.map"',
    )
    if any(builder.count(token) != 1 for token in required):
        reject("WLPQ FFI dynamic-library build path changed")
    if builder.count("Darwin)") != 1 or builder.count("Linux)") != 1:
        reject("WLPQ FFI qualified target set changed")
    for forbidden in ("cargo ", "curl", "wget", "git ", "eval", "source ", "LD_PRELOAD"):
        if forbidden in builder:
            reject("WLPQ FFI builder capability surface expanded")


def validate_dynamic_test(test: str) -> None:
    required = (
        "library = ctypes.CDLL(str(library_path))",
        "function = library.wln_wlpq_validate_v1",
        "function.argtypes = (ctypes.c_void_p, ctypes.c_uint64, ctypes.c_void_p)",
        "function.restype = ctypes.c_int32  # WLPQ FFI validate restype",
        'expected_identity = b"@rpath/libwasabi_liquid_wlpq_v1.dylib\\0"',
        'expected_identity = b"libwasabi_liquid_wlpq_v1.so\\0"',
        "library_bytes.count(expected_identity) != 1",
        'str(library_path).encode("utf-8") + b"\\0" in library_bytes',
        '("frame-test-toy-single.hex", epoch, 0)',
        '("frame-wrong-magic.hex", epoch, -2)',
        '("frame-truncated-body.hex", epoch, -3)',
        '("frame-candidate-length-plus-one.hex", epoch, -4)',
        '("frame-test-toy-single.hex", bytes([0x42]) * 32, -5)',
        "function(None, 1, epoch_buffer) != -1",
        "function(ctypes.byref(byte), 268_435_457, epoch_buffer) != -4",
        "read_regular(library_path, 64 * 1024 * 1024) != library_bytes",
        "sign_function = library.wln_wlpq_sign_finalize_v1",
        'reject("WLPQ FFI dynamic sign null-pointer precedence changed")',
    )
    if any(test.count(token) != 1 for token in required):
        reject("WLPQ FFI dynamic-test authority changed")
    for forbidden in ("subprocess", "socket", "urllib", "requests", "http"):
        if forbidden in test:
            reject("WLPQ FFI dynamic-test capability surface expanded")


def validate_symbols(platform: str, path: Path) -> None:
    symbols = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        symbol = line.split()[-1]
        if platform == "Darwin":
            if not symbol.startswith("_"):
                reject("WLPQ FFI Darwin export spelling changed")
            symbol = symbol[1:]
        elif platform != "Linux":
            reject("unsupported WLPQ FFI symbol platform")
        symbols.append(symbol)
    if symbols != ["wln_wlpq_sign_finalize_v1", "wln_wlpq_validate_v1"]:
        reject("WLPQ FFI dynamic export allowlist changed")


def validate(root: Path) -> None:
    crate = root / "crates" / "ordinary-wallet-plan-ffi"
    actual = {
        path.relative_to(crate).as_posix()
        for path in crate.rglob("*")
        if path.is_file() or path.is_symlink()
    }
    if actual != set(EXPECTED_FILES):
        reject("WLPQ FFI file inventory changed")

    contents = {}
    for relative, expected_hash in EXPECTED_FILES.items():
        data = read_exact_file(crate / relative, relative)
        if sha256(data) != expected_hash:
            reject(f"WLPQ FFI reviewed bytes changed: {relative}")
        contents[relative] = data.decode("utf-8")

    support_contents = {}
    for relative, (expected_hash, mode) in EXPECTED_SUPPORT_FILES.items():
        data = read_exact_file(root / relative, relative, mode)
        if sha256(data) != expected_hash:
            reject(f"WLPQ FFI reviewed bytes changed: {relative}")
        support_contents[relative] = data.decode("utf-8")

    validate_manifest(root, contents["Cargo.toml"])
    validate_rust_source(contents["src/lib.rs"])
    validate_header(contents["include/wasabi_liquid_wlpq_v1.h"])
    validate_shim(contents["src/shim.c"])
    validate_export_maps(contents)
    validate_builder(support_contents["ci/build-wlpq-ffi-library.sh"])
    validate_dynamic_test(support_contents["ci/test-wlpq-ffi-dynamic.py"])


def main() -> None:
    if len(sys.argv) == 2:
        validate(Path(sys.argv[1]).resolve())
        return
    if len(sys.argv) == 5 and sys.argv[2] == "--symbols":
        validate_symbols(sys.argv[3], Path(sys.argv[4]).resolve())
        return
    reject("usage: check-wlpq-ffi-surface.py ROOT [--symbols PLATFORM FILE]")


if __name__ == "__main__":
    main()
