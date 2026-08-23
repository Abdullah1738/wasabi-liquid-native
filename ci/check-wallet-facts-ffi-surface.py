#!/usr/bin/env python3
import pathlib
import sys
import tomllib


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def main() -> None:
    require(len(sys.argv) == 2, "usage: check-wallet-facts-ffi-surface.py REPOSITORY_ROOT")
    root = pathlib.Path(sys.argv[1]).resolve()
    crate = root / "crates/wallet-facts-ffi"
    manifest = tomllib.loads((crate / "Cargo.toml").read_text())
    require(manifest["lib"]["crate-type"] == ["rlib", "cdylib"], "crate types drifted")
    require(set(manifest["dependencies"]) == {
        "rand", "sha2", "wasabi-liquid-native-wallet-facts",
        "wasabi-liquid-native-wallet-facts-wire", "zeroize"
    }, "dependency capability surface drifted")
    require(set(manifest["dev-dependencies"]) == {"elements", "miniscript", "rand"}, "dev dependency surface drifted")
    source = (crate / "src/lib.rs").read_text()
    for token in (
        "wln_wallet_facts_observe_impl_v1", "catch_unwind(AssertUnwindSafe",
        "ptr::write(out_response_length, 0)", "decode_request(&request.0)",
        ".prepare()", "observe_owned_outputs(", "encode_response(",
        "WLN_WALLET_FACTS_HASH_DRBG_V1", "PanicPoint::PreCopy",
        "PanicPoint::RequestStaging", "PanicPoint::Preparation",
        "PanicPoint::Drbg", "PanicPoint::Observation",
        "PanicPoint::PerScriptDerivation", "PanicPoint::Encoding",
        "PanicPoint::ResponseScratch",
    ):
        require(token in source, f"missing required source token: {token}")
    require(source.count("observe_owned_outputs(") == 1, "observer call count drifted")
    require(source.count("encode_response(") == 1, "response encoder call count drifted")
    require("open_confidential_output" not in source, "narrow opening primitive is forbidden")
    shim = (crate / "src/shim.c").read_text()
    require(shim.count("WLN_WALLET_FACTS_EXPORT_V1 int32_t") == 1, "C export count drifted")
    require("wln_wallet_facts_observe_v1" in shim, "public C symbol missing")
    require(
        (crate / "exports/linux.map").read_text()
        == "{\n    global:\n        wln_wallet_facts_observe_v1;\n    local:\n        *;\n};\n",
        "Linux export map drifted",
    )
    require(
        (crate / "exports/macos.txt").read_text() == "_wln_wallet_facts_observe_v1\n",
        "macOS export map drifted",
    )
    require(
        (crate / "exports/windows.def").read_text()
        == "LIBRARY wasabi_liquid_wallet_facts_v1\nEXPORTS\n    wln_wallet_facts_observe_v1\n",
        "Windows export map drifted",
    )
    print("wallet-facts FFI surface: OK")


if __name__ == "__main__":
    main()
