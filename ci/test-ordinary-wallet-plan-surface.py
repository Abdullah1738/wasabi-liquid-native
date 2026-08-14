#!/usr/bin/env python3
"""Negative mutation tests for the fail-closed WLPQ source surface."""

from __future__ import annotations

import importlib.util
import os
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
TEST_DARWIN_SDKROOT_VARIABLE = "WLPQ_TEST_DARWIN_SDKROOT"


def test_precomputed_compiled_source_boundary() -> None:
    checker_path = ROOT / "ci/check-ordinary-wallet-plan-surface.py"
    spec = importlib.util.spec_from_file_location("plan_surface_boundary", checker_path)
    if spec is None or spec.loader is None:
        raise AssertionError("surface checker import specification is unavailable")
    checker = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(checker)
    expected = ("src/lib.rs", "src/reader.rs", "src/writer.rs")
    source = checker.production_text()
    if checker.validate_compiled_source_closure_and_pins(source, expected) != source:
        raise AssertionError("valid precomputed compiled-source boundary changed")
    invalid = (
        expected[:-1],
        (expected[1], expected[0], expected[2]),
        (*expected, expected[0]),
        (*expected, "src/extra.rs"),
        tuple(f"crates/ordinary-wallet-plan/{path}" for path in expected),
        tuple(str((ROOT / "crates/ordinary-wallet-plan" / path).resolve()) for path in expected),
    )
    for compiled_files in invalid:
        try:
            checker.validate_compiled_source_closure_and_pins(source, compiled_files)
        except SystemExit as error:
            if str(error) != "ordinary-wallet plan compiler source closure changed":
                raise AssertionError(
                    f"unexpected precomputed boundary rejection: {error}"
                ) from error
        else:
            raise AssertionError(
                f"invalid precomputed compiled-source boundary was accepted: {compiled_files}"
            )


def append_lib(root: Path, text: str) -> None:
    path = root / "crates/ordinary-wallet-plan/src/lib.rs"
    path.write_text(path.read_text() + text)


def replace_once(root: Path, relative: str, old: str, new: str) -> None:
    path = root / relative
    text = path.read_text()
    if text.count(old) != 1:
        raise AssertionError(f"mutation target mismatch: {relative}: {old}")
    path.write_text(text.replace(old, new, 1))


def replace_exact_count(
    root: Path, relative: str, old: str, new: str, expected_count: int
) -> None:
    path = root / relative
    text = path.read_text()
    if text.count(old) != expected_count:
        raise AssertionError(
            f"mutation target mismatch: {relative}: expected {expected_count}: {old}"
        )
    path.write_text(text.replace(old, new))


def add_ninth_error(root: Path) -> None:
    relative = "crates/ordinary-wallet-plan/src/lib.rs"
    replace_once(
        root,
        relative,
        "    FundingRejected,\n}",
        "    FundingRejected,\n    Disclosed,\n}",
    )
    replace_once(
        root,
        relative,
        "            Self::FundingRejected => 8,\n",
        "            Self::FundingRejected => 8,\n            Self::Disclosed => 9,\n",
    )
    replace_once(
        root,
        relative,
        '            Self::FundingRejected => "ordinary wallet plan wire funding was rejected",\n',
        '            Self::FundingRejected => "ordinary wallet plan wire funding was rejected",\n'
        '            Self::Disclosed => "ordinary wallet plan wire disclosure was rejected",\n',
    )


def compiled_sources(root: Path) -> tuple[str, ...]:
    result = subprocess.run(
        [
            "cargo",
            "rustc",
            "-p",
            "wasabi-liquid-native-ordinary-wallet-plan",
            "--lib",
            "--locked",
            "--offline",
            "--",
            "--emit=dep-info=-",
        ],
        cwd=root,
        env=cargo_environment(root),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        raise AssertionError(f"source-closure mutation did not compile:\n{result.stderr}")
    crate = (root / "crates/ordinary-wallet-plan").resolve()
    sources = set()
    for line in result.stdout.splitlines():
        if ":" not in line:
            continue
        for token in line.split(":", 1)[1].split():
            path = Path(token)
            if not path.is_absolute():
                path = root / path
            if not path.exists():
                continue
            path = path.resolve()
            try:
                sources.add(path.relative_to(crate).as_posix())
            except ValueError:
                sources.add(path.relative_to(root.resolve()).as_posix())
    return tuple(sorted(sources))


def add_external_disclosure_module(root: Path) -> None:
    (root / "external-disclosure.rs").write_text(
        """pub(crate) fn exercise() {
    let _ = std::process::id();
    let _ = std::fs::metadata(".");
    let _ = "127.0.0.1".parse::<std::net::IpAddr>();
}
"""
    )
    replace_once(
        root,
        "crates/ordinary-wallet-plan/src/lib.rs",
        "#[cfg(test)]\nmod tests;",
        "#[cfg(test)]\nmod tests;\n\n#[path = \"../../../external-disclosure.rs\"]\nmod external_disclosure;",
    )
    replace_once(
        root,
        "crates/ordinary-wallet-plan/src/lib.rs",
        "fn encode_view<R: RequestView>(\n    request: &R,\n) -> Result<EncodedOrdinaryWalletPlanRequest, OrdinaryWalletPlanWireError> {",
        "fn encode_view<R: RequestView>(\n    request: &R,\n) -> Result<EncodedOrdinaryWalletPlanRequest, OrdinaryWalletPlanWireError> {\n"
        "    external_disclosure::exercise();",
    )


def add_ordinary_pset_capability(root: Path, item: str, source: str) -> None:
    replace_once(
        root,
        "crates/ordinary-wallet-plan/src/lib.rs",
        "    OrdinaryP2wpkhSigner,\n};",
        f"    OrdinaryP2wpkhSigner, {item},\n}};",
    )
    append_lib(root, source)


def add_wallet_facts_capability(root: Path, item: str, source: str) -> None:
    replace_once(
        root,
        "crates/ordinary-wallet-plan/src/lib.rs",
        "    BorrowedSelectedOutput, DescriptorCatalog, DescriptorNetwork, SelectedOutputBatch,\n"
        "    SelectedOutputOpeningProvider, prepare_selected_owned_inputs,\n",
        "    BorrowedSelectedOutput, DescriptorCatalog, DescriptorNetwork, SelectedOutputBatch,\n"
        f"    SelectedOutputOpeningProvider, prepare_selected_owned_inputs, {item},\n",
    )
    append_lib(root, source)


def replace_lib_with_inline_table(root: Path) -> None:
    path = root / "crates/ordinary-wallet-plan/Cargo.toml"
    text = path.read_text()
    stanza = '[lib]\ncrate-type = ["rlib"]\n\n'
    if text.count(stanza) != 1:
        raise AssertionError("inline library mutation target mismatch")
    path.write_text(
        '"lib" = { "crate-type" = ["rlib"], "test" = false }\n\n'
        + text.replace(stanza, "", 1)
    )


def cargo_environment(root: Path, *, platform: str | None = None) -> dict[str, str]:
    environment = os.environ.copy()
    darwin_sdkroot = environment.pop(TEST_DARWIN_SDKROOT_VARIABLE, "")
    environment.pop("SDKROOT", None)
    active_platform = sys.platform if platform is None else platform
    if active_platform == "darwin":
        sdkroot = Path(darwin_sdkroot)
        if not sdkroot.is_absolute() or sdkroot.is_symlink() or not sdkroot.is_dir():
            raise AssertionError("validated Darwin test SDK root is required")
        environment["SDKROOT"] = str(sdkroot)
    elif darwin_sdkroot:
        raise AssertionError("Darwin test SDK root was supplied on a non-Darwin host")
    environment["CARGO_TARGET_DIR"] = str(root.parent / ".target")
    return environment


def test_cargo_environment_boundary() -> None:
    original = os.environ.get(TEST_DARWIN_SDKROOT_VARIABLE)
    original_sdkroot = os.environ.get("SDKROOT")
    try:
        with tempfile.TemporaryDirectory(prefix="ordinary-wallet-plan-sdkroot-") as directory:
            sdkroot = Path(directory).resolve()
            os.environ[TEST_DARWIN_SDKROOT_VARIABLE] = str(sdkroot)
            os.environ["SDKROOT"] = "/tmp/unreviewed-sdkroot"
            environment = cargo_environment(ROOT, platform="darwin")
            if (
                environment.get("SDKROOT") != str(sdkroot)
                or TEST_DARWIN_SDKROOT_VARIABLE in environment
            ):
                raise AssertionError("validated Darwin SDK root was not isolated")
            try:
                cargo_environment(ROOT, platform="linux")
            except AssertionError:
                pass
            else:
                raise AssertionError("Darwin SDK root was accepted on a non-Darwin host")

            os.environ[TEST_DARWIN_SDKROOT_VARIABLE] = ""
            if "SDKROOT" in cargo_environment(ROOT, platform="linux"):
                raise AssertionError("ambient SDK root reached a non-Darwin Cargo child")

            sdkroot_link = sdkroot / "sdkroot-link"
            sdkroot_link.symlink_to(sdkroot, target_is_directory=True)
            os.environ[TEST_DARWIN_SDKROOT_VARIABLE] = str(sdkroot_link)
            try:
                cargo_environment(ROOT, platform="darwin")
            except AssertionError:
                pass
            else:
                raise AssertionError("symlinked Darwin SDK root was accepted")

            invalid = sdkroot / "not-a-directory"
            invalid.write_text("not an SDK root\n")
            os.environ[TEST_DARWIN_SDKROOT_VARIABLE] = str(invalid)
            try:
                cargo_environment(ROOT, platform="darwin")
            except AssertionError:
                pass
            else:
                raise AssertionError("non-directory Darwin SDK root was accepted")
    finally:
        if original is None:
            os.environ.pop(TEST_DARWIN_SDKROOT_VARIABLE, None)
        else:
            os.environ[TEST_DARWIN_SDKROOT_VARIABLE] = original
        if original_sdkroot is None:
            os.environ.pop("SDKROOT", None)
        else:
            os.environ["SDKROOT"] = original_sdkroot


def require_compiles(root: Path, *, integration_test: bool = False) -> None:
    target = ["--test", "preparation"] if integration_test else ["--lib"]
    result = subprocess.run(
        [
            "cargo",
            "rustc",
            "-p",
            "wasabi-liquid-native-ordinary-wallet-plan",
            *target,
            "--locked",
            "--offline",
            "--",
            "-Dwarnings",
        ],
        cwd=root,
        env=cargo_environment(root),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0 or "warning:" in result.stderr.lower():
        raise AssertionError(
            "compile-valid mutation did not compile warning-free:\n"
            f"{result.stdout}{result.stderr}"
        )


def add_external_include(root: Path, *, rust_source: bool) -> tuple[str, ...]:
    if rust_source:
        external = root / "external-include.rs"
        external.write_text("const EXTERNAL_INCLUDE_VALUE: u8 = 1;\n")
        append_lib(root, '\ninclude/**/!("../../../external-include.rs");\n')
    else:
        external = root / "external-payload.bin"
        external.write_bytes(b"public fixture only")
        append_lib(
            root,
            '\nconst EXTERNAL_PAYLOAD: &[u8] = include_bytes/**/!("../../../external-payload.bin");\n',
        )
    return compiled_sources(root)


SOURCE_DRIFT = "source pins detect drift only and updating them requires fresh review"
AUTHORITY_DRIFT = "region pins detect drift only and updating them requires fresh review"
RUNTIME_AUTHORITY_DRIFT = (
    "pins are drift alarms; updating pins/checker requires fresh review"
)


def run_checker(root: Path, *, success: bool, contains: str | None = None) -> None:
    result = subprocess.run(
        ["python3", "ci/check-ordinary-wallet-plan-surface.py"],
        cwd=root,
        env=cargo_environment(root),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if (result.returncode == 0) != success:
        raise AssertionError(
            f"unexpected surface result {result.returncode}:\n"
            f"{result.stdout}{result.stderr}"
        )
    output = result.stdout + result.stderr
    if contains is not None and contains not in output:
        raise AssertionError(f"surface result did not contain {contains!r}:\n{output}")


def make_owner_mutable(root: Path) -> None:
    paths = (root, *root.rglob("*"))
    for path in paths:
        metadata = os.lstat(path)
        if stat.S_ISLNK(metadata.st_mode):
            continue
        os.chmod(path, stat.S_IMODE(metadata.st_mode) | stat.S_IWUSR)


def test_make_owner_mutable() -> None:
    with tempfile.TemporaryDirectory(prefix="ordinary-wallet-plan-mutable-") as directory:
        root = Path(directory) / "sealed-copy"
        nested = root / "nested"
        nested.mkdir(parents=True)
        source = nested / "source.rs"
        source.write_text("pub fn checked() {}\n")
        source.chmod(0o444)
        nested.chmod(0o555)
        root.chmod(0o555)
        make_owner_mutable(root)
        for path in (root, nested, source):
            if not stat.S_IMODE(os.lstat(path).st_mode) & stat.S_IWUSR:
                raise AssertionError(f"private mutation copy remained read-only: {path}")


def copy_root(parent: Path, name: str) -> Path:
    destination = parent / name
    shutil.copytree(
        ROOT,
        destination,
        ignore=shutil.ignore_patterns(".git", "target", "tmp", "__pycache__", "*.pyc"),
    )
    make_owner_mutable(destination)
    return destination


def mutate(parent: Path, name: str, mutation, *, contains: str | None = None) -> None:
    root = copy_root(parent, name)
    mutation(root)
    run_checker(root, success=False, contains=contains)


def mutate_compiling(
    parent: Path,
    name: str,
    mutation,
    *,
    integration_test: bool = False,
    contains: str | None = None,
) -> None:
    root = copy_root(parent, name)
    mutation(root)
    require_compiles(root, integration_test=integration_test)
    run_checker(root, success=False, contains=contains)


def add_module_stateful_encoder(root: Path, declaration: str, expression: str) -> None:
    append_lib(root, f"\n{declaration}\n")
    replace_once(
        root,
        "crates/ordinary-wallet-plan/src/lib.rs",
        "fn encode_view<R: RequestView>(\n"
        "    request: &R,\n"
        ") -> Result<EncodedOrdinaryWalletPlanRequest, OrdinaryWalletPlanWireError> {\n"
        "    let facts = validate_structural_view(request)?;",
        "fn encode_view<R: RequestView>(\n"
        "    request: &R,\n"
        ") -> Result<EncodedOrdinaryWalletPlanRequest, OrdinaryWalletPlanWireError> {\n"
        f"    if {expression} {{\n"
        "        return Err(OrdinaryWalletPlanWireError::InvalidArgument);\n"
        "    }\n"
        "    let facts = validate_structural_view(request)?;",
    )


def add_local_stateful_encoder(root: Path, declaration: str, expression: str) -> None:
    replace_once(
        root,
        "crates/ordinary-wallet-plan/src/lib.rs",
        "fn encode_view<R: RequestView>(\n"
        "    request: &R,\n"
        ") -> Result<EncodedOrdinaryWalletPlanRequest, OrdinaryWalletPlanWireError> {\n"
        "    let facts = validate_structural_view(request)?;",
        "fn encode_view<R: RequestView>(\n"
        "    request: &R,\n"
        ") -> Result<EncodedOrdinaryWalletPlanRequest, OrdinaryWalletPlanWireError> {\n"
        f"    {declaration}\n"
        f"    if {expression} {{\n"
        "        return Err(OrdinaryWalletPlanWireError::InvalidArgument);\n"
        "    }\n"
        "    let facts = validate_structural_view(request)?;",
    )


def main() -> None:
    test_precomputed_compiled_source_boundary()
    test_cargo_environment_boundary()
    test_make_owner_mutable()
    with tempfile.TemporaryDirectory(prefix="ordinary-wallet-plan-surface-") as directory:
        scratch = Path(directory)
        valid = copy_root(scratch, "valid")
        run_checker(valid, success=True)

        mutate(
            scratch,
            "conformance-module-detached",
            lambda root: replace_once(
                root,
                "crates/ordinary-wallet-plan/src/tests.rs",
                "mod conformance;\n",
                "",
            ),
            contains="ordinary-wallet plan conformance test module binding changed",
        )
        mutate(
            scratch,
            "conformance-source-byte-drift",
            lambda root: (
                root / "crates/ordinary-wallet-plan/src/tests/conformance.rs"
            ).write_text(
                (
                    root / "crates/ordinary-wallet-plan/src/tests/conformance.rs"
                ).read_text()
                + "\n"
            ),
            contains="ordinary-wallet plan conformance test source changed",
        )
        mutate_compiling(
            scratch,
            "finalized-integration-test-renamed",
            lambda root: replace_once(
                root,
                "crates/ordinary-wallet-plan/tests/preparation.rs",
                "fn prepared_multiasset_request_consumes_into_a_finalized_transaction() {\n",
                "fn renamed_multiasset_request_consumes_into_a_finalized_transaction() {\n",
            ),
            integration_test=True,
            contains="ordinary-wallet plan integration test source changed",
        )
        for name, attribute in (
            ("conformance-module-cfg-disabled", "#[cfg(any())]"),
            ("conformance-module-path-redirected", '#[path = "ignored.rs"]'),
        ):
            mutate(
                scratch,
                name,
                lambda root, attribute=attribute: replace_once(
                    root,
                    "crates/ordinary-wallet-plan/src/tests.rs",
                    "mod conformance;\n",
                    f"{attribute}\nmod conformance;\n",
                ),
                contains="ordinary-wallet plan conformance test module source changed",
            )

        reviewed_source_drift_mutations = {
            "ordinary-stack-copy": (
                "#[allow(dead_code)]\n"
                "fn leaked_stack_copy(value: [u8; 32]) -> ([u8; 32], [u8; 32]) {\n"
                "    let copy = value;\n"
                "    (value, copy)\n"
                "}"
            ),
            "vec-copy": (
                "#[allow(dead_code)]\n"
                "fn leaked_vec_copy(value: &Vec<u8>) -> Vec<u8> { value.clone() }"
            ),
            "box-copy": (
                "#[allow(dead_code)]\n"
                "fn leaked_box_copy(value: &Box<[u8]>) -> Box<[u8]> { value.clone() }"
            ),
            "string-copy": (
                "#[allow(dead_code)]\n"
                "fn leaked_string_copy(value: &String) -> String { value.clone() }"
            ),
            "box-leak": (
                "#[allow(dead_code)]\n"
                "fn leaked_box(value: Box<[u8]>) { let _ = Box::leak(value); }"
            ),
            "vec-leak": (
                "#[allow(dead_code)]\n"
                "fn leaked_vec(value: Vec<u8>) { let _ = value.leak(); }"
            ),
            "string-leak": (
                "#[allow(dead_code)]\n"
                "fn leaked_string(value: String) { let _ = value.leak(); }"
            ),
            "box-into-raw": (
                "#[allow(dead_code)]\n"
                "fn leaked_box_raw(value: Box<[u8]>) { let _ = Box::into_raw(value); }"
            ),
            "vec-into-raw-parts": (
                "#[allow(dead_code)]\n"
                "fn leaked_vec_raw(value: Vec<u8>) { let _ = value.into_raw_parts(); }"
            ),
            "aliased-mem-forget": (
                "use std::mem::forget as retain_allocation;\n"
                "#[allow(dead_code)]\n"
                "fn leaked_alias(value: Vec<u8>) { retain_allocation(value); }"
            ),
            "comment-separated-mem-forget": (
                "#[allow(dead_code)]\n"
                "fn leaked_comment(value: Vec<u8>) { std/**/::mem/**/::forget(value); }"
            ),
            "raw-token-mem-forget": (
                "#[allow(dead_code)]\n"
                "fn leaked_raw_token(value: Vec<u8>) { std::mem::r#forget(value); }"
            ),
            "manually-drop": (
                "#[allow(dead_code)]\n"
                "fn leaked_manual(value: Vec<u8>) {\n"
                "    let _retained = core::mem::ManuallyDrop::new(value);\n"
                "}"
            ),
            "maybe-uninit": (
                "#[allow(dead_code)]\n"
                "fn leaked_uninit(value: Vec<u8>) {\n"
                "    let _retained = core::mem::MaybeUninit::new(value);\n"
                "}"
            ),
        }
        for name, syntax in reviewed_source_drift_mutations.items():
            mutate_compiling(
                scratch,
                name,
                lambda root, syntax=syntax: append_lib(root, f"\n{syntax}\n"),
                contains=SOURCE_DRIFT,
            )
        for name, relative in [
            ("reader-reviewed-byte-drift", "crates/ordinary-wallet-plan/src/reader.rs"),
            ("writer-reviewed-byte-drift", "crates/ordinary-wallet-plan/src/writer.rs"),
        ]:
            mutate_compiling(
                scratch,
                name,
                lambda root, relative=relative: (
                    root / relative
                ).write_text(
                    (root / relative).read_text()
                    + "\n#[allow(dead_code)]\nconst REVIEWED_BYTE_DRIFT: usize = 0;\n"
                ),
                contains=SOURCE_DRIFT,
            )

        for name, relative in [
            ("address-whole-file-byte-drift", "crates/address/src/lib.rs"),
            ("ordinary-pset-whole-file-byte-drift", "crates/ordinary-pset/src/lib.rs"),
            ("wallet-facts-whole-file-byte-drift", "crates/wallet-facts/src/lib.rs"),
            (
                "transaction-validation-whole-file-byte-drift",
                "crates/transaction-validation/src/lib.rs",
            ),
        ]:
            mutate_compiling(
                scratch,
                name,
                lambda root, relative=relative: (root / relative).write_text(
                    (root / relative).read_text()
                    + "\n// Runtime-authority whole-file drift mutation.\n"
                ),
                contains=RUNTIME_AUTHORITY_DRIFT,
            )

        for name, relative, old, new in [
            (
                "wallet-facts-previous-outputs-environment-drift",
                "crates/wallet-facts/src/lib.rs",
                ") -> Result<BTreeMap<OutPoint, TxOut>, WalletObservationError> {\n"
                "    let mut previous_by_id = BTreeMap::<Txid, Transaction>::new();",
                ") -> Result<BTreeMap<OutPoint, TxOut>, WalletObservationError> {\n"
                "    let _ = std::env::var_os(\"WLPQ_RUNTIME_AUTHORITY_DRIFT\");\n"
                "    let mut previous_by_id = BTreeMap::<Txid, Transaction>::new();",
            ),
            (
                "transaction-validation-amount-proof-drift",
                "crates/transaction-validation/src/lib.rs",
                "verify_tx_amt_proofs(secp, &ordered_previous_outputs)",
                "verify_tx_amt_proofs(secp, &ordered_previous_outputs[..0])",
            ),
            (
                "ordinary-pset-confidential-output-asset-drift",
                "crates/ordinary-pset/src/lib.rs",
                "    pub const fn asset(&self) -> AssetId {\n"
                "        self.asset\n"
                "    }",
                "    pub const fn asset(&self) -> AssetId {\n"
                "        AssetId::from_byte_array([0; 32])\n"
                "    }",
            ),
            (
                "address-limit-outside-region-drift",
                "crates/address/src/lib.rs",
                "pub const MAX_ADDRESS_BYTES: usize = 256;",
                "pub const MAX_ADDRESS_BYTES: usize = 255;",
            ),
        ]:
            mutate_compiling(
                scratch,
                name,
                lambda root, relative=relative, old=old, new=new: replace_once(
                    root, relative, old, new
                ),
                contains=RUNTIME_AUTHORITY_DRIFT,
            )

        descriptor_method_end = (
            "    pub fn script_count(&self) -> usize {\n"
            "        self.entries.len()\n"
            "    }\n"
            "}\n\n"
            "fn key_uses_unhardened_wildcard"
        )
        descriptor_authority_mutations = {
            "descriptor-network-setter": (
                "    pub fn script_count(&self) -> usize {\n"
                "        self.entries.len()\n"
                "    }\n\n"
                "    /// Changes the catalog network after validation.\n"
                "    pub fn set_network(&mut self, network: DescriptorNetwork) {\n"
                "        self.network = network;\n"
                "    }\n"
                "}\n\n"
                "fn key_uses_unhardened_wildcard"
            ),
            "descriptor-retag": (
                "    pub fn script_count(&self) -> usize {\n"
                "        self.entries.len()\n"
                "    }\n\n"
                "    /// Retags the catalog network after validation.\n"
                "    pub fn retag(mut self, network: DescriptorNetwork) -> Self {\n"
                "        self.network = network;\n"
                "        self\n"
                "    }\n"
                "}\n\n"
                "fn key_uses_unhardened_wildcard"
            ),
            "descriptor-alternate-constructor": (
                "    pub fn script_count(&self) -> usize {\n"
                "        self.entries.len()\n"
                "    }\n\n"
                "    /// Creates an empty catalog without descriptor validation.\n"
                "    pub fn empty(network: DescriptorNetwork) -> Self {\n"
                "        Self { entries: BTreeMap::new(), network, last_index: 0 }\n"
                "    }\n"
                "}\n\n"
                "fn key_uses_unhardened_wildcard"
            ),
            "descriptor-constant-accessor": (
                "    pub fn script_count(&self) -> usize {\n"
                "        self.entries.len()\n"
                "    }\n\n"
                "    /// Returns a constant network without consulting catalog state.\n"
                "    pub const fn assumed_network() -> DescriptorNetwork {\n"
                "        DescriptorNetwork::Mainnet\n"
                "    }\n"
                "}\n\n"
                "fn key_uses_unhardened_wildcard"
            ),
        }
        for name, replacement in descriptor_authority_mutations.items():
            mutate_compiling(
                scratch,
                name,
                lambda root, replacement=replacement: replace_once(
                    root,
                    "crates/wallet-facts/src/lib.rs",
                    descriptor_method_end,
                    replacement,
                ),
                contains=AUTHORITY_DRIFT,
            )
        mutate_compiling(
            scratch,
            "descriptor-wrong-field-accessor",
            lambda root: replace_once(
                root,
                "crates/wallet-facts/src/lib.rs",
                "    pub const fn network(&self) -> DescriptorNetwork {\n"
                "        self.network\n"
                "    }",
                "    pub const fn network(&self) -> DescriptorNetwork {\n"
                "        if self.last_index == 0 {\n"
                "            DescriptorNetwork::Mainnet\n"
                "        } else {\n"
                "            DescriptorNetwork::Test\n"
                "        }\n"
                "    }",
            ),
            contains=AUTHORITY_DRIFT,
        )
        mutate_compiling(
            scratch,
            "descriptor-drop-network-drift",
            lambda root: replace_once(
                root,
                "crates/wallet-facts/src/lib.rs",
                "impl Drop for DescriptorCatalog {\n"
                "    fn drop(&mut self) {\n"
                "        self.network = DescriptorNetwork::Mainnet;",
                "impl Drop for DescriptorCatalog {\n"
                "    fn drop(&mut self) {\n"
                "        self.network = DescriptorNetwork::Test;",
            ),
            contains=AUTHORITY_DRIFT,
        )
        mutate_compiling(
            scratch,
            "descriptor-network-enum-drift",
            lambda root: (
                replace_once(
                    root,
                    "crates/wallet-facts/src/lib.rs",
                    "    Mainnet,",
                    "    Mainnet = 1,",
                ),
                replace_once(
                    root,
                    "crates/wallet-facts/src/lib.rs",
                    "    Test,",
                    "    Test = 2,",
                ),
            ),
            contains=AUTHORITY_DRIFT,
        )
        for name, relative, old, new in [
            (
                "address-profile-bypass",
                "crates/address/src/lib.rs",
                "Address::parse_with_params(encoded, expected_profile.params())",
                "Address::parse_with_params(encoded, LiquidAddressProfile::ElementsDefault.params())",
            ),
            (
                "address-canonical-encoding-drift",
                "crates/address/src/lib.rs",
                "let canonical_address = address.to_string();",
                "let canonical_address = address.to_unconfidential().to_string();",
            ),
            (
                "selected-batch-limit-drift",
                "crates/wallet-facts/src/lib.rs",
                "requests.is_empty() || requests.len() > MAX_SELECTED_OUTPUTS",
                "requests.is_empty() || requests.len() >= MAX_SELECTED_OUTPUTS",
            ),
            (
                "selected-preparation-ownership-drift",
                "crates/wallet-facts/src/lib.rs",
                "        if !catalog\n"
                "            .entries\n"
                "            .contains_key(selected_output.script_pubkey.as_bytes())",
                "        if catalog\n"
                "            .entries\n"
                "            .contains_key(selected_output.script_pubkey.as_bytes())",
            ),
            (
                "confidential-output-zero-value-drift",
                "crates/ordinary-pset/src/lib.rs",
                "    pub fn from_address(\n"
                "        asset: AssetId,\n"
                "        value: u64,\n"
                "        address: &ConfidentialLiquidAddress,\n"
                "    ) -> Result<Self, ConfidentialOutputError> {\n"
                "        if value == 0 {",
                "    pub fn from_address(\n"
                "        asset: AssetId,\n"
                "        value: u64,\n"
                "        address: &ConfidentialLiquidAddress,\n"
                "    ) -> Result<Self, ConfidentialOutputError> {\n"
                "        if value == u64::MAX {",
            ),
            (
                "explicit-fee-zero-value-drift",
                "crates/ordinary-pset/src/lib.rs",
                "    pub fn new(asset: AssetId, value: u64) -> Result<Self, ExplicitFeeError> {\n"
                "        if value == 0 {",
                "    pub fn new(asset: AssetId, value: u64) -> Result<Self, ExplicitFeeError> {\n"
                "        if value == u64::MAX {",
            ),
        ]:
            mutate_compiling(
                scratch,
                name,
                lambda root, relative=relative, old=old, new=new: replace_once(
                    root, relative, old, new
                ),
                contains=AUTHORITY_DRIFT,
            )

        mutate(
            scratch,
            "new-module",
            lambda root: (root / "crates/ordinary-wallet-plan/src/escape.rs").write_text(""),
        )
        mutate(
            scratch,
            "build-script",
            lambda root: (root / "crates/ordinary-wallet-plan/build.rs").write_text(
                "fn main() {}\n"
            ),
        )
        mutate(
            scratch,
            "provider-call",
            lambda root: append_lib(root, "\nfn escape() { open_prepared_selected_owned_inputs(); }\n"),
        )
        mutate(
            scratch,
            "public-accessor",
            lambda root: append_lib(root, "\npub fn leaked_plan_accessor() {}\n"),
        )
        mutate(
            scratch,
            "public-field",
            lambda root: replace_once(
                root,
                "crates/ordinary-wallet-plan/src/lib.rs",
                "    _catalog: &'catalog DescriptorCatalog,",
                "    pub _catalog: &'catalog DescriptorCatalog,",
            ),
        )
        mutate(
            scratch,
            "inline-public-field",
            lambda root: append_lib(root, "\nstruct Leaked { pub value: u8 }\n"),
        )
        mutate(
            scratch,
            "remove-non-exhaustive",
            lambda root: replace_once(
                root,
                "crates/ordinary-wallet-plan/src/lib.rs",
                "#[non_exhaustive]\n",
                "",
            ),
        )
        mutate(
            scratch,
            "derive-default-owner",
            lambda root: replace_once(
                root,
                "crates/ordinary-wallet-plan/src/lib.rs",
                "pub struct EncodedOrdinaryWalletPlanRequest {",
                "#[derive(Default)]\npub struct EncodedOrdinaryWalletPlanRequest {",
            ),
        )
        mutate(
            scratch,
            "production-only-default-owner",
            lambda root: replace_once(
                root,
                "crates/ordinary-wallet-plan/src/lib.rs",
                "pub struct EncodedOrdinaryWalletPlanRequest {",
                "#[cfg_attr(not(test), derive(Default))]\npub struct EncodedOrdinaryWalletPlanRequest {",
            ),
        )
        mutate(
            scratch,
            "comment-separated-derive-default",
            lambda root: replace_once(
                root,
                "crates/ordinary-wallet-plan/src/lib.rs",
                "pub struct EncodedOrdinaryWalletPlanRequest {",
                "#/**/[derive(Default)]\npub struct EncodedOrdinaryWalletPlanRequest {",
            ),
        )
        mutate(
            scratch,
            "multiline-derive-default",
            lambda root: replace_once(
                root,
                "crates/ordinary-wallet-plan/src/lib.rs",
                "pub struct EncodedOrdinaryWalletPlanRequest {",
                "#[\n    derive(Default)\n]\npub struct EncodedOrdinaryWalletPlanRequest {",
            ),
        )
        for name, syntax in {
            "public-use": "pub use core::fmt;",
            "public-module": "pub mod leaked {}",
            "public-const": "pub const LEAKED: u8 = 0;",
            "public-static": "pub static LEAKED: u8 = 0;",
            "public-type": "pub type Leaked = u8;",
            "public-trait": "pub trait Leaked {}",
            "public-union": "pub union Leaked { value: u8 }",
            "crate-public-accessor": "pub(crate) fn leaked_crate_accessor() {}",
            "self-public-accessor": "pub(self) fn leaked_self_accessor() {}",
            "super-public-accessor": "pub(super) fn leaked_super_accessor() {}",
            "in-public-accessor": "pub(in crate) fn leaked_in_accessor() {}",
            "public-macro": "pub macro leaked() {}",
        }.items():
            mutate(scratch, name, lambda root, syntax=syntax: append_lib(root, f"\n{syntax}\n"))
        disclosure_mutations = {
            "log-source-epoch": (
                "fn encode_view<R: RequestView>(\n    request: &R,\n) -> Result<EncodedOrdinaryWalletPlanRequest, OrdinaryWalletPlanWireError> {\n"
                "    let facts = validate_structural_view(request)?;",
                "fn encode_view<R: RequestView>(\n    request: &R,\n) -> Result<EncodedOrdinaryWalletPlanRequest, OrdinaryWalletPlanWireError> {\n"
                '    eprintln!("source epoch: {:?}", request.source_epoch());\n'
                "    let facts = validate_structural_view(request)?;",
            ),
            "log-source-revision": (
                "fn reencode_view<R: RequestView>(\n    request: &R,\n) -> Result<EncodedOrdinaryWalletPlanRequest, OrdinaryWalletPlanWireError> {",
                "fn reencode_view<R: RequestView>(\n    request: &R,\n) -> Result<EncodedOrdinaryWalletPlanRequest, OrdinaryWalletPlanWireError> {\n"
                '    println!("source revision: {}", request.source_revision());',
            ),
            "debug-address": (
                "    for destination in &self.destinations {\n            let address_text =",
                "    for destination in &self.destinations {\n            dbg!(&destination.address);\n            let address_text =",
            ),
            "print-amount": (
                "    let facts = validate_structural_view(request)?;\n    validate_plan_view(request)?;",
                '    print!("amount: {}", request.explicit_fee_value());\n'
                "    let facts = validate_structural_view(request)?;\n    validate_plan_view(request)?;",
            ),
            "format-frame": (
                ") -> Result<HeaderFacts, OrdinaryWalletPlanWireError> {\n    if !is_nonzero(expected_source_epoch)",
                ") -> Result<HeaderFacts, OrdinaryWalletPlanWireError> {\n"
                '    let _disclosure = format!("frame: {frame:?}");\n'
                "    if !is_nonzero(expected_source_epoch)",
            ),
            "write-frame": (
                ") -> Result<HeaderFacts, OrdinaryWalletPlanWireError> {\n    if !is_nonzero(expected_source_epoch)",
                ") -> Result<HeaderFacts, OrdinaryWalletPlanWireError> {\n"
                "    use core::fmt::Write as _;\n"
                "    let mut disclosure = String::new();\n"
                '    let _ = write!(&mut disclosure, "frame: {frame:?}");\n'
                "    if !is_nonzero(expected_source_epoch)",
            ),
            "writeln-address": (
                "    for destination in &self.destinations {\n            let address_text =",
                "    for destination in &self.destinations {\n"
                "            use core::fmt::Write as _;\n"
                "            let mut disclosure = String::new();\n"
                '            let _ = writeln!(&mut disclosure, "address: {:?}", destination.address);\n'
                "            let address_text =",
            ),
        }
        for name, (old, new) in disclosure_mutations.items():
            mutate(
                scratch,
                name,
                lambda root, old=old, new=new: replace_once(
                    root,
                    "crates/ordinary-wallet-plan/src/lib.rs",
                    old,
                    new,
                ),
            )
        for name, syntax in {
            "macro-export": "#[macro_export]\nmacro_rules! leaked { () => {} }",
            "no-mangle": "#[unsafe(no_mangle)]\npub extern \"C\" fn leaked() {}",
            "export-name": "#[unsafe(export_name = \"leaked\")]\npub fn leaked() {}",
            "link-name": "unsafe extern \"C\" { #[link_name = \"leaked\"] fn linked(); }",
            "link-section": "#[unsafe(link_section = \"leaked\")]\nstatic LEAKED: u8 = 0;",
            "extern-block": "unsafe extern \"C\" { fn leaked(); }",
            "include": "include!(\"leaked.rs\");",
        }.items():
            mutate(scratch, name, lambda root, syntax=syntax: append_lib(root, f"\n{syntax}\n"))
        for name, syntax in {
            "process": "fn leaked() { let _ = std::process::id(); }",
            "environment": "fn leaked() { let _ = std::env::vars(); }",
            "thread": "fn leaked() { std::thread::yield_now(); }",
            "clock": "fn leaked() { let _ = std::time::Instant::now(); }",
            "std-alias": "use std as leaked_std;",
        }.items():
            mutate(scratch, name, lambda root, syntax=syntax: append_lib(root, f"\n{syntax}\n"))
        for name, syntax in {
            "comment-separated-process": "fn leaked() { let _ = std/**/::process::id(); }",
            "comment-separated-filesystem": (
                'fn leaked() { let _ = std/**/::fs::metadata("."); }'
            ),
            "comment-separated-network": (
                'fn leaked() { let _ = "127.0.0.1".parse::<std/**/::net::IpAddr>(); }'
            ),
        }.items():
            mutate(scratch, name, lambda root, syntax=syntax: append_lib(root, f"\n{syntax}\n"))
        for name, syntax in {
            "braced-std-root-alias": (
                "use {std as hidden_std};\n"
                "#[allow(dead_code)]\n"
                "fn leaked() -> u32 { hidden_std::process::id() }"
            ),
            "grouped-std-process-alias": (
                "use std::{process as hidden_process};\n"
                "#[allow(dead_code)]\n"
                "fn leaked() -> u32 { hidden_process::id() }"
            ),
            "nested-braced-std-fs-alias": (
                "use {std::{fs as hidden_fs}};\n"
                "#[allow(dead_code)]\n"
                "fn leaked() -> bool { hidden_fs::metadata(\".\").is_ok() }"
            ),
        }.items():
            mutate_compiling(
                scratch,
                name,
                lambda root, syntax=syntax: append_lib(root, f"\n{syntax}\n"),
            )
        stateful_atomic_mutations = {
            "module-core-atomic-state": (
                "use core::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};\n"
                "static ENCODER_STATE: AtomicU64 = AtomicU64::new(0);",
                "ENCODER_STATE.fetch_add(1, AtomicOrdering::Relaxed) & 1 != 0",
            ),
            "module-std-atomic-state": (
                "static ENCODER_STATE: std::sync::atomic::AtomicU64 = "
                "std::sync::atomic::AtomicU64::new(0);",
                "ENCODER_STATE.fetch_add(1, std::sync::atomic::Ordering::Relaxed) & 1 != 0",
            ),
            "aliased-core-atomic-state": (
                "use core::sync::atomic as hidden_atomic;\n"
                "static ENCODER_STATE: hidden_atomic::AtomicU64 = "
                "hidden_atomic::AtomicU64::new(0);",
                "ENCODER_STATE.fetch_add(1, hidden_atomic::Ordering::Relaxed) & 1 != 0",
            ),
            "macro-produced-atomic-state": (
                "macro_rules! define_encoder_state {\n"
                "    () => {\n"
                "        static ENCODER_STATE: ::core::sync::atomic::AtomicU64 = "
                "::core::sync::atomic::AtomicU64::new(0);\n"
                "    };\n"
                "}\n"
                "define_encoder_state!();",
                "ENCODER_STATE.fetch_add(1, ::core::sync::atomic::Ordering::Relaxed) & 1 != 0",
            ),
        }
        for name, (declaration, expression) in stateful_atomic_mutations.items():
            mutate_compiling(
                scratch,
                name,
                lambda root, declaration=declaration, expression=expression: (
                    add_module_stateful_encoder(root, declaration, expression)
                ),
            )
        mutate_compiling(
            scratch,
            "function-local-fq-atomic-state",
            lambda root: add_local_stateful_encoder(
                root,
                "static ENCODER_STATE: ::core::sync::atomic::AtomicU64 = "
                "::core::sync::atomic::AtomicU64::new(0);",
                "ENCODER_STATE.fetch_add(1, ::core::sync::atomic::Ordering::Relaxed) & 1 != 0",
            ),
        )
        process_global_storage_mutations = {
            "once-lock-state": (
                "static ENCODER_STATE: std::sync::OnceLock<u64> = std::sync::OnceLock::new();",
                "*ENCODER_STATE.get_or_init(|| 0) == u64::MAX",
            ),
            "lazy-lock-state": (
                "static ENCODER_STATE: std::sync::LazyLock<u64> = "
                "std::sync::LazyLock::new(|| 0);",
                "*ENCODER_STATE == u64::MAX",
            ),
            "mutex-state": (
                "static ENCODER_STATE: std::sync::Mutex<u64> = std::sync::Mutex::new(0);",
                "ENCODER_STATE.is_poisoned()",
            ),
            "rwlock-state": (
                "static ENCODER_STATE: std::sync::RwLock<u64> = std::sync::RwLock::new(0);",
                "ENCODER_STATE.is_poisoned()",
            ),
            "cell-behind-mutex-state": (
                "static ENCODER_STATE: std::sync::Mutex<core::cell::Cell<u64>> = "
                "std::sync::Mutex::new(core::cell::Cell::new(0));",
                "ENCODER_STATE.is_poisoned()",
            ),
            "unsafe-cell-behind-mutex-state": (
                "static ENCODER_STATE: std::sync::Mutex<core::cell::UnsafeCell<u64>> = "
                "std::sync::Mutex::new(core::cell::UnsafeCell::new(0));",
                "ENCODER_STATE.is_poisoned()",
            ),
        }
        for name, (declaration, expression) in process_global_storage_mutations.items():
            mutate_compiling(
                scratch,
                name,
                lambda root, declaration=declaration, expression=expression: (
                    add_module_stateful_encoder(root, declaration, expression)
                ),
            )
        mutate_compiling(
            scratch,
            "static-mut-state",
            lambda root: append_lib(
                root,
                "\n#[allow(dead_code)]\nstatic mut ENCODER_STATE: u64 = 0;\n",
            ),
        )
        mutate(
            scratch,
            "expanded-test-thread-local-state",
            lambda root: replace_once(
                root,
                "crates/ordinary-wallet-plan/src/lib.rs",
                "    static PANIC_AFTER: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };\n}",
                "    static PANIC_AFTER: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };\n"
                "    static EXTRA_AUDIT: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };\n}",
            ),
        )
        mutate_compiling(
            scratch,
            "const-and-static-literal-drift",
            lambda root: (
                append_lib(
                    root,
                    "\n// The words static mut, AtomicU64, and UnsafeCell are inert here.\n"
                    'const STATIC_WORDS_ARE_DATA: &\'static str = "static mut AtomicU64 UnsafeCell";\n'
                    "const ENCODER_STATELESS_MASK: u64 = 0;\n",
                ),
                replace_once(
                    root,
                    "crates/ordinary-wallet-plan/src/lib.rs",
                    "fn encode_view<R: RequestView>(\n"
                    "    request: &R,\n"
                    ") -> Result<EncodedOrdinaryWalletPlanRequest, OrdinaryWalletPlanWireError> {\n"
                    "    let facts = validate_structural_view(request)?;",
                    "fn encode_view<R: RequestView>(\n"
                    "    request: &R,\n"
                    ") -> Result<EncodedOrdinaryWalletPlanRequest, OrdinaryWalletPlanWireError> {\n"
                    "    if ENCODER_STATELESS_MASK == u64::MAX || STATIC_WORDS_ARE_DATA == \"\" {\n"
                    "        return Err(OrdinaryWalletPlanWireError::InvalidArgument);\n"
                    "    }\n"
                    "    let facts = validate_structural_view(request)?;",
                ),
            ),
            contains=SOURCE_DRIFT,
        )
        mutate(
            scratch,
            "comment-separated-extern",
            lambda root: (
                replace_once(
                    root,
                    "crates/ordinary-wallet-plan/src/lib.rs",
                    "#![forbid(unsafe_code)]\n",
                    "",
                ),
                append_lib(root, '\nunsafe extern/**/"C" { fn leaked(); }\n'),
            ),
        )
        mutate(
            scratch,
            "cargo-target",
            lambda root: (root / "crates/ordinary-wallet-plan/Cargo.toml").write_text(
                (root / "crates/ordinary-wallet-plan/Cargo.toml").read_text()
                + "\n[[bin]]\nname = \"escape\"\npath = \"src/lib.rs\"\n"
            ),
        )
        for name, stanza in {
            "lib-test-disabled": "test = false",
            "lib-doctest-disabled": "doctest = false",
            "lib-doc-disabled": "doc = false",
        }.items():
            mutate(
                scratch,
                name,
                lambda root, stanza=stanza: replace_once(
                    root,
                    "crates/ordinary-wallet-plan/Cargo.toml",
                    '[lib]\ncrate-type = ["rlib"]',
                    f'[lib]\ncrate-type = ["rlib"]\n{stanza}',
                ),
            )
        mutate(
            scratch,
            "explicit-integration-test-disabled",
            lambda root: (
                root / "crates/ordinary-wallet-plan/Cargo.toml"
            ).write_text(
                (root / "crates/ordinary-wallet-plan/Cargo.toml").read_text()
                + '\n[[test]]\nname = "preparation"\npath = "tests/preparation.rs"\ntest = false\n'
            ),
        )
        mutate_compiling(
            scratch,
            "quoted-whitespace-test-harness-disabled",
            lambda root: (
                (root / "crates/ordinary-wallet-plan/tests/preparation.rs").write_text(
                    "fn main() {}\n"
                ),
                (root / "crates/ordinary-wallet-plan/Cargo.toml").write_text(
                    (root / "crates/ordinary-wallet-plan/Cargo.toml").read_text()
                    + '\n[[   "test"   ]]\n"name" = "preparation"\n'
                    '"path" = "tests/preparation.rs"\n"harness" = false\n'
                ),
            ),
            integration_test=True,
        )
        mutate_compiling(
            scratch,
            "inline-quoted-lib-test-disabled",
            replace_lib_with_inline_table,
        )
        mutate(
            scratch,
            "lib-harness-disabled",
            lambda root: replace_once(
                root,
                "crates/ordinary-wallet-plan/Cargo.toml",
                '[lib]\ncrate-type = ["rlib"]',
                '[lib]\ncrate-type = ["rlib"]\nharness = false',
            ),
        )
        mutate(
            scratch,
            "lib-harness-explicit",
            lambda root: replace_once(
                root,
                "crates/ordinary-wallet-plan/Cargo.toml",
                '[lib]\ncrate-type = ["rlib"]',
                '[lib]\ncrate-type = ["rlib"]\nharness = true',
            ),
        )
        mutate(
            scratch,
            "lib-crate-types-expanded",
            lambda root: replace_once(
                root,
                "crates/ordinary-wallet-plan/Cargo.toml",
                'crate-type = ["rlib"]',
                'crate-type = ["rlib", "staticlib"]',
            ),
        )
        mutate(
            scratch,
            "integration-required-features",
            lambda root: (
                root / "crates/ordinary-wallet-plan/Cargo.toml"
            ).write_text(
                (root / "crates/ordinary-wallet-plan/Cargo.toml").read_text()
                + '\n[features]\nmutated = []\n\n[[test]]\nname = "preparation"\n'
                'path = "tests/preparation.rs"\nrequired-features = ["mutated"]\n'
            ),
        )
        mutate(
            scratch,
            "composition-dependency-removed",
            lambda root: replace_once(
                root,
                "crates/ordinary-wallet-plan/Cargo.toml",
                'wasabi-liquid-native-ordinary-wallet-pset = { path = "../ordinary-wallet-pset" }\n',
                "",
            ),
        )
        mutate(
            scratch,
            "opening-test-dependency-removed",
            lambda root: replace_once(
                root,
                "crates/ordinary-wallet-plan/Cargo.toml",
                'wasabi-liquid-native-output-opening = { path = "../output-opening" }\n',
                "",
            ),
        )
        for name, item, source in [
            ("pset-spendable-input", "SpendableInput", "\nfn leaked(_: Option<SpendableInput>) {}\n"),
            (
                "pset-prepared-owner",
                "PreparedOrdinaryPset",
                "\nfn leaked(_: Option<PreparedOrdinaryPset>) {}\n",
            ),
            (
                "pset-constructor",
                "prepare_ordinary_pset",
                "\nfn leaked() { let _ = prepare_ordinary_pset; }\n",
            ),
            (
                "pset-signed-owner",
                "SignedOrdinaryPset",
                "\nfn leaked(_: Option<SignedOrdinaryPset>) {}\n",
            ),
            (
                "pset-public-map-access",
                "PreparedOrdinaryPset",
                "\nfn leaked(value: &PreparedOrdinaryPset) { let _ = value.as_pset(); }\n",
            ),
            (
                "pset-other-error-item",
                "ExplicitFeeError",
                "\nfn leaked(_: Option<ExplicitFeeError>) {}\n",
            ),
        ]:
            mutate(
                scratch,
                name,
                lambda root, item=item, source=source: add_ordinary_pset_capability(
                    root, item, source
                ),
            )
        mutate_compiling(
            scratch,
            "pset-direct-blinded-map-accessor",
            lambda root: append_lib(
                root,
                "\n/// Test-only mutation exposing the returned sensitive PSET map.\n"
                "pub const fn leaked_direct_pset_map(\n"
                "    value: &BlindedOrdinaryPset,\n"
                ") -> &elements::pset::PartiallySignedTransaction {\n"
                "    value.as_pset()\n"
                "}\n",
            ),
        )
        mutate_compiling(
            scratch,
            "composition-call-aliased",
            lambda root: (
                replace_once(
                    root,
                    "crates/ordinary-wallet-plan/src/lib.rs",
                    "    OrdinaryWalletPsetError, OrdinaryWalletTransactionFailure, build_blinded_ordinary_wallet_pset,\n",
                    "    OrdinaryWalletPsetError, OrdinaryWalletTransactionFailure, build_blinded_ordinary_wallet_pset as compose_pset,\n",
                ),
                replace_once(
                    root,
                    "crates/ordinary-wallet-plan/src/lib.rs",
                    "        build_blinded_ordinary_wallet_pset(\n",
                    "        compose_pset(\n",
                ),
            ),
        )
        mutate_compiling(
            scratch,
            "finalized-composition-call-aliased",
            lambda root: (
                replace_once(
                    root,
                    "crates/ordinary-wallet-plan/src/lib.rs",
                    "    build_sign_and_finalize_ordinary_wallet_transaction,\n",
                    "    build_sign_and_finalize_ordinary_wallet_transaction as finalize_transaction,\n",
                ),
                replace_once(
                    root,
                    "crates/ordinary-wallet-plan/src/lib.rs",
                    "        build_sign_and_finalize_ordinary_wallet_transaction(\n",
                    "        finalize_transaction(\n",
                ),
            ),
        )
        mutate_compiling(
            scratch,
            "composition-return-type-aliased",
            lambda root: (
                replace_once(
                    root,
                    "crates/ordinary-wallet-plan/src/lib.rs",
                    "/// A linear request that completed all public preparation.\n",
                    "/// Test-only mutation replacing the exact composition result type.\n"
                    "pub type ComposedOrdinaryWalletPset = BlindedOrdinaryPset;\n\n"
                    "/// A linear request that completed all public preparation.\n",
                ),
                replace_once(
                    root,
                    "crates/ordinary-wallet-plan/src/lib.rs",
                    ") -> Result<BlindedOrdinaryPset, OrdinaryWalletPsetError>\n",
                    ") -> Result<ComposedOrdinaryWalletPset, OrdinaryWalletPsetError>\n",
                ),
            ),
        )
        mutate_compiling(
            scratch,
            "finalized-composition-return-type-aliased",
            lambda root: (
                replace_once(
                    root,
                    "crates/ordinary-wallet-plan/src/lib.rs",
                    "/// A linear request that completed all public preparation.\n",
                    "/// Test-only mutation replacing the exact finalized result type.\n"
                    "pub type ComposedFinalizedTransaction = FinalizedOrdinaryTransaction;\n\n"
                    "/// A linear request that completed all public preparation.\n",
                ),
                replace_once(
                    root,
                    "crates/ordinary-wallet-plan/src/lib.rs",
                    ") -> Result<FinalizedOrdinaryTransaction, OrdinaryWalletTransactionFailure>\n",
                    ") -> Result<ComposedFinalizedTransaction, OrdinaryWalletTransactionFailure>\n",
                ),
            ),
        )
        mutate_compiling(
            scratch,
            "signer-trait-extra-use",
            lambda root: append_lib(
                root,
                "\n#[allow(dead_code)]\nfn leaked_signer_use<S: OrdinaryP2wpkhSigner>() {}\n",
            ),
        )
        mutate_compiling(
            scratch,
            "direct-signing-bypasses-finalized-orchestration",
            lambda root: append_lib(
                root,
                "\n#[allow(dead_code)]\n"
                "fn leaked_direct_sign<S: OrdinaryP2wpkhSigner>(\n"
                "    value: BlindedOrdinaryPset,\n"
                "    signer: &mut S,\n"
                ") {\n"
                "    let _ = value.sign_and_finalize(&Secp256k1::new(), signer);\n"
                "}\n",
            ),
        )
        mutate_compiling(
            scratch,
            "raw-signing-key-capability",
            lambda root: (
                replace_once(
                    root,
                    "crates/ordinary-wallet-plan/src/lib.rs",
                    "use elements::secp256k1_zkp::{All, Secp256k1};",
                    "use elements::secp256k1_zkp::{All, Secp256k1, SecretKey};",
                ),
                append_lib(
                    root,
                    "\n#[allow(dead_code)]\nfn leaked_raw_key(_: Option<SecretKey>) {}\n",
                ),
            ),
        )
        mutate(
            scratch,
            "wallet-facts-observation-function",
            lambda root: add_wallet_facts_capability(
                root,
                "observe_owned_outputs",
                "\nfn leaked() { let _ = observe_owned_outputs; }\n",
            ),
        )
        mutate(
            scratch,
            "pset-fully-qualified-item",
            lambda root: append_lib(
                root,
                "\nconst LEAKED_LIMIT: usize = "
                "wasabi_liquid_native_ordinary_pset::MAX_ORDINARY_INPUTS;\n",
            ),
        )
        for name, item, source in [
            (
                "wallet-facts-slip77",
                "BorrowedSlip77",
                "\n#[allow(dead_code)]\nfn leaked(_: Option<BorrowedSlip77<'_>>) {}\n",
            ),
            (
                "wallet-facts-candidate-batch",
                "CandidateBatch",
                "\n#[allow(dead_code)]\nfn leaked(_: Option<CandidateBatch>) {}\n",
            ),
        ]:
            mutate_compiling(
                scratch,
                name,
                lambda root, item=item, source=source: add_wallet_facts_capability(
                    root, item, source
                ),
            )
        mutate_compiling(
            scratch,
            "wallet-facts-opening-provider-aliased",
            lambda root: (
                replace_once(
                    root,
                    "crates/ordinary-wallet-plan/src/lib.rs",
                    "    SelectedOutputOpeningProvider, prepare_selected_owned_inputs,\n",
                    "    SelectedOutputOpeningProvider as OpeningProvider, prepare_selected_owned_inputs,\n",
                ),
                replace_exact_count(
                    root,
                    "crates/ordinary-wallet-plan/src/lib.rs",
                    "        P: SelectedOutputOpeningProvider + ?Sized,\n",
                    "        P: OpeningProvider + ?Sized,\n",
                    2,
                ),
            ),
        )
        mutate_compiling(
            scratch,
            "wallet-facts-braced-alias",
            lambda root: append_lib(
                root,
                "\nuse {wasabi_liquid_native_wallet_facts::DescriptorCatalog as HiddenCatalog};\n"
                "#[allow(dead_code)]\nfn leaked(_: &HiddenCatalog) {}\n",
            ),
        )
        mutate_compiling(
            scratch,
            "wallet-facts-fully-qualified-sensitive-type",
            lambda root: append_lib(
                root,
                "\nconst _: usize = core::mem::size_of::<"
                "wasabi_liquid_native_wallet_facts::CandidateBatch>();\n",
            ),
        )
        mutate_compiling(
            scratch,
            "wallet-facts-unapproved-method",
            lambda root: replace_once(
                root,
                "crates/ordinary-wallet-plan/src/lib.rs",
                "        if catalog.network() != context.descriptor_network {",
                "        let _ = catalog.script_count();\n"
                "        if catalog.network() != context.descriptor_network {",
            ),
        )
        mutate_compiling(
            scratch,
            "address-unapproved-item",
            lambda root: (
                replace_once(
                    root,
                    "crates/ordinary-wallet-plan/src/lib.rs",
                    "use wasabi_liquid_native_address::{ConfidentialLiquidAddress, LiquidAddressProfile};",
                    "use wasabi_liquid_native_address::{"
                    "ConfidentialLiquidAddress, LiquidAddressError, LiquidAddressProfile};",
                ),
                append_lib(
                    root,
                    "\n#[allow(dead_code)]\nfn leaked(_: Option<LiquidAddressError>) {}\n",
                ),
            ),
        )
        mutate_compiling(
            scratch,
            "elements-fully-qualified-item",
            lambda root: append_lib(
                root,
                "\nconst _: usize = core::mem::size_of::<elements::Transaction>();\n",
            ),
        )
        mutate_compiling(
            scratch,
            "zeroize-unapproved-item",
            lambda root: (
                replace_once(
                    root,
                    "crates/ordinary-wallet-plan/src/lib.rs",
                    "use zeroize::Zeroize;",
                    "use zeroize::{DefaultIsZeroes, Zeroize};",
                ),
                append_lib(
                    root,
                    "\n#[allow(dead_code)]\nfn leaked<T: DefaultIsZeroes>(_: &T) {}\n",
                ),
            ),
        )
        mutate_compiling(
            scratch,
            "dependency-long-visibility-reexport",
            lambda root: replace_once(
                root,
                "crates/ordinary-wallet-plan/src/reader.rs",
                "use zeroize::Zeroize;",
                "pub(in crate::reader) use zeroize::Zeroize;",
            ),
        )
        for name, rust_source, expected in [
            ("comment-separated-include", True, "external-include.rs"),
            ("external-non-rs-include", False, "external-payload.bin"),
        ]:
            included = copy_root(scratch, name)
            inputs = add_external_include(included, rust_source=rust_source)
            if expected not in inputs:
                raise AssertionError(f"compiler inputs did not expose {expected}: {inputs}")
            run_checker(included, success=False)
        mutate(scratch, "ninth-error-with-code-and-display", add_ninth_error)
        for name, implementation in {
            "owner-as-ref": """
impl AsRef<[u8]> for EncodedOrdinaryWalletPlanRequest {
    fn as_ref(&self) -> &[u8] { &self.bytes }
}
""",
            "owner-deref": """
impl core::ops::Deref for EncodedOrdinaryWalletPlanRequest {
    type Target = [u8];
    fn deref(&self) -> &Self::Target { &self.bytes }
}
""",
            "owner-from": """
impl From<Vec<u8>> for EncodedOrdinaryWalletPlanRequest {
    fn from(bytes: Vec<u8>) -> Self { Self { bytes } }
}
""",
            "owner-borrow": """
impl core::borrow::Borrow<[u8]> for EncodedOrdinaryWalletPlanRequest {
    fn borrow(&self) -> &[u8] { &self.bytes }
}
""",
        }.items():
            mutate(
                scratch,
                name,
                lambda root, implementation=implementation: append_lib(root, implementation),
            )
        mutate(
            scratch,
            "multiline-public-parameter",
            lambda root: replace_once(
                root,
                "crates/ordinary-wallet-plan/src/lib.rs",
                "        expected_output_index: u32,\n        expected_asset:",
                "        expected_output_index: core::primitive::u32,\n        expected_asset:",
            ),
        )
        mutate(
            scratch,
            "multiline-public-return",
            lambda root: replace_once(
                root,
                "crates/ordinary-wallet-plan/src/lib.rs",
                "    ) -> Result<EncodedOrdinaryWalletPlanRequest, OrdinaryWalletPlanWireError> {\n        reencode_view(self)\n",
                "    ) -> core::result::Result<EncodedOrdinaryWalletPlanRequest, OrdinaryWalletPlanWireError> {\n"
                "        reencode_view(self)\n",
            ),
        )
        mutate(
            scratch,
            "indented-trait-impl",
            lambda root: replace_once(
                root,
                "crates/ordinary-wallet-plan/src/lib.rs",
                "impl std::error::Error for OrdinaryWalletPlanWireError {}",
                "    impl std::error::Error for OrdinaryWalletPlanWireError {}",
            ),
        )
        mutate(
            scratch,
            "remove-forbid-and-add-unsafe-impl",
            lambda root: (
                replace_once(
                    root,
                    "crates/ordinary-wallet-plan/src/lib.rs",
                    "#![forbid(unsafe_code)]\n",
                    "",
                ),
                append_lib(
                    root,
                    "\nunsafe trait LeakedUnsafe {}\n"
                    "unsafe impl LeakedUnsafe for EncodedOrdinaryWalletPlanRequest {}\n",
                ),
            ),
        )
        external = copy_root(scratch, "external-path-disclosure")
        add_external_disclosure_module(external)
        closure = compiled_sources(external)
        if closure == (
            "src/lib.rs",
            "src/reader.rs",
            "src/writer.rs",
        ) or "external-disclosure.rs" not in closure:
            raise AssertionError("compiler source closure did not expose external path module")
        external_source = (external / "external-disclosure.rs").read_text()
        if not all(
            capability in external_source
            for capability in ("std::process", "std::fs", "std::net")
        ):
            raise AssertionError("external source closure mutation lost its capabilities")
        run_checker(external, success=False)
        mutate_compiling(
            scratch,
            "explicit-fee-zeroize-noop",
            lambda root: replace_once(
                root,
                "crates/ordinary-pset/src/lib.rs",
                "impl Zeroize for ExplicitFee {\n    fn zeroize(&mut self) {\n        self.asset = AssetId::from_byte_array([0; 32]);\n        self.value.zeroize();\n    }\n}",
                "impl Zeroize for ExplicitFee {\n    fn zeroize(&mut self) {}\n}",
            ),
            contains=AUTHORITY_DRIFT,
        )
        mutate(
            scratch,
            "staged-fee-zeroize-noop",
            lambda root: replace_once(
                root,
                "crates/ordinary-wallet-plan/src/lib.rs",
                "impl Drop for StagedFee {\n    fn drop(&mut self) {\n        self.value.zeroize();",
                "impl Drop for StagedFee {\n    fn drop(&mut self) {",
            ),
        )
        mutate(
            scratch,
            "fee-transfer-zeroize-noop",
            lambda root: replace_once(
                root,
                "crates/ordinary-wallet-plan/src/lib.rs",
                "        self.value.zeroize();\n        #[cfg(test)]\n        note_zeroized_drop(DropKind::FeeTransfer",
                "        #[cfg(test)]\n        note_zeroized_drop(DropKind::FeeTransfer",
            ),
        )
        mutate(
            scratch,
            "prepared-fee-transfer-clear-noop",
            lambda root: replace_once(
                root,
                "crates/ordinary-wallet-plan/src/lib.rs",
                "        self.value.zeroize();\n"
                "        #[cfg(test)]\n"
                "        note_zeroized_drop(DropKind::PreparedFeeTransferClear, self.is_zeroized());\n",
                "        #[cfg(test)]\n"
                "        note_zeroized_drop(DropKind::PreparedFeeTransferClear, self.is_zeroized());\n",
            ),
        )
        mutate(
            scratch,
            "prepared-fee-transfer-clear-audit-removed",
            lambda root: replace_once(
                root,
                "crates/ordinary-wallet-plan/src/lib.rs",
                "        #[cfg(test)]\n"
                "        note_zeroized_drop(DropKind::PreparedFeeTransferClear, self.is_zeroized());\n",
                "",
            ),
        )
        mutate(
            scratch,
            "prepared-fee-zeroize-noop",
            lambda root: replace_once(
                root,
                "crates/ordinary-wallet-plan/src/lib.rs",
                "    fn zeroize(&mut self) {\n        self.value.zeroize();\n    }",
                "    fn zeroize(&mut self) {}",
            ),
        )
        mutate(
            scratch,
            "composition-transfer-hook-before-fee-clear",
            lambda root: replace_once(
                root,
                "crates/ordinary-wallet-plan/src/lib.rs",
                "        let fee = self.fee.transfer();\n"
                "        #[cfg(test)]\n"
                "        maybe_panic_at(StagingPoint::PreparedCompositionTransfer);\n",
                "        #[cfg(test)]\n"
                "        maybe_panic_at(StagingPoint::PreparedCompositionTransfer);\n"
                "        let fee = self.fee.transfer();\n",
            ),
        )
        mutate(
            scratch,
            "finalized-transfer-hook-before-fee-clear",
            lambda root: replace_once(
                root,
                "crates/ordinary-wallet-plan/src/lib.rs",
                "        let fee = self.fee.transfer();\n"
                "        #[cfg(test)]\n"
                "        maybe_panic_at(StagingPoint::PreparedFinalizationTransfer);\n",
                "        #[cfg(test)]\n"
                "        maybe_panic_at(StagingPoint::PreparedFinalizationTransfer);\n"
                "        let fee = self.fee.transfer();\n",
            ),
        )
        mutate_compiling(
            scratch,
            "signing-failure-drops-retry-capability",
            lambda root: replace_once(
                root,
                "crates/ordinary-wallet-pset/src/lib.rs",
                "            retryable_blinded: Some(Box::new(blinded)),",
                "            retryable_blinded: { core::mem::drop(blinded); None },",
            ),
            contains="ordinary-wallet plan reviewed authority-critical dependency region changed",
        )
        mutate(
            scratch,
            "blinded-pset-borrow-surface-expanded",
            lambda root: replace_once(
                root,
                "crates/ordinary-pset/src/lib.rs",
                "impl BlindedOrdinaryPset {\n",
                "impl BlindedOrdinaryPset {\n"
                "    /// Test-only mutation adding another direct sensitive-map accessor.\n"
                "    pub const fn leaked_pset_map(&self) -> &PartiallySignedTransaction {\n"
                "        &self.pset\n"
                "    }\n\n",
            ),
            contains="ordinary-wallet plan authority-critical inherent method inventory changed",
        )
        mutate(
            scratch,
            "blinded-pset-signing-surface-expanded",
            lambda root: replace_once(
                root,
                "crates/ordinary-pset/src/signing.rs",
                "impl BlindedOrdinaryPset {\n",
                "impl BlindedOrdinaryPset {\n"
                "    /// Test-only mutation expanding the returned signing capability.\n"
                "    pub const fn leaked_signing_surface(&self) {}\n\n",
            ),
            contains="ordinary-wallet plan authority-critical inherent method inventory changed",
        )
        mutate(
            scratch,
            "finalized-transaction-surface-expanded",
            lambda root: replace_once(
                root,
                "crates/ordinary-pset/src/signing.rs",
                "impl FinalizedOrdinaryTransaction {\n",
                "impl FinalizedOrdinaryTransaction {\n"
                "    /// Test-only mutation expanding finalized transaction access.\n"
                "    pub fn leaked_serialization(&self) -> Vec<u8> {\n"
                "        self.serialize_for_broadcast()\n"
                "    }\n\n",
            ),
            contains="ordinary-wallet plan reviewed authority-critical dependency region changed",
        )
        mutate(
            scratch,
            "elements-default",
            lambda root: (root / "crates/ordinary-wallet-plan/src/lib.rs").write_text(
                (root / "crates/ordinary-wallet-plan/src/lib.rs")
                .read_text()
                .replace(
                    "LiquidAddressProfile::LiquidMainnet",
                    "LiquidAddressProfile::ElementsDefault",
                    1,
                )
            ),
        )
        mutate(
            scratch,
            "third-context-arm",
            lambda root: (root / "crates/ordinary-wallet-plan/src/lib.rs").write_text(
                (root / "crates/ordinary-wallet-plan/src/lib.rs")
                .read_text()
                .replace("        _ => None,", "        _ => Some(ReviewedContext { address_profile: LiquidAddressProfile::LiquidTestnet, descriptor_network: DescriptorNetwork::Test }),", 1)
            ),
        )


if __name__ == "__main__":
    main()
