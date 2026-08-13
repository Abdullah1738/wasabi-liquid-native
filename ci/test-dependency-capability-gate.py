#!/usr/bin/env python3
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
GATE = ROOT / "ci" / "check-dependency-capabilities.sh"
REAL_CARGO = shutil.which("cargo")
CONFORMANCE_CHECKER = ROOT / "ci" / "check-wallet-facts-conformance.py"
REFERENCE = Path("contracts/wallet-facts/v1/nonlinkable-reference")


def expect_conformance(root: Path, *, success: bool) -> None:
    result = subprocess.run(
        ["python3", str(CONFORMANCE_CHECKER), str(root)],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if (result.returncode == 0) != success:
        raise AssertionError(
            f"unexpected conformance result {result.returncode}:\n"
            f"{result.stdout}{result.stderr}"
        )


def close_checksums(root: Path) -> None:
    reference = root / REFERENCE
    vectors = reference / "vectors"
    nested = []
    for path in sorted(
        (path for path in vectors.rglob("*") if path.is_file()),
        key=lambda path: path.relative_to(vectors).as_posix().encode(),
    ):
        relative = path.relative_to(vectors).as_posix()
        if relative != "SHA256SUMS":
            nested.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {relative}\n")
    (vectors / "SHA256SUMS").write_text("".join(nested))
    parent_paths = [
        "ERROR_MAPPING_V1.tsv",
        "WIRE_FORMAT_V1.md",
        "vectors/SHA256SUMS",
    ]
    (reference / "SHA256SUMS").write_text(
        "".join(
            f"{hashlib.sha256((reference / relative).read_bytes()).hexdigest()}  {relative}\n"
            for relative in parent_paths
        )
    )


def close_parent_checksum(root: Path) -> None:
    reference = root / REFERENCE
    parent_paths = [
        "ERROR_MAPPING_V1.tsv",
        "WIRE_FORMAT_V1.md",
        "vectors/SHA256SUMS",
    ]
    (reference / "SHA256SUMS").write_text(
        "".join(
            f"{hashlib.sha256((reference / relative).read_bytes()).hexdigest()}  {relative}\n"
            for relative in parent_paths
        )
    )


def mutate_conformance_copy(scratch: Path, name: str, mutation, *, reclose: bool = True) -> None:
    target = scratch / name
    (target / REFERENCE.parent).mkdir(parents=True)
    shutil.copytree(ROOT / REFERENCE, target / REFERENCE)
    mutation(target)
    if reclose:
        close_checksums(target)
    expect_conformance(target, success=False)


def reorder_first_rows(path: Path) -> None:
    lines = path.read_text().splitlines()
    path.write_text("\n".join([lines[0], lines[2], lines[1], *lines[3:]]) + "\n")


def reorder_nested_checksum(root: Path) -> None:
    path = root / REFERENCE / "vectors/SHA256SUMS"
    reorder_first_rows(path)
    close_parent_checksum(root)


def add_symlink_directory(root: Path) -> None:
    vectors = root / REFERENCE / "vectors"
    os.symlink(vectors / "frames", vectors / "linked-frames", target_is_directory=True)


def replace_vectors_root_with_symlink(root: Path) -> None:
    vectors = root / REFERENCE / "vectors"
    target = root / "vectors-root-target"
    vectors.rename(target)
    os.symlink(target, vectors, target_is_directory=True)


def swap_same_code_replay_frames(root: Path) -> None:
    path = root / REFERENCE / "vectors/CASES_V1.tsv"
    text = path.read_text()
    first = "\trequest-10-truncated-zero\t"
    second = "\trequest-11-truncated-header\t"
    text = text.replace(first, "\t__first_frame__\t", 1)
    text = text.replace(second, first, 1)
    text = text.replace("\t__first_frame__\t", second, 1)
    path.write_text(text)


def set_recipe_field(root: Path, recipe_id: str, index: int, value: str) -> None:
    path = root / REFERENCE / "vectors/RECIPES_V1.tsv"
    lines = path.read_text().splitlines()
    matches = 0
    for line_index, line in enumerate(lines):
        fields = line.split("\t")
        if fields[0] == recipe_id:
            fields[index] = value
            lines[line_index] = "\t".join(fields)
            matches += 1
    if matches != 1:
        raise AssertionError(f"recipe mutation target count: {recipe_id}")
    path.write_text("\n".join(lines) + "\n")


def set_recipe_output_value(root: Path, recipe_id: str, value: str) -> None:
    path = root / REFERENCE / "vectors/RECIPES_V1.tsv"
    lines = path.read_text().splitlines()
    matches = 0
    for line_index, line in enumerate(lines):
        fields = line.split("\t")
        if fields[0] == recipe_id:
            outputs = fields[8].split(";")
            output = outputs[0].split("/")
            output[8] = value
            outputs[0] = "/".join(output)
            fields[8] = ";".join(outputs)
            lines[line_index] = "\t".join(fields)
            matches += 1
    if matches != 1:
        raise AssertionError(f"recipe output mutation target count: {recipe_id}")
    path.write_text("\n".join(lines) + "\n")


def swap_multiasset_outputs(root: Path) -> None:
    path = root / REFERENCE / "vectors/RECIPES_V1.tsv"
    lines = path.read_text().splitlines()
    matches = 0
    for line_index, line in enumerate(lines):
        fields = line.split("\t")
        if fields[0] == "multi-asset-accepted-response-source":
            outputs = fields[8].split(";")
            if len(outputs) != 2:
                raise AssertionError("multiasset output count")
            fields[8] = ";".join(reversed(outputs))
            lines[line_index] = "\t".join(fields)
            matches += 1
    if matches != 1:
        raise AssertionError("multiasset recipe mutation target count")
    path.write_text("\n".join(lines) + "\n")


def focused_replay_is_exact(gate: str) -> bool:
    unfolded = gate.replace("\\\n", " ")
    normalized = [
        " ".join(line.strip().split()).replace('run_sealed "$compiler_cargo_bin"', "cargo", 1)
        for line in unfolded.splitlines()
    ]
    expected = (
        "cargo test -p wasabi-liquid-native-wallet-facts-wire "
        "--locked --offline conformance"
    )
    return normalized.count(expected) == 1


def test_conformance_checker(scratch: Path) -> None:
    valid = scratch / "conformance-valid"
    (valid / REFERENCE.parent).mkdir(parents=True)
    shutil.copytree(ROOT / REFERENCE, valid / REFERENCE)
    expect_conformance(valid, success=True)

    vectors = REFERENCE / "vectors"
    frame = vectors / "frames/request-00-base-empty.hex"

    mutate_conformance_copy(
        scratch,
        "conformance-frame-content",
        lambda root: (root / frame).write_text((root / frame).read_text()[:-2] + "0\n"),
    )
    mutate_conformance_copy(
        scratch,
        "conformance-orphan-frame-file",
        lambda root: (root / vectors / "frames/orphan.hex").write_text("00\n"),
    )
    mutate_conformance_copy(
        scratch,
        "conformance-missing-frame-file",
        lambda root: (root / frame).unlink(),
    )
    mutate_conformance_copy(
        scratch,
        "conformance-expected-code",
        lambda root: (root / vectors / "CASES_V1.tsv").write_text(
            (root / vectors / "CASES_V1.tsv").read_text().replace(
                "request-10-truncated-zero-decode\trequest-10-truncated-zero\trequest-decode\t-\terror\t3\tno",
                "request-10-truncated-zero-decode\trequest-10-truncated-zero\trequest-decode\t-\terror\t2\tno",
            )
        ),
    )
    mutate_conformance_copy(
        scratch,
        "conformance-canonical-reencode",
        lambda root: (root / vectors / "CASES_V1.tsv").write_text(
            (root / vectors / "CASES_V1.tsv").read_text().replace(
                "request-empty-decode\trequest-00-base-empty\trequest-decode\t-\tok\t0\tyes\n",
                "request-empty-decode\trequest-00-base-empty\trequest-decode\t-\tok\t0\tno\n",
                1,
            )
        ),
    )
    mutate_conformance_copy(
        scratch,
        "conformance-same-code-frame-swap",
        swap_same_code_replay_frames,
    )
    mutate_conformance_copy(
        scratch,
        "conformance-response-epoch-relabel",
        lambda root: (root / vectors / "CASES_V1.tsv").write_text(
            (root / vectors / "CASES_V1.tsv").read_text().replace(
                "response-00-base-empty-a-decode\tresponse-00-base-empty-a\tresponse-decode\t"
                + "41" * 32
                + "\tok\t0\tno\n",
                "response-00-base-empty-a-decode\tresponse-00-base-empty-a\tresponse-decode\t"
                + "42" * 32
                + "\tok\t0\tno\n",
                1,
            )
        ),
    )
    mutate_conformance_copy(
        scratch,
        "conformance-backslash-frame-path",
        lambda root: (root / vectors / "FRAMES_V1.tsv").write_text(
            (root / vectors / "FRAMES_V1.tsv").read_text().replace(
                "frames/request-00-base-empty.hex",
                "frames/request-00-base\\-empty.hex",
                1,
            )
        ),
    )
    mutate_conformance_copy(
        scratch,
        "conformance-wrong-decoded-sha",
        lambda root: (root / vectors / "FRAMES_V1.tsv").write_text(
            (root / vectors / "FRAMES_V1.tsv").read_text().replace(
                "ebdf2cc9fc516e9034d30faf5b8fe3e2d56957f5963d7776ddd6aa04c1003682",
                "0" * 64,
                1,
            )
        ),
    )
    mutate_conformance_copy(
        scratch,
        "conformance-operation",
        lambda root: (root / vectors / "CASES_V1.tsv").write_text(
            (root / vectors / "CASES_V1.tsv").read_text().replace(
                "request-empty-decode\trequest-00-base-empty\trequest-decode",
                "request-empty-decode\trequest-00-base-empty\tresponse-decode",
            )
        ),
    )
    mutate_conformance_copy(
        scratch,
        "conformance-recipe-relabel",
        lambda root: (root / vectors / "RECIPES_V1.tsv").write_text(
            (root / vectors / "RECIPES_V1.tsv").read_text().replace(
                "accepted-empty-a-response", "accepted-spend-only-response", 1
            )
        ),
    )
    mutate_conformance_copy(
        scratch,
        "conformance-empty-candidate-transaction-text",
        lambda root: (root / vectors / "RECIPES_V1.tsv").write_text(
            (root / vectors / "RECIPES_V1.tsv").read_text().replace(
                "\t_:-\t-\t-\tcandidate-transaction-empty\n",
                "\t:-\t-\t-\tcandidate-transaction-empty\n",
                1,
            )
        ),
    )
    mutate_conformance_copy(
        scratch,
        "conformance-candidate-derivation-precedence",
        lambda root: set_recipe_field(root, "candidate-rejected-request", 4, "100001"),
    )
    mutate_conformance_copy(
        scratch,
        "conformance-recipe-over-u32",
        lambda root: set_recipe_field(root, "candidate-rejected-request", 4, "4294967296"),
    )
    mutate_conformance_copy(
        scratch,
        "conformance-recipe-over-u64",
        lambda root: set_recipe_output_value(
            root,
            "orphan-output-response-source",
            "18446744073709551616",
        ),
    )
    mutate_conformance_copy(
        scratch,
        "conformance-multiasset-output-order",
        swap_multiasset_outputs,
    )
    mutate_conformance_copy(
        scratch,
        "conformance-api-operation-relabel",
        lambda root: (root / vectors / "API_CASES_V1.tsv").write_text(
            (root / vectors / "API_CASES_V1.tsv").read_text().replace(
                "api-zero-input-transaction\tresponse-source-validation\t",
                "api-zero-input-transaction\tresponse-encode\t",
                1,
            )
        ),
    )
    mutate_conformance_copy(
        scratch,
        "conformance-boundary-relabel",
        lambda root: (root / vectors / "BOUNDARIES_V1.tsv").write_text(
            (root / vectors / "BOUNDARIES_V1.tsv").read_text().replace(
                "aggregate-inputs-maximum\tresponse-decode\t",
                "aggregate-inputs-maximum\trequest-decode\t",
                1,
            )
        ),
    )
    mutate_conformance_copy(
        scratch,
        "conformance-constant-map-relabel",
        lambda root: (root / vectors / "CORPUS_V1.md").write_text(
            (root / vectors / "CORPUS_V1.md").read_text().replace(
                "| max-aggregate-inputs | MAX_AGGREGATE_INPUTS | Aggregate observed inputs |",
                "| max-aggregate-inputs | MAX_AGGREGATE_OWNED_OUTPUTS | Aggregate observed inputs |",
                1,
            )
        ),
    )
    mutate_conformance_copy(
        scratch,
        "conformance-duplicate-row",
        lambda root: (root / vectors / "API_CASES_V1.tsv").write_text(
            (root / vectors / "API_CASES_V1.tsv").read_text()
            + (root / vectors / "API_CASES_V1.tsv").read_text().splitlines()[1]
            + "\n"
        ),
    )
    mutate_conformance_copy(
        scratch,
        "conformance-reordered-tsv",
        lambda root: reorder_first_rows(root / vectors / "CASES_V1.tsv"),
    )
    mutate_conformance_copy(
        scratch,
        "conformance-omitted-case",
        lambda root: (root / vectors / "CASES_V1.tsv").write_text(
            "\n".join(
                line
                for line in (root / vectors / "CASES_V1.tsv").read_text().splitlines()
                if not line.startswith("request-10-truncated-zero-decode\t")
            )
            + "\n"
        ),
    )
    mutate_conformance_copy(
        scratch,
        "conformance-path-traversal",
        lambda root: (root / vectors / "FRAMES_V1.tsv").write_text(
            (root / vectors / "FRAMES_V1.tsv").read_text().replace(
                "frames/request-00-base-empty.hex", "frames/../request-00-base-empty.hex", 1
            )
        ),
    )
    mutate_conformance_copy(
        scratch,
        "conformance-wrong-length",
        lambda root: (root / vectors / "FRAMES_V1.tsv").write_text(
            (root / vectors / "FRAMES_V1.tsv").read_text().replace(
                "request-00-base-empty\trequest\tframes/request-00-base-empty.hex\t232\t",
                "request-00-base-empty\trequest\tframes/request-00-base-empty.hex\t233\t",
            )
        ),
    )
    mutate_conformance_copy(
        scratch,
        "conformance-identity",
        lambda root: (root / vectors / "CORPUS_V1.md").write_text(
            (root / vectors / "CORPUS_V1.md").read_text().replace(
                "Wire version: 1\n", "Wire version: 1\nWire version: 1\n"
            )
        ),
    )
    mutate_conformance_copy(
        scratch,
        "conformance-extra-file",
        lambda root: (root / vectors / "extra.txt").write_text("extra\n"),
        reclose=False,
    )
    mutate_conformance_copy(
        scratch,
        "conformance-parent-extra-file",
        lambda root: (root / REFERENCE / "extra.txt").write_text("extra\n"),
    )
    mutate_conformance_copy(
        scratch,
        "conformance-vectors-root-symlink",
        replace_vectors_root_with_symlink,
        reclose=False,
    )
    mutate_conformance_copy(
        scratch,
        "conformance-malformed-checksum",
        lambda root: (root / vectors / "SHA256SUMS").write_text("invalid\n"),
        reclose=False,
    )
    mutate_conformance_copy(
        scratch,
        "conformance-reordered-checksum",
        reorder_nested_checksum,
        reclose=False,
    )
    mutate_conformance_copy(
        scratch,
        "conformance-symlink-directory",
        add_symlink_directory,
        reclose=False,
    )
    mutate_conformance_copy(
        scratch,
        "conformance-parent-drift",
        lambda root: (root / REFERENCE / "SHA256SUMS").write_text(
            (root / REFERENCE / "SHA256SUMS").read_text().replace("0", "1", 1)
        ),
        reclose=False,
    )


def expect_lock_snippet(snippet: str, root: Path, *, success: bool) -> None:
    result = subprocess.run(
        ["python3", "-", str(root)],
        input=snippet,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if (result.returncode == 0) != success:
        raise AssertionError(
            f"unexpected lock proof result {result.returncode}:\n"
            f"{result.stdout}{result.stderr}"
        )


def remove_lock_dependency(root: Path, package: str, dependency: str) -> None:
    path = root / "Cargo.lock"
    blocks = path.read_text().split("[[package]]\n")
    marker = f'name = "{package}"\n'
    indexes = [index for index, block in enumerate(blocks) if marker in block]
    entry = f' "{dependency}",\n'
    if len(indexes) != 1 or blocks[indexes[0]].count(entry) != 1:
        raise AssertionError(f"lock mutation target mismatch: {package} -> {dependency}")
    blocks[indexes[0]] = blocks[indexes[0]].replace(entry, "", 1)
    path.write_text("[[package]]\n".join(blocks))


def test_public_proof_preflight_blocks_build_script(scratch: Path) -> None:
    root = scratch / "public-proof-preflight"
    (root / "ci").mkdir(parents=True)
    shutil.copy2(ROOT / "Cargo.toml", root / "Cargo.toml")
    shutil.copy2(GATE, root / "ci/check-dependency-capabilities.sh")
    shutil.copy2(
        ROOT / "ci/check-ordinary-wallet-plan-public-proof-surface.py",
        root / "ci/check-ordinary-wallet-plan-public-proof-surface.py",
    )
    shutil.copy2(
        ROOT / "ci/test-ordinary-wallet-plan-public-proof-surface.py",
        root / "ci/test-ordinary-wallet-plan-public-proof-surface.py",
    )
    shutil.copy2(
        ROOT / "ci/test-ordinary-wallet-plan-proof-snapshot.py",
        root / "ci/test-ordinary-wallet-plan-proof-snapshot.py",
    )
    tool = Path("tools/ordinary-wallet-plan-public-proof-verifier")
    shutil.copytree(ROOT / tool, root / tool)

    sentinel = root / "cargo-or-build-script-executed"
    (root / tool / "build.rs").write_text(
        "fn main() { std::fs::write("
        + json.dumps(str(sentinel))
        + ', b"executed").unwrap(); }\n',
        encoding="utf-8",
    )
    tool_manifest = root / tool / "Cargo.toml"
    original_manifest = tool_manifest.read_text(encoding="utf-8")
    tool_manifest.write_text(
        original_manifest.replace('build = false\n', 'build = "build.rs"\n', 1),
        encoding="utf-8",
    )

    positive_control = scratch / "build-script-positive-control"
    (positive_control / "src").mkdir(parents=True)
    shutil.copy2(root / tool / "build.rs", positive_control / "build.rs")
    (positive_control / "src/lib.rs").write_text("pub fn control() {}\n", encoding="utf-8")
    (positive_control / "Cargo.toml").write_text(
        '[package]\nname = "build-script-positive-control"\nversion = "0.0.0"\n'
        'edition = "2024"\npublish = false\nbuild = "build.rs"\n\n[workspace]\n',
        encoding="utf-8",
    )
    (positive_control / "Cargo.lock").write_text(
        '# This file is automatically @generated by Cargo.\n# It is not intended for manual editing.\nversion = 4\n\n'
        '[[package]]\nname = "build-script-positive-control"\nversion = "0.0.0"\n',
        encoding="utf-8",
    )
    control_environment = os.environ.copy()
    control_environment["CARGO_TARGET_DIR"] = str(scratch / "build-script-control-target")
    control_result = subprocess.run(
        [REAL_CARGO, "build", "--locked", "--offline"],
        cwd=positive_control,
        env=control_environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if control_result.returncode != 0 or not sentinel.exists():
        raise AssertionError(
            "build-script sentinel positive control did not activate:\n"
            f"{control_result.stdout}{control_result.stderr}"
        )
    sentinel.unlink()

    mock_cargo = root / "cargo-sentinel"
    mock_cargo.write_text(
        '#!/bin/sh\nprintf executed >"$PREFLIGHT_SENTINEL"\nexit 97\n',
        encoding="utf-8",
    )
    mock_cargo.chmod(0o755)
    environment = {
        name: value
        for name, value in os.environ.items()
        if not re.search(
            r"(TOKEN|SECRET|PASSWORD|PASSPHRASE|PRIVATE_KEY|API_KEY)|^AWS_|^(GIT_ASKPASS|SSH_ASKPASS|SSH_AUTH_SOCK|SSH_AGENT_PID|HTTP_PROXY|HTTPS_PROXY|ALL_PROXY|NO_PROXY)$",
            name,
            re.IGNORECASE,
        )
    }
    result = subprocess.run(
        [str(root / "ci/check-dependency-capabilities.sh")],
        cwd=root,
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    expected_preflight = "public proof verifier source-file topology differs from exact authority"
    if result.returncode == 0 or sentinel.exists() or expected_preflight not in result.stderr:
        raise AssertionError(
            "malicious public-proof build script reached Cargo before preflight:\n"
            f"{result.stdout}{result.stderr}"
        )

    (root / tool / "build.rs").unlink()
    tool_manifest.write_text(original_manifest, encoding="utf-8")

    path_sentinel = root / "ambient-path-tool-executed"
    malicious_path = root / "malicious-path"
    malicious_path.mkdir()
    fake_env = malicious_path / "env"
    fake_env.write_text(
        '#!/bin/sh\nprintf executed >"$PATH_SENTINEL"\nexit 0\n', encoding="utf-8"
    )
    fake_env.chmod(0o755)
    environment = {
        name: value
        for name, value in os.environ.items()
        if not re.search(
            r"(TOKEN|SECRET|PASSWORD|PASSPHRASE|PRIVATE_KEY|API_KEY)|^AWS_|^(GIT_ASKPASS|SSH_ASKPASS|SSH_AUTH_SOCK|SSH_AGENT_PID|HTTP_PROXY|HTTPS_PROXY|ALL_PROXY|NO_PROXY)$",
            name,
            re.IGNORECASE,
        )
    }
    environment.update(
        PATH=f"{malicious_path}:{environment.get('PATH', '')}",
        PATH_SENTINEL=str(path_sentinel),
        CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER=str(mock_cargo),
    )
    result = subprocess.run(
        [str(root / "ci/check-dependency-capabilities.sh")],
        cwd=root,
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if (
        result.returncode == 0
        or path_sentinel.exists()
        or "compiler or Cargo execution environment contains an unreviewed override"
        not in result.stderr
    ):
        raise AssertionError(
            "ambient PATH bypassed compiler environment rejection:\n"
            f"{result.stdout}{result.stderr}"
        )

    for variable in (
        "CARGO",
        "cargo_build_rustc_workspace_wrapper",
        "RuStFlAgS",
        "BASH_ENV",
        "MAKEFLAGS",
        "GIT_CONFIG_COUNT",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_ASKPASS",
        "SSH_ASKPASS",
        "SSH_AUTH_SOCK",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "GITHUB_TOKEN",
        "CARGO_REGISTRY_TOKEN",
        "DEVELOPER_DIR",
        "COMPILER_PATH",
        "GcC_ExEc_PrEfIx",
        "CPATH",
        "C_INCLUDE_PATH",
        "CPLUS_INCLUDE_PATH",
        "LIBRARY_PATH",
        "ClAnG_CoNfIg_FiLe_UsEr_DiR",
        "LD_LIBRARY_PATH",
        "Ld_PrElOaD",
        "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER",
        "CARGO_ENCODED_RUSTFLAGS",
        "CARGO_PROFILE_RELEASE_INCREMENTAL",
        "CARGO_TARGET_AARCH64_APPLE_DARWIN_LINKER",
        "RUSTC",
        "RUSTC_WRAPPER",
        "RUSTDOC",
        "RUSTDOCFLAGS",
        "RUSTFLAGS",
        "RUSTUP_HOME",
        "RUSTUP_TOOLCHAIN",
        "CC",
        "CXX_AARCH64_APPLE_DARWIN",
        "HOST_CC",
        "HOST_CFLAGS",
        "HOST",
        "TARGET",
        "TARGET_AR",
        "TARGET_ARFLAGS",
        "TARGET_CXX",
        "RANLIB",
        "RANLIBFLAGS",
        "AARCH64_APPLE_DARWIN_RANLIB",
        "AARCH64_APPLE_DARWIN_CC",
        "X86_64_UNKNOWN_LINUX_GNU_LINKER",
        "X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS",
        "AR",
        "LDFLAGS",
        "MACOSX_DEPLOYMENT_TARGET",
        "SDKROOT",
    ):
        environment = {
            name: value
            for name, value in os.environ.items()
            if not re.search(
                r"(TOKEN|SECRET|PASSWORD|PASSPHRASE|PRIVATE_KEY|API_KEY)|^AWS_|^(GIT_ASKPASS|SSH_ASKPASS|SSH_AUTH_SOCK|SSH_AGENT_PID|HTTP_PROXY|HTTPS_PROXY|ALL_PROXY|NO_PROXY)$",
                name,
                re.IGNORECASE,
            )
        }
        for name in tuple(environment):
            if name == variable:
                del environment[name]
        environment[variable] = str(mock_cargo)
        result = subprocess.run(
            [str(root / "ci/check-dependency-capabilities.sh")],
            cwd=root,
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if (
            result.returncode == 0
            or sentinel.exists()
            or "compiler or Cargo execution environment contains an unreviewed override"
            not in result.stderr
        ):
            raise AssertionError(
                f"unreviewed compiler environment was not rejected: {variable}:\n"
                f"{result.stdout}{result.stderr}"
            )


def test_gate_wiring_and_lock_proof(scratch: Path) -> None:
    gate = GATE.read_text()
    workflow = (ROOT / ".github/workflows/dependency-capabilities.yml").read_text(
        encoding="utf-8"
    )
    minimal_environment = (
        '/usr/bin/env -i HOME="$HOME" TMPDIR="$RUNNER_TEMP" '
        'PATH="$HOME/.cargo/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin"'
    )
    if (
        workflow.count(minimal_environment) != 2
        or workflow.count(minimal_environment + " ./ci/check-dependency-capabilities.sh") != 1
        or workflow.count(minimal_environment + " python3 ci/test-dependency-capability-gate.py") != 1
    ):
        raise AssertionError("CI gate processes do not use the exact minimal environment")
    if "run: cargo fetch" in workflow:
        raise AssertionError("workflow Cargo fetch bypasses tracked preflight")
    fetch_preflight = '"$python_bin" -I ci/check-cargo-fetch-preflight.py "$repository_root"'
    isolated_fetch = '/usr/bin/env -i HOME="$fetch_home" TMPDIR="$fetch_tmp" PATH="$trusted_bin"'
    fetch_git_config = (
        "GIT_CONFIG_COUNT=2 GIT_CONFIG_KEY_0=pack.writeReverseIndex "
        "GIT_CONFIG_VALUE_0=false \\\n"
        "            GIT_CONFIG_KEY_1=maintenance.auto GIT_CONFIG_VALUE_1=false"
    )
    fetch_environment = (
        '/usr/bin/env -i HOME="$fetch_home" TMPDIR="$fetch_tmp" PATH="$trusted_bin" \\\n'
        '            CARGO_HOME="$source_cargo_home" CARGO_NET_GIT_FETCH_WITH_CLI=true \\\n'
        '            GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null GIT_CONFIG_NOSYSTEM=1 \\\n'
        f"            {fetch_git_config} \\\n"
        '            GIT_TERMINAL_PROMPT=0 GIT_ASKPASS=/usr/bin/false SSH_ASKPASS=/usr/bin/false \\\n'
        '            "$compiler_cargo_bin" fetch \\\n'
        "                --manifest-path "
    )
    fetch_commands = (
        fetch_environment + '"$sealed_workspace/Cargo.toml" \\\n                --locked',
        fetch_environment + '"$proof_snapshot/Cargo.toml" \\\n                --locked',
    )

    def fetch_git_config_is_exact(candidate: str) -> bool:
        return (
            all(candidate.count(command) == 1 for command in fetch_commands)
            and candidate.count(fetch_git_config) == 2
            and candidate.count("GIT_CONFIG_COUNT=2") == 2
            and candidate.count("GIT_CONFIG_KEY_0=pack.writeReverseIndex") == 2
            and candidate.count("GIT_CONFIG_VALUE_0=false") == 2
            and candidate.count("GIT_CONFIG_KEY_1=maintenance.auto") == 2
            and candidate.count("GIT_CONFIG_VALUE_1=false") == 2
        )

    if (
        gate.count(fetch_preflight) != 1
        or gate.count(isolated_fetch) != 2
        or gate.count('"$compiler_cargo_bin" fetch \\') != 2
        or gate.count('CARGO_HOME="$source_cargo_home" CARGO_NET_GIT_FETCH_WITH_CLI=true') != 2
        or gate.count('GIT_ASKPASS=/usr/bin/false SSH_ASKPASS=/usr/bin/false') != 2
        or gate.count('credential_sentinel="$scratch/external-credential-provider-ran"') != 1
        or gate.count('credential_cargo_home="$scratch/credential-positive-cargo-home"') != 1
        or gate.count('"$compiler_cargo_bin" login --registry wlpq-positive') != 1
        or gate.count('if [ "$(cat "$credential_sentinel")" != provider-ran ]; then') != 1
        or gate.count('/bin/rm "$credential_sentinel"') != 1
        or gate.count('source_cargo_home="$scratch/source-cargo-home"') != 1
        or gate.count('for root_cargo_config in /.cargo/config /.cargo/config.toml; do') != 1
        or gate.count('[ -e "$root_cargo_config" ] || [ -L "$root_cargo_config" ]') != 1
        or not fetch_git_config_is_exact(gate)
    ):
        raise AssertionError("isolated snapshot-only Cargo fetch is not exact")
    for name, mutated_gate in {
        "removed": gate.replace(fetch_git_config, "", 1),
        "count changed": gate.replace("GIT_CONFIG_COUNT=2", "GIT_CONFIG_COUNT=3", 1),
        "key changed": gate.replace(
            "GIT_CONFIG_KEY_0=pack.writeReverseIndex",
            "GIT_CONFIG_KEY_0=pack.readReverseIndex",
            1,
        ),
        "value changed": gate.replace("GIT_CONFIG_VALUE_0=false", "GIT_CONFIG_VALUE_0=true", 1),
        "maintenance key changed": gate.replace(
            "GIT_CONFIG_KEY_1=maintenance.auto",
            "GIT_CONFIG_KEY_1=maintenance.autoDetach",
            1,
        ),
        "maintenance value changed": gate.replace(
            "GIT_CONFIG_VALUE_1=false", "GIT_CONFIG_VALUE_1=true", 1
        ),
        "duplicated": gate.replace(
            fetch_git_config,
            fetch_git_config + " " + fetch_git_config,
            1,
        ),
        "relocated to credential provider": gate.replace(
            f"            {fetch_git_config} \\\n",
            "",
            1,
        ).replace(
            "    GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null GIT_CONFIG_NOSYSTEM=1 \\\n"
            '    "$compiler_cargo_bin" login --registry wlpq-positive',
            "    GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null GIT_CONFIG_NOSYSTEM=1 \\\n"
            f"    {fetch_git_config} \\\n"
            '    "$compiler_cargo_bin" login --registry wlpq-positive',
            1,
        ),
    }.items():
        if mutated_gate == gate or fetch_git_config_is_exact(mutated_gate):
            raise AssertionError(f"isolated fetch Git config {name} mutation was accepted")
    first_fetch = gate.index('"$compiler_cargo_bin" fetch \\')
    if gate.index(fetch_preflight) > first_fetch or gate.index('    --snapshot-only \\') > first_fetch:
        raise AssertionError("tracked fetch preflight or proof snapshot follows Cargo fetch")
    copied_toolchain = gate.index('    --construct-toolchain \\')
    copied_check = gate.index('check-pinned-rust-toolchain.py --toolchain-root "$sealed_toolchain"')
    toolchain_seal = gate.index('sealed_toolchain_authority_sha256="$(', copied_check)
    root_handoff = gate.index('/usr/bin/sudo -n "$chown_bin" -R 0 "$sealed"')
    root_check = gate.index('check-pinned-rust-toolchain.py --root-owned-toolchain "$sealed_toolchain"')
    if not (
        gate.count('check-pinned-rust-toolchain.py --toolchain-root "$sealed_toolchain"') == 1
        and gate.count('check-pinned-rust-toolchain.py --root-owned-toolchain "$sealed_toolchain"') == 4
        and gate.count('check-sealed-rust-command-bin.py "$sealed_command_bin" "$sealed_toolchain"') == 4
        and copied_toolchain < copied_check < toolchain_seal < root_handoff < root_check
    ):
        raise AssertionError("constructed Rust toolchain validation ordering is not exact")
    environment_pattern_match = re.search(r"grep -Eiq '([^']+)'", gate)
    if environment_pattern_match is None:
        raise AssertionError("compiler environment rejection pattern is missing")
    environment_pattern = environment_pattern_match.group(1)
    for assignment in (
        "LD_LIBRARY_PATH=/tmp/unreviewed",
        "Ld_PrElOaD=/tmp/unreviewed",
        "DYLD_INSERT_LIBRARIES=/tmp/unreviewed",
        "dYlD_fRaMeWoRk_PaTh=/tmp/unreviewed",
    ):
        if re.search(environment_pattern, assignment, re.IGNORECASE) is None:
            raise AssertionError(f"dynamic-loader override pattern was accepted: {assignment}")
    proof_preflight = '"$python_bin" -I ci/check-ordinary-wallet-plan-public-proof-surface.py "$repository_root"'
    proof_surface_mutations = "python3 -I ci/test-ordinary-wallet-plan-public-proof-surface.py"
    proof_snapshot_mutations = (
        'python3 -I ci/test-ordinary-wallet-plan-proof-snapshot.py "$source_cargo_home"'
    )
    if (
        gate.count(proof_preflight) != 1
        or gate.count(proof_surface_mutations) != 1
        or gate.count(proof_snapshot_mutations) != 1
    ):
        raise AssertionError("ordinary-wallet plan public proof preflight is not exact and singular")
    first_cargo_invocation = gate.index('"$compiler_cargo_bin" fetch \\')
    if gate.index(proof_preflight) > first_cargo_invocation:
        raise AssertionError("ordinary-wallet plan public proof preflight does not precede Cargo")
    first_build_capable_cargo = gate.index('tree_raw="$(')
    if gate.index(proof_surface_mutations) > first_build_capable_cargo:
        raise AssertionError("public proof surface mutations do not precede build-capable Cargo")

    def proof_snapshot_wiring_is_exact(candidate: str) -> bool:
        if (
            candidate.count(proof_snapshot_mutations) != 1
            or candidate.count("python3 -I ci/test-ordinary-wallet-plan-proof-snapshot.py") != 1
        ):
            return False
        fetches = [
            index
            for index in range(len(candidate))
            if candidate.startswith('"$compiler_cargo_bin" fetch \\', index)
        ]
        if len(fetches) != 2:
            return False
        try:
            source_home = candidate.index('source_cargo_home="$scratch/source-cargo-home"')
            snapshot_mutations = candidate.index(proof_snapshot_mutations)
            credential_sentinel_check = candidate.index('if [ -e "$credential_sentinel" ]; then')
            credential_sentinel_clear = candidate.index("fi\n", credential_sentinel_check) + len("fi\n")
            first_cache_copy = candidate.index(
                "python3 -I ci/prepare-ordinary-wallet-plan-proof-snapshot.py \\\n"
                "    --copy-cache \\\n"
            )
            first_build = candidate.index('tree_raw="$(')
        except ValueError:
            return False
        return (
            source_home < fetches[0] < fetches[1] < credential_sentinel_check
            < credential_sentinel_clear <= snapshot_mutations < first_cache_copy < first_build
        )

    if not proof_snapshot_wiring_is_exact(gate):
        raise AssertionError("private proof snapshot mutations do not consume the isolated fetched Cargo home")
    snapshot_without_call = gate.replace(proof_snapshot_mutations + "\n", "", 1)
    snapshot_wiring_mutations = {
        "missing source Cargo home": gate.replace(
            proof_snapshot_mutations,
            proof_snapshot_mutations.rsplit(" ", 1)[0],
            1,
        ),
        "ambient Cargo home": gate.replace(
            proof_snapshot_mutations,
            'python3 -I ci/test-ordinary-wallet-plan-proof-snapshot.py "$HOME/.cargo"',
            1,
        ),
        "before fetch": snapshot_without_call.replace(
            "(\n    cd /\n",
            proof_snapshot_mutations + "\n(\n    cd /\n",
            1,
        ),
        "after cache copy": snapshot_without_call.replace(
            "python3 -I ci/prepare-ordinary-wallet-plan-proof-snapshot.py \\\n"
            "    --workspace-cache \\\n",
            proof_snapshot_mutations
            + "\npython3 -I ci/prepare-ordinary-wallet-plan-proof-snapshot.py \\\n"
            "    --workspace-cache \\\n",
            1,
        ),
    }
    for name, mutated_gate in snapshot_wiring_mutations.items():
        if mutated_gate == gate or proof_snapshot_wiring_is_exact(mutated_gate):
            raise AssertionError(f"private proof snapshot {name} wiring mutation was accepted")
    checker_call = 'python3 -I ci/check-wallet-facts-conformance.py "$repository_root"'
    if gate.count(checker_call) != 1:
        raise AssertionError("conformance checker invocation is not fixed and singular")
    nested_pin = "9bcdcf31ffe90e7a23ada162c61c71cfc84343ba1c190865e0ed34af8c7da933"
    parent_pin = "9a3d11662670d13e23ed248f2ae145c87a52739e2e3bb03f7628e4d12e147c63"
    if gate.count(nested_pin) != 1:
        raise AssertionError("conformance inventory root pin is not singular")
    if gate.count(parent_pin) != 1:
        raise AssertionError("conformance parent root pin is not singular")
    plan_checker_call = 'python3 -I ci/check-ordinary-wallet-plan-conformance.py "$repository_root"'
    if gate.count(plan_checker_call) != 1:
        raise AssertionError("ordinary-wallet plan conformance checker invocation is not fixed and singular")
    plan_mutation_call = "python3 -I ci/test-ordinary-wallet-plan-conformance.py"
    if gate.count(plan_mutation_call) != 1:
        raise AssertionError("ordinary-wallet plan conformance mutation test invocation is not fixed and singular")
    proof_build_stanza = '''(
    cd /
    CARGO_HOME="$proof_cargo_home" CARGO_TARGET_DIR="$proof_target" \\
        run_sealed "$compiler_cargo_bin" build \\
            --manifest-path "$proof_snapshot/Cargo.toml" \\
            --quiet \\
            --locked \\
            --offline \\
            -p wasabi-liquid-native-ordinary-wallet-plan-public-proof-verifier \\
            --bin ordinary-wallet-plan-public-proof-verifier
)'''
    if gate.count(proof_build_stanza) != 1:
        raise AssertionError("ordinary-wallet plan public proof build stanza is not exact and singular")
    for name, mutated_stanza in {
        "scratch target": proof_build_stanza.replace('CARGO_TARGET_DIR="$proof_target" ', ""),
        "build verb": proof_build_stanza.replace(" build \\", " run \\", 1),
        "quiet": proof_build_stanza.replace("        --quiet \\\n", ""),
        "locked": proof_build_stanza.replace("        --locked \\\n", ""),
        "offline": proof_build_stanza.replace("        --offline \\\n", ""),
        "package": proof_build_stanza.replace("wasabi-liquid-native-ordinary-wallet-plan-public-proof-verifier", "wasabi-liquid-native-ordinary-wallet-plan", 1),
        "configuration root": proof_build_stanza.replace("cd /", 'cd "$repository_root"'),
        "snapshot manifest": proof_build_stanza.replace('"$proof_snapshot/Cargo.toml"', '"$repository_root/Cargo.toml"'),
        "binary": proof_build_stanza.replace("--bin ordinary-wallet-plan-public-proof-verifier", "--lib"),
    }.items():
        mutated_gate = gate.replace(proof_build_stanza, mutated_stanza, 1)
        if mutated_gate == gate or mutated_gate.count(proof_build_stanza) != 0:
            raise AssertionError(f"ordinary-wallet plan public proof build {name} mutation was accepted")
    workspace_manifest = (ROOT / "Cargo.toml").read_text(encoding="utf-8")
    tool_path = '"tools/ordinary-wallet-plan-public-proof-verifier"'
    if workspace_manifest.count(f"exclude = [{tool_path}]") != 1:
        raise AssertionError("public proof verifier is not excluded from the live workspace")
    for name, (token, expected_count) in {
        "surface checker": ("check-ordinary-wallet-plan-public-proof-surface.py", 3),
        "surface mutations": (proof_surface_mutations, 1),
        "dep-info path": ('"$proof_dep_info"', 4),
        "direct binary execution": ('"$proof_binary" "$proof_snapshot"', 1),
        "binary digest": ("--binary-digest \"$proof_binary\"", 2),
    }.items():
        if gate.count(token) != expected_count:
            raise AssertionError(f"ordinary-wallet plan public proof verifier {name} is not singular")
    snapshot_preparer = "python3 -I ci/prepare-ordinary-wallet-plan-proof-snapshot.py"
    if (
        gate.count(snapshot_preparer) != 32
        or gate.count("    --verify \\\n") != 4
        or gate.count("    --verify-cache \\\n") != 3
        or gate.count("--verify-tree \\\n") != 11
        or gate.count("    --workspace-cache \\\n") != 1
        or gate.count("    --copy-cache \\\n") != 3
        or gate.count("    --snapshot-only \\\n") != 1
        or gate.count("        --finalize-cache \\\n") != 2
        or gate.count("        --seal-tree \\\n") != 4
    ):
        raise AssertionError("ordinary-wallet plan private proof state checks are not exact")
    proof_materialization_stanza = '''CARGO_HOME="$proof_materialized_cargo_home" CARGO_TARGET_DIR="$scratch/proof-materialize-target" \\
    "$compiler_cargo_bin" metadata \\
        --manifest-path "$proof_snapshot/Cargo.toml" \\
        --locked \\
        --offline \\
        --format-version 1 >/dev/null'''
    workspace_materialization_stanza = '''CARGO_HOME="$workspace_materialized_cargo_home" CARGO_TARGET_DIR="$scratch/workspace-materialize-target" \\
    "$compiler_cargo_bin" metadata \\
        --manifest-path "$sealed_workspace/Cargo.toml" \\
        --locked \\
        --offline \\
        --format-version 1 >/dev/null'''
    proof_state_verification_stanza = '''python3 -I ci/prepare-ordinary-wallet-plan-proof-snapshot.py \\
    --verify \\
    "$proof_snapshot" \\
    "$proof_cargo_home" \\
    "$proof_cache_authority" \\
    "$proof_cache_authority_sha256" \\
    "$build_uid"'''
    workspace_state_verification_stanza = '''python3 -I ci/prepare-ordinary-wallet-plan-proof-snapshot.py \\
    --verify-cache \\
    "$workspace_cargo_home" \\
    "$workspace_cache_authority" \\
    "$workspace_cache_authority_sha256" \\
    "$build_uid"'''
    final_workspace_state_verification_stanza = '''        python3 -I ci/prepare-ordinary-wallet-plan-proof-snapshot.py \\
            --verify-cache \\
            "$workspace_cargo_home" \\
            "$workspace_cache_authority" \\
            "$workspace_cache_authority_sha256" \\
            "$build_uid"'''
    for name, stanza, expected_count in (
        ("proof source materialization", proof_materialization_stanza, 1),
        ("workspace source materialization", workspace_materialization_stanza, 1),
        ("proof external-authority verification", proof_state_verification_stanza, 4),
        ("workspace initial external-authority verification", workspace_state_verification_stanza, 2),
        ("workspace final external-authority verification", final_workspace_state_verification_stanza, 1),
    ):
        if gate.count(stanza) != expected_count:
            raise AssertionError(f"ordinary-wallet plan {name} is not exact")
    proof_materialized = gate.index(proof_materialization_stanza)
    proof_sealed = gate.index('proof_cache_authority_sha256="$(')
    proof_built = gate.index(proof_build_stanza)
    proof_verifications = [
        index
        for index in range(len(gate))
        if gate.startswith(proof_state_verification_stanza, index)
    ]
    if not (
        proof_materialized < proof_sealed < gate.index('"$chown_bin" -R 0 "$sealed"')
        < proof_verifications[0] < proof_verifications[1] < proof_built
        < proof_verifications[2] < gate.index('"$proof_binary" "$proof_snapshot"')
        < proof_verifications[3]
        and len(proof_verifications) == 4
    ):
        raise AssertionError("ordinary-wallet plan proof source seal ordering is not exact")
    workspace_materialized = gate.index(workspace_materialization_stanza)
    workspace_sealed = gate.index('workspace_cache_authority_sha256="$(')
    workspace_verifications = [
        index
        for index in range(len(gate))
        if gate.startswith(workspace_state_verification_stanza, index)
    ] + [gate.index(final_workspace_state_verification_stanza)]
    if not (
        workspace_materialized < workspace_sealed < workspace_verifications[0]
        < workspace_verifications[1] < gate.index('tree_raw="$(', workspace_verifications[1])
        < workspace_verifications[2]
        and len(workspace_verifications) == 3
    ):
        raise AssertionError("workspace dependency source seal ordering is not exact")
    for token in (
        'source_cargo_home="$scratch/source-cargo-home"',
        'proof_snapshot="$scratch/ordinary-wallet-plan-public-proof-snapshot"',
        'proof_authority_cargo_home="$scratch/proof-authority-cargo-home"',
        'workspace_authority_cargo_home="$scratch/workspace-authority-cargo-home"',
        'proof_materialized_cargo_home="$scratch/proof-materialized-cargo-home"',
        'workspace_materialized_cargo_home="$scratch/workspace-materialized-cargo-home"',
        'proof_cargo_home="$scratch/proof-final-cargo-home"',
        'workspace_cargo_home="$scratch/workspace-final-cargo-home"',
        'proof_cache_authority="$scratch/proof-cache-authority.jsonl"',
        'workspace_cache_authority="$scratch/workspace-cache-authority.jsonl"',
        'sealed_workspace="$scratch/sealed-workspace"',
        'sealed_toolchain="$scratch/sealed-toolchain"',
        'sealed_probe="$scratch/sealed-build-boundary-probe"',
        'export CARGO_HOME="$workspace_cargo_home"',
        'CARGO_HOME="$proof_cargo_home" CARGO_TARGET_DIR="$proof_target"',
        'CARGO_TARGET_DIR="$workspace_target"',
        'export RUSTC="$compiler_rustc_bin"',
        'export RUSTDOC="$compiler_rustdoc_bin"',
        '--snapshot "$proof_snapshot"',
        'proof_target="$scratch/ordinary-wallet-plan-public-proof-target"',
        'proof_binary="$proof_target/debug/ordinary-wallet-plan-public-proof-verifier"',
    ):
        expected_count = 2 if token in ('--snapshot "$proof_snapshot"', 'CARGO_TARGET_DIR="$workspace_target"') else 1
        if gate.count(token) != expected_count:
            raise AssertionError(f"ordinary-wallet plan proof snapshot token is not singular: {token}")
    privilege_tokens = (
        'if ! /usr/bin/sudo -n true; then',
        'if /usr/bin/sudo -n -u "$build_user" /usr/bin/sudo -n true',
        'build_user=nobody',
        'build_user="wlpq$build_nonce"',
        '/usr/bin/sudo -n "$chown_bin" -R 0 "$sealed"',
        '/usr/bin/sudo -n "$sealed_workspace/ci/run-sealed-darwin-command.sh"',
        '/usr/bin/sudo -n /usr/bin/unshare --net --mount --pid --fork --kill-child --mount-proc --propagation private --',
        'for boundary_target in "$proof_target" "$workspace_target"; do',
        'case "$("$sealed_toolchain/bin/cargo" --version --verbose)" in',
        'case "$(run_sealed "$compiler_cargo_bin" --version --verbose)" in',
        'case "$(run_sealed "$compiler_rustc_bin" --version --verbose)" in',
        'SEALED_DEPENDENCY_TARGET="$sealed_dependency_target"',
        'SEALED_WORKSPACE_TARGET="$sealed_workspace/Cargo.toml"',
    )
    for token in privilege_tokens:
        if gate.count(token) != 1:
            raise AssertionError(f"sealed compiler boundary token is not exact: {token}")
    writable_handoff = '''for writable in "$build_home" "$proof_target" "$workspace_target" "$build_tmp"; do
    /usr/bin/sudo -n "$chown_bin" "$build_uid" "$writable"
    /usr/bin/sudo -n /bin/chmod 0700 "$writable"
done
/usr/bin/sudo -n /bin/chmod 0755 "$proof_target" "$workspace_target"'''
    denied_write_handoff = '''for denied_write in "$host_write_target" "$var_tmp_target"; do
    /usr/bin/sudo -n "$chown_bin" "$build_uid" "$denied_write"
    /usr/bin/sudo -n /bin/chmod 0600 "$denied_write"
done'''
    sandbox_profile_handoff = '''            /usr/bin/sudo -n "$chown_bin" 0 "$sandbox_profile"
            /usr/bin/sudo -n /bin/chmod 0444 "$sandbox_profile"'''

    def handoff_is_exact(candidate: str) -> bool:
        if any(
            candidate.count(stanza) != 1
            for stanza in (
                writable_handoff,
                denied_write_handoff,
                sandbox_profile_handoff,
            )
        ):
            return False
        return (
            candidate.index(writable_handoff)
            < candidate.index(denied_write_handoff)
            < candidate.index('/bin/chmod 0711 "$scratch"')
            < candidate.index(sandbox_profile_handoff)
        )

    if not handoff_is_exact(gate):
        raise AssertionError("sealed writable ownership handoff is not exact")
    handoff_mutations = {
        "writable mode privilege": gate.replace(
            '/usr/bin/sudo -n /bin/chmod 0700 "$writable"',
            '/bin/chmod 0700 "$writable"',
            1,
        ),
        "target mode privilege": gate.replace(
            '/usr/bin/sudo -n /bin/chmod 0755 "$proof_target" "$workspace_target"',
            '/bin/chmod 0755 "$proof_target" "$workspace_target"',
            1,
        ),
        "denied-write mode privilege": gate.replace(
            '/usr/bin/sudo -n /bin/chmod 0600 "$denied_write"',
            '/bin/chmod 0600 "$denied_write"',
            1,
        ),
        "sandbox-profile mode privilege": gate.replace(
            '/usr/bin/sudo -n /bin/chmod 0444 "$sandbox_profile"',
            '/bin/chmod 0444 "$sandbox_profile"',
            1,
        ),
        "writable ownership ordering": gate.replace(
            writable_handoff,
            writable_handoff.replace(
                '    /usr/bin/sudo -n "$chown_bin" "$build_uid" "$writable"\n'
                '    /usr/bin/sudo -n /bin/chmod 0700 "$writable"',
                '    /usr/bin/sudo -n /bin/chmod 0700 "$writable"\n'
                '    /usr/bin/sudo -n "$chown_bin" "$build_uid" "$writable"',
                1,
            ),
            1,
        ),
        "denied-write ownership ordering": gate.replace(
            denied_write_handoff,
            denied_write_handoff.replace(
                '    /usr/bin/sudo -n "$chown_bin" "$build_uid" "$denied_write"\n'
                '    /usr/bin/sudo -n /bin/chmod 0600 "$denied_write"',
                '    /usr/bin/sudo -n /bin/chmod 0600 "$denied_write"\n'
                '    /usr/bin/sudo -n "$chown_bin" "$build_uid" "$denied_write"',
                1,
            ),
            1,
        ),
        "sandbox-profile ownership ordering": gate.replace(
            sandbox_profile_handoff,
            sandbox_profile_handoff.replace(
                '            /usr/bin/sudo -n "$chown_bin" 0 "$sandbox_profile"\n'
                '            /usr/bin/sudo -n /bin/chmod 0444 "$sandbox_profile"',
                '            /usr/bin/sudo -n /bin/chmod 0444 "$sandbox_profile"\n'
                '            /usr/bin/sudo -n "$chown_bin" 0 "$sandbox_profile"',
                1,
            ),
            1,
        ),
    }
    for name, mutated_gate in handoff_mutations.items():
        if mutated_gate == gate or handoff_is_exact(mutated_gate):
            raise AssertionError(f"sealed writable {name} mutation was accepted")

    def darwin_cleanup_is_exact(candidate: str) -> bool:
        cleanup_start = candidate.find("cleanup() {")
        cleanup_end = candidate.find("\n}\ntrap cleanup EXIT HUP INT TERM", cleanup_start)
        if cleanup_start < 0 or cleanup_end < 0:
            return False
        cleanup = candidate[cleanup_start:cleanup_end]
        lifecycle = (
            'if darwin_marker_matches; then',
            'if /usr/bin/sudo -n /usr/bin/dscl . -read "/Users/$build_user" >/dev/null 2>&1; then',
            'if darwin_account_matches; then',
            '/usr/bin/sudo -n /usr/bin/pkill -TERM -u "$build_uid" 2>/dev/null || :',
            '/bin/sleep 1',
            '/usr/bin/sudo -n /usr/bin/pkill -KILL -u "$build_uid" 2>/dev/null || :',
            'if /usr/bin/sudo -n /usr/bin/pgrep -u "$build_uid" >/dev/null 2>&1; then',
            '/usr/bin/sudo -n /usr/bin/dscl . -delete "/Users/$build_user"',
            'if ! /usr/bin/sudo -n /usr/bin/dscl . -read "/Users/$build_user" >/dev/null 2>&1; then',
            '/usr/bin/sudo -n /bin/rm "$darwin_account_marker"',
            '/usr/bin/sudo -n /bin/rmdir "$darwin_account_lock"',
            'if [ -n "$var_tmp_target" ]; then',
            '/usr/bin/sudo -n /bin/rm -f "$var_tmp_target" 2>/dev/null || :',
            'if [ -d "$scratch" ]; then',
            '/usr/bin/sudo -n "$chown_bin" -R "$(/usr/bin/id -u)" "$scratch" 2>/dev/null || :',
            'chmod -R u+w "$scratch" 2>/dev/null || :',
            'rm -rf "$scratch"',
        )
        return all(cleanup.count(token) == 1 for token in lifecycle) and [
            cleanup.index(token) for token in lifecycle
        ] == sorted(cleanup.index(token) for token in lifecycle)

    if gate.count("trap cleanup EXIT HUP INT TERM") != 1 or not darwin_cleanup_is_exact(gate):
        raise AssertionError("Darwin account, lock, or scratch cleanup lifecycle is not exact")
    for name, token in (
        (
            "account deletion",
            '/usr/bin/sudo -n /usr/bin/dscl . -delete "/Users/$build_user"',
        ),
        ("marker removal", '/usr/bin/sudo -n /bin/rm "$darwin_account_marker"'),
        ("lock removal", '/usr/bin/sudo -n /bin/rmdir "$darwin_account_lock"'),
    ):
        mutated = gate.replace(token, "", 1)
        if mutated == gate or darwin_cleanup_is_exact(mutated):
            raise AssertionError(f"Darwin cleanup {name} mutation was accepted")
    darwin_root_read = "'(allow file-read* (literal \"/\"))'"
    darwin_system_read = (
        "'(allow file-read* (subpath \"/System\") (subpath \"/usr\") "
        "(subpath \"/bin\") (subpath \"/sbin\") (subpath \"/Applications\") "
        "(subpath \"/Library/Developer\") (subpath \"/private/etc\") "
        "(subpath \"/private/var/db\"))'"
    )
    darwin_xcode_select_read = (
        "'(allow file-read-metadata (literal \"/var\") "
        "(literal \"/private/var/select/developer_dir\"))'"
    )
    darwin_system_map = (
        "'(allow file-map-executable (subpath \"/System\") (subpath \"/usr\") "
        "(subpath \"/bin\") (subpath \"/sbin\") (subpath \"/Applications\") "
        "(subpath \"/Library/Developer\"))'"
    )
    darwin_private_map = (
        r'"(allow file-map-executable (subpath \"$sealed_toolchain\") '
        r'(subpath \"$sealed_command_bin\") (subpath \"$profile_target\"))"'
    )
    darwin_system_exec = (
        "'(allow process-exec* (subpath \"/System\") (subpath \"/usr\") "
        "(subpath \"/bin\") (subpath \"/sbin\") (subpath \"/Applications\") "
        "(subpath \"/Library/Developer\"))'"
    )
    darwin_private_exec = (
        r'"(allow process-exec* (subpath \"$sealed_toolchain\") '
        r'(subpath \"$sealed_command_bin\") (subpath \"$profile_target\"))"'
    )
    darwin_private_write = (
        r'"(allow file-write* (subpath \"$build_home\") '
        r'(subpath \"$build_tmp\") (subpath \"$profile_target\"))"'
    )
    darwin_allow_tokens = (
        "'(allow process*)'",
        darwin_system_exec,
        darwin_private_exec,
        "'(allow signal (target self))'",
        "'(allow sysctl-read)'",
        "'(allow mach-lookup)'",
        darwin_root_read,
        darwin_system_read,
        darwin_xcode_select_read,
        r'"(allow file-read* (subpath \"$scratch\"))"',
        r'"(allow file-read-metadata (literal \"$var_tmp_target\"))"',
        darwin_system_map,
        darwin_private_map,
        darwin_private_write,
        "'(allow file-write-data (literal \"/dev/null\"))'",
    )
    darwin_profile_tokens = (
        "'(deny default)'",
        *darwin_allow_tokens,
        "'(deny network*)'",
    )

    def darwin_profile_is_exact(candidate: str) -> bool:
        if any(candidate.count(token) != 1 for token in darwin_profile_tokens):
            return False
        if (
            len(re.findall(r"\(\s*allow(?:\s|\))", candidate)) != len(darwin_allow_tokens)
            or len(re.findall(r"\(\s*deny(?:\s|\))", candidate)) != 2
            or candidate.count("(allow file-read") != 5
            or candidate.count("(allow file-map-executable") != 2
            or candidate.count("(allow process-exec") != 2
            or '(subpath "/")' in candidate
            or "(allow file-read*)" in candidate
            or "(allow file-map-executable)" in candidate
            or "(allow process-exec*)" in candidate
            or "(with no-sandbox)" in candidate
            or '(subpath "$scratch")' in candidate
            or '(subpath "$build_home")' in candidate
            or '(subpath "$build_tmp")' in candidate
            or '(subpath "$sealed_workspace")' in candidate
            or '(subpath "$trusted_bin")' in candidate
            or '(subpath "$proof_target")' in candidate
            or '(subpath "$workspace_target")' in candidate
            or '(subpath "/dev")' in candidate
            or '(subpath "/dev/fd")' in candidate
        ):
            return False
        return [candidate.index(token) for token in darwin_profile_tokens] == sorted(
            candidate.index(token) for token in darwin_profile_tokens
        )

    if not darwin_profile_is_exact(gate):
        raise AssertionError("sealed Darwin profile ordering or root-directory grant is not exact")
    for name, replacement in (
        ("missing root read", ""),
        ("root subtree read", "'(allow file-read* (subpath \"/\"))'"),
        ("unfiltered read", "'(allow file-read*)'"),
    ):
        mutated = gate.replace(darwin_root_read, replacement, 1)
        if mutated == gate or darwin_profile_is_exact(mutated):
            raise AssertionError(f"sealed Darwin {name} mutation was accepted")
    additive_unfiltered = gate.replace(
        darwin_root_read + " \\\n",
        darwin_root_read + ' \\\n                "(allow file-read*)" \\\n',
        1,
    )
    if additive_unfiltered == gate or darwin_profile_is_exact(additive_unfiltered):
        raise AssertionError("sealed Darwin additive unfiltered read mutation was accepted")
    reordered = gate.replace(darwin_root_read + " \\\n", "", 1).replace(
        "                '(deny network*)'",
        "                " + darwin_root_read + " \\\n                '(deny network*)'",
        1,
    )
    if reordered == gate or darwin_profile_is_exact(reordered):
        raise AssertionError("sealed Darwin root-directory grant reordering was accepted")
    for name, clause in (
        ("umbrella file capability", "'(allow file*)'"),
        ("unfiltered write capability", "'(allow file-write*)'"),
        ("unfiltered child-exec capability", "'(allow process-exec*)'"),
        ("dynamic-code capability", "'(allow dynamic-code-generation)'"),
        ("network capability", "'(allow network*)'"),
    ):
        mutated = gate.replace(
            "                '(deny network*)'",
            f"                {clause} \\\n                '(deny network*)'",
            1,
        )
        if mutated == gate or darwin_profile_is_exact(mutated):
            raise AssertionError(f"sealed Darwin additive {name} mutation was accepted")
    for name, extra_path in (
        ("scratch write", r'(subpath \"$scratch\")'),
        ("sealed-workspace write", r'(subpath \"$sealed_workspace\")'),
        ("sealed-toolchain write", r'(subpath \"$sealed_toolchain\")'),
        ("external temporary write", '(subpath "/private/tmp")'),
    ):
        broadened_write = darwin_private_write.replace('))"', f" {extra_path}))\"", 1)
        mutated = gate.replace(darwin_private_write, broadened_write, 1)
        if mutated == gate or darwin_profile_is_exact(mutated):
            raise AssertionError(f"sealed Darwin {name} mutation was accepted")
    for name, original, replacement in (
        ("missing system child execution", darwin_system_exec, ""),
        ("missing private child execution", darwin_private_exec, ""),
        (
            "unfiltered child execution",
            darwin_system_exec,
            "'(allow process-exec*)'",
        ),
        (
            "root child execution",
            darwin_system_exec,
            "'(allow process-exec* (subpath \"/\"))'",
        ),
        (
            "no-sandbox child execution",
            darwin_system_exec,
            "'(allow process-exec* (with no-sandbox) (subpath \"/System\"))'",
        ),
        (
            "interpreter-only child execution",
            darwin_system_exec,
            "'(allow process-exec* (literal \"/usr/bin/env\"))'",
        ),
        (
            "interpreter operation substitution",
            darwin_system_exec,
            "'(allow process-exec-interpreter (literal \"/usr/bin/env\"))'",
        ),
        (
            "scratch child execution",
            darwin_private_exec,
            r'"(allow process-exec* (subpath \"$scratch\"))"',
        ),
        (
            "build-home child execution",
            darwin_private_exec,
            r'"(allow process-exec* (subpath \"$build_home\"))"',
        ),
        (
            "build-tmp child execution",
            darwin_private_exec,
            r'"(allow process-exec* (subpath \"$build_tmp\"))"',
        ),
        (
            "sealed-workspace child execution",
            darwin_private_exec,
            r'"(allow process-exec* (subpath \"$sealed_workspace\"))"',
        ),
        (
            "trusted-bin child execution",
            darwin_private_exec,
            r'"(allow process-exec* (subpath \"$trusted_bin\"))"',
        ),
        (
            "external temporary child execution",
            darwin_private_exec,
            "'(allow process-exec* (subpath \"/private/tmp\") (subpath \"/var/tmp\"))'",
        ),
        (
            "both-target child execution",
            darwin_private_exec,
            r'"(allow process-exec* (subpath \"$sealed_toolchain\") (subpath \"$sealed_command_bin\") (subpath \"$proof_target\") (subpath \"$workspace_target\"))"',
        ),
        ("missing system executable map", darwin_system_map, ""),
        ("missing private executable map", darwin_private_map, ""),
        (
            "unfiltered executable map",
            darwin_system_map,
            "'(allow file-map-executable)'",
        ),
        (
            "root executable map",
            darwin_system_map,
            "'(allow file-map-executable (subpath \"/\"))'",
        ),
        (
            "scratch executable map",
            darwin_private_map,
            r'"(allow file-map-executable (subpath \"$scratch\"))"',
        ),
        (
            "build-home executable map",
            darwin_private_map,
            r'"(allow file-map-executable (subpath \"$build_home\"))"',
        ),
        (
            "build-tmp executable map",
            darwin_private_map,
            r'"(allow file-map-executable (subpath \"$build_tmp\"))"',
        ),
        (
            "sealed-workspace executable map",
            darwin_private_map,
            r'"(allow file-map-executable (subpath \"$sealed_workspace\"))"',
        ),
        (
            "both-target executable map",
            darwin_private_map,
            r'"(allow file-map-executable (subpath \"$sealed_toolchain\") (subpath \"$sealed_command_bin\") (subpath \"$proof_target\") (subpath \"$workspace_target\"))"',
        ),
    ):
        mutated = gate.replace(original, replacement, 1)
        if mutated == gate or darwin_profile_is_exact(mutated):
            raise AssertionError(f"sealed Darwin {name} mutation was accepted")
    for name, original, replacement in (
        (
            "additive user subtree read",
            darwin_system_read,
            darwin_system_read[:-2] + ' (subpath "/Users"))\'',
        ),
        (
            "restored device subtree read",
            darwin_system_read,
            darwin_system_read[:-2] + ' (subpath "/dev"))\'',
        ),
        ("missing system read", darwin_system_read, ""),
        ("missing Xcode selector read", darwin_xcode_select_read, ""),
        (
            "broadened Xcode selector read",
            darwin_xcode_select_read,
            "'(allow file-read-metadata (subpath \"/private/var\"))'",
        ),
    ):
        mutated = gate.replace(original, replacement, 1)
        if mutated == gate or darwin_profile_is_exact(mutated):
            raise AssertionError(f"sealed Darwin {name} mutation was accepted")
    for device in ("null", "random", "urandom", "tty", "stdin", "stdout", "stderr"):
        additive_device_read = gate.replace(
            darwin_xcode_select_read + " \\\n",
            darwin_xcode_select_read
            + f' \\\n                \'(allow file-read* (literal "/dev/{device}"))\' \\\n',
            1,
        )
        if additive_device_read == gate or darwin_profile_is_exact(additive_device_read):
            raise AssertionError(
                f"sealed Darwin additive /dev/{device} read mutation was accepted"
            )
    dependency_target_selection = (
        'sealed_dependency_target="$(find "$workspace_cargo_home/registry/src" '
        '-type f ! -name .cargo-ok -print -quit)"'
    )
    old_dependency_target_selection = dependency_target_selection.replace(
        "-print -quit", "-print | head -1"
    )

    def dependency_target_selection_is_exact(candidate: str) -> bool:
        return (
            candidate.count(dependency_target_selection) == 1
            and old_dependency_target_selection not in candidate
        )

    if not dependency_target_selection_is_exact(gate):
        raise AssertionError("sealed dependency probe selection is not bounded and exact")
    for name, mutated in (
        ("missing", gate.replace(dependency_target_selection, "", 1)),
        (
            "broken-pipe pipeline",
            gate.replace(
                dependency_target_selection,
                old_dependency_target_selection,
                1,
            ),
        ),
    ):
        if mutated == gate or dependency_target_selection_is_exact(mutated):
            raise AssertionError(f"sealed dependency probe {name} mutation was accepted")
    for token, expected in (
        ('(deny default)', 1),
        ('(allow file-write* (subpath', 1),
        ('(deny network*)', 1),
        ('proof_sandbox_profile="$scratch/build-proof.sb"', 1),
        ('workspace_sandbox_profile="$scratch/build-workspace.sb"', 1),
        ('for profile_target in "$proof_target" "$workspace_target"; do', 1),
        ('"$proof_target") sandbox_profile="$proof_sandbox_profile"', 2),
        ('"$workspace_target") sandbox_profile="$workspace_sandbox_profile"', 2),
        ('darwin_account_lock=/var/tmp/wasabi-liquid-wlpq-account.lock', 1),
        ('if ! /usr/bin/sudo -n /bin/mkdir "$darwin_account_lock"; then', 1),
        ('Darwin account lifecycle lock already exists; stale and concurrent locks fail closed', 1),
        ('if darwin_marker_matches; then', 1),
        ('if darwin_account_matches; then', 1),
        ('refusing Darwin account cleanup after account attributes changed', 1),
        ('refusing Darwin account cleanup after lock marker changed', 1),
        ('collision-resistant Darwin build account name already exists', 1),
        ('python3 -I ci/prepare-cargo-credential-provider.py "$credential_provider" "$credential_sentinel"', 1),
        ('python3 -I ci/test-cargo-credential-provider.py', 1),
        ('python3 -I ci/test-sealed-tree-readable.py', 1),
        ('"$sealed_command_bin/cargo-fmt" --version', 1),
        ('"$sealed_command_bin/cargo-clippy" --version', 1),
        ('"$sealed_command_bin/clippy-driver" --version', 1),
    ):
        if gate.count(token) != expected:
            raise AssertionError(f"sealed Darwin lifecycle or profile token is not exact: {token}")
    for name, token in (
        ("concurrent lock", 'if ! /usr/bin/sudo -n /bin/mkdir "$darwin_account_lock"; then'),
        ("stale account name", 'collision-resistant Darwin build account name already exists'),
        ("cleanup marker mismatch", 'refusing Darwin account cleanup after lock marker changed'),
        ("cleanup attribute mismatch", 'refusing Darwin account cleanup after account attributes changed'),
    ):
        mutated = gate.replace(token, "", 1)
        if mutated == gate or mutated.count(token) != 0:
            raise AssertionError(f"Darwin {name} mutation was accepted")
    linux_wrapper = (ROOT / "ci/run-sealed-linux-command.sh").read_text(encoding="utf-8")
    for token, expected in (
        ('[ "$$" -ne 1 ]', 1),
        ('/usr/bin/readlink /proc/1/ns/pid', 1),
        ('/usr/bin/readlink /proc/self/ns/pid', 1),
        ('/usr/bin/findmnt --first-only --noheadings --raw --output FSTYPE --target /proc', 1),
        ('NSpid:', 1),
        ('/proc/1/status', 2),
        ('/usr/bin/mount --bind "$hidden_home" "$original_home"', 1),
        ('/usr/bin/mount -o remount,ro=recursive /', 1),
        ('/proc/self/mountinfo', 2),
        ('sealed Linux recursive read-only mount transition is incomplete', 1),
        ('sealed Linux writable mount inventory differs from the exact build roots', 1),
        ('/usr/bin/mount -o remount,bind,rw "$writable"', 1),
        ('/usr/bin/setpriv --reuid="$build_uid" --regid="$build_uid" --clear-groups', 1),
        ('/usr/bin/env -i HOME="$build_home" TMPDIR="$build_tmp" PATH="$trusted_bin:/usr/bin:/bin"', 1),
        ('SEALED_ORIGINAL_CARGO_HOME="$original_cargo_home"', 1),
        ('SEALED_INACTIVE_BUILD_TARGET="$inactive_target_dir"', 1),
        ('exec /usr/bin/python3 "$sealed_workspace_root/ci/run-sealed-command-supervisor.py"', 1),
    ):
        if linux_wrapper.count(token) != expected:
            raise AssertionError(f"sealed Linux boundary token is not exact: {token}")
    linux_recursive_read_only = '/usr/bin/mount -o remount,ro=recursive /'
    linux_all_read_only_audit = '''if ! /usr/bin/awk '
function has_option(options, wanted, count, index, fields) {
    count = split(options, fields, ",")
    for (index = 1; index <= count; index++) {
        if (fields[index] == wanted) return 1
    }
    return 0
}
NF < 6 { invalid = 1; next }
{
    read_only = has_option($6, "ro")
    read_write = has_option($6, "rw")
    if (!read_only || read_write) invalid = 1
    if ($5 == "/" && read_only && !read_write) root_read_only = 1
}
END { exit !(NR > 0 && root_read_only && !invalid) }
' /proc/self/mountinfo; then
    echo "sealed Linux recursive read-only mount transition is incomplete" >&2
    exit 1
fi'''
    linux_writable_loop = '''for writable in "$build_home" "$build_tmp" "$target_dir"; do
    /usr/bin/mount --bind "$writable" "$writable"
    /usr/bin/mount -o remount,bind,rw "$writable"
done'''
    linux_exact_writable_audit = '''if ! /usr/bin/awk -v build_home="$build_home" -v build_tmp="$build_tmp" -v target_dir="$target_dir" '
function has_option(options, wanted, count, index, fields) {
    count = split(options, fields, ",")
    for (index = 1; index <= count; index++) {
        if (fields[index] == wanted) return 1
    }
    return 0
}
NF < 6 { invalid = 1; next }
{
    read_only = has_option($6, "ro")
    read_write = has_option($6, "rw")
    if (read_only == read_write) invalid = 1
    if ($5 == "/" && read_only && !read_write) root_read_only = 1
    if (read_write) {
        if ($5 == build_home) build_home_count++
        else if ($5 == build_tmp) build_tmp_count++
        else if ($5 == target_dir) target_dir_count++
        else invalid = 1
    }
}
END {
    exit !(NR > 0 && root_read_only && !invalid &&
        build_home_count == 1 && build_tmp_count == 1 && target_dir_count == 1)
}
' /proc/self/mountinfo; then
    echo "sealed Linux writable mount inventory differs from the exact build roots" >&2
    exit 1
fi'''

    def linux_mount_boundary_is_exact(candidate: str) -> bool:
        required = (
            linux_recursive_read_only,
            linux_all_read_only_audit,
            linux_writable_loop,
            linux_exact_writable_audit,
        )
        if any(candidate.count(token) != 1 for token in required):
            return False
        forbidden = (
            'mountpoints="$(/usr/bin/findmnt',
            'for mountpoint in $mountpoints',
            'remount,bind,ro "$mountpoint"',
            'remount,rw=recursive',
            'remount,ro /',
            'remount,ro=recursive / || :',
        )
        if any(token in candidate for token in forbidden):
            return False
        return (
            candidate.index('/usr/bin/mount --bind "$hidden_home" "$original_home"')
            < candidate.index(linux_recursive_read_only)
            < candidate.index(linux_all_read_only_audit)
            < candidate.index(linux_writable_loop)
            < candidate.index(linux_exact_writable_audit)
            < candidate.index('cd -P "$sealed_workspace_root"')
        )

    if not linux_mount_boundary_is_exact(linux_wrapper):
        raise AssertionError("sealed Linux recursive mount boundary is not exact")
    linux_mount_mutations = {
        "missing recursive transition": linux_wrapper.replace(linux_recursive_read_only, "", 1),
        "writable recursive transition": linux_wrapper.replace("ro=recursive", "rw=recursive", 1),
        "nonrecursive transition": linux_wrapper.replace("ro=recursive", "ro", 1),
        "non-root transition": linux_wrapper.replace("ro=recursive /", 'ro=recursive "$original_home"', 1),
        "ignored recursive failure": linux_wrapper.replace(
            linux_recursive_read_only, linux_recursive_read_only + " || :", 1
        ),
        "missing all-read-only audit": linux_wrapper.replace(linux_all_read_only_audit, "", 1),
        "missing exact-writable audit": linux_wrapper.replace(linux_exact_writable_audit, "", 1),
        "unexpected writable accepted": linux_wrapper.replace(
            "        else invalid = 1", "        else next", 1
        ),
        "prefix writable accepted": linux_wrapper.replace(
            "if ($5 == build_home)", "if (index($5, build_home) == 1)", 1
        ),
        "missing build-home count": linux_wrapper.replace("build_home_count == 1 && ", "", 1),
        "missing build-tmp count": linux_wrapper.replace("build_tmp_count == 1 && ", "", 1),
        "missing target count": linux_wrapper.replace(" && target_dir_count == 1", "", 1),
        "duplicate build-home accepted": linux_wrapper.replace("build_home_count == 1", "build_home_count >= 1", 1),
        "restored target loop": linux_wrapper.replace(
            linux_recursive_read_only,
            'mountpoints="$(/usr/bin/findmnt --kernel --list --noheadings --output TARGET)"\nfor mountpoint in $mountpoints; do /usr/bin/mount -o remount,bind,ro "$mountpoint"; done',
            1,
        ),
    }
    for name, mutated in linux_mount_mutations.items():
        if mutated == linux_wrapper or linux_mount_boundary_is_exact(mutated):
            raise AssertionError(f"sealed Linux mount boundary {name} mutation was accepted")
    for name, original, replacement in (
        ("writable target remount", 'remount,bind,rw "$writable"', 'remount,bind,ro "$writable"'),
        ("writable bind scope", 'remount,bind,rw "$writable"', 'remount,rw "$writable"'),
    ):
        mutated = linux_wrapper.replace(original, replacement, 1)
        if mutated == linux_wrapper or original in mutated:
            raise AssertionError(f"sealed Linux {name} mutation was accepted")
    linux_namespace_diagnostics = (
        "sealed Linux PID-one namespace handle is unavailable",
        "sealed Linux active PID namespace handle is unavailable",
        "sealed Linux procfs PID namespace differs from the active namespace",
        "sealed Linux proc filesystem type lookup failed",
        "sealed Linux proc filesystem type is not proc",
        "sealed Linux PID-one status is unavailable",
        "sealed Linux PID-one namespace PID is not one",
    )
    if any(linux_wrapper.count(message) != 1 for message in linux_namespace_diagnostics):
        raise AssertionError("sealed Linux namespace diagnostics are not exact")
    for name, original, replacement in (
        ("PID-one handle", "/usr/bin/readlink /proc/1/ns/pid", "/usr/bin/false"),
        ("active handle", "/usr/bin/readlink /proc/self/ns/pid", "/usr/bin/false"),
        ("namespace equality", '[ "$pid_one_namespace" != "$active_pid_namespace" ]', "false"),
        ("first mount only", " --first-only", ""),
        ("raw mount output", " --raw", ""),
        ("proc type equality", '[ "$proc_filesystem_type" != proc ]', "false"),
        ("PID-one readability", "[ ! -r /proc/1/status ]", "false"),
        ("PID-one namespace PID", '$NF == "1"', '$NF == "2"'),
    ):
        mutated = linux_wrapper.replace(original, replacement, 1)
        if mutated == linux_wrapper or original in mutated:
            raise AssertionError(f"sealed Linux {name} mutation was accepted")
    linux_child_status = linux_wrapper.replace("/proc/1/status", "/proc/self/status", 1)
    if linux_child_status == linux_wrapper or linux_child_status.count("/proc/1/status") != 1:
        raise AssertionError("sealed Linux PID-one status mutation was accepted")
    darwin_wrapper = (ROOT / "ci/run-sealed-darwin-command.sh").read_text(encoding="utf-8")
    for token in (
        '/usr/bin/sudo -n -u "$build_user" /usr/bin/sandbox-exec -f "$sandbox_profile"',
        '/usr/bin/env -i HOME="$build_home" TMPDIR="$build_tmp" PATH="$trusted_bin:/usr/bin:/bin"',
        '/usr/bin/pkill -TERM -u "$build_uid"',
        '/usr/bin/pkill -KILL -u "$build_uid"',
        '/usr/bin/pgrep -u "$build_uid"',
        'SEALED_INACTIVE_BUILD_TARGET="$inactive_target_dir"',
    ):
        if darwin_wrapper.count(token) != 1:
            raise AssertionError(f"sealed Darwin boundary token is not exact: {token}")

    def sealed_cwd_is_exact(candidate: str, platform: str) -> bool:
        sibling = '''expected_workspace_target="${target_dir%/*}/sealed-workspace/Cargo.toml"
if [ "$sealed_workspace_target" != "$expected_workspace_target" ]; then
    echo "sealed PLATFORM workspace target differs from its exact sibling" >&2
    exit 1
fi
sealed_workspace_root=${sealed_workspace_target%/Cargo.toml}'''.replace(
            "PLATFORM", platform
        )
        chdir = '''cd -P "$sealed_workspace_root"
if [ "$(/bin/pwd -P)" != "$sealed_workspace_root" ]; then
    echo "sealed PLATFORM workspace root is nonphysical or noncanonical" >&2
    exit 1
fi'''.replace("PLATFORM", platform)
        if candidate.count(sibling) != 1 or candidate.count(chdir) != 1:
            return False
        if platform == "Darwin":
            return (
                candidate.index(sibling)
                < candidate.index('for path in "$sandbox_profile"')
                < candidate.index(chdir)
                < candidate.index("set +e")
                < candidate.index('/usr/bin/sudo -n -u "$build_user" /usr/bin/sandbox-exec')
            )
        return (
            candidate.index(sibling)
            < candidate.index('for writable in "$build_home" "$build_tmp" "$target_dir"; do')
            < candidate.index('/usr/bin/mount -o remount,bind,rw "$writable"')
            < candidate.index(chdir)
            < candidate.index('exec /usr/bin/python3 "$sealed_workspace_root/ci/run-sealed-command-supervisor.py"')
        )

    for platform, wrapper in (("Darwin", darwin_wrapper), ("Linux", linux_wrapper)):
        if not sealed_cwd_is_exact(wrapper, platform):
            raise AssertionError(f"sealed {platform} physical workspace CWD is not exact")
        cwd_mutations = {
            "missing physical chdir": wrapper.replace('cd -P "$sealed_workspace_root"', "", 1),
            "logical chdir": wrapper.replace('cd -P "$sealed_workspace_root"', 'cd "$sealed_workspace_root"', 1),
            "alternate derivation": wrapper.replace(
                'expected_workspace_target="${target_dir%/*}/sealed-workspace/Cargo.toml"',
                'expected_workspace_target="$build_home/sealed-workspace/Cargo.toml"',
                1,
            ),
            "broadened target": wrapper.replace(
                'if [ "$sealed_workspace_target" != "$expected_workspace_target" ]; then',
                'case "$sealed_workspace_target" in */Cargo.toml) ;; *)',
                1,
            ),
            "missing physical equality": wrapper.replace(
                'if [ "$(/bin/pwd -P)" != "$sealed_workspace_root" ]; then',
                'if false; then',
                1,
            ),
        }
        for mutation_name, mutated_wrapper in cwd_mutations.items():
            if mutated_wrapper == wrapper or sealed_cwd_is_exact(mutated_wrapper, platform):
                raise AssertionError(
                    f"sealed {platform} CWD {mutation_name} mutation was accepted"
                )

    sealed_cwd_probe = '''if [ "$(run_sealed /bin/pwd -P)" != "$sealed_workspace" ]; then
    echo "sealed command current directory differs from the workspace authority" >&2
    exit 1
fi'''
    if (
        gate.count(sealed_cwd_probe) != 1
        or gate.index(sealed_cwd_probe)
        > gate.index('case "$(run_sealed "$compiler_cargo_bin" --version --verbose)" in')
    ):
        raise AssertionError("sealed command live CWD assertion is not exact")
    for name, replacement in (
        ("missing", ""),
        ("logical", sealed_cwd_probe.replace("/bin/pwd -P", "/bin/pwd -L")),
        ("unchecked", 'run_sealed /bin/pwd -P >/dev/null'),
    ):
        mutated_gate = gate.replace(sealed_cwd_probe, replacement, 1)
        if mutated_gate == gate or mutated_gate.count(sealed_cwd_probe) != 0:
            raise AssertionError(f"sealed command live CWD {name} mutation was accepted")
    darwin_child_exec_probe = '''if [ "$host_system" = Darwin ]; then
    expected_darwin_rustc_version='rustc 1.96.0 (ac68faa20 2026-05-25)
binary: rustc
commit-hash: ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96
commit-date: 2026-05-25
host: aarch64-apple-darwin
release: 1.96.0
LLVM version: 22.1.2'
    if [ "$(run_sealed /usr/bin/env "$compiler_rustc_bin" -vV)" != "$expected_darwin_rustc_version" ]; then
        echo "isolated Darwin child-exec Rust compiler identity mismatch" >&2
        exit 1
    fi
fi'''
    if (
        gate.count(darwin_child_exec_probe) != 1
        or gate.index(sealed_cwd_probe)
        > gate.index(darwin_child_exec_probe)
        or gate.index(darwin_child_exec_probe)
        > gate.index('case "$(run_sealed "$compiler_cargo_bin" --version --verbose)" in')
    ):
        raise AssertionError("sealed Darwin child-exec identity probe is not exact")
    for name, replacement in (
        ("missing", ""),
        (
            "direct compiler launch",
            darwin_child_exec_probe.replace(
                'run_sealed /usr/bin/env "$compiler_rustc_bin" -vV',
                'run_sealed "$compiler_rustc_bin" -vV',
            ),
        ),
        (
            "unchecked compiler launch",
            darwin_child_exec_probe.replace(
                'if [ "$(run_sealed /usr/bin/env "$compiler_rustc_bin" -vV)" != "$expected_darwin_rustc_version" ]; then',
                'if ! run_sealed /usr/bin/env "$compiler_rustc_bin" -vV >/dev/null; then',
            ),
        ),
    ):
        mutated_gate = gate.replace(darwin_child_exec_probe, replacement, 1)
        if mutated_gate == gate or mutated_gate.count(darwin_child_exec_probe) != 0:
            raise AssertionError(f"sealed Darwin child-exec probe {name} mutation was accepted")
    signal_diagnostic = '''status=$?
if [ "$status" -gt 128 ]; then
    echo "sealed Darwin command returned signal-style status $status (signal $((status - 128)))" >&2
fi'''

    def signal_diagnostic_is_exact(candidate: str) -> bool:
        if (
            candidate.count(signal_diagnostic) != 1
            or candidate.count('    "$@"\n' + signal_diagnostic) != 1
            or candidate.count('exit "$status"') != 1
        ):
            return False
        return (
            candidate.index(signal_diagnostic)
            < candidate.index("# This account is unique to this gate")
            < candidate.index('exit "$status"')
        )

    if not signal_diagnostic_is_exact(darwin_wrapper):
        raise AssertionError("sealed Darwin signal diagnostic is not exact")
    signal_mutations = {
        "missing": darwin_wrapper.replace(signal_diagnostic, "status=$?", 1),
        "broadened threshold": darwin_wrapper.replace(
            'if [ "$status" -gt 128 ]; then', 'if [ "$status" -ge 128 ]; then', 1
        ),
        "relocated after exit": darwin_wrapper.replace(signal_diagnostic + "\n", "", 1).replace(
            'exit "$status"', 'exit "$status"\n' + signal_diagnostic, 1
        ),
    }
    for name, mutated_diagnostic in signal_mutations.items():
        if mutated_diagnostic == darwin_wrapper or signal_diagnostic_is_exact(mutated_diagnostic):
            raise AssertionError(f"sealed Darwin signal diagnostic {name} mutation was accepted")
    for name, wrapper, minimum in (
        ("Darwin", darwin_wrapper, 20),
        ("Linux", linux_wrapper, 20),
    ):
        if (
            wrapper.count('if [ "$#" -lt 20 ]') != 1
            or wrapper.count('shift 19') != 1
            or wrapper.count('if [ "$#" -lt 1 ]; then') != 1
        ):
            raise AssertionError(f"sealed {name} wrapper lacks exact post-shift command check")
        def accepts(count: int) -> bool:
            return count >= minimum and count - 19 >= 1

        accepted = {count: accepts(count) for count in (19, 20, 21)}
        if accepted != {19: False, 20: True, 21: True}:
            raise AssertionError(f"sealed {name} wrapper 19/20/21 argument contract differs")
        for removed in ('if [ "$#" -lt 20 ]', 'shift 19', 'if [ "$#" -lt 1 ]; then'):
            mutated = wrapper.replace(removed, "", 1)
            if mutated == wrapper or mutated.count(removed) != 0:
                raise AssertionError(f"sealed {name} wrapper argument mutation was accepted: {removed}")
    probe_source = (ROOT / "ci/prepare-sealed-build-boundary-probe.py").read_text(encoding="utf-8")
    for token, expected in (
        ('sleep 5; printf escaped', 1),
        ('.stdin(Stdio::null())', 1),
        ('.stdout(Stdio::null())', 1),
        ('.stderr(Stdio::null())', 1),
        ('require_denied_write("SEALED_HOST_WRITE_TARGET")', 1),
        ('require_denied_write("SEALED_VAR_TMP_TARGET")', 1),
        ('require_denied_write("SEALED_INACTIVE_BUILD_TARGET")', 1),
        ('std::path::Path::new(&path).join("sealed-denied-write-probe")', 1),
        ('let wrote = fs::write(&write_path, b"boundary escape").is_ok();', 1),
        ('require_allowed_write("SEALED_BUILD_', 3),
        ('require_linux_mount_boundary();', 1),
    ):
        if probe_source.count(token) != expected:
            raise AssertionError(f"sealed boundary probe token is not exact: {token}")
    linux_probe_mount_assertion = '''#[cfg(target_os = "linux")]
fn require_linux_mount_boundary() {
    let build_roots = [
        env::var("SEALED_BUILD_HOME").expect("build home path"),
        env::var("SEALED_BUILD_TMP").expect("build temporary path"),
        env::var("SEALED_BUILD_TARGET").expect("build target path"),
    ];
    let mountinfo = fs::read_to_string("/proc/self/mountinfo").expect("Linux mountinfo");
    assert!(!mountinfo.is_empty(), "Linux mountinfo is empty");
    let mut writable_counts = [0_usize; 3];
    let mut root_read_only = false;
    for line in mountinfo.lines() {
        let mut fields = line.split_whitespace();
        let mountpoint = fields.nth(4).expect("mountinfo mountpoint");
        let options = fields.next().expect("mountinfo VFS options");
        let read_only = options.split(',').any(|option| option == "ro");
        let read_write = options.split(',').any(|option| option == "rw");
        assert_ne!(read_only, read_write, "mountinfo has ambiguous VFS access mode");
        if mountpoint == "/" {
            assert!(read_only, "Linux root mount is writable");
            root_read_only = true;
        }
        if read_write {
            let index = build_roots
                .iter()
                .position(|root| root == mountpoint)
                .expect("unexpected writable Linux mount");
            writable_counts[index] += 1;
        }
    }
    assert!(root_read_only, "Linux root mount is absent");
    assert_eq!(
        writable_counts,
        [1, 1, 1],
        "exact Linux writable mount roots must appear once each"
    );
}

#[cfg(not(target_os = "linux"))]
fn require_linux_mount_boundary() {}'''

    def linux_probe_mount_assertion_is_exact(candidate: str) -> bool:
        return (
            candidate.count(linux_probe_mount_assertion) == 1
            and candidate.count("require_linux_mount_boundary();") == 1
            and candidate.index(linux_probe_mount_assertion)
            < candidate.index("fn main()")
            < candidate.index("require_linux_mount_boundary();")
            < candidate.index('require_allowed_write("SEALED_BUILD_HOME")')
        )

    if not linux_probe_mount_assertion_is_exact(probe_source):
        raise AssertionError("post-drop Linux mount boundary assertion is not exact")
    linux_probe_mount_mutations = {
        "missing assertion": probe_source.replace(linux_probe_mount_assertion, "", 1),
        "missing call": probe_source.replace("    require_linux_mount_boundary();\n", "", 1),
        "root read-only removed": probe_source.replace(
            '            assert!(read_only, "Linux root mount is writable");\n', "", 1
        ),
        "unexpected writable accepted": probe_source.replace(
            '.expect("unexpected writable Linux mount")', ".unwrap_or(0)", 1
        ),
        "prefix writable accepted": probe_source.replace(
            ".position(|root| root == mountpoint)",
            ".position(|root| mountpoint.starts_with(root))",
            1,
        ),
        "fourth writable root": probe_source.replace(
            '        env::var("SEALED_BUILD_TARGET").expect("build target path"),',
            '        env::var("SEALED_BUILD_TARGET").expect("build target path"),\n'
            '        env::var("SEALED_INACTIVE_BUILD_TARGET").expect("inactive target path"),',
            1,
        ),
        "duplicate accepted": probe_source.replace(
            "        [1, 1, 1],", "        [writable_counts[0], 1, 1],", 1
        ),
    }
    for name, mutated in linux_probe_mount_mutations.items():
        if mutated == probe_source or linux_probe_mount_assertion_is_exact(mutated):
            raise AssertionError(f"post-drop Linux mount {name} mutation was accepted")
    supervisor = (ROOT / "ci/run-sealed-command-supervisor.py").read_text(encoding="utf-8")
    for token in (
        'if os.getpid() != 1',
        'os.waitpid(-1, os.WNOHANG)',
        'signal.SIGTERM',
        'signal.SIGKILL',
        'if descendants():',
    ):
        if supervisor.count(token) != 1:
            raise AssertionError(f"sealed Linux supervisor token is not exact: {token}")
    if gate.index('cd "$sealed_workspace"') > gate.index('tree_raw="$('):
        raise AssertionError("Cargo analysis did not enter the sealed workspace")
    plan_nested_pin = "c0cdf0e1353b32a941fb7fa34ceb5ab682c76c1f5d01e892578ea8a800a25014"
    plan_parent_pin = "45265732edffe658cb7925ad536c4c8372219cc415d4b185d67f8230dde113c7"
    if gate.count(plan_nested_pin) != 1:
        raise AssertionError("ordinary-wallet plan conformance inventory root pin is not singular")
    if gate.count(plan_parent_pin) != 1:
        raise AssertionError("ordinary-wallet plan conformance parent root pin is not singular")
    declared_plan_root = 'cat contracts/ordinary-wallet-plan/v1/nonlinkable-reference/CORPUS_ROOT_SHA256'
    if gate.count(declared_plan_root) != 1:
        raise AssertionError("ordinary-wallet plan declared corpus root check is not singular")
    plan_preflight_pin = "483952c5fa1f9aea89585f317551c728513241c8800aeaf1fca4d0e534d6ea28"
    if gate.count(plan_preflight_pin) != 1:
        raise AssertionError("ordinary-wallet plan preflight source pin is not singular")
    shell_macro_fallback_tokens = {
        "target disable rejection": (
            "ordinary-wallet plan Cargo test or documentation target was disabled"
        ),
        "test toggle": "(test|doctest|doc)[[:space:]]*=[[:space:]]*false",
        "harness toggle": "harness[[:space:]]*=",
        "required features toggle": "required-features[[:space:]]*=",
        "lexical source scan": 'plan_lexical_source="$(',
        "comment stripping": ".strip_rust_comments",
        "all-input dep-info": (
            '--emit=dep-info=- >"$gate_output/ordinary-wallet-plan.dep-info"'
        ),
        "ordinary pset import": (
            "use wasabi_liquid_native_ordinary_pset::{ConfidentialOutput, ExplicitFee};"
        ),
        "ordinary pset API rejection": (
            "ordinary-wallet plan ordinary-pset capability escaped its boundary"
        ),
        "crate attribute inventory": 'plan_crate_attributes="$(grep',
        "exact forbid unsafe": "#![forbid(unsafe_code)]",
        "exact deny docs": "#![deny(missing_docs)]",
        "path and unsafe rejection": (
            "ordinary-wallet plan path attribute or unsafe syntax escaped its boundary"
        ),
        "module inventory": 'plan_module_count="$(',
        "module attribute hash": (
            "9bf302755ec28c38c79a36f3f7945a47fe8d736d267b8373981852afa6949272"
        ),
        "outer attribute inventory": 'plan_outer_attribute_hash="$(',
        "outer attribute hash": (
            "51ebc7d7bb8f19ef7c51c0f6614e23c4f950a3caaf8a652588206492ea2c02df"
        ),
        "trait implementation inventory": 'plan_trait_impl_count="$(',
        "compiled source closure": 'plan_compiled_sources="$(',
        "compiled source closure root": (
            "expected_plan_compiled_sources='crates/ordinary-wallet-plan/src/lib.rs"
        ),
        "function-like macro scan": "plan_function_macro_count=",
        "function-like macro expression": (
            "[[:alpha:]_][[:alnum:]_]*[[:space:]]*![[:space:]]*(\\(|\\{|\\[)"
        ),
        "test thread-local pin": "plan_test_thread_local_count=",
        "test panic pin": "plan_test_panic_count=",
        "exact test panic": 'panic!("test-only ordinary-wallet plan staging unwind");',
        "function-like macro rejection": (
            "ordinary-wallet plan function-like macro surface is not the exact test-only hook"
        ),
        "normalized target fallback": "m.validate_manifest_targets()",
        "semantic authority fallback": (
            "m.validate_dependency_authority_surface(m.production_text())"
        ),
    }
    for name, token in shell_macro_fallback_tokens.items():
        if gate.count(token) != 1:
            raise AssertionError(f"ordinary-wallet plan shell {name} is not singular")
        mutated_gate = gate.replace(token, "", 1)
        if mutated_gate == gate or token in mutated_gate:
            raise AssertionError(f"ordinary-wallet plan shell {name} mutation was accepted")
    if not focused_replay_is_exact(gate):
        raise AssertionError("focused conformance replay is not exact and singular")
    focused_stanza = """run_sealed "$compiler_cargo_bin" test \\
            -p wasabi-liquid-native-wallet-facts-wire \\
            --locked \\
            --offline \\
            conformance"""
    if gate.count(focused_stanza) != 1:
        raise AssertionError("focused conformance replay stanza is not singular")
    plan_stanza = """run_sealed "$compiler_cargo_bin" test \\
            -p wasabi-liquid-native-ordinary-wallet-plan \\
            --locked \\
            --offline"""
    if gate.count(plan_stanza) != 1:
        raise AssertionError("ordinary-wallet plan replay stanza is not singular")
    required_automatic_stanzas = {
        "surface checker": "python3 -I ci/check-ordinary-wallet-plan-surface.py",
        "surface negative mutations": "python3 -I ci/test-ordinary-wallet-plan-surface.py",
        "workspace debug check": """run_sealed "$compiler_cargo_bin" check \\
            --workspace \\
            --all-targets \\
            --all-features \\
            --locked \\
            --offline""",
        "workspace release check": """run_sealed "$compiler_cargo_bin" check \\
            --workspace \\
            --all-targets \\
            --all-features \\
            --release \\
            --locked \\
            --offline""",
        "workspace debug test": """run_sealed "$compiler_cargo_bin" test \\
            --workspace \\
            --all-targets \\
            --all-features \\
            --locked \\
            --offline""",
        "workspace release test": """run_sealed "$compiler_cargo_bin" test \\
            --workspace \\
            --all-targets \\
            --all-features \\
            --release \\
            --locked \\
            --offline""",
        "release replay": """run_sealed "$compiler_cargo_bin" test \\
            -p wasabi-liquid-native-ordinary-wallet-plan \\
            --release \\
            --locked \\
            --offline""",
        "format": 'run_sealed "$compiler_cargo_bin" fmt --all -- --check',
        "clippy": """run_sealed "$compiler_cargo_bin" clippy \\
            --workspace \\
            --all-targets \\
            --all-features \\
            --locked \\
            --offline \\
            -- \\
            -D warnings""",
        "rustdoc": """RUSTDOCFLAGS='-D warnings' run_sealed "$compiler_cargo_bin" doc \\
            --workspace \\
            --no-deps \\
            --all-features \\
            --locked \\
            --offline""",
    }
    for name, stanza in required_automatic_stanzas.items():
        if gate.count(stanza) != 1:
            raise AssertionError(f"ordinary-wallet plan automatic {name} stanza is not singular")
        mutated_gate = gate.replace(stanza, "", 1)
        if mutated_gate.count(stanza) != 0:
            raise AssertionError(f"ordinary-wallet plan automatic {name} removal was accepted")
        required_flags = {
            "workspace debug check": ["--workspace", "--all-targets", "--all-features", "--locked", "--offline"],
            "workspace release check": ["--workspace", "--all-targets", "--all-features", "--release", "--locked", "--offline"],
            "workspace debug test": ["--workspace", "--all-targets", "--all-features", "--locked", "--offline"],
            "workspace release test": ["--workspace", "--all-targets", "--all-features", "--release", "--locked", "--offline"],
            "release replay": ["--release", "--locked", "--offline"],
            "clippy": ["--workspace", "--all-targets", "--all-features", "--locked", "--offline", "-D warnings"],
            "rustdoc": ["--workspace", "--no-deps", "--all-features", "--locked", "--offline", "-D warnings"],
        }.get(name, [])
        for required_flag in required_flags:
            if stanza.count(required_flag) != 1:
                raise AssertionError(
                    f"ordinary-wallet plan automatic {name} {required_flag} is not singular"
                )
            mutated_stanza = stanza.replace(required_flag, "", 1)
            mutated_gate = gate.replace(stanza, mutated_stanza, 1)
            if mutated_gate == gate or mutated_gate.count(stanza) != 0:
                raise AssertionError(
                    f"ordinary-wallet plan automatic {name} {required_flag} mutation was accepted"
                )
    for name, mutated_stanza in {
        "verb": plan_stanza.replace(" test \\", " check \\", 1),
        "package": plan_stanza.replace(
            "wasabi-liquid-native-ordinary-wallet-plan",
            "wasabi-liquid-native-wallet-facts",
            1,
        ),
        "locked": plan_stanza.replace("            --locked \\\n", "", 1),
        "offline": plan_stanza.replace("            --offline", "", 1),
    }.items():
        mutated_gate = gate.replace(plan_stanza, mutated_stanza, 1)
        if mutated_gate == gate or mutated_gate.count(plan_stanza) != 0:
            raise AssertionError(f"ordinary-wallet plan replay {name} mutation was accepted")
    replay_mutations = {
        "verb": focused_stanza.replace(" test \\", " check \\", 1),
        "package": focused_stanza.replace(
            "wasabi-liquid-native-wallet-facts-wire",
            "wasabi-liquid-native-wallet-facts",
            1,
        ),
        "filter": focused_stanza.replace("conformance", "codec", 1),
        "locked": focused_stanza.replace("            --locked \\\n", "", 1),
        "offline": focused_stanza.replace("            --offline \\\n", "", 1),
    }
    for name, mutated_stanza in replay_mutations.items():
        mutated_gate = gate.replace(focused_stanza, mutated_stanza, 1)
        if mutated_gate == gate or focused_replay_is_exact(mutated_gate):
            raise AssertionError(f"focused replay {name} mutation was accepted")

    parent_root = scratch / "reclosed-parent-root"
    (parent_root / REFERENCE.parent).mkdir(parents=True)
    shutil.copytree(ROOT / REFERENCE, parent_root / REFERENCE)
    wire = parent_root / REFERENCE / "WIRE_FORMAT_V1.md"
    wire.write_text(wire.read_text().replace("Status: nonlinkable reference", "Status: changed reference", 1))
    close_checksums(parent_root)
    expect_conformance(parent_root, success=True)
    changed_parent = hashlib.sha256((parent_root / REFERENCE / "SHA256SUMS").read_bytes()).hexdigest()
    if changed_parent == parent_pin:
        raise AssertionError("reclosed WIRE_FORMAT change retained the accepted parent root")

    marker = 'python3 -I - "$repository_root" <<\'PY\'\n'
    if gate.count(marker) != 1:
        raise AssertionError("lock proof is missing or duplicated")
    snippet = gate.split(marker, 1)[1].split("\nPY\n", 1)[0] + "\n"

    def lock_root(name: str) -> Path:
        target = scratch / name
        (target / "ci").mkdir(parents=True)
        shutil.copy2(ROOT / "Cargo.lock", target / "Cargo.lock")
        shutil.copy2(
            ROOT / "ci/expected-wallet-facts-conformance-lock-baseline.txt",
            target / "ci/expected-wallet-facts-conformance-lock-baseline.txt",
        )
        return target

    valid = lock_root("lock-valid")
    expect_lock_snippet(snippet, valid, success=True)

    unrelated = lock_root("lock-unrelated-byte")
    (unrelated / "Cargo.lock").write_text(
        (unrelated / "Cargo.lock").read_text().replace("version = 4", "version = 3", 1)
    )
    expect_lock_snippet(snippet, unrelated, success=False)

    other_edge = lock_root("lock-other-edge")
    (other_edge / "Cargo.lock").write_text(
        (other_edge / "Cargo.lock").read_text().replace(' "base58ck",', ' "bech32",', 1)
    )
    expect_lock_snippet(snippet, other_edge, success=False)

    wire_edge = lock_root("lock-wire-edge")
    (wire_edge / "Cargo.lock").write_text(
        (wire_edge / "Cargo.lock").read_text().replace(' "sha2",\n', "", 1)
    )
    expect_lock_snippet(snippet, wire_edge, success=False)

    facts_provider_edge = lock_root("lock-wallet-facts-provider-edge")
    remove_lock_dependency(
        facts_provider_edge,
        "wasabi-liquid-native-wallet-facts",
        "wasabi-liquid-native-output-opening",
    )
    expect_lock_snippet(snippet, facts_provider_edge, success=False)

    composer_provider_edge = lock_root("lock-composer-provider-edge")
    remove_lock_dependency(
        composer_provider_edge,
        "wasabi-liquid-native-ordinary-wallet-pset",
        "wasabi-liquid-native-output-opening",
    )
    expect_lock_snippet(snippet, composer_provider_edge, success=False)

    baseline = lock_root("lock-baseline")
    (baseline / "ci/expected-wallet-facts-conformance-lock-baseline.txt").write_text("0" * 64 + "\n")
    expect_lock_snippet(snippet, baseline, success=False)

    changed_pin = snippet.replace(
        "f30d4a8bfc6b43f61fb7eefdd0d86f866ebef815d5aa57cc2b5b3319023fcf25",
        "0" * 64,
        1,
    )
    expect_lock_snippet(changed_pin, valid, success=False)
    changed_provider_pin = snippet.replace(
        "5d105ea8138170cac5501f42d148855b9b9141d38b3c2b9532a246a4d5dc9ade",
        "0" * 64,
        1,
    )
    expect_lock_snippet(changed_provider_pin, valid, success=False)
    changed_plan_pin = snippet.replace(
        "3287e329ab3d1b9868cb5eb3c39b1713a0d660b0dcd35100688bfb7c7a867178",
        "0" * 64,
        1,
    )
    expect_lock_snippet(changed_plan_pin, valid, success=False)


def main() -> None:
    if REAL_CARGO is None:
        raise RuntimeError("cargo is unavailable")

    with tempfile.TemporaryDirectory(prefix="wasabi-liquid-capability-gate-") as directory:
        scratch = Path(directory)
        test_conformance_checker(scratch)
        test_public_proof_preflight_blocks_build_script(scratch)
        test_gate_wiring_and_lock_proof(scratch)


if __name__ == "__main__":
    main()
