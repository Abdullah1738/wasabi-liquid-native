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
        and gate.count("check-sealed-rust-command-bin.py") == 10
        and gate.count("check_sealed_command_bin >/dev/null") == 4
        and copied_toolchain < copied_check < toolchain_seal < root_handoff < root_check
    ):
        raise AssertionError("constructed Rust toolchain validation ordering is not exact")
    sealed_command_checker = (ROOT / "ci/check-sealed-rust-command-bin.py").read_text(
        encoding="utf-8"
    )
    sealed_command_checker_main = '''def main() -> int:
    if len(sys.argv) == 3 and sys.argv[1] == "--digest":
        try:
            print(stable_digest(Path(sys.argv[2]))[1])
        except (OSError, ValueError) as error:
            print(f"sealed Darwin command digest failed: {error}", file=sys.stderr)
            return 1
        return 0
    if len(sys.argv) not in (3, 23):
        print(
            "usage: check-sealed-rust-command-bin.py ABSOLUTE_BIN ABSOLUTE_TOOLCHAIN [10 DARWIN TARGETS AND 10 SHA256 DIGESTS]",
            file=sys.stderr,
        )
        return 2
    try:
        darwin_targets = (
            None
            if len(sys.argv) == 3
            else dict(zip(DARWIN_COMMANDS, map(Path, sys.argv[3:13]), strict=True))
        )
        darwin_digests = (
            None
            if len(sys.argv) == 3
            else dict(zip(DARWIN_COMMANDS, sys.argv[13:23], strict=True))
        )
        if darwin_digests is not None and any(
            len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest)
            for digest in darwin_digests.values()
        ):
            raise ValueError("sealed Darwin command digest is noncanonical")
        validate(Path(sys.argv[1]), Path(sys.argv[2]), 0, darwin_targets, darwin_digests)
    except (OSError, ValueError) as error:
        print(f"sealed Rust command check failed: {error}", file=sys.stderr)
        return 1
    print("sealed Rust command authority accepted")
    return 0'''
    sealed_command_checker_entrypoint = '''if __name__ == "__main__":
    raise SystemExit(main())'''
    sealed_command_checker_tokens = (
        sealed_command_checker_main,
        'DARWIN_COMMANDS = ("cc", "c++", "clang", "clang++", "ar", "as", "ld", "nm", "ranlib", "strip")',
        "def stable_digest(path: Path) -> tuple[os.stat_result, str]:",
        "or stat.S_IMODE(before.st_mode) & 0o022",
        "descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)",
        "value.st_ctime_ns,",
        'raise ValueError("sealed Darwin command target changed before hashing")',
        'raise ValueError("sealed Darwin command target changed while hashing")',
        "if (darwin_targets is None) != (darwin_digests is None)",
        "tuple(darwin_targets) != DARWIN_COMMANDS",
        "tuple(darwin_digests or {}) != DARWIN_COMMANDS",
        'digest != (darwin_digests or {})[name]',
        'if len(sys.argv) == 3 and sys.argv[1] == "--digest":',
        "if len(sys.argv) not in (3, 23):",
        "dict(zip(DARWIN_COMMANDS, map(Path, sys.argv[3:13]), strict=True))",
        "dict(zip(DARWIN_COMMANDS, sys.argv[13:23], strict=True))",
        'len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest)',
    )

    def sealed_command_checker_is_exact(candidate: str) -> bool:
        return (
            all(candidate.count(token) == 1 for token in sealed_command_checker_tokens)
            and candidate.count("def main() -> int:") == 1
            and candidate.count("def validate(") == 1
            and candidate.count('if __name__ == "__main__":') == 1
            and candidate.count('raise SystemExit(main())') == 1
            and candidate.endswith(sealed_command_checker_entrypoint + "\n")
            and candidate.index(sealed_command_checker_main)
            < candidate.index(sealed_command_checker_entrypoint)
            < candidate.index('raise SystemExit(main())')
            and all(
                forbidden not in candidate
                for forbidden in (
                    "follow_symlinks=True",
                    "os.access(",
                    "hashlib.md5",
                    "hashlib.sha1",
                    "main =",
                    "globals(",
                )
            )
        )

    if not sealed_command_checker_is_exact(sealed_command_checker):
        raise AssertionError("sealed Darwin command checker is not exact")
    for token in sealed_command_checker_tokens:
        mutated = sealed_command_checker.replace(token, "", 1)
        if mutated == sealed_command_checker or sealed_command_checker_is_exact(mutated):
            raise AssertionError(f"sealed Darwin command checker mutation was accepted: {token}")
    for name, original, replacement in (
        ("writable target", "or stat.S_IMODE(before.st_mode) & 0o022", "or False"),
        (
            "unbound content",
            'digest != (darwin_digests or {})[name]',
            "False",
        ),
        ("followed target", "os.O_RDONLY | os.O_NOFOLLOW", "os.O_RDONLY"),
        ("wrong Darwin arity", "if len(sys.argv) not in (3, 23):", "if len(sys.argv) < 3:"),
        (
            "early main return",
            sealed_command_checker_main,
            sealed_command_checker_main.replace(
                "def main() -> int:\n", "def main() -> int:\n    return 0\n", 1
            ),
        ),
        (
            "early successful entrypoint",
            sealed_command_checker_main,
            sealed_command_checker_main
            + '\n\n\nif __name__ == "__main__":\n    raise SystemExit(0)',
        ),
    ):
        mutated = sealed_command_checker.replace(original, replacement, 1)
        if mutated == sealed_command_checker or sealed_command_checker_is_exact(mutated):
            raise AssertionError(f"sealed Darwin command checker {name} mutation was accepted")
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
        'WLPQ_TEST_DARWIN_SDKROOT="$darwin_sdkroot" \\\n'
        '    python3 -I ci/test-ordinary-wallet-plan-proof-snapshot.py "$source_cargo_home"'
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
    proof_snapshot_test = (ROOT / "ci/test-ordinary-wallet-plan-proof-snapshot.py").read_text(
        encoding="utf-8"
    )
    for token in (
        'TEST_DARWIN_SDKROOT_VARIABLE = "WLPQ_TEST_DARWIN_SDKROOT"',
        'darwin_sdkroot = environment.pop(TEST_DARWIN_SDKROOT_VARIABLE, "")',
        'if sys.platform == "darwin":',
        'if not sdkroot.is_absolute() or sdkroot.is_symlink() or not sdkroot.is_dir():',
        'environment["SDKROOT"] = str(sdkroot)',
        'elif darwin_sdkroot:',
        'build_environment = controlled_build_environment(scratch)',
    ):
        if proof_snapshot_test.count(token) != 1:
            raise AssertionError(f"private proof snapshot Darwin SDK boundary is not exact: {token}")
    if 'environment["DEVELOPER_DIR"]' in proof_snapshot_test:
        raise AssertionError("private proof snapshot inherited a Darwin developer-directory override")
    snapshot_preparer_source = (
        ROOT / "ci/prepare-ordinary-wallet-plan-proof-snapshot.py"
    ).read_text(encoding="utf-8")
    cargo_binary_authority_tokens = (
        "or before.st_uid != expected_uid",
        "or dep_info_metadata.st_uid != expected_uid",
        "value.st_ctime_ns,",
        "binary_identity(os.fstat(top_descriptor)) != binary_identity(top_metadata)",
        "or binary_identity(os.fstat(dependency_descriptor))",
        "or binary_identity(os.lstat(top_binary)) != binary_identity(top_metadata)",
        "or binary_identity(os.lstat(dependency_binary))",
    )

    def cargo_binary_authority_is_exact(candidate: str) -> bool:
        return all(candidate.count(token) == 1 for token in cargo_binary_authority_tokens)

    if not cargo_binary_authority_is_exact(snapshot_preparer_source):
        raise AssertionError("Cargo proof binary ownership and race authority is not exact")
    for token in cargo_binary_authority_tokens:
        mutated = snapshot_preparer_source.replace(token, "", 1)
        if mutated == snapshot_preparer_source or cargo_binary_authority_is_exact(mutated):
            raise AssertionError(
                f"Cargo proof binary authority mutation was accepted: {token}"
            )
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
    plan_mutation_test = (ROOT / "ci/test-ordinary-wallet-plan-conformance.py").read_text(
        encoding="utf-8"
    )
    mutable_copy_helper = '''def copy_mutable_tree(source: Path, destination: Path) -> None:
    source_metadata = os.lstat(source)
    if stat.S_ISLNK(source_metadata.st_mode) or not stat.S_ISDIR(source_metadata.st_mode):
        raise AssertionError("mutable corpus copy source root is linked or not a directory")
    shutil.copytree(source, destination, symlinks=True)
    for directory, directories, files in os.walk(
        destination,
        topdown=False,
        followlinks=False,
    ):
        directory_path = Path(directory)
        for name in files:
            path = directory_path / name
            metadata = os.lstat(path)
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
                raise AssertionError("mutable corpus copy contains a linked or special file")
            os.chmod(path, 0o600)
        for name in directories:
            path = directory_path / name
            metadata = os.lstat(path)
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
                raise AssertionError("mutable corpus copy contains a linked or non-directory entry")
            os.chmod(path, 0o700)
        os.chmod(directory_path, 0o700)'''
    mutable_copy_test_tokens = (
        'os.chmod(source_file, 0o444)',
        'os.chmod(nested, 0o555)',
        'os.chmod(source, 0o555)',
        'stat.S_IMODE(os.lstat(source).st_mode) != 0o555',
        'stat.S_IMODE(os.lstat(nested).st_mode) != 0o555',
        'stat.S_IMODE(os.lstat(source_file).st_mode) != 0o444',
        'stat.S_IMODE(os.lstat(destination).st_mode) != 0o700',
        'stat.S_IMODE(os.lstat(destination / "nested").st_mode) != 0o700',
        'stat.S_IMODE(os.lstat(destination_file).st_mode) != 0o600',
        'destination_file.write_text("changed\\n", encoding="utf-8", newline="\\n")',
        'created.write_text("created\\n", encoding="utf-8", newline="\\n")',
        'created.unlink()',
        'for name, directory_link in (("file-link", False), ("directory-link", True)):',
        'test_mutable_copy_modes(scratch)',
    )

    def mutable_copy_boundary_is_exact(candidate: str) -> bool:
        return (
            candidate.count(mutable_copy_helper) == 1
            and candidate.count('copy_mutable_tree(ROOT / "contracts", target / "contracts")') == 1
            and candidate.count("copy_mutable_contracts(target)") == 1
            and candidate.count("copy_mutable_contracts(valid)") == 1
            and candidate.count("shutil.copytree(") == 1
            and all(candidate.count(token) == 1 for token in mutable_copy_test_tokens)
        )

    if not mutable_copy_boundary_is_exact(plan_mutation_test):
        raise AssertionError("ordinary-wallet plan mutable corpus copy boundary is not exact")
    for name, original, replacement in (
        ("followed links", "followlinks=False", "followlinks=True"),
        ("dereferenced copy links", "symlinks=True", "symlinks=False"),
        ("writable source file", "os.chmod(path, 0o600)", "os.chmod(source / path.relative_to(destination), 0o600)"),
        ("nonwritable copy file", "os.chmod(path, 0o600)", "os.chmod(path, 0o400)"),
        ("nonwritable copy directory", "os.chmod(path, 0o700)", "os.chmod(path, 0o500)"),
        (
            "accepted linked file",
            "if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):",
            "if not stat.S_ISREG(metadata.st_mode):",
        ),
        (
            "accepted linked directory",
            "if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):",
            "if not stat.S_ISDIR(metadata.st_mode):",
        ),
        ("direct mutable copy", "copy_mutable_contracts(target)", 'shutil.copytree(ROOT / "contracts", target / "contracts")'),
        ("missing mode regression", "test_mutable_copy_modes(scratch)", ""),
    ):
        mutated = plan_mutation_test.replace(original, replacement, 1)
        if mutated == plan_mutation_test or mutable_copy_boundary_is_exact(mutated):
            raise AssertionError(f"ordinary-wallet plan mutable copy {name} mutation was accepted")
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
        "dep-info path": ('"$proof_dep_info"', 5),
        "direct binary execution": ('"$proof_binary" "$proof_snapshot"', 1),
        "binary digest": ("--binary-digest \"$proof_binary\"", 2),
    }.items():
        if gate.count(token) != expected_count:
            raise AssertionError(f"ordinary-wallet plan public proof verifier {name} is not singular")
    snapshot_preparer = "python3 -I ci/prepare-ordinary-wallet-plan-proof-snapshot.py"
    if (
        gate.count(snapshot_preparer) != 33
        or gate.count("    --verify \\\n") != 4
        or gate.count("    --verify-cache \\\n") != 3
        or gate.count("--verify-tree \\\n") != 11
        or gate.count("    --workspace-cache \\\n") != 1
        or gate.count("    --copy-cache \\\n") != 3
        or gate.count("    --snapshot-only \\\n") != 1
        or gate.count("        --finalize-cache \\\n") != 2
        or gate.count("        --seal-tree \\\n") != 4
        or gate.count("    --seal-binary \\\n") != 1
    ):
        raise AssertionError("ordinary-wallet plan private proof state checks are not exact")
    sealed_binary_stanza = '''proof_binary="$sealed_proof_binary"
python3 -I ci/prepare-ordinary-wallet-plan-proof-snapshot.py \\
    --seal-binary \\
    "$proof_target" \\
    "$proof_dep_info" \\
    "$proof_binary" \\
    "$build_uid"
/usr/bin/sudo -n "$chown_bin" 0 "$proof_binary"
/usr/bin/sudo -n /bin/chmod 0555 "$proof_binary"
proof_binary_sha256="$(python3 -I ci/prepare-ordinary-wallet-plan-proof-snapshot.py --binary-digest "$proof_binary")"'''
    if (
        gate.count('sealed_proof_binary="$scratch/ordinary-wallet-plan-public-proof-verifier"') != 1
        or gate.count(sealed_binary_stanza) != 1
        or gate.count('"$proof_target/debug/ordinary-wallet-plan-public-proof-verifier"') != 0
        or not (
            gate.index(proof_build_stanza)
            < gate.index('proof_dep_info="$(')
            < gate.index(sealed_binary_stanza)
            < gate.index('run_sealed "$proof_binary" "$proof_snapshot"')
        )
    ):
        raise AssertionError("ordinary-wallet plan sealed proof binary handoff is not exact")
    for name, replacement in (
        ("missing seal", sealed_binary_stanza.replace('    --seal-binary \\\n', "", 1)),
        ("live target binary", sealed_binary_stanza.replace('proof_binary="$sealed_proof_binary"', 'proof_binary="$proof_target/debug/ordinary-wallet-plan-public-proof-verifier"', 1)),
        ("missing root handoff", sealed_binary_stanza.replace('/usr/bin/sudo -n "$chown_bin" 0 "$proof_binary"\n', "", 1)),
        ("writable sealed binary", sealed_binary_stanza.replace('/usr/bin/sudo -n /bin/chmod 0555 "$proof_binary"', '/usr/bin/sudo -n /bin/chmod 0755 "$proof_binary"', 1)),
        ("unsealed first digest", sealed_binary_stanza.replace('--binary-digest "$proof_binary"', '--binary-digest "$proof_target/debug/ordinary-wallet-plan-public-proof-verifier"', 1)),
    ):
        mutated = gate.replace(sealed_binary_stanza, replacement, 1)
        if mutated == gate or mutated.count(sealed_binary_stanza) != 0:
            raise AssertionError(f"ordinary-wallet plan proof binary {name} mutation was accepted")
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
        'proof_binary="$sealed_proof_binary"',
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

    darwin_sealed_command_check_helper = '''check_sealed_command_bin() {
    if [ "$host_system" = Darwin ]; then
        for darwin_command_target in \\
            "$darwin_cc_bin" "$darwin_cxx_bin" "$darwin_ar_bin" "$darwin_as_bin" \\
            "$darwin_ld_bin" "$darwin_nm_bin" "$darwin_ranlib_bin" "$darwin_strip_bin"; do
            darwin_require_host_authority_path "$darwin_command_target" 'Regular File'
        done
        python3 -I ci/check-sealed-rust-command-bin.py \\
            "$sealed_command_bin" "$sealed_toolchain" \\
            "$darwin_cc_bin" "$darwin_cxx_bin" "$darwin_cc_bin" "$darwin_cxx_bin" \\
            "$darwin_ar_bin" "$darwin_as_bin" "$darwin_ld_bin" "$darwin_nm_bin" \\
            "$darwin_ranlib_bin" "$darwin_strip_bin" \\
            "$darwin_cc_sha256" "$darwin_cxx_sha256" "$darwin_cc_sha256" "$darwin_cxx_sha256" \\
            "$darwin_ar_sha256" "$darwin_as_sha256" "$darwin_ld_sha256" "$darwin_nm_sha256" \\
            "$darwin_ranlib_sha256" "$darwin_strip_sha256"
    else
        python3 -I ci/check-sealed-rust-command-bin.py "$sealed_command_bin" "$sealed_toolchain"
    fi
}'''
    darwin_system_exec_authority = '''    for darwin_system_exec in \\
        /usr/bin/env /bin/sh /bin/bash /bin/pwd /bin/sleep /bin/zsh /usr/bin/dirname /bin/realpath; do
        darwin_require_host_authority_path "$darwin_system_exec" 'Regular File'
    done'''
    darwin_toolchain_authority_tokens = (
        'prepare_darwin_toolchain() {',
        'expected_darwin_developer_dir=/Applications/Xcode_15.4.app/Contents/Developer',
        'expected_darwin_sdkroot="$expected_darwin_developer_dir/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk"',
        "expected_darwin_xcode_version='Xcode 15.4\nBuild version 15F31d'",
        'darwin_host_uid="$(/usr/bin/id -u)"',
        'case "$darwin_host_uid" in *[!0-9]*|\'\')',
        'darwin_require_host_authority_path() {',
        'authority_state="$(/usr/bin/sudo -n /usr/bin/stat -f \'%u:%OLp:%HT\' "$authority_path")"',
        'if { [ "$authority_uid" != 0 ] && [ "$authority_uid" != "$darwin_host_uid" ]; } || [ "$authority_actual_type" != "$authority_type" ]; then',
        '*[2367][0-7]|*[0-7][2367])',
        'darwin_resolve_tool() {',
        'link_name="$(/usr/bin/readlink "$tool_path")"',
        "case \"$link_name\" in ''|.|..|*/*)",
        'if [ "$link_depth" -gt 8 ]; then',
        'tool_parent="$(cd -P "${tool_path%/*}" && /bin/pwd -P)"',
        'case "$tool_path" in "$darwin_toolchain_bin"/*)',
        'darwin_require_host_authority_path "$tool_path" \'Regular File\'',
        'darwin_developer_dir="$(/usr/bin/xcode-select --print-path)"',
        'if [ "$darwin_developer_dir" != "$expected_darwin_developer_dir" ]; then',
        'darwin_require_host_authority_path "$darwin_developer_dir" \'Directory\'',
        'darwin_require_host_authority_path "$darwin_xcodebuild" \'Regular File\'',
        'if [ "$("$darwin_xcodebuild" -version)" != "$expected_darwin_xcode_version" ]; then',
        'darwin_sdkroot="$(DEVELOPER_DIR="$darwin_developer_dir" /usr/bin/xcrun --sdk macosx --show-sdk-path)"',
        'if [ "$darwin_sdkroot" != "$expected_darwin_sdkroot" ]; then',
        'darwin_require_host_authority_path "$darwin_sdkroot" \'Directory\'',
        'darwin_toolchain_bin="$(cd -P "$darwin_toolchain_bin" && /bin/pwd -P)"',
        'darwin_require_host_authority_path "$darwin_toolchain_bin" \'Directory\'',
        'if [ "$(DEVELOPER_DIR="$darwin_developer_dir" /usr/bin/xcrun --sdk macosx --find clang)" != "$darwin_toolchain_bin/clang" ]; then',
        'darwin_cc_bin="$(darwin_resolve_tool clang)"',
        'darwin_cxx_bin="$(darwin_resolve_tool clang++)"',
        'darwin_ar_bin="$(darwin_resolve_tool ar)"',
        'darwin_as_bin="$(darwin_resolve_tool as)"',
        'darwin_ld_bin="$(darwin_resolve_tool ld)"',
        'darwin_nm_bin="$(darwin_resolve_tool nm)"',
        'darwin_ranlib_bin="$(darwin_resolve_tool ranlib)"',
        'darwin_strip_bin="$(darwin_resolve_tool strip)"',
        'darwin_cc_sha256="$("$python_bin" -I ci/check-sealed-rust-command-bin.py --digest "$darwin_cc_bin")"',
        'darwin_cxx_sha256="$("$python_bin" -I ci/check-sealed-rust-command-bin.py --digest "$darwin_cxx_bin")"',
        'darwin_ar_sha256="$("$python_bin" -I ci/check-sealed-rust-command-bin.py --digest "$darwin_ar_bin")"',
        'darwin_as_sha256="$("$python_bin" -I ci/check-sealed-rust-command-bin.py --digest "$darwin_as_bin")"',
        'darwin_ld_sha256="$("$python_bin" -I ci/check-sealed-rust-command-bin.py --digest "$darwin_ld_bin")"',
        'darwin_nm_sha256="$("$python_bin" -I ci/check-sealed-rust-command-bin.py --digest "$darwin_nm_bin")"',
        'darwin_ranlib_sha256="$("$python_bin" -I ci/check-sealed-rust-command-bin.py --digest "$darwin_ranlib_bin")"',
        'darwin_strip_sha256="$("$python_bin" -I ci/check-sealed-rust-command-bin.py --digest "$darwin_strip_bin")"',
        darwin_system_exec_authority,
        'for system_name in awk bash cat chmod diff env find git grep head id make mkdir mktemp perl rm sed sh sort tr uname wc; do',
        'link_trusted_tool cc "$darwin_cc_bin"',
        'link_trusted_tool c++ "$darwin_cxx_bin"',
        'link_trusted_tool ar "$darwin_ar_bin"',
        'link_trusted_tool as "$darwin_as_bin"',
        'link_trusted_tool ld "$darwin_ld_bin"',
        'link_trusted_tool nm "$darwin_nm_bin"',
        'link_trusted_tool ranlib "$darwin_ranlib_bin"',
        'link_trusted_tool strip "$darwin_strip_bin"',
        '/bin/ln -s "$darwin_cc_bin" "$sealed_command_bin/cc"',
        '/bin/ln -s "$darwin_cxx_bin" "$sealed_command_bin/c++"',
        '/bin/ln -s "$darwin_cc_bin" "$sealed_command_bin/clang"',
        '/bin/ln -s "$darwin_cxx_bin" "$sealed_command_bin/clang++"',
        '/bin/ln -s "$darwin_ar_bin" "$sealed_command_bin/ar"',
        '/bin/ln -s "$darwin_as_bin" "$sealed_command_bin/as"',
        '/bin/ln -s "$darwin_ld_bin" "$sealed_command_bin/ld"',
        '/bin/ln -s "$darwin_nm_bin" "$sealed_command_bin/nm"',
        '/bin/ln -s "$darwin_ranlib_bin" "$sealed_command_bin/ranlib"',
        '/bin/ln -s "$darwin_strip_bin" "$sealed_command_bin/strip"',
        darwin_sealed_command_check_helper,
        'for system_name in ar as cc c++ ld nm ranlib strip; do',
        '\nprepare_darwin_toolchain\n',
        '                "$darwin_sdkroot" \\\n                "${@}"',
    )

    def darwin_toolchain_authority_is_exact(candidate: str) -> bool:
        if any(candidate.count(token) != 1 for token in darwin_toolchain_authority_tokens):
            return False
        if any(
            token in candidate
            for token in (
                'link_system_tool xcrun',
                '/Library/Developer/CommandLineTools',
                '/var/folders',
                'xcrun_nocache',
            )
        ):
            return False
        return (
            candidate.index('prepare_darwin_toolchain() {')
            < candidate.index('"$python_bin" -I ci/check-ordinary-wallet-plan-public-proof-surface.py')
            < candidate.index('if ! /usr/bin/sudo -n true; then')
            < candidate.index('\nprepare_darwin_toolchain\n')
            < candidate.index('trusted_bin="$scratch/trusted-bin"')
            < candidate.index('link_trusted_tool cc "$darwin_cc_bin"')
            < candidate.index('sealed_command_bin="$scratch/sealed-rust-command-bin"')
            < candidate.index('/bin/ln -s "$darwin_cc_bin" "$sealed_command_bin/cc"')
            < candidate.index(darwin_sealed_command_check_helper)
            < candidate.index('proof_sandbox_profile="$scratch/build-proof.sb"')
            < candidate.index('                "$darwin_sdkroot" \\\n                "${@}"')
        )

    if not darwin_toolchain_authority_is_exact(gate):
        raise AssertionError("pinned Darwin SDK and toolchain authority is not exact")
    for token in darwin_toolchain_authority_tokens:
        mutated = gate.replace(token, "", 1)
        if mutated == gate or darwin_toolchain_authority_is_exact(mutated):
            raise AssertionError(f"Darwin toolchain authority mutation was accepted: {token}")
    for name, mutation in (
        (
            "unversioned Xcode",
            gate.replace("/Applications/Xcode_15.4.app", "/Applications/Xcode.app", 1),
        ),
        (
            "ambient SDK resolution",
            gate.replace(
                'DEVELOPER_DIR="$darwin_developer_dir" /usr/bin/xcrun --sdk macosx --show-sdk-path',
                '/usr/bin/xcrun --sdk macosx --show-sdk-path',
                1,
            ),
        ),
        (
            "system compiler shim",
            gate.replace('link_trusted_tool cc "$darwin_cc_bin"', 'link_system_tool cc', 1),
        ),
        (
            "trusted xcrun shim",
            gate.replace(
                'link_trusted_tool cc "$darwin_cc_bin"',
                'link_system_tool xcrun\n    link_trusted_tool cc "$darwin_cc_bin"',
                1,
            ),
        ),
        (
            "sealed system compiler shim",
            gate.replace(
                '/bin/ln -s "$darwin_cc_bin" "$sealed_command_bin/cc"',
                '/bin/ln -s /usr/bin/cc "$sealed_command_bin/cc"',
                1,
            ),
        ),
        (
            "sealed checker early return",
            gate.replace(
                darwin_sealed_command_check_helper,
                darwin_sealed_command_check_helper.replace(
                    'check_sealed_command_bin() {\n',
                    'check_sealed_command_bin() {\n    return 0\n',
                    1,
                ),
                1,
            ),
        ),
        (
            "sealed checker wrong platform",
            gate.replace(
                darwin_sealed_command_check_helper,
                darwin_sealed_command_check_helper.replace(
                    '[ "$host_system" = Darwin ]', '[ "$host_system" = Linux ]', 1
                ),
                1,
            ),
        ),
        (
            "sealed checker dropped digest",
            gate.replace(
                darwin_sealed_command_check_helper,
                darwin_sealed_command_check_helper.replace(' "$darwin_strip_sha256"', '', 1),
                1,
            ),
        ),
    ):
        if mutation == gate or darwin_toolchain_authority_is_exact(mutation):
            raise AssertionError(f"Darwin toolchain {name} mutation was accepted")
    writable_handoff = '''for writable in "$build_home" "$proof_target" "$workspace_target" "$build_tmp"; do
    /usr/bin/sudo -n "$chown_bin" "$build_uid" "$writable"
    /usr/bin/sudo -n /bin/chmod 0700 "$writable"
done
/usr/bin/sudo -n /bin/chmod 0755 "$proof_target" "$workspace_target"'''
    denied_write_handoff = '''for denied_write in "$host_write_target" "$var_tmp_target"; do
    /usr/bin/sudo -n "$chown_bin" "$build_uid" "$denied_write"
    /usr/bin/sudo -n /bin/chmod 0600 "$denied_write"
done'''
    darwin_var_tmp_physical_stanza = '''if [ "$host_system" = Darwin ]; then
    var_tmp_physical_target="$(/bin/realpath "$var_tmp_target")"
    if [ "$var_tmp_physical_target" != "/private$var_tmp_target" ]; then
        echo "Darwin var-tmp probe physical path differs from its exact alias" >&2
        exit 1
    fi
fi'''
    darwin_var_tmp_target_metadata = (
        r'"(allow file-read-metadata (literal \"$var_tmp_target\") '
        r'(literal \"$var_tmp_physical_target\"))"'
    )
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
    if (
        gate.count(darwin_var_tmp_physical_stanza) != 1
        or gate.count("var_tmp_physical_target=") != 2
        or not (
            gate.index('/usr/bin/sudo -n /usr/bin/touch "$var_tmp_target"')
            < gate.index(darwin_var_tmp_physical_stanza)
            < gate.index(denied_write_handoff)
            < gate.index(darwin_var_tmp_target_metadata)
        )
    ):
        raise AssertionError("Darwin physical var-tmp target derivation is not exact")
    for name, token in (
        ("physical resolution", '    var_tmp_physical_target="$(/bin/realpath "$var_tmp_target")"\n'),
        (
            "physical alias equality",
            '    if [ "$var_tmp_physical_target" != "/private$var_tmp_target" ]; then\n',
        ),
        (
            "physical alias rejection",
            '        echo "Darwin var-tmp probe physical path differs from its exact alias" >&2\n',
        ),
    ):
        mutated = gate.replace(token, "", 1)
        if mutated == gate or mutated.count(darwin_var_tmp_physical_stanza) != 0:
            raise AssertionError(f"Darwin var-tmp {name} mutation was accepted")
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
    darwin_tmp_parent_metadata = (
        "'(allow file-read-metadata (literal \"/private\") "
        "(literal \"/private/tmp\") (literal \"/private/var\") "
        "(literal \"/private/var/tmp\"))'"
    )
    darwin_system_read = (
        "'(allow file-read* (subpath \"/System\") (subpath \"/usr\") "
        "(subpath \"/bin\") (subpath \"/sbin\") (subpath \"/Applications\") "
        "(subpath \"/Library/Developer\") (subpath \"/private/etc\") "
        "(subpath \"/private/var/db\"))'"
    )
    darwin_xcode_select_read = (
        "'(allow file-read-metadata (literal \"/var\") (literal \"/var/tmp\") "
        "(literal \"/private/var/select/developer_dir\") "
        "(literal \"/private/var/select/sh\"))'"
    )
    darwin_system_map = (
        "'(allow file-map-executable (subpath \"/System\") (subpath \"/usr\") "
        "(subpath \"/bin\") (subpath \"/sbin\") (subpath \"/Applications\") "
        "(subpath \"/Library/Developer\"))'"
    )
    darwin_private_map = (
        r'"(allow file-map-executable (subpath \"$sealed_toolchain\") '
        r'(subpath \"$sealed_command_bin\") (subpath \"$profile_target\") '
        r'(literal \"$sealed_proof_binary\"))"'
    )
    darwin_process_fork = "'(allow process-fork)'"
    darwin_process_info = "'(allow process-info* (target self))'"
    darwin_system_exec = (
        "'(allow process-exec* (literal \"/usr/bin/env\") "
        "(literal \"/bin/sh\") (literal \"/bin/bash\") (literal \"/bin/pwd\") "
        "(literal \"/bin/sleep\") (literal \"/bin/zsh\") "
        "(literal \"/usr/bin/dirname\") (literal \"/bin/realpath\"))'"
    )
    darwin_xcode_exec = (
        r'"(allow process-exec* (literal \"$darwin_cc_bin\") '
        r'(literal \"$darwin_cxx_bin\") (literal \"$darwin_ar_bin\") '
        r'(literal \"$darwin_as_bin\") (literal \"$darwin_ld_bin\") '
        r'(literal \"$darwin_nm_bin\") (literal \"$darwin_ranlib_bin\") '
        r'(literal \"$darwin_strip_bin\"))"'
    )
    darwin_private_exec = (
        r'"(allow process-exec* (subpath \"$sealed_toolchain\") '
        r'(subpath \"$sealed_command_bin\") (subpath \"$profile_target\") '
        r'(literal \"$sealed_proof_binary\"))"'
    )
    darwin_private_write = (
        r'"(allow file-write* (subpath \"$build_home\") '
        r'(subpath \"$build_tmp\") (subpath \"$profile_target\"))"'
    )
    darwin_null_read = "'(allow file-read-data (literal \"/dev/null\"))'"
    darwin_allow_tokens = (
        darwin_process_fork,
        darwin_process_info,
        darwin_system_exec,
        darwin_xcode_exec,
        darwin_private_exec,
        "'(allow signal (target self))'",
        "'(allow sysctl-read)'",
        "'(allow mach-lookup)'",
        darwin_root_read,
        darwin_system_read,
        darwin_xcode_select_read,
        darwin_tmp_parent_metadata,
        r'"(allow file-read* (subpath \"$scratch\"))"',
        darwin_var_tmp_target_metadata,
        darwin_system_map,
        darwin_private_map,
        darwin_private_write,
        darwin_null_read,
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
            or candidate.count("(allow file-read") != 7
            or candidate.count("(allow file-map-executable") != 2
            or candidate.count("(allow process-exec") != 3
            or '(subpath "/")' in candidate
            or "(allow file-read*)" in candidate
            or "(allow file-map-executable)" in candidate
            or "(allow process-exec*)" in candidate
            or "(allow process*)" in candidate
            or "(allow process-info*)" in candidate
            or "(with no-sandbox)" in candidate
            or '(subpath "$scratch")' in candidate
            or '(subpath "$build_home")' in candidate
            or '(subpath "$build_tmp")' in candidate
            or '(subpath "$sealed_workspace")' in candidate
            or '(subpath "$trusted_bin")' in candidate
            or '(subpath "$proof_target")' in candidate
            or '(subpath "$workspace_target")' in candidate
            or '(subpath "$sealed_proof_binary")' in candidate
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
        ("missing process fork", darwin_process_fork, ""),
        ("broad process capability", darwin_process_fork, "'(allow process*)'"),
        ("missing self process information", darwin_process_info, ""),
        (
            "unfiltered process information",
            darwin_process_info,
            "'(allow process-info*)'",
        ),
        ("missing system child execution", darwin_system_exec, ""),
        ("missing Xcode child execution", darwin_xcode_exec, ""),
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
            "missing shell and pwd execution",
            darwin_system_exec,
            "'(allow process-exec* (literal \"/usr/bin/env\"))'",
        ),
        (
            "interpreter operation substitution",
            darwin_system_exec,
            "'(allow process-exec-interpreter (literal \"/usr/bin/env\"))'",
        ),
        (
            "broad usr child execution",
            darwin_system_exec,
            "'(allow process-exec* (subpath \"/usr\") (literal \"/bin/sh\") (literal \"/bin/pwd\"))'",
        ),
        (
            "system make child execution",
            darwin_system_exec,
            darwin_system_exec[:-2] + ' (literal "/usr/bin/make"))\'',
        ),
        (
            "broad Xcode child execution",
            darwin_xcode_exec,
            r'"(allow process-exec* (subpath \"$darwin_toolchain_bin\"))"',
        ),
        (
            "incomplete Xcode child execution",
            darwin_xcode_exec,
            darwin_xcode_exec.replace(
                r' (literal \"$darwin_strip_bin\")', "", 1
            ),
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
        (
            "missing sealed proof execution",
            darwin_private_exec,
            darwin_private_exec.replace(
                r' (literal \"$sealed_proof_binary\")', "", 1
            ),
        ),
        (
            "sealed proof subtree execution",
            darwin_private_exec,
            darwin_private_exec.replace(
                r'(literal \"$sealed_proof_binary\")',
                r'(subpath \"$sealed_proof_binary\")',
                1,
            ),
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
        (
            "missing sealed proof executable map",
            darwin_private_map,
            darwin_private_map.replace(
                r' (literal \"$sealed_proof_binary\")', "", 1
            ),
        ),
        (
            "sealed proof subtree executable map",
            darwin_private_map,
            darwin_private_map.replace(
                r'(literal \"$sealed_proof_binary\")',
                r'(subpath \"$sealed_proof_binary\")',
                1,
            ),
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
        ("missing private tmp parent metadata", darwin_tmp_parent_metadata, ""),
        (
            "private parent subtree metadata",
            darwin_tmp_parent_metadata,
            darwin_tmp_parent_metadata.replace(
                '(literal \"/private\")', '(subpath \"/private\")'
            ),
        ),
        (
            "private tmp subtree metadata",
            darwin_tmp_parent_metadata,
            darwin_tmp_parent_metadata.replace(
                '(literal \"/private/tmp\")', '(subpath \"/private/tmp\")'
            ),
        ),
        (
            "private tmp parent data read",
            darwin_tmp_parent_metadata,
            darwin_tmp_parent_metadata.replace("file-read-metadata", "file-read-data"),
        ),
        (
            "missing private parent literal",
            darwin_tmp_parent_metadata,
            darwin_tmp_parent_metadata.replace('(literal \"/private\") ', ""),
        ),
        (
            "missing private tmp literal",
            darwin_tmp_parent_metadata,
            darwin_tmp_parent_metadata.replace(' (literal \"/private/tmp\")', ""),
        ),
        (
            "missing private var parent literal",
            darwin_tmp_parent_metadata,
            darwin_tmp_parent_metadata.replace(' (literal \"/private/var\")', ""),
        ),
        (
            "missing private var tmp literal",
            darwin_tmp_parent_metadata,
            darwin_tmp_parent_metadata.replace(' (literal \"/private/var/tmp\")', ""),
        ),
        (
            "private var subtree metadata",
            darwin_tmp_parent_metadata,
            darwin_tmp_parent_metadata.replace(
                '(literal \"/private/var\")', '(subpath \"/private/var\")'
            ),
        ),
        (
            "private var tmp subtree metadata",
            darwin_tmp_parent_metadata,
            darwin_tmp_parent_metadata.replace(
                '(literal \"/private/var/tmp\")', '(subpath \"/private/var/tmp\")'
            ),
        ),
        (
            "unfiltered private metadata",
            darwin_tmp_parent_metadata,
            "'(allow file-read-metadata)'",
        ),
        (
            "private subtree read",
            darwin_tmp_parent_metadata,
            "'(allow file-read* (subpath \"/private\"))'",
        ),
        (
            "private tmp subtree read",
            darwin_tmp_parent_metadata,
            "'(allow file-read* (subpath \"/private/tmp\"))'",
        ),
        (
            "tmp subtree read",
            darwin_tmp_parent_metadata,
            "'(allow file-read* (subpath \"/tmp\"))'",
        ),
        (
            "restored device subtree read",
            darwin_system_read,
            darwin_system_read[:-2] + ' (subpath "/dev"))\'',
        ),
        ("missing system read", darwin_system_read, ""),
        ("missing Xcode selector read", darwin_xcode_select_read, ""),
        (
            "missing var tmp alias metadata",
            darwin_xcode_select_read,
            darwin_xcode_select_read.replace(' (literal \"/var/tmp\")', ""),
        ),
        (
            "broadened var tmp alias metadata",
            darwin_xcode_select_read,
            darwin_xcode_select_read.replace(
                '(literal \"/var/tmp\")', '(subpath \"/var/tmp\")'
            ),
        ),
        (
            "broadened Xcode selector read",
            darwin_xcode_select_read,
            "'(allow file-read-metadata (subpath \"/private/var\"))'",
        ),
        (
            "Xcode selector data read",
            darwin_xcode_select_read,
            darwin_xcode_select_read.replace("file-read-metadata", "file-read-data"),
        ),
        (
            "Xcode selector subtree read",
            darwin_xcode_select_read,
            "'(allow file-read-metadata (literal \"/var\") (subpath \"/private/var/select\"))'",
        ),
        (
            "missing physical var tmp target metadata",
            darwin_var_tmp_target_metadata,
            r'"(allow file-read-metadata (literal \"$var_tmp_target\"))"',
        ),
        (
            "physical var tmp target subtree metadata",
            darwin_var_tmp_target_metadata,
            darwin_var_tmp_target_metadata.replace(
                r'(literal \"$var_tmp_physical_target\")',
                r'(subpath \"$var_tmp_physical_target\")',
            ),
        ),
    ):
        mutated = gate.replace(original, replacement, 1)
        if mutated == gate or darwin_profile_is_exact(mutated):
            raise AssertionError(f"sealed Darwin {name} mutation was accepted")
    for device in ("random", "urandom", "tty", "stdin", "stdout", "stderr"):
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
    for name, replacement in (
        ("missing null-data read", ""),
        ("umbrella null read", "'(allow file-read* (literal \"/dev/null\"))'"),
        ("device subtree read", "'(allow file-read-data (subpath \"/dev\"))'"),
        ("wrong device read", "'(allow file-read-data (literal \"/dev/random\"))'"),
        (
            "additional device read",
            "'(allow file-read-data (literal \"/dev/null\") (literal \"/dev/random\"))'",
        ),
    ):
        mutated = gate.replace(darwin_null_read, replacement, 1)
        if mutated == gate or darwin_profile_is_exact(mutated):
            raise AssertionError(f"sealed Darwin {name} mutation was accepted")
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
        ('preexisting_mount_ids="$(/usr/bin/awk \'NF < 6 { exit 1 } { print $1 }\' /proc/self/mountinfo | /usr/bin/sort -n)"', 1),
        ('/usr/bin/python3 -I "$sealed_workspace_root/ci/set-recursive-mount-readonly.py"', 1),
        ('post_transition_mount_ids="$(/usr/bin/awk \'NF < 6 { exit 1 } { print $1 }\' /proc/self/mountinfo | /usr/bin/sort -n)"', 1),
        ('if [ "$post_transition_mount_ids" != "$preexisting_mount_ids" ]; then', 1),
        ('/proc/self/mountinfo', 4),
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
    linux_recursive_read_only = (
        '/usr/bin/python3 -I "$sealed_workspace_root/ci/set-recursive-mount-readonly.py"'
    )
    linux_mount_identity_audit = '''preexisting_mount_ids="$(/usr/bin/awk 'NF < 6 { exit 1 } { print $1 }' /proc/self/mountinfo | /usr/bin/sort -n)"
if [ -z "$preexisting_mount_ids" ]; then
    echo "sealed Linux pre-transition mount inventory is empty" >&2
    exit 1
fi'''
    linux_post_transition_identity_audit = '''post_transition_mount_ids="$(/usr/bin/awk 'NF < 6 { exit 1 } { print $1 }' /proc/self/mountinfo | /usr/bin/sort -n)"
if [ "$post_transition_mount_ids" != "$preexisting_mount_ids" ]; then
    echo "sealed Linux mount inventory changed during read-only transition" >&2
    exit 1
fi'''
    linux_all_read_only_audit = '''if ! /usr/bin/awk '
function has_option(options, wanted, count, position, fields) {
    count = split(options, fields, ",")
    for (position = 1; position <= count; position++) {
        if (fields[position] == wanted) return 1
    }
    return 0
}
NF < 6 { invalid = 1; next }
{
    read_only = has_option($6, "ro")
    read_write = has_option($6, "rw")
    if (!read_only || read_write) {
        invalid = 1
        if (reported < 20) {
            print "sealed Linux unexpected writable mount record: " $5 " " $6 > "/dev/stderr"
        }
        reported++
    }
    if ($5 == "/" && read_only && !read_write) root_read_only = 1
}
END {
    if (reported > 20) {
        print "sealed Linux additional writable mount records: " reported - 20 > "/dev/stderr"
    }
    exit !(NR > 0 && root_read_only && !invalid)
}
' /proc/self/mountinfo; then
    echo "sealed Linux recursive read-only mount transition is incomplete" >&2
    exit 1
fi'''
    linux_writable_loop = '''for writable in "$build_home" "$build_tmp" "$target_dir"; do
    /usr/bin/mount --bind "$writable" "$writable"
    /usr/bin/mount -o remount,bind,rw "$writable"
done'''
    linux_exact_writable_audit = '''if ! /usr/bin/awk -v build_home="$build_home" -v build_tmp="$build_tmp" -v target_dir="$target_dir" '
function has_option(options, wanted, count, position, fields) {
    count = split(options, fields, ",")
    for (position = 1; position <= count; position++) {
        if (fields[position] == wanted) return 1
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
            linux_mount_identity_audit,
            linux_recursive_read_only,
            linux_post_transition_identity_audit,
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
            'set-recursive-mount-readonly.py" || :',
            'remount,bind,ro=recursive /',
            'remount,rw=recursive',
            'remount,bind,ro /',
            'remount,ro=recursive /',
            'remount,bind,ro=recursive / || :',
        )
        if any(token in candidate for token in forbidden):
            return False
        return (
            candidate.index('/usr/bin/mount --bind "$hidden_home" "$original_home"')
            < candidate.index(linux_mount_identity_audit)
            < candidate.index(linux_recursive_read_only)
            < candidate.index(linux_post_transition_identity_audit)
            < candidate.index(linux_all_read_only_audit)
            < candidate.index(linux_writable_loop)
            < candidate.index(linux_exact_writable_audit)
            < candidate.index('cd -P "$sealed_workspace_root"')
        )

    if not linux_mount_boundary_is_exact(linux_wrapper):
        raise AssertionError("sealed Linux recursive mount boundary is not exact")
    mount_helper = (ROOT / "ci/set-recursive-mount-readonly.py").read_text(encoding="utf-8")
    mount_attributes_layout = '''    _fields_ = (
        ("attr_set", ctypes.c_uint64),
        ("attr_clr", ctypes.c_uint64),
        ("propagation", ctypes.c_uint64),
        ("userns_fd", ctypes.c_uint64),
    )'''
    mount_helper_tokens = (
        'AT_FDCWD = -100',
        'AT_RECURSIVE = 0x8000',
        'MOUNT_ATTR_RDONLY = 0x00000001',
        'SYS_MOUNT_SETATTR_X86_64 = 442',
        'class MountAttributes(ctypes.Structure):',
        mount_attributes_layout,
        'sys.platform != "linux"\n        or os.uname().machine != "x86_64"',
        'or len(sys.argv) != 1\n        or os.geteuid() != 0',
        'libc = ctypes.CDLL(None, use_errno=True)',
        'syscall = libc.syscall',
        'syscall.restype = ctypes.c_long',
        'attributes = MountAttributes(attr_set=MOUNT_ATTR_RDONLY)',
        'ctypes.c_long(SYS_MOUNT_SETATTR_X86_64)',
        'ctypes.c_int(AT_FDCWD)',
        'ctypes.c_char_p(b"/")',
        'ctypes.c_uint(AT_RECURSIVE)',
        'ctypes.byref(attributes)',
        'ctypes.c_size_t(ctypes.sizeof(attributes))',
        'error_number = ctypes.get_errno()',
    )

    def mount_helper_is_exact(candidate: str) -> bool:
        return (
            all(candidate.count(token) == 1 for token in mount_helper_tokens)
            and 'subprocess' not in candidate
            and 'socket' not in candidate
            and 'os.environ' not in candidate
            and 'libc.mount_setattr' not in candidate
            and 'attr_clr=' not in candidate
            and 'propagation=' not in candidate
            and '_pack_' not in candidate
            and '_align_' not in candidate
            and '_layout_' not in candidate
            and candidate.index('attributes = MountAttributes(attr_set=MOUNT_ATTR_RDONLY)')
            < candidate.index('    if syscall(')
            < candidate.index('        error_number = ctypes.get_errno()')
        )

    if not mount_helper_is_exact(mount_helper):
        raise AssertionError("sealed Linux mount_setattr helper is not exact")
    for token in mount_helper_tokens:
        mutated = mount_helper.replace(token, "", 1)
        if mutated == mount_helper or mount_helper_is_exact(mutated):
            raise AssertionError(f"sealed Linux mount helper mutation was accepted: {token}")
    for name, original, replacement in (
        ("nonrecursive flags", "AT_RECURSIVE = 0x8000", "AT_RECURSIVE = 0"),
        ("writable attributes", "MOUNT_ATTR_RDONLY = 0x00000001", "MOUNT_ATTR_RDONLY = 0"),
        ("non-root target", 'ctypes.c_char_p(b"/")', 'ctypes.c_char_p(b"/tmp")'),
        (
            "cleared read-only attribute",
            "attributes = MountAttributes(attr_set=MOUNT_ATTR_RDONLY)",
            "attributes = MountAttributes(attr_clr=MOUNT_ATTR_RDONLY)",
        ),
        (
            "extra ABI field",
            mount_attributes_layout,
            mount_attributes_layout.replace(
                '        ("userns_fd", ctypes.c_uint64),',
                '        ("userns_fd", ctypes.c_uint64),\n'
                '        ("unexpected", ctypes.c_uint64),',
            ),
        ),
        (
            "packed ABI layout",
            mount_attributes_layout,
            "    _pack_ = 1\n" + mount_attributes_layout,
        ),
        (
            "over-aligned ABI layout",
            mount_attributes_layout,
            "    _align_ = 16\n" + mount_attributes_layout,
        ),
        (
            "alternate ABI layout",
            mount_attributes_layout,
            '    _layout_ = "gcc-sysv"\n' + mount_attributes_layout,
        ),
    ):
        mutated = mount_helper.replace(original, replacement, 1)
        if mutated == mount_helper or mount_helper_is_exact(mutated):
            raise AssertionError(f"sealed Linux mount helper {name} mutation was accepted")
    for diagnostic in (
        'if (reported < 20)',
        'sealed Linux unexpected writable mount record:',
        'if (reported > 20)',
        'sealed Linux additional writable mount records:',
    ):
        if linux_wrapper.count(diagnostic) != 1:
            raise AssertionError(f"sealed Linux mount diagnostic is not exact: {diagnostic}")
    linux_mount_mutations = {
        "missing recursive transition": linux_wrapper.replace(linux_recursive_read_only, "", 1),
        "missing pre-transition inventory": linux_wrapper.replace(linux_mount_identity_audit, "", 1),
        "missing post-transition inventory": linux_wrapper.replace(
            linux_post_transition_identity_audit, "", 1
        ),
        "alternate helper": linux_wrapper.replace(
            "set-recursive-mount-readonly.py", "unreviewed-mount-helper.py", 1
        ),
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
        'SDKROOT="$darwin_sdkroot"',
        'darwin_sdkroot=${20}',
        '"$delayed_write_target" "$darwin_sdkroot"; do',
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
    darwin_system_shim_probe = '''    for denied_darwin_tool in /usr/bin/cc /usr/bin/make /usr/bin/xcrun; do
        if [ ! -x "$denied_darwin_tool" ] || ! run_sealed /bin/sh -c \\
            '\"$1\" --version >/dev/null 2>&1; [ "$?" -eq 126 ]' \\
            wlpq-denied-darwin-tool "$denied_darwin_tool"; then
            echo "sealed Darwin system compiler shim remained executable" >&2
            exit 1
        fi
    done'''
    darwin_as_probe = '''    if ! run_sealed "$sealed_command_bin/as" --version >/dev/null; then
        echo "sealed Darwin assembler wrapper could not reach its exact interpreter and helpers" >&2
        exit 1
    fi'''
    darwin_child_exec_probe = '''if [ "$host_system" = Darwin ]; then
''' + darwin_system_shim_probe + '''
''' + darwin_as_probe + '''
    expected_darwin_rustc_version='rustc 1.96.0 (ac68faa20 2026-05-25)
binary: rustc
commit-hash: ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96
commit-date: 2026-05-25
host: aarch64-apple-darwin
release: 1.96.0
LLVM version: 22.1.2'
    if [ "$(run_sealed /bin/sh -c 'exec "$1" -vV </dev/null' wlpq-rustc "$compiler_rustc_bin")" != "$expected_darwin_rustc_version" ]; then
        echo "isolated Darwin null-stdin child-exec Rust compiler identity mismatch" >&2
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
                'run_sealed /bin/sh -c \'exec "$1" -vV </dev/null\' wlpq-rustc "$compiler_rustc_bin"',
                'run_sealed "$compiler_rustc_bin" -vV',
            ),
        ),
        (
            "unchecked compiler launch",
            darwin_child_exec_probe.replace(
                'if [ "$(run_sealed /bin/sh -c \'exec "$1" -vV </dev/null\' wlpq-rustc "$compiler_rustc_bin")" != "$expected_darwin_rustc_version" ]; then',
                'if ! run_sealed /bin/sh -c \'exec "$1" -vV </dev/null\' wlpq-rustc "$compiler_rustc_bin" >/dev/null; then',
            ),
        ),
        (
            "missing system shim probes",
            darwin_child_exec_probe.replace(darwin_system_shim_probe + "\n", "", 1),
        ),
        (
            "missing assembler wrapper probe",
            darwin_child_exec_probe.replace(darwin_as_probe + "\n", "", 1),
        ),
        (
            "unchecked assembler wrapper probe",
            darwin_child_exec_probe.replace(
                darwin_as_probe,
                '    run_sealed "$sealed_command_bin/as" --version >/dev/null',
                1,
            ),
        ),
        (
            "partial system shim probes",
            darwin_child_exec_probe.replace(
                "/usr/bin/cc /usr/bin/make /usr/bin/xcrun", "/usr/bin/cc /usr/bin/xcrun", 1
            ),
        ),
        (
            "accepted non-denial status",
            darwin_child_exec_probe.replace('eq 126', 'ne 0', 1),
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
    for name, wrapper, minimum, shift_count in (
        ("Darwin", darwin_wrapper, 21, 20),
        ("Linux", linux_wrapper, 20, 19),
    ):
        initial_check = f'if [ "$#" -lt {minimum} ]'
        shift = f"shift {shift_count}"
        if (
            wrapper.count(initial_check) != 1
            or wrapper.count(shift) != 1
            or wrapper.count('if [ "$#" -lt 1 ]; then') != 1
        ):
            raise AssertionError(f"sealed {name} wrapper lacks exact post-shift command check")
        def accepts(count: int) -> bool:
            return count >= minimum and count - shift_count >= 1

        counts = (minimum - 1, minimum, minimum + 1)
        accepted = {count: accepts(count) for count in counts}
        if accepted != {minimum - 1: False, minimum: True, minimum + 1: True}:
            raise AssertionError(f"sealed {name} wrapper argument contract differs")
        for removed in (initial_check, shift, 'if [ "$#" -lt 1 ]; then'):
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
        ('panic!("sealed target metadata {name}: {error}")', 1),
        ('let wrote = fs::write(&write_path, b"boundary escape").is_ok();', 1),
        ('require_allowed_write("SEALED_BUILD_', 3),
        ('require_linux_mount_boundary();', 1),
    ):
        if probe_source.count(token) != expected:
            raise AssertionError(f"sealed boundary probe token is not exact: {token}")
    sudo_denial_probe = '''fn require_no_sudo_authority() {
    match Command::new("/usr/bin/sudo").args(["-n", "true"]).status() {
        Ok(status) => assert!(!status.success(), "build identity unexpectedly has sudo authority"),
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {}
        Err(error) => panic!("absolute sudo denial was not OS-enforced: {error}"),
    }
}'''

    def sudo_denial_probe_is_exact(candidate: str) -> bool:
        return (
            candidate.count(sudo_denial_probe) == 1
            and candidate.count("    require_no_sudo_authority();") == 1
            and candidate.index(sudo_denial_probe)
            < candidate.index("fn main()")
            < candidate.index("    require_no_sudo_authority();")
            < candidate.index('require_denied_write("SEALED_DEPENDENCY_TARGET")')
        )

    if not sudo_denial_probe_is_exact(probe_source):
        raise AssertionError("sealed sudo authority denial probe is not exact")
    for name, mutated in (
        ("missing function", probe_source.replace(sudo_denial_probe, "", 1)),
        (
            "missing call",
            probe_source.replace("    require_no_sudo_authority();\n", "", 1),
        ),
        (
            "successful sudo accepted",
            probe_source.replace("assert!(!status.success()", "assert!(status.success()", 1),
        ),
        (
            "arbitrary launch error accepted",
            probe_source.replace(
                "Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {}",
                "Err(_) => {}",
                1,
            ),
        ),
    ):
        if mutated == probe_source or sudo_denial_probe_is_exact(mutated):
            raise AssertionError(f"sealed sudo authority {name} mutation was accepted")
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
            '--emit=dep-info="$plan_dep_info"'
        ),
        "bounded compiler diagnostics": (
            'python3 -I ci/capture-bounded-command-diagnostics.py \\\n'
            '    --capture-stdin "$plan_diagnostic_output"'
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
    diagnostic_lifecycle_stanza = r'''plan_diagnostic_output="$gate_output/ordinary-wallet-plan.stderr"
plan_diagnostic_status="$gate_output/ordinary-wallet-plan.status"
plan_dep_info="$workspace_target/ordinary-wallet-plan-source-closure.d"
if [ -e "$plan_dep_info" ] || [ -L "$plan_dep_info" ]; then
    echo "ordinary-wallet plan compiler source closure already exists" >&2
    exit 1
fi
if ! (
    umask 022
    if run_sealed "$compiler_cargo_bin" rustc \
            -p wasabi-liquid-native-ordinary-wallet-plan \
            --lib \
            --locked \
            --offline \
            -- \
            --emit=dep-info="$plan_dep_info"
    then
        plan_pipeline_status=0
    else
        plan_pipeline_status=$?
    fi
    /usr/bin/printf '%s\n' "$plan_pipeline_status" >"$plan_diagnostic_status"
) 2>&1 | python3 -I ci/capture-bounded-command-diagnostics.py \
    --capture-stdin "$plan_diagnostic_output"
then
    echo "ordinary-wallet plan bounded compiler diagnostic capture failed" >&2
    exit 1
fi
if [ ! -f "$plan_diagnostic_status" ]; then
    echo "ordinary-wallet plan compiler status handoff is missing" >&2
    exit 1
fi
plan_compile_status="$(cat "$plan_diagnostic_status")"
case "$plan_compile_status" in *[!0-9]*|'') echo "ordinary-wallet plan compiler status handoff is invalid" >&2; exit 1 ;; esac
if [ "$plan_compile_status" -gt 255 ]; then
    echo "ordinary-wallet plan compiler status handoff is out of range" >&2
    exit 1
fi
if [ "$plan_compile_status" -ne 0 ]; then
    if ! python3 -I ci/capture-bounded-command-diagnostics.py \
        --emit "$plan_diagnostic_output"; then
        echo "ordinary-wallet plan bounded compiler diagnostic emission failed" >&2
        exit 1
    fi
    if [ -e "$plan_dep_info" ] || [ -L "$plan_dep_info" ]; then
        plan_dep_info_state=present
    else
        plan_dep_info_state=absent
    fi
    echo "ordinary-wallet plan compiler source closure derivation failed: status=$plan_compile_status dep-info=$plan_dep_info_state" >&2
    exit 1
fi'''
    if (
        gate.count(diagnostic_lifecycle_stanza) != 1
        or len(re.findall(r"(?m)^plan_diagnostic_output=", gate)) != 1
        or len(re.findall(r"(?m)^plan_diagnostic_status=", gate)) != 1
        or len(re.findall(r"(?m)^plan_compile_status=", gate)) != 1
        or len(re.findall(r"(?m)^plan_dep_info=", gate)) != 1
        or len(re.findall(r"(?m)^\s*plan_dep_info_state=", gate)) != 2
        or len(re.findall(r"(?m)^\s*plan_pipeline_status=", gate)) != 2
        or gate.count('--emit "$plan_diagnostic_output"') != 1
        or "ordinary-wallet-plan.stderr.fifo" in gate
        or 'wait "$plan_diagnostic_collector"' in gate
    ):
        raise AssertionError("bounded compiler diagnostic lifecycle is not exact")
    for name, token in (
        ("producer success status", "        plan_pipeline_status=0\n"),
        ("producer failure status", "        plan_pipeline_status=$?\n"),
        ("status handoff", "    /usr/bin/printf '%s\\n' \"$plan_pipeline_status\" >\"$plan_diagnostic_status\"\n"),
        ("collector pipeline", ') 2>&1 | python3 -I ci/capture-bounded-command-diagnostics.py \\\n'),
        ("missing-status rejection", 'if [ ! -f "$plan_diagnostic_status" ]; then\n'),
        ("status parse", 'plan_compile_status="$(cat "$plan_diagnostic_status")"\n'),
        ("status range", 'if [ "$plan_compile_status" -gt 255 ]; then\n'),
        ("failure-only emission", 'if [ "$plan_compile_status" -ne 0 ]; then\n'),
        ("bounded emission", '        --emit "$plan_diagnostic_output"; then\n'),
        ("fresh dep-info", 'if [ -e "$plan_dep_info" ] || [ -L "$plan_dep_info" ]; then\n'),
        ("writable dep-info", '            --emit=dep-info="$plan_dep_info"\n'),
        ("dep-info mode", "    umask 022\n"),
        ("failure artifact state", '        plan_dep_info_state=present\n'),
        (
            "failure status report",
            '    echo "ordinary-wallet plan compiler source closure derivation failed: status=$plan_compile_status dep-info=$plan_dep_info_state" >&2\n',
        ),
    ):
        mutated = gate.replace(token, "", 1)
        if mutated == gate or mutated.count(diagnostic_lifecycle_stanza) != 0:
            raise AssertionError(f"bounded compiler diagnostic {name} mutation was accepted")
    if gate.count("python3 -I ci/test-bounded-command-diagnostics.py") != 1:
        raise AssertionError("bounded command diagnostic mutation test is not singular")
    source_closure_reader = '''python3 -I ci/read-compiler-source-closure.py \\
        "$sealed_workspace" "$workspace_target" "$plan_dep_info" 0 "$build_uid"'''
    if (
        gate.count("python3 -I ci/test-compiler-source-closure.py") != 1
        or gate.count(source_closure_reader) != 1
        or gate.count("ordinary-wallet-plan-source-closure.d") != 1
        or '"$gate_output/ordinary-wallet-plan.dep-info"' in gate
    ):
        raise AssertionError("compiler source-closure reader wiring is not exact")
    surface_checker = (
        ROOT / "ci/check-ordinary-wallet-plan-surface.py"
    ).read_text(encoding="utf-8")
    surface_mutations = (
        ROOT / "ci/test-ordinary-wallet-plan-surface.py"
    ).read_text(encoding="utf-8")
    surface_sdk_invocation = '''WLPQ_TEST_DARWIN_SDKROOT="$darwin_sdkroot" \\
    python3 -I ci/test-ordinary-wallet-plan-surface.py'''
    surface_sdk_environment = '''def cargo_environment(root: Path, *, platform: str | None = None) -> dict[str, str]:
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
    return environment'''

    def surface_sdk_boundary_is_exact(candidate_gate: str, candidate_test: str) -> bool:
        return (
            candidate_gate.count(surface_sdk_invocation) == 1
            and candidate_test.count(
                'TEST_DARWIN_SDKROOT_VARIABLE = "WLPQ_TEST_DARWIN_SDKROOT"'
            )
            == 1
            and candidate_test.count(surface_sdk_environment) == 1
            and candidate_test.count("def test_cargo_environment_boundary() -> None:") == 1
            and candidate_test.count("    test_cargo_environment_boundary()\n") == 1
            and 'environment["DEVELOPER_DIR"]' not in candidate_test
        )

    if not surface_sdk_boundary_is_exact(gate, surface_mutations):
        raise AssertionError("private surface-mutation Darwin SDK boundary is not exact")
    for name, candidate_gate, candidate_test in (
        ("gate handoff", gate.replace(surface_sdk_invocation, "", 1), surface_mutations),
        (
            "test-only variable consumption",
            gate,
            surface_mutations.replace(
                '    darwin_sdkroot = environment.pop(TEST_DARWIN_SDKROOT_VARIABLE, "")\n',
                "",
                1,
            ),
        ),
        (
            "absolute SDK root",
            gate,
            surface_mutations.replace("not sdkroot.is_absolute() or ", "", 1),
        ),
        (
            "ambient SDK root removal",
            gate,
            surface_mutations.replace('    environment.pop("SDKROOT", None)\n', "", 1),
        ),
        (
            "symlink rejection",
            gate,
            surface_mutations.replace("sdkroot.is_symlink() or ", "", 1),
        ),
        (
            "directory rejection",
            gate,
            surface_mutations.replace("or not sdkroot.is_dir()", "", 1),
        ),
        (
            "Darwin-only child assignment",
            gate,
            surface_mutations.replace('        environment["SDKROOT"] = str(sdkroot)\n', "", 1),
        ),
        (
            "non-Darwin rejection",
            gate,
            surface_mutations.replace("    elif darwin_sdkroot:\n", "", 1),
        ),
        (
            "focused behavior test",
            gate,
            surface_mutations.replace("    test_cargo_environment_boundary()\n", "", 1),
        ),
    ):
        if surface_sdk_boundary_is_exact(candidate_gate, candidate_test):
            raise AssertionError(f"private surface-mutation Darwin SDK {name} mutation was accepted")
    owner_mutable_helper = '''def make_owner_mutable(root: Path) -> None:
    paths = (root, *root.rglob("*"))
    for path in paths:
        metadata = os.lstat(path)
        if stat.S_ISLNK(metadata.st_mode):
            continue
        os.chmod(path, stat.S_IMODE(metadata.st_mode) | stat.S_IWUSR)'''

    def owner_mutation_copy_is_exact(candidate: str) -> bool:
        return (
            candidate.count(owner_mutable_helper) == 1
            and candidate.count("    make_owner_mutable(destination)\n") == 1
            and candidate.count("def test_make_owner_mutable() -> None:") == 1
            and candidate.count("    test_make_owner_mutable()\n") == 1
        )

    if not owner_mutation_copy_is_exact(surface_mutations):
        raise AssertionError("private surface-mutation copy mutability is not exact")
    for name, token in (
        ("owner mode repair", "        os.chmod(path, stat.S_IMODE(metadata.st_mode) | stat.S_IWUSR)\n"),
        ("symlink exclusion", "        if stat.S_ISLNK(metadata.st_mode):\n"),
        ("copy integration", "    make_owner_mutable(destination)\n"),
        ("focused behavior test", "    test_make_owner_mutable()\n"),
    ):
        mutated = surface_mutations.replace(token, "", 1)
        if mutated == surface_mutations or owner_mutation_copy_is_exact(mutated):
            raise AssertionError(f"private mutation-copy {name} mutation was accepted")
    internal_surface_call = (
        'python3 -I -c \'import importlib.util, pathlib, sys; '
        'p = pathlib.Path("ci/check-ordinary-wallet-plan-surface.py"); '
        's = importlib.util.spec_from_file_location("plan_surface", p); '
        'm = importlib.util.module_from_spec(s); s.loader.exec_module(m); '
        'm.validate_with_compiled_source_files(tuple(path.removeprefix('
        '"crates/ordinary-wallet-plan/") for path in sys.argv[1].splitlines()))\' '
        '"$plan_compiled_sources"'
    )
    exact_source_rejection = '''if [ "$plan_compiled_sources" != "$expected_plan_compiled_sources" ]; then
    echo "ordinary-wallet plan compiler source closure changed" >&2
    exit 1
fi'''
    compiled_boundary = '''def validate_compiled_source_closure_and_pins(
    source: str, compiled_files: tuple[str, ...]
) -> str:
    if compiled_files != EXPECTED_COMPILED_SOURCE_FILES:
        reject("ordinary-wallet plan compiler source closure changed")'''
    direct_checker_entry = '''def main() -> None:
    validate_with_compiled_source_files(compiled_source_files())


if __name__ == "__main__":
    if len(sys.argv) != 1:
        reject("usage: check-ordinary-wallet-plan-surface.py")
    main()'''

    def surface_composition_is_exact(candidate_gate: str, candidate_checker: str) -> bool:
        return (
            candidate_gate.count("python3 -I ci/check-ordinary-wallet-plan-surface.py")
            == 0
            and candidate_gate.count(internal_surface_call) == 1
            and candidate_gate.count(exact_source_rejection) == 1
            and candidate_gate.count(diagnostic_lifecycle_stanza) == 1
            and candidate_gate.count(source_closure_reader) == 1
            and candidate_gate.index(diagnostic_lifecycle_stanza)
            < candidate_gate.index(source_closure_reader)
            < candidate_gate.index(exact_source_rejection)
            < candidate_gate.index(internal_surface_call)
            and candidate_checker.count("def compiled_source_files() -> tuple[str, ...]:")
            == 1
            and candidate_checker.count(compiled_boundary) == 1
            and candidate_checker.count(
                "def validate_with_compiled_source_files(compiled_files: tuple[str, ...]) -> None:"
            )
            == 1
            and candidate_checker.count(
                "validate_with_compiled_source_files(compiled_source_files())"
            )
            == 1
            and candidate_checker.count(direct_checker_entry) == 1
            and candidate_checker.count('"rustc",') == 1
            and "compiled_files: tuple[str, ...] | None" not in candidate_checker
            and "compiled_files = compiled_source_files()" not in candidate_checker
        )

    if not surface_composition_is_exact(gate, surface_checker):
        raise AssertionError("sealed compiler closure to surface-checker composition is not exact")
    for name, candidate_gate, candidate_checker in (
        (
            "internal surface call",
            gate.replace(internal_surface_call, "", 1),
            surface_checker,
        ),
        (
            "exact source comparison",
            gate.replace(exact_source_rejection, "", 1),
            surface_checker,
        ),
        (
            "direct CLI compiler binding",
            gate,
            surface_checker.replace(
                "validate_with_compiled_source_files(compiled_source_files())", "", 1
            ),
        ),
        (
            "zero-argument direct CLI",
            gate,
            surface_checker.replace(direct_checker_entry, "", 1),
        ),
        (
            "explicit compiled-file boundary",
            gate,
            surface_checker.replace(compiled_boundary, "", 1),
        ),
    ):
        if surface_composition_is_exact(candidate_gate, candidate_checker):
            raise AssertionError(f"surface checker {name} mutation was accepted")
    source_closure_helper = (
        ROOT / "ci/read-compiler-source-closure.py"
    ).read_text(encoding="utf-8")
    source_closure_tokens = (
        "MAX_DEP_INFO_BYTES = 64 * 1024",
        'DEP_INFO_NAME = "ordinary-wallet-plan-source-closure.d"',
        'target_root.name != "workspace-target"',
        "target_root.parent != workspace_root.parent",
        "stat.S_IMODE(root_metadata.st_mode) != 0o755",
        "root_metadata.st_uid != expected_uid",
        "stat.S_IMODE(workspace_metadata.st_mode) != 0o555",
        "workspace_metadata.st_uid != expected_workspace_uid",
        'os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)',
        "or before.st_nlink != 1",
        "or before.st_uid != expected_uid",
        "or before.st_size > MAX_DEP_INFO_BYTES",
        "or exact_identity(os.lstat(target_root)) != exact_identity(root_metadata)",
        "parsed.as_posix() != token",
        "source.relative_to(workspace_root)",
        'part in ("", ".", "..")',
        "if stat.S_ISLNK(source_metadata.st_mode):",
        "exact_identity(os.lstat(workspace_root)) != exact_identity(workspace_metadata)",
    )

    def source_closure_helper_is_exact(candidate: str) -> bool:
        return (
            all(candidate.count(token) == 1 for token in source_closure_tokens)
            and len(re.findall(r"(?m)^MAX_DEP_INFO_BYTES\s*=", candidate)) == 1
            and len(re.findall(r"(?m)^DEP_INFO_NAME\s*=", candidate)) == 1
        )

    if not source_closure_helper_is_exact(source_closure_helper):
        raise AssertionError("compiler source-closure authority is not exact")
    for token in source_closure_tokens:
        mutated = source_closure_helper.replace(token, "", 1)
        if mutated == source_closure_helper or source_closure_helper_is_exact(mutated):
            raise AssertionError(
                f"compiler source-closure authority mutation was accepted: {token}"
            )
    for mutation in (
        "\nMAX_DEP_INFO_BYTES = 1024 * 1024\n",
        '\nDEP_INFO_NAME = "changed.d"\n',
    ):
        if source_closure_helper_is_exact(source_closure_helper + mutation):
            raise AssertionError("compiler source-closure authority reassignment was accepted")
    diagnostic_helper = (
        ROOT / "ci/capture-bounded-command-diagnostics.py"
    ).read_text(encoding="utf-8")
    diagnostic_cap_tokens = (
        "MAX_DIAGNOSTIC_BYTES = 16 * 1024",
        'TRUNCATION_MARKER = b"\\n[diagnostics truncated]\\n"',
        "chunk = os.read(0, 64 * 1024)",
        "if not stat.S_ISFIFO(stdin_metadata.st_mode):",
        "os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, \"O_NOFOLLOW\", 0)",
        "or output_metadata.st_nlink != 1",
        "or output_metadata.st_uid != os.getuid()",
        "or exact_identity(os.lstat(output)) != exact_identity(output_metadata)",
        "if len(retained) < MAX_DIAGNOSTIC_BYTES:",
        "retained.extend(chunk[: MAX_DIAGNOSTIC_BYTES - len(retained)])",
        "if total > MAX_DIAGNOSTIC_BYTES:",
        "retained[MAX_DIAGNOSTIC_BYTES - len(TRUNCATION_MARKER) :] = TRUNCATION_MARKER",
        "or before.st_size > MAX_DIAGNOSTIC_BYTES",
        "or before.st_nlink != 1",
        "or before.st_uid != os.getuid()",
        "if exact_identity(opened) != exact_identity(before):",
        "data = os.read(descriptor, MAX_DIAGNOSTIC_BYTES + 1)",
        "or len(data) > MAX_DIAGNOSTIC_BYTES",
        "exact_identity(os.fstat(descriptor)) != exact_identity(opened)",
        "os.lstat(output)\n        ) != exact_identity(opened)",
    )

    def diagnostic_caps_are_exact(candidate: str) -> bool:
        return (
            all(candidate.count(token) == 1 for token in diagnostic_cap_tokens)
            and len(re.findall(r"(?m)^MAX_DIAGNOSTIC_BYTES\s*=", candidate)) == 1
            and len(re.findall(r"(?m)^TRUNCATION_MARKER\s*=", candidate)) == 1
        )

    if not diagnostic_caps_are_exact(diagnostic_helper):
        raise AssertionError("bounded command diagnostic byte limits are not exact")
    for token in diagnostic_cap_tokens:
        mutated = diagnostic_helper.replace(token, "", 1)
        if mutated == diagnostic_helper or diagnostic_caps_are_exact(mutated):
            raise AssertionError(
                f"bounded command diagnostic cap mutation was accepted: {token}"
            )
    for name, mutation in (
        ("reassigned cap", "\nMAX_DIAGNOSTIC_BYTES = 32 * 1024\n"),
        ("reassigned marker", '\nTRUNCATION_MARKER = b"changed"\n'),
    ):
        mutated = diagnostic_helper + mutation
        if diagnostic_caps_are_exact(mutated):
            raise AssertionError(f"bounded command diagnostic {name} mutation was accepted")
    for unbounded_emitter in (
        'cat "$plan_diagnostic_output"',
        'sed -n \'1,120p\' "$plan_diagnostic_output"',
        'tail "$plan_diagnostic_output"',
    ):
        if unbounded_emitter in gate:
            raise AssertionError("unbounded compiler diagnostic emitter was accepted")
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
        "surface checker": (
            'm.validate_with_compiled_source_files(tuple(path.removeprefix('
            '"crates/ordinary-wallet-plan/") for path in sys.argv[1].splitlines()))'
        ),
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
