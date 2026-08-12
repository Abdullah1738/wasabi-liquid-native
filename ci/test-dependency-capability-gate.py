#!/usr/bin/env python3
import copy
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
GATE = ROOT / "ci" / "check-dependency-capabilities.sh"
REAL_CARGO = shutil.which("cargo")
CONFORMANCE_CHECKER = ROOT / "ci" / "check-wallet-facts-conformance.py"
REFERENCE = Path("contracts/wallet-facts/v1/nonlinkable-reference")


def run(command: list[str]) -> str:
    return subprocess.run(
        command,
        cwd=ROOT,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
    ).stdout


def write_json(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, separators=(",", ":")))


def expect_gate(mock_cargo: Path, *, success: bool, **environment: str) -> None:
    merged_environment = os.environ.copy()
    merged_environment.update(environment)
    merged_environment["CARGO"] = str(mock_cargo)
    result = subprocess.run(
        [str(GATE)],
        cwd=ROOT,
        env=merged_environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if (result.returncode == 0) != success:
        raise AssertionError(
            f"unexpected gate result {result.returncode}:\n{result.stdout}{result.stderr}"
        )


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
        " ".join(line.strip().split()).replace('"$compiler_cargo_bin"', "cargo", 1)
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


def test_gate_wiring_and_lock_proof(scratch: Path) -> None:
    gate = GATE.read_text()
    checker_call = 'python3 ci/check-wallet-facts-conformance.py "$repository_root"'
    if gate.count(checker_call) != 1:
        raise AssertionError("conformance checker invocation is not fixed and singular")
    nested_pin = "9bcdcf31ffe90e7a23ada162c61c71cfc84343ba1c190865e0ed34af8c7da933"
    parent_pin = "9a3d11662670d13e23ed248f2ae145c87a52739e2e3bb03f7628e4d12e147c63"
    if gate.count(nested_pin) != 1:
        raise AssertionError("conformance inventory root pin is not singular")
    if gate.count(parent_pin) != 1:
        raise AssertionError("conformance parent root pin is not singular")
    if not focused_replay_is_exact(gate):
        raise AssertionError("focused conformance replay is not exact and singular")
    focused_stanza = """"$compiler_cargo_bin" test \\
            -p wasabi-liquid-native-wallet-facts-wire \\
            --locked \\
            --offline \\
            conformance"""
    if gate.count(focused_stanza) != 1:
        raise AssertionError("focused conformance replay stanza is not singular")
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

    marker = 'python3 - "$repository_root" <<\'PY\'\n'
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

    baseline = lock_root("lock-baseline")
    (baseline / "ci/expected-wallet-facts-conformance-lock-baseline.txt").write_text("0" * 64 + "\n")
    expect_lock_snippet(snippet, baseline, success=False)

    changed_pin = snippet.replace(
        "de5ddee5639aa7b44f15115736c3c538b0dabc7524feea44c6ce7316d1e6979f",
        "0" * 64,
        1,
    )
    expect_lock_snippet(changed_pin, valid, success=False)


def main() -> None:
    if REAL_CARGO is None:
        raise RuntimeError("cargo is unavailable")

    tree = run(
        [
            REAL_CARGO,
            "tree",
            "--workspace",
            "--locked",
            "--target",
            "all",
            "-e",
            "normal,build",
            "--no-dedupe",
            "--prefix",
            "depth",
            "--format",
            "{p}|{f}",
        ]
    )
    metadata = json.loads(
        run([REAL_CARGO, "metadata", "--locked", "--format-version", "1"])
    )

    with tempfile.TemporaryDirectory(prefix="wasabi-liquid-capability-gate-") as directory:
        scratch = Path(directory)
        test_conformance_checker(scratch)
        test_gate_wiring_and_lock_proof(scratch)
        tree_path = scratch / "tree.txt"
        metadata_path = scratch / "metadata.json"
        tree_path.write_text(tree)
        write_json(metadata_path, metadata)

        mock_cargo = scratch / "cargo"
        mock_cargo.write_text(
            """#!/bin/sh
set -eu
case "$1" in
    tree)
        case " $* " in
            *" --target all "*" --prefix depth "*) ;;
            *) exit 99 ;;
        esac
        cat "$TREE_FILE"
        if [ -n "${EXTRA_TREE_LINE:-}" ]; then
            printf '%s\\n' "$EXTRA_TREE_LINE"
        fi
        if [ "${FAIL_TREE:-0}" = 1 ]; then
            exit 17
        fi
        ;;
    metadata)
        cat "$METADATA_FILE"
        ;;
    *) exit 98 ;;
esac
"""
        )
        mock_cargo.chmod(0o755)
        base_environment = {
            "TREE_FILE": str(tree_path),
            "METADATA_FILE": str(metadata_path),
        }

        expect_gate(mock_cargo, success=True, **base_environment)
        expect_gate(
            mock_cargo,
            success=False,
            EXTRA_TREE_LINE="0reqwest v0.12.24|default-tls,json",
            **base_environment,
        )
        expect_gate(mock_cargo, success=False, FAIL_TREE="1", **base_environment)

        target_metadata = copy.deepcopy(metadata)
        wallet_id = next(
            package["id"]
            for package in target_metadata["packages"]
            if package["name"] == "wasabi-liquid-native-wallet-facts"
        )
        wallet_node = next(
            node for node in target_metadata["resolve"]["nodes"] if node["id"] == wallet_id
        )
        rand_dependency = next(
            dependency for dependency in wallet_node["deps"] if dependency["name"] == "rand"
        )
        rand_dependency["dep_kinds"].append(
            {"kind": None, "target": 'cfg(target_os = "linux")'}
        )
        target_metadata_path = scratch / "target-metadata.json"
        write_json(target_metadata_path, target_metadata)
        wallet_root = next(
            line
            for line in tree.splitlines()
            if line.startswith("0wasabi-liquid-native-wallet-facts v0.1.0 ")
        )
        target_tree_path = scratch / "target-tree.txt"
        target_tree_path.write_text(f"{tree}\n{wallet_root}\n1rand v0.8.7|\n")
        expect_gate(
            mock_cargo,
            success=False,
            TREE_FILE=str(target_tree_path),
            METADATA_FILE=str(target_metadata_path),
        )

        rewired_metadata = copy.deepcopy(metadata)
        transaction_package = next(
            package
            for package in rewired_metadata["packages"]
            if package["name"] == "wasabi-liquid-native-transaction-validation"
        )
        original_id = transaction_package["id"]
        replacement_id = (
            "path+file:///tmp/rewired-transaction-validation"
            "#wasabi-liquid-native-transaction-validation@0.1.0"
        )
        replacement_package = copy.deepcopy(transaction_package)
        replacement_package["id"] = replacement_id
        replacement_package["manifest_path"] = (
            "/tmp/rewired-transaction-validation/Cargo.toml"
        )
        rewired_metadata["packages"].append(replacement_package)
        original_node = next(
            node
            for node in rewired_metadata["resolve"]["nodes"]
            if node["id"] == original_id
        )
        replacement_node = copy.deepcopy(original_node)
        replacement_node["id"] = replacement_id
        rewired_metadata["resolve"]["nodes"].append(replacement_node)
        rewired_wallet_node = next(
            node for node in rewired_metadata["resolve"]["nodes"] if node["id"] == wallet_id
        )
        transaction_dependency = next(
            dependency
            for dependency in rewired_wallet_node["deps"]
            if dependency["pkg"] == original_id
        )
        transaction_dependency["pkg"] = replacement_id
        rewired_metadata_path = scratch / "rewired-metadata.json"
        write_json(rewired_metadata_path, rewired_metadata)

        rewired_tree_lines = tree.splitlines()
        in_wallet_tree = False
        for index, line in enumerate(rewired_tree_lines):
            if line.startswith("0wasabi-liquid-native-wallet-facts v0.1.0 "):
                in_wallet_tree = True
                continue
            if in_wallet_tree and not line:
                break
            if in_wallet_tree and line.startswith(
                "1wasabi-liquid-native-transaction-validation v0.1.0 ("
            ):
                rewired_tree_lines[index] = (
                    "1wasabi-liquid-native-transaction-validation v0.1.0 "
                    "(/tmp/rewired-transaction-validation)|"
                )
                break
        else:
            raise AssertionError("wallet transaction-validation edge was not found")
        rewired_tree_path = scratch / "rewired-tree.txt"
        rewired_tree_path.write_text("\n".join(rewired_tree_lines) + "\n")
        expect_gate(
            mock_cargo,
            success=False,
            TREE_FILE=str(rewired_tree_path),
            METADATA_FILE=str(rewired_metadata_path),
        )


if __name__ == "__main__":
    main()
