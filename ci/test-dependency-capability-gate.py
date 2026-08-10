#!/usr/bin/env python3
import copy
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
GATE = ROOT / "ci" / "check-dependency-capabilities.sh"
REAL_CARGO = shutil.which("cargo")


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
