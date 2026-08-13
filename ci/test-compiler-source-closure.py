#!/usr/bin/env python3
"""Mutation-test sealed compiler source-closure reads."""

from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "ci/read-compiler-source-closure.py"
EXPECTED_MAX_DEP_INFO_BYTES = 64 * 1024
EXPECTED_DEP_INFO_NAME = "ordinary-wallet-plan-source-closure.d"


def load_helper():
    spec = importlib.util.spec_from_file_location("compiler_source_closure", HELPER)
    if spec is None or spec.loader is None:
        raise AssertionError("compiler source-closure helper import failed")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def expect_rejection(operation, message: str) -> None:
    try:
        operation()
    except Exception as error:
        if error.__class__.__name__ != "SourceClosureError":
            raise
        return
    raise AssertionError(message)


def main() -> int:
    helper = load_helper()
    if (
        helper.MAX_DEP_INFO_BYTES != EXPECTED_MAX_DEP_INFO_BYTES
        or helper.DEP_INFO_NAME != EXPECTED_DEP_INFO_NAME
    ):
        raise AssertionError("compiler source-closure helper authority changed")
    with tempfile.TemporaryDirectory(prefix="compiler-source-closure-") as directory:
        root = Path(directory).resolve()
        workspace = root / "sealed-workspace"
        target = root / "workspace-target"
        source_root = workspace / "crates/ordinary-wallet-plan/src"
        source_root.mkdir(parents=True)
        target.mkdir()
        target.chmod(0o755)
        sources = [source_root / name for name in ("lib.rs", "reader.rs", "writer.rs")]
        for source in sources:
            source.write_bytes(b"source\n")
        workspace.chmod(0o555)
        dep_info = target / EXPECTED_DEP_INFO_NAME
        dep_info.write_bytes(
            b"target: crates/ordinary-wallet-plan/src/lib.rs "
            b"crates/ordinary-wallet-plan/src/reader.rs "
            b"crates/ordinary-wallet-plan/src/writer.rs\n"
        )
        dep_info.chmod(0o644)
        expected = tuple(
            f"crates/ordinary-wallet-plan/src/{name}"
            for name in ("lib.rs", "reader.rs", "writer.rs")
        )
        if helper.read_source_closure(workspace, target, dep_info, os.getuid(), os.getuid()) != expected:
            raise AssertionError("compiler source-closure reader changed canonical sources")

        dep_info.write_text(
            "target: " + " ".join(source.as_posix() for source in sources) + "\n",
            encoding="utf-8",
        )
        dep_info.chmod(0o644)
        if helper.read_source_closure(workspace, target, dep_info, os.getuid(), os.getuid()) != expected:
            raise AssertionError("absolute compiler source paths changed canonical sources")

        invoked = subprocess.run(
            [
                sys.executable,
                "-I",
                str(HELPER),
                str(workspace),
                str(target),
                str(dep_info),
                str(os.getuid()),
                str(os.getuid()),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=10,
        )
        if invoked.returncode != 0 or invoked.stderr or invoked.stdout != ("\n".join(expected) + "\n").encode():
            raise AssertionError("compiler source-closure CLI changed canonical output")

        target.chmod(0o775)
        expect_rejection(
            lambda: helper.read_source_closure(workspace, target, dep_info, os.getuid(), os.getuid()),
            "writable compiler target root was accepted",
        )
        target.chmod(0o755)

        workspace.chmod(0o755)
        expect_rejection(
            lambda: helper.read_source_closure(workspace, target, dep_info, os.getuid(), os.getuid()),
            "writable compiler workspace root was accepted",
        )
        workspace.chmod(0o555)

        expect_rejection(
            lambda: helper.read_source_closure(workspace, target, dep_info, os.getuid() + 1, os.getuid()),
            "wrong-owner compiler workspace root was accepted",
        )

        wrong_mode = root / "wrong-mode" / "workspace-target"
        wrong_mode.mkdir(parents=True)
        wrong_mode_dep = wrong_mode / EXPECTED_DEP_INFO_NAME
        wrong_mode_dep.write_bytes(dep_info.read_bytes())
        wrong_mode_dep.chmod(0o600)
        expect_rejection(
            lambda: helper.stable_read(wrong_mode, wrong_mode_dep, os.getuid()),
            "wrong-mode compiler source-closure was accepted",
        )

        linked_target = root / "linked" / "workspace-target"
        linked_target.mkdir(parents=True)
        linked_dep = linked_target / EXPECTED_DEP_INFO_NAME
        linked_dep.write_bytes(dep_info.read_bytes())
        linked_dep.chmod(0o644)
        os.link(linked_dep, root / "linked-alias")
        expect_rejection(
            lambda: helper.stable_read(linked_target, linked_dep, os.getuid()),
            "hardlinked compiler source-closure was accepted",
        )

        symlink_target = root / "symlink" / "workspace-target"
        symlink_target.mkdir(parents=True)
        symlink_dep = symlink_target / EXPECTED_DEP_INFO_NAME
        symlink_dep.symlink_to(dep_info)
        expect_rejection(
            lambda: helper.stable_read(symlink_target, symlink_dep, os.getuid()),
            "symlinked compiler source-closure was accepted",
        )

        expect_rejection(
            lambda: helper.stable_read(target, dep_info, os.getuid() + 1),
            "wrong-owner compiler source-closure was accepted",
        )

        oversized_target = root / "oversized" / "workspace-target"
        oversized_target.mkdir(parents=True)
        oversized_dep = oversized_target / EXPECTED_DEP_INFO_NAME
        oversized_dep.write_bytes(b"x" * (EXPECTED_MAX_DEP_INFO_BYTES + 1))
        oversized_dep.chmod(0o644)
        expect_rejection(
            lambda: helper.stable_read(oversized_target, oversized_dep, os.getuid()),
            "oversized compiler source-closure was accepted",
        )

        original_read = helper.os.read
        replaced = False
        displaced = target / "displaced.d"

        def replace_after_read(descriptor, maximum):
            nonlocal replaced
            data = original_read(descriptor, maximum)
            if descriptor > 2 and not replaced:
                replaced = True
                dep_info.rename(displaced)
                dep_info.write_bytes(data)
                dep_info.chmod(0o644)
            return data

        helper.os.read = replace_after_read
        try:
            expect_rejection(
                lambda: helper.stable_read(target, dep_info, os.getuid()),
                "replaced compiler source-closure was accepted",
            )
        finally:
            helper.os.read = original_read

        original_read = helper.os.read
        target_changed = False

        def change_target_after_read(descriptor, maximum):
            nonlocal target_changed
            data = original_read(descriptor, maximum)
            if descriptor > 2 and not target_changed:
                target_changed = True
                target.chmod(0o700)
                target.chmod(0o755)
            return data

        helper.os.read = change_target_after_read
        try:
            expect_rejection(
                lambda: helper.stable_read(target, dep_info, os.getuid()),
                "mutated-and-restored compiler target root was accepted",
            )
        finally:
            helper.os.read = original_read
        displaced.rename(dep_info)

        original_read = helper.os.read
        restored = False

        def mutate_and_restore_after_read(descriptor, maximum):
            nonlocal restored
            data = original_read(descriptor, maximum)
            if descriptor > 2 and not restored:
                restored = True
                dep_info.write_bytes(data[::-1])
                dep_info.write_bytes(data)
                dep_info.chmod(0o644)
            return data

        helper.os.read = mutate_and_restore_after_read
        try:
            expect_rejection(
                lambda: helper.stable_read(target, dep_info, os.getuid()),
                "mutated-and-restored compiler source-closure was accepted",
            )
        finally:
            helper.os.read = original_read

        dep_info.write_text(f"target: {(root / 'outside.rs').as_posix()}\n", encoding="utf-8")
        dep_info.chmod(0o644)
        expect_rejection(
            lambda: helper.read_source_closure(workspace, target, dep_info, os.getuid(), os.getuid()),
            "absolute compiler source path outside the workspace was accepted",
        )

        escaped = target / EXPECTED_DEP_INFO_NAME
        escaped.write_bytes(b"target: ../outside.rs\n")
        escaped.chmod(0o644)
        expect_rejection(
            lambda: helper.read_source_closure(workspace, target, escaped, os.getuid(), os.getuid()),
            "escaping compiler source path was accepted",
        )

        escaped.write_bytes(b"target: crates\\ordinary-wallet-plan\\src\\lib.rs\n")
        escaped.chmod(0o644)
        expect_rejection(
            lambda: helper.read_source_closure(workspace, target, escaped, os.getuid(), os.getuid()),
            "escaped compiler source path syntax was accepted",
        )

        for noncanonical in (
            b"target: crates//ordinary-wallet-plan/src/lib.rs\n",
            b"target: crates/./ordinary-wallet-plan/src/lib.rs\n",
        ):
            escaped.write_bytes(noncanonical)
            escaped.chmod(0o644)
            expect_rejection(
                lambda: helper.read_source_closure(workspace, target, escaped, os.getuid(), os.getuid()),
                "normalized compiler source path syntax was accepted",
            )

        escaped.write_bytes(b"target: crates/ordinary-wallet-plan/src/lib.rs\r\n")
        escaped.chmod(0o644)
        expect_rejection(
            lambda: helper.read_source_closure(workspace, target, escaped, os.getuid(), os.getuid()),
            "noncanonical compiler source-closure encoding was accepted",
        )

        for noncanonical in (
            b"",
            b"target: crates/ordinary-wallet-plan/src/lib.rs",
            b"target: crates/ordinary-wallet-plan/src/lib.rs\x00\n",
            b"target: crates/ordinary-wallet-plan/src/lib.rs\xff\n",
        ):
            escaped.write_bytes(noncanonical)
            escaped.chmod(0o644)
            expect_rejection(
                lambda: helper.read_source_closure(workspace, target, escaped, os.getuid(), os.getuid()),
                "noncanonical compiler source-closure bytes were accepted",
            )

    print("compiler source-closure reader accepted")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
