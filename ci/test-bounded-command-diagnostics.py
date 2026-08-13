#!/usr/bin/env python3
"""Mutation-test bounded command diagnostic capture and emission."""

from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "ci/capture-bounded-command-diagnostics.py"
EXPECTED_MAX_DIAGNOSTIC_BYTES = 16 * 1024
EXPECTED_TRUNCATION_MARKER = b"\n[diagnostics truncated]\n"


def load_helper():
    spec = importlib.util.spec_from_file_location("bounded_command_diagnostics", HELPER)
    if spec is None or spec.loader is None:
        raise AssertionError("bounded diagnostic helper import failed")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def expect_helper_rejection(operation, message: str) -> None:
    try:
        operation()
    except Exception as error:
        if error.__class__.__name__ != "DiagnosticError":
            raise
        return
    raise AssertionError(message)


def capture(payload: bytes, root: Path) -> bytes:
    output = root / "diagnostics.log"
    collector = subprocess.run(
        [sys.executable, "-I", str(HELPER), "--capture-stdin", str(output)],
        input=payload,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=10,
    )
    if collector.returncode != 0 or collector.stdout or collector.stderr:
        raise AssertionError("bounded diagnostic collector failed")
    return output.read_bytes()


def main() -> int:
    helper = load_helper()
    with tempfile.TemporaryDirectory(prefix="bounded-command-diagnostics-") as directory:
        root = Path(directory).resolve()
        small_root = root / "small"
        small_root.mkdir()
        small = capture(b"exact diagnostic\n", small_root)
        if small != b"exact diagnostic\n":
            raise AssertionError("bounded diagnostic capture changed an in-range payload")

        large_root = root / "large"
        large_root.mkdir()
        large = capture(b"x" * (EXPECTED_MAX_DIAGNOSTIC_BYTES * 8), large_root)
        if (
            len(large) != EXPECTED_MAX_DIAGNOSTIC_BYTES
            or not large.endswith(EXPECTED_TRUNCATION_MARKER)
        ):
            raise AssertionError("bounded diagnostic capture retained unbounded bytes")

        emitted = subprocess.run(
            [sys.executable, "-I", str(HELPER), "--emit", str(large_root / "diagnostics.log")],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if emitted.returncode != 0 or emitted.stdout or emitted.stderr != large:
            raise AssertionError("bounded diagnostic emission differs from retained bytes")

        oversized = root / "oversized.log"
        oversized.write_bytes(b"x" * (EXPECTED_MAX_DIAGNOSTIC_BYTES + 1))
        oversized.chmod(0o600)
        rejected = subprocess.run(
            [sys.executable, "-I", str(HELPER), "--emit", str(oversized)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if rejected.returncode == 0 or len(rejected.stderr) > 256:
            raise AssertionError("oversized diagnostic output was accepted or emitted unboundedly")

        preexisting_root = root / "preexisting"
        preexisting_root.mkdir()
        preexisting = preexisting_root / "diagnostics.log"
        preexisting.write_bytes(b"existing")
        rejected = subprocess.run(
            [sys.executable, "-I", str(HELPER), "--capture-stdin", str(preexisting)],
            input=b"producer diagnostics",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=10,
        )
        if rejected.returncode == 0 or preexisting.read_bytes() != b"existing":
            raise AssertionError("preexisting diagnostic destination was accepted")

        pipeline_status = root / "pipeline.status"
        pipeline_script = r'''
set -eu
diagnostic_output=$1
diagnostic_status=$2
helper=$3
python_bin=$4
if ! (
    "$python_bin" -c 'import sys; sys.stderr.buffer.write(b"x" * (2 * 1024 * 1024))'
    /usr/bin/printf '%s\n' 0 >"$diagnostic_status"
) 2>&1 | "$python_bin" -I "$helper" --capture-stdin "$diagnostic_output"
then
    exit 19
fi
exit 0
'''
        rejected_pipeline = subprocess.run(
            [
                "/bin/sh",
                "-c",
                pipeline_script,
                "bounded-diagnostic-pipeline",
                str(preexisting),
                str(pipeline_status),
                str(HELPER),
                sys.executable,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=10,
        )
        if rejected_pipeline.returncode != 19 or preexisting.read_bytes() != b"existing":
            raise AssertionError("collector pre-open failure did not terminate the producer pipeline")

        regular_input = root / "regular-input"
        regular_input.write_bytes(b"producer diagnostics")
        regular_output = root / "regular-input-output"
        with regular_input.open("rb") as stream:
            rejected = subprocess.run(
                [sys.executable, "-I", str(HELPER), "--capture-stdin", str(regular_output)],
                stdin=stream,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=10,
            )
        if rejected.returncode == 0 or regular_output.exists():
            raise AssertionError("non-pipe diagnostic input was accepted")

        wrong_mode = root / "wrong-mode.log"
        wrong_mode.write_bytes(b"diagnostic")
        wrong_mode.chmod(0o644)
        expect_helper_rejection(
            lambda: helper.emit(wrong_mode),
            "wrong-mode diagnostic output was accepted",
        )

        hardlinked = root / "hardlinked.log"
        hardlinked.write_bytes(b"diagnostic")
        hardlinked.chmod(0o600)
        os.link(hardlinked, root / "hardlinked-alias.log")
        expect_helper_rejection(
            lambda: helper.emit(hardlinked),
            "hardlinked diagnostic output was accepted",
        )

        symlink_target = root / "symlink-target.log"
        symlink_target.write_bytes(b"diagnostic")
        symlink_target.chmod(0o600)
        symlink_output = root / "symlink.log"
        symlink_output.symlink_to(symlink_target)
        expect_helper_rejection(
            lambda: helper.emit(symlink_output),
            "symlinked diagnostic output was accepted",
        )

        wrong_owner = root / "wrong-owner.log"
        wrong_owner.write_bytes(b"diagnostic")
        wrong_owner.chmod(0o600)
        original_getuid = helper.os.getuid
        helper.os.getuid = lambda: original_getuid() + 1
        try:
            expect_helper_rejection(
                lambda: helper.emit(wrong_owner),
                "wrong-owner diagnostic output was accepted",
            )
        finally:
            helper.os.getuid = original_getuid

        replaced = root / "replaced.log"
        replaced.write_bytes(b"diagnostic")
        replaced.chmod(0o600)
        displaced = root / "replaced-displaced.log"
        original_read = helper.os.read
        replaced_once = False

        def replace_after_read(descriptor, maximum):
            nonlocal replaced_once
            data = original_read(descriptor, maximum)
            if descriptor > 2 and not replaced_once:
                replaced_once = True
                replaced.rename(displaced)
                replaced.write_bytes(data)
                replaced.chmod(0o600)
            return data

        helper.os.read = replace_after_read
        try:
            expect_helper_rejection(
                lambda: helper.emit(replaced),
                "replaced diagnostic output was accepted",
            )
        finally:
            helper.os.read = original_read

        restored = root / "restored.log"
        restored.write_bytes(b"diagnostic")
        restored.chmod(0o600)
        original_read = helper.os.read
        restored_once = False

        def mutate_and_restore_after_read(descriptor, maximum):
            nonlocal restored_once
            data = original_read(descriptor, maximum)
            if descriptor > 2 and not restored_once:
                restored_once = True
                restored.write_bytes(data[::-1])
                restored.write_bytes(data)
                restored.chmod(0o600)
            return data

        helper.os.read = mutate_and_restore_after_read
        try:
            expect_helper_rejection(
                lambda: helper.emit(restored),
                "mutated-and-restored diagnostic output was accepted",
            )
        finally:
            helper.os.read = original_read

    print("bounded command diagnostics accepted")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
