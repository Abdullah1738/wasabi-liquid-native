#!/usr/bin/env python3
"""Drain command diagnostics while retaining and emitting fixed byte bounds."""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path


MAX_DIAGNOSTIC_BYTES = 16 * 1024
TRUNCATION_MARKER = b"\n[diagnostics truncated]\n"


class DiagnosticError(Exception):
    pass


def reject(message: str) -> None:
    raise DiagnosticError(message)


def exact_identity(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_uid,
        value.st_gid,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def capture_stdin(output: Path) -> None:
    if not output.is_absolute():
        reject("diagnostic output path must be absolute")
    if os.path.lexists(output):
        reject("diagnostic output already exists")
    stdin_metadata = os.fstat(0)
    if not stat.S_ISFIFO(stdin_metadata.st_mode):
        reject("diagnostic input is not a pipe")

    retained = bytearray()
    total = 0
    while True:
        chunk = os.read(0, 64 * 1024)
        if not chunk:
            break
        total += len(chunk)
        if len(retained) < MAX_DIAGNOSTIC_BYTES:
            retained.extend(chunk[: MAX_DIAGNOSTIC_BYTES - len(retained)])

    if total > MAX_DIAGNOSTIC_BYTES:
        retained[MAX_DIAGNOSTIC_BYTES - len(TRUNCATION_MARKER) :] = TRUNCATION_MARKER
    output_descriptor = os.open(
        output,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        view = memoryview(retained)
        while view:
            written = os.write(output_descriptor, view)
            view = view[written:]
        os.fsync(output_descriptor)
        output_metadata = os.fstat(output_descriptor)
        if (
            not stat.S_ISREG(output_metadata.st_mode)
            or stat.S_IMODE(output_metadata.st_mode) != 0o600
            or output_metadata.st_nlink != 1
            or output_metadata.st_uid != os.getuid()
            or output_metadata.st_size != len(retained)
            or exact_identity(os.lstat(output)) != exact_identity(output_metadata)
        ):
            reject("captured diagnostic output authority differs")
    finally:
        os.close(output_descriptor)


def emit(output: Path) -> None:
    if not output.is_absolute():
        reject("diagnostic output path must be absolute")
    before = os.lstat(output)
    if (
        not stat.S_ISREG(before.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or stat.S_IMODE(before.st_mode) != 0o600
        or before.st_nlink != 1
        or before.st_uid != os.getuid()
        or before.st_size > MAX_DIAGNOSTIC_BYTES
    ):
        reject("diagnostic output authority differs")
    descriptor = os.open(output, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(descriptor)
        if exact_identity(opened) != exact_identity(before):
            reject("diagnostic output changed before open")
        data = os.read(descriptor, MAX_DIAGNOSTIC_BYTES + 1)
        if len(data) != opened.st_size or len(data) > MAX_DIAGNOSTIC_BYTES:
            reject("diagnostic output exceeded its bound")
        if exact_identity(os.fstat(descriptor)) != exact_identity(opened) or exact_identity(
            os.lstat(output)
        ) != exact_identity(opened):
            reject("diagnostic output changed during read")
    finally:
        os.close(descriptor)
    view = memoryview(data)
    while view:
        written = os.write(2, view)
        view = view[written:]


def main() -> int:
    try:
        if len(sys.argv) == 3 and sys.argv[1] == "--capture-stdin":
            capture_stdin(Path(sys.argv[2]))
        elif len(sys.argv) == 3 and sys.argv[1] == "--emit":
            emit(Path(sys.argv[2]))
        else:
            reject("usage: capture-bounded-command-diagnostics.py --capture-stdin OUTPUT | --emit OUTPUT")
    except (DiagnosticError, OSError) as error:
        print(error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
