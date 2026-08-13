#!/usr/bin/env python3
"""Read one sealed compiler dep-info file without trusting its writable owner."""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path, PurePosixPath


MAX_DEP_INFO_BYTES = 64 * 1024
DEP_INFO_NAME = "ordinary-wallet-plan-source-closure.d"


class SourceClosureError(Exception):
    pass


def reject(message: str) -> None:
    raise SourceClosureError(message)


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


def stable_read(target_root: Path, dep_info: Path, expected_uid: int) -> bytes:
    if not target_root.is_absolute() or not dep_info.is_absolute():
        reject("compiler source-closure paths must be absolute")
    if target_root.name != "workspace-target" or dep_info != target_root / DEP_INFO_NAME:
        reject("compiler source-closure path is noncanonical")
    root_metadata = os.lstat(target_root)
    if (
        stat.S_ISLNK(root_metadata.st_mode)
        or not stat.S_ISDIR(root_metadata.st_mode)
        or stat.S_IMODE(root_metadata.st_mode) != 0o755
        or root_metadata.st_uid != expected_uid
    ):
        reject("compiler target root is linked or non-directory")
    before = os.lstat(dep_info)
    if (
        stat.S_ISLNK(before.st_mode)
        or not stat.S_ISREG(before.st_mode)
        or stat.S_IMODE(before.st_mode) != 0o644
        or before.st_nlink != 1
        or before.st_uid != expected_uid
        or before.st_size <= 0
        or before.st_size > MAX_DEP_INFO_BYTES
    ):
        reject("compiler source-closure authority differs")
    descriptor = os.open(dep_info, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(descriptor)
        if exact_identity(opened) != exact_identity(before):
            reject("compiler source-closure changed before open")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(4096, MAX_DEP_INFO_BYTES + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > MAX_DEP_INFO_BYTES:
                reject("compiler source-closure exceeded its bound")
        if total != opened.st_size:
            reject("compiler source-closure size changed during read")
        if (
            exact_identity(os.fstat(descriptor)) != exact_identity(opened)
            or exact_identity(os.lstat(dep_info)) != exact_identity(opened)
            or exact_identity(os.lstat(target_root)) != exact_identity(root_metadata)
        ):
            reject("compiler source-closure changed during read")
    finally:
        os.close(descriptor)
    return b"".join(chunks)


def read_source_closure(
    workspace_root: Path,
    target_root: Path,
    dep_info: Path,
    expected_workspace_uid: int,
    expected_uid: int,
) -> tuple[str, ...]:
    if not workspace_root.is_absolute() or workspace_root.name != "sealed-workspace":
        reject("compiler workspace root is noncanonical")
    if target_root.parent != workspace_root.parent:
        reject("compiler target root is not the workspace sibling")
    workspace_metadata = os.lstat(workspace_root)
    target_metadata = os.lstat(target_root)
    if (
        stat.S_ISLNK(workspace_metadata.st_mode)
        or not stat.S_ISDIR(workspace_metadata.st_mode)
        or stat.S_IMODE(workspace_metadata.st_mode) != 0o555
        or workspace_metadata.st_uid != expected_workspace_uid
        or stat.S_ISLNK(target_metadata.st_mode)
        or not stat.S_ISDIR(target_metadata.st_mode)
        or stat.S_IMODE(target_metadata.st_mode) != 0o755
        or target_metadata.st_uid != expected_uid
    ):
        reject("compiler workspace root is linked or non-directory")
    data = stable_read(target_root, dep_info, expected_uid)
    if b"\x00" in data or b"\r" in data or not data.endswith(b"\n"):
        reject("compiler source-closure encoding is noncanonical")
    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise SourceClosureError("compiler source-closure is not UTF-8") from error

    found: set[str] = set()
    for line in text.splitlines():
        if ":" not in line:
            continue
        for token in line.split(":", 1)[1].split():
            if "\\" in token:
                reject("compiler source path contains an escape")
            parsed = PurePosixPath(token)
            if (
                parsed.as_posix() != token
                or not parsed.parts
                or any(part in ("", ".", "..") for part in parsed.parts)
            ):
                reject("compiler source path is noncanonical")
            if parsed.is_absolute():
                source = Path(parsed.as_posix())
                try:
                    relative_path = source.relative_to(workspace_root)
                except ValueError as error:
                    raise SourceClosureError("compiler source path escaped its workspace") from error
                relative = PurePosixPath(relative_path.as_posix())
            else:
                relative = parsed
                source = workspace_root.joinpath(*relative.parts)
            relative_text = relative.as_posix()
            current = workspace_root
            for index, part in enumerate(relative.parts):
                current /= part
                source_metadata = os.lstat(current)
                if stat.S_ISLNK(source_metadata.st_mode):
                    reject("compiler source ancestry is linked")
                if index + 1 == len(relative.parts):
                    if not stat.S_ISREG(source_metadata.st_mode):
                        reject("compiler source path is nonregular")
                elif not stat.S_ISDIR(source_metadata.st_mode):
                    reject("compiler source ancestry is non-directory")
            found.add(relative_text)
    if not found:
        reject("compiler source-closure is empty")
    if exact_identity(os.lstat(workspace_root)) != exact_identity(workspace_metadata):
        reject("compiler workspace root changed during parse")
    return tuple(sorted(found))


def main() -> int:
    if len(sys.argv) != 6:
        print(
            "usage: read-compiler-source-closure.py WORKSPACE_ROOT TARGET_ROOT DEP_INFO WORKSPACE_UID BUILD_UID",
            file=sys.stderr,
        )
        return 2
    try:
        expected_workspace_uid = int(sys.argv[4], 10)
        expected_uid = int(sys.argv[5], 10)
        if (
            expected_workspace_uid < 0
            or str(expected_workspace_uid) != sys.argv[4]
            or expected_uid < 0
            or str(expected_uid) != sys.argv[5]
        ):
            reject("compiler source-closure UID is noncanonical")
        sources = read_source_closure(
            Path(sys.argv[1]),
            Path(sys.argv[2]),
            Path(sys.argv[3]),
            expected_workspace_uid,
            expected_uid,
        )
    except (OSError, ValueError, SourceClosureError) as error:
        print(error, file=sys.stderr)
        return 1
    print("\n".join(sources))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
