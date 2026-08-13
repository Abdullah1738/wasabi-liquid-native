#!/usr/bin/env python3
"""Read every regular byte in exact sealed trees as the build identity."""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path


def read_tree(root: Path) -> None:
    metadata = os.lstat(root)
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise ValueError("sealed read root is linked or non-directory")
    file_count = 0

    def fail_traversal(error: OSError) -> None:
        raise error

    for directory, directories, files in os.walk(
        root,
        topdown=True,
        onerror=fail_traversal,
        followlinks=False,
    ):
        directories.sort()
        files.sort()
        for name in directories:
            child = Path(directory) / name
            child_metadata = os.lstat(child)
            if stat.S_ISLNK(child_metadata.st_mode) or not stat.S_ISDIR(child_metadata.st_mode):
                raise ValueError("sealed read topology contains a linked or non-directory entry")
        for name in files:
            file_count += 1
            path = Path(directory) / name
            file_metadata = os.lstat(path)
            if stat.S_ISLNK(file_metadata.st_mode) or not stat.S_ISREG(file_metadata.st_mode):
                raise ValueError("sealed read topology contains a linked or special file")
            descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            try:
                while os.read(descriptor, 1024 * 1024):
                    pass
            finally:
                os.close(descriptor)
    if file_count == 0:
        raise ValueError("sealed read tree contains no regular files")


def main() -> int:
    if len(sys.argv) < 2 or any(not Path(value).is_absolute() for value in sys.argv[1:]):
        print("usage: check-sealed-tree-readable.py ABSOLUTE_ROOT...", file=sys.stderr)
        return 2
    try:
        for value in sys.argv[1:]:
            read_tree(Path(value))
    except (OSError, ValueError) as error:
        print(f"sealed build identity read check failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
