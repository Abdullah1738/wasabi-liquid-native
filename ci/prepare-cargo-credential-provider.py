#!/usr/bin/env python3
"""Create the isolated Cargo credential-provider positive-control fixture."""

from __future__ import annotations

import os
import shlex
import sys
from pathlib import Path


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: prepare-cargo-credential-provider.py ABSOLUTE_PROVIDER ABSOLUTE_SENTINEL", file=sys.stderr)
        return 2
    provider, sentinel = map(Path, sys.argv[1:])
    if (
        not provider.is_absolute()
        or not sentinel.is_absolute()
        or os.path.lexists(provider)
        or os.path.lexists(sentinel)
    ):
        print("credential-provider fixture requires fresh absolute paths", file=sys.stderr)
        return 1
    source = "\n".join(
        (
            "#!/bin/sh",
            "set -eu",
            "printf '%s\\n' '{\"v\":[1]}'",
            "IFS= read -r request",
            "case \"$request\" in *'\"kind\":\"login\"'*'\"token\":\"wlpq-positive-control\"'*) ;; *) exit 97 ;; esac",
            f"printf '%s' provider-ran >{shlex.quote(str(sentinel))}",
            "printf '%s\\n' '{\"Ok\":{\"kind\":\"login\"}}'",
            "",
        )
    ).encode("utf-8")
    descriptor = os.open(provider, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o700)
    try:
        view = memoryview(source)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short write while creating credential-provider fixture")
            view = view[written:]
    finally:
        os.close(descriptor)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
