#!/usr/bin/env python3
"""Run one command and terminate every descendant before returning."""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import time


def descendants() -> list[int]:
    return sorted(
        int(name)
        for name in os.listdir("/proc")
        if name.isdecimal() and int(name) != os.getpid()
    )


def reap() -> None:
    while True:
        try:
            pid, _ = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            return
        if pid == 0:
            return


def terminate_all() -> None:
    for requested, deadline in ((signal.SIGTERM, time.monotonic() + 1), (signal.SIGKILL, time.monotonic() + 2)):
        for pid in descendants():
            try:
                os.kill(pid, requested)
            except ProcessLookupError:
                pass
        while time.monotonic() < deadline:
            reap()
            if not descendants():
                return
            time.sleep(0.01)
    reap()
    if descendants():
        raise RuntimeError("sealed Linux command left an unreaped descendant")


def main() -> int:
    if os.getpid() != 1 or len(sys.argv) < 2:
        print("sealed command supervisor requires PID 1 and a command", file=sys.stderr)
        return 2
    command = subprocess.Popen(sys.argv[1:])
    try:
        status = command.wait()
    finally:
        terminate_all()
    return status if status >= 0 else 128 - status


if __name__ == "__main__":
    raise SystemExit(main())
