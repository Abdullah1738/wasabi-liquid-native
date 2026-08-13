#!/usr/bin/env python3
"""Set the current Linux mount tree read-only through mount_setattr(2)."""

from __future__ import annotations

import ctypes
import os
import sys


AT_FDCWD = -100
AT_RECURSIVE = 0x8000
MOUNT_ATTR_RDONLY = 0x00000001
SYS_MOUNT_SETATTR_X86_64 = 442


class MountAttributes(ctypes.Structure):
    """Version-zero Linux mount_attr structure."""

    _fields_ = (
        ("attr_set", ctypes.c_uint64),
        ("attr_clr", ctypes.c_uint64),
        ("propagation", ctypes.c_uint64),
        ("userns_fd", ctypes.c_uint64),
    )


def main() -> int:
    """Apply the read-only VFS attribute to the complete root mount tree."""

    if (
        sys.platform != "linux"
        or os.uname().machine != "x86_64"
        or len(sys.argv) != 1
        or os.geteuid() != 0
    ):
        raise SystemExit("recursive mount boundary requires Linux x86_64 root and no arguments")

    libc = ctypes.CDLL(None, use_errno=True)
    syscall = libc.syscall
    syscall.restype = ctypes.c_long
    attributes = MountAttributes(attr_set=MOUNT_ATTR_RDONLY)
    if syscall(
        ctypes.c_long(SYS_MOUNT_SETATTR_X86_64),
        ctypes.c_int(AT_FDCWD),
        ctypes.c_char_p(b"/"),
        ctypes.c_uint(AT_RECURSIVE),
        ctypes.byref(attributes),
        ctypes.c_size_t(ctypes.sizeof(attributes)),
    ) != 0:
        error_number = ctypes.get_errno()
        message = os.strerror(error_number)
        raise SystemExit(f"mount_setattr recursive read-only transition failed: {message}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
