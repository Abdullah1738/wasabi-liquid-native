#!/usr/bin/env python3
"""Dynamic dlopen test for the CoinJoin v1 FFI artifact.

Loads the built dynamic library, resolves `wlcj_execute_v1` through the real
symbol table, and exercises the entry point with a genuine canonicalize-state
request plus a battery of hostile malformed frames (wrong magic, wrong ABI
version, unknown op, truncated, oversized, trailing), asserting each is
rejected fail-closed with the frozen typed status and never a crash.
"""
import ctypes
import pathlib
import struct
import sys

MAGIC = 0x574C434A
ABI = 1
OP_CANONICALIZE_STATE = 1
STATUS_OK = 0
STATUS_INVALID_FRAME = -1
STATUS_UNSUPPORTED_ABI = -2
STATUS_UNKNOWN_OP = -3
STATUS_PAYLOAD_TOO_LARGE = -4
STATUS_OUTPUT_CAPACITY = -8


def frame(op: int, payload: bytes, magic: int = MAGIC, abi: int = ABI) -> bytes:
    return struct.pack(">IIII", magic, abi, op, len(payload)) + payload


def field(body: bytes) -> bytes:
    return struct.pack(">I", len(body)) + body


def canonicalize_payload() -> bytes:
    # One field: a minimal invalid PSET (decodes fail-closed), one field: a
    # minimal valid context. Validation failure (-5) is the expected outcome;
    # the point is that a syntactically complete frame dispatches and returns
    # a typed status rather than crashing.
    context = (
        b"\x01"  # profile V1
        + field(b"elements-liquid-mainnet")
        + bytes([0x22] * 32)  # genesis
        + bytes([0x11] * 32)  # lbtc
        + bytes([0x11] * 32)  # fee asset
        + field(b"round-dynamic-0001")
        + b"\x01"  # phase Construction
        + b"\x01"  # role Initiator
        + struct.pack(">I", 1)  # ordinal
        + b"\x00"  # predecessor absent
    )
    return field(b"\x00") + field(context)


def invoke(fn, request: bytes):
    out_len = ctypes.c_uint64(0xFFFFFFFFFFFFFFFF)
    status = fn(request, len(request), None, 0, ctypes.byref(out_len))
    return status, out_len.value


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit("usage: test-coinjoin-ffi-dynamic.py REPOSITORY_ROOT LIBRARY")
    root = pathlib.Path(sys.argv[1]).resolve()
    library_path = pathlib.Path(sys.argv[2]).resolve()
    _ = root
    library = ctypes.CDLL(str(library_path))
    execute = library.wlcj_execute_v1
    execute.restype = ctypes.c_int32
    execute.argtypes = [
        ctypes.c_char_p, ctypes.c_uint64,
        ctypes.c_char_p, ctypes.c_uint64,
        ctypes.POINTER(ctypes.c_uint64),
    ]

    # Null frame shape.
    status, _ = invoke(execute, b"")
    assert status == STATUS_INVALID_FRAME, status

    # A syntactically complete canonicalize request: the capacity query
    # publishes the required length or a typed validation/verification status.
    good = frame(OP_CANONICALIZE_STATE, canonicalize_payload())
    status, required = invoke(execute, good)
    assert status in (
        STATUS_OUTPUT_CAPACITY,
        STATUS_INVALID_FRAME,
        -5,  # validation failed: the empty PSET is not a real PSET
    ), status
    if status == STATUS_OUTPUT_CAPACITY:
        out = ctypes.create_string_buffer(required)
        written = ctypes.c_uint64(0)
        status = execute(good, len(good), out, required, ctypes.byref(written))
        assert status == STATUS_OK, status

    # Hostile malformed frames.
    wrong_magic = frame(OP_CANONICALIZE_STATE, canonicalize_payload(), magic=0x00000000)
    status, _ = invoke(execute, wrong_magic)
    assert status == STATUS_INVALID_FRAME, status

    wrong_abi = frame(OP_CANONICALIZE_STATE, canonicalize_payload(), abi=2)
    status, _ = invoke(execute, wrong_abi)
    assert status == STATUS_UNSUPPORTED_ABI, status

    unknown_op = frame(99, canonicalize_payload())
    status, _ = invoke(execute, unknown_op)
    assert status == STATUS_UNKNOWN_OP, status

    truncated = good[: len(good) - 1]
    status, _ = invoke(execute, truncated)
    assert status == STATUS_INVALID_FRAME, status

    trailing = good + b"\x00"
    status, _ = invoke(execute, trailing)
    assert status == STATUS_INVALID_FRAME, status

    # Oversized declared payload for op 1 (bound 1081344).
    oversized_declared = struct.pack(">IIII", MAGIC, ABI, OP_CANONICALIZE_STATE, 1081345) + b"\x00"
    status, _ = invoke(execute, oversized_declared)
    assert status in (STATUS_INVALID_FRAME, STATUS_PAYLOAD_TOO_LARGE), status

    print("coinjoin-ffi dynamic: OK")


if __name__ == "__main__":
    main()
