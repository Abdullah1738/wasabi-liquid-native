#!/usr/bin/env python3
import ctypes
import pathlib
import sys


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit("usage: test-wallet-facts-ffi-dynamic.py REPOSITORY_ROOT LIBRARY")
    root = pathlib.Path(sys.argv[1]).resolve()
    library = ctypes.CDLL(str(pathlib.Path(sys.argv[2]).resolve()))
    observe = library.wln_wallet_facts_observe_v1
    observe.restype = ctypes.c_int32
    observe.argtypes = [
        ctypes.POINTER(ctypes.c_uint8), ctypes.c_uint64,
        ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(ctypes.c_uint8),
        ctypes.POINTER(ctypes.c_uint8), ctypes.c_uint64,
        ctypes.POINTER(ctypes.c_uint64), ctypes.POINTER(ctypes.c_uint8), ctypes.c_uint64,
    ]
    frame_hex = (root / "contracts/wallet-facts/v1/nonlinkable-reference/vectors/frames/request-00-base-empty.hex").read_text().strip()
    frame_bytes = bytes.fromhex(frame_hex)
    frame = (ctypes.c_uint8 * len(frame_bytes)).from_buffer_copy(frame_bytes)
    epoch = (ctypes.c_uint8 * 32).from_buffer_copy(frame_bytes[28:60])
    key = (ctypes.c_uint8 * 32)(*([0x52] * 32))
    entropy = (ctypes.c_uint8 * 32)(*([0x63] * 32))
    required = ctypes.c_uint64(999)
    status = observe(frame, len(frame_bytes), epoch, key, None, 0, ctypes.byref(required), entropy, 32)
    assert status == -10 and required.value == 64
    output = (ctypes.c_uint8 * required.value)(*([0xA5] * required.value))
    entropy2 = (ctypes.c_uint8 * 32)(*([0x74] * 32))
    written = ctypes.c_uint64(999)
    status = observe(frame, len(frame_bytes), epoch, key, output, len(output), ctypes.byref(written), entropy2, 32)
    assert status == 0 and written.value == required.value
    assert bytes(output[:4]) == b"WLFV"
    print("wallet-facts FFI dynamic: OK")


if __name__ == "__main__":
    main()
