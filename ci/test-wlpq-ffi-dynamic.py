#!/usr/bin/env python3
import ctypes
import os
import stat
import sys
from pathlib import Path


def reject(message: str) -> None:
    raise SystemExit(message)


def read_regular(path: Path, maximum: int) -> bytes:
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > maximum:
        reject("WLPQ FFI dynamic-test input is not a bounded regular file")
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        before = os.fstat(descriptor)
        data = os.read(descriptor, maximum + 1)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (
        len(data) != metadata.st_size
        or before.st_dev != metadata.st_dev
        or before.st_ino != metadata.st_ino
        or before.st_size != metadata.st_size
        or after.st_dev != before.st_dev
        or after.st_ino != before.st_ino
        or after.st_size != before.st_size
    ):
        reject("WLPQ FFI dynamic-test input changed during read")
    return data


def decode_fixture(root: Path, name: str) -> bytes:
    path = (
        root
        / "contracts/ordinary-wallet-plan/v1/nonlinkable-reference/vectors/frames"
        / name
    )
    text = read_regular(path, 1024 * 1024)
    if not text.endswith(b"\n") or b"\r" in text:
        reject("WLPQ FFI dynamic-test fixture framing changed")
    try:
        return bytes.fromhex(text[:-1].decode("ascii"))
    except (UnicodeDecodeError, ValueError):
        reject("WLPQ FFI dynamic-test fixture encoding changed")


def invoke(function, frame: bytes, epoch: bytes) -> int:
    frame_buffer = ctypes.create_string_buffer(frame)
    epoch_buffer = ctypes.create_string_buffer(epoch)
    return int(function(frame_buffer, len(frame), epoch_buffer))


def main() -> None:
    if len(sys.argv) != 3:
        reject("usage: test-wlpq-ffi-dynamic.py REPOSITORY_ROOT LIBRARY")
    root = Path(sys.argv[1]).resolve()
    library_path = Path(sys.argv[2]).resolve()
    library_bytes = read_regular(library_path, 64 * 1024 * 1024)
    if len(library_bytes) == 0:
        reject("WLPQ FFI dynamic library is empty")
    if sys.platform == "darwin":
        expected_identity = b"@rpath/libwasabi_liquid_wlpq_v1.dylib\0"
    elif sys.platform.startswith("linux"):
        expected_identity = b"libwasabi_liquid_wlpq_v1.so\0"
    else:
        reject("WLPQ FFI dynamic library host is not qualified")
    if (
        library_bytes.count(expected_identity) != 1
        or str(library_path).encode("utf-8") + b"\0" in library_bytes
    ):
        reject("WLPQ FFI dynamic library identity changed")

    library = ctypes.CDLL(str(library_path))
    try:
        function = library.wln_wlpq_validate_v1
    except AttributeError:
        reject("WLPQ FFI dynamic export is missing")
    function.argtypes = (ctypes.c_void_p, ctypes.c_uint64, ctypes.c_void_p)
    function.restype = ctypes.c_int32  # WLPQ FFI validate restype
    try:
        sign_function = library.wln_wlpq_sign_finalize_v1
    except AttributeError:
        reject("WLPQ FFI dynamic sign export is missing")
    sign_function.argtypes = (
        ctypes.c_void_p,
        ctypes.c_uint64,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_uint64,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_uint64,
        ctypes.c_uint64,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_uint64,
    )
    sign_function.restype = ctypes.c_int32  # WLPQ FFI dynamic sign restype

    epoch = bytes([0x41]) * 32
    rows = (
        ("frame-test-toy-single.hex", epoch, 0),
        ("frame-wrong-magic.hex", epoch, -2),
        ("frame-truncated-body.hex", epoch, -3),
        ("frame-candidate-length-plus-one.hex", epoch, -4),
        ("frame-test-toy-single.hex", bytes([0x42]) * 32, -5),
    )
    for name, expected_epoch, expected_status in rows:
        actual = invoke(function, decode_fixture(root, name), expected_epoch)
        if actual != expected_status:
            reject("WLPQ FFI dynamic status mismatch")

    byte = ctypes.c_uint8(0)
    epoch_buffer = ctypes.create_string_buffer(epoch)
    if function(None, 1, epoch_buffer) != -1:
        reject("WLPQ FFI dynamic null-pointer precedence changed")
    if function(ctypes.byref(byte), 268_435_457, epoch_buffer) != -4:
        reject("WLPQ FFI dynamic outer-limit precedence changed")
    out_length = ctypes.c_uint64(0)
    if (
        sign_function(
            None,
            1,
            epoch_buffer,
            None,
            None,
            None,
            None,
            0,
            ctypes.byref(out_length),
            None,
            0,
            0,
            None,
            None,
            0,
        )
        != -1
    ):
        reject("WLPQ FFI dynamic sign null-pointer precedence changed")
    if read_regular(library_path, 64 * 1024 * 1024) != library_bytes:
        reject("WLPQ FFI dynamic library changed during execution")

    try:
        txid_function = library.wln_wlpq_transaction_id_v1
    except AttributeError:
        reject("WLPQ FFI dynamic txid export is missing")
    txid_function.argtypes = (
        ctypes.c_void_p,
        ctypes.c_uint64,
        ctypes.c_void_p,
        ctypes.c_uint64,
    )
    txid_function.restype = ctypes.c_int32  # WLPQ FFI dynamic txid restype

    txid_out = ctypes.create_string_buffer(64)
    txid_sentinel = bytes([0xA5]) * 64
    ctypes.memset(txid_out, 0xA5, 64)
    if txid_function(None, 1, txid_out, 64) != -1:
        reject("WLPQ FFI dynamic txid null-pointer precedence changed")
    if txid_out.raw != txid_sentinel:
        reject("WLPQ FFI dynamic txid null-pointer wrote output")
    if txid_function(ctypes.byref(byte), 0, txid_out, 64) != -1:
        reject("WLPQ FFI dynamic txid zero-length precedence changed")
    if txid_out.raw != txid_sentinel:
        reject("WLPQ FFI dynamic txid zero-length wrote output")
    if txid_function(ctypes.byref(byte), 1, None, 64) != -1:
        reject("WLPQ FFI dynamic txid null-output precedence changed")
    if txid_function(ctypes.byref(byte), 1, txid_out, 63) != -1:
        reject("WLPQ FFI dynamic txid capacity precedence changed")
    if txid_out.raw != txid_sentinel:
        reject("WLPQ FFI dynamic txid capacity wrote output")
    if txid_function(ctypes.byref(byte), 268_435_457, txid_out, 64) != -4:
        reject("WLPQ FFI dynamic txid outer-limit precedence changed")
    if txid_out.raw != txid_sentinel:
        reject("WLPQ FFI dynamic txid outer-limit wrote output")
    txid_frame = decode_fixture(root, "frame-test-toy-single.hex")
    if txid_function(txid_frame, len(txid_frame), txid_out, 64) != -3:
        reject("WLPQ FFI dynamic txid invalid-encoding status changed")
    if txid_out.raw != txid_sentinel:
        reject("WLPQ FFI dynamic txid invalid-encoding wrote output")
    txid_truncated = txid_frame[: len(txid_frame) // 2]
    if txid_function(txid_truncated, len(txid_truncated), txid_out, 64) != -3:
        reject("WLPQ FFI dynamic txid truncated status changed")
    if txid_out.raw != txid_sentinel:
        reject("WLPQ FFI dynamic txid truncated wrote output")
    txid_trailing = txid_frame + b"\x00"
    if txid_function(txid_trailing, len(txid_trailing), txid_out, 64) != -3:
        reject("WLPQ FFI dynamic txid trailing status changed")
    if txid_out.raw != txid_sentinel:
        reject("WLPQ FFI dynamic txid trailing wrote output")

    candidate_path = (
        root
        / "contracts/ordinary-wallet-plan/v1/nonlinkable-reference/vectors/public/test-candidate-valid.hex"
    )
    candidate_text = read_regular(candidate_path, 1024 * 1024)
    if not candidate_text.endswith(b"\n") or b"\r" in candidate_text:
        reject("WLPQ FFI dynamic-test candidate fixture framing changed")
    try:
        candidate = bytes.fromhex(candidate_text[:-1].decode("ascii"))
    except (UnicodeDecodeError, ValueError):
        reject("WLPQ FFI dynamic-test candidate fixture encoding changed")
    expected_txid = b"c71de6c2b9dfb2b68f6676d49203ddca9e624ce6398b6b38e9db7fc899864fc0"
    ctypes.memset(txid_out, 0xA5, 64)
    if txid_function(candidate, len(candidate), txid_out, 64) != 0:
        reject("WLPQ FFI dynamic txid known-answer status changed")
    if txid_out.raw != expected_txid:
        reject("WLPQ FFI dynamic txid known-answer mismatch")
    if read_regular(library_path, 64 * 1024 * 1024) != library_bytes:
        reject("WLPQ FFI dynamic library changed during execution")


if __name__ == "__main__":
    main()
