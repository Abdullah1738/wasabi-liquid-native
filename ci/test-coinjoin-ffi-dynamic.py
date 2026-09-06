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
    if len(sys.argv) not in (3, 4, 5):
        raise SystemExit("usage: test-coinjoin-ffi-dynamic.py REPOSITORY_ROOT LIBRARY [C1_FIXTURES [C2_FIXTURES]]")
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

    if len(sys.argv) >= 4:
        fixtures = pathlib.Path(sys.argv[3]).resolve()

        def call(request):
            status, required = invoke(execute, request)
            assert status == STATUS_OUTPUT_CAPACITY, status
            out = ctypes.create_string_buffer(required)
            written = ctypes.c_uint64(0)
            status = execute(request, len(request), out, required, ctypes.byref(written))
            assert status == STATUS_OK and written.value == required
            return out.raw

        for prove_op, verify_op, suffix, proof_len, scalar_field in (
            (8, 2, "", 162, 4), (9, 3, "", 162, 4),
            (10, 7, "-0", 65, 2), (10, 7, "-1", 65, 2),
        ):
            request = (fixtures / f"op{prove_op}{suffix}.request").read_bytes()
            response = call(request)
            assert response == (fixtures / f"op{prove_op}{suffix}.response").read_bytes()
            assert call(request) == response
            assert len(response) == 20 + proof_len
            assert response[:20] == struct.pack(">IIIII", MAGIC, ABI, prove_op, 4 + proof_len, proof_len)
            verification = bytearray((fixtures / f"op{verify_op}{suffix}.request").read_bytes())
            # Replace its proof with the actual dynamically generated proof.
            offset = 16
            for _ in range(2):
                offset += 4 + struct.unpack_from(">I", verification, offset)[0]
            assert struct.unpack_from(">I", verification, offset)[0] == proof_len
            verification[offset + 4:offset + 4 + proof_len] = response[20:]
            assert call(bytes(verification))[16:] == field(b"OK\x00\x00")
            if prove_op == 10:
                # The balance context's final u64 is the fee share.
                context_offset = 20 + struct.unpack_from(">I", request, 16)[0]
                fee_offset = context_offset + 4 + struct.unpack_from(">I", request, context_offset)[0] - 8
                zero_fee_verification = bytearray(verification)
                zero_fee_verification[fee_offset:fee_offset + 8] = bytes(8)
                status, length = invoke(execute, bytes(zero_fee_verification))
                assert status == -6 and length == 0
                for zero_fee, zero_residual in ((True, False), (False, True), (True, True)):
                    invalid = bytearray(request)
                    if zero_fee:
                        invalid[fee_offset:fee_offset + 8] = bytes(8)
                    if zero_residual:
                        invalid[fee_offset + 12:fee_offset + 44] = bytes(32)
                    status, length = invoke(execute, bytes(invalid))
                    assert status == -5 and length == 0
                    out = ctypes.create_string_buffer(b"\xa5" * 85, 85)
                    written = ctypes.c_uint64(123)
                    status = execute(bytes(invalid), len(invalid), out, 85, ctypes.byref(written))
                    assert status == -5 and written.value == 0 and out.raw == b"\xa5" * 85
            verification[offset + 4] ^= 1
            status, length = invoke(execute, bytes(verification))
            assert status == -6 and length == 0
            # Malformed scalar fails through the real export.
            offset = 16
            for _ in range(scalar_field):
                offset += 4 + struct.unpack_from(">I", request, offset)[0]
            invalid = bytearray(request)
            invalid[offset + 4:offset + 36] = bytes([255] * 32)
            status, length = invoke(execute, bytes(invalid))
            assert status == -5 and length == 0
            if prove_op == 10:
                invalid = bytearray(request)
                invalid[offset + 35] ^= 1
                out = ctypes.create_string_buffer(b"\xa5" * 85, 85)
                written = ctypes.c_uint64(123)
                status = execute(bytes(invalid), len(invalid), out, 85, ctypes.byref(written))
                assert status == -6 and written.value == 0 and out.raw == b"\xa5" * 85
                out = ctypes.create_string_buffer(b"\xa5" * 84, 84)
                status = execute(request, len(request), out, 84, ctypes.byref(written))
                assert status == STATUS_OUTPUT_CAPACITY and written.value == 85
                assert out.raw == b"\xa5" * 84
        print("coinjoin-ffi C1 dynamic: ops 8->2, 9->3 and both participants 10->7 OK")

    if len(sys.argv) == 5:
        fixtures = pathlib.Path(sys.argv[4]).resolve()
        cases = sorted(fixtures.glob("*.status"))
        assert len(cases) >= 50, "missing C2 success/hostile fixtures"
        successful = set()
        for case in cases:
            request = case.with_suffix(".request").read_bytes()
            expected_status = int(case.read_text())
            status, length = invoke(execute, request)
            if expected_status == STATUS_OK:
                expected = case.with_suffix(".response").read_bytes()
                assert status == STATUS_OUTPUT_CAPACITY and length == len(expected), case
                out = ctypes.create_string_buffer(b"\xa5" * (length - 1), length - 1)
                written = ctypes.c_uint64(123)
                status = execute(request, len(request), out, length - 1, ctypes.byref(written))
                assert status == STATUS_OUTPUT_CAPACITY and written.value == length, case
                assert out.raw == b"\xa5" * (length - 1), case
                assert call(request) == expected, case
                assert call(request) == expected, case
                successful.add(case.stem)
            else:
                assert status == expected_status and length == 0, (case, status)
                out = ctypes.create_string_buffer(b"\xa5" * 32768, 32768)
                written = ctypes.c_uint64(123)
                status = execute(request, len(request), out, 32768, ctypes.byref(written))
                assert status == expected_status and written.value == 0, (case, status)
                assert out.raw == b"\xa5" * 32768, case
        assert successful == {"op11-0", "op11-1", "op12"}, successful
        print(f"coinjoin-ffi C2 dynamic: {len(cases)} cases, independent digests and signature assembly OK")

    print("coinjoin-ffi dynamic: OK")


if __name__ == "__main__":
    main()
