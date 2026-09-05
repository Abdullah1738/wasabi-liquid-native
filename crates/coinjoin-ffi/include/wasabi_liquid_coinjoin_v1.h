#ifndef WASABI_LIQUID_COINJOIN_V1_H
#define WASABI_LIQUID_COINJOIN_V1_H

#include <stdint.h>

#if defined(__cplusplus)
extern "C" {
#endif

#define WLCJ_ABI_VERSION_V1 UINT32_C(1)
#define WLCJ_MAGIC_V1 UINT32_C(0x574C434A)
#define WLCJ_MAX_FRAME_BYTES_V1 UINT64_C(16777216)
#define WLCJ_MAX_RESPONSE_BYTES_V1 UINT64_C(16777216)
#define WLCJ_MAX_FIELDS_V1 UINT32_C(258)
#define WLCJ_MAX_FIELD_BYTES_V1 UINT32_C(2097152)
#define WLCJ_HEADER_BYTES_V1 UINT32_C(16)

#define WLCJ_OP_CANONICALIZE_STATE_V1 UINT32_C(1)
#define WLCJ_OP_VERIFY_INPUT_REGISTRATION_V1 UINT32_C(2)
#define WLCJ_OP_VERIFY_OUTPUT_REGISTRATION_V1 UINT32_C(3)
#define WLCJ_OP_BLIND_NON_LAST_V1 UINT32_C(4)
#define WLCJ_OP_BLIND_LAST_V1 UINT32_C(5)
#define WLCJ_OP_VALIDATE_SIGNER_VIEW_V1 UINT32_C(6)
#define WLCJ_OP_VERIFY_PARTIAL_BALANCE_V1 UINT32_C(7)

#define WLCJ_STATUS_OK_V1 INT32_C(0)
#define WLCJ_STATUS_INVALID_FRAME_V1 (-INT32_C(1))
#define WLCJ_STATUS_UNSUPPORTED_ABI_V1 (-INT32_C(2))
#define WLCJ_STATUS_UNKNOWN_OP_V1 (-INT32_C(3))
#define WLCJ_STATUS_PAYLOAD_TOO_LARGE_V1 (-INT32_C(4))
#define WLCJ_STATUS_VALIDATION_FAILED_V1 (-INT32_C(5))
#define WLCJ_STATUS_VERIFICATION_FAILED_V1 (-INT32_C(6))
#define WLCJ_STATUS_INTERNAL_ERROR_V1 (-INT32_C(7))
#define WLCJ_STATUS_OUTPUT_CAPACITY_V1 (-INT32_C(8))

/*
 * Executes one bounded CoinJoin v1 operation over raw byte frames.
 *
 * The request is exactly one frame:
 *
 *     [magic u32 BE = WLCJ_MAGIC_V1]
 *     [abi_version u32 BE = WLCJ_ABI_VERSION_V1]
 *     [op u32 BE]
 *     [payload_len u32 BE]
 *     [payload: payload_len bytes]
 *
 * The payload is a concatenation of fields, each exactly
 * [u32 BE length][bytes]; every length must individually satisfy the per-field
 * bound, the concatenation must consume the payload exactly, and every field
 * required by the op must be present in the declared order with no extras.
 * The complete request frame must satisfy WLCJ_MAX_FRAME_BYTES_V1 and the
 * per-op payload bound; wrong magic, wrong ABI version, unknown op, a
 * truncated frame, trailing bytes, or an over-bound payload is rejected
 * fail-closed with a typed status and never a panic.
 *
 * On success the response is exactly one frame with the same header shape
 * (same magic, ABI version, and op as the request) whose payload is the op's
 * declared field concatenation. A null out_frame with a zero capacity is the
 * capacity query: the required response frame length is published through
 * out_frame_length and WLCJ_STATUS_OUTPUT_CAPACITY_V1 is returned. The same
 * status is returned when a non-null buffer is too small; the required length
 * is always published first. Every status other than WLCJ_STATUS_OK_V1 and
 * WLCJ_STATUS_OUTPUT_CAPACITY_V1 publishes an out_frame_length of zero and
 * writes nothing to out_frame.
 *
 * No response frame ever carries secret material: response payloads are
 * public canonical projections, 32-byte digests, serialized PSET handoffs,
 * and fixed-size verification verdicts. Caller-supplied witness material
 * (input blinding factors, the partial-balance residual blinding factor, and
 * blinding entropy) is copied into scoped native storage, zeroized before
 * return on every path, and never retained; the native side fabricates no
 * entropy of its own. The serialized intermediate handoff produced by
 * WLCJ_OP_BLIND_NON_LAST_V1 carries the fork's pending balancing scalars
 * inside its PSET global map by protocol construction; the caller must treat
 * those bytes as witness-class material even though they are not marked as
 * fields.
 *
 * The caller retains every buffer and MUST keep request_frame readable and
 * immutable, and a non-null out_frame writable with no overlap with any
 * input, until this call returns. Null shapes are rejected before any
 * dereference, but no C ABI can validate arbitrary non-null pointer
 * provenance.
 */
int32_t wlcj_execute_v1(
    const uint8_t *request_frame,
    uint64_t request_frame_length,
    uint8_t *out_frame,
    uint64_t out_frame_capacity,
    uint64_t *out_frame_length);

#if defined(__cplusplus)
}
#endif

#if defined(__cplusplus)
static_assert(sizeof(uint32_t) == 4, "uint32_t must be four bytes");
static_assert(sizeof(uint64_t) == 8, "uint64_t must be eight bytes");
static_assert(sizeof(int32_t) == 4, "int32_t must be four bytes");
#else
_Static_assert(sizeof(uint32_t) == 4, "uint32_t must be four bytes");
_Static_assert(sizeof(uint64_t) == 8, "uint64_t must be eight bytes");
_Static_assert(sizeof(int32_t) == 4, "int32_t must be four bytes");
#endif

#endif
