#ifndef WASABI_LIQUID_WLPQ_V1_H
#define WASABI_LIQUID_WLPQ_V1_H

#include <stdint.h>

#if defined(__cplusplus)
extern "C" {
#endif

#define WLN_WLPQ_ABI_VERSION_V1 UINT32_C(1)
#define WLN_WLPQ_MAX_FRAME_BYTES_V1 UINT64_C(268435456)

#define WLN_WLPQ_STATUS_OK_V1 INT32_C(0)
#define WLN_WLPQ_STATUS_INVALID_ARGUMENT_V1 (-INT32_C(1))
#define WLN_WLPQ_STATUS_VERSION_MISMATCH_V1 (-INT32_C(2))
#define WLN_WLPQ_STATUS_INVALID_ENCODING_V1 (-INT32_C(3))
#define WLN_WLPQ_STATUS_LIMIT_EXCEEDED_V1 (-INT32_C(4))
#define WLN_WLPQ_STATUS_SOURCE_BINDING_MISMATCH_V1 (-INT32_C(5))
#define WLN_WLPQ_STATUS_CONTEXT_REJECTED_V1 (-INT32_C(6))
#define WLN_WLPQ_STATUS_PLAN_REJECTED_V1 (-INT32_C(7))
#define WLN_WLPQ_STATUS_FUNDING_REJECTED_V1 (-INT32_C(8))
#define WLN_WLPQ_STATUS_INTERNAL_ERROR_V1 (-INT32_C(9))

/*
 * Validates one canonical WLPQ v1 frame against an exact 32-byte source epoch.
 *
 * The caller retains both buffers and MUST keep them readable and immutable
 * until this call returns. frame_length must be in 1..=268435456. A successful
 * call proves that the native decoder accepted the frame and re-encoded it
 * byte-for-byte; it does not prepare, open, sign, finalize, or broadcast it.
 */
int32_t wln_wlpq_validate_v1(
    const uint8_t *frame,
    uint64_t frame_length,
    const uint8_t *expected_source_epoch);

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
