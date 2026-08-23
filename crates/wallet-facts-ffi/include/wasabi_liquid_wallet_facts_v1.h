#ifndef WASABI_LIQUID_WALLET_FACTS_V1_H
#define WASABI_LIQUID_WALLET_FACTS_V1_H

#include <stdint.h>

#if defined(__cplusplus)
extern "C" {
#endif

#define WLN_WALLET_FACTS_ABI_VERSION_V1 UINT32_C(1)
#define WLN_WALLET_FACTS_MAX_REQUEST_FRAME_BYTES_V1 UINT64_C(268435456)
#define WLN_WALLET_FACTS_MAX_RESPONSE_FRAME_BYTES_V1 UINT64_C(268435456)
#define WLN_WALLET_FACTS_MAX_REACHABLE_RESPONSE_BYTES_V1 UINT64_C(80599492)

#define WLN_WALLET_FACTS_STATUS_OK_V1 INT32_C(0)
#define WLN_WALLET_FACTS_STATUS_INVALID_ARGUMENT_V1 (-INT32_C(1))
#define WLN_WALLET_FACTS_STATUS_VERSION_MISMATCH_V1 (-INT32_C(2))
#define WLN_WALLET_FACTS_STATUS_INVALID_ENCODING_V1 (-INT32_C(3))
#define WLN_WALLET_FACTS_STATUS_LIMIT_EXCEEDED_V1 (-INT32_C(4))
#define WLN_WALLET_FACTS_STATUS_DESCRIPTOR_REJECTED_V1 (-INT32_C(5))
#define WLN_WALLET_FACTS_STATUS_CANDIDATE_REJECTED_V1 (-INT32_C(6))
#define WLN_WALLET_FACTS_STATUS_OBSERVATION_REJECTED_V1 (-INT32_C(7))
#define WLN_WALLET_FACTS_STATUS_SOURCE_BINDING_MISMATCH_V1 (-INT32_C(8))
#define WLN_WALLET_FACTS_STATUS_INTERNAL_ERROR_V1 (-INT32_C(9))
#define WLN_WALLET_FACTS_STATUS_OUTPUT_CAPACITY_V1 (-INT32_C(10))

/*
 * Fully observes one canonical WLFQ v1 request and returns one canonical WLFV
 * v1 response. The caller retains every input. expected_source_epoch and
 * slip77_master_key reference exactly 32 bytes; entropy references exactly
 * entropy_length == 32 fresh CSPRNG bytes. A null output with zero capacity is
 * a full capacity query. Only OK and OUTPUT_CAPACITY publish a nonzero response
 * length. Mutable outputs must not overlap each other or any borrowed input.
 */
int32_t wln_wallet_facts_observe_v1(
    const uint8_t *request_frame,
    uint64_t request_frame_length,
    const uint8_t *expected_source_epoch,
    const uint8_t *slip77_master_key,
    uint8_t *out_response,
    uint64_t out_response_capacity,
    uint64_t *out_response_length,
    const uint8_t *entropy,
    uint64_t entropy_length);

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
