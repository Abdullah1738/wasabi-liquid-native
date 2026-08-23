#include "../include/wasabi_liquid_wallet_facts_v1.h"

#if defined(_WIN32)
#define WLN_WALLET_FACTS_EXPORT_V1 __declspec(dllexport)
#else
#define WLN_WALLET_FACTS_EXPORT_V1 __attribute__((visibility("default")))
#endif

extern int32_t wln_wallet_facts_observe_impl_v1(
    const uint8_t *request_frame,
    uint64_t request_frame_length,
    const uint8_t *expected_source_epoch,
    const uint8_t *slip77_master_key,
    uint8_t *out_response,
    uint64_t out_response_capacity,
    uint64_t *out_response_length,
    const uint8_t *entropy,
    uint64_t entropy_length);

WLN_WALLET_FACTS_EXPORT_V1 int32_t wln_wallet_facts_observe_v1(
    const uint8_t *request_frame,
    uint64_t request_frame_length,
    const uint8_t *expected_source_epoch,
    const uint8_t *slip77_master_key,
    uint8_t *out_response,
    uint64_t out_response_capacity,
    uint64_t *out_response_length,
    const uint8_t *entropy,
    uint64_t entropy_length)
{
    return wln_wallet_facts_observe_impl_v1(
        request_frame,
        request_frame_length,
        expected_source_epoch,
        slip77_master_key,
        out_response,
        out_response_capacity,
        out_response_length,
        entropy,
        entropy_length);
}
