#include "../include/wasabi_liquid_wlpq_v1.h"

#if defined(_WIN32)
#define WLN_WLPQ_EXPORT_V1 __declspec(dllexport)
#else
#define WLN_WLPQ_EXPORT_V1 __attribute__((visibility("default")))
#endif

extern int32_t wln_wlpq_validate_impl_v1(
    const uint8_t *frame,
    uint64_t frame_length,
    const uint8_t *expected_source_epoch);

WLN_WLPQ_EXPORT_V1 int32_t wln_wlpq_validate_v1(
    const uint8_t *frame,
    uint64_t frame_length,
    const uint8_t *expected_source_epoch)
{
    return wln_wlpq_validate_impl_v1(frame, frame_length, expected_source_epoch);
}
