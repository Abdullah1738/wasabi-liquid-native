#include "../include/wasabi_liquid_coinjoin_v1.h"

#if defined(_WIN32)
#define WLCJ_EXPORT_V1 __declspec(dllexport)
#else
#define WLCJ_EXPORT_V1 __attribute__((visibility("default")))
#endif

extern int32_t wlcj_execute_impl_v1(
    const uint8_t *request_frame,
    uint64_t request_frame_length,
    uint8_t *out_frame,
    uint64_t out_frame_capacity,
    uint64_t *out_frame_length);

WLCJ_EXPORT_V1 int32_t wlcj_execute_v1(
    const uint8_t *request_frame,
    uint64_t request_frame_length,
    uint8_t *out_frame,
    uint64_t out_frame_capacity,
    uint64_t *out_frame_length)
{
    return wlcj_execute_impl_v1(
        request_frame,
        request_frame_length,
        out_frame,
        out_frame_capacity,
        out_frame_length);
}
