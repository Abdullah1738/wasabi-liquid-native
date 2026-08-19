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

extern int32_t wln_wlpq_sign_finalize_impl_v1(
    const uint8_t *frame,
    uint64_t frame_length,
    const uint8_t *expected_source_epoch,
    const uint8_t *signer_context,
    wln_wlpq_public_key_callback_v1 public_key_callback,
    wln_wlpq_sign_digest_callback_v1 sign_digest_callback,
    uint8_t *out_transaction,
    uint64_t out_transaction_capacity,
    uint64_t *out_transaction_length,
    const uint8_t *descriptor,
    uint64_t descriptor_length,
    uint64_t last_index,
    const uint8_t *slip77_master_key,
    const uint8_t *entropy,
    uint64_t entropy_length);

extern int32_t wln_wlpq_transaction_id_impl_v1(
    const uint8_t *transaction,
    uint64_t transaction_length,
    uint8_t *out_txid,
    uint64_t out_txid_capacity);

WLN_WLPQ_EXPORT_V1 int32_t wln_wlpq_validate_v1(
    const uint8_t *frame,
    uint64_t frame_length,
    const uint8_t *expected_source_epoch)
{
    return wln_wlpq_validate_impl_v1(frame, frame_length, expected_source_epoch);
}

WLN_WLPQ_EXPORT_V1 int32_t wln_wlpq_sign_finalize_v1(
    const uint8_t *frame,
    uint64_t frame_length,
    const uint8_t *expected_source_epoch,
    const uint8_t *signer_context,
    wln_wlpq_public_key_callback_v1 public_key_callback,
    wln_wlpq_sign_digest_callback_v1 sign_digest_callback,
    uint8_t *out_transaction,
    uint64_t out_transaction_capacity,
    uint64_t *out_transaction_length,
    const uint8_t *descriptor,
    uint64_t descriptor_length,
    uint64_t last_index,
    const uint8_t *slip77_master_key,
    const uint8_t *entropy,
    uint64_t entropy_length)
{
    return wln_wlpq_sign_finalize_impl_v1(
        frame,
        frame_length,
        expected_source_epoch,
        signer_context,
        public_key_callback,
        sign_digest_callback,
        out_transaction,
        out_transaction_capacity,
        out_transaction_length,
        descriptor,
        descriptor_length,
        last_index,
        slip77_master_key,
        entropy,
        entropy_length);
}

WLN_WLPQ_EXPORT_V1 int32_t wln_wlpq_transaction_id_v1(
    const uint8_t *transaction,
    uint64_t transaction_length,
    uint8_t *out_txid,
    uint64_t out_txid_capacity)
{
    return wln_wlpq_transaction_id_impl_v1(
        transaction,
        transaction_length,
        out_txid,
        out_txid_capacity);
}
