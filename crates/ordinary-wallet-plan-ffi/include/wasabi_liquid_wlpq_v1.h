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
#define WLN_WLPQ_STATUS_SIGNER_REFUSED_V1 (-INT32_C(10))
#define WLN_WLPQ_STATUS_SIGNING_REJECTED_V1 (-INT32_C(11))
#define WLN_WLPQ_STATUS_OUTPUT_CAPACITY_V1 (-INT32_C(12))

/*
 * The caller-owned public-key callback. The native adapter passes the opaque
 * signer context, one borrowed 36-byte consensus-serialized outpoint with its
 * explicit length, and a caller output buffer of capacity at least 33. On
 * success the callback writes the 33-byte compressed public key and returns
 * WLN_WLPQ_STATUS_OK_V1; any other return is a fail-closed refusal surfaced
 * as WLN_WLPQ_STATUS_SIGNER_REFUSED_V1.
 */
typedef int32_t (*wln_wlpq_public_key_callback_v1)(
    const uint8_t *context,
    const uint8_t *outpoint,
    uint64_t outpoint_length,
    uint8_t *out_public_key,
    uint64_t public_key_capacity);

/*
 * The caller-owned digest-signature callback. The native adapter passes the
 * opaque signer context, one borrowed 36-byte consensus-serialized outpoint
 * with its explicit length, the natively computed 32-byte
 * sighash-with-rangeproof digest, and a caller output buffer of capacity at
 * least 73. On success the callback writes the strict-DER low-S signature
 * including the trailing sighash byte and returns WLN_WLPQ_STATUS_OK_V1; any
 * other return is a fail-closed refusal surfaced as
 * WLN_WLPQ_STATUS_SIGNER_REFUSED_V1.
 */
typedef int32_t (*wln_wlpq_sign_digest_callback_v1)(
    const uint8_t *context,
    const uint8_t *outpoint,
    uint64_t outpoint_length,
    const uint8_t *digest,
    uint8_t *out_signature,
    uint64_t signature_capacity);

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

/*
 * Signs and finalizes one canonical WLPQ v1 frame through caller-owned signing
 * callbacks.
 *
 * The caller retains the frame and epoch buffers and MUST keep them readable
 * and immutable until this call returns. The signer stays caller-owned: only
 * compressed public keys and digest signatures cross the callback boundary and
 * the native side never receives, copies, or stores a secret key. The
 * descriptor is the caller-owned public spend descriptor text used to prove
 * selected-output ownership, last_index is its highest derived index, and
 * slip77_master_key references the 32-byte SLIP-77 master blinding key used to
 * open the selected confidential outputs. On success the finalized
 * confidential transaction serialization is written to out_transaction and
 * its byte length to *out_transaction_length; when out_transaction_capacity
 * is too small the required length is still reported and
 * WLN_WLPQ_STATUS_OUTPUT_CAPACITY_V1 is returned.
 */
int32_t wln_wlpq_sign_finalize_v1(
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
    const uint8_t *slip77_master_key);

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
