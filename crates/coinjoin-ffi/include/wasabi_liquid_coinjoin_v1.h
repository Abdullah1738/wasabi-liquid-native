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
#define WLCJ_OP_PROVE_INPUT_REGISTRATION_V1 UINT32_C(8)
#define WLCJ_OP_PROVE_OUTPUT_REGISTRATION_V1 UINT32_C(9)
#define WLCJ_OP_PROVE_PARTIAL_BALANCE_V1 UINT32_C(10)
#define WLCJ_OP_SIGNING_DIGESTS_V1 UINT32_C(11)
#define WLCJ_OP_ASSEMBLE_SIGNATURES_V1 UINT32_C(12)

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
 * Ops 8/9 are additive; ops 1-7 retain their original wire contracts.
 * Op 8 fields, in order: exact PSET bytes, registration context, Ma (33-byte
 * compressed point), v (u64 BE), r1 (32-byte BE scalar), r2 (32-byte BE scalar),
 * proof entropy (32 fresh caller-supplied bytes). Op 9 appends the exact output
 * value_rangeproof bytes and asset_surjection_proof bytes, in that order.
 * r2 is the raw Liquid VBF for the PSET element's actual asset generator,
 * not the effective balance blinding. Scalars must be < secp256k1 order (zero
 * allowed); v <= 2100000000000000. The kind must match the op and the indexed
 * element must have the required confidential shape. Op 9 compares both proof
 * fields byte-for-byte to that output. Payload caps: 1081344 / 3178496 bytes.
 * Success returns ONE 162-byte equality-proof field (182-byte complete frame),
 * verified natively before return; inconsistent witnesses return -6, invalid
 * values/scalars/points/context/element/proof bindings -5, field lengths -1.
 * Entropy freshness cannot be checked statelessly; every 32-byte value is
 * accepted. A capacity query performs the proof operation; repeat the identical
 * request to retrieve its deterministic result, then erase caller buffers.
 *
 * Registration context (same as ops 2/3): profile u8=1, network length u32 BE
 * and bytes, genesis[32], L-BTC asset[32], round length u32 BE and bytes, phase
 * u8 (1/2/3), role u8 (1/2), ordinal u32 BE, kind u8 (1=input,2=output), element
 * index u32 BE, PSET state digest[32]. Network/round must be nonempty and within
 * their existing profile bounds. No trailing context bytes are accepted.
 * The digest is caller-supplied, NOT recomputed (also true of ops 2/3/7).
 * Composition must canonicalize/check the exact revision and full canonical
 * context, validate PSET admission/proofs, and enforce ownership/fee policy.
 * Proof creation authenticates neither credential issuance nor consumption;
 * WabiSabi credentials remain managed. No issuer/MAC/state/handles are created.
 *
 * Op 10 is additive; ops 1-9 retain their wire contracts. Fields, in order:
 * exact PSET bytes, partial-balance context (same as op 7), effective residual
 * scalar (32-byte BE, 0 < scalar < secp256k1 order), entropy (32 fresh caller
 * bytes). Residual = sum(vbf + value*abf) over own inputs minus that sum over
 * own outputs, modulo the curve order; raw VBF alone is NOT this witness.
 * Payload cap: 1081344 bytes. Success returns ONE existing 65-byte proof field
 * (85-byte frame), after prove AND verify against the recomputed PSET residual
 * and context. Invalid scalar/context/element or proving failure returns -5;
 * an inconsistent witness returns -6; bad field lengths/count returns -1.
 * Op 10 rejects zero residuals and zero fee shares with -5 (validation failed).
 * Op 7 retains its legacy verification path and -6 for zero-fee proof failure.
 * The compressed Schnorr encoding has no identity-point field; an identity proof cannot
 * bind its transcript. The caller must reject this profile before op 10.
 * Entropy freshness and deterministic capacity-query rules match ops 8/9.
 *
 * Balance context: profile u8=1, network length u32 BE and bytes, genesis[32],
 * L-BTC asset[32], round length u32 BE and bytes, phase u8 (1/2/3), role u8
 * (1/2), ordinal u32 BE, PSET state digest[32], input count u32 BE then input
 * indices u32 BE, output count u32 BE then output indices u32 BE, fee share
 * u64 BE. Existing op-7 profile/count bounds apply; no trailing bytes.
 * The digest is supplied, NOT recomputed. The caller must canonicalize full
 * state, match the digest, validate asset/proof admission, enforce disjoint
 * contributions and fee sums, and retain its own witnesses. No ownership
 * guarantee or output-opening/witness acquisition is provided by op 10.
 *
 * Ops 11/12 are additive; ops 1-10 are unchanged. Both payload caps: 1081344.
 * Common fields: exact final PSET, canonical context, approved digest[32],
 * complete authorization vector. Context (same as op 1): profile u8=1,
 * network length u32 BE and bytes, genesis[32], L-BTC asset[32], fee asset[32],
 * round length u32 BE and bytes, phase u8=3 (PreSigning), role u8 (1/2),
 * ordinal u32 BE, predecessor tag u8 (0 absent, 1 followed by digest[32]).
 * Authorization: count u32 BE (1..16), then ascending records for ALL inputs:
 * index u32 BE, txid[32] in Elements byte-array order (not display hex), vout
 * u32 BE, compressed public key[33]. Native checks exact outpoint and P2WPKH
 * ownership, final lifecycle, full-domain proofs, balance and approved digest.
 * The caller must independently approve the digest/context/full authorization;
 * computing a digest from an untrusted candidate is not participant approval.
 *
 * Op 11 fifth field: owned count u32 BE (1..16), then strictly ascending unique
 * indices u32 BE. Response fields: binding[32], canonical digest[32], requests.
 * Requests: count u32 BE, then (authorization record[73], signing digest[32],
 * sighash u8=0x41). Sign original digest bytes WITHOUT reversal, strict DER
 * low-S ECDSA, append 0x41 (SIGHASH_ALL|RANGEPROOF). No private spend keys enter
 * native code; no signing callback or handle is exposed through this ABI.
 *
 * Binding = SHA256("WLCJ_SIGNING_BINDING_V1" || the exact first four common
 * length-prefixed fields). Owned subset is excluded so independent participants
 * share the binding. This public consistency token is NOT authentication or a
 * MAC: ECDSA authenticates the transaction, not off-chain round context. Caller
 * must retain approved bytes and associate contributions with that binding via
 * authenticated participant messaging; public tokens can be relabeled.
 *
 * Op 12 fifth field: count u32 BE then (binding[32], index u32 BE, compressed
 * public key[33], signature length u32 BE, DER+0x41 bytes, maximum 73 bytes).
 * Order is arbitrary; exactly one contribution per authorized input required.
 * Response fields: binding[32], canonical digest[32], finalized transaction
 * bytes, txid[32] in Elements byte-array order. Native reconstructs capability,
 * revalidates all signatures through the existing callback path and verifies
 * assembly. Transaction body and output proofs are unchanged; no reblinding.
 * Invalid state/digest/authorization/subset: -5; contribution binding/set/key,
 * signature or assembly failure: -6; malformed lengths/count fields/trailing:
 * -1; outer payload/field limits: -4. Capacity queries perform full validation;
 * repeat identical request bytes. Output-opening acquisition is not provided.
 *
 * Apart from the witness-class intermediate handoff below, response payloads are
 * public canonical projections, 32-byte digests, serialized PSET handoffs,
 * fixed-size verification verdicts, and equality/partial-balance proofs. Caller-supplied witness material
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
