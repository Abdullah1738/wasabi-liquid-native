#ifndef WASABI_LIQUID_NATIVE_ABI_FIRST_SLICE_V24_H
#define WASABI_LIQUID_NATIVE_ABI_FIRST_SLICE_V24_H

#include <stddef.h>
#include <stdint.h>

#if defined(_WIN32)
#define WLN_EXPORT __declspec(dllexport)
#define WLN_CALL __cdecl
#else
#define WLN_EXPORT __attribute__((visibility("default")))
#define WLN_CALL
#endif

#if defined(__cplusplus)
extern "C" {
#endif

#if UINTPTR_MAX != UINT64_MAX
#error "product-native ABI v24 requires 64-bit pointers"
#endif

#define WLN_ABI_MAJOR_V24 UINT16_C(24)
#define WLN_ABI_MINOR_V24 UINT16_C(0)
#define WLN_ORDINARY_WALLET_CAPABILITY_V24 UINT8_C(0)
#define WLN_WALLET_RECOVERY_CAPABILITY_V24 UINT8_C(0)
#define WLN_PRODUCTION_SIGNING_CAPABILITY_V24 UINT8_C(0)
#define WLN_MULTIPARTY_TRANSACTION_CAPABILITY_V24 UINT8_C(0)
#define WLN_MAX_INPUT_BYTES_V24 UINT64_C(268435456)
#define WLN_MAX_OUTPUT_BYTES_V24 UINT64_C(268435456)
#define WLN_MAX_DIAGNOSTIC_MESSAGE_BYTES_V24 UINT64_C(4096)
#define WLN_MAX_DIAGNOSTIC_CONTEXT_BYTES_V24 UINT64_C(16384)
#define WLN_MAX_RELATIVE_TIMEOUT_NS_V24 UINT64_C(3600000000000)
#define WLN_INVALID_HANDLE_VALUE_V24 UINT64_C(0)
#define WLN_DIAGNOSTIC_INIT_V24 { UINT32_C(96), UINT16_C(0), UINT16_C(0), UINT32_C(0), UINT32_C(0), { NULL, UINT64_C(0), UINT64_C(0), UINT64_C(0) }, { NULL, UINT64_C(0), UINT64_C(0), UINT64_C(0) }, { UINT64_C(0), UINT64_C(0) } }
#define WLN_RESULT_INIT_V24 { UINT32_C(160), WLN_STATUS_OK_V24, UINT32_C(0), UINT32_C(0), { NULL, UINT64_C(0), UINT64_C(0), UINT64_C(0) }, WLN_DIAGNOSTIC_INIT_V24, { UINT64_C(0), UINT64_C(0) } }

typedef int32_t wln_status_v24;

enum wln_status_code_v24 {
    WLN_STATUS_OK_V24 = 0,
    WLN_STATUS_INVALID_ARGUMENT_V24 = -1,
    WLN_STATUS_ABI_MISMATCH_V24 = -2,
    WLN_STATUS_INVALID_ENCODING_V24 = -3,
    WLN_STATUS_LIMIT_EXCEEDED_V24 = -4,
    WLN_STATUS_AUTHORITY_REJECTED_V24 = -5,
    WLN_STATUS_CRYPTOGRAPHIC_PROOF_REJECTED_V24 = -6,
    WLN_STATUS_PROVIDER_BINDING_REJECTED_V24 = -7,
    WLN_STATUS_NO_VALID_PLAN_V24 = -8,
    WLN_STATUS_CANCELLED_V24 = -9,
    WLN_STATUS_DEADLINE_EXCEEDED_V24 = -10,
    WLN_STATUS_OUT_OF_MEMORY_V24 = -11,
    WLN_STATUS_IO_ERROR_V24 = -12,
    WLN_STATUS_INTERNAL_ERROR_V24 = -13,
    WLN_STATUS_BUSY_V24 = -14,
    WLN_STATUS_CALLBACK_PROTOCOL_ERROR_V24 = -15
};

enum wln_operation_v24 {
    WLN_OP_ORDINARY_PLAN_V24 = 1,
    WLN_OP_ORDINARY_BUILD_PSET_V24 = 2,
    WLN_OP_ORDINARY_BLIND_V24 = 3
};

enum wln_diagnostic_domain_v24 {
    WLN_DIAG_DOMAIN_NONE_V24 = 0,
    WLN_DIAG_DOMAIN_ABI_V24 = 1,
    WLN_DIAG_DOMAIN_KERNEL_V24 = 2,
    WLN_DIAG_DOMAIN_SYSTEM_V24 = 3
};

enum wln_diagnostic_severity_v24 {
    WLN_DIAG_SEVERITY_NONE_V24 = 0,
    WLN_DIAG_SEVERITY_INFO_V24 = 1,
    WLN_DIAG_SEVERITY_WARNING_V24 = 2,
    WLN_DIAG_SEVERITY_ERROR_V24 = 3
};

enum wln_diagnostic_flags_v24 {
    WLN_DIAG_FLAG_NONE_V24 = 0,
    WLN_DIAG_FLAG_MESSAGE_SENSITIVE_V24 = 1,
    WLN_DIAG_FLAG_CONTEXT_SENSITIVE_V24 = 2
};

typedef struct wln_borrowed_buffer_v24 {
    const uint8_t *data;
    uint64_t length;
} wln_borrowed_buffer_v24;

typedef struct wln_owned_buffer_v24 {
    uint8_t *data;
    uint64_t length;
    uint64_t capacity;
    uint64_t owner_cookie;
} wln_owned_buffer_v24;

typedef struct wln_handle_v24 {
    uint64_t value;
    uint64_t generation;
} wln_handle_v24;

typedef void *(WLN_CALL *wln_allocate_fn_v24)(void *context, uint64_t size, uint64_t alignment);
typedef void *(WLN_CALL *wln_reallocate_fn_v24)(void *context, void *pointer, uint64_t old_size, uint64_t new_size, uint64_t alignment);
typedef void (WLN_CALL *wln_free_fn_v24)(void *context, void *pointer, uint64_t size, uint64_t alignment);
typedef uint8_t (WLN_CALL *wln_is_cancelled_fn_v24)(void *context);

typedef struct wln_allocator_v24 {
    uint32_t struct_size;
    uint32_t flags;
    void *context;
    wln_allocate_fn_v24 allocate;
    wln_reallocate_fn_v24 reallocate;
    wln_free_fn_v24 free;
    uint64_t reserved[3];
} wln_allocator_v24;

typedef struct wln_call_context_v24 {
    uint32_t struct_size;
    uint16_t abi_major;
    uint16_t abi_minor;
    uint32_t flags;
    uint32_t reserved0;
    const wln_allocator_v24 *allocator;
    wln_is_cancelled_fn_v24 is_cancelled;
    void *cancel_context;
    uint64_t relative_timeout_ns;
    uint8_t trace_id[16];
    uint64_t reserved[4];
} wln_call_context_v24;

typedef struct wln_diagnostic_v24 {
    uint32_t struct_size;
    uint16_t domain;
    uint16_t severity;
    uint32_t code;
    uint32_t flags;
    wln_owned_buffer_v24 message;
    wln_owned_buffer_v24 context;
    uint64_t reserved[2];
} wln_diagnostic_v24;

typedef struct wln_result_v24 {
    uint32_t struct_size;
    wln_status_v24 status;
    uint32_t operation;
    uint32_t flags;
    wln_owned_buffer_v24 payload;
    wln_diagnostic_v24 diagnostic;
    uint64_t reserved[2];
} wln_result_v24;

typedef struct wln_abi_descriptor_v24 {
    uint32_t struct_size;
    uint16_t abi_major;
    uint16_t abi_minor;
    uint8_t pointer_width;
    uint8_t endianness;
    uint8_t status_width;
    uint8_t flags_width;
    uint32_t feature_flags;
    uint64_t max_input_bytes;
    uint64_t max_output_bytes;
    const uint8_t *abi_header_sha256;
    const uint8_t *abi_layout_sha256;
    const uint8_t *shared_identity_digest;
    uint32_t shared_identity_digest_length;
    uint32_t reserved0;
    uint64_t reserved_identity[2];
    uint64_t reserved[6];
} wln_abi_descriptor_v24;

WLN_EXPORT wln_status_v24 WLN_CALL
wln_abi_get_descriptor_v24(const wln_abi_descriptor_v24 **out_descriptor);

WLN_EXPORT wln_status_v24 WLN_CALL
wln_context_create_v24(const wln_call_context_v24 *call_context,
                      wln_borrowed_buffer_v24 configuration,
                      wln_handle_v24 *out_handle,
                      wln_diagnostic_v24 *out_diagnostic);

WLN_EXPORT wln_status_v24 WLN_CALL
wln_context_release_v24(wln_handle_v24 *handle,
                       wln_diagnostic_v24 *out_diagnostic);

WLN_EXPORT wln_status_v24 WLN_CALL
wln_invoke_v24(wln_handle_v24 handle,
              const wln_call_context_v24 *call_context,
              uint32_t operation,
              wln_borrowed_buffer_v24 input,
              wln_result_v24 *out_result);

WLN_EXPORT wln_status_v24 WLN_CALL
wln_result_release_v24(wln_result_v24 *result);

WLN_EXPORT wln_status_v24 WLN_CALL
wln_diagnostic_release_v24(wln_diagnostic_v24 *diagnostic);

WLN_EXPORT wln_status_v24 WLN_CALL
wln_abi_can_unload_v24(uint8_t *out_can_unload);

#if defined(__cplusplus)
}
#endif

#if defined(__cplusplus)
#define WLN_STATIC_ASSERT_V24(condition, message) static_assert((condition), message)
#define WLN_ALIGNOF_V24(type) alignof(type)
#else
#define WLN_STATIC_ASSERT_V24(condition, message) _Static_assert((condition), message)
#define WLN_ALIGNOF_V24(type) _Alignof(type)
#endif

WLN_STATIC_ASSERT_V24(sizeof(wln_status_v24) == 4, "wln_status_v24 size");
WLN_STATIC_ASSERT_V24(sizeof(wln_borrowed_buffer_v24) == 16, "wln_borrowed_buffer_v24 size");
WLN_STATIC_ASSERT_V24(WLN_ALIGNOF_V24(wln_borrowed_buffer_v24) == 8, "wln_borrowed_buffer_v24 alignment");
WLN_STATIC_ASSERT_V24(sizeof(wln_owned_buffer_v24) == 32, "wln_owned_buffer_v24 size");
WLN_STATIC_ASSERT_V24(WLN_ALIGNOF_V24(wln_owned_buffer_v24) == 8, "wln_owned_buffer_v24 alignment");
WLN_STATIC_ASSERT_V24(sizeof(wln_handle_v24) == 16, "wln_handle_v24 size");
WLN_STATIC_ASSERT_V24(sizeof(wln_allocator_v24) == 64, "wln_allocator_v24 size");
WLN_STATIC_ASSERT_V24(sizeof(wln_call_context_v24) == 96, "wln_call_context_v24 size");
WLN_STATIC_ASSERT_V24(sizeof(wln_diagnostic_v24) == 96, "wln_diagnostic_v24 size");
WLN_STATIC_ASSERT_V24(sizeof(wln_result_v24) == 160, "wln_result_v24 size");
WLN_STATIC_ASSERT_V24(sizeof(wln_abi_descriptor_v24) == 128, "wln_abi_descriptor_v24 size");
WLN_STATIC_ASSERT_V24(offsetof(wln_owned_buffer_v24, owner_cookie) == 24, "owned buffer owner offset");
WLN_STATIC_ASSERT_V24(offsetof(wln_call_context_v24, allocator) == 16, "call context allocator offset");
WLN_STATIC_ASSERT_V24(offsetof(wln_call_context_v24, relative_timeout_ns) == 40, "call context timeout offset");
WLN_STATIC_ASSERT_V24(offsetof(wln_call_context_v24, trace_id) == 48, "call context trace offset");
WLN_STATIC_ASSERT_V24(offsetof(wln_diagnostic_v24, message) == 16, "diagnostic message offset");
WLN_STATIC_ASSERT_V24(offsetof(wln_result_v24, payload) == 16, "result payload offset");
WLN_STATIC_ASSERT_V24(offsetof(wln_result_v24, diagnostic) == 48, "result diagnostic offset");
WLN_STATIC_ASSERT_V24(offsetof(wln_abi_descriptor_v24, max_input_bytes) == 16, "descriptor input limit offset");
WLN_STATIC_ASSERT_V24(offsetof(wln_abi_descriptor_v24, reserved_identity) == 64, "descriptor reserved identity offset");

#undef WLN_STATIC_ASSERT_V24
#undef WLN_ALIGNOF_V24

#endif
