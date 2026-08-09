use std::ffi::c_void;
use std::mem::{align_of, offset_of, size_of};

use wasabi_liquid_native_abi_v24_types::*;

#[test]
fn matches_all_v24_type_sizes_and_alignments() {
    assert_eq!(size_of::<WlnStatusV24>(), 4);
    assert_eq!(align_of::<WlnStatusV24>(), 4);
    assert_eq!(size_of::<WlnBorrowedBufferV24>(), 16);
    assert_eq!(align_of::<WlnBorrowedBufferV24>(), 8);
    assert_eq!(size_of::<WlnOwnedBufferV24>(), 32);
    assert_eq!(align_of::<WlnOwnedBufferV24>(), 8);
    assert_eq!(size_of::<WlnHandleV24>(), 16);
    assert_eq!(align_of::<WlnHandleV24>(), 8);
    assert_eq!(size_of::<WlnAllocatorV24>(), 64);
    assert_eq!(align_of::<WlnAllocatorV24>(), 8);
    assert_eq!(size_of::<WlnCallContextV24>(), 96);
    assert_eq!(align_of::<WlnCallContextV24>(), 8);
    assert_eq!(size_of::<WlnDiagnosticV24>(), 96);
    assert_eq!(align_of::<WlnDiagnosticV24>(), 8);
    assert_eq!(size_of::<WlnResultV24>(), 160);
    assert_eq!(align_of::<WlnResultV24>(), 8);
    assert_eq!(size_of::<WlnAbiDescriptorV24>(), 128);
    assert_eq!(align_of::<WlnAbiDescriptorV24>(), 8);
}

#[test]
fn matches_all_v24_field_offsets() {
    assert_eq!(offset_of!(WlnBorrowedBufferV24, data), 0);
    assert_eq!(offset_of!(WlnBorrowedBufferV24, length), 8);

    assert_eq!(offset_of!(WlnOwnedBufferV24, data), 0);
    assert_eq!(offset_of!(WlnOwnedBufferV24, length), 8);
    assert_eq!(offset_of!(WlnOwnedBufferV24, capacity), 16);
    assert_eq!(offset_of!(WlnOwnedBufferV24, owner_cookie), 24);

    assert_eq!(offset_of!(WlnHandleV24, value), 0);
    assert_eq!(offset_of!(WlnHandleV24, generation), 8);

    assert_eq!(offset_of!(WlnAllocatorV24, struct_size), 0);
    assert_eq!(offset_of!(WlnAllocatorV24, flags), 4);
    assert_eq!(offset_of!(WlnAllocatorV24, context), 8);
    assert_eq!(offset_of!(WlnAllocatorV24, allocate), 16);
    assert_eq!(offset_of!(WlnAllocatorV24, reallocate), 24);
    assert_eq!(offset_of!(WlnAllocatorV24, free), 32);
    assert_eq!(offset_of!(WlnAllocatorV24, reserved), 40);

    assert_eq!(offset_of!(WlnCallContextV24, struct_size), 0);
    assert_eq!(offset_of!(WlnCallContextV24, abi_major), 4);
    assert_eq!(offset_of!(WlnCallContextV24, abi_minor), 6);
    assert_eq!(offset_of!(WlnCallContextV24, flags), 8);
    assert_eq!(offset_of!(WlnCallContextV24, reserved0), 12);
    assert_eq!(offset_of!(WlnCallContextV24, allocator), 16);
    assert_eq!(offset_of!(WlnCallContextV24, is_cancelled), 24);
    assert_eq!(offset_of!(WlnCallContextV24, cancel_context), 32);
    assert_eq!(offset_of!(WlnCallContextV24, relative_timeout_ns), 40);
    assert_eq!(offset_of!(WlnCallContextV24, trace_id), 48);
    assert_eq!(offset_of!(WlnCallContextV24, reserved), 64);

    assert_eq!(offset_of!(WlnDiagnosticV24, struct_size), 0);
    assert_eq!(offset_of!(WlnDiagnosticV24, domain), 4);
    assert_eq!(offset_of!(WlnDiagnosticV24, severity), 6);
    assert_eq!(offset_of!(WlnDiagnosticV24, code), 8);
    assert_eq!(offset_of!(WlnDiagnosticV24, flags), 12);
    assert_eq!(offset_of!(WlnDiagnosticV24, message), 16);
    assert_eq!(offset_of!(WlnDiagnosticV24, context), 48);
    assert_eq!(offset_of!(WlnDiagnosticV24, reserved), 80);

    assert_eq!(offset_of!(WlnResultV24, struct_size), 0);
    assert_eq!(offset_of!(WlnResultV24, status), 4);
    assert_eq!(offset_of!(WlnResultV24, operation), 8);
    assert_eq!(offset_of!(WlnResultV24, flags), 12);
    assert_eq!(offset_of!(WlnResultV24, payload), 16);
    assert_eq!(offset_of!(WlnResultV24, diagnostic), 48);
    assert_eq!(offset_of!(WlnResultV24, reserved), 144);

    assert_eq!(offset_of!(WlnAbiDescriptorV24, struct_size), 0);
    assert_eq!(offset_of!(WlnAbiDescriptorV24, abi_major), 4);
    assert_eq!(offset_of!(WlnAbiDescriptorV24, abi_minor), 6);
    assert_eq!(offset_of!(WlnAbiDescriptorV24, pointer_width), 8);
    assert_eq!(offset_of!(WlnAbiDescriptorV24, endianness), 9);
    assert_eq!(offset_of!(WlnAbiDescriptorV24, status_width), 10);
    assert_eq!(offset_of!(WlnAbiDescriptorV24, flags_width), 11);
    assert_eq!(offset_of!(WlnAbiDescriptorV24, feature_flags), 12);
    assert_eq!(offset_of!(WlnAbiDescriptorV24, max_input_bytes), 16);
    assert_eq!(offset_of!(WlnAbiDescriptorV24, max_output_bytes), 24);
    assert_eq!(offset_of!(WlnAbiDescriptorV24, abi_header_sha256), 32);
    assert_eq!(offset_of!(WlnAbiDescriptorV24, abi_layout_sha256), 40);
    assert_eq!(offset_of!(WlnAbiDescriptorV24, shared_identity_digest), 48);
    assert_eq!(
        offset_of!(WlnAbiDescriptorV24, shared_identity_digest_length),
        56
    );
    assert_eq!(offset_of!(WlnAbiDescriptorV24, reserved0), 60);
    assert_eq!(offset_of!(WlnAbiDescriptorV24, reserved_identity), 64);
    assert_eq!(offset_of!(WlnAbiDescriptorV24, reserved), 80);
}

#[test]
fn matches_v24_constants() {
    assert_eq!(WLN_ABI_MAJOR_V24, 24);
    assert_eq!(WLN_ABI_MINOR_V24, 0);
    assert_eq!(WLN_ORDINARY_WALLET_CAPABILITY_V24, 0);
    assert_eq!(WLN_WALLET_RECOVERY_CAPABILITY_V24, 0);
    assert_eq!(WLN_PRODUCTION_SIGNING_CAPABILITY_V24, 0);
    assert_eq!(WLN_MULTIPARTY_TRANSACTION_CAPABILITY_V24, 0);
    assert_eq!(WLN_MAX_INPUT_BYTES_V24, 268_435_456);
    assert_eq!(WLN_MAX_OUTPUT_BYTES_V24, 268_435_456);
    assert_eq!(WLN_MAX_DIAGNOSTIC_MESSAGE_BYTES_V24, 4_096);
    assert_eq!(WLN_MAX_DIAGNOSTIC_CONTEXT_BYTES_V24, 16_384);
    assert_eq!(WLN_MAX_RELATIVE_TIMEOUT_NS_V24, 3_600_000_000_000);
    assert_eq!(WLN_INVALID_HANDLE_VALUE_V24, 0);

    assert_eq!(WLN_STATUS_OK_V24, 0);
    assert_eq!(WLN_STATUS_INVALID_ARGUMENT_V24, -1);
    assert_eq!(WLN_STATUS_ABI_MISMATCH_V24, -2);
    assert_eq!(WLN_STATUS_INVALID_ENCODING_V24, -3);
    assert_eq!(WLN_STATUS_LIMIT_EXCEEDED_V24, -4);
    assert_eq!(WLN_STATUS_AUTHORITY_REJECTED_V24, -5);
    assert_eq!(WLN_STATUS_CRYPTOGRAPHIC_PROOF_REJECTED_V24, -6);
    assert_eq!(WLN_STATUS_PROVIDER_BINDING_REJECTED_V24, -7);
    assert_eq!(WLN_STATUS_NO_VALID_PLAN_V24, -8);
    assert_eq!(WLN_STATUS_CANCELLED_V24, -9);
    assert_eq!(WLN_STATUS_DEADLINE_EXCEEDED_V24, -10);
    assert_eq!(WLN_STATUS_OUT_OF_MEMORY_V24, -11);
    assert_eq!(WLN_STATUS_IO_ERROR_V24, -12);
    assert_eq!(WLN_STATUS_INTERNAL_ERROR_V24, -13);
    assert_eq!(WLN_STATUS_BUSY_V24, -14);
    assert_eq!(WLN_STATUS_CALLBACK_PROTOCOL_ERROR_V24, -15);

    assert_eq!(WLN_OP_ORDINARY_PLAN_V24, 1);
    assert_eq!(WLN_OP_ORDINARY_BUILD_PSET_V24, 2);
    assert_eq!(WLN_OP_ORDINARY_BLIND_V24, 3);

    assert_eq!(WLN_DIAG_DOMAIN_NONE_V24, 0);
    assert_eq!(WLN_DIAG_DOMAIN_ABI_V24, 1);
    assert_eq!(WLN_DIAG_DOMAIN_KERNEL_V24, 2);
    assert_eq!(WLN_DIAG_DOMAIN_SYSTEM_V24, 3);
    assert_eq!(WLN_DIAG_SEVERITY_NONE_V24, 0);
    assert_eq!(WLN_DIAG_SEVERITY_INFO_V24, 1);
    assert_eq!(WLN_DIAG_SEVERITY_WARNING_V24, 2);
    assert_eq!(WLN_DIAG_SEVERITY_ERROR_V24, 3);
    assert_eq!(WLN_DIAG_FLAG_NONE_V24, 0);
    assert_eq!(WLN_DIAG_FLAG_MESSAGE_SENSITIVE_V24, 1);
    assert_eq!(WLN_DIAG_FLAG_CONTEXT_SENSITIVE_V24, 2);
}

#[test]
fn callback_aliases_are_nullable_pointer_width_values() {
    assert_eq!(size_of::<WlnAllocateFnV24>(), size_of::<*const c_void>());
    assert_eq!(size_of::<WlnReallocateFnV24>(), size_of::<*const c_void>());
    assert_eq!(size_of::<WlnFreeFnV24>(), size_of::<*const c_void>());
    assert_eq!(size_of::<WlnIsCancelledFnV24>(), size_of::<*const c_void>());

    let allocate: WlnAllocateFnV24 = None;
    let reallocate: WlnReallocateFnV24 = None;
    let free: WlnFreeFnV24 = None;
    let is_cancelled: WlnIsCancelledFnV24 = None;
    assert!(allocate.is_none());
    assert!(reallocate.is_none());
    assert!(free.is_none());
    assert!(is_cancelled.is_none());
}

#[test]
fn diagnostic_initializer_is_canonical_empty() {
    let diagnostic = WLN_DIAGNOSTIC_INIT_V24;
    assert_eq!(diagnostic.struct_size, 96);
    assert_eq!(diagnostic.domain, WLN_DIAG_DOMAIN_NONE_V24);
    assert_eq!(diagnostic.severity, WLN_DIAG_SEVERITY_NONE_V24);
    assert_eq!(diagnostic.code, 0);
    assert_eq!(diagnostic.flags, WLN_DIAG_FLAG_NONE_V24);
    assert!(diagnostic.message.data.is_null());
    assert_eq!(diagnostic.message.length, 0);
    assert_eq!(diagnostic.message.capacity, 0);
    assert_eq!(diagnostic.message.owner_cookie, 0);
    assert!(diagnostic.context.data.is_null());
    assert_eq!(diagnostic.context.length, 0);
    assert_eq!(diagnostic.context.capacity, 0);
    assert_eq!(diagnostic.context.owner_cookie, 0);
    assert_eq!(diagnostic.reserved, [0; 2]);
}

#[test]
fn result_initializer_is_canonical_empty() {
    let result = WLN_RESULT_INIT_V24;
    assert_eq!(result.struct_size, 160);
    assert_eq!(result.status, WLN_STATUS_OK_V24);
    assert_eq!(result.operation, 0);
    assert_eq!(result.flags, 0);
    assert!(result.payload.data.is_null());
    assert_eq!(result.payload.length, 0);
    assert_eq!(result.payload.capacity, 0);
    assert_eq!(result.payload.owner_cookie, 0);
    assert_eq!(result.diagnostic.struct_size, 96);
    assert!(result.diagnostic.message.data.is_null());
    assert!(result.diagnostic.context.data.is_null());
    assert_eq!(result.diagnostic.reserved, [0; 2]);
    assert_eq!(result.reserved, [0; 2]);
}
