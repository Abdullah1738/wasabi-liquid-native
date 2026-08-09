#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(not(target_pointer_width = "64"))]
compile_error!("ABI v24 requires 64-bit pointers");

#[cfg(not(target_endian = "little"))]
compile_error!("ABI v24 requires little-endian targets");

use core::ffi::c_void;
use core::ptr::null_mut;

pub type WlnStatusV24 = i32;

pub const WLN_ABI_MAJOR_V24: u16 = 24;
pub const WLN_ABI_MINOR_V24: u16 = 0;
pub const WLN_ORDINARY_WALLET_CAPABILITY_V24: u8 = 0;
pub const WLN_WALLET_RECOVERY_CAPABILITY_V24: u8 = 0;
pub const WLN_PRODUCTION_SIGNING_CAPABILITY_V24: u8 = 0;
pub const WLN_MULTIPARTY_TRANSACTION_CAPABILITY_V24: u8 = 0;
pub const WLN_MAX_INPUT_BYTES_V24: u64 = 268_435_456;
pub const WLN_MAX_OUTPUT_BYTES_V24: u64 = 268_435_456;
pub const WLN_MAX_DIAGNOSTIC_MESSAGE_BYTES_V24: u64 = 4_096;
pub const WLN_MAX_DIAGNOSTIC_CONTEXT_BYTES_V24: u64 = 16_384;
pub const WLN_MAX_RELATIVE_TIMEOUT_NS_V24: u64 = 3_600_000_000_000;
pub const WLN_INVALID_HANDLE_VALUE_V24: u64 = 0;

pub const WLN_STATUS_OK_V24: WlnStatusV24 = 0;
pub const WLN_STATUS_INVALID_ARGUMENT_V24: WlnStatusV24 = -1;
pub const WLN_STATUS_ABI_MISMATCH_V24: WlnStatusV24 = -2;
pub const WLN_STATUS_INVALID_ENCODING_V24: WlnStatusV24 = -3;
pub const WLN_STATUS_LIMIT_EXCEEDED_V24: WlnStatusV24 = -4;
pub const WLN_STATUS_AUTHORITY_REJECTED_V24: WlnStatusV24 = -5;
pub const WLN_STATUS_CRYPTOGRAPHIC_PROOF_REJECTED_V24: WlnStatusV24 = -6;
pub const WLN_STATUS_PROVIDER_BINDING_REJECTED_V24: WlnStatusV24 = -7;
pub const WLN_STATUS_NO_VALID_PLAN_V24: WlnStatusV24 = -8;
pub const WLN_STATUS_CANCELLED_V24: WlnStatusV24 = -9;
pub const WLN_STATUS_DEADLINE_EXCEEDED_V24: WlnStatusV24 = -10;
pub const WLN_STATUS_OUT_OF_MEMORY_V24: WlnStatusV24 = -11;
pub const WLN_STATUS_IO_ERROR_V24: WlnStatusV24 = -12;
pub const WLN_STATUS_INTERNAL_ERROR_V24: WlnStatusV24 = -13;
pub const WLN_STATUS_BUSY_V24: WlnStatusV24 = -14;
pub const WLN_STATUS_CALLBACK_PROTOCOL_ERROR_V24: WlnStatusV24 = -15;

pub const WLN_OP_ORDINARY_PLAN_V24: u32 = 1;
pub const WLN_OP_ORDINARY_BUILD_PSET_V24: u32 = 2;
pub const WLN_OP_ORDINARY_BLIND_V24: u32 = 3;

pub const WLN_DIAG_DOMAIN_NONE_V24: u16 = 0;
pub const WLN_DIAG_DOMAIN_ABI_V24: u16 = 1;
pub const WLN_DIAG_DOMAIN_KERNEL_V24: u16 = 2;
pub const WLN_DIAG_DOMAIN_SYSTEM_V24: u16 = 3;

pub const WLN_DIAG_SEVERITY_NONE_V24: u16 = 0;
pub const WLN_DIAG_SEVERITY_INFO_V24: u16 = 1;
pub const WLN_DIAG_SEVERITY_WARNING_V24: u16 = 2;
pub const WLN_DIAG_SEVERITY_ERROR_V24: u16 = 3;

pub const WLN_DIAG_FLAG_NONE_V24: u32 = 0;
pub const WLN_DIAG_FLAG_MESSAGE_SENSITIVE_V24: u32 = 1;
pub const WLN_DIAG_FLAG_CONTEXT_SENSITIVE_V24: u32 = 2;

#[repr(C)]
pub struct WlnBorrowedBufferV24 {
    pub data: *const u8,
    pub length: u64,
}

#[repr(C)]
pub struct WlnOwnedBufferV24 {
    pub data: *mut u8,
    pub length: u64,
    pub capacity: u64,
    pub owner_cookie: u64,
}

#[repr(C)]
pub struct WlnHandleV24 {
    pub value: u64,
    pub generation: u64,
}

pub type WlnAllocateFnV24 =
    Option<unsafe extern "C" fn(context: *mut c_void, size: u64, alignment: u64) -> *mut c_void>;

pub type WlnReallocateFnV24 = Option<
    unsafe extern "C" fn(
        context: *mut c_void,
        pointer: *mut c_void,
        old_size: u64,
        new_size: u64,
        alignment: u64,
    ) -> *mut c_void,
>;

pub type WlnFreeFnV24 = Option<
    unsafe extern "C" fn(context: *mut c_void, pointer: *mut c_void, size: u64, alignment: u64),
>;

pub type WlnIsCancelledFnV24 = Option<unsafe extern "C" fn(context: *mut c_void) -> u8>;

#[repr(C)]
pub struct WlnAllocatorV24 {
    pub struct_size: u32,
    pub flags: u32,
    pub context: *mut c_void,
    pub allocate: WlnAllocateFnV24,
    pub reallocate: WlnReallocateFnV24,
    pub free: WlnFreeFnV24,
    pub reserved: [u64; 3],
}

#[repr(C)]
pub struct WlnCallContextV24 {
    pub struct_size: u32,
    pub abi_major: u16,
    pub abi_minor: u16,
    pub flags: u32,
    pub reserved0: u32,
    pub allocator: *const WlnAllocatorV24,
    pub is_cancelled: WlnIsCancelledFnV24,
    pub cancel_context: *mut c_void,
    pub relative_timeout_ns: u64,
    pub trace_id: [u8; 16],
    pub reserved: [u64; 4],
}

#[repr(C)]
pub struct WlnDiagnosticV24 {
    pub struct_size: u32,
    pub domain: u16,
    pub severity: u16,
    pub code: u32,
    pub flags: u32,
    pub message: WlnOwnedBufferV24,
    pub context: WlnOwnedBufferV24,
    pub reserved: [u64; 2],
}

#[repr(C)]
pub struct WlnResultV24 {
    pub struct_size: u32,
    pub status: WlnStatusV24,
    pub operation: u32,
    pub flags: u32,
    pub payload: WlnOwnedBufferV24,
    pub diagnostic: WlnDiagnosticV24,
    pub reserved: [u64; 2],
}

#[repr(C)]
pub struct WlnAbiDescriptorV24 {
    pub struct_size: u32,
    pub abi_major: u16,
    pub abi_minor: u16,
    pub pointer_width: u8,
    pub endianness: u8,
    pub status_width: u8,
    pub flags_width: u8,
    pub feature_flags: u32,
    pub max_input_bytes: u64,
    pub max_output_bytes: u64,
    pub abi_header_sha256: *const u8,
    pub abi_layout_sha256: *const u8,
    pub shared_identity_digest: *const u8,
    pub shared_identity_digest_length: u32,
    pub reserved0: u32,
    pub reserved_identity: [u64; 2],
    pub reserved: [u64; 6],
}

pub const WLN_DIAGNOSTIC_INIT_V24: WlnDiagnosticV24 = WlnDiagnosticV24 {
    struct_size: 96,
    domain: 0,
    severity: 0,
    code: 0,
    flags: 0,
    message: WlnOwnedBufferV24 {
        data: null_mut(),
        length: 0,
        capacity: 0,
        owner_cookie: 0,
    },
    context: WlnOwnedBufferV24 {
        data: null_mut(),
        length: 0,
        capacity: 0,
        owner_cookie: 0,
    },
    reserved: [0; 2],
};

pub const WLN_RESULT_INIT_V24: WlnResultV24 = WlnResultV24 {
    struct_size: 160,
    status: WLN_STATUS_OK_V24,
    operation: 0,
    flags: 0,
    payload: WlnOwnedBufferV24 {
        data: null_mut(),
        length: 0,
        capacity: 0,
        owner_cookie: 0,
    },
    diagnostic: WLN_DIAGNOSTIC_INIT_V24,
    reserved: [0; 2],
};
