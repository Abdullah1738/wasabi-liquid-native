use core::ptr;

use wasabi_liquid_native_wallet_facts_ffi::*;
use wasabi_liquid_native_wallet_facts_wire::{
    DescriptorNetwork, WalletFactsRequestRef, decode_response, encode_request,
};

const DESCRIPTOR: &str = "elwpkh([28b3f14e/84'/1'/0']tpubDC2Q4xK4XH72GM7MowNuajyWVbigRLBWKswyP5T88hpPwu5nGqJWnda8zhJEFt71av73Hm8mUMMFSz9acNVzz8b1UbdSHCDXKTbSv5eEytu/<0;1>/*)#u0khc0kg";
const EPOCH: [u8; 32] = [0x41; 32];
const SLIP77: [u8; 32] = [0x52; 32];
const ENTROPY_A: [u8; 32] = [0x63; 32];
const ENTROPY_B: [u8; 32] = [0x74; 32];

fn empty_request() -> Vec<u8> {
    encode_request(&WalletFactsRequestRef::new(
        &EPOCH,
        DescriptorNetwork::Test,
        0,
        DESCRIPTOR,
        &[],
    ))
    .unwrap()
    .as_bytes()
    .to_vec()
}

#[allow(clippy::too_many_arguments)]
unsafe fn call(
    request: *const u8,
    request_len: u64,
    epoch: *const u8,
    key: *const u8,
    output: *mut u8,
    capacity: u64,
    length: *mut u64,
    entropy: *const u8,
    entropy_len: u64,
) -> i32 {
    unsafe {
        wln_wallet_facts_observe_impl_v1(
            request,
            request_len,
            epoch,
            key,
            output,
            capacity,
            length,
            entropy,
            entropy_len,
        )
    }
}

#[test]
fn capacity_query_and_write_return_canonical_empty_response() {
    let request = empty_request();
    let mut required = 999;
    let status = unsafe {
        call(
            request.as_ptr(),
            request.len() as u64,
            EPOCH.as_ptr(),
            SLIP77.as_ptr(),
            ptr::null_mut(),
            0,
            &mut required,
            ENTROPY_A.as_ptr(),
            32,
        )
    };
    assert_eq!(status, WLN_WALLET_FACTS_STATUS_OUTPUT_CAPACITY_V1);
    assert_eq!(required, 64);

    let mut output = vec![0xa5; required as usize + 8];
    let mut written = 777;
    let status = unsafe {
        call(
            request.as_ptr(),
            request.len() as u64,
            EPOCH.as_ptr(),
            SLIP77.as_ptr(),
            output.as_mut_ptr(),
            output.len() as u64,
            &mut written,
            ENTROPY_B.as_ptr(),
            32,
        )
    };
    assert_eq!(status, WLN_WALLET_FACTS_STATUS_OK_V1);
    assert_eq!(written, required);
    assert!(output[written as usize..].iter().all(|byte| *byte == 0xa5));
    let decoded = decode_response(&output[..written as usize], &EPOCH).unwrap();
    assert!(decoded.transactions().is_empty());
}

#[test]
fn short_capacity_publishes_length_without_writing_output() {
    let request = empty_request();
    let mut output = [0xa5; 63];
    let mut required = 999;
    let status = unsafe {
        call(
            request.as_ptr(),
            request.len() as u64,
            EPOCH.as_ptr(),
            SLIP77.as_ptr(),
            output.as_mut_ptr(),
            output.len() as u64,
            &mut required,
            ENTROPY_A.as_ptr(),
            32,
        )
    };
    assert_eq!(status, WLN_WALLET_FACTS_STATUS_OUTPUT_CAPACITY_V1);
    assert_eq!(required, 64);
    assert_eq!(output, [0xa5; 63]);
}

#[test]
fn every_invalid_shape_with_a_length_pointer_resets_length() {
    let request = empty_request();
    let byte = 0_u8;
    macro_rules! reject {
        ($expected:expr, $request:expr, $request_len:expr, $epoch:expr, $key:expr,
         $output:expr, $capacity:expr, $entropy:expr, $entropy_len:expr) => {{
            let mut length = 0xfeed_face_u64;
            let status = unsafe {
                call(
                    $request,
                    $request_len,
                    $epoch,
                    $key,
                    $output,
                    $capacity,
                    &mut length,
                    $entropy,
                    $entropy_len,
                )
            };
            assert_eq!(status, $expected);
            assert_eq!(length, 0);
        }};
    }
    reject!(
        WLN_WALLET_FACTS_STATUS_INVALID_ARGUMENT_V1,
        ptr::null(),
        1,
        EPOCH.as_ptr(),
        SLIP77.as_ptr(),
        ptr::null_mut(),
        0,
        ENTROPY_A.as_ptr(),
        32
    );
    reject!(
        WLN_WALLET_FACTS_STATUS_INVALID_ARGUMENT_V1,
        &byte,
        0,
        EPOCH.as_ptr(),
        SLIP77.as_ptr(),
        ptr::null_mut(),
        0,
        ENTROPY_A.as_ptr(),
        32
    );
    reject!(
        WLN_WALLET_FACTS_STATUS_LIMIT_EXCEEDED_V1,
        &byte,
        WLN_WALLET_FACTS_MAX_REQUEST_FRAME_BYTES_V1 + 1,
        EPOCH.as_ptr(),
        SLIP77.as_ptr(),
        ptr::null_mut(),
        0,
        ENTROPY_A.as_ptr(),
        32
    );
    reject!(
        WLN_WALLET_FACTS_STATUS_INVALID_ARGUMENT_V1,
        request.as_ptr(),
        request.len() as u64,
        ptr::null(),
        SLIP77.as_ptr(),
        ptr::null_mut(),
        0,
        ENTROPY_A.as_ptr(),
        32
    );
    reject!(
        WLN_WALLET_FACTS_STATUS_INVALID_ARGUMENT_V1,
        request.as_ptr(),
        request.len() as u64,
        EPOCH.as_ptr(),
        ptr::null(),
        ptr::null_mut(),
        0,
        ENTROPY_A.as_ptr(),
        32
    );
    reject!(
        WLN_WALLET_FACTS_STATUS_INVALID_ARGUMENT_V1,
        request.as_ptr(),
        request.len() as u64,
        EPOCH.as_ptr(),
        SLIP77.as_ptr(),
        ptr::null_mut(),
        1,
        ENTROPY_A.as_ptr(),
        32
    );
    reject!(
        WLN_WALLET_FACTS_STATUS_INVALID_ARGUMENT_V1,
        request.as_ptr(),
        request.len() as u64,
        EPOCH.as_ptr(),
        SLIP77.as_ptr(),
        ptr::null_mut(),
        0,
        ptr::null(),
        32
    );
    reject!(
        WLN_WALLET_FACTS_STATUS_INVALID_ARGUMENT_V1,
        request.as_ptr(),
        request.len() as u64,
        EPOCH.as_ptr(),
        SLIP77.as_ptr(),
        ptr::null_mut(),
        0,
        ENTROPY_A.as_ptr(),
        31
    );
}

#[test]
fn source_mismatch_resets_length_and_leaves_output_untouched() {
    let request = empty_request();
    let wrong = [0x42; 32];
    let mut output = [0xa5; 64];
    let mut length = 999;
    let status = unsafe {
        call(
            request.as_ptr(),
            request.len() as u64,
            wrong.as_ptr(),
            SLIP77.as_ptr(),
            output.as_mut_ptr(),
            output.len() as u64,
            &mut length,
            ENTROPY_A.as_ptr(),
            32,
        )
    };
    assert_eq!(status, WLN_WALLET_FACTS_STATUS_SOURCE_BINDING_MISMATCH_V1);
    assert_eq!(length, 0);
    assert_eq!(output, [0xa5; 64]);
}

fn corpus_frame(name: &str) -> Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../contracts/wallet-facts/v1/nonlinkable-reference/vectors/frames")
        .join(name);
    let text = std::fs::read_to_string(path).unwrap();
    text.trim()
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

#[test]
fn canonical_corpus_failures_map_to_frozen_statuses_atomically() {
    for (name, expected) in [
        (
            "request-12-wrong-magic.hex",
            WLN_WALLET_FACTS_STATUS_VERSION_MISMATCH_V1,
        ),
        (
            "request-13-wrong-version.hex",
            WLN_WALLET_FACTS_STATUS_VERSION_MISMATCH_V1,
        ),
        (
            "request-09-body-truncated.hex",
            WLN_WALLET_FACTS_STATUS_INVALID_ENCODING_V1,
        ),
        (
            "request-19-derivation-plus-one.hex",
            WLN_WALLET_FACTS_STATUS_LIMIT_EXCEEDED_V1,
        ),
        (
            "request-02-base-semantic-reject.hex",
            WLN_WALLET_FACTS_STATUS_DESCRIPTOR_REJECTED_V1,
        ),
        (
            "request-01-base-nonempty.hex",
            WLN_WALLET_FACTS_STATUS_OBSERVATION_REJECTED_V1,
        ),
        (
            "request-15-declared-length-mismatch.hex",
            WLN_WALLET_FACTS_STATUS_INVALID_ENCODING_V1,
        ),
        (
            "request-16-flags-nonzero.hex",
            WLN_WALLET_FACTS_STATUS_INVALID_ENCODING_V1,
        ),
        (
            "request-17-unknown-network.hex",
            WLN_WALLET_FACTS_STATUS_INVALID_ENCODING_V1,
        ),
        (
            "request-18-header-reserved.hex",
            WLN_WALLET_FACTS_STATUS_INVALID_ENCODING_V1,
        ),
        (
            "request-20-zero-source.hex",
            WLN_WALLET_FACTS_STATUS_INVALID_ARGUMENT_V1,
        ),
        (
            "request-21-zero-descriptor-length.hex",
            WLN_WALLET_FACTS_STATUS_INVALID_ENCODING_V1,
        ),
        (
            "request-22-candidate-count-plus-one.hex",
            WLN_WALLET_FACTS_STATUS_LIMIT_EXCEEDED_V1,
        ),
        (
            "request-23-previous-count-plus-one.hex",
            WLN_WALLET_FACTS_STATUS_LIMIT_EXCEEDED_V1,
        ),
        (
            "request-24-header-tail-reserved.hex",
            WLN_WALLET_FACTS_STATUS_INVALID_ENCODING_V1,
        ),
        (
            "request-25-trailing-byte.hex",
            WLN_WALLET_FACTS_STATUS_INVALID_ENCODING_V1,
        ),
        (
            "request-26-concatenated.hex",
            WLN_WALLET_FACTS_STATUS_INVALID_ENCODING_V1,
        ),
        (
            "request-27-descriptor-whitespace.hex",
            WLN_WALLET_FACTS_STATUS_INVALID_ENCODING_V1,
        ),
        (
            "request-28-descriptor-checksum-uppercase.hex",
            WLN_WALLET_FACTS_STATUS_INVALID_ENCODING_V1,
        ),
        (
            "request-28a-descriptor-nul.hex",
            WLN_WALLET_FACTS_STATUS_INVALID_ENCODING_V1,
        ),
        (
            "request-28b-descriptor-non-ascii.hex",
            WLN_WALLET_FACTS_STATUS_INVALID_ENCODING_V1,
        ),
        (
            "request-29-zero-candidate-length.hex",
            WLN_WALLET_FACTS_STATUS_INVALID_ENCODING_V1,
        ),
        (
            "request-30-candidate-reserved.hex",
            WLN_WALLET_FACTS_STATUS_INVALID_ENCODING_V1,
        ),
        (
            "request-31-previous-count-mismatch.hex",
            WLN_WALLET_FACTS_STATUS_INVALID_ENCODING_V1,
        ),
    ] {
        let frame = corpus_frame(name);
        let epoch: [u8; 32] = frame[28..60].try_into().unwrap();
        let mut output = [0xa5; 128];
        let mut length = 0xfeed_face;
        let status = unsafe {
            call(
                frame.as_ptr(),
                frame.len() as u64,
                epoch.as_ptr(),
                SLIP77.as_ptr(),
                output.as_mut_ptr(),
                output.len() as u64,
                &mut length,
                ENTROPY_A.as_ptr(),
                32,
            )
        };
        assert_eq!(status, expected, "{name}");
        assert_eq!(length, 0, "{name}");
        assert_eq!(output, [0xa5; 128], "{name}");
    }
}

#[test]
fn null_length_is_rejected_without_touching_other_arguments() {
    let status = unsafe {
        call(
            ptr::null(),
            u64::MAX,
            ptr::null(),
            ptr::null(),
            ptr::null_mut(),
            u64::MAX,
            ptr::null_mut(),
            ptr::null(),
            u64::MAX,
        )
    };
    assert_eq!(status, WLN_WALLET_FACTS_STATUS_INVALID_ARGUMENT_V1);
}
