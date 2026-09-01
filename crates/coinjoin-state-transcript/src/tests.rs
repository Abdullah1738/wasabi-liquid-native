use super::*;

const PROTOCOL_DOMAIN: &[u8] = b"WL-COINJOIN-PSET-STATE-V1";
const CONTEXT: &[u8] = b"round:7f4a;phase:blinding;role:participant;ordinal:2;prev:none";
const CANONICAL_STATE: &[u8] = b"canonical-state-v1:inputs=2;outputs=3;scalars=1";
const EXPECTED_KAT: [u8; 32] = [
    0x4c, 0xfc, 0x9a, 0x81, 0xdc, 0x80, 0x9a, 0x66, 0xec, 0x94, 0x2f, 0xc8, 0xc2, 0xae, 0xbd, 0x4f,
    0x0d, 0xe5, 0xb3, 0x3a, 0x71, 0xb8, 0xb4, 0x57, 0x68, 0x4c, 0xdd, 0x3b, 0x79, 0x06, 0xeb, 0xee,
];

#[test]
fn independently_pinned_known_answer_matches() {
    let digest = hash_coinjoin_state(PROTOCOL_DOMAIN, CONTEXT, CANONICAL_STATE).unwrap();

    assert_eq!(digest.into_bytes(), EXPECTED_KAT);
}

#[test]
fn identical_fields_are_deterministic_and_accessors_agree() {
    let first = hash_coinjoin_state(PROTOCOL_DOMAIN, CONTEXT, CANONICAL_STATE).unwrap();
    let second = hash_coinjoin_state(PROTOCOL_DOMAIN, CONTEXT, CANONICAL_STATE).unwrap();

    assert_eq!(first, second);
    assert_eq!(first.as_bytes(), &EXPECTED_KAT);
    assert_eq!(first.into_bytes(), *first.as_bytes());
}

#[test]
fn changing_any_field_changes_the_digest() {
    let baseline = hash_coinjoin_state(PROTOCOL_DOMAIN, CONTEXT, CANONICAL_STATE).unwrap();
    let changed_domain =
        hash_coinjoin_state(b"WL-COINJOIN-PSET-STATE-V2", CONTEXT, CANONICAL_STATE).unwrap();
    let changed_context = hash_coinjoin_state(
        PROTOCOL_DOMAIN,
        b"round:7f4a;phase:blinding;role:participant;ordinal:3;prev:none",
        CANONICAL_STATE,
    )
    .unwrap();
    let changed_state = hash_coinjoin_state(
        PROTOCOL_DOMAIN,
        CONTEXT,
        b"canonical-state-v1:inputs=2;outputs=4;scalars=1",
    )
    .unwrap();

    assert_ne!(baseline, changed_domain);
    assert_ne!(baseline, changed_context);
    assert_ne!(baseline, changed_state);
}

#[test]
fn length_prefixes_prevent_field_boundary_ambiguity() {
    let left = hash_coinjoin_state(b"domain", b"ab", b"c").unwrap();
    let right = hash_coinjoin_state(b"domain", b"a", b"bc").unwrap();

    assert_ne!(left, right);
}

#[test]
fn empty_fields_return_exact_errors() {
    assert_eq!(
        hash_coinjoin_state(b"", b"context", b"state"),
        Err(CoinJoinStateTranscriptError::EmptyDomain)
    );
    assert_eq!(
        hash_coinjoin_state(b"domain", b"", b"state"),
        Err(CoinJoinStateTranscriptError::EmptyContext)
    );
    assert_eq!(
        hash_coinjoin_state(b"domain", b"context", b""),
        Err(CoinJoinStateTranscriptError::EmptyState)
    );
}

#[test]
fn one_byte_over_each_limit_returns_the_exact_error() {
    let oversized_domain = vec![0x11; MAX_PROTOCOL_DOMAIN_LENGTH + 1];
    assert_eq!(
        hash_coinjoin_state(&oversized_domain, b"context", b"state"),
        Err(CoinJoinStateTranscriptError::DomainTooLarge)
    );
    drop(oversized_domain);

    let oversized_context = vec![0x22; MAX_CONTEXT_LENGTH + 1];
    assert_eq!(
        hash_coinjoin_state(b"domain", &oversized_context, b"state"),
        Err(CoinJoinStateTranscriptError::ContextTooLarge)
    );
    drop(oversized_context);

    let oversized_state = vec![0x33; MAX_CANONICAL_STATE_LENGTH + 1];
    assert_eq!(
        hash_coinjoin_state(b"domain", b"context", &oversized_state),
        Err(CoinJoinStateTranscriptError::StateTooLarge)
    );
}

#[test]
fn exact_field_limits_are_accepted() {
    let domain = vec![0x41; MAX_PROTOCOL_DOMAIN_LENGTH];
    let context = vec![0x42; MAX_CONTEXT_LENGTH];
    let state = vec![0x43; MAX_CANONICAL_STATE_LENGTH];

    assert!(hash_coinjoin_state(&domain, &context, &state).is_ok());
}

#[test]
fn caller_buffer_is_not_mutated_or_retained() {
    let digest = {
        let mut state = CANONICAL_STATE.to_vec();
        let original = state.clone();
        let digest = hash_coinjoin_state(PROTOCOL_DOMAIN, CONTEXT, &state).unwrap();

        assert_eq!(state, original);
        state[0] ^= 0xff;
        let changed = hash_coinjoin_state(PROTOCOL_DOMAIN, CONTEXT, &state).unwrap();
        assert_ne!(digest, changed);

        digest
    };

    assert_eq!(digest.into_bytes(), EXPECTED_KAT);
}

#[test]
fn errors_have_stable_display_text_and_implement_error() {
    fn assert_error<T: std::error::Error>() {}

    assert_error::<CoinJoinStateTranscriptError>();
    let cases = [
        (
            CoinJoinStateTranscriptError::EmptyDomain,
            "protocol domain must not be empty",
        ),
        (
            CoinJoinStateTranscriptError::DomainTooLarge,
            "protocol domain exceeds 128-byte limit",
        ),
        (
            CoinJoinStateTranscriptError::EmptyContext,
            "context must not be empty",
        ),
        (
            CoinJoinStateTranscriptError::ContextTooLarge,
            "context exceeds 65536-byte limit",
        ),
        (
            CoinJoinStateTranscriptError::EmptyState,
            "canonical state must not be empty",
        ),
        (
            CoinJoinStateTranscriptError::StateTooLarge,
            "canonical state exceeds 16777216-byte limit",
        ),
    ];

    for (error, expected) in cases {
        assert_eq!(error.to_string(), expected);
    }
}

#[test]
fn source_and_dependency_surface_remain_bounded() {
    let manifest = include_str!("../Cargo.toml");
    let dependencies = manifest
        .split_once("[dependencies]\n")
        .expect("manifest has a dependency section")
        .1
        .trim();
    assert_eq!(
        dependencies,
        "sha2 = { version = \"=0.11.0\", default-features = false }"
    );

    let source = include_str!("lib.rs");
    for forbidden in [
        "elements::",
        "ordinary_pset",
        "ordinary_wallet_pset",
        "bitcoin::",
        "secp256k1",
        "rand::",
        "zeroize::",
        "extern \"C\"",
        "#[no_mangle]",
        "ffi::",
        "libc::",
        "std::net",
        "std::os",
        "tokio::net",
        "reqwest::",
        "ureq::",
        "hyper::",
        "unsafe {",
    ] {
        assert!(
            !source.contains(forbidden),
            "forbidden source capability: {forbidden}"
        );
    }
}
