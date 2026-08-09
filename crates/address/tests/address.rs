use wasabi_liquid_native_address::{
    ConfidentialLiquidAddress, LiquidAddressError, LiquidAddressProfile, MAX_ADDRESS_BYTES,
    ParsedLiquidAddress,
};

const ELEMENTS_BASE58: &str = "2dxmEBXc2qMYcLSKiDBxdEePY3Ytixmnh4E";
const ELEMENTS_CONFIDENTIAL_BASE58: &str =
    "CTEo6VKG8xbe7HnfVW9mQoWTgtgeRSPktwTLbELzGw5tV8Ngzu53EBiasFMQKVbWmKWWTAdN5AUf4M6Y";
const ELEMENTS_SEGWIT: &str = "ert1qwhh2n5qypypm0eufahm2pvj8raj9zq5c27cysu";
const ELEMENTS_CONFIDENTIAL_SEGWIT: &str = "el1qq0umk3pez693jrrlxz9ndlkuwne93gdu9g83mhhzuyf46e3mdzfpva0w48gqgzgrklncnm0k5zeyw8my2ypfsmxh4xcjh2rse";
const ELEMENTS_TAPROOT: &str = "ert1p8qs0qcn25l2y6yvtc5t95rr8w9pndcj64c8rkutnvkcvdp6gh02q2cqvj9";
const ELEMENTS_CONFIDENTIAL_TAPROOT: &str = "el1pqgft7r4ytdenml0gaj67393sd3qkt3nxex0ut5dt3plhzwf6jaww5wpq7p3x4f75f5gch3gktgxxwu2rxm394tsw8dchxedsc6r53w75cj24fq2u2ls5";
const LIQUID_BASE58: &str = "GqiQRsPEyJLAsEBFB5R34KHuqxDNkG3zur";
const LIQUID_CONFIDENTIAL_BASE58: &str =
    "VJLDwMVWXg8RKq4mRe3YFNTAEykVN6V8x5MRUKKoC3nfRnbpnZeiG3jygMC6A4Gw967GY5EotJ4Rau2F";
const LIQUID_SEGWIT: &str = "ex1q7gkeyjut0mrxc3j0kjlt7rmcnvsh0gt45d3fud";
const LIQUID_CONFIDENTIAL_SEGWIT: &str = "lq1qqf8er278e6nyvuwtgf39e6ewvdcnjupn9a86rzpx655y5lhkt0walu3djf9cklkxd3ryld97hu8h3xepw7sh2rlu7q45dcew5";
const LIQUID_TAPROOT: &str = "ex1p8qs0qcn25l2y6yvtc5t95rr8w9pndcj64c8rkutnvkcvdp6gh02qa4lw5j";
const LIQUID_CONFIDENTIAL_TAPROOT: &str = "lq1pqgft7r4ytdenml0gaj67393sd3qkt3nxex0ut5dt3plhzwf6jaww5wpq7p3x4f75f5gch3gktgxxwu2rxm394tsw8dchxedsc6r53w75375l4kfvf08y";
const LIQUID_TESTNET_CONFIDENTIAL: &str = "tlq1qq2xvpcvfup5j8zscjq05u2wxxjcyewk7979f3mmz5l7uw5pqmx6xf5xy50hsn6vhkm5euwt72x878eq6zxx2z58hd7zrsg9qn";
const LIQUID_TESTNET_TAPROOT: &str =
    "tex1p8qs0qcn25l2y6yvtc5t95rr8w9pndcj64c8rkutnvkcvdp6gh02quvdf9a";
const LIQUID_TESTNET_CONFIDENTIAL_TAPROOT: &str = "tlq1pqgft7r4ytdenml0gaj67393sd3qkt3nxex0ut5dt3plhzwf6jaww5wpq7p3x4f75f5gch3gktgxxwu2rxm394tsw8dchxedsc6r53w75kkr3rh2tdxfn";

#[test]
fn parses_upstream_vectors_with_the_exact_profile() {
    let vectors = [
        (
            ELEMENTS_BASE58,
            LiquidAddressProfile::ElementsDefault,
            false,
        ),
        (
            ELEMENTS_CONFIDENTIAL_BASE58,
            LiquidAddressProfile::ElementsDefault,
            true,
        ),
        (
            ELEMENTS_SEGWIT,
            LiquidAddressProfile::ElementsDefault,
            false,
        ),
        (
            ELEMENTS_CONFIDENTIAL_SEGWIT,
            LiquidAddressProfile::ElementsDefault,
            true,
        ),
        (
            ELEMENTS_TAPROOT,
            LiquidAddressProfile::ElementsDefault,
            false,
        ),
        (
            ELEMENTS_CONFIDENTIAL_TAPROOT,
            LiquidAddressProfile::ElementsDefault,
            true,
        ),
        (LIQUID_BASE58, LiquidAddressProfile::LiquidMainnet, false),
        (
            LIQUID_CONFIDENTIAL_BASE58,
            LiquidAddressProfile::LiquidMainnet,
            true,
        ),
        (LIQUID_SEGWIT, LiquidAddressProfile::LiquidMainnet, false),
        (
            LIQUID_CONFIDENTIAL_SEGWIT,
            LiquidAddressProfile::LiquidMainnet,
            true,
        ),
        (LIQUID_TAPROOT, LiquidAddressProfile::LiquidMainnet, false),
        (
            LIQUID_CONFIDENTIAL_TAPROOT,
            LiquidAddressProfile::LiquidMainnet,
            true,
        ),
        (
            LIQUID_TESTNET_CONFIDENTIAL,
            LiquidAddressProfile::LiquidTestnet,
            true,
        ),
        (
            LIQUID_TESTNET_TAPROOT,
            LiquidAddressProfile::LiquidTestnet,
            false,
        ),
        (
            LIQUID_TESTNET_CONFIDENTIAL_TAPROOT,
            LiquidAddressProfile::LiquidTestnet,
            true,
        ),
    ];

    for (encoded, profile, confidential) in vectors {
        let parsed = ParsedLiquidAddress::parse(encoded, profile).expect("valid upstream vector");
        assert_eq!(parsed.profile(), profile);
        assert_eq!(parsed.canonical_address(), encoded);
        assert_eq!(parsed.is_confidential(), confidential);
        assert_eq!(parsed.blinding_pubkey().is_some(), confidential);
        assert!(!parsed.script_pubkey().is_empty());
    }
}

#[test]
fn confidential_and_unconfidential_pairs_have_the_same_script() {
    let pairs = [
        (
            ELEMENTS_BASE58,
            ELEMENTS_CONFIDENTIAL_BASE58,
            LiquidAddressProfile::ElementsDefault,
        ),
        (
            ELEMENTS_SEGWIT,
            ELEMENTS_CONFIDENTIAL_SEGWIT,
            LiquidAddressProfile::ElementsDefault,
        ),
        (
            ELEMENTS_TAPROOT,
            ELEMENTS_CONFIDENTIAL_TAPROOT,
            LiquidAddressProfile::ElementsDefault,
        ),
        (
            LIQUID_BASE58,
            LIQUID_CONFIDENTIAL_BASE58,
            LiquidAddressProfile::LiquidMainnet,
        ),
        (
            LIQUID_SEGWIT,
            LIQUID_CONFIDENTIAL_SEGWIT,
            LiquidAddressProfile::LiquidMainnet,
        ),
        (
            LIQUID_TAPROOT,
            LIQUID_CONFIDENTIAL_TAPROOT,
            LiquidAddressProfile::LiquidMainnet,
        ),
        (
            LIQUID_TESTNET_TAPROOT,
            LIQUID_TESTNET_CONFIDENTIAL_TAPROOT,
            LiquidAddressProfile::LiquidTestnet,
        ),
    ];

    for (plain, confidential, profile) in pairs {
        let plain = ParsedLiquidAddress::parse(plain, profile).expect("valid plain address");
        let confidential = ConfidentialLiquidAddress::parse(confidential, profile)
            .expect("valid confidential address");
        let confidential = confidential.as_parsed();

        assert_eq!(
            confidential.unconfidential_address(),
            plain.canonical_address()
        );
        assert_eq!(confidential.script_pubkey(), plain.script_pubkey());
    }
}

#[test]
fn reports_the_actual_profile_without_retaining_input() {
    let error = ParsedLiquidAddress::parse(
        LIQUID_CONFIDENTIAL_SEGWIT,
        LiquidAddressProfile::ElementsDefault,
    )
    .expect_err("wrong profile must fail");

    assert_eq!(
        error,
        LiquidAddressError::WrongProfile {
            expected: LiquidAddressProfile::ElementsDefault,
            actual: LiquidAddressProfile::LiquidMainnet,
        }
    );
    assert!(!format!("{error}").contains(LIQUID_CONFIDENTIAL_SEGWIT));
    assert!(!format!("{error:?}").contains(LIQUID_CONFIDENTIAL_SEGWIT));
}

#[test]
fn receive_parser_requires_a_blinding_public_key() {
    let error =
        ConfidentialLiquidAddress::parse(LIQUID_SEGWIT, LiquidAddressProfile::LiquidMainnet)
            .expect_err("unconfidential receive address must fail");

    assert_eq!(error, LiquidAddressError::ConfidentialAddressRequired);
}

#[test]
fn constructs_the_known_confidential_addresses() {
    let pairs = [
        (
            ELEMENTS_BASE58,
            ELEMENTS_CONFIDENTIAL_BASE58,
            LiquidAddressProfile::ElementsDefault,
        ),
        (
            ELEMENTS_SEGWIT,
            ELEMENTS_CONFIDENTIAL_SEGWIT,
            LiquidAddressProfile::ElementsDefault,
        ),
        (
            ELEMENTS_TAPROOT,
            ELEMENTS_CONFIDENTIAL_TAPROOT,
            LiquidAddressProfile::ElementsDefault,
        ),
        (
            LIQUID_BASE58,
            LIQUID_CONFIDENTIAL_BASE58,
            LiquidAddressProfile::LiquidMainnet,
        ),
        (
            LIQUID_SEGWIT,
            LIQUID_CONFIDENTIAL_SEGWIT,
            LiquidAddressProfile::LiquidMainnet,
        ),
        (
            LIQUID_TAPROOT,
            LIQUID_CONFIDENTIAL_TAPROOT,
            LiquidAddressProfile::LiquidMainnet,
        ),
        (
            LIQUID_TESTNET_TAPROOT,
            LIQUID_TESTNET_CONFIDENTIAL_TAPROOT,
            LiquidAddressProfile::LiquidTestnet,
        ),
    ];

    for (plain, confidential, profile) in pairs {
        let known = ConfidentialLiquidAddress::parse(confidential, profile)
            .expect("valid confidential vector");
        let reconstructed = ConfidentialLiquidAddress::from_unconfidential(
            plain,
            profile,
            known
                .as_parsed()
                .blinding_pubkey()
                .expect("confidential type has a key"),
        )
        .expect("valid construction");

        assert_eq!(reconstructed.as_parsed().canonical_address(), confidential);
        assert_eq!(reconstructed, known);
    }
}

#[test]
fn constructor_rejects_confidential_source_and_invalid_key() {
    let key = ConfidentialLiquidAddress::parse(
        LIQUID_CONFIDENTIAL_SEGWIT,
        LiquidAddressProfile::LiquidMainnet,
    )
    .expect("valid vector")
    .as_parsed()
    .blinding_pubkey()
    .expect("confidential type has a key");

    let error = ConfidentialLiquidAddress::from_unconfidential(
        LIQUID_CONFIDENTIAL_SEGWIT,
        LiquidAddressProfile::LiquidMainnet,
        key,
    )
    .expect_err("confidential source must fail");
    assert_eq!(error, LiquidAddressError::UnconfidentialAddressRequired);

    let error = ConfidentialLiquidAddress::from_unconfidential(
        LIQUID_SEGWIT,
        LiquidAddressProfile::LiquidMainnet,
        [0; 33],
    )
    .expect_err("invalid public key must fail");
    assert_eq!(error, LiquidAddressError::InvalidBlindingPublicKey);
}

#[test]
fn rejects_checksum_case_length_and_empty_corruption() {
    let mut checksum_corruption = LIQUID_CONFIDENTIAL_SEGWIT.to_owned();
    checksum_corruption.pop();
    checksum_corruption.push('q');

    for malformed in [
        "",
        checksum_corruption.as_str(),
        "Lq1qqf8er278e6nyvuwtgf39e6ewvdcnjupn9a86rzpx655y5lhkt0walu3djf9cklkxd3ryld97hu8h3xepw7sh2rlu7q45dcew5",
    ] {
        assert_eq!(
            ParsedLiquidAddress::parse(malformed, LiquidAddressProfile::LiquidMainnet),
            Err(LiquidAddressError::InvalidEncoding)
        );
    }

    let oversized = "x".repeat(MAX_ADDRESS_BYTES + 1);
    assert_eq!(
        ParsedLiquidAddress::parse(&oversized, LiquidAddressProfile::LiquidMainnet),
        Err(LiquidAddressError::InvalidEncoding)
    );
}

#[test]
fn canonicalizes_valid_uppercase_segwit_without_logging_addresses() {
    let uppercase = LIQUID_CONFIDENTIAL_SEGWIT.to_ascii_uppercase();
    let parsed = ParsedLiquidAddress::parse(&uppercase, LiquidAddressProfile::LiquidMainnet)
        .expect("uniform uppercase is valid");

    assert_eq!(parsed.canonical_address(), LIQUID_CONFIDENTIAL_SEGWIT);
    let debug = format!("{parsed:?}");
    assert!(!debug.contains(LIQUID_CONFIDENTIAL_SEGWIT));
    assert!(!debug.contains(parsed.unconfidential_address()));
}
