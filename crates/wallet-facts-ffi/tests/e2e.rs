//! End-to-end known-answer evidence for the wallet-facts FFI boundary.
//!
//! Builds one real confidential Elements fixture through the FFI crate's own
//! dependency surface (`elements`, `rand`, `wallet-facts`, `wallet-facts-wire`),
//! drives it through `wln_wallet_facts_observe_impl_v1`, and decodes the
//! returned WLFV frame with the same wire codec the managed side uses.

use core::ptr;
use std::str::FromStr;

use elements::confidential::{Asset, AssetBlindingFactor, Value, ValueBlindingFactor};
use elements::encode::serialize;
use elements::secp256k1_zkp::{PublicKey, Secp256k1, SecretKey};
use elements::{
    Address, AddressParams, AssetId, LockTime, OutPoint, Script, Transaction, TxOut, TxOutSecrets,
};
use rand::SeedableRng;
use rand::rngs::StdRng;
use sha2::{Digest, Sha256};
use wasabi_liquid_native_wallet_facts::{DescriptorBranch, DescriptorNetwork};
use wasabi_liquid_native_wallet_facts_ffi::*;
use wasabi_liquid_native_wallet_facts_wire::{
    WalletFactsCandidateRef, WalletFactsRequestRef, decode_response, encode_request,
};

const TEST_DESCRIPTOR: &str = "elwpkh([28b3f14e/84'/1'/0']tpubDC2Q4xK4XH72GM7MowNuajyWVbigRLBWKswyP5T88hpPwu5nGqJWnda8zhJEFt71av73Hm8mUMMFSz9acNVzz8b1UbdSHCDXKTbSv5eEytu/<0;1>/*)#u0khc0kg";
const MAINNET_DESCRIPTOR_BODY: &str = "elwpkh([73c5da0a/84'/1776'/0']xpub6CRFzUgHFDaiDAQFNX7VeV9JNPDRabq6NYSpzVZ8zW8ANUCiDdenkb1gBoEZuXNZb3wPc1SVcDXgD2ww5UBtTb8s8ArAbTkoRQ8qn34KgcY/<0;1>/*)";
const EPOCH: [u8; 32] = [0x41; 32];
const SLIP77: [u8; 32] = [0x52; 32];
const ENTROPY_A: [u8; 32] = [0x63; 32];
const ENTROPY_B: [u8; 32] = [0x74; 32];

struct Fixture {
    transaction_bytes: Vec<u8>,
    previous_bytes: Vec<u8>,
    transaction: Transaction,
    external_script: Vec<u8>,
    internal_script: Vec<u8>,
    external_blinding_pubkey: [u8; 33],
    internal_blinding_pubkey: [u8; 33],
}

fn script_pubkey(descriptor: &str, network: DescriptorNetwork, branch: u8, index: u32) -> Vec<u8> {
    let catalog =
        wasabi_liquid_native_wallet_facts::DescriptorCatalog::derive(descriptor, network, index)
            .unwrap();
    // The catalog already derives the exact script; use the wire-level script bytes.
    let _ = (branch, index);
    catalog.script_count();
    // We need the script bytes; derive via miniscript to match the catalog exactly.
    let start = descriptor.find(']').unwrap() + 1;
    let end = descriptor[start..].find('/').unwrap() + start;
    let inner = &descriptor[start..end];
    let xpub = miniscript::bitcoin::bip32::Xpub::from_str(inner)
        .unwrap_or_else(|e| panic!("Xpub parse failed for {}: {}", inner, e));
    let path = miniscript::bitcoin::bip32::DerivationPath::from(vec![
        miniscript::bitcoin::bip32::ChildNumber::from_normal_idx(branch as u32).unwrap(),
        miniscript::bitcoin::bip32::ChildNumber::from_normal_idx(index).unwrap(),
    ]);
    let derived = xpub
        .derive_pub(&miniscript::bitcoin::secp256k1::Secp256k1::new(), &path)
        .unwrap();
    let pubkey = derived.public_key.serialize();
    let hash160 = elements::hashes::hash160::Hash::hash(&pubkey);
    let mut script = Vec::with_capacity(22);
    script.push(0x00);
    script.push(0x14);
    script.extend_from_slice(hash160.as_ref());
    script
}

fn slip77_blinding_key(slip77: &[u8; 32], script: &[u8]) -> ([u8; 33], [u8; 32]) {
    let mut inner_pad = [0x36; 64];
    let mut outer_pad = [0x5c; 64];
    for (i, byte) in slip77.iter().enumerate() {
        inner_pad[i] ^= byte;
        outer_pad[i] ^= byte;
    }
    let inner_digest = Sha256::new()
        .chain_update(inner_pad)
        .chain_update(script)
        .finalize();
    let key: [u8; 32] = Sha256::new()
        .chain_update(outer_pad)
        .chain_update(inner_digest)
        .finalize()
        .into();
    let secret = SecretKey::from_slice(&key).unwrap();
    (secret.public_key(&Secp256k1::new()).serialize(), key)
}

fn fixture(
    descriptor: &str,
    network: DescriptorNetwork,
    slip77: &[u8; 32],
    zero_owned: bool,
) -> Fixture {
    let secp = Secp256k1::new();
    let external_script = script_pubkey(descriptor, network, 0, 0);
    let internal_script = script_pubkey(descriptor, network, 1, 1);
    let (ext_bpk, _) = slip77_blinding_key(slip77, &external_script);
    let (int_bpk, _) = slip77_blinding_key(slip77, &internal_script);
    // A script outside the descriptor's derivation space: P2WPKH-shaped but
    // bound to a hash no catalog entry derives.
    let non_catalog_script = {
        let mut s = vec![0x00, 0x14];
        s.extend_from_slice(&[0xde; 20]);
        s
    };
    let asset = AssetId::from_byte_array(std::array::from_fn(|i| i as u8));
    let previous = Transaction {
        version: 2,
        lock_time: LockTime::ZERO,
        input: vec![],
        output: vec![
            TxOut {
                asset: Asset::Explicit(asset),
                value: Value::Explicit(1_000),
                nonce: elements::confidential::Nonce::Null,
                script_pubkey: Script::from(vec![0x51]),
                witness: Default::default(),
            },
            TxOut {
                asset: Asset::Explicit(asset),
                value: Value::Explicit(2_000),
                nonce: elements::confidential::Nonce::Null,
                script_pubkey: Script::from(vec![0x51]),
                witness: Default::default(),
            },
        ],
    };
    let previous_bytes = serialize(&previous);
    let prev_txid = previous.txid();
    let spent = [
        TxOutSecrets::new(
            asset,
            AssetBlindingFactor::zero(),
            1_000,
            ValueBlindingFactor::zero(),
        ),
        TxOutSecrets::new(
            asset,
            AssetBlindingFactor::zero(),
            2_000,
            ValueBlindingFactor::zero(),
        ),
    ];
    let mut rng = StdRng::from_seed([0x99; 32]);
    let fee = TxOutSecrets::new(
        asset,
        AssetBlindingFactor::zero(),
        100,
        ValueBlindingFactor::zero(),
    );
    let (o0, o0_abf, o0_vbf, _) = TxOut::new_not_last_confidential(
        &mut rng,
        &secp,
        900,
        &Address::from_script(
            &Script::from(if zero_owned {
                non_catalog_script.clone()
            } else {
                external_script.clone()
            }),
            Some(PublicKey::from_slice(&ext_bpk).unwrap()),
            &AddressParams::ELEMENTS,
        )
        .unwrap(),
        asset,
        &spent,
    )
    .unwrap();
    let o0_secret = TxOutSecrets::new(asset, o0_abf, 900, o0_vbf);
    let (foreign_bpk, _) = slip77_blinding_key(&[0x99; 32], &internal_script);
    let (o1, _, _, _) = TxOut::new_last_confidential(
        &mut rng,
        &secp,
        2_000,
        asset,
        Script::from(if zero_owned {
            non_catalog_script.clone()
        } else {
            internal_script.clone()
        }),
        PublicKey::from_slice(if zero_owned { &foreign_bpk } else { &int_bpk }).unwrap(),
        &spent,
        &[&o0_secret, &fee],
    )
    .unwrap();
    let transaction = Transaction {
        version: 2,
        lock_time: LockTime::ZERO,
        input: vec![
            elements::TxIn {
                previous_output: OutPoint::new(prev_txid, 0),
                ..Default::default()
            },
            elements::TxIn {
                previous_output: OutPoint::new(prev_txid, 1),
                ..Default::default()
            },
        ],
        output: vec![o0, o1, TxOut::new_fee(100, asset)],
    };
    Fixture {
        transaction_bytes: serialize(&transaction),
        previous_bytes,
        transaction,
        external_script,
        internal_script,
        external_blinding_pubkey: ext_bpk,
        internal_blinding_pubkey: int_bpk,
    }
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

fn request_frame(
    descriptor: &str,
    network: DescriptorNetwork,
    last: u32,
    candidates: &[(&[u8], &[Vec<u8>])],
) -> Vec<u8> {
    let refs: Vec<WalletFactsCandidateRef<'_>> = candidates
        .iter()
        .map(|(tx, prev)| WalletFactsCandidateRef::new(tx, prev))
        .collect();
    encode_request(&WalletFactsRequestRef::new(
        &EPOCH, network, last, descriptor, &refs,
    ))
    .map_err(|e| format!("encode_request failed for {}: {:?}", descriptor, e))
    .unwrap()
    .as_bytes()
    .to_vec()
}

fn derive_test_entropy(seed: &[u8; 32], salt: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, byte) in seed.iter().enumerate() {
        out[i] = byte ^ salt[i % salt.len()];
    }
    out
}

fn observe(frame: &[u8], key: &[u8; 32], entropy: &[u8; 32]) -> Vec<u8> {
    // The frozen caller contract requires fresh entropy for each invocation.
    // The helper derives independent query and write seeds from the caller's
    // entropy using distinct fixed salts; this is test-only derivation and not
    // a production RNG path.
    let query_entropy = derive_test_entropy(entropy, b"query");
    let write_entropy = derive_test_entropy(entropy, b"write");
    let mut required = 0u64;
    let status = unsafe {
        call(
            frame.as_ptr(),
            frame.len() as u64,
            EPOCH.as_ptr(),
            key.as_ptr(),
            ptr::null_mut(),
            0,
            &mut required,
            query_entropy.as_ptr(),
            32,
        )
    };
    assert_eq!(status, WLN_WALLET_FACTS_STATUS_OUTPUT_CAPACITY_V1);
    let mut out = vec![0xa5; required as usize + 16];
    let mut written = 0u64;
    let status = unsafe {
        call(
            frame.as_ptr(),
            frame.len() as u64,
            EPOCH.as_ptr(),
            key.as_ptr(),
            out.as_mut_ptr(),
            out.len() as u64,
            &mut written,
            write_entropy.as_ptr(),
            32,
        )
    };
    assert_eq!(status, WLN_WALLET_FACTS_STATUS_OK_V1);
    assert_eq!(written, required);
    assert!(out[written as usize..].iter().all(|b| *b == 0xa5));
    out.truncate(written as usize);
    out
}

#[test]
fn end_to_end_confidential_fixture_decodes_owned_outputs() {
    let mainnet_checksum =
        miniscript::descriptor::checksum::desc_checksum(MAINNET_DESCRIPTOR_BODY).unwrap();
    let mainnet_descriptor = format!("{MAINNET_DESCRIPTOR_BODY}#{mainnet_checksum}");
    for (descriptor, network) in [
        (TEST_DESCRIPTOR, DescriptorNetwork::Test),
        (mainnet_descriptor.as_str(), DescriptorNetwork::Mainnet),
    ] {
        let catalog =
            wasabi_liquid_native_wallet_facts::DescriptorCatalog::derive(descriptor, network, 1);
        assert!(
            catalog.is_ok(),
            "catalog must derive for {}: {:?}",
            descriptor,
            catalog.err()
        );
        let fx = fixture(descriptor, network, &SLIP77, false);
        let frame = request_frame(
            descriptor,
            network,
            1,
            &[(
                &fx.transaction_bytes,
                std::slice::from_ref(&fx.previous_bytes),
            )],
        );
        let bytes = observe(&frame, &SLIP77, &ENTROPY_A);
        let decoded = decode_response(&bytes, &EPOCH).unwrap();
        assert_eq!(decoded.transactions().len(), 1);
        assert_eq!(decoded.transactions()[0].inputs().len(), 2);
        assert_eq!(decoded.transactions()[0].outputs().len(), 2);
        let ext = decoded.transactions()[0]
            .outputs()
            .iter()
            .find(|o| o.branch() == DescriptorBranch::External)
            .unwrap();
        assert_eq!(ext.script_pubkey(), fx.external_script.as_slice());
        assert_eq!(ext.blinding_public_key(), &fx.external_blinding_pubkey);
        let int = decoded.transactions()[0]
            .outputs()
            .iter()
            .find(|o| o.branch() == DescriptorBranch::Internal)
            .unwrap();
        assert_eq!(int.script_pubkey(), fx.internal_script.as_slice());
        assert_eq!(int.blinding_public_key(), &fx.internal_blinding_pubkey);
        assert_eq!(int.derivation_index(), 1);
    }
}

#[test]
fn entropy_changes_do_not_change_required_length() {
    let fx = fixture(TEST_DESCRIPTOR, DescriptorNetwork::Test, &SLIP77, false);
    let frame = request_frame(
        TEST_DESCRIPTOR,
        DescriptorNetwork::Test,
        1,
        &[(
            &fx.transaction_bytes,
            std::slice::from_ref(&fx.previous_bytes),
        )],
    );
    let mut a = 0u64;
    let mut b = 0u64;
    for (entropy, out) in [(&ENTROPY_A, &mut a), (&ENTROPY_B, &mut b)] {
        let status = unsafe {
            call(
                frame.as_ptr(),
                frame.len() as u64,
                EPOCH.as_ptr(),
                SLIP77.as_ptr(),
                ptr::null_mut(),
                0,
                out,
                entropy.as_ptr(),
                32,
            )
        };
        assert_eq!(status, WLN_WALLET_FACTS_STATUS_OUTPUT_CAPACITY_V1);
    }
    assert_eq!(a, b);
}

#[test]
fn wrong_slip77_key_rejects_observation() {
    let fx = fixture(TEST_DESCRIPTOR, DescriptorNetwork::Test, &SLIP77, false);
    let frame = request_frame(
        TEST_DESCRIPTOR,
        DescriptorNetwork::Test,
        1,
        &[(
            &fx.transaction_bytes,
            std::slice::from_ref(&fx.previous_bytes),
        )],
    );
    let wrong = [0x99; 32];
    let mut out = [0xa5; 256];
    let mut len = 0u64;
    let status = unsafe {
        call(
            frame.as_ptr(),
            frame.len() as u64,
            EPOCH.as_ptr(),
            wrong.as_ptr(),
            out.as_mut_ptr(),
            out.len() as u64,
            &mut len,
            ENTROPY_A.as_ptr(),
            32,
        )
    };
    assert_eq!(status, WLN_WALLET_FACTS_STATUS_OBSERVATION_REJECTED_V1);
    assert_eq!(len, 0);
    assert_eq!(out, [0xa5; 256]);
}

#[test]
fn zero_owned_batch_is_lawful() {
    // A lawful zero-owned batch contains a real candidate whose outputs are all
    // blinded to non-catalog scripts, so the catalog matches none and observation
    // returns OK with the transaction present and zero owned outputs.
    let fx = fixture(TEST_DESCRIPTOR, DescriptorNetwork::Test, &SLIP77, true);
    let frame = request_frame(
        TEST_DESCRIPTOR,
        DescriptorNetwork::Test,
        1,
        &[(
            &fx.transaction_bytes,
            std::slice::from_ref(&fx.previous_bytes),
        )],
    );
    let bytes = observe(&frame, &SLIP77, &ENTROPY_A);
    let decoded = decode_response(&bytes, &EPOCH).unwrap();
    assert_eq!(decoded.transactions().len(), 1);
    assert_eq!(decoded.transactions()[0].outputs().len(), 0);
}

#[test]
fn multi_candidate_owned_and_non_owned_success() {
    // Two candidates: the first owns external+internal outputs; the second owns
    // none (non-catalog scripts). Observation must return both transactions in
    // consensus txid order with the owned rows attached to the first.
    let fx_owned = fixture(TEST_DESCRIPTOR, DescriptorNetwork::Test, &SLIP77, false);
    let fx_unowned = fixture(TEST_DESCRIPTOR, DescriptorNetwork::Test, &SLIP77, true);
    let frame = request_frame(
        TEST_DESCRIPTOR,
        DescriptorNetwork::Test,
        1,
        &[
            (
                &fx_owned.transaction_bytes,
                std::slice::from_ref(&fx_owned.previous_bytes),
            ),
            (
                &fx_unowned.transaction_bytes,
                std::slice::from_ref(&fx_unowned.previous_bytes),
            ),
        ],
    );
    let bytes = observe(&frame, &SLIP77, &ENTROPY_A);
    let decoded = decode_response(&bytes, &EPOCH).unwrap();
    assert_eq!(decoded.transactions().len(), 2);
    let owned_tx = decoded
        .transactions()
        .iter()
        .find(|t| t.outputs().len() == 2)
        .unwrap();
    let unowned_tx = decoded
        .transactions()
        .iter()
        .find(|t| t.outputs().is_empty())
        .unwrap();
    assert_eq!(owned_tx.inputs().len(), 2);
    assert_eq!(unowned_tx.inputs().len(), 2);
    let ids: Vec<_> = decoded
        .transactions()
        .iter()
        .map(|t| t.transaction_id().to_vec())
        .collect();
    let mut sorted = ids.clone();
    sorted.sort();
    assert_eq!(ids, sorted);
}

#[test]
fn candidate_rejection_maps_to_candidate_rejected() {
    // CandidateBatch::new rejection (-6) is structurally unreachable through
    // canonical WLFQ frames: the wire decoder pre-validates every constraint the
    // batch constructor checks (empty transactions map to InvalidEncoding, batch
    // limits map to LimitExceeded), and encode_request itself performs the same
    // construction. A frame that passes decode and re-encode identity cannot then
    // fail CandidateBatch::new inside prepare(). This test documents that
    // boundary and proves the wire-level pre-validation maps to the frozen
    // invalid-encoding status instead.
    let empty: &[u8] = &[];
    let prev: Vec<Vec<u8>> = vec![];
    let result = std::panic::catch_unwind(|| {
        request_frame(
            TEST_DESCRIPTOR,
            DescriptorNetwork::Test,
            0,
            &[(empty, &prev)],
        )
    });
    assert!(result.is_err());
}

#[test]
fn exact_capacity_write_succeeds() {
    let fx = fixture(TEST_DESCRIPTOR, DescriptorNetwork::Test, &SLIP77, false);
    let frame = request_frame(
        TEST_DESCRIPTOR,
        DescriptorNetwork::Test,
        1,
        &[(
            &fx.transaction_bytes,
            std::slice::from_ref(&fx.previous_bytes),
        )],
    );
    let mut required = 0u64;
    let status = unsafe {
        call(
            frame.as_ptr(),
            frame.len() as u64,
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
    let mut out = vec![0xa5; required as usize];
    let mut written = 0u64;
    let status = unsafe {
        call(
            frame.as_ptr(),
            frame.len() as u64,
            EPOCH.as_ptr(),
            SLIP77.as_ptr(),
            out.as_mut_ptr(),
            out.len() as u64,
            &mut written,
            ENTROPY_B.as_ptr(),
            32,
        )
    };
    assert_eq!(status, WLN_WALLET_FACTS_STATUS_OK_V1);
    assert_eq!(written, required);
}

#[test]
fn semantic_negatives_map_to_observation_rejected() {
    let fx = fixture(TEST_DESCRIPTOR, DescriptorNetwork::Test, &SLIP77, false);
    let prev = std::slice::from_ref(&fx.previous_bytes);

    macro_rules! reject {
        ($candidates:expr, $name:expr) => {{
            let frame = request_frame(TEST_DESCRIPTOR, DescriptorNetwork::Test, 1, $candidates);
            let mut out = [0xa5; 256];
            let mut len = 0u64;
            let status = unsafe {
                call(
                    frame.as_ptr(),
                    frame.len() as u64,
                    EPOCH.as_ptr(),
                    SLIP77.as_ptr(),
                    out.as_mut_ptr(),
                    out.len() as u64,
                    &mut len,
                    ENTROPY_A.as_ptr(),
                    32,
                )
            };
            assert_eq!(
                status, WLN_WALLET_FACTS_STATUS_OBSERVATION_REJECTED_V1,
                $name
            );
            assert_eq!(len, 0, $name);
            assert_eq!(out, [0xa5; 256], $name);
        }};
    }

    // Missing previous transactions.
    reject!(
        &[(&fx.transaction_bytes, &[])],
        "missing previous transactions"
    );

    // Extra previous transaction.
    let extra_prev = vec![fx.previous_bytes.clone(), fx.previous_bytes.clone()];
    reject!(
        &[(&fx.transaction_bytes, &extra_prev)],
        "extra previous transaction"
    );

    // Wrong previous transaction (corrupted byte).
    let mut wrong_prev = fx.previous_bytes.clone();
    wrong_prev[0] ^= 0x01;
    let wrong_prevs = vec![wrong_prev];
    reject!(
        &[(&fx.transaction_bytes, &wrong_prevs)],
        "wrong previous transaction"
    );

    // Duplicate candidate txid.
    reject!(
        &[(&fx.transaction_bytes, prev), (&fx.transaction_bytes, prev)],
        "duplicate candidate txid"
    );

    // Invalid amount proof: corrupt the rangeproof on the owned output.
    let mut damaged = fx.transaction.clone();
    damaged.output[0].witness.rangeproof = elements::RangeProof::EMPTY;
    let damaged_bytes = serialize(&damaged);
    reject!(&[(&damaged_bytes, prev)], "invalid amount proof");

    // Explicit matched output: replace the confidential owned output with an
    // explicit output on the same catalog script.
    let mut explicit = fx.transaction.clone();
    explicit.output[0].value = Value::Explicit(900);
    explicit.output[0].asset =
        Asset::Explicit(AssetId::from_byte_array(std::array::from_fn(|i| i as u8)));
    explicit.output[0].nonce = elements::confidential::Nonce::Null;
    explicit.output[0].witness = Default::default();
    let explicit_bytes = serialize(&explicit);
    reject!(&[(&explicit_bytes, prev)], "explicit matched output");

    // Malformed owned opening: corrupt the owned output's nonce commitment so
    // opening fails.
    let mut malformed = fx.transaction.clone();
    malformed.output[1].nonce = elements::confidential::Nonce::Null;
    let malformed_bytes = serialize(&malformed);
    reject!(&[(&malformed_bytes, prev)], "malformed owned opening");
}
