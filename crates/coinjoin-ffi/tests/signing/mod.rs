use super::*;
use elements::secp256k1_zkp::{Message, ecdsa};
use elements::sighash::{SighashCache, SighashRangeproofMode};
use elements::{EcdsaSighashType, Transaction};
use sha2::{Digest, Sha256};

struct Fixture {
    common: Vec<Vec<u8>>,
    pset: PartiallySignedTransaction,
    views: Vec<Vec<u8>>,
    signatures: Vec<Vec<u8>>,
}

fn owned(indices: &[u32]) -> Vec<u8> {
    let mut bytes = (indices.len() as u32).to_be_bytes().to_vec();
    for index in indices {
        bytes.extend_from_slice(&index.to_be_bytes());
    }
    bytes
}

fn frame(op: u32, common: &[Vec<u8>], fifth: &[u8]) -> Vec<u8> {
    let mut fields: Vec<_> = common.iter().map(Vec::as_slice).collect();
    fields.push(fifth);
    request(op, &fields)
}

fn fixture() -> Fixture {
    let mut pset = build_preblind();
    for (index, input) in pset.inputs_mut().iter_mut().enumerate() {
        let key = blinding_key(0x61 + index as u8);
        input.witness_utxo.as_mut().unwrap().script_pubkey =
            Script::new_v0_wpkh(&key.wpubkey_hash().unwrap());
    }
    let preblind = serialize(&pset);
    let intermediate = execute(&request(
        4,
        &[
            &preblind,
            &encode_role_map(),
            &encode_secrets(&[0]),
            &ENTROPY_BLIND_A,
        ],
    ));
    let final_response = execute(&request(
        5,
        &[
            &preblind,
            &encode_role_map(),
            response_fields(&intermediate)[0],
            &encode_secrets(&[1]),
            &ENTROPY_BLIND_B,
        ],
    ));
    let final_bytes = response_fields(&final_response)[0].to_vec();
    let pset: PartiallySignedTransaction = deserialize(&final_bytes).unwrap();
    let context = encode_context(3, 1, 1);
    let canonical = execute(&request(1, &[&final_bytes, &context]));
    let mut auth = 2u32.to_be_bytes().to_vec();
    for (index, input) in pset.inputs().iter().enumerate() {
        auth.extend_from_slice(&(index as u32).to_be_bytes());
        auth.extend_from_slice(&input.previous_outpoint().txid.to_byte_array());
        auth.extend_from_slice(&input.previous_outpoint().vout.to_be_bytes());
        auth.extend_from_slice(&blinding_key(0x61 + index as u8).to_bytes());
    }
    let common = vec![
        final_bytes,
        context,
        response_fields(&canonical)[1].to_vec(),
        auth,
    ];
    let views: Vec<_> = (0..2)
        .map(|index| execute(&frame(11, &common, &owned(&[index]))))
        .collect();
    // Each signer sees only its own digest request and owns only one spend key.
    let signatures = views
        .iter()
        .enumerate()
        .map(|(index, view)| {
            let fields = response_fields(view);
            let record = &fields[2][4..];
            assert_eq!(&record[..4], &(index as u32).to_be_bytes());
            assert_eq!(record.len(), 106);
            assert_eq!(record[105], 0x41);
            sign(&record[73..105], 0x61 + index as u8)
        })
        .collect();
    Fixture {
        common,
        pset,
        views,
        signatures,
    }
}

fn sign(digest: &[u8], key_byte: u8) -> Vec<u8> {
    let key = SecretKey::from_slice(&[key_byte; 32]).unwrap();
    let mut signature = Secp256k1::new()
        .sign_ecdsa(&Message::from_digest(digest.try_into().unwrap()), &key)
        .serialize_der()
        .to_vec();
    signature.push(0x41);
    signature
}

fn contributions(f: &Fixture, indices: &[usize]) -> Vec<u8> {
    let mut bytes = (indices.len() as u32).to_be_bytes().to_vec();
    for &index in indices {
        bytes.extend_from_slice(response_fields(&f.views[index])[0]);
        bytes.extend_from_slice(&(index as u32).to_be_bytes());
        bytes.extend_from_slice(&blinding_key(0x61 + index as u8).to_bytes());
        field(&mut bytes, &f.signatures[index]);
    }
    bytes
}

fn rejected(request: &[u8], status: i32) {
    let mut written = 123u64;
    let mut output = vec![0xa5; 32_768];
    let actual = unsafe {
        wlcj_execute_impl_v1(
            request.as_ptr(),
            request.len() as u64,
            output.as_mut_ptr(),
            output.len() as u64,
            &mut written,
        )
    };
    assert_eq!(actual, status);
    assert_eq!(written, 0);
    assert!(output.iter().all(|b| *b == 0xa5));
}

fn export_case(name: &str, request: &[u8], response: Option<&[u8]>, status: i32) {
    if let Some(directory) = std::env::var_os("WLCJ_C2_FIXTURE_DIR") {
        let directory = std::path::PathBuf::from(directory).canonicalize().unwrap();
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tmp")
            .canonicalize()
            .unwrap();
        assert!(directory.starts_with(root));
        std::fs::write(directory.join(format!("{name}.request")), request).unwrap();
        std::fs::write(directory.join(format!("{name}.status")), status.to_string()).unwrap();
        if let Some(response) = response {
            std::fs::write(directory.join(format!("{name}.response")), response).unwrap();
        }
    }
}

#[test]
fn c2_two_independent_signatures_and_exact_body_through_frames() {
    let f = fixture();
    let view = response_fields(&f.views[0]);
    let mut hasher = Sha256::new_with_prefix(b"WLCJ_SIGNING_BINDING_V1");
    for bytes in &f.common {
        hasher.update((bytes.len() as u32).to_be_bytes());
        hasher.update(bytes);
    }
    assert_eq!(view[0], hasher.finalize().as_slice());
    assert_eq!(view[0], response_fields(&f.views[1])[0]);
    assert_eq!(view[1], f.common[2]);
    let original = f.pset.extract_tx().unwrap();
    for index in 0..2 {
        let key = blinding_key(0x61 + index as u8);
        let expected = SighashCache::new(&original)
            .segwitv0_sighash_with_rangeproof_mode(
                index,
                &Script::new_p2pkh(&key.pubkey_hash()),
                f.pset.inputs()[index].witness_utxo.as_ref().unwrap().value,
                EcdsaSighashType::AllPlusRangeproof,
                SighashRangeproofMode::Enabled,
            )
            .to_byte_array();
        assert_eq!(&response_fields(&f.views[index])[2][77..109], &expected);
        let bytes = &f.signatures[index];
        Secp256k1::new()
            .verify_ecdsa(
                &Message::from_digest(expected),
                &ecdsa::Signature::from_der(&bytes[..bytes.len() - 1]).unwrap(),
                &key.inner,
            )
            .unwrap();
        export_case(
            &format!("op11-{index}"),
            &frame(11, &f.common, &owned(&[index as u32])),
            Some(&f.views[index]),
            0,
        );
    }
    let request = frame(12, &f.common, &contributions(&f, &[1, 0]));
    let response = execute(&request);
    assert_eq!(execute(&request), response);
    let fields = response_fields(&response);
    assert_eq!(fields.len(), 4);
    assert_eq!(fields[0], view[0]);
    assert_eq!(fields[1], f.common[2]);
    let mut tx: Transaction = deserialize(fields[2]).unwrap();
    assert_eq!(fields[3], tx.txid().to_byte_array());
    for (index, input) in tx.input.iter_mut().enumerate() {
        let witness = input.witness.script_witness.to_vec();
        assert_eq!(
            witness,
            vec![
                f.signatures[index].clone(),
                blinding_key(0x61 + index as u8).to_bytes()
            ]
        );
        input.witness.script_witness = Default::default();
    }
    assert_eq!(tx, original);
    export_case("op12", &request, Some(&response), 0);
}

#[test]
fn c2_changed_state_context_and_authorization_rejected_at_both_stages() {
    let f = fixture();
    for mutation in 0..11 {
        let mut common = f.common.clone();
        let mut pset = f.pset.clone();
        match mutation {
            0 => common[1][10] ^= 1, // network
            1 => common[2][0] ^= 1,  // approved digest
            2 => pset.inputs_mut()[0].previous_output_index += 1,
            3 => pset.inputs_mut().swap(0, 1),
            4 => pset.outputs_mut()[0].ecdh_pubkey = Some(blinding_key(12)),
            5 => pset.outputs_mut()[2].amount = Some(1_101),
            6 => common[3][8] ^= 1, // authorized outpoint
            7 => common[3][44..77].copy_from_slice(&blinding_key(0x63).to_bytes()),
            8 => common[3][77..81].copy_from_slice(&0u32.to_be_bytes()), // duplicate
            9 => {
                common[3].truncate(77);
                common[3][..4].copy_from_slice(&1u32.to_be_bytes());
            }
            10 => common[1] = encode_context(2, 1, 1),
            _ => unreachable!(),
        }
        if (2..=5).contains(&mutation) {
            common[0] = serialize(&pset);
        }
        for op in [11, 12] {
            let fifth = if op == 11 {
                owned(&[0])
            } else {
                contributions(&f, &[0, 1])
            };
            let request = frame(op, &common, &fifth);
            rejected(&request, -5);
            export_case(&format!("reject-state-{mutation}-{op}"), &request, None, -5);
        }
    }
    // Even a newly approved context cannot consume contributions tagged with
    // the prior exact common fields, although the transaction ECDSA is unchanged.
    let mut common = f.common.clone();
    common[1] = encode_context(3, 2, 2);
    let canonical = execute(&request(1, &[&common[0], &common[1]]));
    common[2] = response_fields(&canonical)[1].to_vec();
    assert_ne!(
        response_fields(&execute(&frame(11, &common, &owned(&[0]))))[0],
        response_fields(&f.views[0])[0]
    );
    let request = frame(12, &common, &contributions(&f, &[0, 1]));
    rejected(&request, -6);
    export_case("reject-new-context-old-contributions", &request, None, -6);
    for indices in [vec![], vec![0, 0], vec![1, 0], vec![2], vec![u32::MAX]] {
        rejected(&frame(11, &f.common, &owned(&indices)), -5);
    }
}

#[test]
fn c2_missing_duplicate_foreign_and_wrong_signatures_fail_closed() {
    let mut f = fixture();
    for (name, indices, status) in [
        ("empty", vec![], -5),
        ("missing", vec![0], -6),
        ("duplicate", vec![0, 0], -6),
        ("extra", vec![0, 1, 1], -6),
    ] {
        let request = frame(12, &f.common, &contributions(&f, &indices));
        rejected(&request, status);
        export_case(&format!("reject-{name}"), &request, None, status);
    }
    for (name, offset) in [("binding", 4), ("foreign-index", 39), ("foreign-key", 41)] {
        let mut submitted = contributions(&f, &[0, 1]);
        submitted[offset] ^= 0x10;
        let request = frame(12, &f.common, &submitted);
        rejected(&request, -6);
        export_case(&format!("reject-{name}"), &request, None, -6);
    }
    let original = f.signatures[0].clone();
    let digest = response_fields(&f.views[0])[2][77..109].to_vec();
    for mutation in 0..9 {
        let mut bytes = original.clone();
        match mutation {
            0 => bytes = sign(&digest, 0x62),
            1 => {
                let mut reversed = digest.clone();
                reversed.reverse();
                bytes = sign(&reversed, 0x61);
            }
            2 => *bytes.last_mut().unwrap() = 1,
            3 => {
                bytes.insert(bytes.len() - 1, 0);
            }
            4 => bytes.clear(),
            5 => bytes = vec![0; 74],
            6 | 7 => {
                let sig = ecdsa::Signature::from_der(&original[..original.len() - 1]).unwrap();
                let mut compact = sig.serialize_compact();
                if mutation == 6 {
                    let s = SecretKey::from_slice(&compact[32..]).unwrap();
                    compact[32..].copy_from_slice(&s.negate().secret_bytes());
                    bytes = ecdsa::Signature::from_compact(&compact)
                        .unwrap()
                        .serialize_der()
                        .to_vec();
                } else {
                    bytes = compact.to_vec();
                }
                bytes.push(0x41);
            }
            8 => bytes[0] = 0,
            _ => unreachable!(),
        }
        f.signatures[0] = bytes;
        let request = frame(12, &f.common, &contributions(&f, &[0, 1]));
        rejected(&request, -6);
        export_case(&format!("reject-signature-{mutation}"), &request, None, -6);
    }
}

#[test]
fn c2_assemble_count_is_bounded_before_allocation() {
    let f = fixture();
    for (name, count) in [
        ("zero", 0),
        (
            "max-plus-one",
            wasabi_liquid_native_coinjoin_pset_state::MAX_INPUT_COUNT + 1,
        ),
        ("u32-max", u32::MAX as usize),
    ] {
        let request = frame(12, &f.common, &(count as u32).to_be_bytes());
        rejected(&request, -5);
        export_case(&format!("reject-assemble-count-{name}"), &request, None, -5);
    }

    let request = frame(12, &f.common, &1u32.to_be_bytes());
    rejected(&request, -6);
    export_case("reject-assemble-truncated", &request, None, -6);
}

#[test]
fn c2_malformed_frames_and_capacity_leave_output_untouched() {
    let f = fixture();
    for op in [11, 12] {
        let fifth = if op == 11 {
            owned(&[0])
        } else {
            contributions(&f, &[0, 1])
        };
        let good = frame(op, &f.common, &fifth);
        let response = execute(&good);
        let mut out = vec![0xa5; response.len() - 1];
        let mut written = 0;
        assert_eq!(
            unsafe {
                wlcj_execute_impl_v1(
                    good.as_ptr(),
                    good.len() as u64,
                    out.as_mut_ptr(),
                    out.len() as u64,
                    &mut written,
                )
            },
            -8
        );
        assert_eq!(written, response.len() as u64);
        assert!(out.iter().all(|b| *b == 0xa5));
        for mutation in 0..7 {
            let mut malformed = good.clone();
            match mutation {
                0 => {
                    malformed.pop();
                }
                1 => malformed.push(0),
                2 => malformed[16..20].copy_from_slice(&u32::MAX.to_be_bytes()),
                3 => {
                    let mut fifth = fifth.clone();
                    fifth.push(0);
                    malformed = frame(op, &f.common, &fifth);
                }
                4 => malformed = frame(op, &f.common, &fifth[..fifth.len() - 1]),
                5 => {
                    let mut common = f.common.clone();
                    common[2].pop();
                    malformed = frame(op, &common, &fifth);
                }
                6 => {
                    let mut common = f.common.clone();
                    common[3].push(0);
                    malformed = frame(op, &common, &fifth);
                }
                _ => unreachable!(),
            }
            let status = if mutation == 2 { -4 } else { -1 };
            rejected(&malformed, status);
            export_case(
                &format!("reject-frame-{op}-{mutation}"),
                &malformed,
                None,
                status,
            );
        }
    }
}
