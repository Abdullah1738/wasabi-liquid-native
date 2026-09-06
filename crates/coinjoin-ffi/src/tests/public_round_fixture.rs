//! Opt-in public export and private-test-only replay material exporter.
use super::*;
use elements::secp256k1_zkp::Message;
use std::fmt::Write as _;
use std::io::Write as _;
use std::path::PathBuf;

thread_local! {
    static PRIVATE_FRAMES: std::cell::RefCell<Option<(Vec<u8>, Vec<u8>)>> = const { std::cell::RefCell::new(None) };
}

fn execute(frame: &[u8]) -> Vec<u8> {
    let response = super::execute(frame);
    PRIVATE_FRAMES.with(|frames| {
        if let Some((requests, responses)) = frames.borrow_mut().as_mut() {
            requests.extend_from_slice(frame);
            responses.extend_from_slice(&response);
        }
    });
    response
}

const LIMITATION: &str = "Public test fixture only; synthetic outpoints and genesis, no node or real wallet. Managed still needs participant-owned input openings, output opening from op13 using the matching receiver key, credential witnesses, fresh proving/blinding entropy and matching spend keys from its own secret witness provider. Public bytes cannot regenerate those witnesses. Reblinding with different entropy or recipient keys produces a different round and different digests. Intermediate scalar-bearing PSET and all secret requests are intentionally absent.";

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(out, "{byte:02x}").unwrap();
    }
    out
}

fn directory() -> PathBuf {
    let variable = if std::env::var_os("WLCJ_PRIVATE_ROUND_FIXTURE_DIR").is_some() {
        "WLCJ_PRIVATE_ROUND_FIXTURE_DIR"
    } else {
        "WLCJ_PUBLIC_ROUND_FIXTURE_DIR"
    };
    let directory = PathBuf::from(std::env::var_os(variable).expect(
        "set the fixture directory variable to an existing empty directory under repo/tmp",
    ))
    .canonicalize()
    .unwrap();
    let tmp = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tmp")
        .canonicalize()
        .unwrap();
    assert!(directory.starts_with(&tmp) && directory != tmp);
    directory
}

fn private_directory() -> PathBuf {
    let directory = PathBuf::from(std::env::var_os("WLCJ_PRIVATE_ROUND_FIXTURE_DIR").expect(
        "set WLCJ_PRIVATE_ROUND_FIXTURE_DIR to an existing empty directory under repo/tmp",
    ))
    .canonicalize()
    .unwrap();
    let tmp = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tmp")
        .canonicalize()
        .unwrap();
    assert!(directory.starts_with(&tmp) && directory != tmp);
    #[cfg(unix)]
    assert_eq!(
        std::fs::metadata(&directory).unwrap().permissions().mode() & 0o777,
        0o700
    );
    directory
}

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

fn state_context(
    phase: Phase,
    role: ParticipantRole,
    ordinal: u32,
    prior: Option<&[u8]>,
) -> Vec<u8> {
    let mut bytes = encode_context(phase, role, ordinal);
    let asset_offset = 1 + 4 + NETWORK.len() + 32;
    for offset in [asset_offset, asset_offset + 32] {
        bytes[offset..offset + 32].copy_from_slice(&AssetId::LIQUID_BTC.to_byte_array());
    }
    if let Some(prior) = prior {
        *bytes.last_mut().unwrap() = 1;
        bytes.extend_from_slice(prior);
    }
    bytes
}

fn public_context(mut bytes: Vec<u8>) -> Vec<u8> {
    let offset = 1 + 4 + NETWORK.len() + 32;
    bytes[offset..offset + 32].copy_from_slice(&AssetId::LIQUID_BTC.to_byte_array());
    bytes
}

fn digest(pset: &[u8], context: &[u8]) -> Vec<u8> {
    response_fields(&execute(&request(1, &[pset, context])))[1].to_vec()
}

#[test]
#[ignore = "writes public fixture artifacts only when explicitly requested under repo/tmp"]
fn export_public_round_fixture() {
    let directory = directory();
    assert_eq!(
        std::fs::read_dir(&directory).unwrap().count(),
        0,
        "use an empty directory"
    );
    let secp = Secp256k1::new();
    let lbtc = AssetId::LIQUID_BTC;
    let fees = [FEE_A, FEE_B];
    let mut preblind = PartiallySignedTransaction::new_v2();
    let mut participants = Vec::new();
    let mut input_json = Vec::new();
    let mut forbidden = Vec::<Vec<u8>>::new();
    // Disposable synthetic witnesses are exported only by the private opt-in test.
    for (index, fee) in fees.iter().enumerate() {
        let mut rng = StdRng::seed_from_u64(SEED ^ (0xface_0000 + index as u64));
        let receiver = SecretKey::new(&mut rng);
        let spend = SecretKey::new(&mut rng);
        let spend_public = BitcoinPublicKey::new(spend.public_key(&secp));
        let opening = elements::TxOutSecrets::new(
            lbtc,
            AssetBlindingFactor::new(&mut rng),
            INPUT_VALUES[index],
            ValueBlindingFactor::new(&mut rng),
        );
        let funding = elements::TxOutSecrets::new(
            lbtc,
            AssetBlindingFactor::zero(),
            opening.value,
            ValueBlindingFactor::zero(),
        );
        let ephemeral = SecretKey::new(&mut rng);
        let prevout = TxOut::with_txout_secrets(
            &mut rng,
            &secp,
            Script::new_v0_wpkh(&spend_public.wpubkey_hash().unwrap()),
            receiver.public_key(&secp),
            ephemeral,
            opening,
            &[funding],
        )
        .unwrap();
        let mut input = Input::from_prevout(OutPoint::new(
            Txid::from_byte_array([0x30 + index as u8; 32]),
            index as u32,
        ));
        input.asset = Some(lbtc);
        input.blind_asset_proof = Some(
            SurjectionProof::blind_asset_proof(&mut rng, &secp, lbtc, opening.asset_bf).unwrap(),
        );
        input.in_utxo_rangeproof = Some(prevout.witness.rangeproof.clone());
        input_json.push(format!(
            "{{\"index\":{index},\"role\":{},\"txid_wire_hex\":\"{}\",\"vout\":{index},\"script_hex\":\"{}\",\"spend_public_key_hex\":\"{}\",\"receiver_public_key_hex\":\"{}\",\"asset_hex\":\"{}\",\"explicit_value\":{},\"asset_commitment_hex\":\"{}\",\"value_commitment_hex\":\"{}\",\"nonce_public_key_hex\":\"{}\",\"rangeproof_hex\":\"{}\",\"surjection_proof_hex\":\"{}\",\"asset_proof_hex\":\"{}\"}}",
            index + 1, hex(&input.previous_outpoint().txid.to_byte_array()),
            hex(prevout.script_pubkey.as_bytes()), hex(&spend_public.to_bytes()),
            hex(&receiver.public_key(&secp).serialize()), hex(&lbtc.to_byte_array()), opening.value,
            hex(&prevout.asset.commitment().unwrap().serialize()),
            hex(&prevout.value.commitment().unwrap().serialize()),
            hex(&prevout.nonce.commitment().unwrap().serialize()),
            hex(&prevout.witness.rangeproof.to_vec()), hex(&prevout.witness.surjection_proof.to_vec()),
            hex(&input.blind_asset_proof.as_ref().unwrap().to_vec()),
        ));
        input.witness_utxo = Some(prevout);
        preblind.add_input(input);
        let mut output = Output::new_explicit(
            Script::new_v0_wpkh(&spend_public.wpubkey_hash().unwrap()),
            opening.value - fee,
            lbtc,
            Some(BitcoinPublicKey::new(receiver.public_key(&secp))),
        );
        output.blinder_index = Some(index as u32);
        preblind.add_output(output);
        forbidden.extend([
            receiver.secret_bytes().to_vec(),
            spend.secret_bytes().to_vec(),
            ephemeral.secret_bytes().to_vec(),
            opening.asset_bf.into_inner().as_ref().to_vec(),
            opening.value_bf.into_inner().as_ref().to_vec(),
        ]);
        participants.push((HashMap::from([(index, opening)]), receiver, spend));
    }
    preblind.add_output(Output::new_explicit(Script::new(), FEE, lbtc, None));
    let preblind_bytes = serialize(&preblind);
    let roles = encode_role_map(&HashMap::from([(0, collab::Role::A), (1, collab::Role::B)]));
    let pre_context = state_context(Phase::Construction, ParticipantRole::Initiator, 1, None);
    let pre_digest = digest(&preblind_bytes, &pre_context);
    let intermediate_response = ScopedBytes(execute(&request(
        4,
        &[
            &preblind_bytes,
            &roles,
            &encode_secrets(&participants[0].0),
            &ENTROPY_BLIND_A,
        ],
    )));
    let intermediate = response_fields(&intermediate_response.0)[0];
    let intermediate_pset: PartiallySignedTransaction = deserialize(intermediate).unwrap();
    assert_eq!(intermediate_pset.global.scalars.len(), 1);
    forbidden.push(intermediate_pset.global.scalars[0].as_ref().to_vec());
    let intermediate_context = state_context(
        Phase::Proofs,
        ParticipantRole::Initiator,
        2,
        Some(&pre_digest),
    );
    let intermediate_digest = digest(intermediate, &intermediate_context);
    let final_response = execute(&request(
        5,
        &[
            &preblind_bytes,
            &roles,
            intermediate,
            &encode_secrets(&participants[1].0),
            &ENTROPY_BLIND_B,
        ],
    ));
    let final_bytes = response_fields(&final_response)[0];
    let final_pset: PartiallySignedTransaction = deserialize(final_bytes).unwrap();
    assert!(final_pset.global.scalars.is_empty());
    let final_context = state_context(
        Phase::PreSigning,
        ParticipantRole::Responder,
        3,
        Some(&intermediate_digest),
    );
    let final_digest = digest(final_bytes, &final_context);
    assert_eq!(
        response_fields(&execute(&request(6, &[final_bytes, &final_context])))[1],
        final_digest
    );
    let state = collab::UnblindedCoinJoin::new(
        preblind.clone(),
        &HashMap::from([(0, collab::Role::A), (1, collab::Role::B)]),
        lbtc,
    )
    .unwrap();
    collab::verify_final(&state, &final_pset).unwrap();
    let tx = final_pset.extract_tx().unwrap();
    let prevouts: Vec<_> = preblind
        .inputs()
        .iter()
        .map(|i| i.witness_utxo.clone().unwrap())
        .collect();
    tx.verify_tx_amt_proofs(&secp, &prevouts).unwrap();
    final_pset
        .verify_all_surjection_proofs_use_all_inputs(&secp, &[0, 1])
        .unwrap();

    let mut authorization = 2u32.to_be_bytes().to_vec();
    let mut output_json = Vec::new();
    let mut participant_json = Vec::new();
    for (index, (inputs, receiver, spend)) in participants.iter().enumerate() {
        let input = inputs[&index];
        let expected_value = input.value - fees[index];
        let opened_response = ScopedBytes(execute(&request(
            13,
            &[
                final_bytes,
                &(index as u32).to_be_bytes(),
                &receiver.secret_bytes(),
                &tx.txid().to_byte_array(),
                tx.output[index].script_pubkey.as_bytes(),
                &lbtc.to_byte_array(),
                &expected_value.to_be_bytes(),
            ],
        )));
        let opened = response_fields(&opened_response.0)[0];
        assert_eq!(opened.len(), 104);
        assert_eq!(&opened[..32], lbtc.to_byte_array());
        assert_eq!(&opened[32..40], expected_value.to_be_bytes());
        let output = elements::TxOutSecrets::new(
            lbtc,
            AssetBlindingFactor::from_slice(&opened[40..72]).unwrap(),
            expected_value,
            ValueBlindingFactor::from_slice(&opened[72..104]).unwrap(),
        );
        forbidden.extend([opened[40..72].to_vec(), opened[72..104].to_vec()]);
        participant_json.push(format!(
            "{{\"receiver_secret_key_hex\":\"{}\",\"spend_secret_key_hex\":\"{}\",\"input_asset_bf_hex\":\"{}\",\"input_value_bf_hex\":\"{}\",\"output_asset_bf_hex\":\"{}\",\"output_value_bf_hex\":\"{}\",\"input_credential_r1_hex\":\"{}\",\"output_credential_r1_hex\":\"{}\"}}",
            hex(&receiver.secret_bytes()), hex(&spend.secret_bytes()),
            hex(input.asset_bf.into_inner().as_ref()), hex(input.value_bf.into_inner().as_ref()),
            hex(&opened[40..72]), hex(&opened[72..104]),
            hex(&[0x60 + index as u8 + RegistrationKind::InputRegistration as u8; 32]),
            hex(&[0x60 + index as u8 + RegistrationKind::OutputRegistration as u8; 32]),
        ));
        let role = if index == 0 {
            ParticipantRole::Initiator
        } else {
            ParticipantRole::Responder
        };
        let range = final_pset.outputs()[index]
            .value_rangeproof
            .as_ref()
            .unwrap()
            .to_vec();
        let surjection = final_pset.outputs()[index]
            .asset_surjection_proof
            .as_ref()
            .unwrap()
            .to_vec();
        for (kind, opening, op, verify) in [
            (RegistrationKind::InputRegistration, input, 8, 2),
            (RegistrationKind::OutputRegistration, output, 9, 3),
        ] {
            let r1 = SecretKey::from_slice(&[0x60 + index as u8 + kind as u8; 32]).unwrap();
            let ma = credential_commitment(&secp, opening.value, &r1).serialize();
            let context = public_context(encode_registration_context(
                kind,
                role,
                index as u32 + 1,
                index as u32,
                final_digest.as_slice().try_into().unwrap(),
            ));
            let value = opening.value.to_be_bytes();
            let r1_bytes = r1.secret_bytes();
            let r2 = opening.value_bf.into_inner();
            let mut fields: Vec<&[u8]> = vec![
                final_bytes,
                &context,
                &ma,
                &value,
                &r1_bytes,
                r2.as_ref(),
                if op == 8 {
                    &ENTROPY_PROVE_INPUT
                } else {
                    &ENTROPY_PROVE_OUTPUT
                },
            ];
            if op == 9 {
                fields.extend([range.as_slice(), surjection.as_slice()]);
            }
            let proof = execute(&request(op, &fields));
            let mut fields = vec![final_bytes, &context, response_fields(&proof)[0], &ma];
            if op == 9 {
                fields.extend([range.as_slice(), surjection.as_slice()]);
            }
            assert_eq!(
                response_fields(&execute(&request(verify, &fields)))[0],
                b"OK\0\0"
            );
            forbidden.extend([r1_bytes.to_vec(), ma.to_vec()]);
        }
        let delta = ValueBlindingFactor::last(
            &secp,
            0,
            AssetBlindingFactor::zero(),
            &[input.value_blind_inputs()],
            &[output.value_blind_inputs()],
        )
        .into_inner();
        let context = public_context(encode_balance_context(
            role,
            index as u32 + 1,
            final_digest.as_slice().try_into().unwrap(),
            &[index as u32],
            &[index as u32],
            fees[index],
        ));
        let proof = execute(&request(
            10,
            &[
                final_bytes,
                &context,
                delta.as_ref(),
                &ENTROPY_PROVE_BALANCE,
            ],
        ));
        assert_eq!(
            response_fields(&execute(&request(
                7,
                &[final_bytes, &context, response_fields(&proof)[0]]
            )))[0],
            b"OK\0\0"
        );
        forbidden.push(delta.as_ref().to_vec());
        let public = BitcoinPublicKey::new(spend.public_key(&secp));
        let out = &final_pset.outputs()[index];
        output_json.push(format!(
            "{{\"index\":{index},\"role\":{},\"blinder_index\":{index},\"script_hex\":\"{}\",\"spend_public_key_hex\":\"{}\",\"receiver_public_key_hex\":\"{}\",\"asset_hex\":\"{}\",\"explicit_value\":{expected_value},\"asset_commitment_hex\":\"{}\",\"value_commitment_hex\":\"{}\",\"nonce_public_key_hex\":\"{}\",\"rangeproof_hex\":\"{}\",\"surjection_proof_hex\":\"{}\",\"asset_proof_hex\":\"{}\",\"value_proof_hex\":\"{}\"}}",
            index + 1, hex(out.script_pubkey.as_bytes()), hex(&public.to_bytes()),
            hex(&receiver.public_key(&secp).serialize()), hex(&lbtc.to_byte_array()),
            hex(&out.asset_comm.unwrap().serialize()), hex(&out.amount_comm.unwrap().serialize()),
            hex(&out.ecdh_pubkey.unwrap().to_bytes()), hex(&range), hex(&surjection),
            hex(&out.blind_asset_proof.as_ref().unwrap().to_vec()), hex(&out.blind_value_proof.as_ref().unwrap().to_vec()),
        ));
        authorization.extend_from_slice(&(index as u32).to_be_bytes());
        authorization.extend_from_slice(
            &preblind.inputs()[index]
                .previous_outpoint()
                .txid
                .to_byte_array(),
        );
        authorization.extend_from_slice(&(index as u32).to_be_bytes());
        authorization.extend_from_slice(&public.to_bytes());
    }
    let mut contributions = 2u32.to_be_bytes().to_vec();
    for (index, (_, _, spend)) in participants.iter().enumerate() {
        let mut owned = 1u32.to_be_bytes().to_vec();
        owned.extend_from_slice(&(index as u32).to_be_bytes());
        let view = execute(&request(
            11,
            &[
                final_bytes,
                &final_context,
                &final_digest,
                &authorization,
                &owned,
            ],
        ));
        let fields = response_fields(&view);
        assert_eq!(fields[1], final_digest);
        assert_eq!(fields[2].len(), 110);
        assert_eq!(fields[2][109], 0x41);
        let mut signature = secp
            .sign_ecdsa(
                &Message::from_digest(fields[2][77..109].try_into().unwrap()),
                spend,
            )
            .serialize_der()
            .to_vec();
        signature.push(0x41);
        contributions.extend_from_slice(fields[0]);
        contributions.extend_from_slice(&(index as u32).to_be_bytes());
        contributions.extend_from_slice(&spend.public_key(&secp).serialize());
        bounded(&mut contributions, &signature);
    }
    let assembled = execute(&request(
        12,
        &[
            final_bytes,
            &final_context,
            &final_digest,
            &authorization,
            &contributions,
        ],
    ));
    let assembled_fields = response_fields(&assembled);
    let mut signed: elements::Transaction = deserialize(assembled_fields[2]).unwrap();
    assert_eq!(assembled_fields[3], signed.txid().to_byte_array());
    for input in &mut signed.input {
        assert_eq!(input.witness.script_witness.len(), 2);
        input.witness.script_witness = Default::default();
    }
    assert_eq!(signed, tx);
    let private = std::env::var_os("WLCJ_PRIVATE_ROUND_FIXTURE_DIR").is_some();
    let artifacts = [
        ("preblind.pset", preblind_bytes.as_slice()),
        ("final.pset", final_bytes),
    ];
    let files: Vec<_> = artifacts
        .iter()
        .map(|(name, bytes)| {
            format!(
                "{{\"name\":\"{name}\",\"bytes\":{},\"sha256\":\"{}\"}}",
                bytes.len(),
                hex(&Sha256::digest(bytes)),
            )
        })
        .collect();
    let states: Vec<_> = [
        ("preblind", Some("preblind.pset"), &pre_context, &pre_digest, 1, 1, 1, None),
        ("intermediate", None, &intermediate_context, &intermediate_digest, 2, 1, 2, Some(&pre_digest)),
        ("final", Some("final.pset"), &final_context, &final_digest, 3, 2, 3, Some(&intermediate_digest)),
    ].iter().map(|(name, file, context, digest, phase, role, ordinal, predecessor)| format!(
        "{{\"name\":\"{name}\",\"file\":{},\"context_hex\":\"{}\",\"digest\":\"{}\",\"phase\":{phase},\"role\":{role},\"ordinal\":{ordinal},\"predecessor\":{}}}",
        file.map_or("null".into(), |f| format!("\"{f}\"")), hex(context), hex(digest),
        predecessor.map_or("null".into(), |d| format!("\"{}\"", hex(d))),
    )).collect();
    let manifest = format!(
        "{{\n\"schema\":\"wlcj-public-round-v1\",\n\"limitation\":\"{LIMITATION}\",\n\"profile\":1,\n\"network_hex\":\"{}\",\n\"genesis_hex\":\"{}\",\n\"round_hex\":\"{}\",\n\"asset_hex\":\"{}\",\n\"fee\":{{\"index\":2,\"asset_hex\":\"{}\",\"explicit_value\":{FEE},\"shares\":[{FEE_A},{FEE_B}],\"script_hex\":\"\"}},\n\"role_map_hex\":\"{}\",\n\"inputs\":[{}],\n\"outputs\":[{}],\n\"states\":[{}],\n\"files\":[{}],\n\"verified_ops\":[1,2,3,4,5,6,7,8,9,10,11,12,13],\n\"assembled_txid_wire_hex\":\"{}\",\n\"assembled_state_digest\":\"{}\"\n}}\n",
        hex(NETWORK),
        hex(&GENESIS),
        hex(ROUND),
        hex(&lbtc.to_byte_array()),
        hex(&lbtc.to_byte_array()),
        hex(&roles),
        input_json.join(","),
        output_json.join(","),
        states.join(","),
        files.join(","),
        hex(assembled_fields[3]),
        hex(assembled_fields[1]),
    );
    forbidden.extend([
        ENTROPY_BLIND_A.to_vec(),
        ENTROPY_BLIND_B.to_vec(),
        ENTROPY_PROVE_INPUT.to_vec(),
        ENTROPY_PROVE_OUTPUT.to_vec(),
        ENTROPY_PROVE_BALANCE.to_vec(),
    ]);
    let mut public_artifacts = artifacts.to_vec();
    if private {
        let private_manifest = format!(
            "{{\"schema\":\"wlcj-private-round-v1\",\"private_test_only\":true,\"source_commit\":\"{}\",\"source_tree_hash\":\"{}\",\"required_ops\":[4,5,8,9,10,11,12,13],\"psets\":[\"preblind.pset\",\"intermediate.pset\",\"final.pset\"],\"public_manifest_file\":\"manifest.json\",\"request_file\":\"requests.bin\",\"response_file\":\"responses.bin\",\"secret_file\":\"secrets.json\",\"facts_file\":\"round-facts.json\"}}\n",
            std::env::var("WLCJ_SOURCE_COMMIT").expect("WLCJ_SOURCE_COMMIT is required"),
            std::env::var("WLCJ_SOURCE_TREE_HASH").expect("WLCJ_SOURCE_TREE_HASH is required")
        );
        let secrets = format!(
            "{{\"private_test_only\":true,\"participants\":[{}]}}\n",
            participant_json.join(",")
        );
        let (requests, responses) =
            PRIVATE_FRAMES.with(|frames| frames.borrow_mut().take().unwrap());
        let facts = format!(
            "{{\"private_test_only\":true,\"role_map_hex\":\"{}\",\"input_facts\":[{}],\"output_facts\":[{}],\"contexts_hex\":[\"{}\",\"{}\",\"{}\"],\"digests_hex\":[\"{}\",\"{}\",\"{}\"],\"entropy_hex\":[\"{}\",\"{}\",\"{}\",\"{}\",\"{}\"],\"assembled_txid_wire_hex\":\"{}\"}}\n",
            hex(&roles),
            input_json.join(","),
            output_json.join(","),
            hex(&pre_context),
            hex(&intermediate_context),
            hex(&final_context),
            hex(&pre_digest),
            hex(&intermediate_digest),
            hex(&final_digest),
            hex(&ENTROPY_BLIND_A),
            hex(&ENTROPY_BLIND_B),
            hex(&ENTROPY_PROVE_INPUT),
            hex(&ENTROPY_PROVE_OUTPUT),
            hex(&ENTROPY_PROVE_BALANCE),
            hex(assembled_fields[3])
        );
        let private_artifacts = [
            ("preblind.pset", preblind_bytes.to_vec()),
            ("intermediate.pset", intermediate.to_vec()),
            ("final.pset", final_bytes.to_vec()),
            ("private-manifest.json", private_manifest.into_bytes()),
            ("manifest.json", manifest.into_bytes()),
            ("secrets.json", secrets.into_bytes()),
            ("round-facts.json", facts.into_bytes()),
            ("requests.bin", requests),
            ("responses.bin", responses),
        ];
        let mut private_sums: Vec<_> = private_artifacts
            .iter()
            .map(|(name, bytes)| (name, format!("{}  {name}\n", hex(&Sha256::digest(bytes)))))
            .collect();
        private_sums.sort_unstable_by_key(|(name, _)| *name);
        let sums: String = private_sums.into_iter().map(|(_, line)| line).collect();
        for (name, bytes) in private_artifacts {
            assert!(bytes.len() <= 1_048_576);
            let mut options = std::fs::OpenOptions::new();
            #[cfg(unix)]
            options.mode(0o600);
            options
                .write(true)
                .create_new(true)
                .open(directory.join(name))
                .unwrap()
                .write_all(&bytes)
                .unwrap();
        }
        let mut options = std::fs::OpenOptions::new();
        #[cfg(unix)]
        options.mode(0o600);
        options
            .write(true)
            .create_new(true)
            .open(directory.join("SHA256SUMS"))
            .unwrap()
            .write_all(sums.as_bytes())
            .unwrap();
        return;
    }
    public_artifacts.push(("manifest.json", manifest.as_bytes()));
    // Check both raw and hex representations before opening any output file.
    for (_, bytes) in &public_artifacts {
        assert!(bytes.len() <= 1_048_576);
        if !private {
            for secret in forbidden.iter() {
                assert!(
                    !windows_contains(bytes, secret),
                    "private bytes in public artifact"
                );
                assert!(
                    !windows_contains(bytes, hex(secret).as_bytes()),
                    "private hex in public artifact"
                );
            }
        }
    }
    let mut sum_entries: Vec<_> = public_artifacts
        .iter()
        .map(|(name, bytes)| (name, format!("{}  {name}\n", hex(&Sha256::digest(bytes)))))
        .collect();
    sum_entries.sort_unstable_by_key(|(name, _)| *name);
    let sums: String = sum_entries.into_iter().map(|(_, line)| line).collect();
    public_artifacts.push(("SHA256SUMS", sums.as_bytes()));
    for (name, bytes) in public_artifacts {
        // create_new refuses existing files and symlinks instead of overwriting them.
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(directory.join(name))
            .unwrap()
            .write_all(bytes)
            .unwrap();
    }
    for secret in &mut forbidden {
        secret.as_mut_slice().zeroize();
    }
}

#[test]
#[ignore = "writes private test replay material only when explicitly requested under repo/tmp"]
fn export_private_round_fixture() {
    let directory = private_directory();
    assert_eq!(
        std::fs::read_dir(&directory).unwrap().count(),
        0,
        "use a fresh empty directory"
    );
    // The private exporter is intentionally a separate opt-in invocation. The
    // public constructor remains the source of truth for all round bytes.
    PRIVATE_FRAMES.with(|frames| *frames.borrow_mut() = Some((Vec::new(), Vec::new())));
    export_public_round_fixture();
}

#[test]
#[ignore = "replays private native frames from an explicitly generated local bundle"]
fn replay_private_round_fixture() {
    let directory = private_directory();
    let schema = std::process::Command::new("python3")
        .arg(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/private_round_fixture_schema.py"),
        )
        .arg("--native-participants")
        .output()
        .unwrap();
    assert!(schema.status.success(), "private fixture schema rejected");
    let records = String::from_utf8(schema.stdout).unwrap();
    assert_eq!(records.lines().count(), 2);
    let preblind: PartiallySignedTransaction =
        deserialize(&std::fs::read(directory.join("preblind.pset")).unwrap()).unwrap();
    let final_pset: PartiallySignedTransaction =
        deserialize(&std::fs::read(directory.join("final.pset")).unwrap()).unwrap();
    let secp = Secp256k1::new();
    for (index, record) in records.lines().enumerate() {
        let fields: Vec<Vec<u8>> = record
            .split_whitespace()
            .map(|field| {
                field
                    .as_bytes()
                    .chunks_exact(2)
                    .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
                    .collect()
            })
            .collect();
        assert_eq!(fields.len(), 6);
        let receiver = SecretKey::from_slice(&fields[0]).unwrap();
        let spend = SecretKey::from_slice(&fields[1]).unwrap();
        let script = Script::new_v0_wpkh(
            &BitcoinPublicKey::new(spend.public_key(&secp))
                .wpubkey_hash()
                .unwrap(),
        );
        let tx = final_pset.extract_tx().unwrap();
        let mut prevout = preblind.inputs()[index].witness_utxo.clone().unwrap();
        // PSET serializes the input rangeproof separately from the witness UTXO.
        prevout.witness.rangeproof = preblind.inputs()[index].in_utxo_rangeproof.clone().unwrap();
        for (output, abf, vbf) in [
            (&prevout, &fields[2], &fields[3]),
            (&tx.output[index], &fields[4], &fields[5]),
        ] {
            assert!(
                output.script_pubkey == script,
                "participant script mismatch"
            );
            let opening = output
                .unblind(&secp, receiver)
                .expect("participant cannot open output");
            assert!(opening.asset == AssetId::LIQUID_BTC);
            assert!(
                opening.asset_bf.into_inner().as_ref() == abf.as_slice(),
                "asset opening mismatch"
            );
            assert!(
                opening.value_bf.into_inner().as_ref() == vbf.as_slice(),
                "value opening mismatch"
            );
        }
    }
    let frames = std::fs::read(directory.join("requests.bin")).unwrap();
    let expected = std::fs::read(directory.join("responses.bin")).unwrap();
    PRIVATE_FRAMES.with(|frames| *frames.borrow_mut() = Some((Vec::new(), Vec::new())));
    let mut offset = 0;
    let mut operations = Vec::new();
    while offset < frames.len() {
        assert!(offset + 16 <= frames.len());
        let payload_len =
            u32::from_be_bytes(frames[offset + 12..offset + 16].try_into().unwrap()) as usize;
        let end = offset + 16 + payload_len;
        assert!(end <= frames.len());
        let frame = &frames[offset..end];
        operations.push(u32::from_be_bytes(frame[8..12].try_into().unwrap()));
        let response = execute(frame);
        assert!(response.len() >= 16);
        offset = end;
    }
    assert_eq!(offset, frames.len());
    let (captured, actual) = PRIVATE_FRAMES.with(|frames| frames.borrow_mut().take().unwrap());
    let captured = ScopedBytes(captured);
    let actual = ScopedBytes(actual);
    assert!(!actual.0.is_empty(), "private replay captured no responses");
    assert!(
        captured.0 == frames,
        "private replay request capture mismatch"
    );
    assert!(actual.0 == expected, "private replay response mismatch");
    for operation in [4, 5, 8, 9, 10, 11, 12, 13] {
        assert!(operations.contains(&operation));
    }
}

#[test]
#[ignore = "independently reloads exported PSETs; run after export_public_round_fixture"]
fn load_public_round_fixture_psets() {
    let directory = directory();
    let schema = std::process::Command::new("python3")
        .arg(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/public_round_fixture_schema.py"))
        .arg("--native-records")
        .output()
        .unwrap();
    assert!(
        schema.status.success(),
        "{}",
        String::from_utf8_lossy(&schema.stderr)
    );
    let records = String::from_utf8(schema.stdout).unwrap();
    assert_eq!(records.lines().count(), 2);
    for record in records.lines() {
        let fields: Vec<_> = record.split_whitespace().collect();
        assert_eq!(fields.len(), 3);
        let name = fields[0];
        assert!(["preblind.pset", "final.pset"].contains(&name));
        let context: Vec<u8> = fields[1]
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect();
        let path = directory.join(name);
        assert!(
            !std::fs::symlink_metadata(&path)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert!(std::fs::metadata(&path).unwrap().len() <= 1_048_576);
        let bytes = std::fs::read(path).unwrap();
        let pset: PartiallySignedTransaction = deserialize(&bytes).unwrap();
        assert_eq!(serialize(&pset), bytes);
        assert!(pset.global.scalars.is_empty());
        assert!(pset.global.proprietary.is_empty() && pset.global.unknown.is_empty());
        for input in pset.inputs() {
            assert!(input.proprietary.is_empty() && input.unknown.is_empty());
        }
        for output in pset.outputs() {
            assert!(output.proprietary.is_empty() && output.unknown.is_empty());
        }
        // Canonical validation rejects all unsupported fields and checks proofs.
        assert_eq!(hex(&digest(&bytes, &context)), fields[2]);
    }
}
