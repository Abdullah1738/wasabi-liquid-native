//! Same-transaction confidential composition and legacy per-operation wire KATs.
use super::*;

use elements::bitcoin::PublicKey as BitcoinPublicKey;
use elements::confidential::{Asset, Nonce, RangeProof, SurjectionProof, Value};
use elements::pset::{Input, Output};
use elements::secp256k1_zkp::{Generator, PedersenCommitment, PublicKey, Scalar, SecretKey};
use elements::{AssetId, CtLocation, CtLocationType, OutPoint, Script, TxOut, Txid};
use rand::{SeedableRng, rngs::StdRng};
use wasabi_liquid_native_coinjoin_partial_balance::{
    PartialBalanceWitness, encode_proof as encode_partial_balance_proof, prove_partial_balance,
};
use wasabi_liquid_native_credential_commitment_equality::{
    EqualityWitness, encode_proof as encode_equality_proof,
};

#[test]
fn c0_confidential_same_transaction_composition() {
    let secp = Secp256k1::new();
    let lbtc = AssetId::LIQUID_BTC;
    let fees = [FEE_A, FEE_B];
    let mut preblind = PartiallySignedTransaction::new_v2();
    // Each simulated participant has separate entropy and its own opening/key.
    // The harness holds both; calls receive only one participant's secrets.
    // Indices, explicit PSET amounts and handoff scalars are NOT unlinkable.
    let mut participants = Vec::new();
    for (index, fee) in fees.iter().enumerate() {
        let mut rng = StdRng::seed_from_u64(SEED ^ (0xc001 + index as u64));
        let receiver = SecretKey::new(&mut rng);
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
            p2wpkh_script(index as u8),
            receiver.public_key(&secp),
            ephemeral,
            opening,
            &[funding],
        )
        .unwrap();
        assert_eq!(prevout.unblind(&secp, receiver).unwrap(), opening);
        let mut input = Input::from_prevout(OutPoint::new(
            Txid::from_byte_array([0x30 + index as u8; 32]),
            index as u32,
        ));
        input.asset = Some(lbtc);
        input.blind_asset_proof = Some(
            SurjectionProof::blind_asset_proof(&mut rng, &secp, lbtc, opening.asset_bf).unwrap(),
        );
        input.in_utxo_rangeproof = Some(prevout.witness.rangeproof.clone());
        input.witness_utxo = Some(prevout);
        preblind.add_input(input);
        let mut output = Output::new_explicit(
            p2wpkh_script(0x40 + index as u8),
            opening.value.checked_sub(*fee).unwrap(),
            lbtc,
            Some(BitcoinPublicKey::new(receiver.public_key(&secp))),
        );
        output.blinder_index = Some(index as u32);
        preblind.add_output(output);
        participants.push((HashMap::from([(index, opening)]), receiver, rng));
    }
    preblind.add_output(Output::new_explicit(Script::new(), FEE, lbtc, None));
    assert!(preblind.inputs().iter().all(|input| {
        let witness = &input.witness_utxo.as_ref().unwrap().witness;
        !witness.rangeproof.is_empty() && !witness.surjection_proof.is_empty()
    }));
    assert_eq!(fees.iter().sum::<u64>(), FEE);
    let mut context = canonical_context(Phase::PreSigning, ParticipantRole::Initiator, 1);
    context.lbtc_asset = lbtc;
    context.fee_asset = lbtc;
    canonicalize_pset_state(&serialize(&preblind), &context).unwrap();
    let roles = HashMap::from([(0, collab::Role::A), (1, collab::Role::B)]);
    let state = collab::UnblindedCoinJoin::new(preblind.clone(), &roles, lbtc).unwrap();
    // Public Rust callers pass populated prevouts without a wire round-trip.
    let rust_intermediate = collab::participant_a_blind_non_last(
        &state,
        &mut HashDrbg::new(&ENTROPY_BLIND_A),
        &participants[0].0,
    )
    .unwrap();
    let rust_final = collab::participant_b_blind_last(
        &state,
        &rust_intermediate,
        &mut HashDrbg::new(&ENTROPY_BLIND_B),
        &participants[1].0,
    )
    .unwrap();
    collab::verify_final(&state, &rust_final).unwrap();
    for (original, frozen) in preblind.inputs().iter().zip(state.pset().inputs()) {
        let mut expected = original.clone();
        expected.witness_utxo.as_mut().unwrap().witness = Default::default();
        assert_eq!(&expected, frozen);
        assert_eq!(original.in_utxo_rangeproof, frozen.in_utxo_rangeproof);
    }

    let role_bytes = encode_role_map(&roles);
    let preblind_bytes = serialize(&preblind);
    let response = execute(&request(
        WLCJ_OP_BLIND_NON_LAST_V1,
        &[
            &preblind_bytes,
            &role_bytes,
            &encode_secrets(&participants[0].0),
            &ENTROPY_BLIND_A,
        ],
    ));
    let intermediate_bytes = response_fields(&response)[0].to_vec();
    assert_eq!(intermediate_bytes, rust_intermediate);
    let intermediate: PartiallySignedTransaction = deserialize(&intermediate_bytes).unwrap();
    assert_eq!(intermediate.global.scalars.len(), 1);
    let asset_offset = 1 + 4 + NETWORK.len() + 32;
    let mut signer_context = encode_context(Phase::PreSigning, ParticipantRole::Initiator, 1);
    signer_context[asset_offset..asset_offset + 32].copy_from_slice(&lbtc.to_byte_array());
    signer_context[asset_offset + 32..asset_offset + 64].copy_from_slice(&lbtc.to_byte_array());
    assert_eq!(
        execute_reject(&request(
            WLCJ_OP_VALIDATE_SIGNER_VIEW_V1,
            &[&intermediate_bytes, &signer_context]
        )),
        WLCJ_STATUS_VALIDATION_FAILED_V1
    );
    let response = execute(&request(
        WLCJ_OP_BLIND_LAST_V1,
        &[
            &preblind_bytes,
            &role_bytes,
            &intermediate_bytes,
            &encode_secrets(&participants[1].0),
            &ENTROPY_BLIND_B,
        ],
    ));
    let final_pset: PartiallySignedTransaction =
        deserialize(response_fields(&response)[0]).unwrap();
    assert_eq!(serialize(&rust_final), serialize(&final_pset));
    assert!(final_pset.global.scalars.is_empty());
    collab::verify_final(&state, &final_pset).unwrap();
    final_pset
        .verify_all_surjection_proofs_use_all_inputs(&secp, &[0, 1])
        .unwrap();
    let transaction = final_pset.extract_tx().unwrap();
    let prevouts: Vec<_> = preblind
        .inputs()
        .iter()
        .map(|i| i.witness_utxo.clone().unwrap())
        .collect();
    transaction.verify_tx_amt_proofs(&secp, &prevouts).unwrap();
    let final_bytes = serialize(&final_pset);
    let final_digest = canonicalize_pset_state(&final_bytes, &context)
        .unwrap()
        .digest()
        .into_bytes();
    let response = execute(&request(
        WLCJ_OP_VALIDATE_SIGNER_VIEW_V1,
        &[&final_bytes, &signer_context],
    ));
    assert_eq!(response_fields(&response)[1], final_digest);

    let mut wrong_fee = final_pset.clone();
    wrong_fee.outputs_mut()[2].amount = Some(FEE + 1);
    assert!(collab::verify_final(&state, &wrong_fee).is_err());
    assert_ne!(
        canonicalize_pset_state(&serialize(&wrong_fee), &context)
            .unwrap()
            .digest()
            .into_bytes(),
        final_digest
    );
    let mut wrong_asset = final_pset.clone();
    wrong_asset.outputs_mut()[0].asset = Some(asset());
    assert!(canonicalize_pset_state(&serialize(&wrong_asset), &context).is_err());
    let mut wrong_domain = final_pset.clone();
    wrong_domain.inputs_mut().swap(0, 1);
    assert!(
        wrong_domain
            .verify_all_surjection_proofs_use_all_inputs(&secp, &[0, 1])
            .is_err()
    );
    assert!(canonicalize_pset_state(&serialize(&wrong_domain), &context).is_err());
    for corrupt_range in [false, true] {
        let mut invalid = final_pset.clone();
        if corrupt_range {
            invalid.outputs_mut()[0].value_rangeproof =
                final_pset.outputs()[1].value_rangeproof.clone();
        } else {
            invalid.outputs_mut()[0].asset_surjection_proof =
                final_pset.outputs()[1].asset_surjection_proof.clone();
        }
        assert!(canonicalize_pset_state(&serialize(&invalid), &context).is_err());
    }
    let mut wrong_handoff = intermediate.clone();
    wrong_handoff.inputs_mut().swap(0, 1);
    let (secrets_b, _, rng_b) = &mut participants[1];
    assert!(matches!(
        collab::participant_b_blind_last(&state, &serialize(&wrong_handoff), rng_b, secrets_b),
        Err(collab::Error::DomainMutationRejected)
    ));
    let mut wrong_handoff = intermediate.clone();
    wrong_handoff.inputs_mut()[0]
        .witness_utxo
        .as_mut()
        .unwrap()
        .script_pubkey = p2wpkh_script(0x7f);
    assert!(matches!(
        collab::participant_b_blind_last(&state, &serialize(&wrong_handoff), rng_b, secrets_b),
        Err(collab::Error::DomainMutationRejected)
    ));

    for index in 0..2 {
        for mutation in 0..6 {
            let mut invalid = preblind.clone();
            match mutation {
                0 => invalid.inputs_mut()[index].blind_asset_proof = None,
                1 => {
                    invalid.inputs_mut()[index].in_utxo_rangeproof =
                        preblind.inputs()[1 - index].in_utxo_rangeproof.clone()
                }
                2 => invalid.inputs_mut()[index].asset = Some(asset()),
                3 => {
                    invalid.inputs_mut()[index].blind_asset_proof =
                        preblind.inputs()[1 - index].blind_asset_proof.clone()
                }
                4 => invalid.inputs_mut()[index].in_utxo_rangeproof = None,
                5 => {
                    invalid.inputs_mut()[index]
                        .witness_utxo
                        .as_mut()
                        .unwrap()
                        .witness
                        .rangeproof = preblind.inputs()[1 - index]
                        .in_utxo_rangeproof
                        .clone()
                        .unwrap();
                }
                _ => unreachable!(),
            }
            assert!(collab::UnblindedCoinJoin::new(invalid, &roles, lbtc).is_err());
        }
        let mut wrong_opening = participants[index].0.clone();
        wrong_opening.get_mut(&index).unwrap().value += 1;
        let mut rng = StdRng::seed_from_u64(SEED);
        assert!(collab::participant_a_blind_non_last(&state, &mut rng, &wrong_opening).is_err());
        let other_receiver = participants[1 - index].1;
        assert!(
            transaction.output[index]
                .unblind(&secp, other_receiver)
                .is_err()
        );
    }

    for (index, (secrets, receiver, _)) in participants.iter().enumerate() {
        let input = secrets[&index];
        // Real recipient unblinding, not replayed RNG or injected scalar fields.
        let output = transaction.output[index].unblind(&secp, *receiver).unwrap();
        assert_eq!(input.value, output.value + fees[index]);
        assert_eq!(output.asset, lbtc);
        let indices = [index as u32];
        let mut balance = balance_context(
            if index == 0 {
                ParticipantRole::Initiator
            } else {
                ParticipantRole::Responder
            },
            index as u32 + 1,
            final_digest,
            &indices,
            &indices,
            fees[index],
        );
        balance.lbtc_asset = lbtc;
        // last(0, 0, inputs, outputs) = sum(vbf + value*abf)_in - sum(...)_out.
        let delta = ValueBlindingFactor::last(
            &secp,
            0,
            AssetBlindingFactor::zero(),
            &[input.value_blind_inputs()],
            &[output.value_blind_inputs()],
        );
        // The fork really transmits A's residual; B absorbs its negative.
        // Protecting this handoff is necessary but does not hide contribution links.
        let handoff_delta =
            ValueBlindingFactor::from_slice(intermediate.global.scalars[0].as_ref()).unwrap();
        assert_eq!(
            delta,
            if index == 0 {
                handoff_delta
            } else {
                -handoff_delta
            }
        );
        for (opening, commitment) in [
            (input, prevouts[index].value.commitment().unwrap()),
            (output, final_pset.outputs()[index].amount_comm.unwrap()),
        ] {
            let effective = ValueBlindingFactor::last(
                &secp,
                0,
                AssetBlindingFactor::zero(),
                &[opening.value_blind_inputs()],
                &[],
            );
            assert_eq!(
                commitment,
                PedersenCommitment::new(
                    &secp,
                    opening.value,
                    effective.into_inner(),
                    Generator::new_unblinded(&secp, lbtc.into_tag())
                )
            );
        }
        let witness =
            PartialBalanceWitness::from_scalar_bytes(delta.into_inner().as_ref()).unwrap();
        let proof = prove_partial_balance(
            &secp,
            &final_pset,
            &balance,
            &witness,
            &ENTROPY_PROVE_BALANCE,
        )
        .unwrap();
        partial_balance::verify_partial_balance(&secp, &final_pset, &balance, &proof).unwrap();
        let mut wire_context = encode_balance_context(
            balance.participant_role,
            balance.contribution_ordinal,
            &final_digest,
            &indices,
            &indices,
            fees[index],
        );
        wire_context[asset_offset..asset_offset + 32].copy_from_slice(&lbtc.to_byte_array());
        let residual = delta.into_inner();
        let creation_fields = [
            final_bytes.clone(),
            wire_context.clone(),
            residual.as_ref().to_vec(),
            ENTROPY_PROVE_BALANCE.to_vec(),
        ];
        let creation_request = request(
            WLCJ_OP_PROVE_PARTIAL_BALANCE_V1,
            &creation_fields
                .iter()
                .map(Vec::as_slice)
                .collect::<Vec<_>>(),
        );
        let creation_response = execute(&creation_request);
        assert_eq!(creation_response.len(), 85);
        assert_eq!(&creation_response[8..12], &10u32.to_be_bytes());
        assert_eq!(response_fields(&creation_response).len(), 1);
        assert_eq!(
            response_fields(&creation_response)[0],
            encode_partial_balance_proof(&proof)
        );
        assert_eq!(execute(&creation_request), creation_response);
        for secret in &creation_fields[2..] {
            assert!(!windows_contains(&creation_response, secret));
        }
        let verification_request = request(
            WLCJ_OP_VERIFY_PARTIAL_BALANCE_V1,
            &[
                &final_bytes,
                &wire_context,
                response_fields(&creation_response)[0],
            ],
        );
        assert_eq!(
            response_fields(&execute(&verification_request))[0],
            b"OK\0\0"
        );

        // Confidential witness values still require explicit PSET asset
        // metadata to match the balance context.
        let mut mismatched_pset = final_pset.clone();
        mismatched_pset.inputs_mut()[index].asset = Some(AssetId::from_byte_array([0x99; 32]));
        assert!(
            partial_balance::verify_partial_balance(&secp, &mismatched_pset, &balance, &proof)
                .is_err()
        );
        let mismatched_request = request(
            WLCJ_OP_PROVE_PARTIAL_BALANCE_V1,
            &[
                &serialize(&mismatched_pset),
                &wire_context,
                residual.as_ref(),
                &ENTROPY_PROVE_BALANCE,
            ],
        );
        assert_eq!(
            execute_reject(&mismatched_request),
            WLCJ_STATUS_VALIDATION_FAILED_V1
        );

        // Optional real-path fixtures, confined to this repository's ignored tmp.
        if let Some(directory) = std::env::var_os("WLCJ_C1_FIXTURE_DIR") {
            let directory = std::path::PathBuf::from(directory).canonicalize().unwrap();
            let tmp = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../tmp")
                .canonicalize()
                .unwrap();
            assert!(directory.starts_with(tmp));
            std::fs::write(
                directory.join(format!("op10-{index}.request")),
                &creation_request,
            )
            .unwrap();
            std::fs::write(
                directory.join(format!("op10-{index}.response")),
                &creation_response,
            )
            .unwrap();
            std::fs::write(
                directory.join(format!("op7-{index}.request")),
                verification_request,
            )
            .unwrap();
        }
        if index == 0 {
            c1_partial_balance_hostiles(&creation_fields);
        }
        let response = execute(&request(
            WLCJ_OP_VERIFY_PARTIAL_BALANCE_V1,
            &[
                &final_bytes,
                &wire_context,
                &encode_partial_balance_proof(&proof),
            ],
        ));
        assert_eq!(response_fields(&response)[0], b"OK\0\0");
        // Raw VBFs omit value*ABF and must not verify against canonical H_A.
        let mut raw_delta = input.value_bf;
        raw_delta += -output.value_bf;
        assert_eq!(
            execute_reject(&request(
                WLCJ_OP_PROVE_PARTIAL_BALANCE_V1,
                &[
                    &final_bytes,
                    &wire_context,
                    raw_delta.into_inner().as_ref(),
                    &ENTROPY_PROVE_BALANCE
                ],
            )),
            WLCJ_STATUS_VERIFICATION_FAILED_V1
        );
        let raw_witness =
            PartialBalanceWitness::from_scalar_bytes(raw_delta.into_inner().as_ref()).unwrap();
        let raw_proof = prove_partial_balance(
            &secp,
            &final_pset,
            &balance,
            &raw_witness,
            &ENTROPY_PROVE_BALANCE,
        )
        .unwrap();
        assert!(
            partial_balance::verify_partial_balance(&secp, &final_pset, &balance, &raw_proof)
                .is_err()
        );
        for mutation in 0..5 {
            let other = [1 - index as u32];
            let mut changed = balance_context(
                balance.participant_role,
                balance.contribution_ordinal,
                final_digest,
                &indices,
                &indices,
                fees[index],
            );
            changed.lbtc_asset = lbtc;
            match mutation {
                0 => changed.fee_share += 1,
                1 => changed.lbtc_asset = asset(),
                2 => changed.input_indices = &other,
                3 => changed.output_indices = &other,
                4 => changed.pset_state_digest[0] ^= 1,
                _ => unreachable!(),
            }
            assert!(
                partial_balance::verify_partial_balance(&secp, &final_pset, &changed, &proof)
                    .is_err()
            );
            let mut wire_context = encode_balance_context(
                changed.participant_role,
                changed.contribution_ordinal,
                &changed.pset_state_digest,
                changed.input_indices,
                changed.output_indices,
                changed.fee_share,
            );
            wire_context[asset_offset..asset_offset + 32]
                .copy_from_slice(&changed.lbtc_asset.to_byte_array());
            let changed_creation = request(
                WLCJ_OP_PROVE_PARTIAL_BALANCE_V1,
                &[
                    &final_bytes,
                    &wire_context,
                    residual.as_ref(),
                    &ENTROPY_PROVE_BALANCE,
                ],
            );
            match mutation {
                // Digest is opaque caller context: a new proof binds the new
                // digest but cannot replay under the original canonical digest.
                4 => {
                    let changed_response = execute(&changed_creation);
                    assert_ne!(changed_response, creation_response);
                    execute(&request(
                        WLCJ_OP_VERIFY_PARTIAL_BALANCE_V1,
                        &[
                            &final_bytes,
                            &wire_context,
                            response_fields(&changed_response)[0],
                        ],
                    ));
                    assert_eq!(
                        execute_reject(&request(
                            WLCJ_OP_VERIFY_PARTIAL_BALANCE_V1,
                            &[
                                &final_bytes,
                                &creation_fields[1],
                                response_fields(&changed_response)[0]
                            ],
                        )),
                        WLCJ_STATUS_VERIFICATION_FAILED_V1
                    );
                }
                1 => assert_eq!(
                    execute_reject(&changed_creation),
                    WLCJ_STATUS_VALIDATION_FAILED_V1
                ),
                _ => assert_eq!(
                    execute_reject(&changed_creation),
                    WLCJ_STATUS_VERIFICATION_FAILED_V1
                ),
            }
            assert_eq!(
                execute_reject(&request(
                    WLCJ_OP_VERIFY_PARTIAL_BALANCE_V1,
                    &[
                        &final_bytes,
                        &wire_context,
                        &encode_partial_balance_proof(&proof)
                    ]
                )),
                WLCJ_STATUS_VERIFICATION_FAILED_V1
            );
        }

        // Equality uses the actual asset generator, hence the raw VBF, not r_eff.
        // Compare direct proving with stateless ABI creation on the same C0 PSET.
        for (kind, opening) in [
            (RegistrationKind::InputRegistration, input),
            (RegistrationKind::OutputRegistration, output),
        ] {
            let r1 = SecretKey::from_slice(&[0x60 + index as u8 + kind as u8; 32]).unwrap();
            let ma = credential_commitment(&secp, opening.value, &r1);
            let statement = match kind {
                RegistrationKind::InputRegistration => equality::input_registration_statement(
                    &ma.serialize(),
                    final_pset.inputs()[index].witness_utxo.as_ref().unwrap(),
                )
                .unwrap(),
                RegistrationKind::OutputRegistration => {
                    equality::output_registration_statement(&ma.serialize(), &final_pset, index)
                        .unwrap()
                }
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
            let mut registration = RegistrationContext {
                profile: ProfileVersion::V1,
                network_identity: NETWORK,
                genesis_hash: GENESIS,
                lbtc_asset: lbtc,
                round_id: ROUND,
                phase: Phase::Proofs,
                participant_role: balance.participant_role,
                contribution_ordinal: balance.contribution_ordinal,
                kind,
                element_index: index as u32,
                pset_state_digest: final_digest,
                output_proof_binding: if kind == RegistrationKind::OutputRegistration {
                    Some(OutputProofBinding {
                        value_rangeproof: &range,
                        asset_surjection_proof: &surjection,
                    })
                } else {
                    None
                },
            };
            let r2 = SecretKey::from_slice(opening.value_bf.into_inner().as_ref()).unwrap();
            let witness = EqualityWitness::new(opening.value, &r1, &r2).unwrap();
            let proof = encode_equality_proof(
                &equality::prove_registration(
                    &secp,
                    &witness,
                    &statement,
                    &registration,
                    &ENTROPY_PROVE_INPUT,
                )
                .unwrap(),
            );
            equality::verify_registration(&secp, &statement, &proof, &registration).unwrap();
            let mut wire_context = encode_registration_context(
                kind,
                registration.participant_role,
                registration.contribution_ordinal,
                index as u32,
                &final_digest,
            );
            wire_context[asset_offset..asset_offset + 32].copy_from_slice(&lbtc.to_byte_array());
            let ma_bytes = ma.serialize();
            let value_bytes = opening.value.to_be_bytes();
            let r1_bytes = r1.secret_bytes();
            let r2_bytes = r2.secret_bytes();
            let mut creation_fields: Vec<&[u8]> = vec![
                &final_bytes,
                &wire_context,
                &ma_bytes,
                &value_bytes,
                &r1_bytes,
                &r2_bytes,
                &ENTROPY_PROVE_INPUT,
            ];
            let creation_op = if kind == RegistrationKind::OutputRegistration {
                creation_fields.extend([range.as_slice(), surjection.as_slice()]);
                WLCJ_OP_PROVE_OUTPUT_REGISTRATION_V1
            } else {
                WLCJ_OP_PROVE_INPUT_REGISTRATION_V1
            };
            assert_eq!(
                response_fields(&execute(&request(creation_op, &creation_fields)))[0],
                proof
            );
            let mut fields: Vec<&[u8]> = vec![&final_bytes, &wire_context, &proof, &ma_bytes];
            let op = if kind == RegistrationKind::OutputRegistration {
                fields.extend([range.as_slice(), surjection.as_slice()]);
                WLCJ_OP_VERIFY_OUTPUT_REGISTRATION_V1
            } else {
                WLCJ_OP_VERIFY_INPUT_REGISTRATION_V1
            };
            let response = execute(&request(op, &fields));
            assert_eq!(response_fields(&response)[0], b"OK\0\0");
            registration.pset_state_digest[0] ^= 1;
            assert!(
                equality::verify_registration(&secp, &statement, &proof, &registration).is_err()
            );
            registration.pset_state_digest = final_digest;
            registration.element_index = 1 - index as u32;
            assert!(
                equality::verify_registration(&secp, &statement, &proof, &registration).is_err()
            );
        }
    }
}

#[test]
fn c0_original_books_reject_even_with_effective_blinding() {
    let secp = Secp256k1::new();
    let round = build_round();
    let pset: PartiallySignedTransaction = deserialize(&round.final_bytes).unwrap();
    let output = pset.extract_tx().unwrap().output[0]
        .unblind(&secp, SecretKey::from_slice(&[3; 32]).unwrap())
        .unwrap();
    assert_eq!(INPUT_VALUES[0] - output.value - FEE_A, 1_000);
    let delta = ValueBlindingFactor::last(
        &secp,
        0,
        AssetBlindingFactor::zero(),
        &[(
            INPUT_VALUES[0],
            AssetBlindingFactor::zero(),
            ValueBlindingFactor::zero(),
        )],
        &[output.value_blind_inputs()],
    );
    let witness = PartialBalanceWitness::from_scalar_bytes(delta.into_inner().as_ref()).unwrap();
    let context = balance_context(
        ParticipantRole::Initiator,
        1,
        round.final_digest,
        &[0],
        &[0],
        FEE_A,
    );
    let proof =
        prove_partial_balance(&secp, &pset, &context, &witness, &ENTROPY_PROVE_BALANCE).unwrap();
    assert!(partial_balance::verify_partial_balance(&secp, &pset, &context, &proof).is_err());
    assert_eq!(
        execute_reject(&request(
            WLCJ_OP_PROVE_PARTIAL_BALANCE_V1,
            &[
                &round.final_bytes,
                &encode_balance_context(
                    ParticipantRole::Initiator,
                    1,
                    &round.final_digest,
                    &[0],
                    &[0],
                    FEE_A
                ),
                delta.into_inner().as_ref(),
                &ENTROPY_PROVE_BALANCE,
            ],
        )),
        WLCJ_STATUS_VERIFICATION_FAILED_V1
    );
}

fn c1_partial_balance_hostiles(fields: &[Vec<u8>; 4]) {
    let make_request = |fields: &[Vec<u8>]| {
        request(
            WLCJ_OP_PROVE_PARTIAL_BALANCE_V1,
            &fields.iter().map(Vec::as_slice).collect::<Vec<_>>(),
        )
    };
    let good = make_request(fields);
    for field in 0..4 {
        for length in [0, fields[field].len() - 1, fields[field].len() + 1] {
            let mut changed = fields.clone();
            changed[field].resize(length, 0);
            let status = execute_reject(&make_request(&changed));
            if field >= 2 {
                assert_eq!(status, WLCJ_STATUS_INVALID_FRAME_V1);
            }
        }
        let mut missing = fields.to_vec();
        missing.remove(field);
        assert_eq!(
            execute_reject(&make_request(&missing)),
            WLCJ_STATUS_INVALID_FRAME_V1
        );
    }
    let mut extra = fields.to_vec();
    extra.push(vec![]);
    assert_eq!(
        execute_reject(&make_request(&extra)),
        WLCJ_STATUS_INVALID_FRAME_V1
    );
    let mut trailing = good.clone();
    trailing.push(0);
    assert_eq!(execute_reject(&trailing), WLCJ_STATUS_INVALID_FRAME_V1);
    assert_eq!(
        execute_reject(&good[..good.len() - 1]),
        WLCJ_STATUS_INVALID_FRAME_V1
    );
    let payload_len = (trailing.len() - 16) as u32;
    trailing[12..16].copy_from_slice(&payload_len.to_be_bytes());
    assert_eq!(execute_reject(&trailing), WLCJ_STATUS_INVALID_FRAME_V1);
    let mut oversized = good.clone();
    let size = OP_PAYLOAD_BOUNDS[9] + 1;
    oversized.resize(16 + size as usize, 0);
    oversized[12..16].copy_from_slice(&size.to_be_bytes());
    assert_eq!(execute_reject(&oversized), WLCJ_STATUS_PAYLOAD_TOO_LARGE_V1);
    assert_eq!(
        execute_reject(&frame(10, &(WLCJ_MAX_FIELD_BYTES_V1 + 1).to_be_bytes())),
        WLCJ_STATUS_PAYLOAD_TOO_LARGE_V1
    );
    assert_eq!(
        execute_reject(&frame(10, &vec![0; (WLCJ_MAX_FIELDS_V1 as usize + 1) * 4])),
        WLCJ_STATUS_PAYLOAD_TOO_LARGE_V1
    );
    let mut out = [0xa5; 85];
    let mut length = u64::MAX;
    let status = unsafe {
        wlcj_execute_impl_v1(
            good.as_ptr(),
            WLCJ_MAX_FRAME_BYTES_V1 + 1,
            out.as_mut_ptr(),
            85,
            &mut length,
        )
    };
    assert_eq!(status, WLCJ_STATUS_PAYLOAD_TOO_LARGE_V1);
    assert_eq!(length, 0);
    assert_eq!(out, [0xa5; 85]);
    for capacity in [0, 1, 84] {
        let status = unsafe {
            wlcj_execute_impl_v1(
                good.as_ptr(),
                good.len() as u64,
                out.as_mut_ptr(),
                capacity,
                &mut length,
            )
        };
        assert_eq!(status, WLCJ_STATUS_OUTPUT_CAPACITY_V1);
        assert_eq!(length, 85);
        assert_eq!(out, [0xa5; 85]);
    }
    INJECT_TEST_PANIC.with(|armed| armed.set(true));
    assert_eq!(execute_reject(&good), WLCJ_STATUS_INTERNAL_ERROR_V1);
    execute(&good);

    let context_len = fields[1].len();
    // Invalid profile, phase, role, out-of-range indices, and count caps.
    for offset in [
        0,
        context_len - 62,
        context_len - 61,
        context_len - 20,
        context_len - 12,
        context_len - 24,
        context_len - 16,
    ] {
        let mut changed = fields.clone();
        changed[1][offset] = 0xff;
        assert_eq!(
            execute_reject(&make_request(&changed)),
            WLCJ_STATUS_VALIDATION_FAILED_V1
        );
    }
    let mut changed = fields.clone();
    changed[2][31] ^= 1;
    assert_eq!(
        execute_reject(&make_request(&changed)),
        WLCJ_STATUS_VERIFICATION_FAILED_V1
    );
    let original_response = execute(&good);
    for entropy in [vec![0; 32], vec![0xff; 32]] {
        let mut changed = fields.clone();
        changed[3] = entropy;
        let response = execute(&make_request(&changed));
        assert_ne!(response, original_response);
        execute(&request(
            7,
            &[&fields[0], &fields[1], response_fields(&response)[0]],
        ));
    }
    let pset: PartiallySignedTransaction = deserialize(&fields[0]).unwrap();
    for input in [false, true] {
        let mut changed_pset = pset.clone();
        if input {
            changed_pset.inputs_mut()[0].witness_utxo = pset.inputs()[1].witness_utxo.clone();
        } else {
            changed_pset.outputs_mut()[0].amount_comm = pset.outputs()[1].amount_comm;
        }
        let mut changed = fields.clone();
        changed[0] = serialize(&changed_pset);
        assert_eq!(
            execute_reject(&make_request(&changed)),
            WLCJ_STATUS_VERIFICATION_FAILED_V1
        );
    }
}

#[test]
fn c1_partial_balance_scalar_boundaries() {
    let secp = Secp256k1::new();
    let maximum = Scalar::MAX.to_be_bytes();
    let mut order = maximum;
    order[31] += 1;
    let mut one = [0; 32];
    one[31] = 1;
    // Diagnostic scalar-boundary fixture, not canonical lifecycle evidence.
    // Residual is -output_vbf = n-1. C0 above supplies the real lifecycle.
    let mut pset = PartiallySignedTransaction::new_v2();
    let mut input = explicit_input(0, 2);
    input.asset = Some(asset());
    pset.add_input(input);
    let generator = Generator::new_unblinded(&secp, asset().into_tag());
    let mut output = Output::new_explicit(p2wpkh_script(1), 1, asset(), None);
    output.asset_comm = Some(generator);
    output.amount_comm = Some(PedersenCommitment::new(
        &secp,
        1,
        ValueBlindingFactor::from_slice(&one).unwrap().into_inner(),
        generator,
    ));
    pset.add_output(output);
    let context = balance_context(ParticipantRole::Initiator, 1, [0; 32], &[0], &[0], 1);
    let wire_context =
        encode_balance_context(ParticipantRole::Initiator, 1, &[0; 32], &[0], &[0], 1);
    for scalar in [[0; 32], order, [0xff; 32], one, maximum] {
        let frame = request(
            10,
            &[
                &serialize(&pset),
                &wire_context,
                &scalar,
                &ENTROPY_PROVE_BALANCE,
            ],
        );
        let witness = PartialBalanceWitness::from_scalar_bytes(&scalar);
        assert_eq!(witness.is_ok(), scalar == one || scalar == maximum);
        if let Ok(witness) = witness {
            let proof =
                prove_partial_balance(&secp, &pset, &context, &witness, &ENTROPY_PROVE_BALANCE)
                    .unwrap();
            let valid =
                partial_balance::verify_partial_balance(&secp, &pset, &context, &proof).is_ok();
            assert_eq!(valid, scalar == maximum);
            if valid {
                let response = execute(&frame);
                assert_eq!(
                    response_fields(&response)[0],
                    encode_partial_balance_proof(&proof)
                );
                execute(&request(
                    7,
                    &[
                        &serialize(&pset),
                        &wire_context,
                        response_fields(&response)[0],
                    ],
                ));
            } else {
                assert_eq!(
                    execute_reject(&frame),
                    if scalar == one {
                        WLCJ_STATUS_VERIFICATION_FAILED_V1
                    } else {
                        WLCJ_STATUS_VALIDATION_FAILED_V1
                    }
                );
            }
        } else {
            assert_eq!(execute_reject(&frame), WLCJ_STATUS_VALIDATION_FAILED_V1);
        }
    }
    let pset_bytes = serialize(&pset);
    let proof = encode_partial_balance_proof(
        &prove_partial_balance(
            &secp,
            &pset,
            &context,
            &PartialBalanceWitness::from_scalar_bytes(&maximum).unwrap(),
            &ENTROPY_PROVE_BALANCE,
        )
        .unwrap(),
    );
    let zero_fee_context =
        encode_balance_context(ParticipantRole::Initiator, 1, &[0; 32], &[0], &[0], 0);
    // Op 7 must retain its legacy verification failure, not op 10's admission status.
    for proof_bytes in [&proof[..], &[0; 65][..]] {
        assert_eq!(
            execute_reject(&request(
                WLCJ_OP_VERIFY_PARTIAL_BALANCE_V1,
                &[&pset_bytes, &zero_fee_context, proof_bytes],
            )),
            WLCJ_STATUS_VERIFICATION_FAILED_V1
        );
    }
    for (context_bytes, residual) in [
        (&zero_fee_context, maximum),
        (&wire_context, [0; 32]),
        (&zero_fee_context, [0; 32]),
    ] {
        assert_eq!(
            execute_reject(&request(
                WLCJ_OP_PROVE_PARTIAL_BALANCE_V1,
                &[
                    &pset_bytes,
                    context_bytes,
                    &residual,
                    &ENTROPY_PROVE_BALANCE
                ],
            )),
            WLCJ_STATUS_VALIDATION_FAILED_V1
        );
    }
}

const NETWORK: &[u8] = b"elements-liquid-mainnet";
const ROUND: &[u8] = b"round-coinjoin-ffi-0001";
const GENESIS: [u8; 32] = [0x22; 32];
const SEED: u64 = 0x5eed_5eed_ff10_0001;

/// WabiSabi NUMS generator `Gg`, pinned by the credential crate's
/// known-answer test (`generator_kat_gg`).
const WABISABI_GG_BYTES: [u8; 33] = [
    0x02, 0xfb, 0x88, 0x68, 0xac, 0xd9, 0xcb, 0xbd, 0x68, 0x96, 0x4b, 0xaa, 0x1c, 0xfa, 0x6b, 0x89,
    0x3a, 0x62, 0x69, 0xe0, 0x15, 0x69, 0x18, 0x34, 0x74, 0xe6, 0xc1, 0xc4, 0x24, 0x2a, 0x00, 0x71,
    0xa9,
];
/// WabiSabi NUMS generator `Gh`, pinned by the credential crate's
/// known-answer test (`generator_kat_gh`).
const WABISABI_GH_BYTES: [u8; 33] = [
    0x02, 0x3d, 0x11, 0xe1, 0x0c, 0xe7, 0xa8, 0xc1, 0x76, 0x71, 0xed, 0x77, 0x78, 0x86, 0xfc, 0x2b,
    0x84, 0xe6, 0x5a, 0x53, 0x2f, 0xa0, 0xc4, 0x11, 0xab, 0xbe, 0x96, 0xe1, 0x20, 0x6f, 0x9d, 0xff,
    0x80,
];

fn asset() -> AssetId {
    AssetId::from_byte_array([0x11; 32])
}

fn blinding_key(byte: u8) -> BitcoinPublicKey {
    let secp = Secp256k1::new();
    BitcoinPublicKey::new(
        SecretKey::from_slice(&[byte; 32])
            .unwrap()
            .public_key(&secp),
    )
}

fn p2wpkh_script(tag: u8) -> Script {
    let mut bytes = vec![0x00, 0x14];
    bytes.extend_from_slice(&[tag; 20]);
    Script::from(bytes)
}

fn scalar_of(key: &SecretKey) -> Scalar {
    Scalar::from_be_bytes(key.secret_bytes()).expect("secret keys are valid scalars")
}

fn value_scalar(value: u64) -> Scalar {
    let mut bytes = [0u8; 32];
    bytes[24..].copy_from_slice(&value.to_be_bytes());
    Scalar::from_be_bytes(bytes).expect("u64 values are valid scalars")
}

fn credential_commitment(secp: &Secp256k1<All>, value: u64, r1: &SecretKey) -> PublicKey {
    let gg = PublicKey::from_slice(&WABISABI_GG_BYTES).unwrap();
    let gh = PublicKey::from_slice(&WABISABI_GH_BYTES).unwrap();
    gg.mul_tweak(secp, &value_scalar(value))
        .unwrap()
        .combine(&gh.mul_tweak(secp, &scalar_of(r1)).unwrap())
        .unwrap()
}

// ---------------------------------------------------------------------------
// Legacy per-operation KAT fixtures, NOT same-transaction composition evidence.
//
// Separate blinding, registration and balance PSETs preserve shipped wire KATs.
// Only the C0 fixture above proves their composition on one final transaction.
// ---------------------------------------------------------------------------

const INPUT_VALUES: [u64; 2] = [5_000, 4_000];
const OUTPUT_VALUES: [u64; 2] = [3_500, 4_400];
const FEE: u64 = 1_100;
const FEE_A: u64 = 500;
const FEE_B: u64 = 600;

const ENTROPY_BLIND_A: [u8; 32] = [0xA1; 32];
const ENTROPY_BLIND_B: [u8; 32] = [0xB2; 32];
const ENTROPY_PROVE_INPUT: [u8; 32] = [0x77; 32];
const ENTROPY_PROVE_OUTPUT: [u8; 32] = [0x88; 32];
const ENTROPY_PROVE_BALANCE: [u8; 32] = [0x99; 32];

// ---------------------------------------------------------------------------
// Typed context builders (mirrors of the frozen ABI parsers' layouts).
// ---------------------------------------------------------------------------

fn canonical_context(
    phase: Phase,
    role: ParticipantRole,
    ordinal: u32,
) -> CanonicalStateContext<'static> {
    CanonicalStateContext {
        profile: ProfileVersion::V1,
        network_identity: NETWORK,
        genesis_hash: GENESIS,
        lbtc_asset: asset(),
        fee_asset: asset(),
        round_id: ROUND,
        phase,
        participant_role: role,
        contribution_ordinal: ordinal,
        predecessor: PredecessorDigest::Absent,
    }
}

fn registration_context(
    kind: RegistrationKind,
    role: ParticipantRole,
    ordinal: u32,
    element_index: u32,
    pset_state_digest: [u8; 32],
    output_proof_binding: Option<OutputProofBinding<'static>>,
) -> RegistrationContext<'static> {
    RegistrationContext {
        profile: ProfileVersion::V1,
        network_identity: NETWORK,
        genesis_hash: GENESIS,
        lbtc_asset: asset(),
        round_id: ROUND,
        phase: Phase::Proofs,
        participant_role: role,
        contribution_ordinal: ordinal,
        kind,
        element_index,
        pset_state_digest,
        output_proof_binding,
    }
}

fn balance_context<'a>(
    role: ParticipantRole,
    ordinal: u32,
    pset_state_digest: [u8; 32],
    input_indices: &'a [u32],
    output_indices: &'a [u32],
    fee_share: u64,
) -> PartialBalanceContext<'a> {
    PartialBalanceContext {
        profile: ProfileVersion::V1,
        network_identity: NETWORK,
        genesis_hash: GENESIS,
        lbtc_asset: asset(),
        round_id: ROUND,
        phase: Phase::Proofs,
        participant_role: role,
        contribution_ordinal: ordinal,
        pset_state_digest,
        input_indices,
        output_indices,
        fee_share,
    }
}

// ---------------------------------------------------------------------------
// PSET builders.
//
// Two shapes share one round context:
//  * The BLINDING shape (explicit witness UTXOs) is the pre-registration
//    preblind revision the collaborative-blinding state machine accepts; it
//    drives op 1, op 4, op 5, op 6, and op 3.
//  * The CONFIDENTIAL shape (confidential witness UTXOs with asset-blind and
//    in-utxo range proofs) is the input-registration revision; it drives op 2,
//    whose statement requires a confidential witness UTXO.
//  * The BALANCE shape (explicit inputs, outputs blinded over the canonical
//    unblinded L-BTC generator) drives op 7. These historical books do not
//    balance per participant; C0 above covers the real composed lifecycle.
// ---------------------------------------------------------------------------

fn explicit_input(index: u8, value: u64) -> Input {
    let mut input = Input::from_prevout(OutPoint::new(
        Txid::from_byte_array([0x30 + index; 32]),
        u32::from(index),
    ));
    input.witness_utxo = Some(TxOut {
        asset: Asset::Explicit(asset()),
        value: Value::Explicit(value),
        nonce: Nonce::Null,
        script_pubkey: p2wpkh_script(index),
        witness: Default::default(),
    });
    input
}

fn confidential_input(
    secp: &Secp256k1<All>,
    rng: &mut StdRng,
    index: u8,
    value: u64,
    asset_bf: AssetBlindingFactor,
    value_bf: ValueBlindingFactor,
) -> Input {
    let generator = Generator::new_blinded(secp, asset().into_tag(), asset_bf.into_inner());
    let commitment = PedersenCommitment::new(secp, value, value_bf.into_inner(), generator);
    let mut input = Input::from_prevout(OutPoint::new(
        Txid::from_byte_array([0x30 + index; 32]),
        u32::from(index),
    ));
    input.witness_utxo = Some(TxOut {
        asset: Asset::Confidential(generator),
        value: Value::Confidential(commitment),
        nonce: Nonce::Confidential(blinding_key(7 + index).inner),
        script_pubkey: p2wpkh_script(index),
        witness: Default::default(),
    });
    input.asset = Some(asset());
    input.blind_asset_proof =
        Some(SurjectionProof::blind_asset_proof(rng, secp, asset(), asset_bf).unwrap());
    input.in_utxo_rangeproof = Some(
        RangeProof::new(
            secp,
            1,
            commitment,
            value,
            value_bf.into_inner(),
            &[],
            p2wpkh_script(index).as_bytes(),
            SecretKey::new(rng),
            0,
            52,
            generator,
        )
        .unwrap(),
    );
    input
}

fn preblind_output(index: u8, value: u64) -> Output {
    let mut output = Output::new_explicit(
        p2wpkh_script(0x40 + index),
        value,
        asset(),
        Some(blinding_key(3 + index)),
    );
    output.blinder_index = Some(u32::from(index));
    output
}

/// The preblind blinding revision: explicit witness UTXOs, two preblind
/// outputs, one explicit fee. Accepted by both `canonicalize_pset_state` and
/// `collab::UnblindedCoinJoin`.
fn build_preblind() -> PartiallySignedTransaction {
    let mut pset = PartiallySignedTransaction::new_v2();
    for (index, value) in INPUT_VALUES.iter().enumerate() {
        pset.add_input(explicit_input(index as u8, *value));
    }
    for (index, value) in OUTPUT_VALUES.iter().enumerate() {
        pset.add_output(preblind_output(index as u8, *value));
    }
    pset.add_output(Output::new_explicit(Script::new(), FEE, asset(), None));
    pset
}

/// The input-registration revision: confidential witness UTXOs over the same
/// outpoints and values, two preblind outputs, one explicit fee.
fn build_confidential(
    secp: &Secp256k1<All>,
    input_blindings: &[(AssetBlindingFactor, ValueBlindingFactor); 2],
) -> PartiallySignedTransaction {
    let mut rng = StdRng::seed_from_u64(SEED ^ 0xb000);
    let mut pset = PartiallySignedTransaction::new_v2();
    for (index, value) in INPUT_VALUES.iter().enumerate() {
        let (asset_bf, value_bf) = input_blindings[index];
        pset.add_input(confidential_input(
            secp,
            &mut rng,
            index as u8,
            *value,
            asset_bf,
            value_bf,
        ));
    }
    for (index, value) in OUTPUT_VALUES.iter().enumerate() {
        pset.add_output(preblind_output(index as u8, *value));
    }
    pset.add_output(Output::new_explicit(Script::new(), FEE, asset(), None));
    pset
}

// ---------------------------------------------------------------------------
// Wire framing helpers (test-side mirror of the frozen ABI layout).
// ---------------------------------------------------------------------------

fn field(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn frame(op: u32, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(16 + payload.len());
    out.extend_from_slice(&WLCJ_MAGIC_V1.to_be_bytes());
    out.extend_from_slice(&WLCJ_ABI_VERSION_V1.to_be_bytes());
    out.extend_from_slice(&op.to_be_bytes());
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

fn request(op: u32, fields: &[&[u8]]) -> Vec<u8> {
    let mut payload = Vec::new();
    for bytes in fields {
        field(&mut payload, bytes);
    }
    frame(op, &payload)
}

/// Executes one op through the exported entry point and returns the complete
/// response frame; asserts the two-call capacity protocol.
fn execute(request_frame: &[u8]) -> Vec<u8> {
    let mut required = 0u64;
    let status = unsafe {
        wlcj_execute_impl_v1(
            request_frame.as_ptr(),
            request_frame.len() as u64,
            ptr::null_mut(),
            0,
            &mut required,
        )
    };
    assert_eq!(status, WLCJ_STATUS_OUTPUT_CAPACITY_V1);
    assert!(required >= 16);
    let mut out = vec![0u8; usize::try_from(required).unwrap()];
    let mut written = 0u64;
    let status = unsafe {
        wlcj_execute_impl_v1(
            request_frame.as_ptr(),
            request_frame.len() as u64,
            out.as_mut_ptr(),
            out.len() as u64,
            &mut written,
        )
    };
    assert_eq!(status, WLCJ_STATUS_OK_V1);
    assert_eq!(written, required);
    out
}

/// Executes one op expecting a rejection; the published length must be 0 and
/// the caller's output buffer must be untouched.
fn execute_reject(request_frame: &[u8]) -> i32 {
    let mut required = 0xAAAA_AAAA_AAAA_AAAAu64;
    let mut out = vec![0xA5u8; 256];
    let status = unsafe {
        wlcj_execute_impl_v1(
            request_frame.as_ptr(),
            request_frame.len() as u64,
            out.as_mut_ptr(),
            out.len() as u64,
            &mut required,
        )
    };
    assert_ne!(status, WLCJ_STATUS_OK_V1);
    assert_ne!(status, WLCJ_STATUS_OUTPUT_CAPACITY_V1);
    assert_eq!(required, 0);
    assert!(out.iter().all(|byte| *byte == 0xA5));
    status
}

// ---------------------------------------------------------------------------
// Context field encoders (positional layouts frozen by the ABI parsers).
// ---------------------------------------------------------------------------

fn bounded(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn encode_context(phase: Phase, role: ParticipantRole, ordinal: u32) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(ProfileVersion::V1 as u8);
    bounded(&mut out, NETWORK);
    out.extend_from_slice(&GENESIS);
    out.extend_from_slice(&asset().to_byte_array());
    out.extend_from_slice(&asset().to_byte_array());
    bounded(&mut out, ROUND);
    out.push(phase as u8);
    out.push(role as u8);
    out.extend_from_slice(&ordinal.to_be_bytes());
    out.push(0); // predecessor absent
    out
}

fn encode_registration_context(
    kind: RegistrationKind,
    role: ParticipantRole,
    ordinal: u32,
    element_index: u32,
    digest: &[u8; 32],
) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(ProfileVersion::V1 as u8);
    bounded(&mut out, NETWORK);
    out.extend_from_slice(&GENESIS);
    out.extend_from_slice(&asset().to_byte_array());
    bounded(&mut out, ROUND);
    out.push(Phase::Proofs as u8);
    out.push(role as u8);
    out.extend_from_slice(&ordinal.to_be_bytes());
    out.push(kind as u8);
    out.extend_from_slice(&element_index.to_be_bytes());
    out.extend_from_slice(digest);
    out
}

fn encode_balance_context(
    role: ParticipantRole,
    ordinal: u32,
    digest: &[u8; 32],
    input_indices: &[u32],
    output_indices: &[u32],
    fee_share: u64,
) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(ProfileVersion::V1 as u8);
    bounded(&mut out, NETWORK);
    out.extend_from_slice(&GENESIS);
    out.extend_from_slice(&asset().to_byte_array());
    bounded(&mut out, ROUND);
    out.push(Phase::Proofs as u8);
    out.push(role as u8);
    out.extend_from_slice(&ordinal.to_be_bytes());
    out.extend_from_slice(digest);
    out.extend_from_slice(&(input_indices.len() as u32).to_be_bytes());
    for index in input_indices {
        out.extend_from_slice(&index.to_be_bytes());
    }
    out.extend_from_slice(&(output_indices.len() as u32).to_be_bytes());
    for index in output_indices {
        out.extend_from_slice(&index.to_be_bytes());
    }
    out.extend_from_slice(&fee_share.to_be_bytes());
    out
}

fn encode_role_map(map: &HashMap<usize, collab::Role>) -> Vec<u8> {
    let mut ordered: Vec<(usize, collab::Role)> = map.iter().map(|(i, r)| (*i, *r)).collect();
    ordered.sort_unstable_by_key(|(index, _)| *index);
    let mut out = Vec::new();
    out.extend_from_slice(&(ordered.len() as u32).to_be_bytes());
    for (index, role) in ordered {
        out.extend_from_slice(&(index as u32).to_be_bytes());
        out.push(match role {
            collab::Role::A => 1,
            collab::Role::B => 2,
        });
    }
    out
}

fn encode_secrets(secrets: &HashMap<usize, elements::TxOutSecrets>) -> Vec<u8> {
    let mut ordered: Vec<(usize, elements::TxOutSecrets)> =
        secrets.iter().map(|(i, s)| (*i, *s)).collect();
    ordered.sort_unstable_by_key(|(index, _)| *index);
    let mut out = Vec::new();
    for (index, secret) in ordered {
        out.extend_from_slice(&(index as u32).to_be_bytes());
        out.extend_from_slice(&secret.asset.to_byte_array());
        out.extend_from_slice(secret.asset_bf.into_inner().as_ref());
        out.extend_from_slice(&secret.value.to_be_bytes());
        out.extend_from_slice(secret.value_bf.into_inner().as_ref());
    }
    out
}

fn response_fields(response: &[u8]) -> Vec<&[u8]> {
    assert!(response.len() >= 16);
    assert_eq!(&response[0..4], &WLCJ_MAGIC_V1.to_be_bytes());
    assert_eq!(&response[4..8], &WLCJ_ABI_VERSION_V1.to_be_bytes());
    let payload_len = u32::from_be_bytes(response[12..16].try_into().unwrap()) as usize;
    assert_eq!(payload_len, response.len() - 16);
    match split_fields(&response[16..]) {
        Ok(fields) => fields,
        Err(_) => panic!("response payload splits into fields"),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn explicit_secrets() -> HashMap<usize, elements::TxOutSecrets> {
    explicit_secrets_for(&(0..INPUT_VALUES.len()).collect::<Vec<_>>(), &INPUT_VALUES)
}

fn explicit_secrets_for(
    indices: &[usize],
    values: &[u64],
) -> HashMap<usize, elements::TxOutSecrets> {
    let mut map = HashMap::new();
    for (pos, index) in indices.iter().enumerate() {
        map.insert(
            *index,
            elements::TxOutSecrets::new(
                asset(),
                AssetBlindingFactor::zero(),
                values[pos],
                ValueBlindingFactor::zero(),
            ),
        );
    }
    map
}

// ---------------------------------------------------------------------------
// The genuine two-participant round, driven end-to-end through the frozen ABI.
// ---------------------------------------------------------------------------

struct Round {
    preblind_bytes: Vec<u8>,
    preblind_digest: [u8; 32],
    final_bytes: Vec<u8>,
    final_digest: [u8; 32],
    intermediate_bytes: Vec<u8>,
    confidential_bytes: Vec<u8>,
    confidential_digest: [u8; 32],
    balance_bytes: Vec<u8>,
    balance_digest: [u8; 32],
    input_proof_a: [u8; 162],
    output_proof_a: [u8; 162],
    balance_proof_a: [u8; 65],
    balance_proof_b: [u8; 65],
    ma_in: [u8; 33],
    ma_out: [u8; 33],
    role_map_bytes: Vec<u8>,
    secrets_a_bytes: Vec<u8>,
    secrets_b_bytes: Vec<u8>,
}

fn build_round() -> Round {
    let secp = Secp256k1::new();
    let mut input_blindings = Vec::new();
    for tag in 0u8..2 {
        let mut rng = StdRng::seed_from_u64(SEED ^ 0xa000 ^ u64::from(tag));
        input_blindings.push((
            AssetBlindingFactor::new(&mut rng),
            ValueBlindingFactor::new(&mut rng),
        ));
    }
    let input_blindings: [(AssetBlindingFactor, ValueBlindingFactor); 2] =
        [input_blindings[0], input_blindings[1]];

    let preblind = build_preblind();
    let preblind_bytes = serialize(&preblind);
    let confidential = build_confidential(&secp, &input_blindings);
    let confidential_bytes = serialize(&confidential);

    // Op 1: canonicalize the preblind revision (Construction, Initiator, 1).
    let op1_response = execute(&request(
        WLCJ_OP_CANONICALIZE_STATE_V1,
        &[
            &preblind_bytes,
            &encode_context(Phase::Construction, ParticipantRole::Initiator, 1),
        ],
    ));
    let op1_fields = response_fields(&op1_response);
    assert_eq!(op1_fields.len(), 2);
    let preblind_digest: [u8; 32] = op1_fields[1].try_into().unwrap();
    let expected_preblind = canonicalize_pset_state(
        &preblind_bytes,
        &canonical_context(Phase::Construction, ParticipantRole::Initiator, 1),
    )
    .unwrap();
    assert_eq!(op1_fields[0], expected_preblind.canonical_bytes());
    assert_eq!(preblind_digest, expected_preblind.digest().into_bytes());

    // Canonicalize the confidential input-registration revision (Construction).
    let confidential_digest = canonicalize_pset_state(
        &confidential_bytes,
        &canonical_context(Phase::Construction, ParticipantRole::Initiator, 1),
    )
    .unwrap()
    .digest()
    .into_bytes();

    // Op 2: verify A's input registration (confidential witness UTXO 0).
    let r1_in = SecretKey::from_slice(&[0x51; 32]).unwrap();
    let r2_in = SecretKey::from_slice(input_blindings[0].1.into_inner().as_ref()).unwrap();
    let ma_in = credential_commitment(&secp, INPUT_VALUES[0], &r1_in);
    let statement_in = equality::input_registration_statement(
        &ma_in.serialize(),
        confidential.inputs()[0].witness_utxo.as_ref().unwrap(),
    )
    .unwrap();
    let witness_in = EqualityWitness::new(INPUT_VALUES[0], &r1_in, &r2_in).unwrap();
    let reg_context_in = registration_context(
        RegistrationKind::InputRegistration,
        ParticipantRole::Initiator,
        1,
        0,
        confidential_digest,
        None,
    );
    let proof_in = equality::prove_registration(
        &secp,
        &witness_in,
        &statement_in,
        &reg_context_in,
        &ENTROPY_PROVE_INPUT,
    )
    .unwrap();
    let input_proof_a = encode_equality_proof(&proof_in);
    let op2_response = execute(&request(
        WLCJ_OP_VERIFY_INPUT_REGISTRATION_V1,
        &[
            &confidential_bytes,
            &encode_registration_context(
                RegistrationKind::InputRegistration,
                ParticipantRole::Initiator,
                1,
                0,
                &confidential_digest,
            ),
            &input_proof_a,
            &ma_in.serialize(),
        ],
    ));
    assert_eq!(response_fields(&op2_response)[0], b"OK\0\0");

    // Op 4: A blinds non-last over the preblind revision.
    let role_map: HashMap<usize, collab::Role> =
        HashMap::from([(0usize, collab::Role::A), (1usize, collab::Role::B)]);
    let role_map_bytes = encode_role_map(&role_map);
    let all_secrets = explicit_secrets();
    let secrets_a: HashMap<usize, elements::TxOutSecrets> = all_secrets
        .iter()
        .filter(|(i, _)| **i == 0)
        .map(|(i, s)| (*i, *s))
        .collect();
    let secrets_a_bytes = encode_secrets(&secrets_a);
    let op4_response = execute(&request(
        WLCJ_OP_BLIND_NON_LAST_V1,
        &[
            &preblind_bytes,
            &role_map_bytes,
            &secrets_a_bytes,
            &ENTROPY_BLIND_A,
        ],
    ));
    let op4_fields = response_fields(&op4_response);
    assert_eq!(op4_fields.len(), 1);
    let intermediate_bytes = op4_fields[0].to_vec();
    let intermediate: PartiallySignedTransaction = deserialize(&intermediate_bytes).unwrap();
    assert!(!intermediate.global.scalars.is_empty());

    // Op 5: B blinds last; the response is the final blinded PSET.
    let secrets_b: HashMap<usize, elements::TxOutSecrets> = all_secrets
        .iter()
        .filter(|(i, _)| **i == 1)
        .map(|(i, s)| (*i, *s))
        .collect();
    let secrets_b_bytes = encode_secrets(&secrets_b);
    let op5_response = execute(&request(
        WLCJ_OP_BLIND_LAST_V1,
        &[
            &preblind_bytes,
            &role_map_bytes,
            &intermediate_bytes,
            &secrets_b_bytes,
            &ENTROPY_BLIND_B,
        ],
    ));
    let op5_fields = response_fields(&op5_response);
    assert_eq!(op5_fields.len(), 1);
    let final_bytes = op5_fields[0].to_vec();
    let final_pset: PartiallySignedTransaction = deserialize(&final_bytes).unwrap();
    assert!(final_pset.global.scalars.is_empty());

    // Recover A's output value blinding factor by replaying the same seeded
    // non-last blinding natively (the FFI deterministically reproduces it);
    // this feeds the output-registration witness (op 3).
    let mut rng_a = HashDrbg::new(&ENTROPY_BLIND_A);
    let mut replay = preblind.clone();
    let blinded_a = replay
        .blind_non_last_with_all_surjection_inputs(&mut rng_a, &secp, &secrets_a)
        .unwrap();
    let (_abf_a, vbf_a, _eph_a) = blinded_a
        .get(&CtLocation {
            input_index: 0,
            ty: CtLocationType::Input,
        })
        .copied()
        .unwrap();
    assert_eq!(serialize(&replay), intermediate_bytes);

    // Op 6: the final signer-view validation accepts and returns the digest.
    let op6_response = execute(&request(
        WLCJ_OP_VALIDATE_SIGNER_VIEW_V1,
        &[
            &final_bytes,
            &encode_context(Phase::PreSigning, ParticipantRole::Initiator, 1),
        ],
    ));
    let op6_fields = response_fields(&op6_response);
    assert_eq!(op6_fields.len(), 2);
    assert_eq!(op6_fields[0], b"OK\0\0");
    let final_digest: [u8; 32] = op6_fields[1].try_into().unwrap();
    let expected_final = canonicalize_pset_state(
        &final_bytes,
        &canonical_context(Phase::PreSigning, ParticipantRole::Initiator, 1),
    )
    .unwrap();
    assert_eq!(final_digest, expected_final.digest().into_bytes());

    // Op 3: verify A's output registration over blinded output 0.
    let r1_out = SecretKey::from_slice(&[0x61; 32]).unwrap();
    let r2_out = SecretKey::from_slice(vbf_a.into_inner().as_ref()).unwrap();
    let ma_out = credential_commitment(&secp, OUTPUT_VALUES[0], &r1_out);
    let statement_out =
        equality::output_registration_statement(&ma_out.serialize(), &final_pset, 0).unwrap();
    let witness_out = EqualityWitness::new(OUTPUT_VALUES[0], &r1_out, &r2_out).unwrap();
    let output = &final_pset.outputs()[0];
    let value_rangeproof = output.value_rangeproof.as_ref().unwrap().to_vec();
    let asset_surjection_proof = output.asset_surjection_proof.as_ref().unwrap().to_vec();
    let reg_context_out = registration_context(
        RegistrationKind::OutputRegistration,
        ParticipantRole::Initiator,
        1,
        0,
        final_digest,
        Some(OutputProofBinding {
            value_rangeproof: Box::leak(value_rangeproof.clone().into_boxed_slice()),
            asset_surjection_proof: Box::leak(asset_surjection_proof.clone().into_boxed_slice()),
        }),
    );
    let proof_out = equality::prove_registration(
        &secp,
        &witness_out,
        &statement_out,
        &reg_context_out,
        &ENTROPY_PROVE_OUTPUT,
    )
    .unwrap();
    let output_proof_a = encode_equality_proof(&proof_out);
    let op3_response = execute(&request(
        WLCJ_OP_VERIFY_OUTPUT_REGISTRATION_V1,
        &[
            &final_bytes,
            &encode_registration_context(
                RegistrationKind::OutputRegistration,
                ParticipantRole::Initiator,
                1,
                0,
                &final_digest,
            ),
            &output_proof_a,
            &ma_out.serialize(),
            &value_rangeproof,
            &asset_surjection_proof,
        ],
    ));
    assert_eq!(response_fields(&op3_response)[0], b"OK\0\0");

    // Legacy op-7 wire KAT only: different books/PSET, not composition credit.
    // C0 above instead uses r_eff = vbf + value*abf on the actual final PSET.
    let mut balance = PartiallySignedTransaction::new_v2();
    let balance_inputs = [OUTPUT_VALUES[0] + FEE_A, OUTPUT_VALUES[1] + FEE_B];
    balance.add_input(explicit_input(0, balance_inputs[0]));
    balance.add_input(explicit_input(1, balance_inputs[1]));
    let canonical_gen = Generator::new_unblinded(&secp, asset().into_tag());
    let mut balance_vbfs = Vec::new();
    for (index, output_value) in OUTPUT_VALUES.iter().enumerate() {
        let mut rng = StdRng::seed_from_u64(SEED ^ 0xc000 ^ (index as u64));
        let value_bf = ValueBlindingFactor::new(&mut rng);
        let commitment =
            PedersenCommitment::new(&secp, *output_value, value_bf.into_inner(), canonical_gen);
        let mut output = Output::new_explicit(
            p2wpkh_script(0x40 + index as u8),
            *output_value,
            asset(),
            None,
        );
        output.asset_comm = Some(canonical_gen);
        output.amount_comm = Some(commitment);
        balance.add_output(output);
        balance_vbfs.push(value_bf);
    }
    // No explicit fee output: the fee is the per-participant `fee_share` bound
    // in the context, which the verifier turns into fee·H_A directly.
    let balance_bytes = serialize(&balance);
    let balance_digest = Sha256::digest(&balance_bytes).into();
    let mut balance_proofs = Vec::new();
    for (role, ordinal, in_index, out_index, fee_share) in [
        (ParticipantRole::Initiator, 1u32, 0usize, 0usize, FEE_A),
        (ParticipantRole::Responder, 2u32, 1usize, 1usize, FEE_B),
    ] {
        let delta_r = SecretKey::from_slice(balance_vbfs[out_index].into_inner().as_ref())
            .unwrap()
            .negate();
        let in_indices = [in_index as u32];
        let out_indices = [out_index as u32];
        let context = balance_context(
            role,
            ordinal,
            balance_digest,
            &in_indices,
            &out_indices,
            fee_share,
        );
        let witness = PartialBalanceWitness::from_secret_key(&delta_r);
        let proof =
            prove_partial_balance(&secp, &balance, &context, &witness, &ENTROPY_PROVE_BALANCE)
                .unwrap();
        let proof_bytes = encode_partial_balance_proof(&proof);
        let response = execute(&request(
            WLCJ_OP_VERIFY_PARTIAL_BALANCE_V1,
            &[
                &balance_bytes,
                &encode_balance_context(
                    role,
                    ordinal,
                    &balance_digest,
                    &in_indices,
                    &out_indices,
                    fee_share,
                ),
                &proof_bytes,
            ],
        ));
        assert_eq!(response_fields(&response)[0], b"OK\0\0");
        balance_proofs.push(proof_bytes);
    }

    Round {
        preblind_bytes,
        preblind_digest,
        final_bytes,
        final_digest,
        intermediate_bytes,
        confidential_bytes,
        confidential_digest,
        balance_bytes,
        balance_digest,
        input_proof_a,
        output_proof_a,
        balance_proof_a: balance_proofs[0],
        balance_proof_b: balance_proofs[1],
        ma_in: ma_in.serialize(),
        ma_out: ma_out.serialize(),
        role_map_bytes,
        secrets_a_bytes,
        secrets_b_bytes,
    }
}

// ---------------------------------------------------------------------------
// Request builders for each op (used by the KAT, hostile, and leak tests).
// ---------------------------------------------------------------------------

fn op1_request(round: &Round) -> Vec<u8> {
    request(
        WLCJ_OP_CANONICALIZE_STATE_V1,
        &[
            &round.preblind_bytes,
            &encode_context(Phase::Construction, ParticipantRole::Initiator, 1),
        ],
    )
}

fn op2_request(round: &Round) -> Vec<u8> {
    request(
        WLCJ_OP_VERIFY_INPUT_REGISTRATION_V1,
        &[
            &round.confidential_bytes,
            &encode_registration_context(
                RegistrationKind::InputRegistration,
                ParticipantRole::Initiator,
                1,
                0,
                &round.confidential_digest,
            ),
            &round.input_proof_a,
            &round.ma_in,
        ],
    )
}

fn op4_request(round: &Round) -> Vec<u8> {
    request(
        WLCJ_OP_BLIND_NON_LAST_V1,
        &[
            &round.preblind_bytes,
            &round.role_map_bytes,
            &round.secrets_a_bytes,
            &ENTROPY_BLIND_A,
        ],
    )
}

fn op5_request(round: &Round) -> Vec<u8> {
    request(
        WLCJ_OP_BLIND_LAST_V1,
        &[
            &round.preblind_bytes,
            &round.role_map_bytes,
            &round.intermediate_bytes,
            &round.secrets_b_bytes,
            &ENTROPY_BLIND_B,
        ],
    )
}

fn op6_request(round: &Round) -> Vec<u8> {
    request(
        WLCJ_OP_VALIDATE_SIGNER_VIEW_V1,
        &[
            &round.final_bytes,
            &encode_context(Phase::PreSigning, ParticipantRole::Initiator, 1),
        ],
    )
}

fn op3_request(round: &Round) -> Vec<u8> {
    let final_pset: PartiallySignedTransaction = deserialize(&round.final_bytes).unwrap();
    let output = &final_pset.outputs()[0];
    let value_rangeproof = output.value_rangeproof.as_ref().unwrap().to_vec();
    let asset_surjection_proof = output.asset_surjection_proof.as_ref().unwrap().to_vec();
    request(
        WLCJ_OP_VERIFY_OUTPUT_REGISTRATION_V1,
        &[
            &round.final_bytes,
            &encode_registration_context(
                RegistrationKind::OutputRegistration,
                ParticipantRole::Initiator,
                1,
                0,
                &round.final_digest,
            ),
            &round.output_proof_a,
            &round.ma_out,
            &value_rangeproof,
            &asset_surjection_proof,
        ],
    )
}

fn op7_request(round: &Round, responder: bool) -> Vec<u8> {
    let (role, ordinal, in_index, out_index, fee_share, proof) = if responder {
        (
            ParticipantRole::Responder,
            2u32,
            1usize,
            1usize,
            FEE_B,
            &round.balance_proof_b,
        )
    } else {
        (
            ParticipantRole::Initiator,
            1u32,
            0usize,
            0usize,
            FEE_A,
            &round.balance_proof_a,
        )
    };
    request(
        WLCJ_OP_VERIFY_PARTIAL_BALANCE_V1,
        &[
            &round.balance_bytes,
            &encode_balance_context(
                role,
                ordinal,
                &round.balance_digest,
                &[in_index as u32],
                &[out_index as u32],
                fee_share,
            ),
            proof,
        ],
    )
}

// ---------------------------------------------------------------------------
// Pinned known-answer values (derived from the genuine round; regenerate only
// by re-deriving from a real run, never by hand).
// ---------------------------------------------------------------------------

mod kat {
    pub const PREBLIND_DIGEST: [u8; 32] = [
        0xdd, 0xef, 0xd8, 0xf2, 0x3e, 0xa4, 0x33, 0xf9, 0xa6, 0xc8, 0x04, 0x9a, 0x54, 0xf6, 0x60,
        0x53, 0x0f, 0xca, 0x40, 0xff, 0xf3, 0xc2, 0xc1, 0xcf, 0xef, 0x54, 0x21, 0xf2, 0xd8, 0x5c,
        0x72, 0x16,
    ];
    pub const FINAL_DIGEST: [u8; 32] = [
        0xc8, 0xdc, 0x56, 0xe7, 0xcb, 0xd5, 0x37, 0x58, 0x4c, 0x2e, 0x9d, 0xe9, 0x82, 0xe1, 0x16,
        0xfd, 0xc1, 0x07, 0x51, 0x9b, 0xaf, 0x51, 0x4a, 0x95, 0xb4, 0x4d, 0x0d, 0xc9, 0x5b, 0x89,
        0xd4, 0x59,
    ];
    pub const PREBLIND_SHA256: &str =
        "aeb70c16b7cae9ec4e7c65600b1ca6d6958b16a8c111fea5ed6f6b9b24404dae";
    pub const INTERMEDIATE_SHA256: &str =
        "0409d8678303f4188ea5e84cd5e65a5b79c06164d213aeef76eed0143a8fff8e";
    pub const FINAL_SHA256: &str =
        "9be308565a04c192347c97dc84137eb31e6ef12c6f9063bcdd0bb56f8107544b";
}

#[test]
fn e2e_two_participant_round_all_ops() {
    // The genuine round driven ENTIRELY through the FFI frames; every op
    // succeeds and returns the declared response shape.
    let round = build_round();
    assert_eq!(round.preblind_digest, kat::PREBLIND_DIGEST);
    assert_eq!(round.final_digest, kat::FINAL_DIGEST);
}

#[test]
fn wire_kat_pinned_bytes_per_op() {
    // Fixed request frames produce fixed response frames, pinned at the byte
    // level (digests, PSET handoffs, and verdicts).
    let round = build_round();
    assert_eq!(
        hex(&Sha256::digest(&round.preblind_bytes)),
        kat::PREBLIND_SHA256
    );
    assert_eq!(
        hex(&Sha256::digest(&round.intermediate_bytes)),
        kat::INTERMEDIATE_SHA256
    );
    assert_eq!(hex(&Sha256::digest(&round.final_bytes)), kat::FINAL_SHA256);
    assert_eq!(round.preblind_digest, kat::PREBLIND_DIGEST);
    assert_eq!(round.final_digest, kat::FINAL_DIGEST);
    // Verdict ops return the fixed 8-byte OK verdict field.
    let verdict = verdict_payload();
    for response in [
        execute(&op2_request(&round)),
        execute(&op3_request(&round)),
        execute(&op7_request(&round, false)),
        execute(&op7_request(&round, true)),
    ] {
        assert_eq!(response_fields(&response).len(), 1);
        assert_eq!(response_fields(&response)[0], &verdict[4..]);
        assert_eq!(response[16..].to_vec(), verdict);
    }
}

#[test]
fn determinism_identical_frames_identical_outputs() {
    let round = build_round();
    for request in [
        op1_request(&round),
        op2_request(&round),
        op3_request(&round),
        op4_request(&round),
        op5_request(&round),
        op6_request(&round),
        op7_request(&round, false),
        op7_request(&round, true),
    ] {
        assert_eq!(execute(&request), execute(&request));
    }
}

#[test]
fn hostile_malformed_frames_fail_closed() {
    let round = build_round();
    let good = op1_request(&round);
    // Wrong magic.
    let mut wrong_magic = good.clone();
    wrong_magic[0] ^= 0xFF;
    assert_eq!(execute_reject(&wrong_magic), WLCJ_STATUS_INVALID_FRAME_V1);
    // Wrong ABI version.
    let mut wrong_abi = good.clone();
    wrong_abi[7] = 0x02;
    assert_eq!(execute_reject(&wrong_abi), WLCJ_STATUS_UNSUPPORTED_ABI_V1);
    // Unknown op.
    let mut unknown_op = good.clone();
    unknown_op[11] = 0x7F;
    assert_eq!(execute_reject(&unknown_op), WLCJ_STATUS_UNKNOWN_OP_V1);
    // Truncated frame (payload_len claims more than supplied).
    let truncated = &good[..good.len() - 1];
    assert_eq!(execute_reject(truncated), WLCJ_STATUS_INVALID_FRAME_V1);
    // Trailing bytes (payload_len smaller than supplied).
    let mut trailing = good.clone();
    trailing.push(0x00);
    assert_eq!(execute_reject(&trailing), WLCJ_STATUS_INVALID_FRAME_V1);
    // Oversized payload (op 1 bound exceeded via a bloated declared length).
    let mut oversized = good.clone();
    let over = (OP_PAYLOAD_BOUNDS[0] + 1).to_be_bytes();
    oversized[12..16].copy_from_slice(&over);
    oversized.extend(std::iter::repeat_n(
        0u8,
        (OP_PAYLOAD_BOUNDS[0] + 1) as usize - (good.len() - 16),
    ));
    assert_eq!(execute_reject(&oversized), WLCJ_STATUS_PAYLOAD_TOO_LARGE_V1);
    // Empty frame.
    assert_eq!(execute_reject(&[]), WLCJ_STATUS_INVALID_FRAME_V1);
    // Short frame (header only, no payload).
    assert_eq!(execute_reject(&good[..16]), WLCJ_STATUS_INVALID_FRAME_V1);
}

#[test]
fn hostile_field_shape_failures_fail_closed() {
    let round = build_round();
    // Wrong field count for op 1 (one field instead of two).
    let mut one_field = Vec::new();
    field(&mut one_field, &round.preblind_bytes);
    let req = frame(WLCJ_OP_CANONICALIZE_STATE_V1, &one_field);
    assert_eq!(execute_reject(&req), WLCJ_STATUS_INVALID_FRAME_V1);
    // A field length that exceeds the per-field bound.
    let mut big_field = Vec::new();
    big_field.extend_from_slice(&(WLCJ_MAX_FIELD_BYTES_V1 + 1).to_be_bytes());
    big_field.extend_from_slice(&[0u8; 16]);
    let req = frame(WLCJ_OP_CANONICALIZE_STATE_V1, &big_field);
    assert_eq!(execute_reject(&req), WLCJ_STATUS_PAYLOAD_TOO_LARGE_V1);
    // Invalid context profile byte.
    let mut bad_ctx = encode_context(Phase::Construction, ParticipantRole::Initiator, 1);
    bad_ctx[0] = 0x7E;
    let req = request(
        WLCJ_OP_CANONICALIZE_STATE_V1,
        &[&round.preblind_bytes, &bad_ctx],
    );
    assert_eq!(execute_reject(&req), WLCJ_STATUS_VALIDATION_FAILED_V1);
    // Validation failure: garbage PSET bytes for op 1.
    let garbage = vec![0xDEu8; 64];
    let req = request(
        WLCJ_OP_CANONICALIZE_STATE_V1,
        &[
            &garbage,
            &encode_context(Phase::Construction, ParticipantRole::Initiator, 1),
        ],
    );
    assert_eq!(execute_reject(&req), WLCJ_STATUS_VALIDATION_FAILED_V1);
}

#[test]
fn no_secret_bytes_in_any_response() {
    // A witness supplied to a prove/blind op never appears in the response
    // frame bytes. The blinding entropy and the input secrets are witness-class.
    let round = build_round();
    for secret in [&ENTROPY_BLIND_A, &ENTROPY_BLIND_B] {
        for response in [execute(&op4_request(&round)), execute(&op5_request(&round))] {
            assert!(
                !windows_contains(&response, secret),
                "blinding entropy must never appear in a response frame"
            );
        }
    }
    // The input secret blinding factors are zero in this fixture (explicit
    // inputs), so the secret record's distinguishing bytes are the asset id and
    // values; assert the raw secret FIELD bytes are not echoed.
    for response in [execute(&op4_request(&round)), execute(&op5_request(&round))] {
        assert!(
            !windows_contains(&response, &round.secrets_a_bytes),
            "input secret records must never appear in a response frame"
        );
        assert!(
            !windows_contains(&response, &round.secrets_b_bytes),
            "input secret records must never appear in a response frame"
        );
    }
    // Grep-level: the response payloads carry only public projections, digests,
    // serialized handoffs, and verdicts — no 32-byte witness echoes.
    assert!(!windows_contains(
        &execute(&op4_request(&round)),
        &ENTROPY_BLIND_A
    ));
}

#[test]
fn c1_zero_blindings_and_scalar_boundaries() {
    let secp = Secp256k1::new();
    let gg = PublicKey::from_slice(&WABISABI_GG_BYTES).unwrap();
    let gh = PublicKey::from_slice(&WABISABI_GH_BYTES).unwrap();
    let mut one = [0; 32];
    one[31] = 1;
    let order = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36,
        0x41, 0x41,
    ];
    let maximum = wasabi_liquid_native_credential_commitment_equality::MAX_VALUE;
    for (value, r1, r2, ma) in [
        (1u64, [0u8; 32], [0u8; 32], gg),
        (0, one, one, gh),
        (
            maximum,
            [0u8; 32],
            one,
            gg.mul_tweak(&secp, &value_scalar(maximum)).unwrap(),
        ),
    ] {
        let generator = Generator::new_unblinded(&secp, asset().into_tag());
        let commitment = PedersenCommitment::new(
            &secp,
            value,
            ValueBlindingFactor::from_slice(&r2).unwrap().into_inner(),
            generator,
        );
        let mut pset = PartiallySignedTransaction::new_v2();
        let mut input = explicit_input(0, value);
        input.witness_utxo.as_mut().unwrap().asset = Asset::Confidential(generator);
        input.witness_utxo.as_mut().unwrap().value = Value::Confidential(commitment);
        pset.add_input(input);
        let context = encode_registration_context(
            RegistrationKind::InputRegistration,
            ParticipantRole::Initiator,
            1,
            0,
            &[0; 32],
        );
        let fields = vec![
            serialize(&pset),
            context,
            ma.serialize().to_vec(),
            value.to_be_bytes().to_vec(),
            r1.to_vec(),
            r2.to_vec(),
            vec![0; 32],
        ];
        let make_request = |f: &[Vec<u8>]| {
            request(
                WLCJ_OP_PROVE_INPUT_REGISTRATION_V1,
                &f.iter().map(Vec::as_slice).collect::<Vec<_>>(),
            )
        };
        let response = execute(&make_request(&fields));
        let proof = response_fields(&response)[0];
        execute(&request(
            WLCJ_OP_VERIFY_INPUT_REGISTRATION_V1,
            &[&fields[0], &fields[1], proof, &fields[2]],
        ));
        for field in [4, 5] {
            let mut invalid = fields.clone();
            invalid[field] = order.to_vec();
            assert_eq!(
                execute_reject(&make_request(&invalid)),
                WLCJ_STATUS_VALIDATION_FAILED_V1
            );
        }
        let mut invalid = fields.clone();
        invalid[3] = (maximum + 1).to_be_bytes().to_vec();
        assert_eq!(
            execute_reject(&make_request(&invalid)),
            WLCJ_STATUS_VALIDATION_FAILED_V1
        );
    }
}

fn windows_contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

#[test]
fn c1_registration_creation_and_hostiles() {
    let secp = Secp256k1::new();
    let blindings = [
        (
            AssetBlindingFactor::from_slice(&[0x21; 32]).unwrap(),
            ValueBlindingFactor::from_slice(&[0x31; 32]).unwrap(),
        ),
        (
            AssetBlindingFactor::from_slice(&[0x22; 32]).unwrap(),
            ValueBlindingFactor::from_slice(&[0x32; 32]).unwrap(),
        ),
    ];
    let preblind = build_confidential(&secp, &blindings);
    let roles = HashMap::from([(0, collab::Role::A), (1, collab::Role::B)]);
    let state = collab::UnblindedCoinJoin::new(preblind, &roles, asset()).unwrap();
    let secrets: Vec<_> = blindings
        .iter()
        .enumerate()
        .map(|(i, (abf, vbf))| {
            HashMap::from([(
                i,
                elements::TxOutSecrets::new(asset(), *abf, INPUT_VALUES[i], *vbf),
            )])
        })
        .collect();
    let intermediate = collab::participant_a_blind_non_last(
        &state,
        &mut HashDrbg::new(&ENTROPY_BLIND_A),
        &secrets[0],
    )
    .unwrap();
    let pset = collab::participant_b_blind_last(
        &state,
        &intermediate,
        &mut HashDrbg::new(&ENTROPY_BLIND_B),
        &secrets[1],
    )
    .unwrap();
    collab::verify_final(&state, &pset).unwrap();
    let pset_bytes = serialize(&pset);
    let digest = canonicalize_pset_state(
        &pset_bytes,
        &canonical_context(Phase::PreSigning, ParticipantRole::Initiator, 1),
    )
    .unwrap()
    .digest()
    .into_bytes();
    // Real recipient unblinding, never seeded blinding replay.
    let output = pset.extract_tx().unwrap().output[0]
        .unblind(&secp, SecretKey::from_slice(&[3; 32]).unwrap())
        .unwrap();
    for (kind, opening, prove_op, verify_op) in [
        (
            RegistrationKind::InputRegistration,
            secrets[0][&0],
            WLCJ_OP_PROVE_INPUT_REGISTRATION_V1,
            WLCJ_OP_VERIFY_INPUT_REGISTRATION_V1,
        ),
        (
            RegistrationKind::OutputRegistration,
            output,
            WLCJ_OP_PROVE_OUTPUT_REGISTRATION_V1,
            WLCJ_OP_VERIFY_OUTPUT_REGISTRATION_V1,
        ),
    ] {
        let r1 = SecretKey::from_slice(&[0x51; 32]).unwrap();
        let mut fields = vec![
            pset_bytes.clone(),
            encode_registration_context(kind, ParticipantRole::Initiator, 1, 0, &digest),
            credential_commitment(&secp, opening.value, &r1)
                .serialize()
                .to_vec(),
            opening.value.to_be_bytes().to_vec(),
            r1.secret_bytes().to_vec(),
            opening.value_bf.into_inner().as_ref().to_vec(),
            ENTROPY_PROVE_INPUT.to_vec(),
        ];
        if kind == RegistrationKind::OutputRegistration {
            fields.push(
                pset.outputs()[0]
                    .value_rangeproof
                    .as_ref()
                    .unwrap()
                    .to_vec(),
            );
            fields.push(
                pset.outputs()[0]
                    .asset_surjection_proof
                    .as_ref()
                    .unwrap()
                    .to_vec(),
            );
        }
        let make_request = |fields: &[Vec<u8>]| {
            request(
                prove_op,
                &fields.iter().map(Vec::as_slice).collect::<Vec<_>>(),
            )
        };
        let response = execute(&make_request(&fields));
        assert_eq!(response.len(), 182);
        assert_eq!(&response[8..12], &prove_op.to_be_bytes());
        let proof_fields = response_fields(&response);
        assert_eq!(proof_fields.len(), 1);
        assert_eq!(proof_fields[0].len(), 162);
        for secret in &fields[3..7] {
            assert!(!windows_contains(&response, secret));
        }
        assert_eq!(execute(&make_request(&fields)), response);
        let mut verification = vec![
            fields[0].clone(),
            fields[1].clone(),
            proof_fields[0].to_vec(),
            fields[2].clone(),
        ];
        verification.extend_from_slice(&fields[7..]);
        let verify_request = |fields: &[Vec<u8>]| {
            request(
                verify_op,
                &fields.iter().map(Vec::as_slice).collect::<Vec<_>>(),
            )
        };
        assert_eq!(
            response_fields(&execute(&verify_request(&verification)))[0],
            b"OK\0\0"
        );
        // Optional synthetic fixtures for the real dylib loader test.
        if let Some(directory) = std::env::var_os("WLCJ_C1_FIXTURE_DIR") {
            let directory = std::path::PathBuf::from(directory);
            std::fs::write(
                directory.join(format!("op{prove_op}.request")),
                make_request(&fields),
            )
            .unwrap();
            std::fs::write(directory.join(format!("op{prove_op}.response")), &response).unwrap();
            std::fs::write(
                directory.join(format!("op{verify_op}.request")),
                verify_request(&verification),
            )
            .unwrap();
        }

        // Wrong witness values and even valid-but-unrelated Ma must not escape.
        for field in 2..6 {
            let mut changed = fields.clone();
            if field == 2 {
                changed[2] = credential_commitment(&secp, opening.value + 1, &r1)
                    .serialize()
                    .to_vec();
            } else {
                let last = changed[field].len() - 1;
                changed[field][last] ^= 1;
            }
            assert_eq!(
                execute_reject(&make_request(&changed)),
                WLCJ_STATUS_VERIFICATION_FAILED_V1
            );
        }
        for field in [2, 3, 4, 5] {
            let mut changed = fields.clone();
            changed[field].fill(0xff);
            assert_eq!(
                execute_reject(&make_request(&changed)),
                WLCJ_STATUS_VALIDATION_FAILED_V1
            );
        }
        // Exact field lengths, count, framing and per-op payload limits.
        for field in 0..fields.len() {
            for extra in [false, true] {
                let mut changed = fields.clone();
                if extra {
                    changed[field].push(0);
                } else {
                    changed[field].pop();
                }
                execute_reject(&make_request(&changed));
            }
        }
        let mut extra = fields.clone();
        extra.push(vec![]);
        assert_eq!(
            execute_reject(&make_request(&extra)),
            WLCJ_STATUS_INVALID_FRAME_V1
        );
        assert_eq!(
            execute_reject(&make_request(&fields[..fields.len() - 1])),
            WLCJ_STATUS_INVALID_FRAME_V1
        );
        let mut oversized = make_request(&fields);
        let size = OP_PAYLOAD_BOUNDS[prove_op as usize - 1] + 1;
        oversized.resize(16 + size as usize, 0);
        oversized[12..16].copy_from_slice(&size.to_be_bytes());
        assert_eq!(execute_reject(&oversized), WLCJ_STATUS_PAYLOAD_TOO_LARGE_V1);

        let context_len = fields[1].len();
        for offset in [0, context_len - 43, context_len - 42, context_len - 37] {
            let mut changed = fields.clone();
            changed[1][offset] = 0xff;
            assert_eq!(
                execute_reject(&make_request(&changed)),
                WLCJ_STATUS_VALIDATION_FAILED_V1
            );
        }
        let mut wrong_kind = fields.clone();
        wrong_kind[1][context_len - 37] = if kind == RegistrationKind::InputRegistration {
            2
        } else {
            1
        };
        assert_eq!(
            execute_reject(&make_request(&wrong_kind)),
            WLCJ_STATUS_VALIDATION_FAILED_V1
        );
        let mut wrong_index = fields.clone();
        wrong_index[1][context_len - 36..context_len - 32].copy_from_slice(&99u32.to_be_bytes());
        assert_eq!(
            execute_reject(&make_request(&wrong_index)),
            WLCJ_STATUS_VALIDATION_FAILED_V1
        );
        wrong_index[1][context_len - 36..context_len - 32].copy_from_slice(&1u32.to_be_bytes());
        assert_eq!(
            execute_reject(&make_request(&wrong_index)),
            if kind == RegistrationKind::InputRegistration {
                WLCJ_STATUS_VERIFICATION_FAILED_V1
            } else {
                WLCJ_STATUS_VALIDATION_FAILED_V1 // indexed output has different proof bytes
            }
        );

        // Arbitrary digest/round/role/ordinal are accepted caller context, but a
        // proof made under one context cannot verify under a different one.
        for offset in [context_len - 1, 5, context_len - 38, context_len - 42] {
            let mut changed = fields.clone();
            changed[1][offset] ^= if offset == context_len - 42 { 3 } else { 1 };
            let other_response = execute(&make_request(&changed));
            let other_proof = response_fields(&other_response)[0];
            assert_ne!(other_proof, proof_fields[0]);
            let mut wrong_context = verification.clone();
            wrong_context[1] = changed[1].clone();
            assert_eq!(
                execute_reject(&verify_request(&wrong_context)),
                WLCJ_STATUS_VERIFICATION_FAILED_V1
            );
            wrong_context[2] = other_proof.to_vec();
            execute(&verify_request(&wrong_context));
        }
        let mut other_entropy = fields.clone();
        other_entropy[6][0] ^= 1;
        let other_response = execute(&make_request(&other_entropy));
        assert_ne!(other_response, response);
        let mut other_verification = verification.clone();
        other_verification[2] = response_fields(&other_response)[0].to_vec();
        execute(&verify_request(&other_verification));

        let mut changed_pset = pset.clone();
        match kind {
            RegistrationKind::InputRegistration => {
                changed_pset.inputs_mut()[0].witness_utxo = pset.inputs()[1].witness_utxo.clone();
            }
            RegistrationKind::OutputRegistration => {
                changed_pset.outputs_mut()[0].amount_comm = pset.outputs()[1].amount_comm;
            }
        }
        let mut changed = fields.clone();
        changed[0] = serialize(&changed_pset);
        assert_eq!(
            execute_reject(&make_request(&changed)),
            WLCJ_STATUS_VERIFICATION_FAILED_V1
        );
        let mut changed_verification = verification.clone();
        changed_verification[0] = changed[0].clone();
        assert_eq!(
            execute_reject(&verify_request(&changed_verification)),
            WLCJ_STATUS_VERIFICATION_FAILED_V1
        );
        if kind == RegistrationKind::OutputRegistration {
            for field in [7, 8] {
                let mut changed = fields.clone();
                changed[field][0] ^= 1;
                assert_eq!(
                    execute_reject(&make_request(&changed)),
                    WLCJ_STATUS_VALIDATION_FAILED_V1
                );
                let mut changed_verification = verification.clone();
                changed_verification[field - 3] = changed[field].clone();
                assert_eq!(
                    execute_reject(&verify_request(&changed_verification)),
                    WLCJ_STATUS_VERIFICATION_FAILED_V1
                );
                let mut changed_pset = pset.clone();
                if field == 7 {
                    changed_pset.outputs_mut()[0].value_rangeproof =
                        pset.outputs()[1].value_rangeproof.clone();
                } else {
                    changed_pset.outputs_mut()[0].asset_surjection_proof =
                        pset.outputs()[1].asset_surjection_proof.clone();
                }
                changed[0] = serialize(&changed_pset);
                changed[field] = fields[field].clone();
                assert_eq!(
                    execute_reject(&make_request(&changed)),
                    WLCJ_STATUS_VALIDATION_FAILED_V1
                );
            }
        }
    }
}
