use super::*;
use elements::{
    AssetId, OutPoint, Script,
    bitcoin::PublicKey,
    confidential::{AssetBlindingFactor, ValueBlindingFactor},
    pset::{Input, Output},
    secp256k1_zkp::SecretKey,
};
use rand::{SeedableRng, rngs::StdRng};
use wasabi_liquid_native_coinjoin_pset_state::{
    ParticipantRole, Phase, PredecessorDigest, ProfileVersion,
};

const NETWORK: &[u8] = b"elements-liquid-mainnet";
const ROUND: &[u8] = b"round-collab-0001";
const SEED: u64 = 0x5eed_5eed_c0de_0001;

fn asset() -> AssetId {
    AssetId::from_byte_array([0x11; 32])
}

fn context() -> CanonicalStateContext<'static> {
    CanonicalStateContext {
        profile: ProfileVersion::V1,
        network_identity: NETWORK,
        genesis_hash: [0x22; 32],
        lbtc_asset: asset(),
        fee_asset: asset(),
        round_id: ROUND,
        phase: Phase::PreSigning,
        participant_role: ParticipantRole::Initiator,
        contribution_ordinal: 1,
        predecessor: PredecessorDigest::Absent,
    }
}

fn blinding_key(byte: u8) -> PublicKey {
    let secp = Secp256k1::new();
    PublicKey::new(
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

struct Fixture {
    pset: PartiallySignedTransaction,
    role_of_output: HashMap<usize, Role>,
    secrets_a: HashMap<usize, elements::TxOutSecrets>,
    secrets_b: HashMap<usize, elements::TxOutSecrets>,
}

/// Two inputs (A contributes input 0, B contributes input 1), two confidential
/// outputs (output 0 blinded by A, output 1 blinded by B), one explicit fee.
fn two_input_fixture() -> Fixture {
    explicit_fixture(
        &[(0, 5_000), (1, 4_000)],
        &[(0, Role::A, 3_500, 0), (1, Role::B, 4_400, 1)],
        1_100,
    )
}

/// Three inputs (A contributes input 0, B contributes inputs 1 and 2): proves
/// the surjection domain is the FULL ordered input set, not one participant's.
fn three_input_fixture() -> Fixture {
    explicit_fixture(
        &[(0, 5_000), (1, 4_000), (2, 3_000)],
        &[(0, Role::A, 4_500, 0), (1, Role::B, 7_300, 1)],
        200,
    )
}

fn explicit_fixture(
    inputs: &[(u8, u64)],
    outputs: &[(usize, Role, u64, u32)],
    fee: u64,
) -> Fixture {
    let mut pset = PartiallySignedTransaction::new_v2();
    for (tag, value) in inputs {
        let mut input = Input::from_prevout(OutPoint::new(
            Txid::from_byte_array([0x30 + tag; 32]),
            u32::from(*tag),
        ));
        input.witness_utxo = Some(TxOut {
            asset: Asset::Explicit(asset()),
            value: Value::Explicit(*value),
            nonce: Nonce::Null,
            script_pubkey: p2wpkh_script(*tag),
            witness: Default::default(),
        });
        pset.add_input(input);
    }
    let mut role_of_output = HashMap::new();
    for (index, role, value, blinder) in outputs {
        let mut output = Output::new_explicit(
            p2wpkh_script(0x40 + *index as u8),
            *value,
            asset(),
            Some(blinding_key(3 + *index as u8)),
        );
        output.blinder_index = Some(*blinder);
        pset.add_output(output);
        role_of_output.insert(*index, *role);
    }
    pset.add_output(Output::new_explicit(Script::new(), fee, asset(), None));

    let secrets = |indices: &[u8]| -> HashMap<usize, elements::TxOutSecrets> {
        inputs
            .iter()
            .enumerate()
            .filter(|(_, (tag, _))| indices.contains(tag))
            .map(|(index, (_, value))| {
                (
                    index,
                    elements::TxOutSecrets::new(
                        asset(),
                        AssetBlindingFactor::zero(),
                        *value,
                        ValueBlindingFactor::zero(),
                    ),
                )
            })
            .collect()
    };
    Fixture {
        pset,
        role_of_output,
        secrets_a: secrets(&[0]),
        secrets_b: if inputs.len() == 2 {
            secrets(&[1])
        } else {
            secrets(&[1, 2])
        },
    }
}

fn state(fixture: &Fixture) -> UnblindedCoinJoin {
    UnblindedCoinJoin::new(fixture.pset.clone(), &fixture.role_of_output, asset()).unwrap()
}

/// The six-step real acceptance path: A blinds non-last, scalars cross the
/// trust boundary byte-exactly, B blinds last, scalars clear, every surjection
/// proof commits the full ordered input domain, and the result balances.
fn run_real_path(fixture: &Fixture) -> (Vec<u8>, PartiallySignedTransaction) {
    let state = state(fixture);

    // Step 1: participant A calls blind_non_last_with_all_surjection_inputs.
    let mut rng_a = StdRng::seed_from_u64(SEED);
    let intermediate = participant_a_blind_non_last(&state, &mut rng_a, &fixture.secrets_a)
        .expect("participant A non-last blinding must succeed");

    // Step 2: non-empty global.scalars survive serialization/parsing byte-exactly.
    let parsed = deserialize_handoff(&intermediate).expect("intermediate must parse canonically");
    assert!(!parsed.global.scalars.is_empty());
    assert_eq!(serialize_handoff(&parsed), intermediate);

    // Step 3: participant B calls blind_last_with_all_surjection_inputs on the
    // decoded intermediate (no shared in-memory object).
    let mut rng_b = StdRng::seed_from_u64(SEED ^ 0x00ff);
    let final_pset =
        participant_b_blind_last(&state, &intermediate, &mut rng_b, &fixture.secrets_b)
            .expect("participant B last blinding must succeed");

    // Step 4: scalars clear only after success.
    assert!(final_pset.global.scalars.is_empty());

    // Step 5 (surfaced inside step 3): every surjection proof commits the full
    // ordered input domain; assert the observable shape.
    let input_count = state.pset().inputs().len();
    for &index in state.expected_confidential_outputs() {
        let proof = final_pset.outputs()[index]
            .asset_surjection_proof
            .as_ref()
            .expect("confidential output carries a surjection proof");
        assert_eq!(proof.input_count(), input_count);
        assert!(proof.uses_all_inputs());
    }

    // Balance: extract_tx + verify_tx_amt_proofs against the real witness UTXOs.
    verify_final(&state, &final_pset).expect("final blinded PSET must balance");
    (intermediate, final_pset)
}

#[test]
fn two_participant_real_path_six_acceptance_steps() {
    let fixture = two_input_fixture();
    let (intermediate, final_pset) = run_real_path(&fixture);
    let canonical = canonical_accept_final(&final_pset, &context())
        .expect("final blinded PSET must be canonical");
    assert!(!canonical.canonical_bytes().is_empty());
    // The genuine mid-lifecycle state is honestly partially-blinded; a partial
    // state that claims to be final (every output fully blinded, scalars still
    // pending) is cryptographically non-canonical and must be rejected.
    let partial_as_final = fabricate_partial_claiming_final(&intermediate);
    canonical_reject_partial(&partial_as_final, &context())
        .expect("scalar-bearing state claiming final blinding must be rejected canonically");
}

/// Builds a scalar-bearing state that masquerades as final: every non-fee
/// output claims full blinding by reusing participant A's committed fields.
/// The copied surjection/range proofs cannot verify for participant B's output
/// against the full ordered input domain, so the canonical validator rejects.
fn fabricate_partial_claiming_final(intermediate: &[u8]) -> Vec<u8> {
    let mut pset = deserialize_handoff(intermediate).unwrap();
    assert!(!pset.global.scalars.is_empty());
    let source = pset.outputs()[0].clone();
    for output in pset.outputs_mut().iter_mut() {
        if output.blinding_key.is_some() && output.asset_surjection_proof.is_none() {
            output.asset_comm = source.asset_comm;
            output.amount_comm = source.amount_comm;
            output.ecdh_pubkey = source.ecdh_pubkey;
            output.value_rangeproof = source.value_rangeproof.clone();
            output.asset_surjection_proof = source.asset_surjection_proof.clone();
            output.blind_value_proof = source.blind_value_proof.clone();
            output.blind_asset_proof = source.blind_asset_proof.clone();
        }
    }
    serialize_handoff(&pset)
}

#[test]
fn three_input_full_ordered_domain_two_participant() {
    let fixture = three_input_fixture();
    let state = state(&fixture);
    let (_, final_pset) = run_real_path(&fixture);
    // B blinds with secrets for inputs 1 and 2 only; the surjection proofs must
    // still cover input 0 (A's input): the domain is the full input set.
    for &index in state.expected_confidential_outputs() {
        let proof = final_pset.outputs()[index]
            .asset_surjection_proof
            .as_ref()
            .unwrap();
        assert_eq!(proof.input_count(), 3);
        assert!(proof.uses_all_inputs());
    }
}

#[test]
fn seeded_rerun_produces_identical_bytes_and_canonical_digest() {
    let fixture = two_input_fixture();
    let (first_intermediate, first_final) = run_real_path(&fixture);
    let (second_intermediate, second_final) = run_real_path(&fixture);
    assert_eq!(first_intermediate, second_intermediate);
    assert_eq!(
        crate::serialize_handoff(&first_final),
        crate::serialize_handoff(&second_final)
    );
    let first_digest = canonical_accept_final(&first_final, &context())
        .unwrap()
        .digest();
    let second_digest = canonical_accept_final(&second_final, &context())
        .unwrap()
        .digest();
    assert_eq!(first_digest, second_digest);
}

#[test]
fn add_input_after_step1_fails_step3() {
    let fixture = two_input_fixture();
    let state = state(&fixture);
    let mut rng_a = StdRng::seed_from_u64(SEED);
    let intermediate =
        participant_a_blind_non_last(&state, &mut rng_a, &fixture.secrets_a).unwrap();
    let mut mutated = deserialize_handoff(&intermediate).unwrap();
    let mut input = Input::from_prevout(OutPoint::new(Txid::from_byte_array([0x77; 32]), 9));
    input.witness_utxo = Some(TxOut {
        asset: Asset::Explicit(asset()),
        value: Value::Explicit(1_000),
        nonce: Nonce::Null,
        script_pubkey: p2wpkh_script(0x77),
        witness: Default::default(),
    });
    mutated.add_input(input);
    let bytes = serialize_handoff(&mutated);
    let mut rng_b = StdRng::seed_from_u64(SEED ^ 0x00ff);
    assert_eq!(
        participant_b_blind_last(&state, &bytes, &mut rng_b, &fixture.secrets_b),
        Err(Error::DomainMutationRejected)
    );
}

#[test]
fn remove_input_after_step1_fails_step3() {
    let fixture = two_input_fixture();
    let state = state(&fixture);
    let mut rng_a = StdRng::seed_from_u64(SEED);
    let intermediate =
        participant_a_blind_non_last(&state, &mut rng_a, &fixture.secrets_a).unwrap();
    let mutated = deserialize_handoff(&intermediate).unwrap();
    // Rebuild the PSET with the first input removed, encoding the global map
    // manually so the declared input count matches the removed input (the
    // public Global API cannot rewrite the count directly).
    let bytes = serialize_without_first_input(&mutated);
    let reparsed = deserialize_handoff(&bytes).expect("rebuilt PSET must stay canonical");
    assert_eq!(reparsed.inputs().len(), mutated.inputs().len() - 1);
    let mut rng_b = StdRng::seed_from_u64(SEED ^ 0x00ff);
    assert_eq!(
        participant_b_blind_last(&state, &bytes, &mut rng_b, &fixture.secrets_b),
        Err(Error::DomainMutationRejected)
    );
}

/// Serializes `pset` with its first input removed and the global input count
/// decremented, matching the pinned fork's canonical global key ordering.
fn serialize_without_first_input(pset: &PartiallySignedTransaction) -> Vec<u8> {
    use elements::encode::Encodable;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"pset");
    bytes.push(0xff);
    // Fork's global map in BIP-174 key order: 0x02 tx version, 0x04 input
    // count, 0x05 output count, 0xfb PSET version, then one 0xfc proprietary
    // key per scalar ("pset" prefix, subtype 0x00, 32-byte key, empty value).
    let push_pair = |bytes: &mut Vec<u8>, key: &[u8], value: &[u8]| {
        bytes.push(u8::try_from(key.len()).unwrap());
        bytes.extend_from_slice(key);
        bytes.push(u8::try_from(value.len()).unwrap());
        bytes.extend_from_slice(value);
    };
    push_pair(&mut bytes, &[0x02], &2u32.to_le_bytes());
    push_pair(&mut bytes, &[0x04], &[(pset.inputs().len() - 1) as u8]);
    push_pair(&mut bytes, &[0x05], &[pset.outputs().len() as u8]);
    push_pair(&mut bytes, &[0xfb], &2u32.to_le_bytes());
    for scalar in &pset.global.scalars {
        let mut key = vec![0xfc, 0x04];
        key.extend_from_slice(b"pset");
        key.push(0x00); // PSBT_ELEMENTS_GLOBAL_SCALAR subtype
        key.extend_from_slice(scalar.as_ref());
        push_pair(&mut bytes, &key, &[]);
    }
    bytes.push(0x00);
    for input in pset.inputs().iter().skip(1) {
        input
            .consensus_encode(&mut bytes)
            .expect("encoding to Vec cannot fail");
    }
    for output in pset.outputs() {
        output
            .consensus_encode(&mut bytes)
            .expect("encoding to Vec cannot fail");
    }
    bytes
}

#[test]
fn witness_utxo_asset_mutation_after_step1_fails_step3() {
    let fixture = two_input_fixture();
    let state = state(&fixture);
    let mut rng_a = StdRng::seed_from_u64(SEED);
    let intermediate =
        participant_a_blind_non_last(&state, &mut rng_a, &fixture.secrets_a).unwrap();
    let mut mutated = deserialize_handoff(&intermediate).unwrap();
    // Mutating the witness-UTXO asset is a byte mutation of the frozen witness
    // set; the wrapper's identity binding rejects before any blinding call.
    let utxo = mutated.inputs_mut()[0].witness_utxo.as_mut().unwrap();
    utxo.asset = Asset::Explicit(AssetId::from_byte_array([0x99; 32]));
    let bytes = serialize_handoff(&mutated);
    let mut rng_b = StdRng::seed_from_u64(SEED ^ 0x00ff);
    assert_eq!(
        participant_b_blind_last(&state, &bytes, &mut rng_b, &fixture.secrets_b),
        Err(Error::DomainMutationRejected)
    );
}

#[test]
fn same_count_outpoint_swap_after_step1_fails_step3() {
    // A same-count input swap keeps input_count and n_inputs intact, so only
    // the wrapper's identity binding (txid + vout + witness bytes versus the
    // frozen state) catches it — the fork's count-based checks cannot.
    let fixture = two_input_fixture();
    let state = state(&fixture);
    let mut rng_a = StdRng::seed_from_u64(SEED);
    let intermediate =
        participant_a_blind_non_last(&state, &mut rng_a, &fixture.secrets_a).unwrap();
    let mut mutated = deserialize_handoff(&intermediate).unwrap();
    let mut swapped = Input::from_prevout(OutPoint::new(
        Txid::from_byte_array([0x42; 32]),
        mutated.inputs()[0].previous_output_index,
    ));
    swapped.witness_utxo = mutated.inputs()[0].witness_utxo.clone();
    mutated.inputs_mut()[0] = swapped;
    let bytes = serialize_handoff(&mutated);
    let mut rng_b = StdRng::seed_from_u64(SEED ^ 0x00ff);
    assert_eq!(
        participant_b_blind_last(&state, &bytes, &mut rng_b, &fixture.secrets_b),
        Err(Error::DomainMutationRejected)
    );
}

#[test]
fn witness_utxo_value_mutation_after_step1_fails_step3() {
    // Mutating any witness-UTXO value the last blinder must trust is a witness
    // commitment mutation; the wrapper rejects it before any blinding call.
    let fixture = two_input_fixture();
    let state = state(&fixture);
    let mut rng_a = StdRng::seed_from_u64(SEED);
    let intermediate =
        participant_a_blind_non_last(&state, &mut rng_a, &fixture.secrets_a).unwrap();
    let mut mutated = deserialize_handoff(&intermediate).unwrap();
    let original_value = match mutated.inputs()[0].witness_utxo.as_ref().unwrap().value {
        Value::Explicit(value) => value,
        _ => unreachable!("fixture inputs are explicit"),
    };
    mutated.inputs_mut()[0].witness_utxo.as_mut().unwrap().value =
        Value::Explicit(original_value - 1);
    let bytes = serialize_handoff(&mutated);
    // B must blind output 0 (blinder_index 0 → input 0), so B's secrets cover
    // the mutated input 0; the mutated UTXO no longer matches those secrets.
    let mut secrets_b = fixture.secrets_b.clone();
    secrets_b.insert(
        0,
        elements::TxOutSecrets::new(
            asset(),
            AssetBlindingFactor::zero(),
            original_value,
            ValueBlindingFactor::zero(),
        ),
    );
    let mut rng_b = StdRng::seed_from_u64(SEED ^ 0x00ff);
    assert_eq!(
        participant_b_blind_last(&state, &bytes, &mut rng_b, &secrets_b),
        Err(Error::DomainMutationRejected)
    );
}

#[test]
fn final_pset_canonical_accept_and_partial_canonical_reject() {
    let fixture = two_input_fixture();
    let (intermediate, final_pset) = run_real_path(&fixture);
    canonical_accept_final(&final_pset, &context()).unwrap();
    canonical_reject_partial(&fabricate_partial_claiming_final(&intermediate), &context()).unwrap();
}

#[test]
fn scalars_asserted_empty_after_step3() {
    let fixture = two_input_fixture();
    let state = state(&fixture);
    let mut rng_a = StdRng::seed_from_u64(SEED);
    let intermediate =
        participant_a_blind_non_last(&state, &mut rng_a, &fixture.secrets_a).unwrap();
    let mut rng_b = StdRng::seed_from_u64(SEED ^ 0x00ff);
    let final_pset =
        participant_b_blind_last(&state, &intermediate, &mut rng_b, &fixture.secrets_b).unwrap();
    assert!(final_pset.global.scalars.is_empty());
}

#[test]
fn unblinded_shape_rejects_non_lbtc_asset() {
    let fixture = two_input_fixture();
    let mut pset = fixture.pset.clone();
    pset.outputs_mut()[0].asset = Some(AssetId::from_byte_array([0x99; 32]));
    assert!(matches!(
        UnblindedCoinJoin::new(pset, &fixture.role_of_output, asset()),
        Err(Error::UnblindedShapeInvalid)
    ));
}

#[test]
fn unblinded_shape_rejects_missing_blinder_index_and_extra_fee() {
    let fixture = two_input_fixture();
    let mut missing = fixture.pset.clone();
    missing.outputs_mut()[0].blinder_index = None;
    assert!(matches!(
        UnblindedCoinJoin::new(missing, &fixture.role_of_output, asset()),
        Err(Error::UnblindedShapeInvalid)
    ));
    let mut extra_fee = fixture.pset.clone();
    extra_fee.add_output(Output::new_explicit(Script::new(), 50, asset(), None));
    assert!(matches!(
        UnblindedCoinJoin::new(extra_fee, &fixture.role_of_output, asset()),
        Err(Error::UnblindedShapeInvalid)
    ));
}

#[test]
fn unblinded_shape_rejects_issuance_and_pegin_inputs() {
    let fixture = two_input_fixture();
    let mut issuance = fixture.pset.clone();
    issuance.inputs_mut()[0].issuance_value_amount = Some(1_000);
    assert!(matches!(
        UnblindedCoinJoin::new(issuance, &fixture.role_of_output, asset()),
        Err(Error::UnblindedShapeInvalid)
    ));
    let mut pegin = fixture.pset.clone();
    pegin.inputs_mut()[0].previous_output_index |= 1 << 30;
    assert!(matches!(
        UnblindedCoinJoin::new(pegin, &fixture.role_of_output, asset()),
        Err(Error::UnblindedShapeInvalid)
    ));
}

#[test]
fn verify_final_rejects_residual_scalars() {
    let fixture = two_input_fixture();
    let state = state(&fixture);
    let mut rng_a = StdRng::seed_from_u64(SEED);
    let intermediate =
        participant_a_blind_non_last(&state, &mut rng_a, &fixture.secrets_a).unwrap();
    let partial = deserialize_handoff(&intermediate).unwrap();
    assert_eq!(
        verify_final(&state, &partial),
        Err(Error::ScalarsNotCleared)
    );
}

#[test]
fn canonical_projection_digest_kat() {
    let fixture = two_input_fixture();
    let (_, final_pset) = run_real_path(&fixture);
    let canonical = canonical_accept_final(&final_pset, &context()).unwrap();
    assert_eq!(canonical.digest().into_bytes(), kat::FINAL_CANONICAL_DIGEST,);
}

mod kat {
    /// KAT: canonical projection digest of the final blinded PSET for `SEED`
    /// and the two-input fixture above. Regenerate only by re-deriving from a
    /// real run, never by hand.
    pub const FINAL_CANONICAL_DIGEST: [u8; 32] = [
        221, 225, 70, 3, 241, 202, 97, 128, 41, 80, 102, 6, 172, 73, 217, 203, 62, 196, 183, 34,
        177, 189, 151, 246, 31, 81, 17, 24, 159, 38, 9, 144,
    ];
}
