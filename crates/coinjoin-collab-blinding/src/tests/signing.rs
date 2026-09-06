use super::*;
use elements::confidential::SurjectionProof;
use elements::secp256k1_zkp::{Message, ecdsa};
use elements::sighash::{SighashCache, SighashRangeproofMode};
use elements::{EcdsaSighashType, Transaction};

const ALL_RANGEPROOF: EcdsaSighashType = EcdsaSighashType::AllPlusRangeproof;

fn signing_fixture() -> (Fixture, [SecretKey; 2]) {
    let mut fixture = two_input_fixture();
    let keys = [
        SecretKey::from_slice(&[0x61; 32]).unwrap(),
        SecretKey::from_slice(&[0x62; 32]).unwrap(),
    ];
    let secp = Secp256k1::new();
    for (input, key) in fixture.pset.inputs_mut().iter_mut().zip(&keys) {
        let public_key = PublicKey::new(key.public_key(&secp));
        input.witness_utxo.as_mut().unwrap().script_pubkey =
            Script::new_v0_wpkh(&public_key.wpubkey_hash().unwrap());
    }
    // B spends a real confidential previous output; A has no B opening or key.
    let mut rng = StdRng::seed_from_u64(SEED ^ 0xc2);
    let secrets = elements::TxOutSecrets::new(
        asset(),
        AssetBlindingFactor::new(&mut rng),
        4_000,
        ValueBlindingFactor::new(&mut rng),
    );
    let domain_secrets = elements::TxOutSecrets::new(
        asset(),
        AssetBlindingFactor::new(&mut rng),
        5_000,
        ValueBlindingFactor::new(&mut rng),
    );
    let input = &mut fixture.pset.inputs_mut()[1];
    let utxo = TxOut::with_txout_secrets(
        &mut rng,
        &secp,
        input.witness_utxo.as_ref().unwrap().script_pubkey.clone(),
        blinding_key(9).inner,
        SecretKey::from_slice(&[10; 32]).unwrap(),
        secrets,
        &[domain_secrets],
    )
    .unwrap();
    input.in_utxo_rangeproof = Some(utxo.witness.rangeproof.clone());
    input.asset = Some(asset());
    input.blind_asset_proof = Some(
        SurjectionProof::blind_asset_proof(&mut rng, &secp, asset(), secrets.asset_bf).unwrap(),
    );
    input.witness_utxo = Some(utxo);
    fixture.secrets_b.insert(1, secrets);
    (fixture, keys)
}

fn authorizations(
    pset: &PartiallySignedTransaction,
    keys: &[SecretKey; 2],
) -> [AuthorizedInput; 2] {
    let secp = Secp256k1::new();
    std::array::from_fn(|index| AuthorizedInput {
        index,
        outpoint: pset.inputs()[index].previous_outpoint(),
        public_key: PublicKey::new(keys[index].public_key(&secp)),
    })
}

fn approved_digest(pset: &PartiallySignedTransaction) -> [u8; 32] {
    canonical_accept_final(pset, &context())
        .unwrap()
        .digest()
        .into_bytes()
}

fn accept(pset: &PartiallySignedTransaction, auth: &[AuthorizedInput]) -> SigningCapability {
    accept_signing_capability(
        &serialize_handoff(pset),
        &context(),
        approved_digest(pset),
        auth,
    )
    .unwrap()
}

#[derive(Clone, Copy)]
enum Behavior {
    Normal,
    Refuse,
    ReverseDigest,
    WrongKey,
    HighS,
    WrongSighash,
    TrailingDer,
    Compact,
    Empty,
}

// Each instance contains exactly one participant's key, never an all-input signer.
struct ParticipantSigner {
    key: SecretKey,
    auth: AuthorizedInput,
    behavior: Behavior,
    calls: Vec<[u8; 32]>,
}

impl ParticipantSigner {
    fn new(key: SecretKey, auth: AuthorizedInput) -> Self {
        Self {
            key,
            auth,
            behavior: Behavior::Normal,
            calls: Vec::new(),
        }
    }
}

impl CollabP2wpkhSigner for ParticipantSigner {
    fn sign_digest(
        &mut self,
        index: usize,
        outpoint: &OutPoint,
        digest: [u8; 32],
        sighash_type: EcdsaSighashType,
    ) -> Option<Vec<u8>> {
        assert_eq!(index, self.auth.index);
        assert_eq!(*outpoint, self.auth.outpoint);
        assert_eq!(sighash_type, ALL_RANGEPROOF);
        self.calls.push(digest);
        let mut signing_digest = digest;
        if matches!(self.behavior, Behavior::Refuse) {
            return None;
        }
        if matches!(self.behavior, Behavior::ReverseDigest) {
            signing_digest.reverse();
        }
        let key = if matches!(self.behavior, Behavior::WrongKey) {
            SecretKey::from_slice(&[0x71; 32]).unwrap()
        } else {
            self.key
        };
        let mut signature =
            Secp256k1::new().sign_ecdsa(&Message::from_digest(signing_digest), &key);
        if matches!(self.behavior, Behavior::HighS) {
            let mut compact = signature.serialize_compact();
            let s = SecretKey::from_slice(&compact[32..]).unwrap();
            compact[32..].copy_from_slice(&s.negate().secret_bytes());
            signature = ecdsa::Signature::from_compact(&compact).unwrap();
        }
        let mut bytes = signature.serialize_der().to_vec();
        match self.behavior {
            Behavior::TrailingDer => bytes.push(0),
            Behavior::Compact => bytes = signature.serialize_compact().to_vec(),
            Behavior::Empty => return Some(Vec::new()),
            _ => {}
        }
        bytes.push(if matches!(self.behavior, Behavior::WrongSighash) {
            1
        } else {
            0x41
        });
        Some(bytes)
    }
}

fn digest_for(
    tx: &Transaction,
    auth: AuthorizedInput,
    value: Value,
    mode: SighashRangeproofMode,
) -> [u8; 32] {
    SighashCache::new(tx)
        .segwitv0_sighash_with_rangeproof_mode(
            auth.index,
            &Script::new_p2pkh(&auth.public_key.pubkey_hash()),
            value,
            ALL_RANGEPROOF,
            mode,
        )
        .to_byte_array()
}

#[test]
fn two_independent_participants_sign_actual_final_pset_without_changing_body() {
    let (fixture, [key_a, key_b]) = signing_fixture();
    let (_, mut final_pset) = run_real_path(&fixture);
    let original_bytes = serialize_handoff(&final_pset);
    let original_tx = final_pset.extract_tx().unwrap();
    let auth = authorizations(&final_pset, &[key_a, key_b]);
    let expected = approved_digest(&final_pset);
    // Independently admitted copies, not a shared mutable PSET between signers.
    let capability_a = accept(&final_pset, &auth);
    let capability_b = accept(&final_pset, &auth);
    assert_eq!(capability_a.digest(), expected);
    let mut signer_a = ParticipantSigner::new(key_a, auth[0]);
    let mut signer_b = ParticipantSigner::new(key_b, auth[1]);
    let a = sign_owned_inputs(&capability_a, &auth[..1], &mut signer_a).unwrap();
    assert!(signer_b.calls.is_empty());
    assert_eq!(serialize_handoff(&final_pset), original_bytes);
    // Mutating the caller's object after admission cannot alter either capability.
    final_pset.outputs_mut()[2].amount = Some(1);
    let b = sign_owned_inputs(&capability_b, &auth[1..], &mut signer_b).unwrap();
    assert_eq!(signer_a.calls.len(), 1);
    assert_eq!(signer_b.calls.len(), 1);
    let contributions = [b[0].clone(), a[0].clone()];
    let finalized = assemble_signatures(&capability_a, &contributions).unwrap();
    let tx = finalized.transaction();
    assert_eq!(finalized.txid(), original_tx.txid());
    assert_eq!(tx.output, original_tx.output);
    let mut without_signatures = tx.clone();
    for input in &mut without_signatures.input {
        input.witness.script_witness = Default::default();
    }
    assert_eq!(without_signatures, original_tx);
    tx.verify_tx_amt_proofs(&Secp256k1::new(), &state(&fixture).witness_utxos())
        .unwrap();
    assert_eq!(
        assemble_signatures(&capability_b, &contributions)
            .unwrap()
            .transaction(),
        tx
    );
    for (index, (contribution, calls)) in [(&a[0], signer_a.calls), (&b[0], signer_b.calls)]
        .into_iter()
        .enumerate()
    {
        assert_eq!(contribution.index(), index);
        assert_eq!(contribution.public_key(), auth[index].public_key);
        assert_eq!(contribution.digest(), expected);
        let value = fixture.pset.inputs()[index]
            .witness_utxo
            .as_ref()
            .unwrap()
            .value;
        let digest = digest_for(tx, auth[index], value, SighashRangeproofMode::Enabled);
        assert_eq!(calls, vec![digest]);
        let bytes = contribution.signature();
        assert_eq!(bytes.last(), Some(&0x41));
        let signature = ecdsa::Signature::from_der(&bytes[..bytes.len() - 1]).unwrap();
        let mut low = signature;
        low.normalize_s();
        assert_eq!(low, signature);
        let secp = Secp256k1::new();
        secp.verify_ecdsa(
            &Message::from_digest(calls[0]),
            &signature,
            &auth[index].public_key.inner,
        )
        .unwrap();
        let disabled = digest_for(tx, auth[index], value, SighashRangeproofMode::Disabled);
        assert_ne!(disabled, digest);
        assert!(
            secp.verify_ecdsa(
                &Message::from_digest(disabled),
                &signature,
                &auth[index].public_key.inner
            )
            .is_err()
        );
        let mut changed_proof = tx.clone();
        changed_proof.output[0].witness.rangeproof = elements::confidential::RangeProof::EMPTY;
        let changed_digest = digest_for(
            &changed_proof,
            auth[index],
            value,
            SighashRangeproofMode::Enabled,
        );
        assert_ne!(changed_digest, digest);
        assert!(
            secp.verify_ecdsa(
                &Message::from_digest(changed_digest),
                &signature,
                &auth[index].public_key.inner
            )
            .is_err()
        );
    }
}

#[test]
fn admission_rejects_preblind_partial_scalars_and_wrong_phase_even_with_matching_digest() {
    let (fixture, keys) = signing_fixture();
    let (intermediate, final_pset) = run_real_path(&fixture);
    let auth = authorizations(&final_pset, &keys);
    let unblinded = state(&fixture);
    for pset in [
        unblinded.pset().clone(),
        deserialize_handoff(&intermediate).unwrap(),
    ] {
        let digest = approved_digest(&pset);
        assert_eq!(
            accept_signing_capability(&serialize_handoff(&pset), &context(), digest, &auth).err(),
            Some(SigningError::InvalidFinalState)
        );
    }
    let mut scalars = final_pset.clone();
    scalars.global.scalars = deserialize_handoff(&intermediate).unwrap().global.scalars;
    assert_eq!(
        accept_signing_capability(
            &serialize_handoff(&scalars),
            &context(),
            approved_digest(&scalars),
            &auth
        )
        .err(),
        Some(SigningError::InvalidFinalState)
    );
    let mut ctx = context();
    ctx.phase = Phase::Proofs;
    let digest = canonical_accept_final(&final_pset, &ctx)
        .unwrap()
        .digest()
        .into_bytes();
    assert_eq!(
        accept_signing_capability(&serialize_handoff(&final_pset), &ctx, digest, &auth).err(),
        Some(SigningError::InvalidFinalState)
    );
}

#[test]
fn admission_binds_expected_digest_order_prevouts_fee_and_context() {
    let (fixture, keys) = signing_fixture();
    let (_, final_pset) = run_real_path(&fixture);
    let auth = authorizations(&final_pset, &keys);
    let expected = approved_digest(&final_pset);
    let mut wrong_digest = expected;
    wrong_digest[0] ^= 1;
    assert_eq!(
        accept_signing_capability(
            &serialize_handoff(&final_pset),
            &context(),
            wrong_digest,
            &auth
        )
        .err(),
        Some(SigningError::DigestMismatch)
    );
    for mutation in 0..6 {
        let mut changed = final_pset.clone();
        match mutation {
            0 => changed.inputs_mut().swap(0, 1),
            1 => changed.inputs_mut()[0].previous_output_index += 1,
            2 => {
                changed.inputs_mut()[0].witness_utxo.as_mut().unwrap().value =
                    Value::Explicit(5_001)
            }
            3 => changed.outputs_mut()[2].amount = Some(1_101),
            4 => {
                changed.global.tx_data.fallback_locktime =
                    Some(elements::LockTime::from_consensus(1))
            }
            5 => changed.outputs_mut()[0].ecdh_pubkey = Some(blinding_key(12)),
            _ => unreachable!(),
        }
        assert!(
            accept_signing_capability(&serialize_handoff(&changed), &context(), expected, &auth)
                .is_err()
        );
    }
    let mut ctx = context();
    ctx.round_id = b"other-round";
    assert_eq!(
        accept_signing_capability(&serialize_handoff(&final_pset), &ctx, expected, &auth).err(),
        Some(SigningError::DigestMismatch)
    );
    let mut extra = serialize_handoff(&final_pset);
    extra.push(0);
    assert_eq!(
        accept_signing_capability(&extra, &context(), expected, &auth).err(),
        Some(SigningError::InvalidFinalState)
    );
}

#[test]
fn admission_checks_balance_and_proofs_before_a_capability_exists() {
    let (fixture, keys) = signing_fixture();
    let (_, final_pset) = run_real_path(&fixture);
    let auth = authorizations(&final_pset, &keys);
    // Canonical projection verifies each proof but does not verify amount balance.
    for mutation in 0..2 {
        let mut changed = final_pset.clone();
        if mutation == 0 {
            changed.outputs_mut()[2].amount = Some(1_101);
        } else {
            changed.inputs_mut()[0].witness_utxo.as_mut().unwrap().value = Value::Explicit(5_001);
        }
        let expected = approved_digest(&changed);
        assert_eq!(
            accept_signing_capability(&serialize_handoff(&changed), &context(), expected, &auth)
                .err(),
            Some(SigningError::InvalidFinalState)
        );
    }
    for mutation in 0..7 {
        let mut changed = final_pset.clone();
        match mutation {
            0 => {
                changed.outputs_mut()[0].value_rangeproof =
                    final_pset.outputs()[1].value_rangeproof.clone()
            }
            1 => {
                changed.outputs_mut()[0].asset_surjection_proof =
                    final_pset.outputs()[1].asset_surjection_proof.clone()
            }
            2 => {
                changed.outputs_mut()[0].blind_value_proof =
                    final_pset.outputs()[1].blind_value_proof.clone()
            }
            3 => {
                changed.outputs_mut()[0].blind_asset_proof =
                    final_pset.outputs()[1].blind_asset_proof.clone()
            }
            4 => changed.inputs_mut()[1].in_utxo_rangeproof = None,
            5 => changed.outputs_mut()[2].amount = Some(0),
            6 => {
                changed.inputs_mut()[0].final_script_witness =
                    Some(elements::Witness::from_slice(&[vec![1]]))
            }
            _ => unreachable!(),
        }
        assert_eq!(
            accept_signing_capability(
                &serialize_handoff(&changed),
                &context(),
                approved_digest(&final_pset),
                &auth
            )
            .err(),
            Some(SigningError::InvalidFinalState)
        );
    }
}

#[test]
fn full_authorization_and_entire_owned_subset_are_checked_before_any_callback() {
    let (fixture, keys) = signing_fixture();
    let (_, final_pset) = run_real_path(&fixture);
    let auth = authorizations(&final_pset, &keys);
    let capability = accept(&final_pset, &auth);
    let mut bad_key = auth[1];
    bad_key.public_key = auth[0].public_key;
    let mut uncompressed = auth[1];
    uncompressed.public_key = PublicKey::new_uncompressed(auth[1].public_key.inner);
    let mut bad_outpoint = auth[1];
    bad_outpoint.outpoint.vout += 1;
    let mut bad_index = auth[1];
    bad_index.index = usize::MAX;
    for invalid in [
        vec![],
        vec![auth[0]],
        vec![auth[0], auth[0]],
        vec![auth[0], bad_key],
        vec![auth[0], uncompressed],
        vec![auth[0], bad_outpoint],
        vec![auth[0], bad_index],
    ] {
        assert_eq!(
            accept_signing_capability(
                &serialize_handoff(&final_pset),
                &context(),
                approved_digest(&final_pset),
                &invalid
            )
            .err(),
            Some(SigningError::AuthorizationRejected)
        );
    }
    let mut signer = ParticipantSigner::new(keys[0], auth[0]);
    for invalid in [
        vec![],
        vec![auth[0], auth[0]],
        vec![auth[0], bad_key],
        vec![auth[0], uncompressed],
        vec![auth[0], bad_outpoint],
        vec![auth[0], bad_index],
        vec![auth[0]; 3],
    ] {
        assert_eq!(
            sign_owned_inputs(&capability, &invalid, &mut signer).err(),
            Some(SigningError::AuthorizationRejected)
        );
        assert!(signer.calls.is_empty());
    }
}

#[test]
fn callbacks_reject_refusal_wrong_digest_key_sighash_high_s_and_non_der() {
    let (fixture, keys) = signing_fixture();
    let (_, final_pset) = run_real_path(&fixture);
    let auth = authorizations(&final_pset, &keys);
    let capability = accept(&final_pset, &auth);
    for behavior in [
        Behavior::Refuse,
        Behavior::ReverseDigest,
        Behavior::WrongKey,
        Behavior::HighS,
        Behavior::WrongSighash,
        Behavior::TrailingDer,
        Behavior::Compact,
        Behavior::Empty,
    ] {
        let mut signer = ParticipantSigner::new(keys[0], auth[0]);
        signer.behavior = behavior;
        let error = if matches!(behavior, Behavior::Refuse) {
            SigningError::SignerRefused
        } else {
            SigningError::SignatureRejected
        };
        assert_eq!(
            sign_owned_inputs(&capability, &auth[..1], &mut signer).err(),
            Some(error)
        );
        assert_eq!(signer.calls.len(), 1);
    }
}

#[test]
fn assembly_requires_complete_unique_same_context_contributions() {
    let (fixture, keys) = signing_fixture();
    let (_, final_pset) = run_real_path(&fixture);
    let auth = authorizations(&final_pset, &keys);
    let capability = accept(&final_pset, &auth);
    let mut signer_a = ParticipantSigner::new(keys[0], auth[0]);
    let mut signer_b = ParticipantSigner::new(keys[1], auth[1]);
    let a = sign_owned_inputs(&capability, &auth[..1], &mut signer_a).unwrap();
    let b = sign_owned_inputs(&capability, &auth[1..], &mut signer_b).unwrap();
    let mut ctx = context();
    ctx.round_id = b"another-approved-round";
    let foreign_digest = canonical_accept_final(&final_pset, &ctx)
        .unwrap()
        .digest()
        .into_bytes();
    let foreign =
        accept_signing_capability(&serialize_handoff(&final_pset), &ctx, foreign_digest, &auth)
            .unwrap();
    let foreign_b = sign_owned_inputs(&foreign, &auth[1..], &mut signer_b).unwrap();
    assert_eq!(b[0].signature(), foreign_b[0].signature()); // Same tx, different approval context.
    for invalid in [
        vec![],
        a.clone(),
        vec![a[0].clone(), a[0].clone()],
        vec![a[0].clone(), b[0].clone(), b[0].clone()],
        vec![a[0].clone(), foreign_b[0].clone()],
    ] {
        assert_eq!(
            assemble_signatures(&capability, &invalid).err(),
            Some(SigningError::ContributionSetRejected)
        );
    }
    assert!(assemble_signatures(&capability, &[a[0].clone(), b[0].clone()]).is_ok());
}
