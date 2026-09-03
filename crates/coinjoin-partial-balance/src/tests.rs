use super::*;
use elements::{
    OutPoint, RangeProofMessage, Script, TxOut, Txid,
    bitcoin::PublicKey as BitcoinPublicKey,
    confidential::{AssetBlindingFactor, ValueBlindingFactor},
    encode,
    pset::{Input, Output},
    secp256k1_zkp::{Generator, PedersenCommitment},
};
use rand::{SeedableRng, rngs::StdRng};
use wasabi_liquid_native_coinjoin_pset_state::{CanonicalStateContext, canonicalize_pset_state};

const NETWORK: &[u8] = b"elements-liquid-mainnet";
const ROUND: &[u8] = b"round-partial-balance-0001";
const GENESIS: [u8; 32] = [0x22; 32];
const SEED: u64 = 0x5eed_5eed_ba1a_0001;

/// Genuine seeded proof bytes for participant A (pinned known-answer).
const KAT_PROOF_A: [u8; 65] = [
    3, 252, 21, 127, 230, 119, 26, 208, 123, 81, 21, 78, 249, 198, 17, 116, 38, 20, 237, 124, 245,
    42, 105, 122, 144, 105, 190, 63, 214, 107, 87, 183, 233, 6, 43, 205, 2, 160, 131, 237, 121, 63,
    137, 0, 250, 164, 210, 112, 105, 192, 98, 8, 32, 13, 213, 242, 250, 212, 248, 28, 193, 43, 210,
    59, 52,
];

fn asset() -> elements::AssetId {
    elements::AssetId::from_byte_array([0x11; 32])
}

fn canonical_state_context() -> CanonicalStateContext<'static> {
    CanonicalStateContext {
        profile: ProfileVersion::V1,
        network_identity: NETWORK,
        genesis_hash: GENESIS,
        lbtc_asset: asset(),
        fee_asset: asset(),
        round_id: ROUND,
        phase: Phase::Construction,
        participant_role: ParticipantRole::Initiator,
        contribution_ordinal: 1,
        predecessor: wasabi_liquid_native_coinjoin_pset_state::PredecessorDigest::Absent,
    }
}

fn balance_context<'a>(
    input_indices: &'a [u32],
    output_indices: &'a [u32],
    fee_share: u64,
    digest: [u8; 32],
) -> PartialBalanceContext<'a> {
    PartialBalanceContext {
        profile: ProfileVersion::V1,
        network_identity: NETWORK,
        genesis_hash: GENESIS,
        lbtc_asset: asset(),
        round_id: ROUND,
        phase: Phase::Construction,
        participant_role: ParticipantRole::Initiator,
        contribution_ordinal: 1,
        pset_state_digest: digest,
        input_indices,
        output_indices,
        fee_share,
    }
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

fn scalar_add(a: &SecretKey, b: &SecretKey) -> SecretKey {
    a.add_tweak(&scalar_of(b)).expect("nonzero scalar sum")
}

fn bf_key(factor: ValueBlindingFactor) -> SecretKey {
    SecretKey::from_slice(factor.into_inner().as_ref()).expect("blinding factor is a valid key")
}

/// Real cryptographic material for one round. The PSET is built in the
/// canonical PREBLIND shape (explicit L-BTC witness UTXOs, preblind outputs,
/// explicit fee) so each revision passes canonical V1 validation and yields a
/// genuine state digest; the confidential outputs are then blinded over the
/// CANONICAL unblinded L-BTC generator (`asset_bf` zero, fresh seeded value
/// blinding factor) so each output commitment is `v·H_A + r_o·H` — the exact
/// shape the partial-balance relation requires. The explicit inputs
/// contribute `v·H_A` directly (blinding factor zero), so each participant's
/// residual is exactly `−r_o·H` and Δr = −r_o. The output value blinding
/// factors are recovered from the fork's `Value::blind` return, so each
/// participant's witness is genuine.
struct Fixture {
    /// Final blinded PSET: revision R1.
    pset: PartiallySignedTransaction,
    /// Canonical state digest of revision R1.
    digest: [u8; 32],
    /// Canonical state digest of revision R2.
    digest_v2: [u8; 32],
    /// Per-output value blinding factors (asset blinding is zero).
    output_blindings: Vec<ValueBlindingFactor>,
    /// Per-participant explicit input values.
    input_values: [u64; 2],
}

const FEE_A: u64 = 500;
const FEE_B: u64 = 600;

/// Builds the canonical preblind shape (explicit witness UTXOs, preblind
/// outputs, explicit fee), computes the canonical V1 state digest over its
/// exact serialization, then blinds each confidential output over the
/// CANONICAL unblinded generator and returns the final PSET, the digest, and
/// the recovered output value blinding factors.
fn build_revision(
    input_values: &[u64; 2],
    output_values: &[u64; 2],
    fee: u64,
    seed: u64,
) -> (
    PartiallySignedTransaction,
    [u8; 32],
    Vec<ValueBlindingFactor>,
) {
    let secp = Secp256k1::new();
    let mut pset = PartiallySignedTransaction::new_v2();
    for (tag, value) in input_values.iter().enumerate() {
        let tag = tag as u8;
        let mut input = Input::from_prevout(OutPoint::new(
            Txid::from_byte_array([0x30 + tag; 32]),
            u32::from(tag),
        ));
        input.witness_utxo = Some(TxOut {
            asset: Asset::Explicit(asset()),
            value: Value::Explicit(*value),
            nonce: Nonce::Null,
            script_pubkey: p2wpkh_script(tag),
            witness: Default::default(),
        });
        pset.add_input(input);
    }
    for (index, value) in output_values.iter().enumerate() {
        let mut output = Output::new_explicit(
            p2wpkh_script(0x40 + index as u8),
            *value,
            asset(),
            Some(blinding_key(3 + index as u8)),
        );
        output.blinder_index = Some(index as u32);
        pset.add_output(output);
    }
    pset.add_output(Output::new_explicit(Script::new(), fee, asset(), None));
    // The canonical V1 state digest binds the exact preblind revision bytes.
    let raw = encode::serialize(&pset);
    let digest = canonicalize_pset_state(&raw, &canonical_state_context())
        .expect("preblind fixture revision must pass canonical validation")
        .digest()
        .into_bytes();
    // Blind each confidential output over the canonical generator.
    let asset_comm = Generator::new_unblinded(&secp, asset().into_tag());
    let zero_abf = AssetBlindingFactor::from_slice(&[0u8; 32]).unwrap();
    let mut output_blindings = Vec::new();
    for (index, output_value) in output_values.iter().enumerate() {
        let output_value = *output_value;
        let mut rng = StdRng::seed_from_u64(seed ^ 0xc000 ^ (index as u64));
        let value_bf = ValueBlindingFactor::new(&mut rng);
        let ephemeral_sk = SecretKey::new(&mut rng);
        let spk = p2wpkh_script(0x40 + index as u8);
        let msg = RangeProofMessage::new(asset(), zero_abf);
        let (blinded_value, nonce, rangeproof) = Value::Explicit(output_value)
            .blind(
                &secp,
                value_bf,
                blinding_key(3 + index as u8).inner,
                ephemeral_sk,
                &spk,
                &msg,
            )
            .expect("seeded output value blinding must succeed");
        let value_commitment = match blinded_value {
            Value::Confidential(commitment) => commitment,
            _ => panic!("blinded value is confidential"),
        };
        let output = &mut pset.outputs_mut()[index];
        output.asset_comm = Some(asset_comm);
        output.amount_comm = Some(value_commitment);
        output.ecdh_pubkey = Some(BitcoinPublicKey::new(match nonce {
            Nonce::Confidential(key) => key,
            _ => panic!("blinded output nonce is confidential"),
        }));
        output.value_rangeproof = Some(rangeproof);
        output_blindings.push(value_bf);
    }
    (pset, digest, output_blindings)
}

/// The two-participant balanced fixture: participant A (Initiator) owns
/// explicit input 0 and confidential output 0 with fee share FEE_A;
/// participant B (Responder) owns explicit input 1 and confidential output 1
/// with fee share FEE_B; FEE_A + FEE_B == fee. Each Δr = −r_o.
fn build_fixture() -> Fixture {
    let input_values = [5_000u64, 4_000u64];
    let output_values = [4_500u64, 3_400u64];
    let fee = FEE_A + FEE_B;
    assert_eq!(input_values[0], output_values[0] + FEE_A);
    assert_eq!(input_values[1], output_values[1] + FEE_B);
    let (pset, digest, output_blindings) = build_revision(&input_values, &output_values, fee, SEED);
    let (_pset_v2, digest_v2, _) =
        build_revision(&input_values, &output_values, fee + 1, SEED ^ 0x00ff);
    assert_ne!(digest, digest_v2);
    Fixture {
        pset,
        digest,
        digest_v2,
        output_blindings,
        input_values,
    }
}

impl Fixture {
    /// Participant A: input 0, output 0, fee share FEE_A. Δr = −r_o0.
    fn participant_a(&self) -> Participant {
        Participant {
            role: ParticipantRole::Initiator,
            ordinal: 1,
            input_indices: vec![0],
            output_indices: vec![0],
            fee_share: FEE_A,
            delta_r: bf_key(self.output_blindings[0]).negate(),
        }
    }

    /// Participant B: input 1, output 1, fee share FEE_B; shares sum to fee.
    fn participant_b(&self) -> Participant {
        Participant {
            role: ParticipantRole::Responder,
            ordinal: 2,
            input_indices: vec![1],
            output_indices: vec![1],
            fee_share: FEE_B,
            delta_r: bf_key(self.output_blindings[1]).negate(),
        }
    }
}

struct Participant {
    role: ParticipantRole,
    ordinal: u32,
    input_indices: Vec<u32>,
    output_indices: Vec<u32>,
    fee_share: u64,
    delta_r: SecretKey,
}

impl Participant {
    fn context<'a>(&'a self, digest: [u8; 32]) -> PartialBalanceContext<'a> {
        let mut context = balance_context(
            &self.input_indices,
            &self.output_indices,
            self.fee_share,
            digest,
        );
        context.participant_role = self.role;
        context.contribution_ordinal = self.ordinal;
        context
    }

    fn witness(&self) -> PartialBalanceWitness {
        PartialBalanceWitness::from_secret_key(&self.delta_r)
    }

    fn prove(&self, fixture: &Fixture) -> (PartialBalanceProof, PartialBalanceContext<'_>) {
        let secp = Secp256k1::new();
        let context = self.context(fixture.digest);
        let proof =
            prove_partial_balance(&secp, &fixture.pset, &context, &self.witness(), &[0x77; 32])
                .expect("genuine partial-balance proof must succeed");
        (proof, context)
    }
}

#[test]
fn genuine_two_participant_proofs_verify() {
    let fixture = build_fixture();
    let secp = Secp256k1::new();
    for participant in [fixture.participant_a(), fixture.participant_b()] {
        let (proof, context) = participant.prove(&fixture);
        verify_partial_balance(&secp, &fixture.pset, &context, &proof)
            .expect("genuine partial-balance proof must verify");
    }
}

#[test]
fn zero_balance_relation_residual_is_exactly_delta_r_times_h() {
    // The residual commitment recomputed from the PSET elements is exactly
    // Δr·H: for each participant the value terms cancel and only the blinding
    // aggregate remains.
    let fixture = build_fixture();
    let secp = Secp256k1::new();
    let h = blinding_generator();
    for participant in [fixture.participant_a(), fixture.participant_b()] {
        let context = participant.context(fixture.digest);
        let statement =
            build_statement(&secp, &fixture.pset, &context).expect("genuine statement must build");
        let expected = h
            .mul_tweak(&secp, &scalar_of(&participant.delta_r))
            .expect("Δr·H is a valid point");
        assert_eq!(statement.residual, expected);
    }
}

#[test]
fn mutation_wrong_witness_value_fails() {
    // Books that do not balance: the residual carries a nonzero v·H_A
    // component, so no Δr exists and verification of a proof made with the
    // balanced witness fails against the mutated statement.
    let fixture = build_fixture();
    let secp = Secp256k1::new();
    let participant = fixture.participant_a();
    let (proof, context) = participant.prove(&fixture);
    // Mutate the PSET: bump the explicit witness UTXO value by one atomic
    // unit, so the books no longer balance (the residual carries a nonzero
    // v·H_A component) and the genuine witness's proof fails.
    let mut mutated = fixture.pset.clone();
    mutated.inputs_mut()[0].witness_utxo.as_mut().unwrap().value =
        Value::Explicit(fixture.input_values[0] + 1);
    assert_eq!(
        verify_partial_balance(&secp, &mutated, &context, &proof),
        Err(Error::VerificationFailed),
    );
}

#[test]
fn mutation_wrong_blinding_factor_fails() {
    // A witness whose Δr is not the true residual blinding factor produces a
    // proof that fails verification: the prover relation is genuinely checked.
    let fixture = build_fixture();
    let secp = Secp256k1::new();
    let participant = fixture.participant_a();
    let context = participant.context(fixture.digest);
    let wrong = scalar_add(
        &participant.delta_r,
        &SecretKey::from_slice(&[0x09; 32]).unwrap(),
    );
    let witness = PartialBalanceWitness::from_secret_key(&wrong);
    let proof = prove_partial_balance(&secp, &fixture.pset, &context, &witness, &[0x79; 32])
        .expect("proof generation with a wrong Δr still produces a proof");
    assert_eq!(
        verify_partial_balance(&secp, &fixture.pset, &context, &proof),
        Err(Error::VerificationFailed),
    );
}

#[test]
fn mutation_wrong_fee_share_fails() {
    let fixture = build_fixture();
    let secp = Secp256k1::new();
    for participant in [fixture.participant_a(), fixture.participant_b()] {
        let (proof, _context) = participant.prove(&fixture);
        for mutated_fee in [participant.fee_share + 1, participant.fee_share - 1] {
            let mut mutated = balance_context(
                &participant.input_indices,
                &participant.output_indices,
                mutated_fee,
                fixture.digest,
            );
            mutated.participant_role = participant.role;
            mutated.contribution_ordinal = participant.ordinal;
            assert_eq!(
                verify_partial_balance(&secp, &fixture.pset, &mutated, &proof),
                Err(Error::VerificationFailed),
            );
        }
    }
}

#[test]
fn mutation_swapped_fee_shares_fail() {
    // Each participant's proof verified against the OTHER participant's fee
    // share fails: the shares are individually bound.
    let fixture = build_fixture();
    let secp = Secp256k1::new();
    let a = fixture.participant_a();
    let b = fixture.participant_b();
    let (proof_a, _) = a.prove(&fixture);
    let (proof_b, _) = b.prove(&fixture);
    let mut a_as_b_fee = a.context(fixture.digest);
    a_as_b_fee.fee_share = b.fee_share;
    assert_eq!(
        verify_partial_balance(&secp, &fixture.pset, &a_as_b_fee, &proof_a),
        Err(Error::VerificationFailed),
    );
    let mut b_as_a_fee = b.context(fixture.digest);
    b_as_a_fee.fee_share = a.fee_share;
    assert_eq!(
        verify_partial_balance(&secp, &fixture.pset, &b_as_a_fee, &proof_b),
        Err(Error::VerificationFailed),
    );
}

#[test]
fn mutation_wrong_asset_generator_fails() {
    // A different L-BTC asset id in the context changes the canonical
    // generator, the transcript, and every explicit-value term: the genuine
    // proof fails.
    let fixture = build_fixture();
    let secp = Secp256k1::new();
    let participant = fixture.participant_a();
    let (proof, _) = participant.prove(&fixture);
    let mut mutated = participant.context(fixture.digest);
    mutated.lbtc_asset = elements::AssetId::from_byte_array([0x99; 32]);
    // The explicit witness UTXO asset no longer matches the mutated context's
    // asset id, so the statement shape rejects it; where the shape still
    // builds, the changed generator and transcript fail verification.
    assert!(matches!(
        verify_partial_balance(&secp, &fixture.pset, &mutated, &proof),
        Err(Error::VerificationFailed) | Err(Error::ElementShape),
    ));
}

#[test]
fn mutation_wrong_input_index_set_fails() {
    let fixture = build_fixture();
    let secp = Secp256k1::new();
    let participant = fixture.participant_a();
    let (proof, _) = participant.prove(&fixture);
    // Swap the explicit input for the blinded foreign input index: the
    // residual changes (a different commitment replaces v·H_A), so the proof
    // fails.
    let mut swapped = participant.context(fixture.digest);
    swapped.input_indices = &[1];
    assert_eq!(
        verify_partial_balance(&secp, &fixture.pset, &swapped, &proof),
        Err(Error::VerificationFailed),
    );
    // Omit the only index: an empty input set changes the residual and the
    // transcript.
    let mut omitted = participant.context(fixture.digest);
    omitted.input_indices = &[];
    assert!(matches!(
        verify_partial_balance(&secp, &fixture.pset, &omitted, &proof),
        Err(Error::VerificationFailed) | Err(Error::ElementShape),
    ));
    // Add a foreign (out-of-role) index.
    let mut foreign = participant.context(fixture.digest);
    foreign.input_indices = &[0, 1];
    assert_eq!(
        verify_partial_balance(&secp, &fixture.pset, &foreign, &proof),
        Err(Error::VerificationFailed),
    );
}

#[test]
fn mutation_wrong_output_index_set_fails() {
    let fixture = build_fixture();
    let secp = Secp256k1::new();
    let participant = fixture.participant_a();
    let (proof, _) = participant.prove(&fixture);
    // Swapping the confidential output for the fee output index fails (the
    // fee output has no amount commitment; the statement shape rejects it).
    let mut swapped = participant.context(fixture.digest);
    swapped.output_indices = &[1];
    assert!(matches!(
        verify_partial_balance(&secp, &fixture.pset, &swapped, &proof),
        Err(Error::VerificationFailed) | Err(Error::ElementShape),
    ));
    let mut omitted = participant.context(fixture.digest);
    omitted.output_indices = &[];
    assert_eq!(
        verify_partial_balance(&secp, &fixture.pset, &omitted, &proof),
        Err(Error::VerificationFailed),
    );
    let mut foreign = participant.context(fixture.digest);
    foreign.output_indices = &[0, 1];
    assert!(matches!(
        verify_partial_balance(&secp, &fixture.pset, &foreign, &proof),
        Err(Error::VerificationFailed) | Err(Error::ElementShape),
    ));
}

#[test]
fn mutation_wrong_round_fails() {
    let fixture = build_fixture();
    let secp = Secp256k1::new();
    let participant = fixture.participant_a();
    let (proof, _) = participant.prove(&fixture);
    let mut mutated = participant.context(fixture.digest);
    mutated.round_id = b"round-partial-balance-0002";
    assert_eq!(
        verify_partial_balance(&secp, &fixture.pset, &mutated, &proof),
        Err(Error::VerificationFailed),
    );
}

#[test]
fn mutation_wrong_pset_digest_fails() {
    // The second genuine revision's digest binds a different PSET state.
    let fixture = build_fixture();
    let secp = Secp256k1::new();
    let participant = fixture.participant_a();
    let (proof, _) = participant.prove(&fixture);
    let mutated = participant.context(fixture.digest_v2);
    assert_eq!(
        verify_partial_balance(&secp, &fixture.pset, &mutated, &proof),
        Err(Error::VerificationFailed),
    );
}

#[test]
fn mutation_wrong_participant_role_fails() {
    let fixture = build_fixture();
    let secp = Secp256k1::new();
    let participant = fixture.participant_a();
    let (proof, _) = participant.prove(&fixture);
    let mut mutated = participant.context(fixture.digest);
    mutated.participant_role = ParticipantRole::Responder;
    assert_eq!(
        verify_partial_balance(&secp, &fixture.pset, &mutated, &proof),
        Err(Error::VerificationFailed),
    );
}

#[test]
fn replay_of_participant_a_proof_as_participant_b_fails() {
    // Participant A's genuine proof verified under participant B's context
    // (different role, ordinal, indices, and fee share) fails.
    let fixture = build_fixture();
    let secp = Secp256k1::new();
    let a = fixture.participant_a();
    let b = fixture.participant_b();
    let (proof_a, _) = a.prove(&fixture);
    let b_context = b.context(fixture.digest);
    assert_eq!(
        verify_partial_balance(&secp, &fixture.pset, &b_context, &proof_a),
        Err(Error::VerificationFailed),
    );
}

#[test]
fn checked_arithmetic_bounds_fail_closed() {
    let fixture = build_fixture();
    // Index count bounds.
    let too_many_inputs = vec![0u32; MAX_INDICES + 1];
    let mut context = balance_context(&too_many_inputs, &[0], 0, fixture.digest);
    assert_eq!(encode_static_context(&context), Err(Error::InvalidContext),);
    let too_many_outputs = vec![0u32; MAX_INDICES + 1];
    context = balance_context(&[0], &too_many_outputs, 0, fixture.digest);
    assert_eq!(encode_static_context(&context), Err(Error::InvalidContext),);
    // Fee share at and above the L-BTC atomic-units boundary.
    context = balance_context(&[0], &[0], MAX_LBTC_ATOMIC_UNITS, fixture.digest);
    assert!(encode_static_context(&context).is_ok());
    context = balance_context(&[0], &[0], MAX_LBTC_ATOMIC_UNITS + 1, fixture.digest);
    assert_eq!(encode_static_context(&context), Err(Error::InvalidContext),);
    // Empty/oversized network identity and round id.
    for (network, round) in [
        (b"".as_slice(), ROUND),
        (&[0x55; 65][..], ROUND),
        (NETWORK, b"".as_slice()),
        (NETWORK, &[0x55; 129][..]),
    ] {
        let mut bounded = balance_context(&[0], &[0], 0, fixture.digest);
        bounded.network_identity = network;
        bounded.round_id = round;
        assert_eq!(encode_static_context(&bounded), Err(Error::InvalidContext));
    }
}

#[test]
fn max_lbtc_boundary_residual_is_identity_fail_closed() {
    // An explicit-value input at the exact max L-BTC atomic units with an
    // equal fee share leaves a zero residual (the point at infinity), which
    // cannot be represented as a curve point; statement construction fails
    // closed rather than panicking.
    let secp = Secp256k1::new();
    let mut pset = PartiallySignedTransaction::new_v2();
    let mut input = Input::from_prevout(OutPoint::new(Txid::from_byte_array([0x30; 32]), 0));
    input.witness_utxo = Some(TxOut {
        asset: Asset::Explicit(asset()),
        value: Value::Explicit(MAX_LBTC_ATOMIC_UNITS),
        nonce: Nonce::Null,
        script_pubkey: p2wpkh_script(0x30),
        witness: Default::default(),
    });
    pset.add_input(input);
    let context = balance_context(&[0], &[], MAX_LBTC_ATOMIC_UNITS, [0x42; 32]);
    assert_eq!(
        build_statement(&secp, &pset, &context).err(),
        Some(Error::ElementShape),
    );
}

#[test]
fn explicit_value_input_relation_holds() {
    // An explicit-value input contributes v·H_A directly with blinding factor
    // zero; with a confidential output whose value plus the fee equals v and
    // whose blinding factor is known, the residual is exactly Δr·H with
    // Δr = −r_o.
    let secp = Secp256k1::new();
    let value = 10_000u64;
    let fee = 1_000u64;
    let output_value = value - fee;
    let out_value_bf = ValueBlindingFactor::from_slice(&[0x31; 32]).unwrap();
    let canonical = Generator::new_unblinded(&secp, asset().into_tag());
    let output_commitment =
        PedersenCommitment::new(&secp, output_value, out_value_bf.into_inner(), canonical);

    let mut pset = PartiallySignedTransaction::new_v2();
    let mut input = Input::from_prevout(OutPoint::new(Txid::from_byte_array([0x30; 32]), 0));
    input.witness_utxo = Some(TxOut {
        asset: Asset::Explicit(asset()),
        value: Value::Explicit(value),
        nonce: Nonce::Null,
        script_pubkey: p2wpkh_script(0x30),
        witness: Default::default(),
    });
    pset.add_input(input);
    let mut output = Output::new_explicit(p2wpkh_script(0x40), output_value, asset(), None);
    output.amount_comm = Some(output_commitment);
    output.asset_comm = Some(canonical);
    pset.add_output(output);

    // Δr = 0 (explicit input) − r_o = −r_o.
    let delta_r = bf_key(out_value_bf).negate();
    let context = balance_context(&[0], &[0], fee, [0x42; 32]);
    let statement = build_statement(&secp, &pset, &context).expect("statement must build");
    let expected = blinding_generator()
        .mul_tweak(&secp, &scalar_of(&delta_r))
        .unwrap();
    assert_eq!(statement.residual, expected);

    let witness = PartialBalanceWitness::from_secret_key(&delta_r);
    let proof = prove_partial_balance(&secp, &pset, &context, &witness, &[0x77; 32])
        .expect("explicit-input proof must succeed");
    verify_partial_balance(&secp, &pset, &context, &proof)
        .expect("explicit-input proof must verify");
}

#[test]
fn malformed_proof_encodings_fail_closed() {
    let fixture = build_fixture();
    let secp = Secp256k1::new();
    let participant = fixture.participant_a();
    let (proof, context) = participant.prove(&fixture);
    let proof_bytes = encode_proof(&proof);

    // Wrong length (truncated and extended-with-trailing-bytes).
    assert_eq!(
        decode_proof(&proof_bytes[..64]),
        Err(Error::InvalidProofEncoding),
    );
    let mut extended = proof_bytes.to_vec();
    extended.push(0x00);
    assert_eq!(decode_proof(&extended), Err(Error::InvalidProofEncoding));
    // Non-canonical scalar: s set to 0xFF..FF exceeds the curve order.
    let mut bad_scalar = proof_bytes;
    for byte in &mut bad_scalar[33..65] {
        *byte = 0xFF;
    }
    assert_eq!(decode_proof(&bad_scalar), Err(Error::InvalidProofEncoding),);
    // Invalid point: R_k replaced by an x-coordinate with no curve point.
    let mut bad_point = proof_bytes;
    bad_point[0] = 0x02;
    for byte in &mut bad_point[1..33] {
        *byte = 0xFF;
    }
    assert_eq!(decode_proof(&bad_point), Err(Error::InvalidProofEncoding),);
    // The still-canonical-but-tampered proof decodes but fails verification
    // (cryptographic, not lexical, failure).
    let mut tampered = proof_bytes;
    tampered[40] ^= 0x01;
    let decoded = decode_proof(&tampered).expect("bit-flipped canonical proof decodes");
    assert_eq!(
        verify_partial_balance(&secp, &fixture.pset, &context, &decoded),
        Err(Error::VerificationFailed),
    );
}

#[test]
fn seeded_rerun_produces_identical_proof_bytes() {
    let fixture = build_fixture();
    let a1 = fixture.participant_a();
    let a2 = fixture.participant_a();
    let (proof1, context1) = a1.prove(&fixture);
    let (proof2, context2) = a2.prove(&fixture);
    assert_eq!(encode_proof(&proof1), encode_proof(&proof2));
    assert_eq!(
        encode_static_context(&context1).unwrap(),
        encode_static_context(&context2).unwrap(),
    );
}

#[test]
fn known_answer_proof_bytes_and_context_layout_are_pinned() {
    // One KAT pins the genuine proof bytes and the exact static context
    // encoding (magic, field order, length prefixes).
    let fixture = build_fixture();
    let participant = fixture.participant_a();
    let (proof, context) = participant.prove(&fixture);
    let proof_bytes = encode_proof(&proof);
    // The genuine seeded proof bytes are pinned below (see KAT constant).
    assert_eq!(proof_bytes, KAT_PROOF_A);
    // Pin the exact static context encoding (magic, field order, prefixes).
    let encoded = encode_static_context(&context).unwrap();
    let mut expected = Vec::new();
    expected.extend_from_slice(b"WL-CJ-PARTIAL-BALANCE-V1");
    expected.push(1u8); // profile V1
    expected.extend_from_slice(&(NETWORK.len() as u32).to_be_bytes());
    expected.extend_from_slice(NETWORK);
    expected.extend_from_slice(&GENESIS);
    expected.extend_from_slice(&asset().to_byte_array());
    expected.extend_from_slice(&(ROUND.len() as u32).to_be_bytes());
    expected.extend_from_slice(ROUND);
    expected.push(1u8); // Phase::Construction
    expected.push(1u8); // ParticipantRole::Initiator
    expected.extend_from_slice(&1u32.to_be_bytes()); // contribution ordinal
    expected.extend_from_slice(&fixture.digest);
    expected.extend_from_slice(&1u32.to_be_bytes()); // input index count
    expected.extend_from_slice(&0u32.to_be_bytes()); // input index 0
    expected.extend_from_slice(&1u32.to_be_bytes()); // output index count
    expected.extend_from_slice(&0u32.to_be_bytes()); // output index 0
    expected.extend_from_slice(&500u64.to_be_bytes()); // fee share
    assert_eq!(encoded, expected);
}

#[test]
fn element_shape_rejections_fail_closed() {
    let fixture = build_fixture();
    let secp = Secp256k1::new();
    let participant = fixture.participant_a();
    let context = participant.context(fixture.digest);

    // Missing witness UTXO.
    let mut missing_utxo = fixture.pset.clone();
    missing_utxo.inputs_mut()[0].witness_utxo = None;
    assert_eq!(
        build_statement(&secp, &missing_utxo, &context).err(),
        Some(Error::ElementShape),
    );
    // Null value.
    let mut null_value = fixture.pset.clone();
    null_value.inputs_mut()[0]
        .witness_utxo
        .as_mut()
        .unwrap()
        .value = Value::Null;
    assert_eq!(
        build_statement(&secp, &null_value, &context).err(),
        Some(Error::ElementShape),
    );
    // Wrong explicit asset on the witness UTXO.
    let mut wrong_asset = fixture.pset.clone();
    wrong_asset.inputs_mut()[0]
        .witness_utxo
        .as_mut()
        .unwrap()
        .asset = Asset::Explicit(elements::AssetId::from_byte_array([0x99; 32]));
    assert_eq!(
        build_statement(&secp, &wrong_asset, &context).err(),
        Some(Error::ElementShape),
    );
    // Output missing its amount commitment.
    let mut no_amount_comm = fixture.pset.clone();
    no_amount_comm.outputs_mut()[0].amount_comm = None;
    assert_eq!(
        build_statement(&secp, &no_amount_comm, &context).err(),
        Some(Error::ElementShape),
    );
    // Output on a foreign asset generator: the asset_comm bytes are bound
    // into the transcript but not value-checked against the canonical
    // generator (asset identity is the canonical/surjection layer's job), so
    // the statement still builds; the genuine proof would fail under it.
    let mut foreign_generator = fixture.pset.clone();
    foreign_generator.outputs_mut()[0].asset_comm = Some(Generator::new_blinded(
        &secp,
        asset().into_tag(),
        AssetBlindingFactor::from_slice(&[0x07; 32])
            .unwrap()
            .into_inner(),
    ));
    assert!(build_statement(&secp, &foreign_generator, &context).is_ok());
    // Out-of-range input index.
    let mut bad_index = participant.context(fixture.digest);
    bad_index.input_indices = &[7];
    assert_eq!(
        build_statement(&secp, &fixture.pset, &bad_index).err(),
        Some(Error::ElementShape),
    );
}

#[test]
fn prove_rejects_bad_entropy() {
    let fixture = build_fixture();
    let secp = Secp256k1::new();
    let participant = fixture.participant_a();
    let context = participant.context(fixture.digest);
    assert_eq!(
        prove_partial_balance(
            &secp,
            &fixture.pset,
            &context,
            &participant.witness(),
            &[0x77; 31]
        )
        .err(),
        Some(Error::InvalidWitness),
    );
}

#[test]
fn witness_rejects_zero_and_noncanonical_scalars() {
    assert_eq!(
        PartialBalanceWitness::from_scalar_bytes(&[0u8; 32]).err(),
        Some(Error::InvalidWitness),
    );
    assert_eq!(
        PartialBalanceWitness::from_scalar_bytes(&[0xFF; 32]).err(),
        Some(Error::InvalidWitness),
    );
}
