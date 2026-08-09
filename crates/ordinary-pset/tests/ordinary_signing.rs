use elements::bitcoin::PublicKey as BitcoinPublicKey;
use elements::confidential::{AssetBlindingFactor, Value, ValueBlindingFactor};
use elements::encode;
use elements::secp256k1_zkp::{All, Message, Secp256k1, SecretKey, ecdsa, rand::thread_rng};
use elements::sighash::{SighashCache, SighashRangeproofMode};
use elements::{
    AssetId, EcdsaSighashType, LockTime, OutPoint, RangeProof, Script, Sequence, SurjectionProof,
    Transaction, TxOut, TxOutSecrets, Txid,
};
use wasabi_liquid_native_address::{ConfidentialLiquidAddress, LiquidAddressProfile};
use wasabi_liquid_native_ordinary_pset::{
    BlindedOrdinaryPset, ConfidentialOutput, ExplicitFee, OrdinaryP2wpkhSigner,
    OrdinarySigningError, OrdinarySigningFailure, SignedOrdinaryPset, SpendableInput,
    prepare_ordinary_pset,
};
use wasabi_liquid_native_output_opening::open_confidential_output;

const CONFIDENTIAL_RECEIVE_ADDRESS: &str = "lq1qqf8er278e6nyvuwtgf39e6ewvdcnjupn9a86rzpx655y5lhkt0walu3djf9cklkxd3ryld97hu8h3xepw7sh2rlu7q45dcew5";
const ORDINARY_SIGHASH: EcdsaSighashType = EcdsaSighashType::AllPlusRangeproof;

#[test]
fn signs_and_finalizes_explicit_and_confidential_multiasset_inputs() {
    let secp = Secp256k1::new();
    let (blinded, keys) = blinded_fixture(&secp);
    let previous_outputs = retained_previous_outputs(&blinded);
    let unsigned = blinded.as_pset().extract_tx().unwrap();
    let original_sensitive_pset = blinded.serialize_sensitive();
    let expected_outpoints = blinded
        .as_pset()
        .inputs()
        .iter()
        .map(|input| input.previous_outpoint())
        .collect::<Vec<_>>();
    let mut signer = FixtureSigner::new(keys, Behavior::Normal);

    let signed = expect_signed(blinded.sign_and_finalize(&secp, &mut signer));
    let transaction = signed.transaction();

    assert_eq!(signer.public_key_requests, expected_outpoints);
    assert_eq!(signer.signature_requests, expected_outpoints);
    assert_eq!(transaction.output, unsigned.output);
    assert_eq!(transaction.input.len(), 2);
    for input in &transaction.input {
        assert!(input.script_sig.is_empty());
        let witness = input.witness.script_witness.to_vec();
        assert_eq!(witness.len(), 2);
        assert_eq!(witness[0].last(), Some(&(ORDINARY_SIGHASH.as_u32() as u8)));
        assert!(witness[0].len() <= 73);
        let public_key = BitcoinPublicKey::from_slice(&witness[1]).unwrap();
        assert!(public_key.compressed);
    }
    transaction
        .verify_tx_amt_proofs(&secp, &previous_outputs)
        .unwrap();

    let mut expected_signed_pset: elements::pset::PartiallySignedTransaction =
        encode::deserialize(&original_sensitive_pset).unwrap();
    for (expected_input, signed_input) in expected_signed_pset
        .inputs_mut()
        .iter_mut()
        .zip(signed.as_pset().inputs())
    {
        expected_input.final_script_witness = signed_input.final_script_witness.clone();
    }
    assert_eq!(signed.as_pset(), &expected_signed_pset);
    let signed_pset_bytes = signed.serialize_sensitive();
    let decoded_signed_pset: elements::pset::PartiallySignedTransaction =
        encode::deserialize(&signed_pset_bytes).unwrap();
    assert_eq!(decoded_signed_pset, *signed.as_pset());
    assert_eq!(encode::serialize(&decoded_signed_pset), signed_pset_bytes);
    let finalized = signed.into_finalized_transaction();
    assert_eq!(finalized.txid(), unsigned.txid());
    assert_ne!(finalized.wtxid(), unsigned.wtxid());

    let broadcast = finalized.serialize_for_broadcast();
    let decoded: Transaction = encode::deserialize(&broadcast).unwrap();
    assert_eq!(decoded, *finalized.transaction());
    assert_ne!(broadcast, signed_pset_bytes);
    assert!(encode::deserialize::<elements::pset::PartiallySignedTransaction>(&broadcast).is_err());
}

#[test]
fn signatures_bind_output_proofs_and_confidential_prevout_commitment() {
    let secp = Secp256k1::new();
    let (blinded, keys) = blinded_fixture(&secp);
    let previous_outputs = retained_previous_outputs(&blinded);
    assert!(previous_outputs[1].value.is_confidential());
    let mut signer = FixtureSigner::new(keys, Behavior::Normal);
    let signed = expect_signed(blinded.sign_and_finalize(&secp, &mut signer));
    let transaction = signed.transaction();

    let first_signature = witness_signature(transaction, 0);
    let first_public_key = signer.keys[0].public_key(&secp);
    let first_script_code =
        Script::new_p2pkh(&BitcoinPublicKey::new(first_public_key).pubkey_hash());

    let assert_transaction_mutation_rejected = |mutated: &Transaction| {
        let digest = SighashCache::new(mutated).segwitv0_sighash_with_rangeproof_mode(
            0,
            &first_script_code,
            previous_outputs[0].value,
            ORDINARY_SIGHASH,
            SighashRangeproofMode::Enabled,
        );
        assert!(
            secp.verify_ecdsa(
                &Message::from_digest(digest.to_byte_array()),
                &first_signature,
                &first_public_key,
            )
            .is_err()
        );
    };

    let mut rangeproof_mutation = transaction.clone();
    rangeproof_mutation.output[0].witness.rangeproof = RangeProof::EMPTY;
    assert_transaction_mutation_rejected(&rangeproof_mutation);
    let mut surjection_mutation = transaction.clone();
    surjection_mutation.output[0].witness.surjection_proof = SurjectionProof::EMPTY;
    assert_transaction_mutation_rejected(&surjection_mutation);
    let mut commitment_mutation = transaction.clone();
    commitment_mutation.output[0].value = transaction.output[1].value;
    assert_transaction_mutation_rejected(&commitment_mutation);
    let mut nonce_mutation = transaction.clone();
    nonce_mutation.output[0].nonce = transaction.output[1].nonce;
    assert_transaction_mutation_rejected(&nonce_mutation);
    let mut script_mutation = transaction.clone();
    script_mutation.output[0].script_pubkey = Script::from(vec![0x51]);
    assert_transaction_mutation_rejected(&script_mutation);
    let mut fee_mutation = transaction.clone();
    fee_mutation.output[2].value = Value::Explicit(501);
    assert_transaction_mutation_rejected(&fee_mutation);
    let mut locktime_mutation = transaction.clone();
    locktime_mutation.lock_time = LockTime::from_consensus(1);
    assert_transaction_mutation_rejected(&locktime_mutation);
    let mut sequence_mutation = transaction.clone();
    sequence_mutation.input[0].sequence = Sequence::ZERO;
    assert_transaction_mutation_rejected(&sequence_mutation);
    let mut outpoint_mutation = transaction.clone();
    outpoint_mutation.input[0].previous_output.vout += 1;
    assert_transaction_mutation_rejected(&outpoint_mutation);

    let disabled_digest = SighashCache::new(transaction).segwitv0_sighash_with_rangeproof_mode(
        0,
        &first_script_code,
        previous_outputs[0].value,
        ORDINARY_SIGHASH,
        SighashRangeproofMode::Disabled,
    );
    assert!(
        secp.verify_ecdsa(
            &Message::from_digest(disabled_digest.to_byte_array()),
            &first_signature,
            &first_public_key,
        )
        .is_err()
    );
    let ordinary_all_digest = SighashCache::new(transaction).segwitv0_sighash_with_rangeproof_mode(
        0,
        &first_script_code,
        previous_outputs[0].value,
        EcdsaSighashType::All,
        SighashRangeproofMode::Enabled,
    );
    assert!(
        secp.verify_ecdsa(
            &Message::from_digest(ordinary_all_digest.to_byte_array()),
            &first_signature,
            &first_public_key,
        )
        .is_err()
    );

    let second_signature = witness_signature(transaction, 1);
    let second_public_key = signer.keys[1].public_key(&secp);
    let second_script_code =
        Script::new_p2pkh(&BitcoinPublicKey::new(second_public_key).pubkey_hash());
    let wrong_value_digest = SighashCache::new(transaction).segwitv0_sighash_with_rangeproof_mode(
        1,
        &second_script_code,
        Value::Explicit(9_000),
        ORDINARY_SIGHASH,
        SighashRangeproofMode::Enabled,
    );
    assert!(
        secp.verify_ecdsa(
            &Message::from_digest(wrong_value_digest.to_byte_array()),
            &second_signature,
            &second_public_key,
        )
        .is_err()
    );
}

#[test]
fn validates_every_public_key_before_requesting_any_signature() {
    let secp = Secp256k1::new();
    let (blinded, keys) = blinded_fixture(&secp);
    let mut signer = FixtureSigner::new(keys, Behavior::WrongPublicKey(1));

    let failure = expect_signing_failure(blinded.sign_and_finalize(&secp, &mut signer));

    assert_eq!(
        failure.reason(),
        OrdinarySigningError::PublicKeyDoesNotOwnInput
    );
    assert_eq!(signer.public_key_requests.len(), 2);
    assert!(signer.signature_requests.is_empty());
}

#[test]
fn rejects_missing_and_uncompressed_public_keys_before_signing() {
    let secp = Secp256k1::new();
    let (blinded, keys) = blinded_fixture(&secp);
    let mut missing = FixtureSigner::new(keys, Behavior::MissingPublicKey(0));
    let failure = expect_signing_failure(blinded.sign_and_finalize(&secp, &mut missing));
    assert_eq!(failure.reason(), OrdinarySigningError::PublicKeyUnavailable);
    assert!(missing.signature_requests.is_empty());

    let (blinded, keys) = blinded_fixture(&secp);
    let mut uncompressed = FixtureSigner::new(keys, Behavior::UncompressedPublicKey(1));
    let failure = expect_signing_failure(blinded.sign_and_finalize(&secp, &mut uncompressed));
    assert_eq!(
        failure.reason(),
        OrdinarySigningError::UncompressedPublicKey
    );
    assert!(uncompressed.signature_requests.is_empty());
}

#[test]
fn signer_refusal_leaves_the_blinded_capability_retryable() {
    let secp = Secp256k1::new();
    let (blinded, keys) = blinded_fixture(&secp);
    let original_sensitive_pset = blinded.serialize_sensitive();
    let mut refusing = FixtureSigner::new(keys.clone(), Behavior::MissingSignature(1));
    let failure = expect_signing_failure(blinded.sign_and_finalize(&secp, &mut refusing));
    assert_eq!(failure.reason(), OrdinarySigningError::SignatureUnavailable);
    let blinded = failure.into_blinded();
    assert_eq!(blinded.serialize_sensitive(), original_sensitive_pset);

    let mut retry = FixtureSigner::new(keys, Behavior::Normal);
    assert!(blinded.sign_and_finalize(&secp, &mut retry).is_ok());
}

#[test]
fn rejects_signature_for_another_key() {
    let secp = Secp256k1::new();
    let (blinded, keys) = blinded_fixture(&secp);
    let mut signer = FixtureSigner::new(keys, Behavior::InvalidSignature(0));

    let failure = expect_signing_failure(blinded.sign_and_finalize(&secp, &mut signer));
    assert_eq!(failure.reason(), OrdinarySigningError::InvalidSignature);
}

#[test]
fn rejects_high_s_signature_even_when_ecdsa_valid() {
    let secp = Secp256k1::new();
    let (blinded, keys) = blinded_fixture(&secp);
    let mut signer = FixtureSigner::new(keys, Behavior::HighSignature(0));

    let failure = expect_signing_failure(blinded.sign_and_finalize(&secp, &mut signer));
    assert_eq!(
        failure.reason(),
        OrdinarySigningError::NonCanonicalSignature
    );
}

#[derive(Clone, Copy)]
enum Behavior {
    Normal,
    MissingPublicKey(usize),
    WrongPublicKey(usize),
    UncompressedPublicKey(usize),
    MissingSignature(usize),
    InvalidSignature(usize),
    HighSignature(usize),
}

struct FixtureSigner {
    keys: Vec<SecretKey>,
    wrong_key: SecretKey,
    behavior: Behavior,
    public_key_requests: Vec<OutPoint>,
    signature_requests: Vec<OutPoint>,
}

impl FixtureSigner {
    fn new(keys: Vec<SecretKey>, behavior: Behavior) -> Self {
        Self {
            keys,
            wrong_key: SecretKey::new(&mut thread_rng()),
            behavior,
            public_key_requests: Vec::new(),
            signature_requests: Vec::new(),
        }
    }
}

impl OrdinaryP2wpkhSigner for FixtureSigner {
    fn public_key(&mut self, input_index: usize, outpoint: &OutPoint) -> Option<BitcoinPublicKey> {
        self.public_key_requests.push(*outpoint);
        if matches!(self.behavior, Behavior::MissingPublicKey(index) if index == input_index) {
            return None;
        }
        let secp = Secp256k1::new();
        let key = if matches!(self.behavior, Behavior::WrongPublicKey(index) if index == input_index)
        {
            self.wrong_key.public_key(&secp)
        } else {
            self.keys[input_index].public_key(&secp)
        };
        if matches!(self.behavior, Behavior::UncompressedPublicKey(index) if index == input_index) {
            Some(BitcoinPublicKey::new_uncompressed(key))
        } else {
            Some(BitcoinPublicKey::new(key))
        }
    }

    fn sign_digest(
        &mut self,
        input_index: usize,
        outpoint: &OutPoint,
        digest: [u8; 32],
        sighash_type: EcdsaSighashType,
    ) -> Option<ecdsa::Signature> {
        self.signature_requests.push(*outpoint);
        assert_eq!(sighash_type, ORDINARY_SIGHASH);
        if matches!(self.behavior, Behavior::MissingSignature(index) if index == input_index) {
            return None;
        }
        let secp = Secp256k1::new();
        let signing_key = if matches!(self.behavior, Behavior::InvalidSignature(index) if index == input_index)
        {
            &self.wrong_key
        } else {
            &self.keys[input_index]
        };
        let signature = secp.sign_ecdsa(&Message::from_digest(digest), signing_key);
        if matches!(self.behavior, Behavior::HighSignature(index) if index == input_index) {
            Some(to_high_s(signature))
        } else {
            Some(signature)
        }
    }
}

fn blinded_fixture(secp: &Secp256k1<All>) -> (BlindedOrdinaryPset, Vec<SecretKey>) {
    let mut rng = thread_rng();
    let fee_asset = AssetId::from_byte_array([0x11; 32]);
    let second_asset = AssetId::from_byte_array([0x22; 32]);
    let signing_keys = vec![SecretKey::new(&mut rng), SecretKey::new(&mut rng)];

    let explicit_previous_output = TxOut {
        asset: elements::confidential::Asset::Explicit(fee_asset),
        value: Value::Explicit(50_000),
        nonce: elements::confidential::Nonce::Null,
        script_pubkey: p2wpkh_script(secp, &signing_keys[0]),
        witness: Default::default(),
    };
    let explicit_input = SpendableInput::from_explicit(
        OutPoint::new(Txid::from_byte_array([0x31; 32]), 0),
        explicit_previous_output,
        Sequence::MAX,
    )
    .unwrap();

    let opening_key = SecretKey::new(&mut rng);
    let confidential_secrets = TxOutSecrets::new(
        second_asset,
        AssetBlindingFactor::new(&mut rng),
        9_000,
        ValueBlindingFactor::new(&mut rng),
    );
    let domain_secrets = TxOutSecrets::new(
        second_asset,
        AssetBlindingFactor::new(&mut rng),
        10_000,
        ValueBlindingFactor::new(&mut rng),
    );
    let ephemeral_key = SecretKey::new(&mut rng);
    let confidential_previous_output = TxOut::with_txout_secrets(
        &mut rng,
        secp,
        p2wpkh_script(secp, &signing_keys[1]),
        opening_key.public_key(secp),
        ephemeral_key,
        confidential_secrets,
        &[domain_secrets],
    )
    .unwrap();
    let opening =
        open_confidential_output(secp, &confidential_previous_output, &opening_key).unwrap();
    let confidential_input = SpendableInput::from_confidential(
        secp,
        OutPoint::new(Txid::from_byte_array([0x32; 32]), 1),
        confidential_previous_output,
        Sequence::MAX,
        opening,
    )
    .unwrap();

    let address = ConfidentialLiquidAddress::parse(
        CONFIDENTIAL_RECEIVE_ADDRESS,
        LiquidAddressProfile::LiquidMainnet,
    )
    .unwrap();
    let prepared = prepare_ordinary_pset(
        vec![explicit_input, confidential_input],
        vec![
            ConfidentialOutput::from_address(fee_asset, 49_500, &address).unwrap(),
            ConfidentialOutput::from_address(second_asset, 9_000, &address).unwrap(),
        ],
        ExplicitFee::new(fee_asset, 500).unwrap(),
        LockTime::ZERO,
    )
    .unwrap();
    let blinded = prepared.blind(&mut rng, secp).unwrap();
    (blinded, signing_keys)
}

fn retained_previous_outputs(blinded: &BlindedOrdinaryPset) -> Vec<TxOut> {
    blinded
        .as_pset()
        .inputs()
        .iter()
        .map(|input| input.witness_utxo.clone().unwrap())
        .collect()
}

fn p2wpkh_script(secp: &Secp256k1<All>, secret_key: &SecretKey) -> Script {
    let public_key = BitcoinPublicKey::new(secret_key.public_key(secp));
    Script::new_v0_wpkh(&public_key.wpubkey_hash().unwrap())
}

fn witness_signature(transaction: &Transaction, input_index: usize) -> ecdsa::Signature {
    let witness = transaction.input[input_index]
        .witness
        .script_witness
        .to_vec();
    ecdsa::Signature::from_der(&witness[0][..witness[0].len() - 1]).unwrap()
}

fn to_high_s(signature: ecdsa::Signature) -> ecdsa::Signature {
    const CURVE_ORDER: [u8; 32] = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36,
        0x41, 0x41,
    ];

    let mut compact = signature.serialize_compact();
    let low_s = compact[32..].to_vec();
    let mut borrow = 0i16;
    for index in (0..32).rev() {
        let difference = CURVE_ORDER[index] as i16 - low_s[index] as i16 - borrow;
        if difference < 0 {
            compact[32 + index] = (difference + 256) as u8;
            borrow = 1;
        } else {
            compact[32 + index] = difference as u8;
            borrow = 0;
        }
    }
    assert_eq!(borrow, 0);
    ecdsa::Signature::from_compact(&compact).unwrap()
}

fn expect_signing_failure(
    result: Result<SignedOrdinaryPset, OrdinarySigningFailure>,
) -> OrdinarySigningFailure {
    match result {
        Ok(_) => panic!("signing unexpectedly succeeded"),
        Err(failure) => failure,
    }
}

fn expect_signed(result: Result<SignedOrdinaryPset, OrdinarySigningFailure>) -> SignedOrdinaryPset {
    match result {
        Ok(signed) => signed,
        Err(_) => panic!("signing unexpectedly failed"),
    }
}
