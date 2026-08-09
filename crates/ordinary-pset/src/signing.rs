use core::fmt;

use elements::bitcoin::PublicKey as BitcoinPublicKey;
use elements::encode;
use elements::secp256k1_zkp::{All, Message, Secp256k1, ecdsa};
use elements::sighash::{SighashCache, SighashRangeproofMode};
use elements::{EcdsaSighashType, OutPoint, Script, Transaction, Txid, Witness, Wtxid};

use super::{BlindedOrdinaryPset, validate_blinded_pset};

const ORDINARY_SIGHASH_TYPE: EcdsaSighashType = EcdsaSighashType::AllPlusRangeproof;

/// A local signing boundary for native P2WPKH ordinary-wallet inputs.
///
/// The implementation may retain keys in another wallet component, hardware
/// signer, or process. This crate requests only the compressed public key and
/// a signature over one already-computed digest. It never requests, receives,
/// copies, or stores the corresponding secret key.
///
/// Returning a signature does not make it authoritative. The product verifies
/// the public key against the exact previous-output script, rejects high-S
/// signatures, and verifies every signature before finalization.
pub trait OrdinaryP2wpkhSigner {
    /// Returns the compressed public key expected to own one P2WPKH input.
    ///
    /// `None` is treated as a fail-closed signer refusal. The method is called
    /// for every input and every returned key is ownership-checked before any
    /// signing request is issued.
    fn public_key(&mut self, input_index: usize, outpoint: &OutPoint) -> Option<BitcoinPublicKey>;

    /// Signs one 32-byte Elements signature digest.
    ///
    /// `sighash_type` is always
    /// [`EcdsaSighashType::AllPlusRangeproof`]. `None` is treated as a
    /// fail-closed refusal. The returned signature must be strict DER
    /// serializable, low-S, and valid for the public key previously returned
    /// for the same input.
    fn sign_digest(
        &mut self,
        input_index: usize,
        outpoint: &OutPoint,
        digest: [u8; 32],
        sighash_type: EcdsaSighashType,
    ) -> Option<ecdsa::Signature>;
}

/// A signed and finalized ordinary-wallet PSET.
///
/// This type deliberately does not implement `Debug`, `Clone`, or `Copy` and
/// exposes no mutable PSET access. The retained PSET is useful for local wallet
/// persistence and review, but remains sensitive because its output maps carry
/// explicit recipient assets and amounts. A consuming transition removes that
/// metadata and yields only the already-validated broadcast transaction.
pub struct SignedOrdinaryPset {
    pset: elements::pset::PartiallySignedTransaction,
    transaction: Transaction,
}

impl SignedOrdinaryPset {
    /// Borrows the signed PSET without granting mutation.
    pub const fn as_pset(&self) -> &elements::pset::PartiallySignedTransaction {
        &self.pset
    }

    /// Borrows the finalized transaction extracted from the signed PSET.
    pub const fn transaction(&self) -> &Transaction {
        &self.transaction
    }

    /// Serializes the signed PSET for local wallet persistence or review.
    ///
    /// These bytes contain explicit recipient asset and amount metadata and
    /// must not be treated as the confidential broadcast representation.
    pub fn serialize_sensitive(&self) -> Vec<u8> {
        encode::serialize(&self.pset)
    }

    /// Consumes the signed PSET and retains only the finalized transaction.
    pub fn into_finalized_transaction(self) -> FinalizedOrdinaryTransaction {
        FinalizedOrdinaryTransaction {
            transaction: self.transaction,
        }
    }
}

/// A completely signed ordinary transaction ready for a later broadcast
/// boundary.
///
/// This type deliberately does not implement `Debug`, `Clone`, or `Copy` and
/// exposes no mutable transaction access. Construction proves native P2WPKH
/// witness shape, strict low-S signatures, range-proof-committing sighashes,
/// unchanged transaction fields, and confidential amount-proof validity. It
/// does not authenticate a node, chain, current unspentness, fee policy, or
/// broadcast acceptance.
pub struct FinalizedOrdinaryTransaction {
    transaction: Transaction,
}

impl FinalizedOrdinaryTransaction {
    /// Borrows the finalized transaction without granting mutation.
    pub const fn transaction(&self) -> &Transaction {
        &self.transaction
    }

    /// Returns the non-witness transaction identifier.
    pub fn txid(&self) -> Txid {
        self.transaction.txid()
    }

    /// Returns the witness transaction identifier.
    pub fn wtxid(&self) -> Wtxid {
        self.transaction.wtxid()
    }

    /// Serializes the finalized confidential transaction for a later broadcast
    /// boundary.
    ///
    /// Unlike serialized PSET data, these bytes do not contain the PSET output
    /// maps' explicit recipient asset and amount fields.
    pub fn serialize_for_broadcast(&self) -> Vec<u8> {
        encode::serialize(&self.transaction)
    }
}

impl BlindedOrdinaryPset {
    /// Signs and finalizes every native P2WPKH input through a caller-owned
    /// signing boundary.
    ///
    /// The blinded capability is consumed. All public keys are obtained and
    /// matched to their previous-output scripts before the first digest is
    /// submitted for signing. Signatures are applied only after every returned
    /// signature has passed product-owned low-S and cryptographic verification.
    /// On a fail-closed refusal or validation error,
    /// [`OrdinarySigningFailure::into_blinded`] returns the same unmodified
    /// capability for an explicit retry decision.
    pub fn sign_and_finalize<S>(
        self,
        secp: &Secp256k1<All>,
        signer: &mut S,
    ) -> Result<SignedOrdinaryPset, OrdinarySigningFailure>
    where
        S: OrdinaryP2wpkhSigner,
    {
        let final_witnesses = match prepare_final_witnesses(&self, secp, signer) {
            Ok(witnesses) => witnesses,
            Err(reason) => return Err(OrdinarySigningFailure::new(reason, self)),
        };

        let BlindedOrdinaryPset {
            mut pset,
            confidential_output_indices,
            fee_output_index,
        } = self;
        let unsigned_transaction = match pset.extract_tx() {
            Ok(transaction) => transaction,
            Err(_) => {
                return Err(OrdinarySigningFailure::new(
                    OrdinarySigningError::InvalidBlindedPset,
                    BlindedOrdinaryPset {
                        pset,
                        confidential_output_indices,
                        fee_output_index,
                    },
                ));
            }
        };
        let previous_outputs = pset
            .inputs()
            .iter()
            .map(|input| input.witness_utxo.clone())
            .collect::<Option<Vec<_>>>()
            .expect("preflight requires every witness UTXO");

        for (input, witness) in pset.inputs_mut().iter_mut().zip(final_witnesses.iter()) {
            input.final_script_witness = Some(witness.clone());
        }
        let finalization_result = validate_finalized_pset(
            secp,
            &pset,
            unsigned_transaction,
            &previous_outputs,
            final_witnesses,
        );
        match finalization_result {
            Ok(transaction) => Ok(SignedOrdinaryPset { pset, transaction }),
            Err(reason) => {
                for input in pset.inputs_mut() {
                    input.final_script_witness = None;
                }
                Err(OrdinarySigningFailure::new(
                    reason,
                    BlindedOrdinaryPset {
                        pset,
                        confidential_output_indices,
                        fee_output_index,
                    },
                ))
            }
        }
    }
}

fn prepare_final_witnesses<S>(
    blinded: &BlindedOrdinaryPset,
    secp: &Secp256k1<All>,
    signer: &mut S,
) -> Result<Vec<Witness>, OrdinarySigningError>
where
    S: OrdinaryP2wpkhSigner,
{
    validate_blinded_pset(
        secp,
        &blinded.pset,
        &blinded.confidential_output_indices,
        blinded.fee_output_index,
    )
    .map_err(|_| OrdinarySigningError::InvalidBlindedPset)?;
    validate_signable_pset(&blinded.pset)?;

    let unsigned_transaction = blinded
        .pset
        .extract_tx()
        .map_err(|_| OrdinarySigningError::InvalidBlindedPset)?;
    let previous_outputs = blinded
        .pset
        .inputs()
        .iter()
        .map(|input| input.witness_utxo.clone())
        .collect::<Option<Vec<_>>>()
        .ok_or(OrdinarySigningError::InvalidBlindedPset)?;

    let mut public_keys = Vec::with_capacity(blinded.pset.inputs().len());
    for (input_index, input) in blinded.pset.inputs().iter().enumerate() {
        let outpoint = input.previous_outpoint();
        let public_key = signer
            .public_key(input_index, &outpoint)
            .ok_or(OrdinarySigningError::PublicKeyUnavailable)?;
        let witness_hash = public_key
            .wpubkey_hash()
            .map_err(|_| OrdinarySigningError::UncompressedPublicKey)?;
        if Script::new_v0_wpkh(&witness_hash) != previous_outputs[input_index].script_pubkey {
            return Err(OrdinarySigningError::PublicKeyDoesNotOwnInput);
        }
        public_keys.push(public_key);
    }

    let mut final_witnesses = Vec::with_capacity(blinded.pset.inputs().len());
    let mut sighash_cache = SighashCache::new(&unsigned_transaction);
    for (input_index, input) in blinded.pset.inputs().iter().enumerate() {
        let public_key = public_keys[input_index];
        let script_code = Script::new_p2pkh(&public_key.pubkey_hash());
        let digest = sighash_cache
            .segwitv0_sighash_with_rangeproof_mode(
                input_index,
                &script_code,
                previous_outputs[input_index].value,
                ORDINARY_SIGHASH_TYPE,
                SighashRangeproofMode::Enabled,
            )
            .to_byte_array();
        let signature = signer
            .sign_digest(
                input_index,
                &input.previous_outpoint(),
                digest,
                ORDINARY_SIGHASH_TYPE,
            )
            .ok_or(OrdinarySigningError::SignatureUnavailable)?;
        let mut normalized = signature;
        normalized.normalize_s();
        if normalized != signature {
            return Err(OrdinarySigningError::NonCanonicalSignature);
        }
        secp.verify_ecdsa(&Message::from_digest(digest), &signature, &public_key.inner)
            .map_err(|_| OrdinarySigningError::InvalidSignature)?;

        let mut signature_bytes = signature.serialize_der().to_vec();
        signature_bytes.push(ORDINARY_SIGHASH_TYPE.as_u32() as u8);
        if signature_bytes.len() > 73 {
            return Err(OrdinarySigningError::NonCanonicalSignature);
        }
        final_witnesses.push(Witness::from_slice(&[
            signature_bytes,
            public_key.to_bytes(),
        ]));
    }
    Ok(final_witnesses)
}

fn validate_finalized_pset(
    secp: &Secp256k1<All>,
    pset: &elements::pset::PartiallySignedTransaction,
    mut expected_transaction: Transaction,
    previous_outputs: &[elements::TxOut],
    final_witnesses: Vec<Witness>,
) -> Result<Transaction, OrdinarySigningError> {
    let finalized_transaction = pset
        .extract_tx()
        .map_err(|_| OrdinarySigningError::FinalizationFailed)?;
    for (input, witness) in expected_transaction.input.iter_mut().zip(final_witnesses) {
        input.witness.script_witness = witness;
    }
    if finalized_transaction != expected_transaction {
        return Err(OrdinarySigningError::FinalizationFailed);
    }
    validate_final_signatures(secp, &finalized_transaction, previous_outputs)?;
    finalized_transaction
        .verify_tx_amt_proofs(secp, previous_outputs)
        .map_err(|_| OrdinarySigningError::FinalizationFailed)?;
    Ok(finalized_transaction)
}

fn validate_signable_pset(
    pset: &elements::pset::PartiallySignedTransaction,
) -> Result<(), OrdinarySigningError> {
    if pset.global.version != 2
        || pset.global.tx_data.version != 2
        || pset.global.tx_data.tx_modifiable.is_some()
        || !pset.global.xpub.is_empty()
        || !pset.global.scalars.is_empty()
        || pset.global.elements_tx_modifiable_flag.is_some()
        || !pset.global.proprietary.is_empty()
        || !pset.global.unknown.is_empty()
        || pset.inputs().is_empty()
    {
        return Err(OrdinarySigningError::InvalidBlindedPset);
    }
    for input in pset.inputs() {
        let witness_utxo = input
            .witness_utxo
            .as_ref()
            .ok_or(OrdinarySigningError::InvalidBlindedPset)?;
        if !witness_utxo.script_pubkey.is_v0_p2wpkh()
            || !witness_utxo.witness.rangeproof.is_empty()
            || !witness_utxo.witness.surjection_proof.is_empty()
            || input.non_witness_utxo.is_some()
            || input.sighash_type != Some(ORDINARY_SIGHASH_TYPE.into())
            || !input.partial_sigs.is_empty()
            || input.final_script_sig.is_some()
            || input.final_script_witness.is_some()
            || input.redeem_script.is_some()
            || input.witness_script.is_some()
            || !input.bip32_derivation.is_empty()
            || !input.ripemd160_preimages.is_empty()
            || !input.sha256_preimages.is_empty()
            || !input.hash160_preimages.is_empty()
            || !input.hash256_preimages.is_empty()
            || input.required_time_locktime.is_some()
            || input.required_height_locktime.is_some()
            || input.tap_key_sig.is_some()
            || !input.tap_script_sigs.is_empty()
            || !input.tap_scripts.is_empty()
            || !input.tap_key_origins.is_empty()
            || input.tap_internal_key.is_some()
            || input.tap_merkle_root.is_some()
            || input.issuance_value_amount.is_some()
            || input.issuance_value_comm.is_some()
            || input.issuance_value_rangeproof.is_some()
            || input.issuance_keys_rangeproof.is_some()
            || input.pegin_tx.is_some()
            || input.pegin_txout_proof.is_some()
            || input.pegin_genesis_hash.is_some()
            || input.pegin_claim_script.is_some()
            || input.pegin_value.is_some()
            || input.pegin_witness.is_some()
            || input.issuance_inflation_keys.is_some()
            || input.issuance_inflation_keys_comm.is_some()
            || input.issuance_blinding_nonce.is_some()
            || input.issuance_asset_entropy.is_some()
            || input.in_issuance_blind_value_proof.is_some()
            || input.in_issuance_blind_inflation_keys_proof.is_some()
            || input.amount.is_some()
            || input.blind_value_proof.is_some()
            || input.asset.is_some()
            || input.blind_asset_proof.is_some()
            || input.blinded_issuance.is_some()
            || !input.proprietary.is_empty()
            || !input.unknown.is_empty()
        {
            return Err(OrdinarySigningError::InvalidBlindedPset);
        }
        if witness_utxo.value.is_confidential()
            != input
                .in_utxo_rangeproof
                .as_ref()
                .is_some_and(|proof| !proof.is_empty())
        {
            return Err(OrdinarySigningError::InvalidBlindedPset);
        }
    }
    for output in pset.outputs() {
        if output.redeem_script.is_some()
            || output.witness_script.is_some()
            || !output.bip32_derivation.is_empty()
            || output.tap_internal_key.is_some()
            || output.tap_tree.is_some()
            || !output.tap_key_origins.is_empty()
            || !output.proprietary.is_empty()
            || !output.unknown.is_empty()
        {
            return Err(OrdinarySigningError::InvalidBlindedPset);
        }
    }
    Ok(())
}

fn validate_final_signatures(
    secp: &Secp256k1<All>,
    transaction: &Transaction,
    previous_outputs: &[elements::TxOut],
) -> Result<(), OrdinarySigningError> {
    if transaction.input.len() != previous_outputs.len() {
        return Err(OrdinarySigningError::FinalizationFailed);
    }

    let mut sighash_cache = SighashCache::new(transaction);
    for (input_index, (input, previous_output)) in
        transaction.input.iter().zip(previous_outputs).enumerate()
    {
        if !input.script_sig.is_empty()
            || input.is_pegin
            || !input.asset_issuance.is_null()
            || !input.witness.amount_rangeproof.is_empty()
            || !input.witness.inflation_keys_rangeproof.is_empty()
            || !input.witness.pegin_witness.is_empty()
        {
            return Err(OrdinarySigningError::FinalizationFailed);
        }

        let witness = input.witness.script_witness.to_vec();
        if witness.len() != 2 || witness[0].len() < 2 {
            return Err(OrdinarySigningError::FinalizationFailed);
        }
        let (sighash_byte, der_signature) = witness[0]
            .split_last()
            .ok_or(OrdinarySigningError::FinalizationFailed)?;
        if *sighash_byte != ORDINARY_SIGHASH_TYPE.as_u32() as u8 {
            return Err(OrdinarySigningError::FinalizationFailed);
        }
        let signature = ecdsa::Signature::from_der(der_signature)
            .map_err(|_| OrdinarySigningError::FinalizationFailed)?;
        if signature.serialize_der().as_ref() != der_signature {
            return Err(OrdinarySigningError::FinalizationFailed);
        }
        let mut normalized = signature;
        normalized.normalize_s();
        if normalized != signature {
            return Err(OrdinarySigningError::FinalizationFailed);
        }
        let public_key = BitcoinPublicKey::from_slice(&witness[1])
            .map_err(|_| OrdinarySigningError::FinalizationFailed)?;
        let witness_hash = public_key
            .wpubkey_hash()
            .map_err(|_| OrdinarySigningError::FinalizationFailed)?;
        if Script::new_v0_wpkh(&witness_hash) != previous_output.script_pubkey {
            return Err(OrdinarySigningError::FinalizationFailed);
        }

        let script_code = Script::new_p2pkh(&public_key.pubkey_hash());
        let digest = sighash_cache.segwitv0_sighash_with_rangeproof_mode(
            input_index,
            &script_code,
            previous_output.value,
            ORDINARY_SIGHASH_TYPE,
            SighashRangeproofMode::Enabled,
        );
        let message = Message::from_digest(digest.to_byte_array());
        secp.verify_ecdsa(&message, &signature, &public_key.inner)
            .map_err(|_| OrdinarySigningError::FinalizationFailed)?;
    }
    Ok(())
}

/// A signing failure that retains the exact unmodified blinded capability.
///
/// This type deliberately does not implement `Debug`, `Clone`, or `Copy`.
/// Inspect [`Self::reason`] before making an explicit decision to discard or
/// retry the returned capability.
pub struct OrdinarySigningFailure {
    reason: OrdinarySigningError,
    blinded: Box<BlindedOrdinaryPset>,
}

impl OrdinarySigningFailure {
    fn new(reason: OrdinarySigningError, blinded: BlindedOrdinaryPset) -> Self {
        Self {
            reason,
            blinded: Box::new(blinded),
        }
    }

    /// Returns the privacy-redacted failure reason.
    pub const fn reason(&self) -> OrdinarySigningError {
        self.reason
    }

    /// Recovers the exact unmodified blinded capability for an explicit retry
    /// or discard decision.
    pub fn into_blinded(self) -> BlindedOrdinaryPset {
        *self.blinded
    }
}

/// A fail-closed ordinary-wallet signing or finalization failure.
///
/// Variants deliberately contain no key, signature, digest, script, amount,
/// asset, address, or PSET data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum OrdinarySigningError {
    /// The internally produced blinded capability no longer met its invariants.
    InvalidBlindedPset,
    /// The caller-owned signer refused or could not locate a public key.
    PublicKeyUnavailable,
    /// Native P2WPKH requires a compressed public key.
    UncompressedPublicKey,
    /// The returned public key did not commit to the previous-output script.
    PublicKeyDoesNotOwnInput,
    /// The caller-owned signer refused or could not create a signature.
    SignatureUnavailable,
    /// The signer returned a high-S signature rejected by wallet policy.
    NonCanonicalSignature,
    /// The signer returned a signature invalid for the exact protected digest.
    InvalidSignature,
    /// The locally finalized transaction failed a structural or proof check.
    FinalizationFailed,
}

impl fmt::Display for OrdinarySigningError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidBlindedPset => "ordinary blinded PSET invariant failed",
            Self::PublicKeyUnavailable => "ordinary signer public key is unavailable",
            Self::UncompressedPublicKey => "ordinary signer public key is not compressed",
            Self::PublicKeyDoesNotOwnInput => "ordinary signer public key does not own input",
            Self::SignatureUnavailable => "ordinary signer signature is unavailable",
            Self::NonCanonicalSignature => "ordinary signer signature is not canonical",
            Self::InvalidSignature => "ordinary signer signature is invalid",
            Self::FinalizationFailed => "ordinary transaction finalization failed",
        })
    }
}

impl std::error::Error for OrdinarySigningError {}

#[cfg(test)]
mod tests {
    use elements::confidential::{Asset, Nonce, Value};
    use elements::pset::{
        Input as PsetInput, Output as PsetOutput, PartiallySignedTransaction, PsbtSighashType, raw,
    };
    use elements::{AssetId, OutPoint, Script, Sequence, TxOut, Txid, Witness};

    use super::{ORDINARY_SIGHASH_TYPE, validate_signable_pset};

    #[test]
    fn canonical_preflight_rejects_nonconstructor_field_classes_and_sighashes() {
        let canonical = canonical_signable_shape();
        assert!(validate_signable_pset(&canonical).is_ok());

        assert_rejected(&canonical, |pset| {
            pset.global.tx_data.tx_modifiable = Some(0)
        });
        assert_rejected(&canonical, |pset| {
            pset.global.elements_tx_modifiable_flag = Some(0)
        });
        assert_rejected(&canonical, |pset| {
            pset.global.unknown.insert(
                raw::Key {
                    type_value: 0xfa,
                    key: vec![1],
                },
                vec![2],
            );
        });
        for raw_sighash in [0x01, 0x61, 0xc1] {
            assert_rejected(&canonical, |pset| {
                pset.inputs_mut()[0].sighash_type = Some(PsbtSighashType::from_u32(raw_sighash));
            });
        }
        assert_rejected(&canonical, |pset| {
            pset.inputs_mut()[0].final_script_witness = Some(Witness::default())
        });
        assert_rejected(&canonical, |pset| {
            pset.inputs_mut()[0].issuance_value_amount = Some(1)
        });
        assert_rejected(&canonical, |pset| {
            pset.inputs_mut()[0].pegin_value = Some(1)
        });
        assert_rejected(&canonical, |pset| pset.inputs_mut()[0].amount = Some(1));
        assert_rejected(&canonical, |pset| {
            pset.inputs_mut()[0].unknown.insert(
                raw::Key {
                    type_value: 0xfa,
                    key: vec![1],
                },
                vec![2],
            );
        });
        assert_rejected(&canonical, |pset| {
            pset.outputs_mut()[0].redeem_script = Some(Script::new())
        });
        assert_rejected(&canonical, |pset| {
            pset.outputs_mut()[0].unknown.insert(
                raw::Key {
                    type_value: 0xfa,
                    key: vec![1],
                },
                vec![2],
            );
        });
    }

    fn canonical_signable_shape() -> PartiallySignedTransaction {
        let asset = AssetId::from_byte_array([0x11; 32]);
        let script = Script::from([vec![0x00, 0x14], vec![0x42; 20]].concat());
        let mut pset = PartiallySignedTransaction::new_v2();
        let mut input =
            PsetInput::from_prevout(OutPoint::new(Txid::from_byte_array([0x31; 32]), 0));
        input.sequence = Some(Sequence::MAX);
        input.sighash_type = Some(ORDINARY_SIGHASH_TYPE.into());
        input.witness_utxo = Some(TxOut {
            asset: Asset::Explicit(asset),
            value: Value::Explicit(1_000),
            nonce: Nonce::Null,
            script_pubkey: script.clone(),
            witness: Default::default(),
        });
        pset.add_input(input);
        pset.add_output(PsetOutput::new_explicit(script, 900, asset, None));
        pset
    }

    fn assert_rejected(
        canonical: &PartiallySignedTransaction,
        mutate: impl FnOnce(&mut PartiallySignedTransaction),
    ) {
        let mut mutated = canonical.clone();
        mutate(&mut mutated);
        assert!(validate_signable_pset(&mutated).is_err());
    }
}
