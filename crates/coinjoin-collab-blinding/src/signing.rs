use core::fmt;

use elements::bitcoin::PublicKey as BitcoinPublicKey;
use elements::pset::PartiallySignedTransaction;
use elements::secp256k1_zkp::{All, Message, Secp256k1, ecdsa};
use elements::sighash::{SighashCache, SighashRangeproofMode};
use elements::{EcdsaSighashType, OutPoint, Script, Transaction, Witness};
use wasabi_liquid_native_coinjoin_pset_state::Phase;

use super::{CanonicalStateContext, canonical_accept_final, decode_handoff};

const SIGHASH: EcdsaSighashType = EcdsaSighashType::AllPlusRangeproof;

/// One input and the compressed key authorized to sign it.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct AuthorizedInput {
    /// PSET input index.
    pub index: usize,
    /// Independently authorized outpoint at this exact input index.
    pub outpoint: OutPoint,
    /// Key whose P2WPKH script must own the input's previous output.
    pub public_key: BitcoinPublicKey,
}

/// Caller-owned signing callback for one participant's inputs.
pub trait CollabP2wpkhSigner {
    /// Sign the original 32 digest bytes for an owned input, without reversal.
    /// Return strict DER plus `0x41`; high-S signatures are rejected, not normalized.
    fn sign_digest(
        &mut self,
        input_index: usize,
        outpoint: &OutPoint,
        digest: [u8; 32],
        sighash_type: EcdsaSighashType,
    ) -> Option<Vec<u8>>;
}

/// Immutable accepted final-PSET capability used by the signing round.
pub struct SigningCapability {
    pset: PartiallySignedTransaction,
    digest: [u8; 32],
    transaction: Transaction,
    authorized: Vec<AuthorizedInput>,
}

impl SigningCapability {
    /// Returns the caller-approved canonical state digest, including its context.
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }

    /// Returns original signing digest bytes in `owned` order after validating
    /// the entire nonempty subset. This exposes no keys and admits no signatures.
    pub fn owned_digests(&self, owned: &[AuthorizedInput]) -> Result<Vec<[u8; 32]>, SigningError> {
        if owned.is_empty() || owned.len() > self.authorized.len() {
            return Err(SigningError::AuthorizationRejected);
        }
        let mut seen = vec![false; self.authorized.len()];
        for auth in owned {
            if !self.authorized.contains(auth) || seen[auth.index] {
                return Err(SigningError::AuthorizationRejected);
            }
            seen[auth.index] = true;
        }
        owned
            .iter()
            .map(|auth| {
                let prevout = self.pset.inputs()[auth.index]
                    .witness_utxo
                    .as_ref()
                    .ok_or(SigningError::AuthorizationRejected)?;
                Ok(input_digest(&self.transaction, auth, prevout.value))
            })
            .collect()
    }
}

/// A detached signature contribution for exactly one authorized input.
#[derive(Clone, PartialEq, Eq)]
pub struct SignedInputContribution {
    digest: [u8; 32],
    index: usize,
    public_key: BitcoinPublicKey,
    signature: Vec<u8>,
}

impl SignedInputContribution {
    /// Returns the canonical state digest this contribution was admitted against.
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }

    /// Input index covered by this contribution.
    pub const fn index(&self) -> usize {
        self.index
    }

    /// Compressed public key used to verify the signature.
    pub const fn public_key(&self) -> BitcoinPublicKey {
        self.public_key
    }

    /// Strict DER signature followed by `SIGHASH_ALL|RANGEPROOF`.
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }
}

/// Final transaction produced without changing any transaction or output field.
pub struct FinalizedCollaborativeTransaction {
    transaction: Transaction,
}

impl FinalizedCollaborativeTransaction {
    /// Borrows the finalized transaction.
    pub const fn transaction(&self) -> &Transaction {
        &self.transaction
    }
    /// Returns the transaction identifier.
    pub fn txid(&self) -> elements::Txid {
        self.transaction.txid()
    }
}

/// Redacted errors for the bounded collaborative signing bridge.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum SigningError {
    /// The final PSET or canonical caller context was rejected.
    InvalidFinalState,
    /// The caller's expected digest did not match the accepted PSET.
    DigestMismatch,
    /// Authorized indices, keys, or previous-output scripts were invalid.
    AuthorizationRejected,
    /// The callback refused to sign.
    SignerRefused,
    /// The callback returned a malformed or invalid signature.
    SignatureRejected,
    /// Contributions were missing, duplicated, foreign, or inconsistent.
    ContributionSetRejected,
    /// Amount proofs or final extraction failed.
    FinalizationRejected,
}

impl fmt::Display for SigningError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidFinalState => "final PSET rejected",
            Self::DigestMismatch => "canonical digest mismatch",
            Self::AuthorizationRejected => "input authorization rejected",
            Self::SignerRefused => "signer refused",
            Self::SignatureRejected => "signature rejected",
            Self::ContributionSetRejected => "signature contribution set rejected",
            Self::FinalizationRejected => "finalization rejected",
        })
    }
}
impl std::error::Error for SigningError {}

/// Accepts bounded canonical wire bytes and freezes the actual final PSET.
///
/// The caller must independently approve `expected_digest` in `context`, which
/// binds the complete ordered input/prevout domain and output body. Recomputing
/// approval from an untrusted candidate is not participant authorization.
/// Canonical validation owns field/proof/fee policy; this bridge additionally
/// requires the final lifecycle, full surjection domain, and amount balance.
pub fn accept_signing_capability(
    raw_pset: &[u8],
    context: &CanonicalStateContext<'_>,
    expected_digest: [u8; 32],
    authorized: &[AuthorizedInput],
) -> Result<SigningCapability, SigningError> {
    let pset = decode_handoff(raw_pset).map_err(|_| SigningError::InvalidFinalState)?;
    if context.phase != Phase::PreSigning || !pset.global.scalars.is_empty() {
        return Err(SigningError::InvalidFinalState);
    }
    let canonical =
        canonical_accept_final(&pset, context).map_err(|_| SigningError::InvalidFinalState)?;
    if canonical.digest().into_bytes() != expected_digest {
        return Err(SigningError::DigestMismatch);
    }
    // Canonical projection also admits construction and intermediate states.
    let confidential_outputs: Vec<_> = pset
        .outputs()
        .iter()
        .enumerate()
        .filter(|(_, output)| output.blinding_key.is_some())
        .map(|(index, _)| index)
        .collect();
    if confidential_outputs.is_empty()
        || confidential_outputs
            .iter()
            .any(|&index| !pset.outputs()[index].is_fully_blinded())
    {
        return Err(SigningError::InvalidFinalState);
    }
    let secp = Secp256k1::new();
    pset.verify_all_surjection_proofs_use_all_inputs(&secp, &confidential_outputs)
        .map_err(|_| SigningError::InvalidFinalState)?;
    let transaction = pset
        .extract_tx()
        .map_err(|_| SigningError::FinalizationRejected)?;
    if authorized.len() != pset.inputs().len() {
        return Err(SigningError::AuthorizationRejected);
    }
    let mut seen = vec![false; pset.inputs().len()];
    for auth in authorized {
        if auth.index >= pset.inputs().len() || seen[auth.index] {
            return Err(SigningError::AuthorizationRejected);
        }
        let input = &pset.inputs()[auth.index];
        if auth.outpoint != input.previous_outpoint() {
            return Err(SigningError::AuthorizationRejected);
        }
        let prevout = input
            .witness_utxo
            .as_ref()
            .ok_or(SigningError::AuthorizationRejected)?;
        let hash = auth
            .public_key
            .wpubkey_hash()
            .map_err(|_| SigningError::AuthorizationRejected)?;
        if Script::new_v0_wpkh(&hash) != prevout.script_pubkey || !prevout.witness.is_empty() {
            return Err(SigningError::AuthorizationRejected);
        }
        seen[auth.index] = true;
    }
    let prevouts: Vec<_> = pset
        .inputs()
        .iter()
        .map(|input| input.witness_utxo.clone().expect("validated witness UTXO"))
        .collect();
    transaction
        .verify_tx_amt_proofs(&secp, &prevouts)
        .map_err(|_| SigningError::InvalidFinalState)?;
    Ok(SigningCapability {
        pset,
        digest: expected_digest,
        transaction,
        authorized: authorized.to_vec(),
    })
}

/// Signs only the indices present in `owned`, without exposing other inputs to the callback.
pub fn sign_owned_inputs<S: CollabP2wpkhSigner>(
    capability: &SigningCapability,
    owned: &[AuthorizedInput],
    signer: &mut S,
) -> Result<Vec<SignedInputContribution>, SigningError> {
    // Validate the whole subset before the first callback, including duplicates.
    let digests = capability.owned_digests(owned)?;
    let secp = Secp256k1::<All>::new();
    let mut result = Vec::with_capacity(owned.len());
    for (auth, digest) in owned.iter().zip(digests) {
        let input = &capability.pset.inputs()[auth.index];
        let signature = signer
            .sign_digest(auth.index, &input.previous_outpoint(), digest, SIGHASH)
            .ok_or(SigningError::SignerRefused)?;
        verify_signature(&secp, digest, auth.public_key, &signature)?;
        result.push(SignedInputContribution {
            digest: capability.digest,
            index: auth.index,
            public_key: auth.public_key,
            signature,
        });
    }
    Ok(result)
}

/// Assembles exactly one authorized contribution per input and verifies proofs and signatures.
pub fn assemble_signatures(
    capability: &SigningCapability,
    contributions: &[SignedInputContribution],
) -> Result<FinalizedCollaborativeTransaction, SigningError> {
    if contributions.len() != capability.authorized.len() {
        return Err(SigningError::ContributionSetRejected);
    }
    let secp = Secp256k1::<All>::new();
    let mut pset = capability.pset.clone();
    let mut expected_transaction = capability.transaction.clone();
    let mut seen = vec![false; pset.inputs().len()];
    for contribution in contributions {
        let auth = capability
            .authorized
            .iter()
            .find(|x| x.index == contribution.index && x.public_key == contribution.public_key)
            .ok_or(SigningError::ContributionSetRejected)?;
        if seen[auth.index] || contribution.digest != capability.digest {
            return Err(SigningError::ContributionSetRejected);
        }
        let input = &pset.inputs()[auth.index];
        let prevout = input
            .witness_utxo
            .as_ref()
            .ok_or(SigningError::FinalizationRejected)?;
        verify_signature(
            &secp,
            input_digest(&capability.transaction, auth, prevout.value),
            auth.public_key,
            &contribution.signature,
        )?;
        let witness =
            Witness::from_slice(&[contribution.signature.clone(), auth.public_key.to_bytes()]);
        expected_transaction.input[auth.index]
            .witness
            .script_witness = witness.clone();
        pset.inputs_mut()[auth.index].final_script_witness = Some(witness);
        seen[auth.index] = true;
    }
    let transaction = pset
        .extract_tx()
        .map_err(|_| SigningError::FinalizationRejected)?;
    if transaction != expected_transaction || transaction.txid() != capability.transaction.txid() {
        return Err(SigningError::FinalizationRejected);
    }
    let prevouts = capability
        .pset
        .inputs()
        .iter()
        .map(|i| i.witness_utxo.clone())
        .collect::<Option<Vec<_>>>()
        .ok_or(SigningError::FinalizationRejected)?;
    for auth in &capability.authorized {
        let witness = transaction.input[auth.index]
            .witness
            .script_witness
            .to_vec();
        if witness.len() != 2 || witness[1] != auth.public_key.to_bytes() {
            return Err(SigningError::FinalizationRejected);
        }
        verify_signature(
            &secp,
            input_digest(&transaction, auth, prevouts[auth.index].value),
            auth.public_key,
            &witness[0],
        )?;
    }
    transaction
        .verify_tx_amt_proofs(&secp, &prevouts)
        .map_err(|_| SigningError::FinalizationRejected)?;
    Ok(FinalizedCollaborativeTransaction { transaction })
}

fn input_digest(
    transaction: &Transaction,
    auth: &AuthorizedInput,
    value: elements::confidential::Value,
) -> [u8; 32] {
    SighashCache::new(transaction)
        .segwitv0_sighash_with_rangeproof_mode(
            auth.index,
            &Script::new_p2pkh(&auth.public_key.pubkey_hash()),
            value,
            SIGHASH,
            SighashRangeproofMode::Enabled,
        )
        .to_byte_array()
}

fn verify_signature(
    secp: &Secp256k1<All>,
    digest: [u8; 32],
    public_key: BitcoinPublicKey,
    bytes: &[u8],
) -> Result<(), SigningError> {
    if bytes.len() > 73 {
        return Err(SigningError::SignatureRejected);
    }
    let (sighash, der) = bytes.split_last().ok_or(SigningError::SignatureRejected)?;
    if *sighash != SIGHASH.as_u32() as u8 {
        return Err(SigningError::SignatureRejected);
    }
    let signature = ecdsa::Signature::from_der(der).map_err(|_| SigningError::SignatureRejected)?;
    let mut low = signature;
    low.normalize_s();
    if signature.serialize_der().as_ref() != der || low != signature {
        return Err(SigningError::SignatureRejected);
    }
    secp.verify_ecdsa(&Message::from_digest(digest), &signature, &public_key.inner)
        .map_err(|_| SigningError::SignatureRejected)
}
