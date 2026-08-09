#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Construction of an unblinded PSET for an ordinary multiasset Liquid spend.
//!
//! The constructed PSET has confidential recipient outputs marked for a later
//! blinding transition and exactly one explicit fee output. Confidential input
//! openings are retained only in a product-owned, zeroized capability and are
//! not copied into serialized PSET input maps.
//!
//! This crate does not authenticate a node, chain, previous-output provenance,
//! current unspentness, script ownership, or the fee asset. It does not sign,
//! finalize, extract for broadcast, or submit a transaction.

use core::fmt;
use std::collections::HashMap;
use std::hint::black_box;

use elements::bitcoin::PublicKey as BitcoinPublicKey;
use elements::confidential::{Asset, AssetBlindingFactor, Nonce, Value, ValueBlindingFactor};
use elements::encode;
use elements::pset::{Input as PsetInput, Output as PsetOutput, PartiallySignedTransaction};
use elements::secp256k1_zkp::rand::{CryptoRng, RngCore};
use elements::secp256k1_zkp::{All, Secp256k1};
use elements::{
    AssetId, EcdsaSighashType, LockTime, OutPoint, Script, Sequence, TxOut, TxOutSecrets,
};
use wasabi_liquid_native_address::ConfidentialLiquidAddress;
use wasabi_liquid_native_output_opening::OpenedOutput;
use zeroize::Zeroize;

mod signing;

pub use signing::{
    FinalizedOrdinaryTransaction, OrdinaryP2wpkhSigner, OrdinarySigningError,
    OrdinarySigningFailure, SignedOrdinaryPset,
};

/// Maximum inputs accepted by the ordinary-wallet constructor.
///
/// This matches the complete surjection-proof input-domain limit used by the
/// pinned confidential-transaction implementation. Issuance inputs are not
/// supported by this constructor.
pub const MAX_ORDINARY_INPUTS: usize = elements::secp256k1_zkp::MAX_SURJECTION_PROOF_INPUTS;

/// Maximum confidential outputs accepted before the one mandatory fee output.
pub const MAX_CONFIDENTIAL_OUTPUTS: usize = 255;

/// Maximum positive amount accepted by the ordinary-wallet boundary.
///
/// The pinned range-proof implementation accepts positive confidential values
/// only through the signed 64-bit maximum.
pub const MAX_ORDINARY_VALUE: u64 = i64::MAX as u64;

/// A previous output owned by the ordinary wallet and available for spending.
///
/// This type deliberately does not implement `Debug`, `Copy`, or `Clone`.
/// Its private opening facts are cleared when dropped.
pub struct SpendableInput {
    outpoint: OutPoint,
    witness_utxo: TxOut,
    sequence: Sequence,
    secrets: InputSecrets,
}

impl SpendableInput {
    /// Constructs a spendable input from a fully explicit previous output.
    ///
    /// The outpoint-to-output association remains caller-provided. This method
    /// does not establish chain inclusion, current unspentness, or ownership.
    pub fn from_explicit(
        outpoint: OutPoint,
        witness_utxo: TxOut,
        sequence: Sequence,
    ) -> Result<Self, SpendableInputError> {
        validate_common_input(outpoint, &witness_utxo)?;

        let asset = match witness_utxo.asset {
            Asset::Explicit(asset) => asset,
            _ => return Err(SpendableInputError::ExpectedExplicitOutput),
        };
        let value = match witness_utxo.value {
            Value::Explicit(value) if value > MAX_ORDINARY_VALUE => {
                return Err(SpendableInputError::ValueOutOfRange);
            }
            Value::Explicit(value) if value > 0 => value,
            Value::Explicit(_) => return Err(SpendableInputError::ZeroValue),
            _ => return Err(SpendableInputError::ExpectedExplicitOutput),
        };
        if !matches!(witness_utxo.nonce, Nonce::Null)
            || !witness_utxo.witness.rangeproof.is_empty()
            || !witness_utxo.witness.surjection_proof.is_empty()
        {
            return Err(SpendableInputError::ExpectedExplicitOutput);
        }

        Ok(Self {
            outpoint,
            witness_utxo,
            sequence,
            secrets: InputSecrets::explicit(asset, value),
        })
    }

    /// Constructs a spendable input from a confidential previous output and
    /// the result of opening that exact output.
    ///
    /// The opening is consumed. Its asset, value, and blinding factors are
    /// recomputed against the supplied commitments before the input is
    /// accepted. The original range proof is required for the later Elements
    /// signature hash. Transaction-level proof validation and previous-output
    /// provenance remain separate prerequisites.
    pub fn from_confidential(
        secp: &Secp256k1<All>,
        outpoint: OutPoint,
        witness_utxo: TxOut,
        sequence: Sequence,
        opened: OpenedOutput,
    ) -> Result<Self, SpendableInputError> {
        validate_common_input(outpoint, &witness_utxo)?;
        if !witness_utxo.asset.is_confidential()
            || !witness_utxo.value.is_confidential()
            || !witness_utxo.nonce.is_confidential()
        {
            return Err(SpendableInputError::ExpectedConfidentialOutput);
        }
        if witness_utxo.witness.rangeproof.is_empty() {
            return Err(SpendableInputError::MissingRangeProof);
        }
        if witness_utxo.witness.surjection_proof.is_empty() {
            return Err(SpendableInputError::MissingSurjectionProof);
        }

        let secrets = InputSecrets::from_opened(opened)?;
        if secrets.value == 0 {
            return Err(SpendableInputError::ZeroValue);
        }
        if secrets.value > MAX_ORDINARY_VALUE {
            return Err(SpendableInputError::ValueOutOfRange);
        }
        if !secrets.matches_commitments(secp, &witness_utxo) {
            return Err(SpendableInputError::OpeningMismatch);
        }

        Ok(Self {
            outpoint,
            witness_utxo,
            sequence,
            secrets,
        })
    }

    /// Borrows the caller-supplied previous-output identifier.
    pub const fn outpoint(&self) -> &OutPoint {
        &self.outpoint
    }

    /// Borrows the exact previous output retained for the PSET input map.
    pub const fn witness_utxo(&self) -> &TxOut {
        &self.witness_utxo
    }
}

/// One non-fee output that must be blinded before signing.
///
/// This type deliberately does not implement `Debug`, `Copy`, or `Clone`.
pub struct ConfidentialOutput {
    asset: AssetId,
    value: u64,
    script_pubkey: Script,
    receiver_blinding_key: BitcoinPublicKey,
}

impl ConfidentialOutput {
    /// Creates an output from a validated confidential receive address.
    pub fn from_address(
        asset: AssetId,
        value: u64,
        address: &ConfidentialLiquidAddress,
    ) -> Result<Self, ConfidentialOutputError> {
        if value == 0 {
            return Err(ConfidentialOutputError::ZeroValue);
        }
        if value > MAX_ORDINARY_VALUE {
            return Err(ConfidentialOutputError::ValueOutOfRange);
        }

        let parsed = address.as_parsed();
        let script_pubkey = Script::from(parsed.script_pubkey().to_vec());
        if script_pubkey.is_empty() || script_pubkey.is_provably_unspendable() {
            return Err(ConfidentialOutputError::UnspendableScript);
        }
        let receiver_blinding_key = parsed
            .blinding_pubkey()
            .and_then(|bytes| BitcoinPublicKey::from_slice(&bytes).ok())
            .ok_or(ConfidentialOutputError::InvalidAddressFacts)?;

        Ok(Self {
            asset,
            value,
            script_pubkey,
            receiver_blinding_key,
        })
    }

    /// Returns the output asset.
    pub const fn asset(&self) -> AssetId {
        self.asset
    }

    /// Returns the output amount in the asset's indivisible unit.
    pub const fn value(&self) -> u64 {
        self.value
    }
}

/// The explicit network fee to append to an ordinary PSET.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ExplicitFee {
    asset: AssetId,
    value: u64,
}

impl ExplicitFee {
    /// Creates a positive explicit fee.
    ///
    /// The caller must separately authenticate that `asset` is the connected
    /// chain's policy asset.
    pub fn new(asset: AssetId, value: u64) -> Result<Self, ExplicitFeeError> {
        if value == 0 {
            return Err(ExplicitFeeError::ZeroValue);
        }
        if value > MAX_ORDINARY_VALUE {
            return Err(ExplicitFeeError::ValueOutOfRange);
        }
        Ok(Self { asset, value })
    }

    /// Returns the caller-declared fee asset.
    pub const fn asset(self) -> AssetId {
        self.asset
    }

    /// Returns the fee amount in the asset's indivisible unit.
    pub const fn value(self) -> u64 {
        self.value
    }
}

impl fmt::Debug for ExplicitFee {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExplicitFee")
            .field("value", &self.value)
            .finish_non_exhaustive()
    }
}

/// An unblinded ordinary-wallet PSET plus the private input capability needed
/// by a later blinding transition.
///
/// This type deliberately does not implement `Debug`, `Copy`, or `Clone` and
/// exposes no mutable PSET access. It is not ready for signing or broadcast.
pub struct PreparedOrdinaryPset {
    pset: PartiallySignedTransaction,
    input_secrets: Vec<InputSecrets>,
    confidential_output_indices: Vec<usize>,
    fee_output_index: usize,
}

impl PreparedOrdinaryPset {
    /// Borrows the unblinded PSET without granting mutation.
    pub const fn as_pset(&self) -> &PartiallySignedTransaction {
        &self.pset
    }

    /// Serializes the unblinded PSET.
    ///
    /// Confidential input openings are not included. Recipient asset and
    /// amount fields remain explicit until the later blinding transition.
    pub fn serialize_unblinded(&self) -> Vec<u8> {
        encode::serialize(&self.pset)
    }

    /// Borrows the output indices that require blinding.
    pub fn confidential_output_indices(&self) -> &[usize] {
        &self.confidential_output_indices
    }

    /// Returns the index of the sole explicit fee output.
    pub const fn fee_output_index(&self) -> usize {
        self.fee_output_index
    }

    /// Returns the number of private input openings retained for a later
    /// blinding transition.
    pub fn input_secret_count(&self) -> usize {
        self.input_secrets.len()
    }

    /// Consumes the prepared capability and blinds every non-fee output.
    ///
    /// Blinding uses every final input in each output's surjection-proof domain,
    /// verifies those proofs against the exact ordered domain, then validates
    /// the resulting transaction's amount proofs and commitment balance. Input
    /// product-owned opening buffers are cleared when this transition returns.
    /// The pinned library also creates transient typed copies that follow its
    /// ordinary Rust drop behavior and are not guaranteed to be overwritten.
    pub fn blind<R>(
        self,
        rng: &mut R,
        secp: &Secp256k1<All>,
    ) -> Result<BlindedOrdinaryPset, OrdinaryPsetBlindingError>
    where
        R: RngCore + CryptoRng,
    {
        let Self {
            mut pset,
            input_secrets,
            confidential_output_indices,
            fee_output_index,
        } = self;

        let mut upstream_secrets = UpstreamInputSecretMap::with_capacity(input_secrets.len());
        for (index, secrets) in input_secrets.iter().enumerate() {
            upstream_secrets
                .secrets
                .insert(index, secrets.to_txout_secrets()?);
        }

        let mut generated_secrets = pset
            .blind_last_with_all_surjection_inputs(
                rng,
                secp,
                &upstream_secrets.secrets,
                &confidential_output_indices,
            )
            .map_err(|_| OrdinaryPsetBlindingError::BlindingFailed)?;
        for (asset_blinding_factor, value_blinding_factor, ephemeral_key) in
            generated_secrets.values_mut()
        {
            *asset_blinding_factor = AssetBlindingFactor::zero();
            *value_blinding_factor = ValueBlindingFactor::zero();
            ephemeral_key.non_secure_erase();
        }
        black_box(&generated_secrets);

        validate_blinded_pset(secp, &pset, &confidential_output_indices, fee_output_index)?;

        Ok(BlindedOrdinaryPset {
            pset,
            confidential_output_indices,
            fee_output_index,
        })
    }
}

/// An amount-proof-validated PSET whose non-fee outputs are confidential.
///
/// This type deliberately does not implement `Debug`, `Copy`, or `Clone` and
/// exposes no mutable PSET access. It contains no retained input openings or
/// output blinding private keys. Signing is available only through its
/// product-owned consuming transition.
/// Arbitrary deserialized PSETs cannot enter this trusted type-state:
///
/// ```compile_fail
/// use elements::pset::PartiallySignedTransaction;
/// use wasabi_liquid_native_ordinary_pset::BlindedOrdinaryPset;
///
/// let untrusted = PartiallySignedTransaction::new_v2();
/// let trusted: BlindedOrdinaryPset = untrusted.into();
/// ```
pub struct BlindedOrdinaryPset {
    pset: PartiallySignedTransaction,
    confidential_output_indices: Vec<usize>,
    fee_output_index: usize,
}

impl BlindedOrdinaryPset {
    /// Borrows the blinded, amount-proof-validated PSET.
    pub const fn as_pset(&self) -> &PartiallySignedTransaction {
        &self.pset
    }

    /// Serializes the blinded PSET for the later signing boundary.
    ///
    /// PSET output maps intentionally retain explicit recipient asset and
    /// amount fields with proofs that bind them to the commitments. These
    /// sensitive bytes are not the confidential transaction broadcast form.
    pub fn serialize_sensitive(&self) -> Vec<u8> {
        encode::serialize(&self.pset)
    }

    /// Borrows the output indices proven confidential by this transition.
    pub fn confidential_output_indices(&self) -> &[usize] {
        &self.confidential_output_indices
    }

    /// Returns the index of the sole explicit fee output.
    pub const fn fee_output_index(&self) -> usize {
        self.fee_output_index
    }
}

/// Constructs an unblinded PSET for an ordinary wallet spend.
///
/// Inputs and outputs must conserve each asset independently, including the
/// fee in its caller-declared asset. All non-fee outputs are assigned to the
/// wallet's first input as the single-party blinder. The function produces no
/// commitments, proofs, signatures, or broadcastable transaction.
pub fn prepare_ordinary_pset(
    inputs: Vec<SpendableInput>,
    outputs: Vec<ConfidentialOutput>,
    fee: ExplicitFee,
    lock_time: LockTime,
) -> Result<PreparedOrdinaryPset, PsetConstructionError> {
    if inputs.is_empty() {
        return Err(PsetConstructionError::NoInputs);
    }
    if outputs.is_empty() {
        return Err(PsetConstructionError::NoConfidentialOutputs);
    }
    if inputs.len() > MAX_ORDINARY_INPUTS {
        return Err(PsetConstructionError::TooManyInputs);
    }
    if outputs.len() > MAX_CONFIDENTIAL_OUTPUTS {
        return Err(PsetConstructionError::TooManyOutputs);
    }

    for (index, input) in inputs.iter().enumerate() {
        if inputs[..index]
            .iter()
            .any(|earlier| earlier.outpoint == input.outpoint)
        {
            return Err(PsetConstructionError::DuplicateInput);
        }
    }
    if lock_time != LockTime::ZERO && inputs.iter().all(|input| input.sequence == Sequence::MAX) {
        return Err(PsetConstructionError::InertLockTime);
    }

    validate_asset_balance(&inputs, &outputs, fee)?;

    let mut pset = PartiallySignedTransaction::new_v2();
    pset.global.tx_data.fallback_locktime = Some(lock_time);
    let mut input_secrets = Vec::with_capacity(inputs.len());
    for input in inputs {
        let mut pset_input = PsetInput::from_prevout(input.outpoint);
        pset_input.sequence = Some(input.sequence);
        pset_input.sighash_type = Some(EcdsaSighashType::AllPlusRangeproof.into());
        let mut witness_utxo = input.witness_utxo.clone();
        if witness_utxo.value.is_confidential() {
            pset_input.in_utxo_rangeproof = Some(witness_utxo.witness.rangeproof.clone());
        }
        witness_utxo.witness = Default::default();
        pset_input.witness_utxo = Some(witness_utxo);
        pset.add_input(pset_input);
        input_secrets.push(InputSecrets::copy_from(&input.secrets));
    }

    let confidential_output_indices = (0..outputs.len()).collect::<Vec<_>>();
    for output in outputs {
        let mut pset_output = PsetOutput::new_explicit(
            output.script_pubkey,
            output.value,
            output.asset,
            Some(output.receiver_blinding_key),
        );
        pset_output.blinder_index = Some(0);
        pset.add_output(pset_output);
    }

    let fee_output_index = pset.n_outputs();
    pset.add_output(PsetOutput::new_explicit(
        Script::new(),
        fee.value,
        fee.asset,
        None,
    ));
    pset.sanity_check()
        .map_err(|_| PsetConstructionError::PsetInvariant)?;
    pset.extract_tx()
        .map_err(|_| PsetConstructionError::PsetInvariant)?;

    Ok(PreparedOrdinaryPset {
        pset,
        input_secrets,
        confidential_output_indices,
        fee_output_index,
    })
}

fn validate_asset_balance(
    inputs: &[SpendableInput],
    outputs: &[ConfidentialOutput],
    fee: ExplicitFee,
) -> Result<(), PsetConstructionError> {
    let mut input_totals = PrivateAssetTotals::default();
    for input in inputs {
        input_totals.checked_add(input.secrets.asset, input.secrets.value)?;
    }

    let mut output_totals = PrivateAssetTotals::default();
    for output in outputs {
        output_totals.checked_add(output.asset.to_byte_array(), output.value)?;
    }
    output_totals.checked_add(fee.asset.to_byte_array(), fee.value)?;

    if !input_totals.equals(&output_totals) {
        return Err(PsetConstructionError::AssetBalanceMismatch);
    }
    Ok(())
}

fn validate_common_input(
    outpoint: OutPoint,
    witness_utxo: &TxOut,
) -> Result<(), SpendableInputError> {
    const RESERVED_OUTPOINT_FLAGS: u32 = (1 << 31) | (1 << 30);

    if outpoint.is_null() || outpoint.txid == elements::Txid::COINBASE_PREVOUT {
        return Err(SpendableInputError::CoinbaseOutpoint);
    }
    if outpoint.vout & RESERVED_OUTPOINT_FLAGS != 0 {
        return Err(SpendableInputError::ReservedOutpointIndex);
    }
    if witness_utxo.is_fee()
        || witness_utxo.script_pubkey.is_empty()
        || witness_utxo.script_pubkey.is_provably_unspendable()
    {
        return Err(SpendableInputError::UnspendableOutput);
    }
    if !is_supported_native_witness_script(&witness_utxo.script_pubkey) {
        return Err(SpendableInputError::UnsupportedInputScript);
    }
    Ok(())
}

fn is_supported_native_witness_script(script: &Script) -> bool {
    script.is_v0_p2wpkh()
}

pub(crate) fn validate_blinded_pset(
    secp: &Secp256k1<All>,
    pset: &PartiallySignedTransaction,
    confidential_output_indices: &[usize],
    fee_output_index: usize,
) -> Result<(), OrdinaryPsetBlindingError> {
    if fee_output_index + 1 != pset.outputs().len()
        || confidential_output_indices.len() + 1 != pset.outputs().len()
        || confidential_output_indices
            .iter()
            .copied()
            .ne(0..fee_output_index)
    {
        return Err(OrdinaryPsetBlindingError::PostconditionFailed);
    }

    let fee_output = &pset.outputs()[fee_output_index];
    if !fee_output.script_pubkey.is_empty()
        || fee_output.asset.is_none()
        || fee_output.amount == Some(0)
        || fee_output.amount.is_none()
        || fee_output.blinding_key.is_some()
        || fee_output.blinder_index.is_some()
        || fee_output.asset_comm.is_some()
        || fee_output.amount_comm.is_some()
        || fee_output.ecdh_pubkey.is_some()
        || fee_output.value_rangeproof.is_some()
        || fee_output.asset_surjection_proof.is_some()
        || fee_output.blind_value_proof.is_some()
        || fee_output.blind_asset_proof.is_some()
    {
        return Err(OrdinaryPsetBlindingError::PostconditionFailed);
    }

    for &index in confidential_output_indices {
        let Some(output) = pset.outputs().get(index) else {
            return Err(OrdinaryPsetBlindingError::PostconditionFailed);
        };
        if output.script_pubkey.is_empty()
            || output.asset.is_none()
            || output.amount == Some(0)
            || output.amount.is_none()
            || output.blinding_key.is_none()
            || output.blinder_index != Some(0)
            || output.amount_comm.is_none()
            || output.asset_comm.is_none()
            || output.ecdh_pubkey.is_none()
            || output.value_rangeproof.is_none()
            || output.asset_surjection_proof.is_none()
            || output.blind_value_proof.is_none()
            || output.blind_asset_proof.is_none()
        {
            return Err(OrdinaryPsetBlindingError::PostconditionFailed);
        }

        let asset = output
            .asset
            .ok_or(OrdinaryPsetBlindingError::PostconditionFailed)?;
        let amount = output
            .amount
            .ok_or(OrdinaryPsetBlindingError::PostconditionFailed)?;
        let asset_commitment = output
            .asset_comm
            .ok_or(OrdinaryPsetBlindingError::PostconditionFailed)?;
        let amount_commitment = output
            .amount_comm
            .ok_or(OrdinaryPsetBlindingError::PostconditionFailed)?;
        let value_proof = output
            .blind_value_proof
            .as_ref()
            .ok_or(OrdinaryPsetBlindingError::PostconditionFailed)?;
        let asset_proof = output
            .blind_asset_proof
            .as_ref()
            .ok_or(OrdinaryPsetBlindingError::PostconditionFailed)?;
        if !value_proof.blind_value_proof_verify(secp, amount, asset_commitment, amount_commitment)
            || !asset_proof.blind_asset_proof_verify(secp, asset, asset_commitment)
        {
            return Err(OrdinaryPsetBlindingError::PostconditionFailed);
        }
    }

    pset.verify_all_surjection_proofs_use_all_inputs(secp, confidential_output_indices)
        .map_err(|_| OrdinaryPsetBlindingError::PostconditionFailed)?;
    let transaction = pset
        .extract_tx()
        .map_err(|_| OrdinaryPsetBlindingError::PostconditionFailed)?;
    let previous_outputs = pset
        .inputs()
        .iter()
        .map(|input| input.witness_utxo.clone())
        .collect::<Option<Vec<_>>>()
        .ok_or(OrdinaryPsetBlindingError::PostconditionFailed)?;
    transaction
        .verify_tx_amt_proofs(secp, &previous_outputs)
        .map_err(|_| OrdinaryPsetBlindingError::PostconditionFailed)
}

struct PrivateAssetTotals {
    totals: Vec<PrivateAssetTotal>,
}

impl Default for PrivateAssetTotals {
    fn default() -> Self {
        Self {
            totals: Vec::with_capacity(MAX_ORDINARY_INPUTS),
        }
    }
}

impl PrivateAssetTotals {
    fn checked_add(&mut self, asset: [u8; 32], value: u64) -> Result<(), PsetConstructionError> {
        if let Some(total) = self.totals.iter_mut().find(|total| total.asset == asset) {
            total.value = total
                .value
                .checked_add(value)
                .ok_or(PsetConstructionError::AmountOverflow)?;
        } else {
            self.totals.push(PrivateAssetTotal { asset, value });
        }
        Ok(())
    }

    fn equals(&self, other: &Self) -> bool {
        self.totals.len() == other.totals.len()
            && self.totals.iter().all(|left| {
                other
                    .totals
                    .iter()
                    .any(|right| left.asset == right.asset && left.value == right.value)
            })
    }
}

struct PrivateAssetTotal {
    asset: [u8; 32],
    value: u64,
}

impl Drop for PrivateAssetTotal {
    fn drop(&mut self) {
        self.asset.zeroize();
        self.value.zeroize();
    }
}

struct UpstreamInputSecretMap {
    secrets: HashMap<usize, TxOutSecrets>,
}

impl UpstreamInputSecretMap {
    fn with_capacity(capacity: usize) -> Self {
        Self {
            secrets: HashMap::with_capacity(capacity),
        }
    }
}

impl Drop for UpstreamInputSecretMap {
    fn drop(&mut self) {
        for secret in self.secrets.values_mut() {
            secret.asset = AssetId::from_byte_array([0; 32]);
            secret.value = 0;
            secret.asset_bf = AssetBlindingFactor::zero();
            secret.value_bf = ValueBlindingFactor::zero();
        }
        black_box(&self.secrets);
    }
}

struct InputSecrets {
    asset: [u8; 32],
    value: u64,
    asset_blinding_factor: [u8; 32],
    value_blinding_factor: [u8; 32],
}

impl InputSecrets {
    fn explicit(asset: AssetId, value: u64) -> Self {
        Self {
            asset: asset.to_byte_array(),
            value,
            asset_blinding_factor: [0; 32],
            value_blinding_factor: [0; 32],
        }
    }

    fn from_opened(opened: OpenedOutput) -> Result<Self, SpendableInputError> {
        let asset = *opened.asset_id();
        AssetBlindingFactor::from_byte_array(*opened.asset_blinding_factor())
            .map_err(|_| SpendableInputError::InvalidOpening)?;
        ValueBlindingFactor::from_slice(opened.value_blinding_factor())
            .map_err(|_| SpendableInputError::InvalidOpening)?;

        Ok(Self {
            asset,
            value: *opened.value(),
            asset_blinding_factor: *opened.asset_blinding_factor(),
            value_blinding_factor: *opened.value_blinding_factor(),
        })
    }

    fn copy_from(source: &Self) -> Self {
        Self {
            asset: source.asset,
            value: source.value,
            asset_blinding_factor: source.asset_blinding_factor,
            value_blinding_factor: source.value_blinding_factor,
        }
    }

    fn asset(&self) -> AssetId {
        AssetId::from_byte_array(self.asset)
    }

    fn to_txout_secrets(&self) -> Result<TxOutSecrets, OrdinaryPsetBlindingError> {
        let asset_blinding_factor =
            AssetBlindingFactor::from_byte_array(self.asset_blinding_factor)
                .map_err(|_| OrdinaryPsetBlindingError::InvalidRetainedOpening)?;
        let value_blinding_factor = ValueBlindingFactor::from_slice(&self.value_blinding_factor)
            .map_err(|_| OrdinaryPsetBlindingError::InvalidRetainedOpening)?;
        Ok(TxOutSecrets::new(
            self.asset(),
            asset_blinding_factor,
            self.value,
            value_blinding_factor,
        ))
    }

    fn matches_commitments(&self, secp: &Secp256k1<All>, output: &TxOut) -> bool {
        let Ok(asset_blinding_factor) =
            AssetBlindingFactor::from_byte_array(self.asset_blinding_factor)
        else {
            return false;
        };
        let Ok(value_blinding_factor) =
            ValueBlindingFactor::from_slice(&self.value_blinding_factor)
        else {
            return false;
        };

        let asset = self.asset();
        output.asset == Asset::new_confidential(secp, asset, asset_blinding_factor)
            && output.value
                == Value::new_confidential_from_assetid(
                    secp,
                    self.value,
                    asset,
                    value_blinding_factor,
                    asset_blinding_factor,
                )
    }
}

impl Drop for InputSecrets {
    fn drop(&mut self) {
        self.asset.zeroize();
        self.value.zeroize();
        self.asset_blinding_factor.zeroize();
        self.value_blinding_factor.zeroize();
    }
}

/// A failure while binding a previous output to private opening facts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SpendableInputError {
    /// Coinbase/null outpoints are outside this constructor's scope.
    CoinbaseOutpoint,
    /// Output indexes containing issuance or peg-in flag bits are unsupported.
    ReservedOutpointIndex,
    /// The previous output has no spendable script.
    UnspendableOutput,
    /// The previous output is not a supported native witness output.
    UnsupportedInputScript,
    /// A spendable zero-valued input was supplied.
    ZeroValue,
    /// The input amount exceeds the pinned proof and consensus amount range.
    ValueOutOfRange,
    /// The explicit constructor received another output encoding.
    ExpectedExplicitOutput,
    /// The confidential constructor received another output encoding.
    ExpectedConfidentialOutput,
    /// A confidential input omitted the original range proof.
    MissingRangeProof,
    /// A confidential input omitted the original surjection proof.
    MissingSurjectionProof,
    /// Recovered blinding factors were not valid scalars.
    InvalidOpening,
    /// The recovered private facts do not reproduce the supplied commitments.
    OpeningMismatch,
}

impl fmt::Display for SpendableInputError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::CoinbaseOutpoint => "input outpoint is reserved for coinbase",
            Self::ReservedOutpointIndex => "input outpoint index contains reserved flags",
            Self::UnspendableOutput => "input previous output is not spendable",
            Self::UnsupportedInputScript => "input script is not a supported native witness output",
            Self::ZeroValue => "input value is zero",
            Self::ValueOutOfRange => "input value is outside the supported range",
            Self::ExpectedExplicitOutput => "input is not fully explicit",
            Self::ExpectedConfidentialOutput => "input is not fully confidential",
            Self::MissingRangeProof => "confidential input range proof is missing",
            Self::MissingSurjectionProof => "confidential input surjection proof is missing",
            Self::InvalidOpening => "confidential input opening is invalid",
            Self::OpeningMismatch => "confidential input opening does not match commitments",
        })
    }
}

impl std::error::Error for SpendableInputError {}

/// A failure while creating a confidential non-fee output.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ConfidentialOutputError {
    /// A zero-valued spendable output was requested.
    ZeroValue,
    /// The amount exceeds the pinned proof and consensus amount range.
    ValueOutOfRange,
    /// The address yielded an empty or provably unspendable script.
    UnspendableScript,
    /// The validated confidential-address facts could not be reconstructed.
    InvalidAddressFacts,
}

impl fmt::Display for ConfidentialOutputError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ZeroValue => "confidential output value is zero",
            Self::ValueOutOfRange => "confidential output value is outside the supported range",
            Self::UnspendableScript => "confidential output script is not spendable",
            Self::InvalidAddressFacts => "confidential address facts are invalid",
        })
    }
}

impl std::error::Error for ConfidentialOutputError {}

/// A failure while declaring an explicit network fee.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ExplicitFeeError {
    /// A positive fee is required by this ordinary-wallet boundary.
    ZeroValue,
    /// The fee exceeds the supported consensus amount range.
    ValueOutOfRange,
}

impl fmt::Display for ExplicitFeeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ZeroValue => "explicit fee value is zero",
            Self::ValueOutOfRange => "explicit fee value is outside the supported range",
        })
    }
}

impl std::error::Error for ExplicitFeeError {}

/// A failure while constructing an ordinary multiasset PSET.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PsetConstructionError {
    /// At least one input is required.
    NoInputs,
    /// At least one confidential non-fee output is required.
    NoConfidentialOutputs,
    /// The construction exceeds the complete input-domain limit.
    TooManyInputs,
    /// The construction exceeds the bounded output count.
    TooManyOutputs,
    /// The same previous output appears more than once.
    DuplicateInput,
    /// A nonzero locktime would be disabled by all-final input sequences.
    InertLockTime,
    /// Summing one asset exceeded the supported amount range.
    AmountOverflow,
    /// Inputs and outputs do not conserve every asset independently.
    AssetBalanceMismatch,
    /// The pinned PSET implementation rejected an internal count invariant.
    PsetInvariant,
}

impl fmt::Display for PsetConstructionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::NoInputs => "ordinary PSET has no inputs",
            Self::NoConfidentialOutputs => "ordinary PSET has no confidential outputs",
            Self::TooManyInputs => "ordinary PSET has too many inputs",
            Self::TooManyOutputs => "ordinary PSET has too many outputs",
            Self::DuplicateInput => "ordinary PSET repeats an input",
            Self::InertLockTime => "ordinary PSET locktime is disabled by final sequences",
            Self::AmountOverflow => "ordinary PSET asset amount overflowed",
            Self::AssetBalanceMismatch => "ordinary PSET asset balances do not match",
            Self::PsetInvariant => "ordinary PSET invariant failed",
        })
    }
}

impl std::error::Error for PsetConstructionError {}

/// A failure while consuming a prepared PSET into its blinded state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum OrdinaryPsetBlindingError {
    /// A retained opening could not be reconstructed for the pinned library.
    InvalidRetainedOpening,
    /// The pinned blinding operation did not complete.
    BlindingFailed,
    /// The blinded result failed a product-owned structural or proof check.
    PostconditionFailed,
}

impl fmt::Display for OrdinaryPsetBlindingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidRetainedOpening => "ordinary PSET retained opening is invalid",
            Self::BlindingFailed => "ordinary PSET blinding failed",
            Self::PostconditionFailed => "ordinary PSET blinded result validation failed",
        })
    }
}

impl std::error::Error for OrdinaryPsetBlindingError {}
