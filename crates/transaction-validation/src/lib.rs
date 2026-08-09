#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Transaction amount-proof validation tied to exact input outpoints and
//! previous outputs.
//!
//! This crate validates the amount-proof and commitment-balance behavior
//! provided by the pinned Elements library. It does not authenticate chain
//! inclusion, current unspentness, scripts, signatures, node identity, or
//! wallet ownership.

use core::fmt;

use elements::secp256k1_zkp::{All, Secp256k1, SecretKey};
use elements::{OutPoint, Transaction, TxOut, VerificationError};
use wasabi_liquid_native_output_opening::{
    OpenedOutput, OutputOpenError, open_confidential_output,
};

/// A transaction whose amount proofs and commitment balance were validated
/// against the retained exact outpoint and previous-output slices.
///
/// The immutable borrows prevent the transaction or its validation inputs from
/// changing while this value exists. This type deliberately does not implement
/// `Debug`, `Copy`, or `Clone`.
pub struct AmountProofValidatedTransaction<'transaction, 'spent> {
    transaction: &'transaction Transaction,
    spent_outpoints: &'spent [OutPoint],
    spent_outputs: &'spent [TxOut],
}

impl<'transaction, 'spent> AmountProofValidatedTransaction<'transaction, 'spent> {
    /// Borrows the validated transaction.
    pub const fn transaction(&self) -> &Transaction {
        self.transaction
    }

    /// Borrows the outpoints used to bind validation inputs.
    pub const fn spent_outpoints(&self) -> &[OutPoint] {
        self.spent_outpoints
    }

    /// Borrows the previous outputs used for validation.
    pub const fn spent_outputs(&self) -> &[TxOut] {
        self.spent_outputs
    }

    /// Opens one output from this amount-proof-validated transaction.
    ///
    /// Successful opening still does not establish chain inclusion,
    /// unspentness, script ownership, or blinding-key provenance.
    pub fn open_output(
        &self,
        secp: &Secp256k1<All>,
        output_index: usize,
        blinding_key: &SecretKey,
    ) -> Result<OpenedOutput, ValidatedOutputOpenError> {
        let output = self
            .transaction
            .output
            .get(output_index)
            .ok_or(ValidatedOutputOpenError::OutputIndexOutOfRange)?;

        open_confidential_output(secp, output, blinding_key)
            .map_err(ValidatedOutputOpenError::Opening)
    }
}

/// A privacy-redacted transaction amount-proof validation failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TransactionValidationError {
    /// Input, outpoint, and previous-output counts differ.
    InputCountMismatch,
    /// The transaction has no inputs or no outputs.
    EmptyTransaction,
    /// A null coinbase previous output is outside this validator's scope.
    UnsupportedCoinbase,
    /// The transaction spends the same previous output more than once.
    DuplicatePreviousOutput,
    /// A supplied outpoint does not match the transaction input at that index.
    PreviousOutputMismatch,
    /// Issuance inputs require a later validation slice.
    UnsupportedIssuance,
    /// Peg-in inputs require a later validation slice.
    UnsupportedPegin,
    /// A confidential output has no range proof.
    MissingRangeProof,
    /// A confidential output has no surjection proof.
    MissingSurjectionProof,
    /// A present confidential proof did not validate.
    InvalidProof,
    /// An input or output amount commitment is invalid.
    InvalidAmount,
    /// Input and output commitments do not balance.
    BalanceMismatch,
}

impl fmt::Display for TransactionValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InputCountMismatch => "transaction validation input count mismatch",
            Self::EmptyTransaction => "transaction has no inputs or no outputs",
            Self::UnsupportedCoinbase => "coinbase transaction validation is unavailable",
            Self::DuplicatePreviousOutput => "transaction repeats a previous output",
            Self::PreviousOutputMismatch => "transaction previous output mismatch",
            Self::UnsupportedIssuance => "transaction issuance validation is unavailable",
            Self::UnsupportedPegin => "transaction peg-in validation is unavailable",
            Self::MissingRangeProof => "transaction range proof is missing",
            Self::MissingSurjectionProof => "transaction surjection proof is missing",
            Self::InvalidProof => "transaction confidential proof validation failed",
            Self::InvalidAmount => "transaction amount commitment is invalid",
            Self::BalanceMismatch => "transaction commitments do not balance",
        })
    }
}

impl std::error::Error for TransactionValidationError {}

/// A failure while opening an output from a validated transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ValidatedOutputOpenError {
    /// The requested output index is absent.
    OutputIndexOutOfRange,
    /// The selected output could not be opened.
    Opening(OutputOpenError),
}

impl fmt::Display for ValidatedOutputOpenError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::OutputIndexOutOfRange => "transaction output index is out of range",
            Self::Opening(_) => "validated transaction output opening failed",
        })
    }
}

impl std::error::Error for ValidatedOutputOpenError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::OutputIndexOutOfRange => None,
            Self::Opening(error) => Some(error),
        }
    }
}

/// Validates one transaction against exact ordered input outpoints and previous
/// outputs.
///
/// Coinbase, issuance, and peg-in inputs are rejected until their additional
/// amount and provenance requirements are implemented. Success validates
/// confidential range proofs, surjection proofs, and the commitment-balance
/// equation for the supported transaction shape. Callers must separately
/// authenticate the connected node, chain, previous-output source, current
/// unspentness, scripts, signatures, confirmations, and wallet ownership before
/// crediting funds.
pub fn validate_transaction_amount_proofs<'transaction, 'spent>(
    secp: &Secp256k1<All>,
    transaction: &'transaction Transaction,
    spent_outpoints: &'spent [OutPoint],
    spent_outputs: &'spent [TxOut],
) -> Result<AmountProofValidatedTransaction<'transaction, 'spent>, TransactionValidationError> {
    if transaction.input.is_empty() || transaction.output.is_empty() {
        return Err(TransactionValidationError::EmptyTransaction);
    }

    if transaction.input.len() != spent_outpoints.len()
        || transaction.input.len() != spent_outputs.len()
    {
        return Err(TransactionValidationError::InputCountMismatch);
    }

    if transaction
        .input
        .iter()
        .zip(spent_outpoints)
        .any(|(input, outpoint)| input.previous_output != *outpoint)
    {
        return Err(TransactionValidationError::PreviousOutputMismatch);
    }

    if transaction
        .input
        .iter()
        .any(|input| input.previous_output.is_null())
    {
        return Err(TransactionValidationError::UnsupportedCoinbase);
    }

    if spent_outpoints
        .iter()
        .enumerate()
        .any(|(index, outpoint)| spent_outpoints[..index].contains(outpoint))
    {
        return Err(TransactionValidationError::DuplicatePreviousOutput);
    }

    if transaction.input.iter().any(elements::TxIn::has_issuance) {
        return Err(TransactionValidationError::UnsupportedIssuance);
    }

    if transaction.input.iter().any(elements::TxIn::is_pegin) {
        return Err(TransactionValidationError::UnsupportedPegin);
    }

    transaction
        .verify_tx_amt_proofs(secp, spent_outputs)
        .map_err(map_verification_error)?;

    Ok(AmountProofValidatedTransaction {
        transaction,
        spent_outpoints,
        spent_outputs,
    })
}

fn map_verification_error(error: VerificationError) -> TransactionValidationError {
    match error {
        VerificationError::UtxoInputLenMismatch => TransactionValidationError::InputCountMismatch,
        VerificationError::RangeProofMissing(_) => TransactionValidationError::MissingRangeProof,
        VerificationError::SurjectionProofMissing(_) => {
            TransactionValidationError::MissingSurjectionProof
        }
        VerificationError::RangeProofError(_, _)
        | VerificationError::SurjectionProofError(_, _)
        | VerificationError::SurjectionProofVerificationError(_) => {
            TransactionValidationError::InvalidProof
        }
        VerificationError::SpentTxOutError(_, _) | VerificationError::TxOutError(_, _) => {
            TransactionValidationError::InvalidAmount
        }
        VerificationError::BalanceCheckFailed => TransactionValidationError::BalanceMismatch,
        VerificationError::IssuanceTransactionInput(_) => {
            TransactionValidationError::UnsupportedIssuance
        }
    }
}
