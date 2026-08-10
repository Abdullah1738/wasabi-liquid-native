use core::cmp::Ordering;

use wasabi_liquid_native_wallet_facts::{
    DescriptorBranch, MAX_CANDIDATE_TRANSACTIONS, MAX_DERIVATION_INDEX, ObservedOwnedOutput,
    ObservedTransactionInput, ObservedWalletBatch, ObservedWalletTransaction,
    validates_observed_public_output,
};
use zeroize::Zeroize;

use crate::reader::Reader;
use crate::request::validate_outer_length;
use crate::writer::{Writer, checked_add, checked_multiply};
use crate::{
    MAX_AGGREGATE_INPUTS, MAX_AGGREGATE_OWNED_OUTPUTS, MAX_INPUTS_PER_TRANSACTION,
    MAX_OWNED_OUTPUT_VALUE, MAX_OWNED_OUTPUTS_PER_TRANSACTION, MAX_REACHABLE_RESPONSE_BYTES,
    MAX_RESPONSE_FRAME_BYTES, MAX_SPENDABLE_OUTPUT_INDEX, NATIVE_P2WPKH_SCRIPT_BYTES,
    ScopedWireBytes, WalletFactsWireError, is_nonzero,
};

const RESPONSE_MAGIC: &[u8; 4] = b"WLFV";
const WIRE_VERSION: u16 = 1;
const RESPONSE_HEADER_BYTES: usize = 64;
const TRANSACTION_FIXED_BYTES: usize = 72;
const INPUT_BYTES: usize = 36;
const OUTPUT_BYTES: usize = 144;

/// A canonical encoded wallet-facts response.
///
/// The owned bytes are overwritten on drop. This linear wrapper deliberately
/// implements neither `Debug`, `Clone`, nor `Copy`.
pub struct EncodedWalletFactsResponse {
    bytes: Vec<u8>,
}

impl EncodedWalletFactsResponse {
    /// Borrows the complete canonical frame.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl Drop for EncodedWalletFactsResponse {
    fn drop(&mut self) {
        self.bytes.zeroize();
        #[cfg(test)]
        crate::note_drop(
            crate::DropKind::EncodedResponse,
            self.bytes.iter().all(|byte| *byte == 0),
        );
    }
}

/// One decoded input outpoint in exact consensus input order.
///
/// This fact deliberately implements none of `Debug`, `Clone`, `Copy`, or
/// `Display`.
pub struct DecodedTransactionInput {
    previous_transaction_id: [u8; 32],
    previous_output_index: u32,
}

impl DecodedTransactionInput {
    /// Borrows the consensus-order previous-transaction identifier.
    pub const fn previous_transaction_id(&self) -> &[u8; 32] {
        &self.previous_transaction_id
    }

    /// Returns the previous output index.
    pub const fn previous_output_index(&self) -> u32 {
        self.previous_output_index
    }
}

impl Drop for DecodedTransactionInput {
    fn drop(&mut self) {
        self.previous_transaction_id.zeroize();
        self.previous_output_index.zeroize();
        #[cfg(test)]
        crate::note_drop(
            crate::DropKind::DecodedInput,
            self.previous_transaction_id.iter().all(|byte| *byte == 0)
                && self.previous_output_index == 0,
        );
    }
}

impl InputSource for DecodedTransactionInput {
    fn previous_transaction_id(&self) -> &[u8; 32] {
        self.previous_transaction_id()
    }

    fn previous_output_index(&self) -> u32 {
        self.previous_output_index()
    }
}

/// One decoded public owned-output observation nested under its parent
/// transaction.
///
/// This fact deliberately implements none of `Debug`, `Clone`, `Copy`, or
/// `Display` and grants no UTXO or balance-credit authority.
pub struct DecodedOwnedOutput {
    output_index: u32,
    script_pubkey: [u8; NATIVE_P2WPKH_SCRIPT_BYTES],
    spend_public_key: [u8; 33],
    blinding_public_key: [u8; 33],
    branch: DescriptorBranch,
    derivation_index: u32,
    asset_id: [u8; 32],
    value: u64,
}

impl DecodedOwnedOutput {
    /// Returns the parent transaction output index.
    pub const fn output_index(&self) -> u32 {
        self.output_index
    }

    /// Borrows the exact native-P2WPKH scriptPubKey.
    pub const fn script_pubkey(&self) -> &[u8; NATIVE_P2WPKH_SCRIPT_BYTES] {
        &self.script_pubkey
    }

    /// Borrows the compressed spend public key.
    pub const fn spend_public_key(&self) -> &[u8; 33] {
        &self.spend_public_key
    }

    /// Borrows the compressed blinding public key.
    pub const fn blinding_public_key(&self) -> &[u8; 33] {
        &self.blinding_public_key
    }

    /// Returns the public descriptor branch.
    pub const fn branch(&self) -> DescriptorBranch {
        self.branch
    }

    /// Returns the normal derivation index.
    pub const fn derivation_index(&self) -> u32 {
        self.derivation_index
    }

    /// Borrows the consensus-order asset identifier.
    pub const fn asset_id(&self) -> &[u8; 32] {
        &self.asset_id
    }

    /// Returns the strictly positive asset amount.
    pub const fn value(&self) -> u64 {
        self.value
    }
}

impl Drop for DecodedOwnedOutput {
    fn drop(&mut self) {
        self.output_index.zeroize();
        self.script_pubkey.zeroize();
        self.spend_public_key.zeroize();
        self.blinding_public_key.zeroize();
        self.branch = DescriptorBranch::External;
        self.derivation_index.zeroize();
        self.asset_id.zeroize();
        self.value.zeroize();
        #[cfg(test)]
        crate::note_drop(
            crate::DropKind::DecodedOutput,
            self.output_index == 0
                && self.script_pubkey.iter().all(|byte| *byte == 0)
                && self.spend_public_key.iter().all(|byte| *byte == 0)
                && self.blinding_public_key.iter().all(|byte| *byte == 0)
                && self.derivation_index == 0
                && self.asset_id.iter().all(|byte| *byte == 0)
                && self.value == 0,
        );
    }
}

/// One decoded transaction observation in canonical unsigned transaction-ID
/// order.
///
/// Inputs retain exact consensus order. This fact deliberately implements none
/// of `Debug`, `Clone`, `Copy`, or `Display`.
pub struct DecodedWalletTransaction {
    transaction_id: [u8; 32],
    transaction_witness_binding: [u8; 32],
    inputs: Vec<DecodedTransactionInput>,
    outputs: Vec<DecodedOwnedOutput>,
}

impl DecodedWalletTransaction {
    /// Borrows the consensus-order transaction identifier.
    pub const fn transaction_id(&self) -> &[u8; 32] {
        &self.transaction_id
    }

    /// Borrows the SHA-256 witness-inclusive transaction binding.
    pub const fn transaction_witness_binding(&self) -> &[u8; 32] {
        &self.transaction_witness_binding
    }

    /// Borrows inputs in exact consensus order.
    pub fn inputs(&self) -> &[DecodedTransactionInput] {
        &self.inputs
    }

    /// Borrows outputs in strictly ascending output-index order.
    pub fn outputs(&self) -> &[DecodedOwnedOutput] {
        &self.outputs
    }
}

impl Drop for DecodedWalletTransaction {
    fn drop(&mut self) {
        self.transaction_id.zeroize();
        self.transaction_witness_binding.zeroize();
        self.inputs.clear();
        self.outputs.clear();
        #[cfg(test)]
        crate::note_drop(
            crate::DropKind::DecodedTransaction,
            self.transaction_id.iter().all(|byte| *byte == 0)
                && self
                    .transaction_witness_binding
                    .iter()
                    .all(|byte| *byte == 0)
                && self.inputs.is_empty()
                && self.outputs.is_empty(),
        );
    }
}

/// An immutable decoded response whose source binding was matched before
/// publication.
///
/// This aggregate deliberately implements none of `Debug`, `Clone`, `Copy`,
/// or `Display` and grants no chain, UTXO, or wallet-credit authority.
pub struct DecodedWalletFactsResponse {
    source_epoch: [u8; 32],
    transactions: Vec<DecodedWalletTransaction>,
}

impl DecodedWalletFactsResponse {
    /// Borrows the matched source-epoch binding.
    pub const fn source_epoch(&self) -> &[u8; 32] {
        &self.source_epoch
    }

    /// Borrows transactions in canonical unsigned transaction-ID order.
    pub fn transactions(&self) -> &[DecodedWalletTransaction] {
        &self.transactions
    }

    /// Returns whether the response contains no transaction observations.
    pub fn is_empty(&self) -> bool {
        self.transactions.is_empty()
    }
}

impl Drop for DecodedWalletFactsResponse {
    fn drop(&mut self) {
        self.source_epoch.zeroize();
        self.transactions.clear();
        #[cfg(test)]
        crate::note_drop(
            crate::DropKind::DecodedResponse,
            self.source_epoch.iter().all(|byte| *byte == 0) && self.transactions.is_empty(),
        );
    }
}

pub(crate) trait InputSource {
    fn previous_transaction_id(&self) -> &[u8; 32];
    fn previous_output_index(&self) -> u32;
}

impl InputSource for ObservedTransactionInput {
    fn previous_transaction_id(&self) -> &[u8; 32] {
        self.previous_transaction_id()
    }

    fn previous_output_index(&self) -> u32 {
        self.previous_output_index()
    }
}

pub(crate) trait TransactionSource {
    type Input: InputSource;

    fn transaction_id(&self) -> &[u8; 32];
    fn transaction_witness_binding(&self) -> &[u8; 32];
    fn inputs(&self) -> &[Self::Input];
}

impl TransactionSource for ObservedWalletTransaction {
    type Input = ObservedTransactionInput;

    fn transaction_id(&self) -> &[u8; 32] {
        self.transaction_id()
    }

    fn transaction_witness_binding(&self) -> &[u8; 32] {
        self.transaction_witness_binding()
    }

    fn inputs(&self) -> &[Self::Input] {
        self.inputs()
    }
}

pub(crate) trait OutputSource {
    fn transaction_id(&self) -> &[u8; 32];
    fn output_index(&self) -> u32;
    fn transaction_witness_binding(&self) -> &[u8; 32];
    fn script_pubkey(&self) -> &[u8];
    fn spend_public_key(&self) -> &[u8; 33];
    fn blinding_public_key(&self) -> &[u8; 33];
    fn branch(&self) -> DescriptorBranch;
    fn derivation_index(&self) -> u32;
    fn asset_id(&self) -> &[u8; 32];
    fn value(&self) -> u64;
}

impl OutputSource for ObservedOwnedOutput {
    fn transaction_id(&self) -> &[u8; 32] {
        self.transaction_id()
    }

    fn output_index(&self) -> u32 {
        self.output_index()
    }

    fn transaction_witness_binding(&self) -> &[u8; 32] {
        self.transaction_witness_binding()
    }

    fn script_pubkey(&self) -> &[u8] {
        self.script_pubkey()
    }

    fn spend_public_key(&self) -> &[u8; 33] {
        self.spend_public_key()
    }

    fn blinding_public_key(&self) -> &[u8; 33] {
        self.blinding_public_key()
    }

    fn branch(&self) -> DescriptorBranch {
        self.branch()
    }

    fn derivation_index(&self) -> u32 {
        self.derivation_index()
    }

    fn asset_id(&self) -> &[u8; 32] {
        self.asset_id()
    }

    fn value(&self) -> u64 {
        self.value()
    }
}

pub(crate) trait ResponseSource {
    type Transaction: TransactionSource;
    type Output: OutputSource;

    fn transactions(&self) -> &[Self::Transaction];
    fn outputs(&self) -> &[Self::Output];
}

impl ResponseSource for ObservedWalletBatch {
    type Transaction = ObservedWalletTransaction;
    type Output = ObservedOwnedOutput;

    fn transactions(&self) -> &[Self::Transaction] {
        self.transactions()
    }

    fn outputs(&self) -> &[Self::Output] {
        self.outputs()
    }
}

struct ScopedWireOutPoint {
    bytes: [u8; INPUT_BYTES],
}

impl ScopedWireOutPoint {
    fn new(input: &impl InputSource) -> Self {
        Self::new_parts(
            input.previous_transaction_id(),
            input.previous_output_index(),
        )
    }

    fn new_parts(previous_transaction_id: &[u8; 32], previous_output_index: u32) -> Self {
        let mut bytes = [0; INPUT_BYTES];
        bytes[..32].copy_from_slice(previous_transaction_id);
        bytes[32..].copy_from_slice(&previous_output_index.to_le_bytes());
        Self { bytes }
    }
}

impl Drop for ScopedWireOutPoint {
    fn drop(&mut self) {
        self.bytes.zeroize();
        #[cfg(test)]
        SCRATCH_POINT_DROPS.with(|count| count.set(count.get() + 1));
    }
}

struct WireOutPointScratch(Vec<ScopedWireOutPoint>);

impl Drop for WireOutPointScratch {
    fn drop(&mut self) {
        self.0.clear();
    }
}

struct ResponseHeader {
    source_epoch: [u8; 32],
    transaction_count: usize,
    output_count: usize,
}

impl Drop for ResponseHeader {
    fn drop(&mut self) {
        self.source_epoch.zeroize();
        self.transaction_count.zeroize();
        self.output_count.zeroize();
    }
}

struct ResponseShape {
    total_length: usize,
    total_inputs: usize,
    total_outputs: usize,
}

/// Encodes a native validated observation batch and echoes a nonzero source
/// binding.
pub fn encode_response(
    observations: &ObservedWalletBatch,
    source_epoch: &[u8; 32],
) -> Result<EncodedWalletFactsResponse, WalletFactsWireError> {
    encode_source(observations, source_epoch)
}

pub(crate) fn encode_source(
    source: &impl ResponseSource,
    source_epoch: &[u8; 32],
) -> Result<EncodedWalletFactsResponse, WalletFactsWireError> {
    if !is_nonzero(source_epoch) {
        return Err(WalletFactsWireError::InvalidArgument);
    }
    let shape = validate_source(source)?;
    validate_source_uniqueness(source)?;
    let mut writer = Writer::new(shape.total_length);
    writer.write(RESPONSE_MAGIC);
    writer.write_u16(WIRE_VERSION);
    writer.write_u16(RESPONSE_HEADER_BYTES as u16);
    writer.write_u64(shape.total_length as u64);
    writer.write_u32(0);
    writer.write_u32(source.transactions().len() as u32);
    writer.write_u32(shape.total_outputs as u32);
    writer.write_u32(0);
    writer.write(source_epoch);

    let mut output_cursor = 0_usize;
    for transaction in source.transactions() {
        let output_start = output_cursor;
        while output_cursor < source.outputs().len()
            && source.outputs()[output_cursor].transaction_id() == transaction.transaction_id()
        {
            output_cursor += 1;
        }
        writer.write(transaction.transaction_id());
        writer.write(transaction.transaction_witness_binding());
        writer.write_u32(transaction.inputs().len() as u32);
        writer.write_u32((output_cursor - output_start) as u32);
        for input in transaction.inputs() {
            writer.write(input.previous_transaction_id());
            writer.write_u32(input.previous_output_index());
        }
        for output in &source.outputs()[output_start..output_cursor] {
            writer.write_u32(output.output_index());
            writer.write_u32(NATIVE_P2WPKH_SCRIPT_BYTES as u32);
            writer.write(output.spend_public_key());
            writer.write(output.blinding_public_key());
            writer.write_u8(match output.branch() {
                DescriptorBranch::External => 0,
                DescriptorBranch::Internal => 1,
            });
            writer.write(&[0; 3]);
            writer.write_u32(output.derivation_index());
            writer.write(output.asset_id());
            writer.write_u64(output.value());
            writer.write(output.script_pubkey());
        }
    }
    debug_assert_eq!(
        shape.total_inputs,
        source
            .transactions()
            .iter()
            .map(|item| item.inputs().len())
            .sum()
    );
    Ok(EncodedWalletFactsResponse {
        bytes: writer.finish()?,
    })
}

/// Decodes one canonical response only when its nonzero source binding equals
/// `expected_source_epoch`.
pub fn decode_response(
    frame: &[u8],
    expected_source_epoch: &[u8; 32],
) -> Result<DecodedWalletFactsResponse, WalletFactsWireError> {
    if !is_nonzero(expected_source_epoch) {
        return Err(WalletFactsWireError::InvalidArgument);
    }
    validate_outer_length(frame.len(), MAX_RESPONSE_FRAME_BYTES)?;
    let header = parse_header(frame, expected_source_epoch)?;
    if frame.len() > MAX_REACHABLE_RESPONSE_BYTES {
        return Err(WalletFactsWireError::LimitExceeded);
    }

    validate_response_layout(frame, &header)?;
    validate_response_uniqueness(frame, &header)?;
    construct_response(frame, header)
}

fn validate_source(source: &impl ResponseSource) -> Result<ResponseShape, WalletFactsWireError> {
    if source.transactions().len() > MAX_CANDIDATE_TRANSACTIONS
        || source.outputs().len() > MAX_AGGREGATE_OWNED_OUTPUTS
    {
        return Err(WalletFactsWireError::ObservationRejected);
    }

    let mut total_inputs = 0_usize;
    let mut output_cursor = 0_usize;
    let mut previous_transaction_id: Option<&[u8; 32]> = None;
    for transaction in source.transactions() {
        if !is_nonzero(transaction.transaction_id())
            || previous_transaction_id
                .is_some_and(|previous| previous >= transaction.transaction_id())
            || transaction.inputs().is_empty()
            || transaction.inputs().len() > MAX_INPUTS_PER_TRANSACTION
        {
            return Err(WalletFactsWireError::ObservationRejected);
        }
        previous_transaction_id = Some(transaction.transaction_id());
        total_inputs = checked_add(total_inputs, transaction.inputs().len())
            .map_err(|_| WalletFactsWireError::ObservationRejected)?;
        if total_inputs > MAX_AGGREGATE_INPUTS {
            return Err(WalletFactsWireError::ObservationRejected);
        }
        for input in transaction.inputs() {
            if !is_nonzero(input.previous_transaction_id())
                || input.previous_output_index() > MAX_SPENDABLE_OUTPUT_INDEX
            {
                return Err(WalletFactsWireError::ObservationRejected);
            }
        }

        let mut transaction_outputs = 0_usize;
        let mut previous_output_index = None;
        while output_cursor < source.outputs().len() {
            let output = &source.outputs()[output_cursor];
            match output.transaction_id().cmp(transaction.transaction_id()) {
                Ordering::Less => return Err(WalletFactsWireError::ObservationRejected),
                Ordering::Greater => break,
                Ordering::Equal => {}
            }
            if output.transaction_witness_binding() != transaction.transaction_witness_binding()
                || previous_output_index.is_some_and(|previous| previous >= output.output_index())
            {
                return Err(WalletFactsWireError::ObservationRejected);
            }
            validate_output(output)?;
            previous_output_index = Some(output.output_index());
            transaction_outputs = checked_add(transaction_outputs, 1)
                .map_err(|_| WalletFactsWireError::ObservationRejected)?;
            if transaction_outputs > MAX_OWNED_OUTPUTS_PER_TRANSACTION {
                return Err(WalletFactsWireError::ObservationRejected);
            }
            output_cursor += 1;
        }
    }
    if output_cursor != source.outputs().len() {
        return Err(WalletFactsWireError::ObservationRejected);
    }

    let transaction_bytes = checked_multiply(source.transactions().len(), TRANSACTION_FIXED_BYTES)
        .map_err(|_| WalletFactsWireError::ObservationRejected)?;
    let input_bytes = checked_multiply(total_inputs, INPUT_BYTES)
        .map_err(|_| WalletFactsWireError::ObservationRejected)?;
    let output_bytes = checked_multiply(source.outputs().len(), OUTPUT_BYTES)
        .map_err(|_| WalletFactsWireError::ObservationRejected)?;
    let total_length = checked_add(
        checked_add(
            checked_add(RESPONSE_HEADER_BYTES, transaction_bytes)?,
            input_bytes,
        )?,
        output_bytes,
    )
    .map_err(|_| WalletFactsWireError::ObservationRejected)?;
    if total_length > MAX_REACHABLE_RESPONSE_BYTES || total_length > MAX_RESPONSE_FRAME_BYTES {
        return Err(WalletFactsWireError::ObservationRejected);
    }
    Ok(ResponseShape {
        total_length,
        total_inputs,
        total_outputs: source.outputs().len(),
    })
}

fn validate_source_uniqueness(source: &impl ResponseSource) -> Result<(), WalletFactsWireError> {
    for transaction in source.transactions() {
        validate_inputs_unique(transaction.inputs())?;
    }
    Ok(())
}

#[allow(clippy::unnecessary_sort_by)]
fn validate_inputs_unique<T: InputSource>(inputs: &[T]) -> Result<(), WalletFactsWireError> {
    let mut scratch = WireOutPointScratch(Vec::with_capacity(inputs.len()));
    #[cfg(test)]
    SCRATCH_PASS_INVOCATIONS.with(|count| count.set(count.get() + 1));
    for input in inputs {
        scratch.0.push(ScopedWireOutPoint::new(input));
    }
    if scratch_is_unique(&mut scratch) {
        Ok(())
    } else {
        Err(WalletFactsWireError::ObservationRejected)
    }
}

#[allow(clippy::unnecessary_sort_by)]
fn scratch_is_unique(scratch: &mut WireOutPointScratch) -> bool {
    #[cfg(test)]
    {
        SCRATCH_LAST_CAPACITY.with(|capacity| capacity.set(scratch.0.capacity()));
        if SCRATCH_PANIC_AFTER_FILL.with(|enabled| enabled.replace(false)) {
            panic!("test-only scratch unwind");
        }
    }
    scratch
        .0
        .sort_unstable_by(|left, right| left.bytes.cmp(&right.bytes));
    !scratch
        .0
        .windows(2)
        .any(|pair| pair[0].bytes == pair[1].bytes)
}

#[cfg(test)]
thread_local! {
    static SCRATCH_POINT_DROPS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static SCRATCH_LAST_CAPACITY: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static SCRATCH_PANIC_AFTER_FILL: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static SCRATCH_PASS_INVOCATIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
pub(crate) fn scratch_point_drop_count() -> usize {
    SCRATCH_POINT_DROPS.with(std::cell::Cell::get)
}

#[cfg(test)]
pub(crate) fn scratch_last_capacity() -> usize {
    SCRATCH_LAST_CAPACITY.with(std::cell::Cell::get)
}

#[cfg(test)]
pub(crate) fn scratch_pass_invocation_count() -> usize {
    SCRATCH_PASS_INVOCATIONS.with(std::cell::Cell::get)
}

#[cfg(test)]
pub(crate) fn panic_after_scratch_fill() {
    SCRATCH_PANIC_AFTER_FILL.with(|enabled| enabled.set(true));
}

fn validate_output(output: &impl OutputSource) -> Result<(), WalletFactsWireError> {
    if output.output_index() > MAX_SPENDABLE_OUTPUT_INDEX
        || output.derivation_index() > MAX_DERIVATION_INDEX
        || !is_nonzero(output.asset_id())
        || output.value() == 0
        || output.value() > MAX_OWNED_OUTPUT_VALUE
        || !validates_observed_public_output(
            output.script_pubkey(),
            output.spend_public_key(),
            output.blinding_public_key(),
        )
    {
        return Err(WalletFactsWireError::ObservationRejected);
    }
    Ok(())
}

fn parse_header(
    frame: &[u8],
    expected_source_epoch: &[u8; 32],
) -> Result<ResponseHeader, WalletFactsWireError> {
    let mut reader = Reader::new(frame);
    if reader.take(4)? != RESPONSE_MAGIC
        || reader.read_u16()? != WIRE_VERSION
        || reader.read_u16()? as usize != RESPONSE_HEADER_BYTES
    {
        return Err(WalletFactsWireError::VersionMismatch);
    }
    let declared_length =
        usize::try_from(reader.read_u64()?).map_err(|_| WalletFactsWireError::LimitExceeded)?;
    if declared_length != frame.len() || reader.read_u32()? != 0 {
        return Err(WalletFactsWireError::InvalidEncoding);
    }
    let transaction_count = reader.read_u32()? as usize;
    let output_count = reader.read_u32()? as usize;
    if reader.read_u32()? != 0 {
        return Err(WalletFactsWireError::InvalidEncoding);
    }
    let source_epoch = ScopedWireBytes(reader.read_array::<32>()?);
    if !is_nonzero(&source_epoch.0) {
        return Err(WalletFactsWireError::InvalidEncoding);
    }
    if source_epoch.0 != *expected_source_epoch {
        return Err(WalletFactsWireError::SourceBindingMismatch);
    }
    if transaction_count > MAX_CANDIDATE_TRANSACTIONS || output_count > MAX_AGGREGATE_OWNED_OUTPUTS
    {
        return Err(WalletFactsWireError::LimitExceeded);
    }
    Ok(ResponseHeader {
        source_epoch: source_epoch.0,
        transaction_count,
        output_count,
    })
}

fn validate_response_layout(
    frame: &[u8],
    header: &ResponseHeader,
) -> Result<(), WalletFactsWireError> {
    let mut reader = Reader::new(frame);
    reader.take(RESPONSE_HEADER_BYTES)?;
    let mut total_inputs = 0_usize;
    let mut total_outputs = 0_usize;
    let mut previous_transaction_id: Option<ScopedWireBytes<32>> = None;
    for _ in 0..header.transaction_count {
        let transaction_id = ScopedWireBytes(reader.read_array::<32>()?);
        let transaction_witness_binding = ScopedWireBytes(reader.read_array::<32>()?);
        let input_count = reader.read_u32()? as usize;
        let output_count = reader.read_u32()? as usize;
        if !is_nonzero(&transaction_id.0)
            || previous_transaction_id
                .as_ref()
                .is_some_and(|previous| previous.0 >= transaction_id.0)
            || input_count == 0
        {
            return Err(WalletFactsWireError::InvalidEncoding);
        }
        if input_count > MAX_INPUTS_PER_TRANSACTION
            || output_count > MAX_OWNED_OUTPUTS_PER_TRANSACTION
        {
            return Err(WalletFactsWireError::LimitExceeded);
        }
        previous_transaction_id = Some(transaction_id);
        total_inputs = checked_add(total_inputs, input_count)?;
        total_outputs = checked_add(total_outputs, output_count)?;
        if total_inputs > MAX_AGGREGATE_INPUTS || total_outputs > MAX_AGGREGATE_OWNED_OUTPUTS {
            return Err(WalletFactsWireError::LimitExceeded);
        }
        for _ in 0..input_count {
            let previous_id = ScopedWireBytes(reader.read_array::<32>()?);
            let previous_index = reader.read_u32()?;
            if !is_nonzero(&previous_id.0) || previous_index > MAX_SPENDABLE_OUTPUT_INDEX {
                return Err(WalletFactsWireError::InvalidEncoding);
            }
        }
        let mut previous_output_index = None;
        for _ in 0..output_count {
            let output_index = reader.read_u32()?;
            let script_length = reader.read_u32()? as usize;
            let spend_public_key = ScopedWireBytes(reader.read_array::<33>()?);
            let blinding_public_key = ScopedWireBytes(reader.read_array::<33>()?);
            let branch = reader.read_u8()?;
            let reserved = reader.take(3)?;
            let derivation_index = reader.read_u32()?;
            let asset_id = ScopedWireBytes(reader.read_array::<32>()?);
            let value = reader.read_u64()?;
            if script_length != NATIVE_P2WPKH_SCRIPT_BYTES {
                return Err(WalletFactsWireError::InvalidEncoding);
            }
            let script_pubkey = ScopedWireBytes(reader.read_array::<NATIVE_P2WPKH_SCRIPT_BYTES>()?);
            if output_index > MAX_SPENDABLE_OUTPUT_INDEX
                || previous_output_index.is_some_and(|previous| previous >= output_index)
                || branch > 1
                || reserved != [0; 3]
                || derivation_index > MAX_DERIVATION_INDEX
                || !is_nonzero(&asset_id.0)
                || value == 0
                || value > MAX_OWNED_OUTPUT_VALUE
                || !validates_observed_public_output(
                    &script_pubkey.0,
                    &spend_public_key.0,
                    &blinding_public_key.0,
                )
            {
                return Err(WalletFactsWireError::InvalidEncoding);
            }
            previous_output_index = Some(output_index);
        }
        drop(transaction_witness_binding);
    }
    if total_outputs != header.output_count {
        return Err(WalletFactsWireError::InvalidEncoding);
    }
    reader.require_end()
}

fn validate_response_uniqueness(
    frame: &[u8],
    header: &ResponseHeader,
) -> Result<(), WalletFactsWireError> {
    let mut reader = Reader::new(frame);
    reader.take(RESPONSE_HEADER_BYTES)?;
    for _ in 0..header.transaction_count {
        reader.take(64)?;
        let input_count = reader.read_u32()? as usize;
        let output_count = reader.read_u32()? as usize;
        let mut scratch = WireOutPointScratch(Vec::with_capacity(input_count));
        #[cfg(test)]
        SCRATCH_PASS_INVOCATIONS.with(|count| count.set(count.get() + 1));
        for _ in 0..input_count {
            let previous_transaction_id = ScopedWireBytes(reader.read_array::<32>()?);
            let previous_output_index = reader.read_u32()?;
            scratch.0.push(ScopedWireOutPoint::new_parts(
                &previous_transaction_id.0,
                previous_output_index,
            ));
        }
        if !scratch_is_unique(&mut scratch) {
            return Err(WalletFactsWireError::InvalidEncoding);
        }
        let output_bytes = checked_multiply(output_count, OUTPUT_BYTES)?;
        reader.take(output_bytes)?;
    }
    reader.require_end()
}

fn construct_response(
    frame: &[u8],
    header: ResponseHeader,
) -> Result<DecodedWalletFactsResponse, WalletFactsWireError> {
    let mut reader = Reader::new(frame);
    reader.take(RESPONSE_HEADER_BYTES)?;
    let mut response = DecodedWalletFactsResponse {
        source_epoch: header.source_epoch,
        transactions: Vec::new(),
    };
    response
        .transactions
        .reserve_exact(header.transaction_count);
    for _ in 0..header.transaction_count {
        let mut transaction = DecodedWalletTransaction {
            transaction_id: [0; 32],
            transaction_witness_binding: [0; 32],
            inputs: Vec::new(),
            outputs: Vec::new(),
        };
        let transaction_id = ScopedWireBytes(reader.read_array::<32>()?);
        transaction
            .transaction_id
            .copy_from_slice(&transaction_id.0);
        let transaction_witness_binding = ScopedWireBytes(reader.read_array::<32>()?);
        transaction
            .transaction_witness_binding
            .copy_from_slice(&transaction_witness_binding.0);
        let input_count = reader.read_u32()? as usize;
        let output_count = reader.read_u32()? as usize;
        maybe_panic_response_staging(1);
        transaction.inputs.reserve_exact(input_count);
        transaction.outputs.reserve_exact(output_count);
        for _ in 0..input_count {
            let mut input = DecodedTransactionInput {
                previous_transaction_id: [0; 32],
                previous_output_index: 0,
            };
            let previous_transaction_id = ScopedWireBytes(reader.read_array::<32>()?);
            input
                .previous_transaction_id
                .copy_from_slice(&previous_transaction_id.0);
            input.previous_output_index = reader.read_u32()?;
            maybe_panic_response_staging(2);
            transaction.inputs.push(input);
        }
        for _ in 0..output_count {
            let mut output = DecodedOwnedOutput {
                output_index: 0,
                script_pubkey: [0; NATIVE_P2WPKH_SCRIPT_BYTES],
                spend_public_key: [0; 33],
                blinding_public_key: [0; 33],
                branch: DescriptorBranch::External,
                derivation_index: 0,
                asset_id: [0; 32],
                value: 0,
            };
            output.output_index = reader.read_u32()?;
            reader.read_u32()?;
            let spend_public_key = ScopedWireBytes(reader.read_array::<33>()?);
            output.spend_public_key.copy_from_slice(&spend_public_key.0);
            let blinding_public_key = ScopedWireBytes(reader.read_array::<33>()?);
            output
                .blinding_public_key
                .copy_from_slice(&blinding_public_key.0);
            output.branch = match reader.read_u8()? {
                0 => DescriptorBranch::External,
                1 => DescriptorBranch::Internal,
                _ => return Err(WalletFactsWireError::InvalidEncoding),
            };
            reader.take(3)?;
            output.derivation_index = reader.read_u32()?;
            let asset_id = ScopedWireBytes(reader.read_array::<32>()?);
            output.asset_id.copy_from_slice(&asset_id.0);
            output.value = reader.read_u64()?;
            let script_pubkey = ScopedWireBytes(reader.read_array::<NATIVE_P2WPKH_SCRIPT_BYTES>()?);
            output.script_pubkey.copy_from_slice(&script_pubkey.0);
            maybe_panic_response_staging(3);
            transaction.outputs.push(output);
        }
        response.transactions.push(transaction);
    }
    reader.require_end()?;
    Ok(response)
}

#[cfg(test)]
thread_local! {
    static RESPONSE_STAGING_PANIC_POINT: std::cell::Cell<u8> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
fn maybe_panic_response_staging(point: u8) {
    RESPONSE_STAGING_PANIC_POINT.with(|selected| {
        if selected.get() == point {
            selected.set(0);
            panic!("test-only response staging unwind");
        }
    });
}

#[cfg(not(test))]
fn maybe_panic_response_staging(_point: u8) {}

#[cfg(test)]
pub(crate) fn panic_during_response_staging(point: u8) {
    RESPONSE_STAGING_PANIC_POINT.with(|selected| selected.set(point));
}
