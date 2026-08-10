use wasabi_liquid_native_wallet_facts::{
    BorrowedCandidateTransaction, CandidateBatch, DescriptorCatalog, DescriptorNetwork,
    MAX_BATCH_BYTES, MAX_CANDIDATE_TRANSACTIONS, MAX_DERIVATION_INDEX,
    MAX_PREVIOUS_TRANSACTIONS_PER_BATCH, MAX_PUBLIC_DESCRIPTOR_BYTES, MAX_TRANSACTION_BYTES,
};
use zeroize::Zeroize;

use crate::reader::Reader;
use crate::writer::{Writer, checked_add};
use crate::{
    MAX_REACHABLE_REQUEST_BYTES, MAX_REQUEST_FRAME_BYTES, ScopedWireBytes, WalletFactsWireError,
    is_nonzero,
};

const REQUEST_MAGIC: &[u8; 4] = b"WLFQ";
const WIRE_VERSION: u16 = 1;
const REQUEST_HEADER_BYTES: usize = 76;
const CANDIDATE_FIXED_BYTES: usize = 12;
const LENGTH_PREFIX_BYTES: usize = 4;
const CHECKSUM_ALPHABET: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

/// One borrowed candidate and its complete borrowed previous-transaction set.
///
/// This type retains no input and deliberately implements neither `Debug`,
/// `Clone`, nor `Copy`.
pub struct WalletFactsCandidateRef<'candidate> {
    transaction: &'candidate [u8],
    previous_transactions: &'candidate [Vec<u8>],
}

impl<'candidate> WalletFactsCandidateRef<'candidate> {
    /// Creates a borrow-only candidate record.
    pub const fn new(
        transaction: &'candidate [u8],
        previous_transactions: &'candidate [Vec<u8>],
    ) -> Self {
        Self {
            transaction,
            previous_transactions,
        }
    }

    /// Borrows the exact witness-inclusive transaction bytes.
    pub const fn transaction(&self) -> &[u8] {
        self.transaction
    }

    /// Borrows the complete previous-transaction byte strings.
    pub const fn previous_transactions(&self) -> &[Vec<u8>] {
        self.previous_transactions
    }
}

/// A borrow-only request accepted by [`encode_request`].
///
/// The request retains no input and contains no blinding key, provider, wallet
/// state, randomness source, or chain authority.
pub struct WalletFactsRequestRef<'request> {
    source_epoch: &'request [u8; 32],
    descriptor_network: DescriptorNetwork,
    last_derivation_index: u32,
    public_descriptor: &'request str,
    candidates: &'request [WalletFactsCandidateRef<'request>],
}

impl<'request> WalletFactsRequestRef<'request> {
    /// Creates a borrow-only request.
    pub const fn new(
        source_epoch: &'request [u8; 32],
        descriptor_network: DescriptorNetwork,
        last_derivation_index: u32,
        public_descriptor: &'request str,
        candidates: &'request [WalletFactsCandidateRef<'request>],
    ) -> Self {
        Self {
            source_epoch,
            descriptor_network,
            last_derivation_index,
            public_descriptor,
            candidates,
        }
    }
}

/// A canonical encoded wallet-facts request.
///
/// The owned bytes are overwritten on drop. This linear wrapper deliberately
/// implements neither `Debug`, `Clone`, nor `Copy`.
pub struct EncodedWalletFactsRequest {
    bytes: Vec<u8>,
}

impl EncodedWalletFactsRequest {
    /// Borrows the complete canonical frame.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl Drop for EncodedWalletFactsRequest {
    fn drop(&mut self) {
        self.bytes.zeroize();
        #[cfg(test)]
        crate::note_drop(
            crate::DropKind::EncodedRequest,
            self.bytes.iter().all(|byte| *byte == 0),
        );
    }
}

struct ParsedCandidate {
    transaction: Vec<u8>,
    previous_transactions: Vec<Vec<u8>>,
}

impl Drop for ParsedCandidate {
    fn drop(&mut self) {
        self.transaction.zeroize();
        for previous in &mut self.previous_transactions {
            previous.zeroize();
        }
        #[cfg(test)]
        let zeroized = self.transaction.iter().all(|byte| *byte == 0)
            && self
                .previous_transactions
                .iter()
                .all(|previous| previous.iter().all(|byte| *byte == 0));
        self.previous_transactions.clear();
        #[cfg(test)]
        crate::note_drop(crate::DropKind::ParsedCandidate, zeroized);
    }
}

/// A structurally accepted request whose exact raw fields remain owned.
///
/// This value is not a semantic acceptance. Call [`Self::prepare`] to invoke
/// the existing descriptor-catalog and candidate-batch validators. The value
/// deliberately implements neither `Debug`, `Clone`, nor `Copy`.
pub struct ParsedWalletFactsRequest {
    source_epoch: [u8; 32],
    descriptor_network: DescriptorNetwork,
    last_derivation_index: u32,
    public_descriptor: String,
    candidates: Vec<ParsedCandidate>,
}

impl ParsedWalletFactsRequest {
    /// Borrows the opaque source-epoch binding.
    pub const fn source_epoch(&self) -> &[u8; 32] {
        &self.source_epoch
    }

    /// Returns the descriptor network class.
    pub const fn descriptor_network(&self) -> DescriptorNetwork {
        self.descriptor_network
    }

    /// Returns the inclusive last derivation index.
    pub const fn last_derivation_index(&self) -> u32 {
        self.last_derivation_index
    }

    /// Borrows the exact checksummed public descriptor.
    pub fn public_descriptor(&self) -> &str {
        &self.public_descriptor
    }

    /// Re-emits the exact canonical structural representation without making
    /// a semantic-acceptance claim.
    pub fn reencode(&self) -> Result<EncodedWalletFactsRequest, WalletFactsWireError> {
        encode_parts(
            &self.source_epoch,
            self.descriptor_network,
            self.last_derivation_index,
            self.public_descriptor.as_bytes(),
            self.candidates.iter().map(|candidate| CandidateParts {
                transaction: &candidate.transaction,
                previous_transactions: &candidate.previous_transactions,
            }),
            self.candidates.len(),
        )
    }

    /// Consumes raw storage and constructs the existing validated descriptor
    /// catalog and atomically bounded candidate batch.
    pub fn prepare(self) -> Result<PreparedWalletFactsRequest, WalletFactsWireError> {
        let catalog = DescriptorCatalog::derive(
            &self.public_descriptor,
            self.descriptor_network,
            self.last_derivation_index,
        )
        .map_err(|_| WalletFactsWireError::DescriptorRejected)?;
        let borrowed = self
            .candidates
            .iter()
            .map(|candidate| {
                BorrowedCandidateTransaction::new(
                    &candidate.transaction,
                    &candidate.previous_transactions,
                )
            })
            .collect::<Vec<_>>();
        let candidates =
            CandidateBatch::new(&borrowed).map_err(|_| WalletFactsWireError::CandidateRejected)?;
        let source_epoch = self.source_epoch;
        Ok(PreparedWalletFactsRequest {
            source_epoch,
            catalog,
            candidates,
        })
    }
}

impl Drop for ParsedWalletFactsRequest {
    fn drop(&mut self) {
        self.source_epoch.zeroize();
        self.last_derivation_index.zeroize();
        self.public_descriptor.zeroize();
        self.candidates.clear();
        #[cfg(test)]
        crate::note_drop(
            crate::DropKind::ParsedRequest,
            self.source_epoch.iter().all(|byte| *byte == 0)
                && self.last_derivation_index == 0
                && self
                    .public_descriptor
                    .as_bytes()
                    .iter()
                    .all(|byte| *byte == 0)
                && self.candidates.is_empty(),
        );
    }
}

/// A semantically validated request ready for a future same-crate invocation
/// adapter.
///
/// It deliberately implements neither `Debug` nor `Clone` and exposes only
/// immutable borrows.
pub struct PreparedWalletFactsRequest {
    source_epoch: [u8; 32],
    catalog: DescriptorCatalog,
    candidates: CandidateBatch,
}

impl PreparedWalletFactsRequest {
    /// Borrows the opaque source-epoch binding.
    pub const fn source_epoch(&self) -> &[u8; 32] {
        &self.source_epoch
    }

    /// Borrows the validated descriptor catalog.
    pub const fn descriptor_catalog(&self) -> &DescriptorCatalog {
        &self.catalog
    }

    /// Borrows the atomically bounded candidate batch.
    pub const fn candidate_batch(&self) -> &CandidateBatch {
        &self.candidates
    }
}

impl Drop for PreparedWalletFactsRequest {
    fn drop(&mut self) {
        self.source_epoch.zeroize();
        #[cfg(test)]
        crate::note_drop(
            crate::DropKind::PreparedRequest,
            self.source_epoch.iter().all(|byte| *byte == 0),
        );
    }
}

struct CandidateParts<'candidate> {
    transaction: &'candidate [u8],
    previous_transactions: &'candidate [Vec<u8>],
}

struct RequestHeader {
    source_epoch: [u8; 32],
    descriptor_network: DescriptorNetwork,
    last_derivation_index: u32,
    descriptor_length: usize,
    candidate_count: usize,
    previous_transaction_count: usize,
}

impl Drop for RequestHeader {
    fn drop(&mut self) {
        self.source_epoch.zeroize();
        self.last_derivation_index.zeroize();
        self.descriptor_length.zeroize();
        self.candidate_count.zeroize();
        self.previous_transaction_count.zeroize();
    }
}

/// Validates and encodes one borrow-only request.
pub fn encode_request(
    request: &WalletFactsRequestRef<'_>,
) -> Result<EncodedWalletFactsRequest, WalletFactsWireError> {
    if !is_nonzero(request.source_epoch) {
        return Err(WalletFactsWireError::InvalidArgument);
    }
    validate_descriptor_shape(request.public_descriptor.as_bytes())?;
    if request.last_derivation_index > MAX_DERIVATION_INDEX
        || request.candidates.len() > MAX_CANDIDATE_TRANSACTIONS
    {
        return Err(WalletFactsWireError::LimitExceeded);
    }

    let borrowed = request
        .candidates
        .iter()
        .map(|candidate| {
            BorrowedCandidateTransaction::new(
                candidate.transaction,
                candidate.previous_transactions,
            )
        })
        .collect::<Vec<_>>();
    let catalog = DescriptorCatalog::derive(
        request.public_descriptor,
        request.descriptor_network,
        request.last_derivation_index,
    )
    .map_err(|_| WalletFactsWireError::DescriptorRejected)?;
    let candidates =
        CandidateBatch::new(&borrowed).map_err(|_| WalletFactsWireError::CandidateRejected)?;
    drop(candidates);
    drop(catalog);
    drop(borrowed);

    encode_parts(
        request.source_epoch,
        request.descriptor_network,
        request.last_derivation_index,
        request.public_descriptor.as_bytes(),
        request.candidates.iter().map(|candidate| CandidateParts {
            transaction: candidate.transaction,
            previous_transactions: candidate.previous_transactions,
        }),
        request.candidates.len(),
    )
}

/// Structurally parses one canonical request frame without invoking descriptor
/// derivation or candidate transaction decoding.
pub fn decode_request(frame: &[u8]) -> Result<ParsedWalletFactsRequest, WalletFactsWireError> {
    validate_outer_length(frame.len(), MAX_REQUEST_FRAME_BYTES)?;
    let header = parse_header(frame)?;
    if frame.len() > MAX_REACHABLE_REQUEST_BYTES {
        return Err(WalletFactsWireError::LimitExceeded);
    }

    let mut first_pass = Reader::new(frame);
    first_pass.take(REQUEST_HEADER_BYTES)?;
    let descriptor = first_pass.take(header.descriptor_length)?;
    validate_descriptor_shape(descriptor)?;
    validate_candidate_layout(&mut first_pass, &header)?;
    first_pass.require_end()?;

    let mut reader = Reader::new(frame);
    reader.take(REQUEST_HEADER_BYTES)?;
    let mut parsed = ParsedWalletFactsRequest {
        source_epoch: header.source_epoch,
        descriptor_network: header.descriptor_network,
        last_derivation_index: header.last_derivation_index,
        public_descriptor: String::new(),
        candidates: Vec::new(),
    };
    let descriptor_bytes = reader.take(header.descriptor_length)?;
    let public_descriptor = core::str::from_utf8(descriptor_bytes)
        .map_err(|_| WalletFactsWireError::InvalidEncoding)?;
    parsed
        .public_descriptor
        .reserve_exact(header.descriptor_length);
    parsed.public_descriptor.push_str(public_descriptor);
    maybe_panic_request_staging(1);
    parsed.candidates.reserve_exact(header.candidate_count);
    for _ in 0..header.candidate_count {
        let transaction_length = reader.read_u32()? as usize;
        let previous_count = reader.read_u32()? as usize;
        reader.read_u32()?;
        let mut candidate = ParsedCandidate {
            transaction: Vec::new(),
            previous_transactions: Vec::new(),
        };
        candidate.transaction.reserve_exact(transaction_length);
        candidate
            .transaction
            .extend_from_slice(reader.take(transaction_length)?);
        maybe_panic_request_staging(2);
        candidate
            .previous_transactions
            .reserve_exact(previous_count);
        for _ in 0..previous_count {
            let previous_length = reader.read_u32()? as usize;
            candidate.previous_transactions.push(Vec::new());
            let previous = candidate
                .previous_transactions
                .last_mut()
                .ok_or(WalletFactsWireError::InvalidEncoding)?;
            previous.reserve_exact(previous_length);
            previous.extend_from_slice(reader.take(previous_length)?);
            maybe_panic_request_staging(3);
        }
        parsed.candidates.push(candidate);
    }
    reader.require_end()?;
    Ok(parsed)
}

#[cfg(test)]
thread_local! {
    static REQUEST_STAGING_PANIC_POINT: std::cell::Cell<u8> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
fn maybe_panic_request_staging(point: u8) {
    REQUEST_STAGING_PANIC_POINT.with(|selected| {
        if selected.get() == point {
            selected.set(0);
            panic!("test-only request staging unwind");
        }
    });
}

#[cfg(not(test))]
fn maybe_panic_request_staging(_point: u8) {}

#[cfg(test)]
pub(crate) fn panic_during_request_staging(point: u8) {
    REQUEST_STAGING_PANIC_POINT.with(|selected| selected.set(point));
}

fn parse_header(frame: &[u8]) -> Result<RequestHeader, WalletFactsWireError> {
    let mut reader = Reader::new(frame);
    if reader.take(4)? != REQUEST_MAGIC
        || reader.read_u16()? != WIRE_VERSION
        || reader.read_u16()? as usize != REQUEST_HEADER_BYTES
    {
        return Err(WalletFactsWireError::VersionMismatch);
    }
    let declared_length =
        usize::try_from(reader.read_u64()?).map_err(|_| WalletFactsWireError::LimitExceeded)?;
    if declared_length != frame.len() || reader.read_u32()? != 0 {
        return Err(WalletFactsWireError::InvalidEncoding);
    }
    let descriptor_network = match reader.read_u8()? {
        0 => DescriptorNetwork::Mainnet,
        1 => DescriptorNetwork::Test,
        _ => return Err(WalletFactsWireError::InvalidEncoding),
    };
    if reader.take(3)? != [0; 3] {
        return Err(WalletFactsWireError::InvalidEncoding);
    }
    let last_derivation_index = reader.read_u32()?;
    if last_derivation_index > MAX_DERIVATION_INDEX {
        return Err(WalletFactsWireError::LimitExceeded);
    }
    let source_epoch = ScopedWireBytes(reader.read_array::<32>()?);
    if !is_nonzero(&source_epoch.0) {
        return Err(WalletFactsWireError::InvalidEncoding);
    }
    let descriptor_length = reader.read_u32()? as usize;
    let candidate_count = reader.read_u32()? as usize;
    let previous_transaction_count = reader.read_u32()? as usize;
    if reader.read_u32()? != 0 {
        return Err(WalletFactsWireError::InvalidEncoding);
    }
    if descriptor_length == 0 {
        return Err(WalletFactsWireError::InvalidEncoding);
    }
    if descriptor_length > MAX_PUBLIC_DESCRIPTOR_BYTES
        || candidate_count > MAX_CANDIDATE_TRANSACTIONS
        || previous_transaction_count > MAX_PREVIOUS_TRANSACTIONS_PER_BATCH
    {
        return Err(WalletFactsWireError::LimitExceeded);
    }
    Ok(RequestHeader {
        source_epoch: source_epoch.0,
        descriptor_network,
        last_derivation_index,
        descriptor_length,
        candidate_count,
        previous_transaction_count,
    })
}

fn validate_candidate_layout(
    reader: &mut Reader<'_>,
    header: &RequestHeader,
) -> Result<(), WalletFactsWireError> {
    let mut aggregate_bytes = 0_usize;
    let mut aggregate_previous = 0_usize;
    for _ in 0..header.candidate_count {
        let transaction_length = reader.read_u32()? as usize;
        let previous_count = reader.read_u32()? as usize;
        if reader.read_u32()? != 0 {
            return Err(WalletFactsWireError::InvalidEncoding);
        }
        validate_transaction_length(transaction_length)?;
        aggregate_previous = checked_add(aggregate_previous, previous_count)?;
        if aggregate_previous > MAX_PREVIOUS_TRANSACTIONS_PER_BATCH {
            return Err(WalletFactsWireError::LimitExceeded);
        }
        aggregate_bytes = checked_add(aggregate_bytes, transaction_length)?;
        if aggregate_bytes > MAX_BATCH_BYTES {
            return Err(WalletFactsWireError::LimitExceeded);
        }
        reader.take(transaction_length)?;
        for _ in 0..previous_count {
            let previous_length = reader.read_u32()? as usize;
            validate_transaction_length(previous_length)?;
            aggregate_bytes = checked_add(aggregate_bytes, previous_length)?;
            if aggregate_bytes > MAX_BATCH_BYTES {
                return Err(WalletFactsWireError::LimitExceeded);
            }
            reader.take(previous_length)?;
        }
    }
    if aggregate_previous != header.previous_transaction_count {
        return Err(WalletFactsWireError::InvalidEncoding);
    }
    Ok(())
}

fn validate_transaction_length(length: usize) -> Result<(), WalletFactsWireError> {
    if length == 0 {
        Err(WalletFactsWireError::InvalidEncoding)
    } else if length > MAX_TRANSACTION_BYTES {
        Err(WalletFactsWireError::LimitExceeded)
    } else {
        Ok(())
    }
}

fn validate_descriptor_shape(descriptor: &[u8]) -> Result<(), WalletFactsWireError> {
    if descriptor.is_empty() {
        return Err(WalletFactsWireError::InvalidEncoding);
    }
    if descriptor.len() > MAX_PUBLIC_DESCRIPTOR_BYTES {
        return Err(WalletFactsWireError::LimitExceeded);
    }
    if !descriptor.is_ascii()
        || descriptor
            .iter()
            .any(|byte| *byte == 0 || matches!(*byte, 0x09..=0x0d | 0x20))
    {
        return Err(WalletFactsWireError::InvalidEncoding);
    }
    let mut separators = descriptor
        .iter()
        .enumerate()
        .filter(|(_, byte)| **byte == b'#');
    let Some((separator, _)) = separators.next() else {
        return Err(WalletFactsWireError::InvalidEncoding);
    };
    if separator == 0 || separators.next().is_some() {
        return Err(WalletFactsWireError::InvalidEncoding);
    }
    let checksum = &descriptor[separator + 1..];
    if checksum.len() != 8
        || checksum
            .iter()
            .any(|byte| !CHECKSUM_ALPHABET.contains(byte))
    {
        return Err(WalletFactsWireError::InvalidEncoding);
    }
    Ok(())
}

fn encode_parts<'candidate>(
    source_epoch: &[u8; 32],
    descriptor_network: DescriptorNetwork,
    last_derivation_index: u32,
    descriptor: &[u8],
    candidates: impl Iterator<Item = CandidateParts<'candidate>> + Clone,
    candidate_count: usize,
) -> Result<EncodedWalletFactsRequest, WalletFactsWireError> {
    let mut previous_count = 0_usize;
    let mut aggregate_bytes = 0_usize;
    let mut total_length = checked_add(REQUEST_HEADER_BYTES, descriptor.len())?;
    total_length = checked_add(
        total_length,
        candidate_count
            .checked_mul(CANDIDATE_FIXED_BYTES)
            .ok_or(WalletFactsWireError::LimitExceeded)?,
    )?;
    for candidate in candidates.clone() {
        validate_transaction_length(candidate.transaction.len())?;
        previous_count = checked_add(previous_count, candidate.previous_transactions.len())?;
        if previous_count > MAX_PREVIOUS_TRANSACTIONS_PER_BATCH {
            return Err(WalletFactsWireError::LimitExceeded);
        }
        aggregate_bytes = checked_add(aggregate_bytes, candidate.transaction.len())?;
        for previous in candidate.previous_transactions {
            validate_transaction_length(previous.len())?;
            aggregate_bytes = checked_add(aggregate_bytes, previous.len())?;
            total_length = checked_add(total_length, LENGTH_PREFIX_BYTES)?;
        }
        if aggregate_bytes > MAX_BATCH_BYTES {
            return Err(WalletFactsWireError::LimitExceeded);
        }
    }
    total_length = checked_add(total_length, aggregate_bytes)?;
    if total_length > MAX_REACHABLE_REQUEST_BYTES || total_length > MAX_REQUEST_FRAME_BYTES {
        return Err(WalletFactsWireError::LimitExceeded);
    }

    let mut writer = Writer::new(total_length);
    writer.write(REQUEST_MAGIC);
    writer.write_u16(WIRE_VERSION);
    writer.write_u16(REQUEST_HEADER_BYTES as u16);
    writer.write_u64(total_length as u64);
    writer.write_u32(0);
    writer.write_u8(match descriptor_network {
        DescriptorNetwork::Mainnet => 0,
        DescriptorNetwork::Test => 1,
    });
    writer.write(&[0; 3]);
    writer.write_u32(last_derivation_index);
    writer.write(source_epoch);
    writer.write_u32(descriptor.len() as u32);
    writer.write_u32(candidate_count as u32);
    writer.write_u32(previous_count as u32);
    writer.write_u32(0);
    writer.write(descriptor);
    for candidate in candidates {
        writer.write_u32(candidate.transaction.len() as u32);
        writer.write_u32(candidate.previous_transactions.len() as u32);
        writer.write_u32(0);
        writer.write(candidate.transaction);
        for previous in candidate.previous_transactions {
            writer.write_u32(previous.len() as u32);
            writer.write(previous);
        }
    }
    Ok(EncodedWalletFactsRequest {
        bytes: writer.finish()?,
    })
}

pub(crate) fn validate_outer_length(
    length: usize,
    ceiling: usize,
) -> Result<(), WalletFactsWireError> {
    if length > ceiling {
        Err(WalletFactsWireError::LimitExceeded)
    } else {
        Ok(())
    }
}
