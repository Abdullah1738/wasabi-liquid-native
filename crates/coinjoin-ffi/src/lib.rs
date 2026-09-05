#![deny(missing_docs)]
#![deny(unsafe_op_in_unsafe_fn)]

//! Versioned C ABI adapter for the Wasabi Liquid CoinJoin native primitives.
//!
//! This crate is a thin marshaling layer over the four landed, already-reviewed
//! pure primitives: `coinjoin-pset-state` (canonical PSET state projection and
//! digest), `coinjoin-equality-integration` (registration-bound equality proof
//! verification), `coinjoin-collab-blinding` (two-participant collaborative
//! blinding), and `coinjoin-partial-balance` (per-participant balance proof
//! verification). It adds NO new cryptography and NO new protocol logic.
//!
//! Every request and response crosses the boundary as exactly one bounded
//! frame `[magic u32][abi_version u32][op u32][payload_len u32][payload]`
//! whose payload is an exact concatenation of length-prefixed fields
//! `[u32 length][bytes]`. All state is serialized bytes in and out; no opaque
//! context structs are exposed. Witness material (input blinding factors, the
//! residual balance factor, blinding entropy) is supplied by the caller per
//! call, copied into scoped native storage, and zeroized before return on
//! every path; nothing retains it and no response frame carries it. The
//! intermediate handoff produced by the non-last blinding op carries the
//! fork's pending balancing scalars inside its serialized PSET global map by
//! protocol construction and is therefore witness-class bytes the caller must
//! protect; it is the only handoff representation the landed state machine
//! emits. The adapter owns no wallet, node, signer, coordinator, network,
//! broadcaster, key custody, or persistent state.

use core::{ptr, slice};
use std::collections::HashMap;
use std::panic::{AssertUnwindSafe, catch_unwind};

use elements::confidential::{AssetBlindingFactor, ValueBlindingFactor};
use elements::encode::{deserialize, serialize};
use elements::pset::PartiallySignedTransaction;
use elements::secp256k1_zkp::{All, Secp256k1};
use sha2::{Digest, Sha256};
use wasabi_liquid_native_coinjoin_collab_blinding::{self as collab, UnblindedCoinJoin};
use wasabi_liquid_native_coinjoin_equality_integration::{
    self as equality, OutputProofBinding, RegistrationContext, RegistrationKind,
};
use wasabi_liquid_native_coinjoin_partial_balance::{
    self as partial_balance, PartialBalanceContext,
};
use wasabi_liquid_native_coinjoin_pset_state::{
    CanonicalStateContext, ParticipantRole, Phase, PredecessorDigest, ProfileVersion,
    canonicalize_pset_state,
};
use zeroize::Zeroize;

/// The frozen CoinJoin ABI version.
pub const WLCJ_ABI_VERSION_V1: u32 = 1;
/// The frozen outer frame magic (`WLCJ`).
pub const WLCJ_MAGIC_V1: u32 = 0x574C_434A;
/// The complete request-frame cap enforced before caller memory is read.
pub const WLCJ_MAX_FRAME_BYTES_V1: u64 = 16_777_216;
/// The complete response-frame cap.
pub const WLCJ_MAX_RESPONSE_BYTES_V1: u64 = 16_777_216;
/// The maximum field count admitted by one payload.
pub const WLCJ_MAX_FIELDS_V1: u32 = 258;
/// The maximum individual field length.
pub const WLCJ_MAX_FIELD_BYTES_V1: u32 = 2_097_152;

const HEADER_BYTES: usize = 16;
const RESPONSE_VERDICT_BYTES: usize = 8;

/// Operation: canonical PSET state validation and digest.
pub const WLCJ_OP_CANONICALIZE_STATE_V1: u32 = 1;
/// Operation: input-registration equality proof verification.
pub const WLCJ_OP_VERIFY_INPUT_REGISTRATION_V1: u32 = 2;
/// Operation: output-registration equality proof verification.
pub const WLCJ_OP_VERIFY_OUTPUT_REGISTRATION_V1: u32 = 3;
/// Operation: participant contribution (non-last blinding).
pub const WLCJ_OP_BLIND_NON_LAST_V1: u32 = 4;
/// Operation: last-blinder completion.
pub const WLCJ_OP_BLIND_LAST_V1: u32 = 5;
/// Operation: final signer-view validation.
pub const WLCJ_OP_VALIDATE_SIGNER_VIEW_V1: u32 = 6;
/// Operation: partial-balance proof verification.
pub const WLCJ_OP_VERIFY_PARTIAL_BALANCE_V1: u32 = 7;

/// The operation succeeded and the complete response frame was copied.
pub const WLCJ_STATUS_OK_V1: i32 = 0;
/// A null shape, truncated frame, trailing bytes, or malformed field encoding.
pub const WLCJ_STATUS_INVALID_FRAME_V1: i32 = -1;
/// The ABI version is not supported.
pub const WLCJ_STATUS_UNSUPPORTED_ABI_V1: i32 = -2;
/// The operation code is not assigned.
pub const WLCJ_STATUS_UNKNOWN_OP_V1: i32 = -3;
/// A frame, payload, or field bound was exceeded.
pub const WLCJ_STATUS_PAYLOAD_TOO_LARGE_V1: i32 = -4;
/// The delegated validation rejected the request's public state.
pub const WLCJ_STATUS_VALIDATION_FAILED_V1: i32 = -5;
/// The delegated proof verification failed.
pub const WLCJ_STATUS_VERIFICATION_FAILED_V1: i32 = -6;
/// A contained panic or impossible invariant was encountered.
pub const WLCJ_STATUS_INTERNAL_ERROR_V1: i32 = -7;
/// The response buffer is absent or too small; the required length is published.
pub const WLCJ_STATUS_OUTPUT_CAPACITY_V1: i32 = -8;

/// Per-op payload bounds, fixed by the frozen ABI.
const OP_PAYLOAD_BOUNDS: [u32; 7] = [
    1_081_344, // op 1: canonicalize state
    1_081_344, // op 2: verify input registration
    3_178_496, // op 3: verify output registration
    2_097_152, // op 4: blind non-last
    2_097_152, // op 5: blind last
    1_081_344, // op 6: validate signer view
    1_081_344, // op 7: verify partial balance
];

const SECRET_RECORD_BYTES: usize = 108;

struct ScopedBytes(Vec<u8>);

impl Drop for ScopedBytes {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// A NIST SP 800-90A Hash-DRBG built from the already-approved `sha2`
/// primitive. It expands one caller-supplied 32-byte seed into the
/// `R: RngCore + CryptoRng` the blinding paths require. The native side
/// fabricates no RNG from ambient or OS entropy; the entire stream is a pure
/// function of the caller-owned seed. The internal state is zeroized on drop.
struct HashDrbg {
    state: [u8; 32],
    counter: u64,
}

impl HashDrbg {
    fn new(seed: &[u8; 32]) -> Self {
        let state = Sha256::new_with_prefix(b"WLCJ_HASH_DRBG_V1")
            .chain_update(seed)
            .finalize()
            .into();
        Self { state, counter: 0 }
    }

    fn reseed_from_output(&mut self) {
        let next: [u8; 32] = Sha256::new_with_prefix(b"WLCJ_HASH_DRBG_V1_RESEED")
            .chain_update(self.state)
            .finalize()
            .into();
        self.state = next;
        self.counter = 0;
    }
}

impl rand::RngCore for HashDrbg {
    fn next_u32(&mut self) -> u32 {
        let mut word = [0u8; 4];
        self.fill_bytes(&mut word);
        u32::from_le_bytes(word)
    }

    fn next_u64(&mut self) -> u64 {
        let mut word = [0u8; 8];
        self.fill_bytes(&mut word);
        u64::from_le_bytes(word)
    }

    fn fill_bytes(&mut self, destination: &mut [u8]) {
        for chunk in destination.chunks_mut(32) {
            let block: [u8; 32] = Sha256::new_with_prefix(b"WLCJ_HASH_DRBG_V1_BLOCK")
                .chain_update(self.state)
                .chain_update(self.counter.to_le_bytes())
                .finalize()
                .into();
            chunk.copy_from_slice(&block[..chunk.len()]);
            self.counter += 1;
            if self.counter == u64::MAX {
                self.reseed_from_output();
            }
        }
    }

    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), rand::Error> {
        self.fill_bytes(destination);
        Ok(())
    }
}

impl rand::CryptoRng for HashDrbg {}

impl Drop for HashDrbg {
    fn drop(&mut self) {
        self.state.zeroize();
        self.counter = 0;
    }
}

/// Privacy-redacted internal failure categories; each maps to exactly one
/// frozen public status.
enum Rejection {
    InvalidFrame,
    PayloadTooLarge,
    ValidationFailed,
    VerificationFailed,
    InternalError,
}

impl Rejection {
    const fn status(&self) -> i32 {
        match self {
            Self::InvalidFrame => WLCJ_STATUS_INVALID_FRAME_V1,
            Self::PayloadTooLarge => WLCJ_STATUS_PAYLOAD_TOO_LARGE_V1,
            Self::ValidationFailed => WLCJ_STATUS_VALIDATION_FAILED_V1,
            Self::VerificationFailed => WLCJ_STATUS_VERIFICATION_FAILED_V1,
            Self::InternalError => WLCJ_STATUS_INTERNAL_ERROR_V1,
        }
    }
}

struct FrameHeader {
    op: u32,
    payload_len: usize,
}

struct ParsedContext {
    network_identity: Vec<u8>,
    genesis_hash: [u8; 32],
    lbtc_asset: [u8; 32],
    fee_asset: [u8; 32],
    round_id: Vec<u8>,
    phase: u8,
    participant_role: u8,
    contribution_ordinal: u32,
    predecessor: Option<[u8; 32]>,
}

struct ParsedRegistrationContext {
    network_identity: Vec<u8>,
    genesis_hash: [u8; 32],
    lbtc_asset: [u8; 32],
    round_id: Vec<u8>,
    phase: u8,
    participant_role: u8,
    contribution_ordinal: u32,
    kind: u8,
    element_index: u32,
    pset_state_digest: [u8; 32],
}

struct ParsedPartialBalanceContext {
    network_identity: Vec<u8>,
    genesis_hash: [u8; 32],
    lbtc_asset: [u8; 32],
    round_id: Vec<u8>,
    phase: u8,
    participant_role: u8,
    contribution_ordinal: u32,
    pset_state_digest: [u8; 32],
    input_indices: Vec<u32>,
    output_indices: Vec<u32>,
    fee_share: u64,
}

struct SecretRecord {
    input_index: u32,
    asset: [u8; 32],
    asset_bf: [u8; 32],
    value: u64,
    value_bf: [u8; 32],
}

struct SecretSet {
    asset: elements::AssetId,
    records: Vec<SecretRecord>,
}

impl Drop for SecretSet {
    fn drop(&mut self) {
        for record in &mut self.records {
            record.asset.zeroize();
            record.asset_bf.zeroize();
            record.value = 0;
            record.value_bf.zeroize();
        }
    }
}

fn push_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn push_field(out: &mut Vec<u8>, bytes: &[u8]) {
    push_u32(out, bytes.len() as u32);
    out.extend_from_slice(bytes);
}

fn take<'a>(bytes: &mut &'a [u8], length: usize) -> Result<&'a [u8], Rejection> {
    if bytes.len() < length {
        return Err(Rejection::InvalidFrame);
    }
    let (head, tail) = bytes.split_at(length);
    *bytes = tail;
    Ok(head)
}

fn take_u32(bytes: &mut &[u8]) -> Result<u32, Rejection> {
    Ok(u32::from_be_bytes(
        take(bytes, 4)?
            .try_into()
            .map_err(|_| Rejection::InternalError)?,
    ))
}

fn take_u64(bytes: &mut &[u8]) -> Result<u64, Rejection> {
    Ok(u64::from_be_bytes(
        take(bytes, 8)?
            .try_into()
            .map_err(|_| Rejection::InternalError)?,
    ))
}

fn take_array<const N: usize>(bytes: &mut &[u8]) -> Result<[u8; N], Rejection> {
    take(bytes, N)?
        .try_into()
        .map_err(|_| Rejection::InternalError)
}

/// Splits one exact payload into its field bodies, enforcing the per-field
/// bound, the field-count bound, and exact consumption (no truncation, no
/// trailing bytes).
fn split_fields(payload: &[u8]) -> Result<Vec<&[u8]>, Rejection> {
    let mut fields = Vec::new();
    let mut rest = payload;
    while !rest.is_empty() {
        let length = take_u32(&mut rest)?;
        if length > WLCJ_MAX_FIELD_BYTES_V1 {
            return Err(Rejection::PayloadTooLarge);
        }
        fields.push(take(&mut rest, length as usize)?);
        if fields.len() > WLCJ_MAX_FIELDS_V1 as usize {
            return Err(Rejection::PayloadTooLarge);
        }
    }
    Ok(fields)
}

fn expect_fields<'a>(payload: &'a [u8], expected: &[u32]) -> Result<Vec<&'a [u8]>, Rejection> {
    let fields = split_fields(payload)?;
    if fields.len() != expected.len() {
        return Err(Rejection::InvalidFrame);
    }
    for (field, expected_len) in fields.iter().zip(expected.iter()) {
        // u32::MAX is the variable-length wildcard; a fixed entry pins the
        // exact field length.
        if *expected_len != u32::MAX && field.len() != *expected_len as usize {
            return Err(Rejection::InvalidFrame);
        }
    }
    Ok(fields)
}

fn parse_bounded_bytes(bytes: &mut &[u8], maximum: usize) -> Result<Vec<u8>, Rejection> {
    let length = take_u32(bytes)? as usize;
    if length == 0 || length > maximum {
        return Err(Rejection::ValidationFailed);
    }
    Ok(take(bytes, length)?.to_vec())
}

fn parse_context(bytes: &[u8]) -> Result<ParsedContext, Rejection> {
    let mut rest = bytes;
    let profile = take(&mut rest, 1)?[0];
    if profile != ProfileVersion::V1 as u8 {
        return Err(Rejection::ValidationFailed);
    }
    let network_identity = parse_bounded_bytes(
        &mut rest,
        wasabi_liquid_native_coinjoin_pset_state::MAX_NETWORK_IDENTITY_BYTES,
    )?;
    let genesis_hash = take_array(&mut rest)?;
    let lbtc_asset = take_array(&mut rest)?;
    let fee_asset = take_array(&mut rest)?;
    let round_id = parse_bounded_bytes(
        &mut rest,
        wasabi_liquid_native_coinjoin_pset_state::MAX_ROUND_ID_BYTES,
    )?;
    let phase = take(&mut rest, 1)?[0];
    let participant_role = take(&mut rest, 1)?[0];
    let contribution_ordinal = take_u32(&mut rest)?;
    let predecessor = match take(&mut rest, 1)?[0] {
        0 => None,
        1 => Some(take_array(&mut rest)?),
        _ => return Err(Rejection::ValidationFailed),
    };
    if !rest.is_empty() {
        return Err(Rejection::InvalidFrame);
    }
    Ok(ParsedContext {
        network_identity,
        genesis_hash,
        lbtc_asset,
        fee_asset,
        round_id,
        phase,
        participant_role,
        contribution_ordinal,
        predecessor,
    })
}

impl ParsedContext {
    fn canonical_context(&self) -> Result<CanonicalStateContext<'_>, Rejection> {
        Ok(CanonicalStateContext {
            profile: ProfileVersion::V1,
            network_identity: &self.network_identity,
            genesis_hash: self.genesis_hash,
            lbtc_asset: elements::AssetId::from_byte_array(self.lbtc_asset),
            fee_asset: elements::AssetId::from_byte_array(self.fee_asset),
            round_id: &self.round_id,
            phase: parse_phase(self.phase)?,
            participant_role: parse_role(self.participant_role)?,
            contribution_ordinal: self.contribution_ordinal,
            predecessor: match self.predecessor {
                None => PredecessorDigest::Absent,
                Some(digest) => PredecessorDigest::Present(digest),
            },
        })
    }
}

fn parse_phase(value: u8) -> Result<Phase, Rejection> {
    match value {
        1 => Ok(Phase::Construction),
        2 => Ok(Phase::Proofs),
        3 => Ok(Phase::PreSigning),
        _ => Err(Rejection::ValidationFailed),
    }
}

fn parse_role(value: u8) -> Result<ParticipantRole, Rejection> {
    match value {
        1 => Ok(ParticipantRole::Initiator),
        2 => Ok(ParticipantRole::Responder),
        _ => Err(Rejection::ValidationFailed),
    }
}

fn parse_registration_context(bytes: &[u8]) -> Result<ParsedRegistrationContext, Rejection> {
    let mut rest = bytes;
    let profile = take(&mut rest, 1)?[0];
    if profile != ProfileVersion::V1 as u8 {
        return Err(Rejection::ValidationFailed);
    }
    let network_identity = parse_bounded_bytes(
        &mut rest,
        wasabi_liquid_native_coinjoin_pset_state::MAX_NETWORK_IDENTITY_BYTES,
    )?;
    let genesis_hash = take_array(&mut rest)?;
    let lbtc_asset = take_array(&mut rest)?;
    let round_id = parse_bounded_bytes(
        &mut rest,
        wasabi_liquid_native_coinjoin_pset_state::MAX_ROUND_ID_BYTES,
    )?;
    let phase = take(&mut rest, 1)?[0];
    let participant_role = take(&mut rest, 1)?[0];
    let contribution_ordinal = take_u32(&mut rest)?;
    let kind = take(&mut rest, 1)?[0];
    let element_index = take_u32(&mut rest)?;
    let pset_state_digest = take_array(&mut rest)?;
    if !rest.is_empty() {
        return Err(Rejection::InvalidFrame);
    }
    // Structural enum cross-checks happen here so the typed reconstruction
    // can never fail for a reason the frame layer did not already reject.
    parse_phase(phase)?;
    parse_role(participant_role)?;
    match kind {
        1 | 2 => {}
        _ => return Err(Rejection::ValidationFailed),
    }
    Ok(ParsedRegistrationContext {
        network_identity,
        genesis_hash,
        lbtc_asset,
        round_id,
        phase,
        participant_role,
        contribution_ordinal,
        kind,
        element_index,
        pset_state_digest,
    })
}

fn parse_partial_balance_context(bytes: &[u8]) -> Result<ParsedPartialBalanceContext, Rejection> {
    let mut rest = bytes;
    let profile = take(&mut rest, 1)?[0];
    if profile != ProfileVersion::V1 as u8 {
        return Err(Rejection::ValidationFailed);
    }
    let network_identity = parse_bounded_bytes(
        &mut rest,
        wasabi_liquid_native_coinjoin_pset_state::MAX_NETWORK_IDENTITY_BYTES,
    )?;
    let genesis_hash = take_array(&mut rest)?;
    let lbtc_asset = take_array(&mut rest)?;
    let round_id = parse_bounded_bytes(
        &mut rest,
        wasabi_liquid_native_coinjoin_pset_state::MAX_ROUND_ID_BYTES,
    )?;
    let phase = take(&mut rest, 1)?[0];
    let participant_role = take(&mut rest, 1)?[0];
    let contribution_ordinal = take_u32(&mut rest)?;
    let pset_state_digest = take_array(&mut rest)?;
    parse_phase(phase)?;
    parse_role(participant_role)?;
    let input_indices = parse_indices(&mut rest)?;
    let output_indices = parse_indices(&mut rest)?;
    let fee_share = take_u64(&mut rest)?;
    if !rest.is_empty() {
        return Err(Rejection::InvalidFrame);
    }
    Ok(ParsedPartialBalanceContext {
        network_identity,
        genesis_hash,
        lbtc_asset,
        round_id,
        phase,
        participant_role,
        contribution_ordinal,
        pset_state_digest,
        input_indices,
        output_indices,
        fee_share,
    })
}

fn parse_indices(rest: &mut &[u8]) -> Result<Vec<u32>, Rejection> {
    let count = take_u32(rest)? as usize;
    if count > wasabi_liquid_native_coinjoin_partial_balance::MAX_INDICES {
        return Err(Rejection::ValidationFailed);
    }
    let mut indices = Vec::with_capacity(count);
    for _ in 0..count {
        indices.push(take_u32(rest)?);
    }
    Ok(indices)
}

/// Parses the role map: `u32 count` then `count` ascending, strictly
/// increasing `(u32 output_index, u8 role)` records.
fn parse_role_map(bytes: &[u8]) -> Result<HashMap<usize, collab::Role>, Rejection> {
    let mut rest = bytes;
    let count = take_u32(&mut rest)? as usize;
    if count > wasabi_liquid_native_coinjoin_pset_state::MAX_OUTPUT_COUNT {
        return Err(Rejection::ValidationFailed);
    }
    let mut map = HashMap::with_capacity(count);
    let mut previous: Option<u32> = None;
    for _ in 0..count {
        let index = take_u32(&mut rest)?;
        let role = match take(&mut rest, 1)?[0] {
            1 => collab::Role::A,
            2 => collab::Role::B,
            _ => return Err(Rejection::ValidationFailed),
        };
        if previous.is_some_and(|prior| index <= prior) {
            return Err(Rejection::ValidationFailed);
        }
        previous = Some(index);
        map.insert(
            usize::try_from(index).map_err(|_| Rejection::ValidationFailed)?,
            role,
        );
    }
    if !rest.is_empty() {
        return Err(Rejection::InvalidFrame);
    }
    Ok(map)
}

/// Parses the witness-class input-secret vector into scoped storage. Every
/// record is `u32 input_index || 32-byte asset id || 32-byte asset blinding
/// factor || u64 value || 32-byte value blinding factor`.
fn parse_input_secrets(bytes: &[u8]) -> Result<SecretSet, Rejection> {
    let mut rest = bytes;
    if !rest.len().is_multiple_of(SECRET_RECORD_BYTES) {
        return Err(Rejection::InvalidFrame);
    }
    let count = rest.len() / SECRET_RECORD_BYTES;
    if count > wasabi_liquid_native_coinjoin_pset_state::MAX_INPUT_COUNT {
        return Err(Rejection::ValidationFailed);
    }
    let mut records = Vec::with_capacity(count);
    let mut asset: Option<[u8; 32]> = None;
    let mut previous: Option<u32> = None;
    while !rest.is_empty() {
        let input_index = take_u32(&mut rest)?;
        let record_asset = take_array(&mut rest)?;
        let asset_bf = take_array(&mut rest)?;
        let value = take_u64(&mut rest)?;
        let value_bf = take_array(&mut rest)?;
        match asset {
            None => asset = Some(record_asset),
            Some(expected) if expected != record_asset => {
                return Err(Rejection::ValidationFailed);
            }
            _ => {}
        }
        if previous.is_some_and(|prior| input_index <= prior) {
            return Err(Rejection::ValidationFailed);
        }
        previous = Some(input_index);
        records.push(SecretRecord {
            input_index,
            asset: record_asset,
            asset_bf,
            value,
            value_bf,
        });
    }
    Ok(SecretSet {
        asset: elements::AssetId::from_byte_array(asset.ok_or(Rejection::ValidationFailed)?),
        records,
    })
}

impl SecretSet {
    fn as_txout_secrets(&self) -> Result<HashMap<usize, elements::TxOutSecrets>, Rejection> {
        let mut map = HashMap::with_capacity(self.records.len());
        for record in &self.records {
            let index =
                usize::try_from(record.input_index).map_err(|_| Rejection::ValidationFailed)?;
            let secrets = elements::TxOutSecrets::new(
                self.asset,
                AssetBlindingFactor::from_slice(&record.asset_bf)
                    .map_err(|_| Rejection::ValidationFailed)?,
                record.value,
                ValueBlindingFactor::from_slice(&record.value_bf)
                    .map_err(|_| Rejection::ValidationFailed)?,
            );
            if map.insert(index, secrets).is_some() {
                return Err(Rejection::ValidationFailed);
            }
        }
        Ok(map)
    }
}

fn decode_pset(bytes: &[u8]) -> Result<PartiallySignedTransaction, Rejection> {
    if bytes.is_empty() {
        return Err(Rejection::ValidationFailed);
    }
    let pset: PartiallySignedTransaction =
        deserialize(bytes).map_err(|_| Rejection::ValidationFailed)?;
    if serialize(&pset) != bytes {
        return Err(Rejection::ValidationFailed);
    }
    Ok(pset)
}

fn build_state(pset_bytes: &[u8], role_map_bytes: &[u8]) -> Result<UnblindedCoinJoin, Rejection> {
    let pset = decode_pset(pset_bytes)?;
    let role_map = parse_role_map(role_map_bytes)?;
    let assets: Vec<Option<elements::AssetId>> =
        pset.outputs().iter().map(|output| output.asset).collect();
    let mut asset: Option<elements::AssetId> = None;
    for candidate in assets.into_iter().flatten() {
        match asset {
            None => asset = Some(candidate),
            Some(expected) if expected != candidate => {
                return Err(Rejection::ValidationFailed);
            }
            _ => {}
        }
    }
    UnblindedCoinJoin::new(pset, &role_map, asset.ok_or(Rejection::ValidationFailed)?)
        .map_err(|_| Rejection::ValidationFailed)
}

fn verdict_payload() -> Vec<u8> {
    let mut payload = Vec::with_capacity(RESPONSE_VERDICT_BYTES);
    push_u32(&mut payload, 4);
    payload.extend_from_slice(b"OK\0\0");
    payload
}

fn op_canonicalize_state(payload: &[u8]) -> Result<Vec<u8>, Rejection> {
    let fields = expect_fields(payload, &[u32::MAX, u32::MAX])?;
    let context = parse_context(fields[1])?;
    let canonical = canonicalize_pset_state(fields[0], &context.canonical_context()?)
        .map_err(|_| Rejection::ValidationFailed)?;
    let (canonical_bytes, digest) = canonical.into_parts();
    let mut response = Vec::with_capacity(canonical_bytes.len() + 72);
    push_field(&mut response, &canonical_bytes);
    push_field(&mut response, digest.as_bytes());
    Ok(response)
}

fn op_verify_registration(payload: &[u8], kind: RegistrationKind) -> Result<Vec<u8>, Rejection> {
    let expected: &[u32] = match kind {
        RegistrationKind::InputRegistration => &[u32::MAX, u32::MAX, 162, 33],
        RegistrationKind::OutputRegistration => &[u32::MAX, u32::MAX, 162, 33, u32::MAX, u32::MAX],
    };
    let fields = expect_fields(payload, expected)?;
    let parsed = parse_registration_context(fields[1])?;
    if parsed.kind != kind as u8 {
        return Err(Rejection::ValidationFailed);
    }
    let secp: Secp256k1<All> = Secp256k1::new();
    let statement = match kind {
        RegistrationKind::InputRegistration => {
            let pset = decode_pset(fields[0])?;
            let index =
                usize::try_from(parsed.element_index).map_err(|_| Rejection::ValidationFailed)?;
            let utxo = pset
                .inputs()
                .get(index)
                .and_then(|input| input.witness_utxo.as_ref())
                .ok_or(Rejection::ValidationFailed)?;
            equality::input_registration_statement(fields[3], utxo)
                .map_err(|_| Rejection::ValidationFailed)?
        }
        RegistrationKind::OutputRegistration => {
            let pset = decode_pset(fields[0])?;
            let index =
                usize::try_from(parsed.element_index).map_err(|_| Rejection::ValidationFailed)?;
            equality::output_registration_statement(fields[3], &pset, index)
                .map_err(|_| Rejection::ValidationFailed)?
        }
    };
    let context = RegistrationContext {
        profile: ProfileVersion::V1,
        network_identity: &parsed.network_identity,
        genesis_hash: parsed.genesis_hash,
        lbtc_asset: elements::AssetId::from_byte_array(parsed.lbtc_asset),
        round_id: &parsed.round_id,
        phase: parse_phase(parsed.phase)?,
        participant_role: parse_role(parsed.participant_role)?,
        contribution_ordinal: parsed.contribution_ordinal,
        kind,
        element_index: parsed.element_index,
        pset_state_digest: parsed.pset_state_digest,
        output_proof_binding: match kind {
            RegistrationKind::InputRegistration => None,
            RegistrationKind::OutputRegistration => Some(OutputProofBinding {
                value_rangeproof: fields[4],
                asset_surjection_proof: fields[5],
            }),
        },
    };
    equality::verify_registration(&secp, &statement, fields[2], &context)
        .map_err(|_| Rejection::VerificationFailed)?;
    Ok(verdict_payload())
}

fn op_blind_non_last(payload: &[u8]) -> Result<Vec<u8>, Rejection> {
    let fields = expect_fields(payload, &[u32::MAX, u32::MAX, u32::MAX, 32])?;
    let state = build_state(fields[0], fields[1])?;
    let secrets = parse_input_secrets(fields[2])?;
    let secrets_map = secrets.as_txout_secrets()?;
    let entropy = ScopedBytes(fields[3].to_vec());
    let intermediate = {
        let entropy_array: &[u8; 32] = entropy
            .0
            .as_slice()
            .try_into()
            .map_err(|_| Rejection::InternalError)?;
        let mut rng = HashDrbg::new(entropy_array);
        collab::participant_a_blind_non_last(&state, &mut rng, &secrets_map)
            .map_err(|_| Rejection::ValidationFailed)?
    };
    let mut response = Vec::with_capacity(intermediate.len() + 8);
    push_field(&mut response, &intermediate);
    Ok(response)
}

fn op_blind_last(payload: &[u8]) -> Result<Vec<u8>, Rejection> {
    let fields = expect_fields(payload, &[u32::MAX, u32::MAX, u32::MAX, u32::MAX, 32])?;
    let state = build_state(fields[0], fields[1])?;
    let secrets = parse_input_secrets(fields[3])?;
    let secrets_map = secrets.as_txout_secrets()?;
    let entropy = ScopedBytes(fields[4].to_vec());
    let final_pset = {
        let entropy_array: &[u8; 32] = entropy
            .0
            .as_slice()
            .try_into()
            .map_err(|_| Rejection::InternalError)?;
        let mut rng = HashDrbg::new(entropy_array);
        collab::participant_b_blind_last(&state, fields[2], &mut rng, &secrets_map)
            .map_err(|_| Rejection::ValidationFailed)?
    };
    collab::verify_final(&state, &final_pset).map_err(|_| Rejection::VerificationFailed)?;
    let final_bytes = serialize(&final_pset);
    let mut response = Vec::with_capacity(final_bytes.len() + 8);
    push_field(&mut response, &final_bytes);
    Ok(response)
}

fn op_validate_signer_view(payload: &[u8]) -> Result<Vec<u8>, Rejection> {
    let fields = expect_fields(payload, &[u32::MAX, u32::MAX])?;
    let pset_bytes = fields[0];
    let pset = decode_pset(pset_bytes)?;
    if !pset.global.scalars.is_empty() {
        return Err(Rejection::ValidationFailed);
    }
    let context = parse_context(fields[1])?;
    let canonical = canonicalize_pset_state(pset_bytes, &context.canonical_context()?)
        .map_err(|_| Rejection::ValidationFailed)?;
    let digest = canonical.digest();
    let mut response = Vec::with_capacity(RESPONSE_VERDICT_BYTES + 40);
    push_field(&mut response, b"OK\0\0");
    push_field(&mut response, digest.as_bytes());
    Ok(response)
}

fn op_verify_partial_balance(payload: &[u8]) -> Result<Vec<u8>, Rejection> {
    let fields = expect_fields(payload, &[u32::MAX, u32::MAX, 65])?;
    let pset = decode_pset(fields[0])?;
    let parsed = parse_partial_balance_context(fields[1])?;
    let proof =
        partial_balance::decode_proof(fields[2]).map_err(|_| Rejection::VerificationFailed)?;
    let context = PartialBalanceContext {
        profile: ProfileVersion::V1,
        network_identity: &parsed.network_identity,
        genesis_hash: parsed.genesis_hash,
        lbtc_asset: elements::AssetId::from_byte_array(parsed.lbtc_asset),
        round_id: &parsed.round_id,
        phase: parse_phase(parsed.phase)?,
        participant_role: parse_role(parsed.participant_role)?,
        contribution_ordinal: parsed.contribution_ordinal,
        pset_state_digest: parsed.pset_state_digest,
        input_indices: &parsed.input_indices,
        output_indices: &parsed.output_indices,
        fee_share: parsed.fee_share,
    };
    let secp: Secp256k1<All> = Secp256k1::new();
    partial_balance::verify_partial_balance(&secp, &pset, &context, &proof)
        .map_err(|_| Rejection::VerificationFailed)?;
    Ok(verdict_payload())
}

fn dispatch(op: u32, payload: &[u8]) -> Result<Vec<u8>, Rejection> {
    match op {
        WLCJ_OP_CANONICALIZE_STATE_V1 => op_canonicalize_state(payload),
        WLCJ_OP_VERIFY_INPUT_REGISTRATION_V1 => {
            op_verify_registration(payload, RegistrationKind::InputRegistration)
        }
        WLCJ_OP_VERIFY_OUTPUT_REGISTRATION_V1 => {
            op_verify_registration(payload, RegistrationKind::OutputRegistration)
        }
        WLCJ_OP_BLIND_NON_LAST_V1 => op_blind_non_last(payload),
        WLCJ_OP_BLIND_LAST_V1 => op_blind_last(payload),
        WLCJ_OP_VALIDATE_SIGNER_VIEW_V1 => op_validate_signer_view(payload),
        WLCJ_OP_VERIFY_PARTIAL_BALANCE_V1 => op_verify_partial_balance(payload),
        _ => Err(Rejection::InvalidFrame),
    }
}

fn parse_header(frame: &[u8]) -> Result<FrameHeader, i32> {
    if frame.len() < HEADER_BYTES {
        return Err(WLCJ_STATUS_INVALID_FRAME_V1);
    }
    let (header, payload) = frame.split_at(HEADER_BYTES);
    let magic = u32::from_be_bytes(
        header[0..4]
            .try_into()
            .map_err(|_| WLCJ_STATUS_INTERNAL_ERROR_V1)?,
    );
    if magic != WLCJ_MAGIC_V1 {
        return Err(WLCJ_STATUS_INVALID_FRAME_V1);
    }
    let abi = u32::from_be_bytes(
        header[4..8]
            .try_into()
            .map_err(|_| WLCJ_STATUS_INTERNAL_ERROR_V1)?,
    );
    if abi != WLCJ_ABI_VERSION_V1 {
        return Err(WLCJ_STATUS_UNSUPPORTED_ABI_V1);
    }
    let op = u32::from_be_bytes(
        header[8..12]
            .try_into()
            .map_err(|_| WLCJ_STATUS_INTERNAL_ERROR_V1)?,
    );
    let payload_len = u32::from_be_bytes(
        header[12..16]
            .try_into()
            .map_err(|_| WLCJ_STATUS_INTERNAL_ERROR_V1)?,
    ) as usize;
    if payload_len != payload.len() {
        return Err(WLCJ_STATUS_INVALID_FRAME_V1);
    }
    if !(1..=7).contains(&op) {
        return Err(WLCJ_STATUS_UNKNOWN_OP_V1);
    }
    if payload_len > OP_PAYLOAD_BOUNDS[op as usize - 1] as usize {
        return Err(WLCJ_STATUS_PAYLOAD_TOO_LARGE_V1);
    }
    Ok(FrameHeader { op, payload_len })
}

fn build_response_frame(op: u32, payload: &[u8]) -> Result<Vec<u8>, i32> {
    if payload.len() > WLCJ_MAX_RESPONSE_BYTES_V1 as usize - HEADER_BYTES {
        return Err(WLCJ_STATUS_PAYLOAD_TOO_LARGE_V1);
    }
    let mut frame = Vec::with_capacity(HEADER_BYTES + payload.len());
    push_u32(&mut frame, WLCJ_MAGIC_V1);
    push_u32(&mut frame, WLCJ_ABI_VERSION_V1);
    push_u32(&mut frame, op);
    push_u32(&mut frame, payload.len() as u32);
    frame.extend_from_slice(payload);
    Ok(frame)
}

/// Executes one bounded CoinJoin v1 operation over raw byte frames.
///
/// A null `out_frame` with a zero capacity is the capacity query: the
/// required response frame length is published through `out_frame_length` and
/// [`WLCJ_STATUS_OUTPUT_CAPACITY_V1`] is returned. The same status is
/// returned when a non-null buffer is too small; the required length is
/// always published first. Every other failure publishes an
/// `out_frame_length` of zero and writes nothing to `out_frame`.
///
/// # Safety
///
/// `request_frame` must reference `request_frame_length` readable immutable
/// bytes and `out_frame_length` must reference one writable `u64`. A non-null
/// `out_frame` must reference `out_frame_capacity` writable bytes that do not
/// overlap any input. All regions must remain valid until this call returns.
/// Null and length shapes are checked before dereference, but no C ABI can
/// validate arbitrary non-null pointer provenance.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wlcj_execute_impl_v1(
    request_frame: *const u8,
    request_frame_length: u64,
    out_frame: *mut u8,
    out_frame_capacity: u64,
    out_frame_length: *mut u64,
) -> i32 {
    if out_frame_length.is_null() {
        return WLCJ_STATUS_INVALID_FRAME_V1;
    }

    let outcome = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: The caller contract requires a writable non-overlapping u64;
        // null was the sole check before entering this panic boundary.
        unsafe { ptr::write(out_frame_length, 0) };

        if request_frame.is_null()
            || request_frame_length == 0
            || (out_frame.is_null() && out_frame_capacity != 0)
        {
            return Err(WLCJ_STATUS_INVALID_FRAME_V1);
        }
        if request_frame_length > WLCJ_MAX_FRAME_BYTES_V1 {
            return Err(WLCJ_STATUS_PAYLOAD_TOO_LARGE_V1);
        }
        let request_frame_length =
            usize::try_from(request_frame_length).map_err(|_| WLCJ_STATUS_INVALID_FRAME_V1)?;
        let out_frame_capacity =
            usize::try_from(out_frame_capacity).map_err(|_| WLCJ_STATUS_INVALID_FRAME_V1)?;

        // SAFETY: The caller contract supplies this readable region; null,
        // zero, the outer cap, and usize conversion were checked first.
        let frame = ScopedBytes(
            unsafe { slice::from_raw_parts(request_frame, request_frame_length) }.to_vec(),
        );
        maybe_inject_test_panic();

        let header = parse_header(&frame.0)?;
        let payload = &frame.0[HEADER_BYTES..HEADER_BYTES + header.payload_len];
        let response_payload = dispatch(header.op, payload).map_err(|error| error.status())?;
        let response = build_response_frame(header.op, &response_payload)?;
        let required = response.len() as u64;
        // SAFETY: The caller supplied one writable u64 and it does not overlap
        // inputs or the response buffer.
        unsafe { ptr::write(out_frame_length, required) };

        if out_frame.is_null() || response.len() > out_frame_capacity {
            return Err(WLCJ_STATUS_OUTPUT_CAPACITY_V1);
        }
        // SAFETY: The caller supplied a non-overlapping writable buffer whose
        // checked capacity covers the complete response.
        unsafe { ptr::copy_nonoverlapping(response.as_ptr(), out_frame, response.len()) };
        Ok(WLCJ_STATUS_OK_V1)
    }));

    let status = match outcome {
        Ok(Ok(status)) | Ok(Err(status)) => status,
        Err(_) => WLCJ_STATUS_INTERNAL_ERROR_V1,
    };
    if status != WLCJ_STATUS_OK_V1 && status != WLCJ_STATUS_OUTPUT_CAPACITY_V1 {
        // SAFETY: This mandatory completion normalization is permitted by the
        // caller's writable, non-overlapping out-parameter contract.
        unsafe { ptr::write(out_frame_length, 0) };
    }
    status
}

#[cfg(test)]
std::thread_local! {
    static INJECT_TEST_PANIC: core::cell::Cell<bool> = const { core::cell::Cell::new(false) };
}

#[cfg(test)]
fn maybe_inject_test_panic() {
    INJECT_TEST_PANIC.with(|armed| {
        if armed.replace(false) {
            panic!("CoinJoin FFI injected panic");
        }
    });
}

#[cfg(not(test))]
const fn maybe_inject_test_panic() {}

#[cfg(test)]
mod tests;
