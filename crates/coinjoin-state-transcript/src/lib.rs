#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Domain-separated, versioned state transcripts for Liquid CoinJoin.
//!
//! This crate hashes opaque caller-provided bytes. It does not parse or validate
//! PSETs, infer serialization, or determine whether a state encoding is
//! canonical or semantically valid.

use core::fmt;
use sha2::{Digest, Sha256};

/// Maximum accepted protocol-domain length in bytes.
pub const MAX_PROTOCOL_DOMAIN_LENGTH: usize = 128;

/// Maximum accepted context length in bytes (64 KiB).
pub const MAX_CONTEXT_LENGTH: usize = 64 * 1024;

/// Maximum accepted canonical-state length in bytes (16 MiB).
pub const MAX_CANONICAL_STATE_LENGTH: usize = 16 * 1024 * 1024;

const TRANSCRIPT_TAG: &[u8] = b"WL-COINJOIN-STATE-TRANSCRIPT-V1";

/// A non-secret SHA-256 digest committing to one CoinJoin state transcript.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CoinJoinStateDigest([u8; 32]);

impl CoinJoinStateDigest {
    /// Borrows the digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Returns the digest bytes by value.
    #[must_use]
    pub const fn into_bytes(self) -> [u8; 32] {
        self.0
    }
}

/// Validation errors returned before any transcript field is hashed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CoinJoinStateTranscriptError {
    /// The protocol domain is empty.
    EmptyDomain,
    /// The protocol domain exceeds [`MAX_PROTOCOL_DOMAIN_LENGTH`].
    DomainTooLarge,
    /// The context is empty.
    EmptyContext,
    /// The context exceeds [`MAX_CONTEXT_LENGTH`].
    ContextTooLarge,
    /// The canonical state is empty.
    EmptyState,
    /// The canonical state exceeds [`MAX_CANONICAL_STATE_LENGTH`].
    StateTooLarge,
}

impl fmt::Display for CoinJoinStateTranscriptError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyDomain => formatter.write_str("protocol domain must not be empty"),
            Self::DomainTooLarge => formatter.write_str("protocol domain exceeds 128-byte limit"),
            Self::EmptyContext => formatter.write_str("context must not be empty"),
            Self::ContextTooLarge => formatter.write_str("context exceeds 65536-byte limit"),
            Self::EmptyState => formatter.write_str("canonical state must not be empty"),
            Self::StateTooLarge => {
                formatter.write_str("canonical state exceeds 16777216-byte limit")
            }
        }
    }
}

impl std::error::Error for CoinJoinStateTranscriptError {}

/// Hashes an opaque canonical state under a protocol domain and caller context.
///
/// `protocol_domain` identifies the protocol or profile whose state is being
/// committed, such as a PSET-state or partial-balance profile. `context` is
/// opaque caller data and must bind the round identifier and domain, phase,
/// participant role, contribution ordinal, and any predecessor state digest.
/// `canonical_state` is also opaque: the caller is solely responsible for its
/// canonical encoding and semantic validity.
///
/// The transcript is BIP-340-style tagged SHA-256 under the fixed outer tag
/// `WL-COINJOIN-STATE-TRANSCRIPT-V1`. The protocol domain, context, and state
/// are absorbed in that order, each preceded by an unsigned 64-bit big-endian
/// byte-length prefix.
///
/// # Errors
///
/// Returns [`CoinJoinStateTranscriptError`] if any field is empty or exceeds
/// its public size limit. Every field is validated before hashing begins.
pub fn hash_coinjoin_state(
    protocol_domain: &[u8],
    context: &[u8],
    canonical_state: &[u8],
) -> Result<CoinJoinStateDigest, CoinJoinStateTranscriptError> {
    if protocol_domain.is_empty() {
        return Err(CoinJoinStateTranscriptError::EmptyDomain);
    }
    if protocol_domain.len() > MAX_PROTOCOL_DOMAIN_LENGTH {
        return Err(CoinJoinStateTranscriptError::DomainTooLarge);
    }
    if context.is_empty() {
        return Err(CoinJoinStateTranscriptError::EmptyContext);
    }
    if context.len() > MAX_CONTEXT_LENGTH {
        return Err(CoinJoinStateTranscriptError::ContextTooLarge);
    }
    if canonical_state.is_empty() {
        return Err(CoinJoinStateTranscriptError::EmptyState);
    }
    if canonical_state.len() > MAX_CANONICAL_STATE_LENGTH {
        return Err(CoinJoinStateTranscriptError::StateTooLarge);
    }

    let tag_hash: [u8; 32] = Sha256::digest(TRANSCRIPT_TAG).into();
    let mut hasher = Sha256::new();
    hasher.update(tag_hash);
    hasher.update(tag_hash);
    absorb(&mut hasher, protocol_domain);
    absorb(&mut hasher, context);
    absorb(&mut hasher, canonical_state);

    Ok(CoinJoinStateDigest(hasher.finalize().into()))
}

fn absorb(hasher: &mut Sha256, bytes: &[u8]) {
    let length = u64::try_from(bytes.len()).expect("validated transcript field length fits in u64");
    hasher.update(length.to_be_bytes());
    hasher.update(bytes);
}

#[cfg(test)]
mod tests;
