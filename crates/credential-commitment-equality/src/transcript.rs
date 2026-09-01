//! Domain-separated, versioned Fiat-Shamir transcript.
//!
//! The challenge is a SHA-256 tagged hash (BIP-340 style: the tag string is
//! hashed once, the 32-byte tag digest is written twice, then the payload) so
//! transcripts for different protocol labels can never collide. The transcript
//! binds the protocol label, both nonce commitments `R1`/`R2`, both statement
//! commitments `Ma`/`C`, the asset generator `A`, and the caller-supplied
//! context. Callers MUST pass the CoinJoin round transcript (round id, phase,
//! output index, and any prior round messages) as `context` so proofs cannot
//! be replayed across rounds or outputs.

use sha2::{Digest, Sha256};

/// Protocol label binding this proof to the Liquid CoinJoin equality statement.
pub(crate) const PROTOCOL_LABEL: &[u8] = b"WL-COINJOIN-EQ-V1";

/// One SHA-256 midstate-ready tagged hash over the transcript fields.
pub(crate) struct Transcript {
    hasher: Sha256,
}

impl Transcript {
    /// Starts a transcript under the protocol label.
    pub(crate) fn new() -> Self {
        let tag = Sha256::digest(PROTOCOL_LABEL);
        let mut hasher = Sha256::new();
        hasher.update(tag);
        hasher.update(tag);
        Self { hasher }
    }

    /// Absorbs one length-prefixed field so field boundaries are unambiguous.
    pub(crate) fn absorb(&mut self, bytes: &[u8]) {
        let length = u64::try_from(bytes.len()).expect("transcript field length fits in u64");
        self.hasher.update(length.to_be_bytes());
        self.hasher.update(bytes);
    }

    /// Finalizes the transcript into the 32-byte challenge digest.
    pub(crate) fn finalize(self) -> [u8; 32] {
        self.hasher.finalize().into()
    }
}
