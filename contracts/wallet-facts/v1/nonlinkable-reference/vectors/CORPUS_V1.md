# Wallet facts wire v1 conformance corpus 1

Corpus ID: wallet-facts-wire-v1-conformance-1
Wire version: 1

This packet contains synthetic-public, language-neutral compatibility evidence
for the export-free wallet-facts wire codec. Passing it proves only the named
operation's byte compatibility and stable numeric result. It authenticates no
implementation, artifact, caller, node, chain, transaction source, response,
wallet fact, ownership claim, state transition, or persistence action. It grants
no signing, broadcast, CoinJoin, release, production, or closure authority.

The five manifests are FRAMES_V1.tsv, CASES_V1.tsv, API_CASES_V1.tsv,
RECIPES_V1.tsv, and BOUNDARIES_V1.tsv. Frame files are canonical lowercase hexadecimal text: one
even-length line matching [0-9a-f]* followed by exactly one LF. The decoded
bytes, not the hexadecimal text, are supplied to wire operations. Nested
SHA256SUMS binds every regular file below this directory except itself. The
parent nonlinkable-reference/SHA256SUMS binds this nested inventory. The exact
corpus identity is the pair of the corpus ID above and the SHA-256 of that
parent checksum file. Any accepted content or semantic change requires a new
corpus number. The parent directory contains exactly its checksum, the error
mapping, the wire format, and a real non-symlink `vectors` directory; the
closure rejects any other parent entry or symlink anywhere in the vector tree.
The paths in `FRAMES_V1.tsv` equal exactly the regular files directly under
`vectors/frames`; descendants, aliases, and unlisted frame files are invalid.

## Symbolic production constants

| Token | Rust constant | Contract limit row |
| --- | --- | --- |
| max-public-descriptor-bytes | MAX_PUBLIC_DESCRIPTOR_BYTES | Public descriptor bytes |
| max-derivation-index | MAX_DERIVATION_INDEX | Last derivation index |
| max-candidate-transactions | MAX_CANDIDATE_TRANSACTIONS | Candidate transactions |
| max-previous-transactions-per-batch | MAX_PREVIOUS_TRANSACTIONS_PER_BATCH | Previous transactions in one batch |
| max-transaction-bytes | MAX_TRANSACTION_BYTES | One serialized transaction |
| max-batch-bytes | MAX_BATCH_BYTES | Aggregate candidate and previous-transaction bytes |
| max-request-frame-bytes | MAX_REQUEST_FRAME_BYTES | Outer request rejection ceiling |
| max-reachable-request-bytes | MAX_REACHABLE_REQUEST_BYTES | Maximum structurally reachable request |
| max-response-frame-bytes | MAX_RESPONSE_FRAME_BYTES | Outer response rejection ceiling |
| max-reachable-response-bytes | MAX_REACHABLE_RESPONSE_BYTES | Maximum structurally reachable response |
| max-aggregate-inputs | MAX_AGGREGATE_INPUTS | Aggregate observed inputs |
| max-aggregate-owned-outputs | MAX_AGGREGATE_OWNED_OUTPUTS | Aggregate owned outputs |
| max-inputs-per-transaction | MAX_INPUTS_PER_TRANSACTION | Inputs in one observed transaction |
| max-owned-outputs-per-transaction | MAX_OWNED_OUTPUTS_PER_TRANSACTION | Owned outputs in one observed transaction |
| max-owned-output-value | MAX_OWNED_OUTPUT_VALUE | Maximum owned-output value |
| max-spendable-output-index | MAX_SPENDABLE_OUTPUT_INDEX | Maximum spendable output index |

none is reserved for pure checked-arithmetic overflow rows. usize64 rows are
valid only on 64-bit Rust targets. Giant component and overflow rows are
symbolic and are never described as decoder executions or allocated frames.
Request candidate payloads are opaque bounded synthetic bytes and are not
claimed to be valid Liquid transactions. Source-epoch bindings prevent only
accidental cross-call mixing; they authenticate no provenance.

## Recipe grammar

`RECIPES_V1.tsv` is the language-neutral source authority for every API case.
Each recipe is consumed independently by the source-only checker and Rust
replay. A request recipe sets every response field to `-`; a response recipe
sets every descriptor and candidate field to `-`. Source epochs, descriptors,
transaction identifiers, witness bindings, previous transaction identifiers,
public keys, asset identifiers, scripts, and candidate payloads are canonical
lowercase hexadecimal bytes.

The `candidates` field is `-` or semicolon-separated
`transaction:previous-list` records. A transaction is nonempty hex or `_` for
the deliberately empty candidate; empty transaction text before `:` is invalid
and is not an alias for `_`. A previous list is `-` or comma-separated nonempty
hex strings. The `transactions` field is `-` or semicolon-separated
`transaction-id/witness-binding/input-list` records. An input list is `-` or
comma-separated `previous-transaction-id:output-index` records. The `outputs`
field is `-` or semicolon-separated records with exactly these slash-separated
fields: transaction ID, output index, witness binding, spend public key,
blinding public key, branch (`external` or `internal`), derivation index, asset
ID, value, and scriptPubKey. Numeric fields are canonical unsigned decimal.
The request last-derivation index, every input previous-output index, every
owned-output index, and every owned-output derivation index have the exact
domain `0..4294967295` (`u32`). Owned-output values have the exact domain
`0..18446744073709551615` (`u64`); narrower production validity limits are
separate semantic checks. Output records are already grouped by transaction in
the exact transaction-list order and are never reordered during encoding.

`expected_property` is a closed assertion token. Accepted recipes freeze their
exact transaction, input, output, asset, value, branch, and source shapes.
Rejected response recipes contain exactly one invalid public source invariant;
the zero-source response additionally freezes that its one invalid source
invariant loses to the zero-epoch API argument. The descriptor-rejection request
deliberately combines a semantic descriptor failure with an empty candidate to
freeze descriptor precedence. The zero-source request combines those same
invalid source fields with a zero epoch to freeze argument precedence.

Source mismatch is checked from replayable bounded frames before count,
uniqueness, key, script, and value validation. Its precedence before the
reachable-response-length predicate is frozen separately by a bounded source
order assertion over the production decoder; no giant frame is tracked or
claimed as a decoder replay. A zero expected response source is rejected before
outer-length or frame-byte inspection, including for truncated and complete
wrong-magic frames.

Body-truncation, trailing-byte, and concatenation replays use distinct mutation
descendants whose declared-length field equals the descendant's actual byte
length. Their immediate parents remain outer-length mismatch evidence, so the
body or trailing condition cannot be masked by the outer length predicate.
