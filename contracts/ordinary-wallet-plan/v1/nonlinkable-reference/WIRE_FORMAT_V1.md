# Ordinary wallet plan wire v1 corpus

Corpus ID: `ordinary-wallet-plan-wire-v1-conformance-1`

This directory is a language-neutral, public-only compatibility authority for
the source-only WLPQ v1 request. It is not a runtime transcript, wallet backup,
node statement, or release claim. The corpus admits Liquid mainnet and testnet
only; local-network contexts are not part of v1.

All integers are unsigned little-endian. The header is exactly:

| Offset | Width | Field |
| ---: | ---: | --- |
| 0 | 4 | ASCII magic `WLPQ` |
| 4 | 2 | version 1 |
| 6 | 2 | header length 152 |
| 8 | 8 | exact total frame length |
| 16 | 4 | flags, zero |
| 20 | 4 | reserved, zero |
| 24 | 32 | nonzero source epoch |
| 56 | 8 | source revision |
| 64 | 32 | reviewed manifest ID bytes in textual order |
| 96 | 32 | nonzero pegged asset bytes in consensus order |
| 128 | 4 | selected-input count |
| 132 | 4 | confidential-destination count |
| 136 | 4 | aggregate previous-transaction count |
| 140 | 4 | reserved, zero |
| 144 | 8 | positive pegged-asset fee value |

Each selected row has a fixed 88-byte prefix: expected transaction ID (32,
consensus order), expected output index (4), expected asset (32, consensus
order), expected value (8), candidate length (4), previous count (4), and zero
reserved (4). The candidate follows, then each previous transaction as a
4-byte length and exact payload. Each destination has a fixed 48-byte prefix:
asset (32, consensus order), value (8), ASCII address length (4), and zero
reserved (4), followed by exact address bytes.

Selected rows are ordered by reversed (RPC/display) transaction identifier and
then output index. Previous payloads are ordered by complete unsigned bytes.
Destinations retain caller order. Asset identifiers in frames are consensus
order; `CONTEXTS_V1.tsv` fixes their RPC/display reversal.

Limits are: outer rejection ceiling 268,435,456 bytes; reachable maximum
67,260,872; 1..100 selected inputs; 1..255 destinations; 1..256 address bytes;
1..4,194,304 bytes per candidate or previous transaction; 0..16,384 expanded
previous entries; 1..67,108,864 expanded transaction bytes; output index
0..1,073,741,823; and each selected, destination, or fee value
1..2,100,000,000,000,000.

Error precedence is exact: invalid caller/expected binding (1); outer ceiling
(4); fewer than eight bytes (3); magic/version/header-length mismatch (2);
remaining fixed-header canonical errors (3); source mismatch (5); numeric and
arithmetic domain errors (4); remaining structural canonical errors (3);
reviewed context mismatch (6); destination/output/declaration plan rejection
(7); then public funding rejection (8). Decode can return codes 1 through 5;
prepare can return 6 through 8. Reencode is success-only for decoded frames.
Native raw encode can return 1, 3, 4, 6, or 7.

`vectors/FRAMES_V1.tsv` binds every concrete frame to exact decoded fields.
`vectors/CASES_V1.tsv` partitions real typed operation surfaces. Giant limits
use the declared execution class and are not checked in as giant hexadecimal
files. `vectors/SOURCE_MODELS_V1.tsv` closes every source-only model and binds
it to one canonical JSON construction object under `vectors/source-models/`.
Those objects contain exact frame/fixture references, scalar values,
collections, identities, lifecycle states, and deterministic virtual-byte
recipes; they are reconstructed rather than interpreted as outcome labels.
Every case carries hashes for its exact input object, any successful byte
output, and a domain-separated binding of the operation and expected result.
`vectors/FRAME_PAYLOAD_BINDINGS_V1.tsv` closes every exact public transaction
payload embedded in a frame. `vectors/FIXTURE_ASSERTIONS_V1.tsv` records
properties independently parsed from those transaction bytes, including
witness-vector lengths and same-transaction/different-witness relations.
`vectors/CATALOG_OUTPUT_SCRIPTS_V1.tsv` pins the public descriptor scripts used
by both branches at the inclusive reviewed derivation boundary.
`vectors/PUBLIC_PROOF_CASES_V1.tsv` closes the six public cryptographic proof
verdicts replayed by the CI-only verifier directly against pinned
`rust-elements`, including successful amount-proof verification for the
explicit-output and descriptor-nonownership candidates before their later
wallet-policy failures. That proof verifier establishes proof validity, public asset
domain membership, and commitment balance only. It does not establish exact
confidential asset/value openings, ownership beyond the separate public script
catalog, chain inclusion, unspentness, node trust, confirmations, or signatures.
`vectors/MUTATIONS_V1.tsv` binds each derived frame to one parent.

The separate `CORPUS_ROOT_SHA256` file declares the SHA-256 of the parent
`SHA256SUMS` bytes. Later native and managed replay commits must pin both exact
roots independently; changing this packet restarts both replay review cycles.
`vectors/SHA256SUMS` covers every vector and public fixture except itself;
the parent `SHA256SUMS` covers each parent file and the nested inventory, but
does not list itself. Paths are sorted bytewise and use `/` separators.

The independent checker only reads this closed corpus. It manually scans and
packs WLPQ primitives and has no update, generation, or write mode. Production
codec replay is intentionally a later slice.
