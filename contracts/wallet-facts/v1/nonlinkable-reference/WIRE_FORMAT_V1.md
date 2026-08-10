# Wallet facts wire format v1

Status: nonlinkable reference for the export-free Rust codec

This document defines the canonical byte representation implemented by the
internal `wasabi-liquid-native-wallet-facts-wire` `rlib`. It does not declare a
C ABI, native export, dynamic library, key-provider boundary, wallet-facts
invocation, chain authority, or managed integration.

All integers are fixed-width unsigned little-endian values. Identifiers use raw
consensus byte order. Every reserved field and flag is zero. Counts, lengths,
offsets, and aggregates are checked before allocation, slicing, or conversion.
A frame is accepted only when its declared length is its exact byte length and
the decoder consumes all bytes.

## Limits

| Property | Limit |
| --- | ---: |
| Outer request rejection ceiling | 268,435,456 |
| Outer response rejection ceiling | 268,435,456 |
| Maximum structurally reachable request | 67,240,012 |
| Maximum structurally reachable response | 80,599,492 |
| Public descriptor bytes | 16,384 |
| Last derivation index | 100,000 |
| Candidate transactions | 4,096 |
| Previous transactions in one batch | 16,384 |
| One serialized transaction | 4,194,304 |
| Aggregate candidate and previous-transaction bytes | 67,108,864 |
| Aggregate observed inputs | 1,636,801 |
| Aggregate owned outputs | 148,470 |
| Inputs in one observed transaction | 102,298 |
| Owned outputs in one observed transaction | 9,279 |
| Maximum owned-output value | 9,223,372,036,854,775,807 |
| Maximum spendable output index | 1,073,741,823 |
| Native P2WPKH scriptPubKey bytes | 22 |

The 256 MiB values are rejection ceilings, not reachable valid-frame sizes.
The reachable maxima are derived from the component limits and fixed layouts.
A limit change requires a new wire version.

## Request

The request magic is `WLFQ`, the version is `1`, and the header is 76 bytes.

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 4 | magic `WLFQ` |
| 4 | 2 | version `1` |
| 6 | 2 | header length `76` |
| 8 | 8 | total frame length |
| 16 | 4 | flags, zero |
| 20 | 1 | descriptor network: `0` mainnet, `1` test |
| 21 | 3 | reserved, zero |
| 24 | 4 | inclusive last derivation index |
| 28 | 32 | nonzero source-epoch binding |
| 60 | 4 | public descriptor byte length |
| 64 | 4 | candidate count |
| 68 | 4 | aggregate previous-transaction count |
| 72 | 4 | reserved, zero |

The header is followed by the exact ASCII public descriptor. It contains no
NUL or ASCII whitespace and includes exactly one `#` followed by exactly eight
lowercase characters from the descriptor-checksum alphabet
`qpzry9x8gf2tvdw0s3jn54khce6mua7l`. The existing descriptor catalog remains
the authority for checksum, grammar, network, branch, wildcard, and derivation
acceptance.

Candidates retain caller order. Each candidate contains:

| Size | Field |
| ---: | --- |
| 4 | candidate transaction byte length |
| 4 | previous-transaction count |
| 4 | reserved, zero |
| variable | exact witness-inclusive candidate transaction bytes |
| repeated | `u32` previous-transaction length and exact bytes |

Transaction strings are nonempty and independently and aggregately bounded.
The aggregate previous-transaction count equals the header value.

Structural decoding does not derive the descriptor or decode transactions. A
consuming preparation step constructs the existing validated descriptor
catalog and atomically bounded candidate batch. Successful public encoding
performs those same product validations before allocating the output frame.
Owned descriptor, transaction, and frame buffers are overwritten on drop.

## Response

The response magic is `WLFV`, the version is `1`, and the header is 64 bytes.

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 4 | magic `WLFV` |
| 4 | 2 | version `1` |
| 6 | 2 | header length `64` |
| 8 | 8 | total frame length |
| 16 | 4 | flags, zero |
| 20 | 4 | transaction count |
| 24 | 4 | aggregate owned-output count |
| 28 | 4 | reserved, zero |
| 32 | 32 | exact echoed source-epoch binding |

Transactions are strictly ascending by unsigned consensus-order transaction
ID. Each transaction contains:

| Size | Field |
| ---: | --- |
| 32 | nonzero transaction ID |
| 32 | SHA-256 of exact witness-inclusive transaction bytes |
| 4 | input count |
| 4 | owned-output count |
| repeated | input records in exact consensus order |
| repeated | owned-output records in strictly ascending output-index order |

An input is a nonzero 32-byte previous-transaction ID followed by one `u32`
output index no greater than `0x3fffffff`. Its 36-byte outpoint key is unique
within the parent transaction. The same outpoint may occur in separate
transaction observations. Duplicate detection uses one exact-capacity vector,
in-place unstable byte ordering, and an adjacent scan; its scratch bytes are
overwritten on success, error, and unwind.

An owned-output record is 144 bytes:

| Size | Field |
| ---: | --- |
| 4 | output index, at most `0x3fffffff` |
| 4 | scriptPubKey length, exactly `22` |
| 33 | compressed spend public key |
| 33 | compressed blinding public key |
| 1 | branch: `0` external, `1` internal |
| 3 | reserved, zero |
| 4 | normal derivation index |
| 32 | nonzero asset ID |
| 8 | value in `1..=0x7fffffffffffffff` |
| 22 | exact native-P2WPKH scriptPubKey |

Both public keys are complete valid compressed secp256k1 points. The script is
the exact HASH160 native-P2WPKH script for the spend public key. The response
encoder accepts only the product-owned validated observation batch and confirms
parent transaction, witness binding, grouping, ordering, and full native-output
consumption. The decoder checks a nonzero expected source binding for equality
before publishing immutable facts.

## Security and authority boundary

The source-epoch binding only prevents accidental cross-call mixing. It does
not authenticate a node, chain, generation, transaction source, caller, or
artifact. Decoded facts grant no chain order, current-UTXO, confirmation,
wallet-input ownership, balance-credit, state-transition, or persistence
authority. The codec contains no blinding key, provider, randomness call,
network, filesystem, clock, signing, broadcast, CoinJoin, fee-sponsor, or USDt
CoinJoin capability.

Errors are the stable privacy-redacted values in `ERROR_MAPPING_V1.tsv`. Error
text never includes caller or frame data.

## Language-neutral conformance corpus

The `vectors/` directory contains canonical lowercase hexadecimal frames,
operation-specific expected results, symbolic boundary arithmetic, and a
closed checksum inventory for corpus
`wallet-facts-wire-v1-conformance-1`. Its exact identity is that corpus ID
paired with the SHA-256 of this directory's `SHA256SUMS` file.

Corpus replay proves only byte compatibility and the named wire operation's
stable numeric result. It does not authenticate an implementation, artifact,
caller, node, chain, transaction source, response provenance, wallet fact, or
state transition, and it grants no ownership, persistence, signing, broadcast,
CoinJoin, release, production, or closure authority.
