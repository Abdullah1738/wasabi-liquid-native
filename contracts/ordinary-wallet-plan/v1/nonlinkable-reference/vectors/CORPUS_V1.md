# Vector partitions

Shared encoder rows are the only cross-language byte-equality authority.
Managed-only rows model funding-owner and encoder caller surfaces. Native-only
rows model raw encode, structural decode, success-only reencode, and semantic
prepare. A row is never assigned to an operation that cannot construct it.

Public transaction fixtures contain witness-inclusive serialized Elements
transactions, commitments, and proofs only. Catalog fixtures contain
checksummed public descriptors only. No construction material or confidential
opening is included. The fixtures are synthetic and are not associated with
funds or an account.

Source-object JSON uses one closed schema: a typed root reconstructed from an
exact frame (or a checked sparse expression) followed by typed operations over
declared paths. The checker rejects unknown fields, paths, types, operations,
no-op edits, materialized giant values, and any model without exactly one case
or boundary consumer. Expected outcomes are table assertions, not instructions
to the evaluator.

Prepare results bind only the frozen public validation phase. The corpus does
not claim that selected confidential commitments match declared assets or
values; that question is deferred to the later opening-provider composition.
It also provides no node, currentness, reservation, signing, PSET, broadcast,
CoinJoin, sponsor, USDt CoinJoin, release, or production-readiness authority.
