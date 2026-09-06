# Wasabi Liquid Native

Native Liquid transaction primitives intended for integration with Wasabi
Wallet.

## Current status

This repository contains frozen reference contract material, a dependency-free
`no_std` Rust representation crate, and internal crates for bounded Liquid
addresses, confidential-output opening, transaction amount-proof validation,
ordinary multiasset PSET construction, and ordinary P2WPKH signing. The root
crate defines only fixed-width constants, nullable callback types, and
`repr(C)` structures. It builds only as an `rlib` and defines no C export,
native operation, wallet integration, or production capability.

The files under `contracts/v24/nonlinkable-reference/` define a frozen ABI
shape for implementation work. They are deliberately outside an `include/`
tree and must not be treated as declarations for available symbols. Their
`SHA256SUMS` file authenticates the exact reference bytes.

The representation crate is pinned by `rust-toolchain.toml`, is not
publishable, and has no dependencies. Its tests assert all frozen type sizes,
alignments, field offsets, constants, callback representations, and empty
initializers. Passing those tests proves representation equality on the tested
target only; it does not make the declared native functions available.

The internal `wasabi-liquid-native-address` crate parses and constructs
confidential addresses against an explicit Liquid mainnet, Liquid testnet, or
default Elements address-encoding profile. A profile match never substitutes
for separately authenticating the connected node's genesis and chain identity.
The crate uses owned library-neutral results, type-state for receive addresses
that must contain a blinding public key, bounded inputs, and privacy-redacted
errors.

The internal `wasabi-liquid-native-output-opening` crate opens one confidential
output with an explicitly borrowed receiver blinding key. It returns a
product-owned result that omits formatting and duplication traits, retains no
caller key or operation state, clears its stored opening fields on drop, and
exposes no C symbol or key-derivation path. Output opening alone does not prove
transaction validity, chain inclusion, unspentness, commitment balance, or the
transaction-level surjection proofs. Script ownership and blinding-key
provenance also remain separate prerequisites before wallet credit.
All Liquid implementation crates pin exact
`Abdullah1738/rust-elements` commit
`5b8865f8061459f82dcb8a1cf476b7ba17b14193`, with default features and the
ambient global secp context disabled;
that fork pins exact `Abdullah1738/rust-secp256k1-zkp` commit
`06ea6e06da81d2e3a51733c8d9b5f6c5fa248c2e`.

The internal `wasabi-liquid-native-wallet-facts` crate derives a bounded
external/internal native P2WPKH public-script catalog, accepts only atomically
bounded candidate batches, validates each transaction against its exact
previous-transaction set, reports every validated transaction and its input
outpoints in deterministic transaction-ID order, and opens only fully
confidential outputs matching that catalog. Input order remains exact consensus
transaction order; deterministic batch order is not chain order and input facts
do not assert wallet ownership. The caller supplies cryptographically secure
context randomness; the context seed, SLIP-77 derivation buffers, hash state and
finalization temporaries, and derived blinding keys follow scoped erasure paths.
Exact asset, amount, public-key, coordinate, outpoint, and witness-inclusive
transaction bindings are returned as observations only. A spend-only candidate
therefore remains observable even when it creates no owned output. The crate
does not claim chain inclusion, current unspentness, confirmations, balance
credit, persistence, or recovery. SHA-256 finalization is pinned to exact
`liquid-wasabi/traits` commit
`113c5ba12876e332335e49d1462a2c96c9928006` so the full truncated-output
temporary is erased when zeroization is enabled.

The internal `wasabi-liquid-native-wallet-facts-wire` crate defines canonical,
bounded binary request and response frames around those wallet-facts inputs and
public observations. Request decoding separates exact structural parsing from
consuming descriptor-catalog and candidate-batch preparation. Response encoding
accepts only the product-owned validated observation batch; response decoding
checks an opaque nonzero source-epoch binding before publishing immutable facts.
Both complete compressed public keys, the exact native-P2WPKH spend-key script
binding, identifier domains, counts, ordering, per-transaction outpoint
uniqueness, and all component and aggregate limits are validated. Owned raw
frames and decoded fields follow scoped overwrite paths. This crate is an
export-free Rust `rlib`: it adds no ABI operation, C symbol, dynamic library,
key provider, wallet-facts invocation, managed bridge, node authentication, or
wallet-credit authority. Its exact nonlinkable wire reference is under
`contracts/wallet-facts/v1/nonlinkable-reference/`.

The internal `wasabi-liquid-native-ordinary-wallet-plan` crate defines the
separate canonical `WLPQ` v1 source-only request for one already selected
ordinary-wallet spend. It binds an opaque caller-retained source epoch, one of
the closed Liquid mainnet or Liquid testnet manifest/pegged-asset contexts, and
the retained descriptor-catalog network before reusing the existing selected
output, confidential destination, explicit fee, and public funding validators.
The caller must generate a fresh unpredictable epoch for each wallet session
and never reuse it; reuse links otherwise separate requests. The request is
plaintext and unauthenticated and supplies neither replay protection nor
currentness. Parsing and validation have variable timing. Public preparation
checks the candidate identifier and selected index, canonical transaction,
complete previous-transaction set, amount proofs, descriptor ownership, and
confidential public shape, but deliberately cannot observe the selected
confidential output's committed asset or value before the later provider-bound
opening transition. Its owned raw storage follows scoped overwrite paths, and
its prepared result exposes only the source revision and counts. The crate is
an export-free Rust `rlib`; it adds no ABI operation, managed runtime bridge,
opening provider, node access, reservation, PSET construction, signing, or
broadcast behavior.

The WLPQ gate derives its production source closure from compiler dependency
information and pins the exact reviewed source bytes plus narrow
authority-critical dependency regions. These pins detect drift only: changing
an expected hash requires fresh review of the exact new bytes and does not
independently authorize the change.

`ci/check-dependency-capabilities.sh` exact-diffs the locked, all-target
normal/build graph for the whole default workspace against its reviewed
snapshot. It also applies semantic checks for the exact narrow library
revisions and feature sets, and separately snapshots each active dependency
edge with its alias, normal/build kind, target condition, source, and
repo-relative workspace path. It rejects ambient randomness, legacy Elements
Miniscript, JSON contract support, and unrelated compiler or serialization
capabilities.

These internal crates do not establish persistence, recovery, wallet
integration, release, or production readiness.

The internal `wasabi-liquid-native-transaction-validation` crate owns an exact
outpoint-keyed previous-output set, resolves it in transaction input order,
validates the pinned library's confidential range proofs, surjection proofs,
and commitment balance, and only then permits opening a selected output through
its validated wrapper. Coinbase, issuance, and peg-in inputs are explicitly
unsupported in this slice, and empty or duplicate-input shapes are rejected.
Validation does not authenticate node or chain identity, previous-output
provenance, current unspentness, scripts, signatures, confirmations, or wallet
ownership, so it is not by itself authority to credit a wallet balance.

The internal `wasabi-liquid-native-ordinary-pset` crate constructs a bounded
PSETv2 for an ordinary wallet spend. It accepts explicit inputs or confidential
inputs whose openings reproduce their exact commitments, conserves every asset
independently, requires confidential receive addresses for all non-fee outputs,
and appends one explicit positive fee output in the caller-declared fee asset.
It accepts only native P2WPKH inputs, explicitly requests
`SIGHASH_ALL|SIGHASH_RANGEPROOF`, and rejects nonzero locktimes disabled by
all-final sequences. Confidential input openings remain outside serialized PSET
input maps, and the product-owned buffers are cleared when their capability is
dropped. The pinned blinding library creates transient typed copies with
ordinary Rust drop behavior; this slice does not claim those temporary copies
are overwritten. A consuming transition blinds every non-fee output over the
exact final input domain, validates the transaction proofs, PSET binding proofs,
and commitment balance, and retains no input openings or generated output
blinding keys in the result. Connected-chain identity, fee-asset identity,
previous-output provenance, unspentness, incoming transaction proof validation,
and ownership remain separate prerequisites.

The same crate provides a consuming ordinary P2WPKH signing transition. A
caller-owned signer supplies only compressed public keys and ECDSA signatures;
the crate never requests or stores private keys. Before requesting any
signature, every public key is matched to the exact previous-output script.
Digests use the previous output's exact explicit value or confidential value
commitment and explicitly enable `SIGHASH_ALL|SIGHASH_RANGEPROOF`. Returned
signatures must be low-S and verify before the crate constructs the exact
two-item native witness. The result retains an immutable signed PSET for local
review or persistence, then consumes it into a broadcast-form transaction that
omits the PSET maps' explicit recipient asset and amount metadata. Finalization
rechecks exact transaction-field preservation, every signature, output proofs,
and commitment balance. A failure returns the unchanged blinded capability for
an explicit retry-or-discard decision. No arbitrary PSET import, signature
injection, node policy check, transaction submission, or broadcast acceptance
claim exists.

## CoinJoin CI artifacts

Successful pushes to `main` publish CoinJoin ABI v1 (operations 1-12) artifacts
from the `Dependency capabilities` workflow, after both existing workspace
gates pass. The output-only job builds fresh release libraries using Rust
1.96.0 and the unchanged `ci/build-coinjoin-ffi-library.sh` export allowlists.
It checks the sole `wlcj_execute_v1` export and runs the existing release FFI
tests and dynamic C1/C2 fixtures before uploading. It does not commit files,
change managed pins, publish a package, or contact a node or wallet.

Supported CI targets are `x86_64-unknown-linux-gnu` on Ubuntu 24.04 (`.so`)
and `aarch64-apple-darwin` on macOS 14 with Xcode 15.4 (`.dylib`). These are
host-native builds, not universal binaries or a claim of support for other
architectures, older Linux glibc versions, or Windows.

Each GitHub Actions artifact is named
`coinjoin-ffi-v1-<target>-<full-commit-sha>-<run-attempt>` and contains only the
dynamic library, C header, `manifest.json`, and `SHA256SUMS`. The manifest
records the exact source commit, repository, run URL/attempt, target, release
profile, Rust compiler identity, lockfile/build-script hashes, ABI operations,
and SHA-256 of the library/header. `SHA256SUMS` also covers the manifest.
Fixture requests, signing test material, static archives, and intermediate
objects are not uploaded.

Download from the successful exact-commit workflow run (for example with
`gh run download <run-id> --repo <owner>/wasabi-liquid-native --name <artifact-name>`).
In the extracted directory, verify `sha256sum -c SHA256SUMS` on Linux or
`shasum -a 256 -c SHA256SUMS` on macOS, and compare the manifest commit and
target with the reviewed run. Checksums alone do not authenticate provenance.
Artifacts have a requested 90-day retention, subject to repository policy;
they are not permanent release assets. Preserve an approved artifact through
a separately reviewed release/pinning step before retention expires.

The managed loader must remain unavailable until a separately reviewed
managed change admits the downloaded target-specific library hash and its
source/run provenance. A local host build is not a production pin. Artifact
publication alone gives no managed-runtime, live testnet round, broadcast,
custody, or production-readiness credit.

## Product boundary

The intended product is an ordinary noncustodial multiasset Liquid wallet,
followed by sponsor-free L-BTC-only CoinJoin after its separate gates close.
Fee sponsorship, USDt CoinJoin, and mixed-asset CoinJoin are outside the
current implementation scope.
