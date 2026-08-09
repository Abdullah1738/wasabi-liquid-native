# Wasabi Liquid Native

Native Liquid transaction primitives intended for integration with Wasabi
Wallet.

## Current status

This repository contains frozen reference contract material, a dependency-free
`no_std` Rust representation crate, a bounded Liquid address crate, and an
internal confidential-output opening crate, plus an internal transaction
amount-proof validator. The root crate defines only fixed-width constants,
nullable callback types, and `repr(C)` structures. It builds only as an `rlib`
and defines no C export, native operation, wallet integration, PSET processor,
signer, blinding provider, or production capability.

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
All three internal crates pin exact `liquid-wasabi/rust-elements` commit
`aeed87e94d3f5dd429a55c16492dca24b5fac16f`, with default features disabled;
that fork pins exact `liquid-wasabi/rust-secp256k1-zkp` commit
`06ea6e06da81d2e3a51733c8d9b5f6c5fa248c2e`.

These internal crates do not establish output blinding, transaction
construction, signing, persistence, recovery, wallet integration, release, or
production readiness.

The internal `wasabi-liquid-native-transaction-validation` crate binds ordered
previous outputs to the transaction's exact input outpoints, validates the
pinned library's confidential range proofs, surjection proofs, and commitment
balance, and only then permits opening a selected output through its validated
wrapper. Coinbase, issuance, and peg-in inputs are explicitly unsupported in
this slice, and empty or duplicate-input shapes are rejected. Validation does
not authenticate node or chain identity, previous-output provenance, current
unspentness, scripts, signatures, confirmations, or wallet ownership, so it is
not by itself authority to credit a wallet balance.

## Product boundary

The intended product is an ordinary noncustodial multiasset Liquid wallet,
followed by sponsor-free L-BTC-only CoinJoin after its separate gates close.
Fee sponsorship, USDt CoinJoin, and mixed-asset CoinJoin are outside the
current implementation scope.
