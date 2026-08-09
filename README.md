# Wasabi Liquid Native

Native Liquid transaction primitives intended for integration with Wasabi
Wallet.

## Current status

This repository contains frozen reference contract material, a dependency-free
`no_std` Rust representation crate, and a bounded Liquid address crate. The
root crate defines only fixed-width constants, nullable callback types, and
`repr(C)` structures. It builds only as an `rlib` and defines no C export,
native operation, transaction behavior, wallet integration, PSET processor,
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
The crate uses owned library-neutral results,
type-state for receive addresses that must contain a blinding public key,
bounded inputs, and privacy-redacted errors. Its sole direct dependency is the exact
`Abdullah1738/rust-elements` commit
`9709e5c39db913344c085588f36b190ff7b08957`, with default features disabled;
that fork in turn pins `Abdullah1738/rust-secp256k1-zkp` commit
`042351625d3d42a495b1da785925f389c0b2d9d9`. Address tests do not establish
confidential output blinding, transaction construction, signing, wallet
integration, release, or production readiness.

## Product boundary

The intended product is an ordinary noncustodial multiasset Liquid wallet,
followed by sponsor-free L-BTC-only CoinJoin after its separate gates close.
Fee sponsorship, USDt CoinJoin, and mixed-asset CoinJoin are outside the
current implementation scope.
