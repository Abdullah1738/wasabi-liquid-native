# Wasabi Liquid Native

Native Liquid transaction primitives intended for integration with Wasabi
Wallet.

## Current status

This repository currently contains reference contract material only. It does
not contain a linkable library, installed header, implementation, package,
wallet integration, transaction builder, PSET processor, signer, blinding
provider, or production capability.

The files under `contracts/v24/nonlinkable-reference/` define a frozen ABI
shape for implementation work. They are deliberately outside an `include/`
tree and must not be treated as declarations for available symbols. Their
`SHA256SUMS` file authenticates the exact reference bytes.

## Product boundary

The intended product is an ordinary noncustodial multiasset Liquid wallet,
followed by sponsor-free L-BTC-only CoinJoin after its separate gates close.
Fee sponsorship, USDt CoinJoin, and mixed-asset CoinJoin are outside the
current implementation scope.
