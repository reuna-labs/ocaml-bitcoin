## v4.0.0~alpha1 (unreleased)

**This release is a complete rewrite. Nothing from 3.0 is retained.**

Versions 1.0-3.0 were a Bitcoin Core JSON-RPC client. Version 4.0 is a
Bitcoin protocol library: it implements the formats and algorithms
directly and talks to no node. Users who need the old JSON-RPC client
should pin `bitcoin < 4.0`.

The project is also relicensed from LGPL-2.1 to ISC; see LICENSE.md.

### Added

* Consensus serialization: little-endian integers, CompactSize varints,
  length-prefixed vectors, and the SegWit marker/flag transaction format.
* Keys: secp256k1 secret/public keys, WIF, compressed and uncompressed
  encodings, x-only keys, ECDSA (strict BIP66 DER, low-S normalized per
  BIP62/BIP146) and BIP340 Schnorr signatures.
* Addresses: P2PKH, P2SH, P2WPKH, P2WSH and P2TR across mainnet, testnet
  and regtest, via Base58Check and Bech32/Bech32m (BIP173, BIP350).
* Bitcoin Script: opcodes, parsing, serialization and the standard
  output templates.
* Transactions and block headers.
* Sighash: legacy (including the SIGHASH_SINGLE bug and FindAndDelete),
  BIP143 SegWit v0, and BIP341 Taproot.
* Taproot: TapLeaf/TapBranch/TapTweak hashing, taptree construction,
  control blocks, output key derivation, key-path and script-path spends.
* BIP32 hierarchical deterministic keys and BIP39 mnemonics (English).
* PSBT: BIP174 version 0 with BIP371 Taproot fields, and the creator,
  updater, signer, combiner, finalizer and extractor roles.
* Worked examples under `examples/`, built and run by CI so they cannot
  drift out of date.
* `unikernel/`, a MirageOS/Solo5 smoke test. The library cross-compiles to a
  Solo5 binary that runs and produces results identical to the hosted build,
  so the no-I/O property is checked rather than assumed.

### Removed

* The Bitcoin Core JSON-RPC client and its five HTTP backends, along
  with the `bitcoin-cohttp-lwt`, `bitcoin-cohttp-async` and
  `bitcoin-ocurl` packages.
