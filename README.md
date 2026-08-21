# ocaml-bitcoin

Bitcoin primitives for OCaml: consensus serialization, keys and addresses,
Bitcoin Script, transactions, sighash, Taproot, BIP32/BIP39, and PSBT.

The core library performs no I/O and does not depend on `Unix`, so it builds
unmodified as a [MirageOS](https://mirageos.org)/Solo5 unikernel.

> **Status: under development.** 4.0 is a ground-up rewrite and is not yet
> released. See [CHANGES.md](CHANGES.md).

## Why

There is no up-to-date Bitcoin SDK in OCaml. What exists on opam is
fragmented and unmaintained: no Taproot, no PSBT, no descriptors, and no
`secp256k1` that survives cross-compilation to a unikernel. This library
aims to be the one obvious answer, and to be usable in the places OCaml is
actually chosen — including inside a unikernel with no operating system
underneath it.

## Design

* **No I/O, no `Unix`, no globals.** Everything is a pure function over
  values. Bringing your own transport is the point; a node client is a
  separate concern and a separate package.
* **Errors are values.** Every parser and every fallible operation returns
  `result`. Nothing raises across a public boundary.
* **Types enforce protocol rules.** BIP341 requires the value and
  `scriptPubKey` of *every* input to compute a Taproot sighash, so the API
  accepts only a `Sighash.Prevouts.t` — a value you cannot construct without
  supplying all of them, and which remembers the transaction it was built
  for. Rules like this are encoded where possible rather than documented.
* **Constant-time where it counts.** Secret-key signing goes through
  `mirage-crypto-ec`'s fiat-crypto/ECCKiila secp256k1. See
  [Security](#security) for what that does and does not cover.

## Supported

| Area | BIPs |
|---|---|
| Schnorr signatures | 340 |
| Taproot, Tapscript | 341, 342 |
| SegWit | 141, 143, 144 |
| Address encodings | 13, 16, 173 (bech32), 350 (bech32m) |
| HD wallets | 32, 39 (English), 43, 44, 49, 84, 86 |
| PSBT | 174 (v0), 371 (Taproot fields) |
| Signature encoding | 62, 66, 146 (strict DER, low-S) |
| Opt-in RBF | 125 |

### Not implemented in 4.0, by design

Script interpreter, output descriptors (BIP380-386), miniscript (BIP379),
coin selection, the P2P wire protocol, block/consensus validation, PSBT v2
(BIP370), and non-English BIP39 wordlists. PSBT v2 is *detected and
rejected* rather than mis-parsed.

These are omissions of scope, not oversights. Several are planned; none are
required to build, sign and broadcast a transaction.

## Security

This library has not been audited. Do not use it to manage funds you are
unwilling to lose.

Signing uses `mirage-crypto-ec`'s constant-time secp256k1. Public-key
arithmetic — which operates only on public data — uses a variable-time
implementation, which is safe by construction.

One residual leak is known and deliberate: BIP32 child key derivation and
Taproot key tweaking add a secret scalar modulo the curve order using
arbitrary-precision arithmetic, which is not constant time. This is a much
weaker leak than variable-time scalar multiplication, but it is real, and it
will be removed once constant-time scalar addition is available upstream.

## History and licensing

This repository began in 2012 as Dario Teixeira's `ocaml-bitcoin`, a Bitcoin
Core JSON-RPC client under the LGPL. Version 4.0 is an unrelated body of
work: the JSON-RPC client was removed in full — it is preserved at the git
tag `legacy/v3.0` — and no part of it is carried forward.

Everything from 4.0 onward is original work under the **ISC** licence. The
git history before that point contains LGPL-licensed code, which is why
LICENSE.md records the transition explicitly.
