# ocaml-bitcoin

Bitcoin primitives for OCaml: consensus serialization, keys and addresses,
Bitcoin Script, transactions, sighash, Taproot, BIP32/BIP39, and PSBT.

The core library performs no I/O and does not depend on `Unix`, so it builds
unmodified as a [MirageOS](https://mirageos.org)/Solo5 unikernel — verified,
not asserted: `unikernel/` cross-compiles it to a Solo5 binary that runs and
produces byte-identical results to the hosted build.

> **Status: under development.** 4.0 is a ground-up rewrite and is not yet
> released. The two cryptographic dependencies are not on opam either; see
> [CONTRIBUTING.md](CONTRIBUTING.md) for the pins. See [CHANGES.md](CHANGES.md).

## A transaction, end to end

```ocaml
open Bitcoin

(* A wallet, from a BIP39 phrase down to a BIP86 Taproot key. *)
let seed   = Result.get_ok (Bip39.to_seed (Bip39.normalize phrase))
let master = Result.get_ok (Bip32.Secret.master seed)
let path   = Result.get_ok (Derivation_path.of_string "m/86'/0'/0'/0/0")
let node   = Result.get_ok (Bip32.Secret.derive_path master path)
let si     = Result.get_ok (Taproot.spend_info
                              ~internal_key:(Key.Secret.public node.key) ())

(* bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr *)
let address = Address.to_string ~network:Mainnet (Taproot.address si)

(* Spend it: create, fund, sign, finalize, extract. *)
let psbt = Result.get_ok (Psbt.Creator.create unsigned_tx)
let psbt = Result.get_ok (Psbt.Updater.set_witness_utxo psbt ~input:0 prevout)
let psbt = Result.get_ok (Psbt.Signer.sign_taproot_key_path psbt ~input:0 node.key ())
let tx   = Result.get_ok (Psbt.Extractor.extract
                            (Result.get_ok (Psbt.Finalizer.finalize psbt)))
```

Signing before the PSBT carries every input's amount and scriptPubKey is not
an error you can make: BIP341 commits to all of them, so `Psbt.Signer` cannot
build a digest until the transaction is complete, and says which input is
missing. See [`examples/`](examples/) for the three worked cases, which CI
builds and runs.

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

## Unikernels

`unikernel/` builds a Solo5 unikernel that links the library and exercises
the hashing, curve, address and HD-wallet paths. Running it under
`solo5-spt` gives:

```
Solo5: Bindings version v0.12.1
[INFO] taproot address: bc1pm7y6q4mr04w6glx7l9eurqahm30mde797dk8fs5j94qfft2m2hhs7r45tv
[INFO] ecdsa verified: true  schnorr verified: true
[INFO] bip32 master xprv: xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRRuL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu
Solo5: solo5_exit(0) called
```

Identical to what the hosted build prints, on a different compiler and with
no operating system underneath. Toolchain versions and the two workarounds
the build needs are in [`unikernel/README.md`](unikernel/README.md).

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

Verified against the specifications' own vectors, not just round-trip tests:
all 19 BIP340 vectors, all 7 BIP341 scriptPubKey and key-path cases, all 4
BIP32 vectors plus its 14 invalid-key cases, all 24 BIP39 vectors, all 30
BIP174/BIP371 PSBTs (and all 31 invalid ones rejected), and from Bitcoin Core
`sighash.json` in full, `tx_valid.json`, `key_io_valid.json` and
`key_io_invalid.json`.

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
