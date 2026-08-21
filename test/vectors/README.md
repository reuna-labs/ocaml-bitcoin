# Test vectors

Every file here is copied verbatim from an upstream project. Recorded below
with its origin, the upstream commit it was taken from, and its licence, so
that the provenance of anything this library claims to pass is checkable.

Retrieved 2026-08-21.

## bitcoin/bips — 7fe0b034ec967b52a5a28276419117326df93263

Licence: BIP-specific. BIP340 and BIP341 are both released under the
2-clause BSD licence; see the `Copyright` header of each BIP.

| File | Upstream path |
|---|---|
| `bip340-test-vectors.csv` | `bip-0340/test-vectors.csv` |
| `bip341-wallet-test-vectors.json` | `bip-0341/wallet-test-vectors.json` |

## bitcoin/bitcoin — bf8402c8803f085a50df96cb7956033cd252e9ab

Licence: MIT.

| File | Upstream path |
|---|---|
| `core-sighash.json` | `src/test/data/sighash.json` |
| `core-tx_valid.json` | `src/test/data/tx_valid.json` |
| `core-tx_invalid.json` | `src/test/data/tx_invalid.json` |
| `core-script_tests.json` | `src/test/data/script_tests.json` |
| `core-key_io_valid.json` | `src/test/data/key_io_valid.json` |
| `core-key_io_invalid.json` | `src/test/data/key_io_invalid.json` |
| `core-base58_encode_decode.json` | `src/test/data/base58_encode_decode.json` |

## trezor/python-mnemonic — b57a5ad77a981e743f4167ab2f7927a55c1e82a8

Licence: MIT.

| File | Upstream path |
|---|---|
| `bip39-vectors.json` | `vectors.json` |

## sipa/bech32 — 7a7d7ab158db7078a333384e0e918c90dbc42917

Licence: MIT.

The BIP173/BIP350 vectors are Python list literals rather than a data file,
so they are transcribed mechanically into `test/bech32_vectors.ml` from
`ref/python/tests.py`. That generated file should not be edited by hand.
