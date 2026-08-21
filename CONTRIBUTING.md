# Contributing

## Building

The two cryptographic dependencies are not yet on opam. Until they are,
`bitcoin.opam.template` pins them via `pin-depends`, so a plain
`opam install --deps-only --with-test .` resolves them.

## Vendored code

`lib/base58.ml` and `lib/bech32.ml` began as copies of the corresponding
files in `ocaml-web3-codec`, with Bitcoin-specific corrections applied
(notably BIP173's 90-character limit on SegWit addresses). They are forks,
not a shared dependency: coupling a Bitcoin package to an Ethereum/Solana
codec would be worse than the duplication. Fixes to either copy should be
considered for the other.

## Conventions

* `dune build @fmt` must be clean; the ocamlformat version is pinned in
  `.ocamlformat` and CI installs exactly that version.
* Nothing under `lib/` may reference `Unix`, `Lwt`, `Async`, `Thread`, or
  any other I/O. CI enforces this with a grep guard and a Solo5 cross-build.
* Every module gets an `.mli`. Public functions return `result`; exceptions
  do not cross a public boundary.
* Test vectors live in `test/vectors/` and every file is recorded in
  `test/vectors/README.md` with its upstream URL, commit and licence.
