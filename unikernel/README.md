# Solo5 unikernel smoke test

Builds a MirageOS/Solo5 unikernel that links `bitcoin` and exercises the
hashing, curve, serialization, address and HD-wallet paths. If this produces
a running unikernel, the library's no-I/O claim holds end to end rather than
by inspection.

## Verified configuration

    OCaml        5.4.1     (ocaml-solo5 pins an exact compiler per release)
    ocaml-solo5  1.3.3
    solo5        0.12.1
    mirage       4.11.2
    opam-monorepo 0.4.3

`ocaml-solo5` constrains the compiler exactly, so the pairing matters:
0.8.5 wants OCaml >= 4.12, 1.0.1 wants 5.2.1, 1.1.0/1.2.0 want 5.3.0,
1.2.1/1.2.2 want 5.4.1, and 1.3.x wants 5.4.1 or 5.5.0. Pairing 1.3.x with
4.14 does not resolve.

## Building

    opam repository add overlays https://github.com/dune-universe/opam-overlays.git
    opam install ocaml-solo5 mirage opam-monorepo
    cd unikernel
    mirage configure -t hvt        # or -t spt to run without virtualization
    make depends                   # vendors every dependency into duniverse/
    make build

`make depends` needs the `overlays` repository because Zarith is not built
with dune upstream and so cannot be vendored; the overlay provides
`zarith.1.14+dune+mirage`. GMP is vendored and cross-compiled alongside it.

## Two things that will bite

`opam-monorepo` resolves `bitcoin` from the opam repository, where the name
still holds the 3.0 JSON-RPC client. That package depends on cryptokit,
which depends on `unix`, which does not exist in a unikernel — so the build
fails on a library this project no longer contains. Until the opam name is
taken over, replace `duniverse/ocaml-bitcoin` with this working tree.

`mirage-crypto-blockchain` and the secp256k1 support in `mirage-crypto-ec`
live only in a fork that is not public, so `duniverse/mirage-crypto` has to
be replaced with a checkout of it as well. See `../CONTRIBUTING.md`.

`build.sh` does both substitutions and is what the numbers above were
measured with.
