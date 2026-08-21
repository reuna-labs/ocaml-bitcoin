#!/bin/sh
# Build the smoke-test unikernel. See README.md for why the two
# substitutions are necessary.
#
# Usage: MIRAGE_CRYPTO=/path/to/the/fork ./build.sh [hvt|spt]
set -e

target="${1:-hvt}"
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/.." && pwd)
: "${MIRAGE_CRYPTO:?set MIRAGE_CRYPTO to a checkout of the mirage-crypto fork}"

cd "$here"
[ -d duniverse ] || { mirage configure -t "$target"; make depends; }

# opam-monorepo resolves `bitcoin` to the 3.0 JSON-RPC client still holding
# that name on opam, which pulls cryptokit and therefore unix.
rm -rf duniverse/ocaml-bitcoin duniverse/cryptokit
mkdir -p duniverse/ocaml-bitcoin
cp -r "$root/lib" "$root/bip39" "$root/dune-project" "$root/bitcoin.opam" \
      duniverse/ocaml-bitcoin/

# Upstream mirage-crypto has neither secp256k1 nor the blockchain package.
rm -rf duniverse/mirage-crypto
cp -r "$MIRAGE_CRYPTO" duniverse/mirage-crypto
rm -rf duniverse/mirage-crypto/.git duniverse/mirage-crypto/_build \
       duniverse/mirage-crypto/_opam
chmod -R u+w duniverse

make build
ls -l dist/
