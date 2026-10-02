(lang dune 3.6)

(name bitcoin)

(version 4.0.0~alpha1)

(generate_opam_files true)

; Development pins are preserved through bitcoin.opam.template.

(implicit_transitive_deps false)

(source
 (github reuna-labs/ocaml-bitcoin))

(license ISC)

(authors "Gil Bahat <bahat.gil@gmail.com>")

(maintainers "Gil Bahat <bahat.gil@gmail.com>")

(documentation "https://reuna-labs.github.io/ocaml-bitcoin/")

(package
 (name bitcoin)
 (synopsis
  "Bitcoin primitives: keys, addresses, script, transactions, Taproot, PSBT")
 (description
  "A Bitcoin library for OCaml covering consensus serialization, keys and\naddresses, Bitcoin Script, transactions, all three sighash algorithms\n(legacy, BIP143 segwit v0, BIP341 Taproot), Taproot key- and script-path\nspends, BIP32/BIP39 hierarchical deterministic wallets, and BIP174 PSBT\nwith BIP371 Taproot fields.\n\nThe core library performs no I/O and does not depend on Unix, so it builds\nunmodified as a MirageOS/Solo5 unikernel.")
 (tags
  ("bitcoin" "cryptocurrency" "taproot" "psbt" "segwit" "org:mirage"))
 (depends
  (ocaml
   (>= 4.14.0))
  (dune
   (>= 3.6))
  eqaf
  (digestif
   (>= 1.2.0))
  (base64
   (>= 3.5.0))
  mirage-crypto-secp256k1
  (mirage-crypto-rng
   (>= 2.1.0))
  mirage-crypto-pbkdf2
  mirage-crypto-bip32
  (alcotest :with-test)
  (qcheck-alcotest :with-test)
  (ohex
   (and
    :with-test
    (>= 0.2.0)))
  (yojson
   (and
    :with-test
    (>= 2.0.0)))))
