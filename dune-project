(lang dune 3.6)

(name bitcoin)

(generate_opam_files true)

(implicit_transitive_deps false)

(source
 (github reuna147/ocaml-bitcoin))

(license ISC)

(authors "Gil Bahat <bahat.gil@gmail.com>")

(maintainers "Gil Bahat <bahat.gil@gmail.com>")

(documentation "https://reuna147.github.io/ocaml-bitcoin/")

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
  (zarith
   (>= 1.13))
  (digestif
   (>= 1.2.0))
  (base64
   (>= 3.5.0))
  (mirage-crypto-ec
   (>= 2.1.0))
  (mirage-crypto-rng
   (>= 2.1.0))
  mirage-crypto-blockchain
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
