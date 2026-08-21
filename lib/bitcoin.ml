(** Bitcoin primitives: consensus serialization, keys, addresses, script, transactions, sighash,
    Taproot, BIP32/BIP39 and PSBT.

    Nothing here performs I/O or depends on [Unix], so the library builds unmodified inside a
    MirageOS/Solo5 unikernel.

    This module is an index: it exists to give the library one documentation page and one place that
    fixes the public surface. Modules not listed here are internal and deliberately unreachable. *)

(** {1 Foundations} *)

module Error = Error
module Hash = Hash
module Base58 = Base58
module Bech32 = Bech32
module Codec = Codec

(** {1 Chain parameters} *)

module Network = Network

(** {1 Amounts} *)

module Amount = Amount

(** {1 Keys, scripts and addresses} *)

module Key = Key
module Script = Script
module Address = Address

(** {1 Transactions} *)

module Tx = Tx
