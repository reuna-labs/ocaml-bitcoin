(** The hash functions Bitcoin uses.

    Thin wrappers over {!Digestif}. All inputs and outputs are raw byte strings, never hex. *)

val sha256 : string -> string
(** SHA-256. 32 bytes. *)

val sha256d : string -> string
(** [sha256d s] is [sha256 (sha256 s)] — "Hash256" in Bitcoin Core, used for txids, block hashes,
    Base58Check checksums and the legacy/BIP143 sighashes. 32 bytes. *)

val ripemd160 : string -> string
(** RIPEMD-160. 20 bytes. *)

val hash160 : string -> string
(** [hash160 s] is [ripemd160 (sha256 s)] — "Hash160" in Bitcoin Core, used for P2PKH/P2SH/P2WPKH
    payload hashes. 20 bytes. *)

val tagged : tag:string -> string -> string
(** [tagged ~tag s] is [sha256 (sha256 tag ^ sha256 tag ^ s)], the tagged hash of BIP340 "Design /
    Tagged Hashes", reused throughout BIP341 for [TapLeaf], [TapBranch], [TapTweak] and
    [TapSighash]. 32 bytes.

    Domain separation only works if the tag is a constant; see {!Tag}. *)

(** The tag constants used by BIP340 and BIP341. Named rather than inlined so a typo cannot silently
    produce a well-formed hash under the wrong tag. *)
module Tag : sig
  val tap_leaf : string
  val tap_branch : string
  val tap_tweak : string
  val tap_sighash : string
  val bip340_challenge : string
  val bip340_aux : string
  val bip340_nonce : string
end

val checksum4 : string -> string
(** The first four bytes of {!sha256d}, as used by Base58Check and BIP32 serialization. *)
