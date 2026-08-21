(** Block headers and blocks.

    This is serialization and the header's self-contained checks — the proof-of-work and the merkle
    commitment. It is not consensus validation: deciding whether a block is {e valid} needs the
    chain it sits in, the UTXO set, and a script interpreter, none of which live here. *)

type error = Codec.error

module Header : sig
  type t = {
    version : int32;
    prev_block : string;  (** 32 bytes, internal byte order *)
    merkle_root : string;  (** 32 bytes *)
    time : int32;  (** Unix seconds, as the miner claimed *)
    bits : int32;  (** the target, in compact form *)
    nonce : int32;
  }

  val size : int
  (** [80]. A header is always exactly this long. *)

  val read : Codec.R.t -> t
  val write : Codec.W.t -> t -> unit
  val parse : string -> (t, error) result
  val serialize : t -> string

  val hash : t -> string
  (** [SHA256d] of the 80 bytes, in internal byte order. *)

  val hash_hex : t -> string
  (** {!hash} reversed into the order block explorers display. *)

  val target : t -> string
  (** The 32-byte big-endian target that {!bits} encodes. *)

  val meets_target : t -> bool
  (** Whether the header's hash is at or below its target — the proof of work. Says nothing about
      whether [bits] is the value consensus would have required at this height, which needs the
      preceding chain. *)

  val difficulty : t -> float
  (** The target expressed as a multiple of the difficulty-1 target. Uses floating point and is for
      display only. *)
end

(** {1 Compact target encoding} *)

val target_of_bits : int32 -> string
(** Expands the compact form to a 32-byte big-endian target. Bitcoin's "nBits": one exponent byte
    and a three-byte mantissa. *)

val bits_of_target : string -> int32
(** The inverse, in the canonical form Bitcoin uses. *)

(** {1 Merkle trees} *)

val merkle_root : string list -> string
(** The root over a list of txids in block order.

    Reproduces the duplication of the last hash when a level has an odd number of nodes — the quirk
    behind CVE-2012-2459. It is consensus behaviour and cannot be corrected without changing which
    blocks are valid. *)

val is_merkle_mutation : string list -> bool
(** Whether any level of the tree would duplicate a hash that is already equal to its neighbour.
    Such a block has a second, distinct transaction list with the same merkle root, which is the
    shape of the CVE-2012-2459 attack. *)

(** {1 Blocks} *)

type t = { header : Header.t; transactions : Tx.t list }

val parse : string -> (t, error) result
val serialize : t -> string
val hash : t -> string
val txids : t -> string list

val computed_merkle_root : t -> string
(** The root over the block's own transactions, to compare against {!Header.merkle_root}. *)

val has_valid_merkle_root : t -> bool
val coinbase : t -> Tx.t option
val total_size : t -> int
val weight : t -> int
