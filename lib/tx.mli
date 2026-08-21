(** Transactions, in both the legacy and SegWit serializations.

    A transaction has two encodings: the original one, and the BIP144 form carrying witnesses. Which
    is used decides the identifier — [txid] is over the legacy bytes and so is unaffected by witness
    data, which is the whole point of SegWit. Both come from one function here so they cannot drift.
*)

type error = Codec.error

module Outpoint : sig
  type t = {
    txid : string;  (** 32 bytes, internal byte order (not the displayed hex) *)
    index : int32;
  }

  val null : t
  (** All-zero txid with index [0xffffffff]: the prevout of a coinbase input. *)

  val is_null : t -> bool
  val equal : t -> t -> bool
  val read : Codec.R.t -> t
  val write : Codec.W.t -> t -> unit

  val to_string : t -> string
  (** ["<txid-hex>:<index>"], with the txid in the usual reversed display order. *)
end

module Witness : sig
  type t = string list
  (** The witness stack for one input, bottom element first. *)

  val empty : t
  val is_empty : t -> bool
  val read : Codec.R.t -> t
  val write : Codec.W.t -> t -> unit
end

module In : sig
  type t = {
    previous_output : Outpoint.t;
    script_sig : Script.t;
    sequence : int32;
    witness : Witness.t;
        (** Held with the input it belongs to, though it serializes in a separate section. *)
  }

  val sequence_final : int32
  (** [0xffffffff]: disables both locktime and BIP125 replaceability. *)

  val sequence_rbf : int32
  (** [0xfffffffd]: the largest sequence that still signals opt-in replaceability under BIP125. *)

  val is_rbf_signalling : t -> bool
  val read : Codec.R.t -> t
  val write : Codec.W.t -> t -> unit
end

module Out : sig
  type t = { value : Amount.t; script_pubkey : Script.t }

  val read : Codec.R.t -> t
  val write : Codec.W.t -> t -> unit
end

type t = { version : int32; inputs : In.t list; outputs : Out.t list; lock_time : int32 }

(** {1 Serialization} *)

val serialize : ?witness:bool -> t -> string
(** [witness] defaults to [true], in which case the BIP144 marker and flag are emitted {e only if}
    some input actually carries witness data — matching Core, which never writes an empty witness
    section.

    Note a consequence of that encoding: because a [0x00] following the version is the SegWit
    marker, a legacy transaction with no inputs cannot be represented. That is correct, and matches
    consensus. *)

val parse : string -> (t, error) result
val read : Codec.R.t -> t
val write : ?witness:bool -> Codec.W.t -> t -> unit

(** {1 Identity} *)

val txid : t -> string
(** [SHA256d] of the legacy serialization, in internal byte order. Witness data is excluded, so
    signatures cannot change it. *)

val wtxid : t -> string
(** [SHA256d] of the full serialization including witnesses. Equal to {!txid} when there is no
    witness data. *)

val txid_hex : t -> string
(** {!txid} reversed into the order block explorers display. *)

(** {1 Size and weight} *)

val total_size : t -> int
(** Serialized size with witnesses. *)

val base_size : t -> int
(** Serialized size without witnesses. *)

val weight : t -> int
(** [base_size * 3 + total_size], per BIP141. *)

val vsize : t -> int
(** [weight] in virtual bytes, rounded up — the size fees are charged on. *)

(** {1 Predicates} *)

val has_witness : t -> bool
val is_coinbase : t -> bool

val is_rbf_signalling : t -> bool
(** Whether any input signals BIP125 opt-in replaceability. *)

val total_output : t -> (Amount.t, Amount.error) result

val fee : t -> inputs:Amount.t list -> (Amount.t, Amount.error) result
(** The difference between the supplied input values and the outputs. Fails with [`Invalid_range] if
    the outputs exceed the inputs, and with [`Invalid_format] if the number of input values does not
    match the number of inputs — a mismatch there means the caller is working from the wrong
    prevouts, and guessing would be worse than refusing. *)
