(** The three sighash algorithms: legacy, BIP143 (SegWit v0) and BIP341 (Taproot).

    Each produces the 32-byte digest a signature commits to. They differ in what they cover, and the
    differences matter: legacy does not commit to the amount being spent, BIP143 commits to the
    amount of the input being signed, and BIP341 commits to the amounts and scriptPubKeys of
    {e every} input. That last requirement is enforced here by {!Prevouts}, which cannot be built
    without them. *)

type error =
  [ `Invalid_range  (** input index out of range for the transaction *)
  | `Invalid_format
  | `Prevout_mismatch  (** the prevout list does not match the transaction's inputs *)
  | `Msg of string ]

val pp_error : Format.formatter -> [< error ] -> unit

(** {1 Sighash flags} *)

module Flag : sig
  type base = All | None_ | Single
  type t = { base : base; anyone_can_pay : bool }

  val all : t
  val to_int : t -> int

  val of_int : int -> (t, error) result
  (** Rejects anything that is not one of the three defined types, with or without [ANYONECANPAY].
      For reading a value off an existing signature use {!of_consensus}, which is total. *)

  val of_consensus : int32 -> t
  (** How consensus reads the field: the type comes from the low five bits, and anything that is not
      [NONE] or [SINGLE] behaves as [ALL]. Total, because non-standard values appear in transactions
      already in the chain and still have to hash to what they hashed to then. *)

  val to_consensus : t -> int32

  type taproot =
    | Default  (** [0x00]: behaves as [SIGHASH_ALL] but is omitted from the signature *)
    | Explicit of t

  val taproot_to_int : taproot -> int

  val taproot_of_int : int -> (taproot, error) result
  (** BIP341 forbids encoding [SIGHASH_ALL] as an explicit [0x01] when [Default] would do, so [0x00]
      and [0x01] are distinct here. *)
end

(** {1 Prevouts} *)

type utxo = { value : Amount.t; script_pubkey : Script.t }

module Prevouts : sig
  type t

  val of_list : Tx.t -> utxo list -> (t, error) result
  (** Fails with [`Prevout_mismatch] unless there is exactly one entry per input, in order. *)

  val tx : t -> Tx.t
  (** The transaction this was built against. Carried along so a prevout set cannot be paired with a
      different transaction by accident. *)

  val get : t -> int -> utxo option
  val to_list : t -> utxo list
  val length : t -> int
end

(** {1 Caches} *)

module Cache : sig
  type t

  val make : Prevouts.t -> t
  (** Precomputes the per-transaction hashes BIP143 and BIP341 both reuse. Without it, signing an
      [n]-input transaction is quadratic in hashing work, so a large consolidation becomes
      pathological. *)
end

(** {1 Digests} *)

val legacy :
  tx:Tx.t -> input:int -> script_code:Script.t -> hash_type:int32 -> (string, error) result
(** The original algorithm.

    [hash_type] is the raw consensus value, not a normalised byte: it is hashed verbatim as a 32-bit
    little-endian integer, and transactions in the chain were signed with non-standard values that
    must keep verifying. Use {!Flag.to_consensus} for the ordinary cases.

    [OP_CODESEPARATOR]s are removed from [script_code] here, as consensus does. Deleting a signature
    being replaced is still the caller's job; see {!Script.find_and_delete}.

    Reproduces the [SIGHASH_SINGLE] bug: when [input] is at or beyond the number of outputs the
    digest is [uint256(1)] rather than an error, which is required to spend certain historical
    outputs. *)

val bip143 :
  ?cache:Cache.t ->
  tx:Tx.t ->
  input:int ->
  script_code:Script.t ->
  amount:Amount.t ->
  hash_type:int32 ->
  unit ->
  (string, error) result
(** SegWit v0. Commits to the amount of the input being signed, which is what made hardware wallets
    able to compute fees safely. [FindAndDelete] does not apply, and neither does [OP_CODESEPARATOR]
    removal. *)

val bip341 :
  ?cache:Cache.t ->
  ?annex:string ->
  ?ext:[ `Key_path | `Script_path of string * int32 ] ->
  prevouts:Prevouts.t ->
  input:int ->
  flag:Flag.taproot ->
  unit ->
  (string, error) result
(** Taproot. Takes a {!Prevouts.t} rather than a transaction because the digest covers every input's
    amount and scriptPubKey; there is no way to call this without having supplied them.

    [ext] is [`Script_path (leaf_hash, codesep_pos)] for a script-path spend ([codesep_pos] is
    [0xffffffff] when no [OP_CODESEPARATOR] was executed), and defaults to [`Key_path]. [annex] is
    the witness annex {e including} its [0x50] prefix.

    Unlike legacy, [SIGHASH_SINGLE] with an out-of-range index is an error here: BIP341 removed the
    bug rather than preserving it. *)

(** {1 Convenience} *)

type spend =
  | P2pkh
  | P2sh of Script.t  (** the redeem script *)
  | P2wpkh
  | P2wsh of Script.t  (** the witness script *)
  | P2tr_key
  | P2tr_script of string * int32  (** leaf hash, codeseparator position *)

val of_prevouts :
  ?cache:Cache.t ->
  ?annex:string ->
  prevouts:Prevouts.t ->
  input:int ->
  spend:spend ->
  flag:Flag.taproot ->
  unit ->
  (string, error) result
(** Picks the algorithm from the spend type and derives [script_code] and [amount] from the
    prevouts. This is the function most callers want: choosing the wrong algorithm produces a digest
    that is silently valid but useless. *)
