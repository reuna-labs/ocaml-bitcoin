(** Bitcoin Script: opcodes, serialization, and the standard output patterns.

    This is a parser and a builder, not an interpreter. Scripts are byte strings with an accidental
    structure — {!parse} recovers that structure where it exists, but a script that does not decode
    cleanly is still a perfectly valid scriptPubKey that consensus will happily evaluate, so parsing
    never changes what a script {e is}. Round-tripping is exact. *)

type t
(** A script, held as its serialized bytes. *)

(** {1 Conversion} *)

val of_octets : string -> t
(** Total: every byte string is a script. *)

val to_octets : t -> string
val length : t -> int
val equal : t -> t -> bool
val is_empty : t -> bool

val read : Codec.R.t -> t
(** Reads a length-prefixed script. *)

val write : Codec.W.t -> t -> unit
(** Writes a length-prefixed script. *)

val write_raw : Codec.W.t -> t -> unit
(** Writes the bytes with no length prefix. *)

(** {1 Opcodes} *)

module Op : sig
  val op_0 : int
  val op_pushdata1 : int
  val op_pushdata2 : int
  val op_pushdata4 : int
  val op_1negate : int
  val op_1 : int
  val op_16 : int
  val op_return : int
  val op_dup : int
  val op_equal : int
  val op_equalverify : int
  val op_hash160 : int
  val op_checksig : int
  val op_checksigverify : int
  val op_checkmultisig : int
  val op_checksigadd : int
  val op_codeseparator : int

  val name : int -> string
  (** A human-readable mnemonic, or ["OP_UNKNOWN(n)"]. *)

  val of_small_int : int -> int
  (** [of_small_int n] is the opcode pushing [n] for [0 <= n <= 16]: [OP_0], or [OP_1 + n - 1].

      @raise Invalid_argument outside that range. *)

  val to_small_int : int -> int option
  (** The inverse: the number an [OP_0]/[OP_1]..[OP_16] opcode pushes. *)
end

(** {1 Structure} *)

type element =
  | Push of { opcode : int;  (** which of the five push forms was used *) data : string }
  | Op of int

val parse : t -> (element list, Codec.error) result
(** Decodes into pushes and opcodes. Fails on a truncated push, which is the only way a script can
    be structurally malformed. *)

val of_elements : element list -> t

val to_elements_exn : t -> element list
(** @raise Invalid_argument if the script does not decode. *)

val minimal_push : string -> element
(** The shortest encoding that pushes [data], following the rule Core's [MINIMALDATA] policy
    enforces: small integers use [OP_0]/[OP_1..16] or [OP_1NEGATE], and longer values use the
    shortest [PUSHDATA] that fits. *)

val push : string -> t
(** A script consisting of a single {!minimal_push}. *)

val concat : t list -> t

(** {1 Standard output patterns} *)

val p2pk : Key.Public.t -> t
val p2pkh : hash160:string -> t
val p2sh : hash160:string -> t
val p2wpkh : hash160:string -> t
val p2wsh : sha256:string -> t
val p2tr : output_key:string -> t

val witness_program : version:int -> program:string -> t
(** The generic form: a version opcode followed by a push of the program. *)

val multisig : threshold:int -> Key.Public.t list -> (t, [> `Invalid_range ]) result
(** A bare [OP_m <pubkeys> OP_n OP_CHECKMULTISIG]. *)

val op_return : string -> t

type kind =
  | P2pk of string  (** the pubkey, as encoded *)
  | P2pkh of string  (** hash160 *)
  | P2sh of string  (** hash160 *)
  | Witness of { version : int; program : string }
  | Multisig of { threshold : int; keys : string list }
  | Op_return of string
  | Nonstandard

val classify : t -> kind
(** Recognises the standard templates. Anything else is [Nonstandard], which is a statement about
    shape, not about validity. *)

val is_witness_program : t -> bool
(** Whether this is a SegWit output: a version opcode followed by a single 2-to-40 byte push, and
    nothing else. *)

(** {1 Sighash support} *)

val find_and_delete : t -> string -> t
(** [find_and_delete script pattern] removes every occurrence of [pattern] from [script], but only
    where it appears at a push boundary — Core's [FindAndDelete]. Legacy sighash removes the
    signature from the scriptCode this way. BIP143 dropped the behaviour, so SegWit v0 and Taproot
    do not use this. *)

val remove_codeseparators : t -> t
(** Drops every [OP_CODESEPARATOR], as legacy sighash requires. *)

val pp : Format.formatter -> t -> unit
(** Renders in Core's [asm] style, so scripts are readable in test output. *)
