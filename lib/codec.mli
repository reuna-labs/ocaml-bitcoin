(** Bitcoin consensus serialization.

    Integers are little-endian unless the name says otherwise; lengths are CompactSize varints;
    vectors are a count followed by that many elements. This module is the spine every other
    serializable type sits on.

    Readers raise {!R.Error} internally and are wrapped by {!R.run}, which is the only way to obtain
    one, so no exception escapes. Writers cannot fail. *)

type error =
  [ `Eof of int
  | `Trailing of int
  | `Non_canonical_varint
  | `Overflow of string  (** a value too large for the target type *)
  | `Invalid_range
    (** a value outside what the protocol permits, such as an amount above the supply *)
  | `Invalid_format
  | `Msg of string ]

val pp_error : Format.formatter -> [< error ] -> unit

(** {1 Writing} *)

module W : sig
  type t

  val create : ?size:int -> unit -> t
  val contents : t -> string
  val length : t -> int
  val byte : t -> char -> unit

  val bytes : t -> string -> unit
  (** Raw, with no length prefix. *)

  val u8 : t -> int -> unit
  val u16 : t -> int -> unit
  val u32 : t -> int32 -> unit
  val u64 : t -> int64 -> unit
  val i64 : t -> int64 -> unit
  val u16_be : t -> int -> unit

  val u32_be : t -> int32 -> unit
  (** Big-endian. Bitcoin uses this only in BIP32 serialization and in the network-order fields of
      P2P addresses — never in consensus data. *)

  val varint : t -> int64 -> unit
  (** CompactSize, always in its shortest form. Values are unsigned; a negative [int64] encodes as
      its 64-bit two's-complement pattern. *)

  val varstr : t -> string -> unit
  (** A {!varint} length followed by the raw bytes. *)

  val vector : t -> (t -> 'a -> unit) -> 'a list -> unit
  (** A {!varint} count followed by each element. *)

  val with_length : t -> (t -> unit) -> unit
  (** [with_length w f] runs [f] into a scratch writer and appends the result as a {!varstr}. *)

  val to_string : (t -> 'a -> unit) -> 'a -> string
  val sha256 : (t -> 'a -> unit) -> 'a -> string
  val sha256d : (t -> 'a -> unit) -> 'a -> string

  val tagged : tag:string -> (t -> 'a -> unit) -> 'a -> string
  (** Hash a sub-serialization without materialising it at the call site. BIP143 and BIP341 are
      largely sequences of these. *)
end

(** {1 Reading} *)

module R : sig
  type t

  exception Parse_error of error
  (** Raised by the primitives below and caught by {!run}. Do not let it escape a public API
      boundary. Named to avoid shadowing [result]'s [Error] constructor inside this module. *)

  val fail : [< error ] -> 'a

  val run : ?exact:bool -> (t -> 'a) -> string -> ('a, error) result
  (** [run f s] applies [f] to a reader over [s]. [exact] defaults to [true], in which case
      unconsumed input is reported as [`Trailing]. *)

  val pos : t -> int
  val remaining : t -> int
  val eof : t -> bool

  val peek_byte : t -> char
  (** Reads the next byte without consuming it. *)

  val byte : t -> char
  val take : t -> int -> string
  val u8 : t -> int
  val u16 : t -> int
  val u32 : t -> int32
  val u64 : t -> int64
  val i64 : t -> int64
  val u16_be : t -> int
  val u32_be : t -> int32

  val varint : t -> int64
  (** Rejects any encoding longer than necessary with [`Non_canonical_varint]. Bitcoin Core does the
      same, and canonical re-encoding is required for consensus hashing to agree. *)

  val varint_int : t -> int
  (** {!varint} narrowed to [int], additionally rejecting any count larger than {!remaining}. Use
      this for every length and every vector count: each element occupies at least one byte, so a
      count exceeding the bytes left cannot be honest, and checking before allocating is what stops
      a hostile [0xff] varint from exhausting memory. *)

  val varstr : t -> string
  val vector : t -> (t -> 'a) -> 'a list

  val sub : t -> int -> t
  (** [sub r n] consumes [n] bytes from [r] and returns a reader bounded to exactly those bytes. *)
end
