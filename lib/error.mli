(** Errors returned across the library.

    Every fallible operation returns [(_, t) result] or [(_, [< t ]) result]; no exception crosses a
    public boundary. The type is a polymorphic variant so that individual modules can expose the
    narrower subset they actually produce while still coercing into this union. *)

type t =
  [ `Eof of int  (** wanted this many more bytes than were available *)
  | `Trailing of int  (** this many bytes left unconsumed after a complete parse *)
  | `Non_canonical_varint  (** a CompactSize not using its shortest encoding *)
  | `Overflow of string  (** a value out of range for the named target type *)
  | `Invalid_length
  | `Invalid_range
  | `Invalid_format
  | `Invalid_checksum
  | `Invalid_version  (** a version or type byte this library does not know *)
  | `Wrong_variant  (** Bech32 used where Bech32m was required, or the reverse *)
  | `Wrong_hrp  (** an address for a different network than the one asked for *)
  | `Not_on_curve
  | `At_infinity
  | `Too_deep  (** a script tree deeper than BIP341 permits *)
  | `Not_in_tree  (** a leaf that the output being spent does not commit to *)
  | `Prevout_mismatch  (** a prevout list that does not match the transaction's inputs *)
  | `Hardened_from_public  (** a hardened BIP32 child asked of an extended public key *)
  | `Msg of string ]

val pp : Format.formatter -> [< t ] -> unit
val to_string : [< t ] -> string
