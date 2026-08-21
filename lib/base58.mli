(** Base58 and Base58Check, as Bitcoin uses them for legacy addresses, WIF private keys and BIP32
    extended keys.

    Base58Check appends the first four bytes of {!Hash.sha256d} over the payload. This
    implementation uses byte-array long division rather than arbitrary-precision arithmetic, so it
    pulls in no bignum dependency. *)

type error =
  [ `Invalid_format  (** a character outside the Base58 alphabet *)
  | `Invalid_length  (** shorter than the four-byte checksum *)
  | `Invalid_checksum ]

val alphabet : string
(** ["123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"] — the digits and letters of
    Base58, with [0], [O], [I] and [l] omitted. *)

val encode : string -> string
val decode : string -> (string, error) result

val encode_check : string -> string
(** [encode_check payload] is [encode (payload ^ Hash.checksum4 payload)]. *)

val decode_check : string -> (string, error) result
(** Decodes and verifies the trailing four-byte checksum, returning the payload without it. *)
