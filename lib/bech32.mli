(** Bech32 (BIP173) and Bech32m (BIP350), the checksummed base-32 encoding behind SegWit addresses.

    Witness version 0 (P2WPKH, P2WSH) uses Bech32; version 1 and above (P2TR and future versions)
    use Bech32m. The two differ only in the checksum constant, which is what stops a v0 address
    being read as v1. *)

type error =
  [ `Invalid_format  (** bad character, mixed case, or a malformed separator *)
  | `Invalid_length
  | `Invalid_checksum
  | `Invalid_version  (** witness version outside 0..16 *)
  | `Wrong_variant  (** Bech32 used for v1+, or Bech32m used for v0 *)
  | `Wrong_hrp ]

type encoding = Bech32 | Bech32m

val max_length : int
(** [90]. BIP173 caps a Bech32 string at 90 characters: beyond that the BCH code no longer
    guarantees detection of up to four errors. This is the default limit for {!decode}.

    Other protocols reuse Bech32 at greater lengths -- Lightning invoices most visibly -- which is
    why {!decode} takes the limit as a parameter rather than hard-coding it. Raising it for a
    Bitcoin address would be a mistake. *)

(** {1 Raw Bech32}

    [data] is a sequence of 5-bit groups, each in [0..31], excluding the six-character checksum. *)

val encode : encoding -> hrp:string -> data:int array -> (string, error) result
(** The human-readable part must be lowercase: BIP173 requires encoders to emit lowercase, and a
    mixed-case string does not decode. *)

val decode : ?limit:int -> string -> (encoding * string * int array, error) result
(** [limit] defaults to {!max_length}. *)

(** {1 SegWit addresses} *)

val encode_segwit : hrp:string -> version:int -> program:string -> (string, error) result
(** [encode_segwit ~hrp ~version ~program] encodes a witness program. Selects Bech32 for version 0
    and Bech32m otherwise, and enforces BIP173's length rules: 2..40 bytes generally, and exactly 20
    or 32 for version 0. *)

val decode_segwit : hrp:string -> string -> (int * string, error) result
(** Decodes a SegWit address whose human-readable part must equal [hrp], returning the witness
    version and program. *)

val decode_segwit_any : string -> (string * int * string, error) result
(** As {!decode_segwit} but returns the human-readable part instead of requiring it, so a caller can
    dispatch on the network it names. *)
