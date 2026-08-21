(** secp256k1 keys, WIF, and the two signature schemes Bitcoin uses.

    A key is one value regardless of which cryptographic backend is doing the work underneath; see
    {!Bitcoin.Backend} for how that is split.

    {1 Randomness}

    There is no [generate]. This library never touches a random number generator, because reaching
    an unseeded one inside a unikernel is a hard failure at the worst possible time. Produce 32
    bytes however your environment prefers and hand them to {!Secret.of_octets}, retrying in the
    vanishing case that they do not encode a valid scalar:

    {[
      let rec fresh () =
        match Key.Secret.of_octets (Mirage_crypto_rng.generate 32) with
        | Ok k -> k
        | Error _ -> fresh ()
    ]} *)

type error =
  [ `Invalid_length
  | `Invalid_range
  | `Invalid_format
  | `Invalid_checksum
  | `Not_on_curve
  | `At_infinity
  | `Wrong_hrp
  | `Msg of string ]

val pp_error : Format.formatter -> [< error ] -> unit

module Public : sig
  type t

  val of_octets : string -> (t, error) result
  (** SEC1: 33 bytes compressed or 65 uncompressed. Which one was given is remembered, because it
      changes {!hash160} and therefore the address. *)

  val to_octets : ?compress:bool -> t -> string
  (** Defaults to the encoding the key was decoded from, so a round trip is faithful. Pass
      [~compress] to force one. *)

  val is_compressed : t -> bool

  val compress : t -> t
  (** Re-tag as compressed. The point is unchanged; the address is not. *)

  val equal : t -> t -> bool
  (** Compares points, ignoring how each was encoded. *)

  val hash160 : t -> string
  (** [HASH160] of the encoding this key carries — the payload of a P2PKH or P2WPKH address. *)

  (** {2 x-only keys (BIP340/BIP341)} *)

  val x_only : t -> string
  (** The 32-byte x coordinate. *)

  val has_even_y : t -> bool

  val of_x_only : string -> (t, error) result
  (** BIP340's [lift_x]: the point with this x coordinate and even [y]. *)

  (** {2 Arithmetic} *)

  val add_tweak : t -> string -> (t, error) result
  (** [add_tweak p t] is [P + t*G]: BIP32 public derivation, and the public half of a BIP341 tweak.
  *)

  val combine : t list -> (t, error) result
  val negate : t -> t
end

module Secret : sig
  type t

  val of_octets : string -> (t, error) result
  (** 32 bytes big-endian, in [\[1, n)]. *)

  val to_octets : t -> string

  val equal : t -> t -> bool
  (** Constant time. *)

  val public : t -> Public.t
  (** Compressed by default, which is what every modern script type wants. *)

  val add_tweak : t -> string -> (t, error) result
  val negate : t -> t

  (** {2 Wallet Import Format} *)

  val of_wif : string -> (t * [ `Compressed | `Uncompressed ] * Network.t list, error) result
  (** Base58Check with a network version byte and, for compressed keys, a trailing [0x01]. Returns
      every network the version byte admits: regtest and all three test networks share one, so it
      never identifies a single network. *)

  val to_wif : network:Network.t -> ?compressed:bool -> t -> string
  (** [compressed] defaults to [true]. *)
end

(** {1 ECDSA} *)

module Ecdsa : sig
  type t

  val sign : key:Secret.t -> digest:string -> t
  (** Signs a 32-byte digest with an RFC 6979 deterministic nonce, normalized low-[s]. The digest is
      used as given: hashing the transaction is {!Sighash}'s job.

      @raise Invalid_argument if [digest] is not 32 bytes. *)

  val verify : key:Public.t -> t -> digest:string -> bool

  val of_compact : string -> (t, error) result
  (** 64 bytes, [r || s]. *)

  val to_compact : t -> string

  val of_der : string -> (t, error) result
  (** Strict DER as required by BIP66: minimal integer encodings, no leading zero padding beyond
      what the sign bit demands, no trailing bytes, and no negative values. Everything else is
      rejected — laxness here is what transaction malleability was made of.

      Does not include the trailing sighash byte; strip it first. *)

  val to_der : t -> string

  val is_low_s : t -> bool
  (** Whether [s <= n/2], as BIP62/BIP146 require for a standard signature. *)

  val normalize_s : t -> t
  (** Replaces [s] with [n - s] when it is high, leaving a valid signature over the same message.
      {!sign} already returns normalized signatures; this is for ones parsed from elsewhere. *)

  val r : t -> string
  val s : t -> string
end

(** {1 BIP340 Schnorr} *)

module Schnorr : sig
  type t

  val sign : key:Secret.t -> ?aux_rand:string -> msg:string -> unit -> t
  (** [aux_rand] must be 32 bytes and defaults to 32 zero bytes, which BIP340 explicitly permits.
      Signing is therefore deterministic and never reaches a random number generator. Supplying real
      randomness is recommended where you have it.

      For a Taproot key-path spend the key must already be tweaked (see {!Taproot.tweak_secret});
      the BIP340 adjustment for a point with odd [y] happens inside, so do not apply it yourself.

      @raise Invalid_argument if [aux_rand] is not 32 bytes. *)

  val verify : x_only:string -> t -> msg:string -> bool

  val of_octets : string -> (t, error) result
  (** 64 bytes. *)

  val to_octets : t -> string
end
