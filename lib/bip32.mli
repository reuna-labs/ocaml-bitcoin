(** BIP32 hierarchical deterministic keys.

    An extended key is a key plus a 32-byte chain code, so that children can be derived
    deterministically. Two facts drive the design:

    - A hardened child needs the private key, so it cannot be derived from an extended public key.
      That is the point: it firewalls a compromised chain code and child key from the rest of the
      tree.
    - A non-hardened child {e can} be derived publicly, which is what lets a watch-only wallet see
      its own addresses — and also means that a non-hardened child private key together with the
      parent extended public key reveals the parent private key. The type system cannot prevent
      that, so it is said plainly here. *)

type error =
  [ `Invalid_length
  | `Invalid_range
  | `Invalid_format
  | `Invalid_checksum
  | `Invalid_version
  | `Not_on_curve
  | `At_infinity
  | `Hardened_from_public  (** a hardened child was asked of an extended public key *)
  | `Msg of string ]

val pp_error : Format.formatter -> [< error ] -> unit

type 'a extended = {
  key : 'a;
  chain_code : string;  (** 32 bytes *)
  depth : int;  (** 0 for a master key *)
  parent_fingerprint : string;  (** 4 bytes; zero for a master key *)
  child_number : int32;  (** 0 for a master key *)
}

module Public : sig
  type t = Key.Public.t extended

  val fingerprint : t -> string
  (** The first four bytes of [HASH160] of the public key. Identifies a key in a PSBT or a
      descriptor; it is short enough to collide, so treat it as a hint rather than an identity. *)

  val derive : t -> int32 -> (t, error) result
  (** Fails with [`Hardened_from_public] for an index at or above [2^31]. *)

  val derive_path : t -> Derivation_path.t -> (t, error) result
  val to_base58 : network:Network.t -> t -> string
  val of_base58 : string -> (t * Network.t list, error) result
end

module Secret : sig
  type t = Key.Secret.t extended

  val master : string -> (t, error) result
  (** From a seed of 16 to 64 bytes, per BIP32. Fails with [`Invalid_range] in the negligible case
      that the seed yields an invalid key — BIP32 says to try a different seed rather than to fix it
      up. *)

  val public : t -> Public.t
  val fingerprint : t -> string

  val derive : t -> int32 -> (t, error) result
  (** Handles hardened and normal children alike. On the negligible chance that a child is invalid,
      BIP32 says to skip to the next index; that is the caller's decision, so this returns
      [`Invalid_range] rather than silently moving on. *)

  val derive_path : t -> Derivation_path.t -> (t, error) result
  val to_base58 : network:Network.t -> t -> string
  val of_base58 : string -> (t * Network.t list, error) result
end
