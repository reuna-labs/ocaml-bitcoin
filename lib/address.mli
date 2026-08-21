(** Bitcoin addresses across all standard output types.

    The representation follows the encodings rather than the friendly names: Base58Check carries a
    version byte and a 20-byte hash, and Bech32 carries a witness version and a program. Modelling
    it that way makes {!of_string} total over well-formed input and keeps future witness versions
    representable instead of erroring. Use {!classify} for the five names. *)

type error =
  [ `Invalid_length
  | `Invalid_format
  | `Invalid_checksum
  | `Invalid_version
  | `Wrong_variant
  | `Wrong_hrp
  | `Not_on_curve
  | `Invalid_range
  | `Msg of string ]

val pp_error : Format.formatter -> [< error ] -> unit

type t =
  | P2pkh of string  (** [HASH160] of a public key, 20 bytes *)
  | P2sh of string  (** [HASH160] of a redeem script, 20 bytes *)
  | Segwit of {
      version : int;  (** 0..16 *)
      program : string;  (** 2..40 bytes; 20 or 32 when [version = 0] *)
    }

type kind =
  [ `P2pkh
  | `P2sh
  | `P2wpkh
  | `P2wsh
  | `P2tr
  | `Future of int  (** a witness version this library predates *) ]

val classify : t -> kind
val equal : t -> t -> bool

(** {1 Encoding} *)

val to_string : network:Network.t -> t -> string

val of_string : string -> (t * Network.t list, error) result
(** Decodes without being told the network, returning every network the encoding admits -- never
    empty on success. No address identifies one network: the test networks share all their
    parameters, and a Base58 address cannot even separate those from regtest. *)

val of_string_on : network:Network.t -> string -> (t, error) result
(** As {!of_string}, but fails with [`Wrong_hrp] unless [network] is among the networks the address
    admits. Prefer this whenever the network is known: it is the check that stops a testnet address
    being paid on mainnet. *)

(** {1 Scripts} *)

val script_pubkey : t -> Script.t
val of_script_pubkey : Script.t -> (t, error) result

(** {1 Construction} *)

val p2pkh_of_key : Key.Public.t -> t
(** Honours the key's compressed flag: the same key yields different P2PKH addresses compressed and
    uncompressed, and both are spendable. *)

val p2sh_of_script : Script.t -> t
val p2wsh_of_script : Script.t -> t

val p2wpkh_of_key : Key.Public.t -> (t, error) result
(** Fails on an uncompressed key. BIP143 makes those non-standard in SegWit, and funds sent to one
    can be unspendable in practice, so this refuses rather than producing an address that looks
    fine. *)

val p2sh_p2wpkh_of_key : Key.Public.t -> (t, error) result
(** A P2WPKH wrapped in P2SH, for wallets that predate Bech32. *)

val p2tr : output_key:string -> (t, error) result
(** [output_key] is the 32-byte tweaked x-only key from {!Taproot.output_key}, not a bare public
    key. *)
