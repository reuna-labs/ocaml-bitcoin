(** Partially Signed Bitcoin Transactions: BIP174 version 0, with the BIP371 Taproot fields.

    A PSBT is three key-value maps — one global, one per input, one per output — carrying everything
    a signer needs that the unsigned transaction itself does not.

    {1 Unknown fields}

    BIP174 requires a combiner to preserve key-value pairs it does not understand, so the model is
    typed fields {e plus} the raw remainder. A purely typed model would silently drop data a newer
    signer put there; a purely untyped map would be unusable. *)

type error =
  [ `Invalid_length
  | `Invalid_format
  | `Invalid_range
  | `Invalid_checksum
  | `Duplicate_key
  | `Unsupported_version  (** PSBT v2 (BIP370), which this library does not implement *)
  | `Incomplete  (** a role was asked for something the PSBT does not yet carry *)
  | `Prevout_mismatch
  | `Eof of int
  | `Trailing of int
  | `Non_canonical_varint
  | `Overflow of string
  | `Msg of string ]

val pp_error : Format.formatter -> [< error ] -> unit

val magic : string
(** ["psbt\xff"]. *)

type key_origin = {
  fingerprint : string;  (** 4 bytes, of the master key *)
  path : Derivation_path.t;
}

type proprietary = { identifier : string; subkey : string; value : string }

type unknown = (string * string) list
(** Raw key-value pairs, key including its type prefix. Preserved verbatim. *)

type global_xpub = {
  xpub : Bip32.Public.t;
  xpub_version : int32;
      (** The BIP32 version bytes as they appear in the file. Kept rather than reduced to a network,
          because they are what actually travels: a PSBT that carried a [tpub] has to keep carrying
          one. *)
  xpub_origin : key_origin;
}

module Global : sig
  type t = {
    unsigned_tx : Tx.t;  (** no scriptSigs, no witnesses *)
    xpubs : global_xpub list;
    version : int32 option;
    proprietary : proprietary list;
    unknown : unknown;
  }
end

module Input : sig
  type t = {
    non_witness_utxo : Tx.t option;
    witness_utxo : Tx.Out.t option;
    partial_sigs : (Key.Public.t * string) list;  (** DER signature with its sighash byte *)
    sighash_type : int32 option;
    redeem_script : Script.t option;
    witness_script : Script.t option;
    bip32_derivation : (Key.Public.t * key_origin) list;
    final_script_sig : Script.t option;
    final_script_witness : Tx.Witness.t option;
    ripemd160 : (string * string) list;
    sha256 : (string * string) list;
    hash160 : (string * string) list;
    hash256 : (string * string) list;
    (* BIP371 *)
    tap_key_sig : string option;  (** 64 or 65 bytes *)
    tap_script_sig : ((string * string) * string) list;  (** (x-only key, leaf hash) -> signature *)
    tap_leaf_script : ((Script.t * int) * string) list;
        (** (script, leaf version) -> control block *)
    tap_bip32_derivation : (string * (string list * key_origin)) list;
    tap_internal_key : string option;
    tap_merkle_root : string option;
    proprietary : proprietary list;
    unknown : unknown;
  }

  val empty : t
end

module Output : sig
  type t = {
    redeem_script : Script.t option;
    witness_script : Script.t option;
    bip32_derivation : (Key.Public.t * key_origin) list;
    tap_internal_key : string option;
    tap_tree : (int * int * Script.t) list;  (** depth, leaf version, script *)
    tap_bip32_derivation : (string * (string list * key_origin)) list;
    proprietary : proprietary list;
    unknown : unknown;
  }

  val empty : t
end

type t = { global : Global.t; inputs : Input.t list; outputs : Output.t list }

(** {1 Serialization} *)

val parse : string -> (t, error) result
val serialize : t -> string
val of_base64 : string -> (t, error) result
val to_base64 : t -> string

(** {1 Roles}

    BIP174 separates the work into roles so that a PSBT can move between machines with different
    trust. Each is a pure function here. *)

module Creator : sig
  val create : Tx.t -> (t, error) result
  (** Fails if the transaction carries scriptSigs or witnesses; an unsigned transaction must be
      genuinely unsigned. *)
end

module Updater : sig
  val set_witness_utxo : t -> input:int -> Tx.Out.t -> (t, error) result

  val set_non_witness_utxo : t -> input:int -> Tx.t -> (t, error) result
  (** Checks that the transaction's txid is the one the input actually spends. Without that check a
      signer can be handed a prevout with an inflated value and be induced to sign away the
      difference as fee. *)

  val set_redeem_script : t -> input:int -> Script.t -> (t, error) result
  val set_witness_script : t -> input:int -> Script.t -> (t, error) result
  val set_sighash_type : t -> input:int -> int32 -> (t, error) result
  val add_bip32_derivation : t -> input:int -> Key.Public.t -> key_origin -> (t, error) result
  val set_tap_internal_key : t -> input:int -> string -> (t, error) result
  val set_tap_merkle_root : t -> input:int -> string -> (t, error) result
end

module Combiner : sig
  val combine : t -> t -> (t, error) result
  (** Fails unless both refer to the same unsigned transaction. Unknown fields from either side are
      kept. *)

  val combine_all : t list -> (t, error) result
end

module Signer : sig
  val prevouts : t -> (Sighash.Prevouts.t, error) result
  (** Assembles the prevout set BIP341 needs from the inputs' utxo fields, failing with
      [`Incomplete] if any input lacks one. Taproot signing is therefore impossible until the PSBT
      is complete, and the error names what is missing rather than producing a digest from guesses.
  *)

  val sighash : t -> input:int -> spend:Sighash.spend -> (string, error) result

  val sign_taproot_key_path :
    t ->
    input:int ->
    Key.Secret.t ->
    ?merkle_root:string ->
    ?aux_rand:string ->
    unit ->
    (t, error) result
  (** Tweaks the key, signs the BIP341 digest, and records the result in [tap_key_sig]. *)

  val sign_ecdsa : t -> input:int -> Key.Secret.t -> spend:Sighash.spend -> (t, error) result
  (** Signs and records a [partial_sig] for the key's public counterpart. *)
end

module Finalizer : sig
  val finalize_input : t -> input:int -> (t, error) result

  val finalize : t -> (t, error) result
  (** Turns signatures into a [final_script_sig] and [final_script_witness], and clears the fields
      they replace. Handles P2WPKH, P2TR key path, and P2PKH; anything else is reported as
      [`Incomplete] rather than half-finalized. *)

  val is_finalized : Input.t -> bool
end

module Extractor : sig
  val extract : t -> (Tx.t, error) result
  (** The network-ready transaction. Fails with [`Incomplete] unless every input is finalized. *)
end
