(** Network parameters: the constants that distinguish mainnet from the various test networks. *)

type t = Mainnet | Testnet3 | Testnet4 | Signet | Regtest

type class_ = [ `Main | `Test | `Regtest ]
(** What an encoded address can actually tell you.

    Testnet3, testnet4 and signet share every Base58 version byte and the same Bech32 human-readable
    part [tb], so no address can distinguish them. Decoding therefore yields a class, not a {!t};
    use {!class_of} with a known network to check membership. *)

val class_of : t -> class_
val all : t list
val to_string : t -> string
val of_string : string -> t option

(** {1 Base58 version bytes} *)

val p2pkh_version : t -> int
val p2sh_version : t -> int
val wif_version : t -> int
val of_p2pkh_version : int -> class_ option
val of_p2sh_version : int -> class_ option
val of_wif_version : int -> class_ option

(** {1 Bech32} *)

val hrp : t -> string
(** ["bc"], ["tb"] or ["bcrt"]. *)

val of_hrp : string -> class_ option

(** {1 BIP32 extended key versions} *)

val bip32_public : t -> int32
(** [0x0488B21E] ([xpub]) on mainnet, [0x043587CF] ([tpub]) elsewhere. *)

val bip32_private : t -> int32
(** [0x0488ADE4] ([xprv]) on mainnet, [0x04358394] ([tprv]) elsewhere. *)

val of_bip32_version : int32 -> (class_ * [ `Public | `Private ]) option

(** {1 P2P} *)

val magic : t -> string
(** The four-byte message-start sequence. Unused by this library today, but it is a network
    parameter and belongs here. *)
