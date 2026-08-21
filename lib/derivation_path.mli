(** BIP32 derivation paths, as written [m/84'/0'/0'/0/0]. *)

type hardened_marker =
  [ `Apostrophe  (** [44'] — BIP32's own notation *)
  | `H  (** [44h] — safer in shells, where [\'] quotes *) ]

type t

val empty : t
(** The master key's own path, [m]. *)

val of_list : int32 list -> t
(** From raw child numbers, where anything at or above [0x80000000] is hardened. *)

val to_list : t -> int32 list

val of_string : string -> (t, [> `Invalid_format ]) result
(** Accepts a leading [m] or [M] and either hardened marker, mixed freely. Rejects an index at or
    above [2^31] written without a marker, since that would silently mean something other than what
    it says. *)

val to_string : ?marker:hardened_marker -> t -> string
(** [marker] defaults to [`Apostrophe]. *)

val append : t -> int32 -> t

val child : t -> int -> hardened:bool -> (t, [> `Invalid_range ]) result
(** [child p n ~hardened] appends index [n], which must be below [2^31]. *)

val parent : t -> t option
val depth : t -> int
val is_hardened : int32 -> bool
val equal : t -> t -> bool

(** {1 Common purposes} *)

val bip44 : coin:int32 -> account:int32 -> (t, [> `Invalid_range ]) result
(** [m/44'/coin'/account'] — legacy P2PKH. *)

val bip49 : coin:int32 -> account:int32 -> (t, [> `Invalid_range ]) result
(** [m/49'/coin'/account'] — P2WPKH wrapped in P2SH. *)

val bip84 : coin:int32 -> account:int32 -> (t, [> `Invalid_range ]) result
(** [m/84'/coin'/account'] — native P2WPKH. *)

val bip86 : coin:int32 -> account:int32 -> (t, [> `Invalid_range ]) result
(** [m/86'/coin'/account'] — Taproot. *)

val coin_type : Network.t -> int32
(** [0] for mainnet, [1] for every test network, per SLIP-44. *)
