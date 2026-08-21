(** Taproot output construction: BIP341 tweaks, script trees, and control blocks.

    A Taproot output commits to an internal public key and, optionally, a merkle tree of scripts.
    The output key is the internal key tweaked by a hash of itself and the tree root, which is what
    lets a key-path spend look like an ordinary signature while a script-path spend reveals only the
    one leaf it uses. *)

type error =
  [ `Invalid_length
  | `Invalid_range
  | `Invalid_format
  | `Not_on_curve
  | `At_infinity
  | `Too_deep  (** a script tree deeper than BIP341's 128 levels *)
  | `Not_in_tree  (** asked for a control block for a leaf this output does not commit to *)
  | `Msg of string ]

val pp_error : Format.formatter -> [< error ] -> unit

val leaf_version_tapscript : int
(** [0xc0], the only leaf version with defined semantics (BIP342). *)

val max_depth : int
(** [128]. A merkle path longer than this cannot be spent. *)

(** {1 Leaves and trees} *)

type leaf = { version : int; script : Script.t }

val leaf : ?version:int -> Script.t -> leaf
(** [version] defaults to {!leaf_version_tapscript}. *)

val leaf_hash : leaf -> string
(** [tagged_hash "TapLeaf" (version || compact_size(script) || script)]. *)

val branch_hash : string -> string -> string
(** [tagged_hash "TapBranch"] of the two children in lexicographic order, so the tree's shape does
    not depend on which side a child was on. *)

type tree = Leaf of leaf | Branch of tree * tree

val tree_of_leaves : leaf list -> tree option
(** A balanced tree over the leaves, or [None] if the list is empty. *)

val huffman : (int * leaf) list -> tree option
(** A tree weighted by how often each leaf is expected to be used, so the common paths get the
    shortest merkle proofs and therefore the cheapest spends. *)

val merkle_root : tree -> string

(** {1 Outputs} *)

type spend_info

val spend_info : internal_key:Key.Public.t -> ?tree:tree -> unit -> (spend_info, error) result
(** Derives the output key. Fails with [`Invalid_range] in the negligible case that the tweak is not
    a valid scalar — BIP341 requires the check, and skipping it is how an implementation works until
    one day it does not. *)

val internal_key : spend_info -> Key.Public.t

val merkle_root_of : spend_info -> string option
(** [None] for a key-path-only output. *)

val tweak : spend_info -> string
(** The 32-byte [TapTweak] hash. *)

val output_key : spend_info -> string
(** The tweaked x-only key, 32 bytes: the witness program. *)

val output_parity : spend_info -> int
(** The y-parity of the output point, [0] or [1]. Needed in a control block, and nowhere else. *)

val script_pubkey : spend_info -> Script.t
val address : spend_info -> Address.t

(** {1 Spending} *)

val tweak_secret : Key.Secret.t -> merkle_root:string option -> (Key.Secret.t, error) result
(** The private counterpart of the output key, for a key-path spend.

    Hand the result straight to {!Key.Schnorr.sign}. BIP340 signing already negates a key whose
    point has odd [y]; negating again here would produce a signature that verifies against a
    different key, silently. *)

val control_block : spend_info -> leaf -> (string, error) result
(** [leaf_version | parity], the internal key, then the merkle path from the leaf upward. Always
    [33 + 32n] bytes. *)

val leaves : spend_info -> (leaf * string) list
(** Every leaf with its control block. *)

val verify_control_block : output_key:string -> control:string -> leaf:leaf -> bool
(** Recomputes the merkle root from the leaf and path, applies the tweak to the internal key the
    control block names, and checks it reproduces [output_key] with the parity the control block
    claims. This is what a verifier does with a script-path spend. *)
