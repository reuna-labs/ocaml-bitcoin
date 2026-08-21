module B = Bitcoin_backend.Backend

type error =
  [ `Invalid_length
  | `Invalid_range
  | `Invalid_format
  | `Not_on_curve
  | `At_infinity
  | `Too_deep
  | `Not_in_tree
  | `Msg of string ]

let pp_error ppf (e : [< error ]) = Error.pp ppf (e :> Error.t)

(* Key's error type is wider than anything reachable from here: checksum and
   hrp failures belong to address decoding, not to curve arithmetic. Map
   them rather than widening this type to admit cases it cannot produce. *)
let of_key_error : Key.error -> error = function
  | (`Invalid_length | `Invalid_range | `Invalid_format | `Not_on_curve | `At_infinity | `Msg _) as
    e ->
      e
  | `Invalid_checksum | `Wrong_hrp -> `Msg "unexpected key error in tweak"

let leaf_version_tapscript = 0xc0
let max_depth = 128

type leaf = { version : int; script : Script.t }

let leaf ?(version = leaf_version_tapscript) script = { version; script }

let leaf_hash l =
  Hash.tagged ~tag:Hash.Tag.tap_leaf
    (Codec.W.to_string
       (fun w () ->
         Codec.W.u8 w l.version;
         Script.write w l.script)
       ())

(* Children are hashed in lexicographic order, so a verifier reconstructing
   the root from a path does not need to know which side each sibling was on. *)
let branch_hash a b =
  let lo, hi = if String.compare a b <= 0 then (a, b) else (b, a) in
  Hash.tagged ~tag:Hash.Tag.tap_branch (lo ^ hi)

type tree = Leaf of leaf | Branch of tree * tree

let rec merkle_root = function
  | Leaf l -> leaf_hash l
  | Branch (a, b) -> branch_hash (merkle_root a) (merkle_root b)

let tree_of_leaves = function
  | [] -> None
  | leaves ->
      let rec build = function
        | [ t ] -> t
        | ts ->
            let rec pair = function
              | a :: b :: rest -> Branch (a, b) :: pair rest
              | [ a ] -> [ a ]
              | [] -> []
            in
            build (pair ts)
      in
      Some (build (List.map (fun l -> Leaf l) leaves))

(* Weighted so the leaves you expect to spend most often sit nearest the
   root and carry the shortest merkle proofs. *)
let huffman = function
  | [] -> None
  | [ (_, l) ] -> Some (Leaf l)
  | weighted ->
      let rec go nodes =
        match List.sort (fun (a, _) (b, _) -> compare a b) nodes with
        | (wa, a) :: (wb, b) :: rest -> go ((wa + wb, Branch (a, b)) :: rest)
        | [ (_, t) ] -> t
        | [] -> assert false
      in
      Some (go (List.map (fun (w, l) -> (w, Leaf l)) weighted))

(* Every leaf with the sibling hashes on its path to the root, bottom-up. *)
let leaf_paths tree =
  let rec go depth t =
    match t with
    | Leaf l -> if depth > max_depth then Error `Too_deep else Ok [ (l, []) ]
    | Branch (a, b) -> (
        match (go (depth + 1) a, go (depth + 1) b) with
        | Ok la, Ok lb ->
            let ra = merkle_root a and rb = merkle_root b in
            Ok
              (List.map (fun (l, p) -> (l, p @ [ rb ])) la
              @ List.map (fun (l, p) -> (l, p @ [ ra ])) lb)
        | (Error _ as e), _ | _, (Error _ as e) -> e)
  in
  go 0 tree

type spend_info = {
  internal : Key.Public.t;
  root : string option;
  tweak_hash : string;
  out_key : string;
  parity : int;
  paths : (leaf * string list) list;
}

let tweak_hash_of ~internal_x ~root =
  Hash.tagged ~tag:Hash.Tag.tap_tweak (internal_x ^ match root with None -> "" | Some r -> r)

let spend_info ~internal_key ?tree () =
  let internal_x = Key.Public.x_only internal_key in
  let root = Option.map merkle_root tree in
  let t = tweak_hash_of ~internal_x ~root in
  (* BIP341 requires the tweak to be a valid scalar. The chance of failure is
     negligible, which is exactly why an implementation that skips the check
     works right up until it does not. *)
  match B.public_of_x_only internal_x with
  | Error e -> Error (e :> error)
  | Ok lifted -> (
      match B.public_add_tweak lifted t with
      | Error e -> Error (e :> error)
      | Ok q -> (
          let paths = match tree with None -> Ok [] | Some tr -> leaf_paths tr in
          match paths with
          | Error _ as e -> e
          | Ok paths ->
              Ok
                {
                  internal = internal_key;
                  root;
                  tweak_hash = t;
                  out_key = B.public_x q;
                  parity = (if B.public_has_even_y q then 0 else 1);
                  paths;
                }))

let internal_key s = s.internal
let merkle_root_of s = s.root
let tweak s = s.tweak_hash
let output_key s = s.out_key
let output_parity s = s.parity
let script_pubkey s = Script.p2tr ~output_key:s.out_key

let address s =
  match Address.p2tr ~output_key:s.out_key with
  | Ok a -> a
  | Error _ -> invalid_arg "Taproot.address: output key is not 32 bytes"

let tweak_secret d ~merkle_root =
  let p = Key.Secret.public d in
  (* BIP341 defines the tweak against lift_x(P), the even-y point, so a key
     whose point has odd y is negated first. *)
  let d = if Key.Public.has_even_y p then d else Key.Secret.negate d in
  let t = tweak_hash_of ~internal_x:(Key.Public.x_only p) ~root:merkle_root in
  match Key.Secret.add_tweak d t with Error e -> Error (of_key_error e) | Ok d' -> Ok d'

let block_for s (l : leaf) path =
  String.make 1 (Char.chr (l.version lor s.parity))
  ^ Key.Public.x_only s.internal ^ String.concat "" path

let control_block s l =
  match
    List.find_opt (fun (l', _) -> l'.version = l.version && Script.equal l'.script l.script) s.paths
  with
  | None -> Error `Not_in_tree
  | Some (l', path) ->
      (* The committed leaf version travels in the control block, so use the
       one actually in the tree rather than the caller's copy. *)
      Ok (block_for s l' path)

let leaves s = List.map (fun (l, path) -> (l, block_for s l path)) s.paths

let verify_control_block ~output_key ~control ~leaf =
  let n = String.length control in
  if n < 33 || (n - 33) mod 32 <> 0 || (n - 33) / 32 > max_depth then false
  else
    let c0 = Char.code control.[0] in
    let parity = c0 land 1 in
    let version = c0 land 0xfe in
    version = leaf.version
    &&
    let internal_x = String.sub control 1 32 in
    let path_len = (n - 33) / 32 in
    let k = ref (leaf_hash leaf) in
    for i = 0 to path_len - 1 do
      k := branch_hash !k (String.sub control (33 + (32 * i)) 32)
    done;
    let t = tweak_hash_of ~internal_x ~root:(Some !k) in
    match B.public_of_x_only internal_x with
    | Error _ -> false
    | Ok lifted -> (
        match B.public_add_tweak lifted t with
        | Error _ -> false
        | Ok q ->
            String.equal (B.public_x q) output_key
            && (if B.public_has_even_y q then 0 else 1) = parity)
