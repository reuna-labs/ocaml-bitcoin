open Bitcoin
open Testutil

(* The BIP341 wallet vectors describe a script tree as nested JSON: a leaf is
   an object with "script"/"leafVersion", a branch is a two-element array. *)
let rec tree_of_json = function
  | `Assoc _ as o ->
      let script = hex Yojson.Safe.Util.(o |> member "script" |> to_string) in
      let version = Yojson.Safe.Util.(o |> member "leafVersion" |> to_int) in
      Taproot.Leaf (Taproot.leaf ~version (Script.of_octets script))
  | `List [ a; b ] -> Taproot.Branch (tree_of_json a, tree_of_json b)
  | `List [ x ] -> tree_of_json x
  | j -> Alcotest.failf "unexpected scriptTree shape: %s" (Yojson.Safe.to_string j)

(* Leaves in the order the vectors number them, which is the order their
   leafHashes and control blocks are listed in. *)
let rec tree_leaves = function
  | Taproot.Leaf l -> [ l ]
  | Taproot.Branch (a, b) -> tree_leaves a @ tree_leaves b

let bip341_script_pubkey () =
  let open Yojson.Safe.Util in
  let cases = json "bip341-wallet-test-vectors.json" |> member "scriptPubKey" |> to_list in
  check_int "vector count" 7 (List.length cases);
  List.iteri
    (fun i case ->
      let given = member "given" case
      and intermediary = member "intermediary" case
      and expected = member "expected" case in
      let internal_hex = given |> member "internalPubkey" |> to_string in
      let internal = ok (Key.Public.of_x_only (hex internal_hex)) in
      let tree =
        match given |> member "scriptTree" with `Null -> None | j -> Some (tree_of_json j)
      in
      let name s = Printf.sprintf "case %d %s" i s in
      let si = ok (Taproot.spend_info ~internal_key:internal ?tree ()) in
      (* Merkle root. *)
      (match (intermediary |> member "merkleRoot", Taproot.merkle_root_of si) with
      | `Null, None -> ()
      | `String want, Some got -> check_hex (name "merkleRoot") want got
      | _ -> Alcotest.failf "%s: merkleRoot presence mismatch" (name ""));
      (* Individual leaf hashes, where the vector lists them. *)
      (match intermediary |> member "leafHashes" with
      | `List hs ->
          let leaves = match tree with None -> [] | Some t -> tree_leaves t in
          List.iteri
            (fun j h ->
              check_hex
                (name (Printf.sprintf "leafHash %d" j))
                (to_string h)
                (Taproot.leaf_hash (List.nth leaves j)))
            hs
      | _ -> ());
      check_hex (name "tweak") (intermediary |> member "tweak" |> to_string) (Taproot.tweak si);
      check_hex (name "tweakedPubkey")
        (intermediary |> member "tweakedPubkey" |> to_string)
        (Taproot.output_key si);
      check_hex (name "scriptPubKey")
        (expected |> member "scriptPubKey" |> to_string)
        (Script.to_octets (Taproot.script_pubkey si));
      check_str (name "bip350Address")
        (expected |> member "bip350Address" |> to_string)
        (Address.to_string ~network:Network.Mainnet (Taproot.address si));
      (* Control blocks, and each must verify against the output key. *)
      match expected |> member "scriptPathControlBlocks" with
      | `List cbs ->
          let leaves = match tree with None -> [] | Some t -> tree_leaves t in
          List.iteri
            (fun j cb ->
              let l = List.nth leaves j in
              let got = ok (Taproot.control_block si l) in
              check_hex (name (Printf.sprintf "controlBlock %d" j)) (to_string cb) got;
              check_bool
                (name (Printf.sprintf "controlBlock %d verifies" j))
                true
                (Taproot.verify_control_block ~output_key:(Taproot.output_key si) ~control:got
                   ~leaf:l))
            cbs
      | _ -> ())
    cases

let bip341_key_path_signing () =
  (* The vectors give the tweaked private key outright, so this compares it
     byte for byte rather than settling for "a signature that verifies".
     That distinction is the whole point: a key negated one time too many
     still signs perfectly well, just against a different public key, so
     verification alone would not notice. *)
  let open Yojson.Safe.Util in
  let cases = json "bip341-wallet-test-vectors.json" |> member "keyPathSpending" |> to_list in
  let checked = ref 0 in
  List.iter
    (fun case ->
      List.iter
        (fun inp ->
          let given = member "given" inp
          and inter = member "intermediary" inp
          and expected = member "expected" inp in
          match given |> member "internalPrivkey" with
          | `String sk -> (
              let idx = given |> member "txinIndex" |> to_int in
              let name s = Printf.sprintf "input %d %s" idx s in
              let d = ok (Key.Secret.of_octets (hex sk)) in
              let merkle_root =
                match given |> member "merkleRoot" with
                | `Null -> None
                | j -> Some (hex (to_string j))
              in
              check_hex (name "internalPubkey")
                (inter |> member "internalPubkey" |> to_string)
                (Key.Public.x_only (Key.Secret.public d));
              let tweaked = ok (Taproot.tweak_secret d ~merkle_root) in
              check_hex (name "tweakedPrivkey")
                (inter |> member "tweakedPrivkey" |> to_string)
                (Key.Secret.to_octets tweaked);
              (* The vector's sigMsg already carries the 0x00 epoch byte, so
               the message signed is just its TapSighash tagged hash. *)
              let sig_msg = hex (inter |> member "sigMsg" |> to_string) in
              let sig_hash = Hash.tagged ~tag:Hash.Tag.tap_sighash sig_msg in
              check_hex (name "sigHash") (inter |> member "sigHash" |> to_string) sig_hash;
              (* The witness holds the 64-byte signature plus, when the sighash
               type is not SIGHASH_DEFAULT, a trailing type byte. *)
              match expected |> member "witness" with
              | `List [ `String wit ] ->
                  let w = hex wit in
                  let hash_type = given |> member "hashType" |> to_int in
                  let expected_len = if hash_type = 0 then 64 else 65 in
                  check_int (name "witness length") expected_len (String.length w);
                  if String.length w = 65 then
                    check_int (name "trailing sighash byte") hash_type (Char.code w.[64]);
                  let sg = ok (Key.Schnorr.of_octets (String.sub w 0 64)) in
                  check_bool
                    (name "signature verifies against the tweaked key")
                    true
                    (Key.Schnorr.verify
                       ~x_only:(Key.Public.x_only (Key.Secret.public tweaked))
                       sg ~msg:sig_hash);
                  (* And must not verify against the untweaked key. *)
                  check_bool
                    (name "does not verify against the internal key")
                    false
                    (Key.Schnorr.verify
                       ~x_only:(Key.Public.x_only (Key.Secret.public d))
                       sg ~msg:sig_hash);
                  incr checked
              | _ -> ())
          | _ -> ())
        (member "inputSpending" case |> to_list))
    cases;
  check_int "key-path inputs exercised" 7 !checked

let double_negation_guard () =
  (* Directly: tweaking must not pre-negate for BIP340. If it did, the
     signature would verify against the negation of the intended key, so
     this is the check that keeps that mistake from being silent. *)
  let d =
    ok
      (Key.Secret.of_octets
         (hex "B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF"))
  in
  let internal = Key.Secret.public d in
  let si = ok (Taproot.spend_info ~internal_key:internal ()) in
  let tweaked = ok (Taproot.tweak_secret d ~merkle_root:None) in
  (* The tweaked secret's x-only public key is exactly the output key. *)
  check_hex "tweaked pubkey is the output key"
    (unhex (Taproot.output_key si))
    (Key.Public.x_only (Key.Secret.public tweaked));
  (* And a signature made with it verifies against that output key. *)
  let msg = Hash.sha256 "taproot key path" in
  let sg = Key.Schnorr.sign ~key:tweaked ~msg () in
  check_bool "signature verifies against the output key" true
    (Key.Schnorr.verify ~x_only:(Taproot.output_key si) sg ~msg);
  (* Signing with the untweaked key must not verify against the output key. *)
  check_bool "untweaked key does not work" false
    (Key.Schnorr.verify ~x_only:(Taproot.output_key si) (Key.Schnorr.sign ~key:d ~msg ()) ~msg)

let tree_construction () =
  let mk n = Taproot.leaf (Script.op_return (string_of_int n)) in
  (* branch_hash sorts its children, so tree shape is order-independent at
     each node. *)
  let a = Taproot.leaf_hash (mk 1) and b = Taproot.leaf_hash (mk 2) in
  check_hex "branch is commutative" (unhex (Taproot.branch_hash a b)) (Taproot.branch_hash b a);
  (* A single leaf's root is its own hash. *)
  let one = Option.get (Taproot.tree_of_leaves [ mk 1 ]) in
  check_hex "single leaf root" (unhex a) (Taproot.merkle_root one);
  check_bool "empty tree" true (Taproot.tree_of_leaves [] = None);
  check_bool "empty huffman" true (Taproot.huffman [] = None);
  (* Huffman weighting gives the heaviest leaf the shortest path. *)
  let leaves = List.init 5 mk in
  let weighted = List.mapi (fun i l -> ((if i = 0 then 100 else 1), l)) leaves in
  let tree = Option.get (Taproot.huffman weighted) in
  let internal =
    Key.Secret.public
      (ok
         (Key.Secret.of_octets
            (hex "B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF")))
  in
  let si = ok (Taproot.spend_info ~internal_key:internal ~tree ()) in
  let all = Taproot.leaves si in
  check_int "every leaf has a control block" 5 (List.length all);
  let len_of l = String.length (snd (List.find (fun (l', _) -> l' = l) all)) in
  check_bool "the heavy leaf has the shortest proof" true (len_of (mk 0) <= len_of (mk 4));
  List.iter
    (fun (l, cb) ->
      check_int "control block length" 0 ((String.length cb - 33) mod 32);
      check_bool "verifies" true
        (Taproot.verify_control_block ~output_key:(Taproot.output_key si) ~control:cb ~leaf:l))
    all;
  (* A leaf not in the tree has no control block. *)
  is_error "leaf not in tree" (Taproot.control_block si (mk 99))

let control_block_rejections () =
  let internal =
    Key.Secret.public
      (ok
         (Key.Secret.of_octets
            (hex "B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF")))
  in
  let l = Taproot.leaf (Script.op_return "x") in
  let tree = Option.get (Taproot.tree_of_leaves [ l; Taproot.leaf (Script.op_return "y") ]) in
  let si = ok (Taproot.spend_info ~internal_key:internal ~tree ()) in
  let cb = ok (Taproot.control_block si l) in
  let ok_ = Taproot.verify_control_block ~output_key:(Taproot.output_key si) ~control:cb ~leaf:l in
  check_bool "baseline verifies" true ok_;
  check_bool "wrong output key" false
    (Taproot.verify_control_block ~output_key:(String.make 32 '\007') ~control:cb ~leaf:l);
  check_bool "wrong leaf" false
    (Taproot.verify_control_block ~output_key:(Taproot.output_key si) ~control:cb
       ~leaf:(Taproot.leaf (Script.op_return "z")));
  check_bool "truncated control block" false
    (Taproot.verify_control_block ~output_key:(Taproot.output_key si)
       ~control:(String.sub cb 0 (String.length cb - 1))
       ~leaf:l);
  check_bool "bad length" false
    (Taproot.verify_control_block ~output_key:(Taproot.output_key si) ~control:(cb ^ "\000") ~leaf:l);
  (* Flipping the parity bit must be caught. *)
  let flipped = String.mapi (fun i c -> if i = 0 then Char.chr (Char.code c lxor 1) else c) cb in
  check_bool "flipped parity" false
    (Taproot.verify_control_block ~output_key:(Taproot.output_key si) ~control:flipped ~leaf:l)

let suite =
  [
    ( "taproot",
      [
        Alcotest.test_case "BIP341 scriptPubKey vectors" `Quick bip341_script_pubkey;
        Alcotest.test_case "BIP341 key-path signing" `Quick bip341_key_path_signing;
        Alcotest.test_case "no double negation" `Quick double_negation_guard;
        Alcotest.test_case "tree construction" `Quick tree_construction;
        Alcotest.test_case "control block rejections" `Quick control_block_rejections;
      ] );
  ]
