(* Build a Taproot output with a script tree, and spend it both ways.

   Run with: dune exec examples/taproot_tree.exe *)

open Bitcoin

let hex s =
  String.concat "" (List.init (String.length s) (fun i -> Printf.sprintf "%02x" (Char.code s.[i])))

let ok = function Ok x -> x | Error e -> failwith (Error.to_string (e :> Error.t))

let () =
  let key name = ok (Key.Secret.of_octets (Hash.sha256 name)) in
  let internal = key "internal" in
  let alice = Key.Secret.public (key "alice") in
  let bob = Key.Secret.public (key "bob") in

  (* Two alternative spending conditions, as tapscript leaves. *)
  let leaf_of pub =
    Taproot.leaf
      (Script.of_elements
         [ Script.minimal_push (Key.Public.x_only pub); Script.Op Script.Op.op_checksig ])
  in
  let alice_leaf = leaf_of alice and bob_leaf = leaf_of bob in

  (* Weight the tree by how often each leaf is expected to be used: the
     heavier leaf gets the shorter merkle proof and so the cheaper spend. *)
  let tree = Option.get (Taproot.huffman [ (10, alice_leaf); (1, bob_leaf) ]) in
  let si = ok (Taproot.spend_info ~internal_key:(Key.Secret.public internal) ~tree ()) in

  Printf.printf "address      %s\n"
    (Address.to_string ~network:Network.Mainnet (Taproot.address si));
  Printf.printf "internal key %s\n" (hex (Key.Public.x_only (Key.Secret.public internal)));
  Printf.printf "merkle root  %s\n" (hex (Option.get (Taproot.merkle_root_of si)));
  Printf.printf "output key   %s (parity %d)\n"
    (hex (Taproot.output_key si))
    (Taproot.output_parity si);
  Printf.printf "scriptPubKey %s\n" (Format.asprintf "%a" Script.pp (Taproot.script_pubkey si));
  print_newline ();

  (* Key path: whoever holds the internal key can spend without revealing
     that a script tree exists at all. The key must be tweaked first. *)
  let tweaked = ok (Taproot.tweak_secret internal ~merkle_root:(Taproot.merkle_root_of si)) in
  let msg = Hash.sha256 "a taproot sighash would go here" in
  let sg = Key.Schnorr.sign ~key:tweaked ~msg () in
  Printf.printf "key path signature verifies: %b\n"
    (Key.Schnorr.verify ~x_only:(Taproot.output_key si) sg ~msg);

  (* Script path: reveal one leaf and prove it is committed to, by control
     block. The witness is [script inputs; script; control block]. *)
  List.iter
    (fun (leaf, control) ->
      Printf.printf "leaf %s\n  control block %s (%d bytes, depth %d)\n  verifies: %b\n"
        (Format.asprintf "%a" Script.pp leaf.Taproot.script)
        (hex control) (String.length control)
        ((String.length control - 33) / 32)
        (Taproot.verify_control_block ~output_key:(Taproot.output_key si) ~control ~leaf))
    (Taproot.leaves si);

  (* Alice's leaf was given ten times Bob's weight, so her proof is no
     longer than his. *)
  let len l = String.length (ok (Taproot.control_block si l)) in
  assert (len alice_leaf <= len bob_leaf);
  print_endline "ok"
