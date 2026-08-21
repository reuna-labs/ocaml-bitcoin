(* The full wallet path: mnemonic to a signed, broadcastable transaction,
   with the PSBT passing between the roles BIP174 defines.

   Run with: dune exec examples/psbt_flow.exe *)

open Bitcoin

let hex s =
  String.concat "" (List.init (String.length s) (fun i -> Printf.sprintf "%02x" (Char.code s.[i])))

let ok = function Ok x -> x | Error e -> failwith (Error.to_string (e :> Error.t))

let () =
  (* A wallet: BIP39 phrase, BIP32 tree, BIP86 Taproot account. *)
  let words =
    Bip39.normalize
      "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
       about"
  in
  let seed = ok (Bip39.to_seed words) in
  let master = ok (Bip32.Secret.master seed) in
  let path = ok (Derivation_path.of_string "m/86'/0'/0'/0/0") in
  let node = ok (Bip32.Secret.derive_path master path) in
  let internal_key = Key.Secret.public node.Bip32.key in
  let si = ok (Taproot.spend_info ~internal_key ()) in
  let address = Taproot.address si in
  Printf.printf "wallet %s -> %s\n" (Derivation_path.to_string path)
    (Address.to_string ~network:Network.Mainnet address);

  (* Creator: an unsigned transaction spending one output of ours. *)
  let unsigned =
    {
      Tx.version = 2l;
      inputs =
        [
          {
            Tx.In.previous_output = { Tx.Outpoint.txid = Hash.sha256d "funding"; index = 0l };
            script_sig = Script.of_octets "";
            sequence = Tx.In.sequence_rbf;
            witness = [];
          };
        ];
      outputs =
        [
          {
            Tx.Out.value = Amount.of_sat_exn 49_000L;
            script_pubkey = Address.script_pubkey address;
          };
        ];
      lock_time = 0l;
    }
  in
  let psbt = ok (Psbt.Creator.create unsigned) in

  (* Signing a Taproot input before the PSBT is complete is not possible:
     BIP341 commits to every input's amount and scriptPubKey. *)
  (match Psbt.Signer.prevouts psbt with
  | Error e -> Printf.printf "before update: %s\n" (Error.to_string (e :> Error.t))
  | Ok _ -> failwith "should not have been complete");

  (* Updater: supply what the signer needs. *)
  let psbt =
    ok
      (Psbt.Updater.set_witness_utxo psbt ~input:0
         { Tx.Out.value = Amount.of_sat_exn 50_000L; script_pubkey = Taproot.script_pubkey si })
  in
  let psbt =
    ok (Psbt.Updater.set_tap_internal_key psbt ~input:0 (Key.Public.x_only internal_key))
  in
  Printf.printf "psbt   %s\n" (Psbt.to_base64 psbt);

  (* Signer: tweak, sign the BIP341 digest, record the signature. *)
  let psbt = ok (Psbt.Signer.sign_taproot_key_path psbt ~input:0 node.Bip32.key ()) in

  (* Finalizer, then Extractor. *)
  let psbt = ok (Psbt.Finalizer.finalize psbt) in
  let tx = ok (Psbt.Extractor.extract psbt) in

  Printf.printf "txid   %s\n" (Tx.txid_hex tx);
  Printf.printf "vsize  %d vbytes\n" (Tx.vsize tx);
  Printf.printf "fee    %s BTC\n"
    (Amount.to_btc_string (ok (Tx.fee tx ~inputs:[ Amount.of_sat_exn 50_000L ])));
  Printf.printf "raw    %s\n" (hex (Tx.serialize tx));

  (* A key-path spend is one witness element and nothing else: on chain it
     is indistinguishable from any other single-signature Taproot spend. *)
  assert (List.length (List.hd tx.Tx.inputs).Tx.In.witness = 1);
  assert (Script.is_empty (List.hd tx.Tx.inputs).Tx.In.script_sig);
  print_endline "ok"
