(* Sign a native SegWit v0 (P2WPKH) spend end to end.

   Run with: dune exec examples/spend_p2wpkh.exe *)

open Bitcoin

let hex s =
  String.concat "" (List.init (String.length s) (fun i -> Printf.sprintf "%02x" (Char.code s.[i])))

let ok = function Ok x -> x | Error e -> failwith (Error.to_string (e :> Error.t))

let () =
  (* A key. In practice this comes from a wallet; see psbt_flow.ml for the
     BIP39/BIP32 route. *)
  let secret = ok (Key.Secret.of_octets (Hash.sha256 "example key, do not use")) in
  let public = Key.Secret.public secret in
  let address = ok (Address.p2wpkh_of_key public) in
  Printf.printf "spending from %s\n" (Address.to_string ~network:Network.Mainnet address);

  (* The output being spent: 100_000 sat sitting at that address. *)
  let funding_txid = Hash.sha256d "pretend this is a funding transaction" in
  let prevout_value = Amount.of_sat_exn 100_000L in
  let prevout_script = Address.script_pubkey address in

  (* Pay 90_000 sat onward, leaving 10_000 as fee. *)
  let unsigned =
    {
      Tx.version = 2l;
      inputs =
        [
          {
            Tx.In.previous_output = { Tx.Outpoint.txid = funding_txid; index = 0l };
            script_sig = Script.of_octets "";
            (* Signal BIP125 replaceability, so the fee can be bumped. *)
            sequence = Tx.In.sequence_rbf;
            witness = [];
          };
        ];
      outputs = [ { Tx.Out.value = Amount.of_sat_exn 90_000L; script_pubkey = prevout_script } ];
      lock_time = 0l;
    }
  in

  (* BIP143 signs over the value of the input being spent, which is what lets
     a signer verify the fee without fetching the whole previous transaction.
     The script code for P2WPKH is the equivalent P2PKH script, not the
     witness program -- of_prevouts derives it for you. *)
  let prevouts =
    ok
      (Sighash.Prevouts.of_list unsigned
         [ { Sighash.value = prevout_value; script_pubkey = prevout_script } ])
  in
  let digest =
    ok
      (Sighash.of_prevouts ~prevouts ~input:0 ~spend:Sighash.P2wpkh
         ~flag:(Sighash.Flag.Explicit Sighash.Flag.all) ())
  in
  let signature = Key.Ecdsa.sign ~key:secret ~digest in

  (* The witness is the DER signature with its sighash byte, then the pubkey. *)
  let signed =
    {
      unsigned with
      Tx.inputs =
        List.map
          (fun i ->
            {
              i with
              Tx.In.witness = [ Key.Ecdsa.to_der signature ^ "\x01"; Key.Public.to_octets public ];
            })
          unsigned.Tx.inputs;
    }
  in

  Printf.printf "txid    %s\n" (Tx.txid_hex signed);
  Printf.printf "vsize   %d vbytes (weight %d)\n" (Tx.vsize signed) (Tx.weight signed);
  Printf.printf "fee     %s BTC\n"
    (Amount.to_btc_string (ok (Tx.fee signed ~inputs:[ prevout_value ])));
  Printf.printf "rbf     %b\n" (Tx.is_rbf_signalling signed);
  Printf.printf "raw     %s\n" (hex (Tx.serialize signed));

  (* The signature verifies, and the txid did not change when we added the
     witness -- that is what SegWit bought. *)
  assert (Key.Ecdsa.verify ~key:public signature ~digest);
  assert (String.equal (Tx.txid signed) (Tx.txid unsigned));
  assert (not (String.equal (Tx.txid signed) (Tx.wtxid signed)));
  print_endline "ok"
