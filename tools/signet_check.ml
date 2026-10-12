(* The published bitcoin package against signet, for tools/signet-check.sh.

   verify < lines
     Each line is "<raw tx hex> <value> <scriptPubKey hex> ..." with one value
     and scriptPubKey per input, in order: a transaction signet already
     confirmed, and what each input spent. For every P2WPKH input and every
     taproot key-path input, recomputes the BIP143 or BIP341 digest and checks
     the signature in the witness against it, then again with that input's
     amount one satoshi higher, which must fail. Prints one line per input:
     "ok", "tamper-verified" (the amount was not committed to) or "bad", with
     the kind; script-path and other inputs print "skip".

   spend <txid hex> <index> <value> <fee>
     Signs, with a fresh key, a P2WPKH spend of that output, which is someone
     else's: its value less the fee to the fresh key's own signet address. The
     witness is the fresh key's, so a node must refuse it at the script check.
     Prints "address <bech32>", "txid", "wtxid" (displayed byte order) and
     "wire <hex>". *)

open Bitcoin

let die fmt = Printf.ksprintf (fun s -> prerr_endline s; exit 1) fmt
let ok what = function Ok v -> v | Error _ -> die "%s failed" what

let unhex h =
  String.init (String.length h / 2) (fun i -> Char.chr (int_of_string ("0x" ^ String.sub h (2 * i) 2)))

let hex s = String.concat "" (List.init (String.length s) (fun i -> Printf.sprintf "%02x" (Char.code s.[i])))

let random n =
  let ic = open_in_bin "/dev/urandom" in
  let s = really_input_string ic n in
  close_in ic;
  s

let rev s = String.init (String.length s) (fun i -> s.[String.length s - 1 - i])

type verdict = Ok_ | Tamper_verified | Bad

let check_input tx utxos i =
  let input = List.nth tx.Tx.inputs i in
  let utxo = List.nth utxos i in
  let bumped = { utxo with Sighash.value = Amount.of_sat_exn (Int64.add (Amount.to_sat utxo.Sighash.value) 1L) } in
  let with_bumped = List.mapi (fun j u -> if j = i then bumped else u) utxos in
  match Script.classify utxo.Sighash.script_pubkey, input.Tx.In.witness with
  | Script.Witness { version = 0; program }, [ sig_; pubkey ] when String.length program = 20 ->
      let hash_type = Char.code sig_.[String.length sig_ - 1] in
      let der = String.sub sig_ 0 (String.length sig_ - 1) in
      let key = ok "pubkey" (Key.Public.of_octets pubkey) in
      let signature = Key.Ecdsa.normalize_s (ok "der" (Key.Ecdsa.of_der der)) in
      let digest amount =
        ok "bip143"
          (Sighash.bip143 ~tx ~input:i ~script_code:(Script.p2pkh ~hash160:program) ~amount
             ~hash_type:(Int32.of_int hash_type) ())
      in
      let verifies amount = Key.Ecdsa.verify ~key signature ~digest:(digest amount) in
      Some
        ( "p2wpkh",
          if not (verifies utxo.Sighash.value) then Bad
          else if verifies bumped.Sighash.value then Tamper_verified
          else Ok_ )
  | Script.Witness { version = 1; program }, (sig_ :: rest)
    when String.length program = 32
         && (rest = [] || (match rest with [ annex ] -> annex <> "" && annex.[0] = '\x50' | _ -> false)) ->
      let annex = match rest with [ a ] -> Some a | _ -> None in
      let flag, signature =
        if String.length sig_ = 65 then
          ok "flag" (Sighash.Flag.taproot_of_int (Char.code sig_.[64])), String.sub sig_ 0 64
        else Sighash.Flag.Default, sig_
      in
      let signature = ok "schnorr" (Key.Schnorr.of_octets signature) in
      let verifies utxos =
        let prevouts = ok "prevouts" (Sighash.Prevouts.of_list tx utxos) in
        let msg = ok "bip341" (Sighash.bip341 ?annex ~prevouts ~input:i ~flag ()) in
        Key.Schnorr.verify ~x_only:program signature ~msg
      in
      Some
        ( "p2tr-key",
          if not (verifies utxos) then Bad else if verifies with_bumped then Tamper_verified else Ok_ )
  | _ -> None

let verify () =
  try
    while true do
      match String.split_on_char ' ' (String.trim (input_line stdin)) with
      | raw :: rest ->
          let tx = ok "tx" (Tx.parse (unhex raw)) in
          let rec utxos = function
            | v :: spk :: more ->
                { Sighash.value = Amount.of_sat_exn (Int64.of_string v); script_pubkey = Script.of_octets (unhex spk) }
                :: utxos more
            | [] -> []
            | _ -> die "odd prevout list"
          in
          let utxos = utxos rest in
          if List.length utxos <> List.length tx.Tx.inputs then die "prevouts do not match inputs";
          List.iteri
            (fun i _ ->
              let where = Printf.sprintf "%s:%d" (Tx.txid_hex tx) i in
              match check_input tx utxos i with
              | Some (kind, Ok_) -> Printf.printf "ok %s %s\n" kind where
              | Some (kind, Tamper_verified) -> Printf.printf "tamper-verified %s %s\n" kind where
              | Some (kind, Bad) -> Printf.printf "bad %s %s\n" kind where
              | None -> Printf.printf "skip - %s\n" where)
            tx.Tx.inputs
      | [] -> ()
    done
  with End_of_file -> ()

let spend txid index value fee =
  let secret = ok "secret" (Key.Secret.of_octets (random 32)) in
  let public = Key.Secret.public secret in
  let hash160 = Key.Public.hash160 public in
  let address = ok "address" (Address.p2wpkh_of_key public) in
  let held = Amount.of_sat_exn value in
  let tx =
    {
      Tx.version = 2l;
      inputs =
        [ { Tx.In.previous_output = { Tx.Outpoint.txid = rev (unhex txid); index = Int32.of_int index };
            script_sig = Script.of_octets "";
            sequence = Tx.In.sequence_final;
            witness = [] } ];
      outputs = [ { Tx.Out.value = Amount.of_sat_exn (Int64.sub value fee); script_pubkey = Address.script_pubkey address } ];
      lock_time = 0l;
    }
  in
  (* Signed as the fresh key would sign its own P2WPKH output of this value:
     the script code is its own, so the witness is well formed and the node
     refuses it only because the output was never this key's. *)
  let digest =
    ok "bip143"
      (Sighash.bip143 ~tx ~input:0 ~script_code:(Script.p2pkh ~hash160) ~amount:held
         ~hash_type:(Sighash.Flag.to_consensus Sighash.Flag.all) ())
  in
  let signature = Key.Ecdsa.to_der (Key.Ecdsa.sign ~key:secret ~digest) ^ "\001" in
  let input = List.hd tx.Tx.inputs in
  let tx = { tx with Tx.inputs = [ { input with Tx.In.witness = [ signature; Key.Public.to_octets public ] } ] } in
  Printf.printf "address %s\n" (Address.to_string ~network:Network.Signet address);
  Printf.printf "txid %s\n" (Tx.txid_hex tx);
  Printf.printf "wtxid %s\n" (hex (rev (Tx.wtxid tx)));
  Printf.printf "wire %s\n" (hex (Tx.serialize tx))

let () =
  match Array.to_list Sys.argv with
  | [ _; "verify" ] -> verify ()
  | [ _; "spend"; txid; index; value; fee ] -> spend txid (int_of_string index) (Int64.of_string value) (Int64.of_string fee)
  | _ -> die "usage: signet_check verify | spend <txid> <index> <value> <fee>"
