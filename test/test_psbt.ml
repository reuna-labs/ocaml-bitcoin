open Bitcoin
open Testutil

let bip174_vectors () =
  let open Yojson.Safe.Util in
  let doc = json "psbt-test-vectors.json" in
  let valid = doc |> member "valid" |> to_list in
  let invalid = doc |> member "invalid" |> to_list in
  check_bool "valid vectors present" true (List.length valid >= 30);
  check_bool "invalid vectors present" true (List.length invalid >= 30);
  List.iter
    (fun c ->
      let name = c |> member "case" |> to_string in
      let b64 = c |> member "psbt" |> to_string in
      match Psbt.of_base64 b64 with
      | Error e ->
          Alcotest.failf "valid PSBT rejected (%s): %s" name
            (Bitcoin.Error.to_string (e :> Bitcoin.Error.t))
      | Ok p ->
          (* Re-serialising must reproduce the input byte for byte, which is
           the real test: it means every field was understood or preserved,
           and that key ordering is deterministic. *)
          check_str (Printf.sprintf "round trip: %s" name) b64 (Psbt.to_base64 p);
          (* The input and output map counts must match the unsigned tx. *)
          check_int
            (Printf.sprintf "input count: %s" name)
            (List.length p.Psbt.global.Psbt.Global.unsigned_tx.Tx.inputs)
            (List.length p.Psbt.inputs);
          check_int
            (Printf.sprintf "output count: %s" name)
            (List.length p.Psbt.global.Psbt.Global.unsigned_tx.Tx.outputs)
            (List.length p.Psbt.outputs))
    valid;
  List.iter
    (fun c ->
      let name = c |> member "case" |> to_string in
      let b64 = c |> member "psbt" |> to_string in
      check_bool
        (Printf.sprintf "rejected: %s" name)
        true
        (match Psbt.of_base64 b64 with Ok _ -> false | Error _ -> true))
    invalid

let unknown_fields_survive () =
  (* BIP174 requires a combiner to preserve pairs it does not understand, so
     that an older signer cannot silently drop what a newer one added. *)
  let open Yojson.Safe.Util in
  let b64 =
    json "psbt-test-vectors.json" |> member "valid" |> to_list |> List.hd |> member "psbt"
    |> to_string
  in
  let p = ok (Psbt.of_base64 b64) in
  let unknown_key = "\xfe\x01\x02" and unknown_value = "\xde\xad\xbe\xef" in
  let with_unknown =
    {
      p with
      Psbt.inputs =
        List.mapi
          (fun i (inp : Psbt.Input.t) ->
            if i = 0 then { inp with Psbt.Input.unknown = [ (unknown_key, unknown_value) ] }
            else inp)
          p.Psbt.inputs;
    }
  in
  let reparsed = ok (Psbt.of_base64 (Psbt.to_base64 with_unknown)) in
  check_bool "unknown field survives a round trip" true
    (List.assoc_opt unknown_key (List.hd reparsed.Psbt.inputs).Psbt.Input.unknown
    = Some unknown_value);
  (* And survives a combine with a PSBT that does not have it. *)
  let combined = ok (Psbt.Combiner.combine p reparsed) in
  check_bool "and survives a combine" true
    (List.assoc_opt unknown_key (List.hd combined.Psbt.inputs).Psbt.Input.unknown
    = Some unknown_value)

let psbt_v2_is_refused () =
  (* PSBT v2 restructures the format entirely. Detecting and refusing it is
     the honest outcome; mis-reading it as v0 would not be. *)
  let open Yojson.Safe.Util in
  let b64 =
    json "psbt-test-vectors.json" |> member "valid" |> to_list |> List.hd |> member "psbt"
    |> to_string
  in
  let p = ok (Psbt.of_base64 b64) in
  let v2 = { p with Psbt.global = { p.Psbt.global with Psbt.Global.version = Some 2l } } in
  check_bool "v2 is rejected" true
    (match Psbt.parse (Psbt.serialize v2) with Error `Unsupported_version -> true | _ -> false);
  (* An explicit version 0 is fine. *)
  let v0 = { p with Psbt.global = { p.Psbt.global with Psbt.Global.version = Some 0l } } in
  check_bool "explicit v0 is accepted" true
    (match Psbt.parse (Psbt.serialize v0) with Ok _ -> true | Error _ -> false)

let creator_rejects_signed () =
  let tx = ok (Tx.parse (hex Test_tx.block170_hex)) in
  (* block 170's transaction is signed, so it is not a valid basis. *)
  check_bool "the fixture is signed" true
    (List.exists (fun (i : Tx.In.t) -> not (Script.is_empty i.Tx.In.script_sig)) tx.Tx.inputs);
  is_error "creator refuses a signed transaction" (Psbt.Creator.create tx);
  let unsigned =
    {
      tx with
      Tx.inputs =
        List.map
          (fun (i : Tx.In.t) -> { i with Tx.In.script_sig = Script.of_octets ""; witness = [] })
          tx.Tx.inputs;
    }
  in
  let p = ok (Psbt.Creator.create unsigned) in
  check_int "one input map" 1 (List.length p.Psbt.inputs);
  check_int "two output maps" 2 (List.length p.Psbt.outputs);
  check_bool "round trips" true
    (match Psbt.parse (Psbt.serialize p) with Ok _ -> true | Error _ -> false)

let non_witness_utxo_is_checked () =
  (* The SegWit fee attack: a signer handed a prevout claiming a larger value
     than the real one can be induced to sign the difference away as fee.
     The txid check is what makes that impossible for the non-witness case. *)
  let real = ok (Tx.parse (hex Test_tx.block170_hex)) in
  let unsigned =
    {
      real with
      Tx.inputs =
        List.map
          (fun (i : Tx.In.t) -> { i with Tx.In.script_sig = Script.of_octets ""; witness = [] })
          real.Tx.inputs;
    }
  in
  let p = ok (Psbt.Creator.create unsigned) in
  (* A transaction that is not the one this input spends must be refused. *)
  is_error "wrong prevout transaction" (Psbt.Updater.set_non_witness_utxo p ~input:0 real);
  is_error "index out of range" (Psbt.Updater.set_non_witness_utxo p ~input:5 real);
  (* witness_utxo has no such check available -- there is no transaction to
     hash -- which is exactly why BIP341 commits to every input's amount. *)
  check_bool "witness_utxo is accepted as given" true
    (match
       Psbt.Updater.set_witness_utxo p ~input:0
         { Tx.Out.value = Amount.of_sat_exn 1L; script_pubkey = Script.of_octets "\x51" }
     with
    | Ok _ -> true
    | Error _ -> false)

let signer_requires_complete_prevouts () =
  let real = ok (Tx.parse (hex Test_tx.block170_hex)) in
  let unsigned =
    {
      real with
      Tx.inputs =
        List.map
          (fun (i : Tx.In.t) -> { i with Tx.In.script_sig = Script.of_octets ""; witness = [] })
          real.Tx.inputs;
    }
  in
  let p = ok (Psbt.Creator.create unsigned) in
  (* Taproot signing is impossible until every input carries a utxo. *)
  is_error "prevouts are incomplete" (Psbt.Signer.prevouts p);
  let filled =
    ok
      (Psbt.Updater.set_witness_utxo p ~input:0
         {
           Tx.Out.value = Amount.of_sat_exn 5_000_000_000L;
           script_pubkey = Script.of_octets "\x51";
         })
  in
  check_bool "and possible once it does" true
    (match Psbt.Signer.prevouts filled with Ok _ -> true | Error _ -> false)

let taproot_end_to_end () =
  (* Build, sign, finalize and extract a Taproot key-path spend, the whole
     workflow the library exists to support. *)
  let d =
    ok
      (Key.Secret.of_octets
         (hex "B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF"))
  in
  let internal_key = Key.Secret.public d in
  let si = ok (Taproot.spend_info ~internal_key ()) in
  let spk = Taproot.script_pubkey si in
  let prev_txid = Hash.sha256d "some funding transaction" in
  let unsigned =
    {
      Tx.version = 2l;
      inputs =
        [
          {
            Tx.In.previous_output = { Tx.Outpoint.txid = prev_txid; index = 0l };
            script_sig = Script.of_octets "";
            sequence = Tx.In.sequence_final;
            witness = [];
          };
        ];
      outputs =
        [
          {
            Tx.Out.value = Amount.of_sat_exn 99_000L;
            script_pubkey = Address.script_pubkey (Address.p2pkh_of_key internal_key);
          };
        ];
      lock_time = 0l;
    }
  in
  let p = ok (Psbt.Creator.create unsigned) in
  let p =
    ok
      (Psbt.Updater.set_witness_utxo p ~input:0
         { Tx.Out.value = Amount.of_sat_exn 100_000L; script_pubkey = spk })
  in
  let p = ok (Psbt.Updater.set_tap_internal_key p ~input:0 (Key.Public.x_only internal_key)) in
  (* Not finalized yet, so extraction must refuse. *)
  is_error "cannot extract before signing" (Psbt.Extractor.extract p);
  let signed = ok (Psbt.Signer.sign_taproot_key_path p ~input:0 d ()) in
  check_bool "a key-path signature was recorded" true
    ((List.hd signed.Psbt.inputs).Psbt.Input.tap_key_sig <> None);
  (* The signature must verify against the output key, which is the point. *)
  let digest = ok (Psbt.Signer.sighash signed ~input:0 ~spend:Sighash.P2tr_key) in
  let sg = Option.get (List.hd signed.Psbt.inputs).Psbt.Input.tap_key_sig in
  check_int "SIGHASH_DEFAULT means a 64-byte signature" 64 (String.length sg);
  check_bool "signature verifies against the output key" true
    (Key.Schnorr.verify ~x_only:(Taproot.output_key si) (ok (Key.Schnorr.of_octets sg)) ~msg:digest);
  (* Finalize and extract. *)
  let final = ok (Psbt.Finalizer.finalize signed) in
  check_bool "input is finalized" true (Psbt.Finalizer.is_finalized (List.hd final.Psbt.inputs));
  check_bool "signing fields were cleared" true
    ((List.hd final.Psbt.inputs).Psbt.Input.tap_key_sig = None);
  let tx = ok (Psbt.Extractor.extract final) in
  check_int "witness has one element" 1 (List.length (List.hd tx.Tx.inputs).Tx.In.witness);
  check_bool "extracted transaction has a witness" true (Tx.has_witness tx);
  check_bool "txid is unchanged by signing" true (String.equal (Tx.txid tx) (Tx.txid unsigned));
  check_bool "wtxid differs" false (String.equal (Tx.txid tx) (Tx.wtxid tx));
  (* And it round-trips through serialization. *)
  check_str "extracted tx re-serializes"
    (unhex (Tx.serialize tx))
    (unhex (Tx.serialize (ok (Tx.parse (Tx.serialize tx)))))

let combine_requires_the_same_tx () =
  let open Yojson.Safe.Util in
  let vs = json "psbt-test-vectors.json" |> member "valid" |> to_list in
  let a = ok (Psbt.of_base64 (List.nth vs 0 |> member "psbt" |> to_string)) in
  let b = ok (Psbt.of_base64 (List.nth vs 1 |> member "psbt" |> to_string)) in
  check_bool "the two vectors differ" false
    (String.equal
       (Tx.txid a.Psbt.global.Psbt.Global.unsigned_tx)
       (Tx.txid b.Psbt.global.Psbt.Global.unsigned_tx));
  is_error "combining unrelated PSBTs" (Psbt.Combiner.combine a b);
  check_bool "combining a PSBT with itself is a no-op" true
    (match Psbt.Combiner.combine a a with
    | Ok c -> String.equal (Psbt.serialize c) (Psbt.serialize a)
    | Error _ -> false);
  is_error "combine_all of nothing" (Psbt.Combiner.combine_all [])

let suite =
  [
    ( "psbt",
      [
        Alcotest.test_case "BIP174 and BIP371 vectors" `Quick bip174_vectors;
        Alcotest.test_case "unknown fields survive" `Quick unknown_fields_survive;
        Alcotest.test_case "v2 is refused" `Quick psbt_v2_is_refused;
        Alcotest.test_case "creator rejects a signed transaction" `Quick creator_rejects_signed;
        Alcotest.test_case "non-witness utxo is checked" `Quick non_witness_utxo_is_checked;
        Alcotest.test_case "signer requires complete prevouts" `Quick
          signer_requires_complete_prevouts;
        Alcotest.test_case "combine requires the same transaction" `Quick
          combine_requires_the_same_tx;
        Alcotest.test_case "taproot end to end" `Quick taproot_end_to_end;
      ] );
  ]
