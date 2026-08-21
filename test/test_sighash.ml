open Bitcoin
open Testutil

let sat n = Amount.of_sat_exn n

let flags_roundtrip () =
  let open Sighash.Flag in
  List.iter
    (fun base ->
      List.iter
        (fun acp ->
          let f = { base; anyone_can_pay = acp } in
          check_bool "round trip" true (of_int (to_int f) = Ok f))
        [ true; false ])
    [ All; None_; Single ];
  check_int "SIGHASH_ALL" 0x01 (to_int all);
  check_int "SIGHASH_NONE" 0x02 (to_int { base = None_; anyone_can_pay = false });
  check_int "SIGHASH_SINGLE" 0x03 (to_int { base = Single; anyone_can_pay = false });
  check_int "ALL|ANYONECANPAY" 0x81 (to_int { base = All; anyone_can_pay = true });
  is_error "zero is not a legacy flag" (of_int 0);
  is_error "four is not a legacy flag" (of_int 4);
  (* BIP341 keeps SIGHASH_DEFAULT distinct from an explicit SIGHASH_ALL: the
     first is omitted from the signature, the second is appended. *)
  check_int "taproot default" 0x00 (taproot_to_int Default);
  check_int "taproot explicit all" 0x01 (taproot_to_int (Explicit all));
  check_bool "0x00 decodes to Default" true (taproot_of_int 0 = Ok Default);
  check_bool "0x01 decodes to Explicit" true (taproot_of_int 1 = Ok (Explicit all))

(* --------------------------------------------------- Core's sighash.json *)

let core_sighash () =
  (* 500 random (tx, script, index, hashType) tuples with the digest Core
     computes, including the SIGHASH_SINGLE bug and odd hashType bytes. *)
  match json "core-sighash.json" with
  | `List rows ->
      let n = ref 0 and single = ref 0 and single_bug = ref 0 in
      List.iter
        (function
          | `List [ `String raw; `String script; `Int index; `Int hash_type; `String expected ] -> (
              match Tx.parse (hex raw) with
              | Error _ -> ()
              | Ok tx ->
                  incr n;
                  let script_code = Script.of_octets (hex script) in
                  (* The fixture's hashType is a full 32-bit value, often
               non-standard; it is hashed verbatim, so it is passed through
               as-is rather than normalised. *)
                  let ht = Int32.of_int hash_type in
                  let flag = Sighash.Flag.of_consensus ht in
                  if flag.Sighash.Flag.base = Sighash.Flag.Single then (
                    incr single;
                    if index >= List.length tx.Tx.outputs then incr single_bug);
                  let got = ok (Sighash.legacy ~tx ~input:index ~script_code ~hash_type:ht) in
                  (* The fixture prints the digest in reversed display order. *)
                  let reversed = String.init 32 (fun i -> got.[31 - i]) in
                  check_hex (Printf.sprintf "row %d" !n) (String.lowercase_ascii expected) reversed)
          | _ -> ())
        rows;
      check_int "every row parsed and matched" 500 !n;
      (* The fixture has 17 SIGHASH_SINGLE rows but none whose index runs past
       the outputs, so it does not reach the bug at all. That is covered
       separately by [single_bug_directly]; asserting it here would be
       claiming coverage this file does not provide. *)
      check_int "SIGHASH_SINGLE rows" 17 !single;
      check_int "rows reaching the SIGHASH_SINGLE bug" 0 !single_bug
  | _ -> Alcotest.fail "sighash.json: unexpected shape"

let single_bug_directly () =
  (* One input, no outputs, SIGHASH_SINGLE: the digest is uint256(1). Core
     returns this rather than failing, and outputs were really spent with
     signatures over it, so it cannot be "fixed". *)
  let tx =
    {
      Tx.version = 1l;
      inputs =
        [
          {
            Tx.In.previous_output = { Tx.Outpoint.txid = String.make 32 '\001'; index = 0l };
            script_sig = Script.of_octets "";
            sequence = Tx.In.sequence_final;
            witness = [];
          };
        ];
      outputs = [];
      lock_time = 0l;
    }
  in
  let flag = { Sighash.Flag.base = Sighash.Flag.Single; anyone_can_pay = false } in
  let got =
    ok
      (Sighash.legacy ~tx ~input:0 ~script_code:(Script.of_octets "\x51")
         ~hash_type:(Sighash.Flag.to_consensus flag))
  in
  check_hex "uint256(1)" "0100000000000000000000000000000000000000000000000000000000000000" got;
  (* BIP341 removed the bug: the same shape is an error there. *)
  let prevouts =
    ok
      (Sighash.Prevouts.of_list tx
         [ { Sighash.value = sat 1000L; script_pubkey = Script.of_octets "\x51" } ])
  in
  is_error "BIP341 rejects out-of-range SINGLE"
    (Sighash.bip341 ~prevouts ~input:0 ~flag:(Sighash.Flag.Explicit flag) ())

let index_bounds () =
  let tx = ok (Tx.parse (hex Test_tx.block170_hex)) in
  let ht = Sighash.Flag.to_consensus Sighash.Flag.all in
  is_error "negative index"
    (Sighash.legacy ~tx ~input:(-1) ~script_code:(Script.of_octets "") ~hash_type:ht);
  is_error "index past the end"
    (Sighash.legacy ~tx ~input:5 ~script_code:(Script.of_octets "") ~hash_type:ht);
  is_error "bip143 index past the end"
    (Sighash.bip143 ~tx ~input:5 ~script_code:(Script.of_octets "") ~amount:(sat 1L) ~hash_type:ht
       ())

(* ------------------------------------------------------------ Prevouts *)

let prevouts_enforce_completeness () =
  let tx = ok (Tx.parse (hex Test_tx.block170_hex)) in
  let one = { Sighash.value = sat 5_000_000_000L; script_pubkey = Script.of_octets "\x51" } in
  check_int "the transaction has one input" 1 (List.length tx.Tx.inputs);
  check_bool "a matching list is accepted" true
    (match Sighash.Prevouts.of_list tx [ one ] with Ok _ -> true | Error _ -> false);
  (* This is the property the type exists for: BIP341 commits to every
     input's amount and scriptPubKey, so a partial list must not be
     constructible. *)
  is_error "empty list" (Sighash.Prevouts.of_list tx []);
  is_error "too many" (Sighash.Prevouts.of_list tx [ one; one ]);
  let p = ok (Sighash.Prevouts.of_list tx [ one ]) in
  check_int "length" 1 (Sighash.Prevouts.length p);
  check_bool "carries its transaction" true
    (String.equal (Tx.txid (Sighash.Prevouts.tx p)) (Tx.txid tx));
  check_bool "get in range" true (Sighash.Prevouts.get p 0 <> None);
  check_bool "get out of range" true (Sighash.Prevouts.get p 1 = None)

(* -------------------------------------------------- BIP341 sigMsg vectors *)

let bip341_sighash () =
  (* The keyPathSpending vector supplies a real transaction, the utxos it
     spends, and the digest expected for each input. This exercises
     SIGHASH_DEFAULT, ALL, NONE, SINGLE and the ANYONECANPAY variants
     together, over one transaction with nine inputs. *)
  let open Yojson.Safe.Util in
  let case =
    json "bip341-wallet-test-vectors.json" |> member "keyPathSpending" |> to_list |> List.hd
  in
  let given = member "given" case in
  let tx = ok (Tx.parse (hex (given |> member "rawUnsignedTx" |> to_string))) in
  let utxos =
    given |> member "utxosSpent" |> to_list
    |> List.map (fun u ->
           {
             Sighash.value = Amount.of_sat_exn (Int64.of_int (u |> member "amountSats" |> to_int));
             script_pubkey = Script.of_octets (hex (u |> member "scriptPubKey" |> to_string));
           })
  in
  check_int "one utxo per input" (List.length tx.Tx.inputs) (List.length utxos);
  let prevouts = ok (Sighash.Prevouts.of_list tx utxos) in
  let cache = Sighash.Cache.make prevouts in
  let checked = ref 0 in
  List.iter
    (fun inp ->
      let g = member "given" inp and inter = member "intermediary" inp in
      let index = g |> member "txinIndex" |> to_int in
      let hash_type = g |> member "hashType" |> to_int in
      let flag = ok (Sighash.Flag.taproot_of_int hash_type) in
      let got = ok (Sighash.bip341 ~cache ~prevouts ~input:index ~flag ()) in
      check_hex
        (Printf.sprintf "input %d sigHash (hashType %d)" index hash_type)
        (inter |> member "sigHash" |> to_string)
        got;
      (* The same digest must come out without the cache. *)
      let uncached = ok (Sighash.bip341 ~prevouts ~input:index ~flag ()) in
      check_hex (Printf.sprintf "input %d uncached" index) (unhex got) uncached;
      (* And through the dispatching helper. *)
      let via_spend =
        ok (Sighash.of_prevouts ~cache ~prevouts ~input:index ~spend:Sighash.P2tr_key ~flag ())
      in
      check_hex (Printf.sprintf "input %d via of_prevouts" index) (unhex got) via_spend;
      incr checked)
    (member "inputSpending" case |> to_list);
  check_int "inputs exercised" 7 !checked;
  (* Every sighash type in the vector should not be the same digest. *)
  check_bool "digests differ across inputs" true
    (let ds =
       List.map
         (fun inp ->
           let g = member "given" inp in
           ok
             (Sighash.bip341 ~cache ~prevouts
                ~input:(g |> member "txinIndex" |> to_int)
                ~flag:(ok (Sighash.Flag.taproot_of_int (g |> member "hashType" |> to_int)))
                ()))
         (member "inputSpending" case |> to_list)
     in
     List.length (List.sort_uniq compare ds) = List.length ds)

let taproot_default_differs_from_all () =
  (* SIGHASH_DEFAULT and an explicit SIGHASH_ALL must not produce the same
     digest, or the distinction BIP341 draws would be meaningless. *)
  let open Yojson.Safe.Util in
  let case =
    json "bip341-wallet-test-vectors.json" |> member "keyPathSpending" |> to_list |> List.hd
  in
  let given = member "given" case in
  let tx = ok (Tx.parse (hex (given |> member "rawUnsignedTx" |> to_string))) in
  let utxos =
    given |> member "utxosSpent" |> to_list
    |> List.map (fun u ->
           {
             Sighash.value = Amount.of_sat_exn (Int64.of_int (u |> member "amountSats" |> to_int));
             script_pubkey = Script.of_octets (hex (u |> member "scriptPubKey" |> to_string));
           })
  in
  let prevouts = ok (Sighash.Prevouts.of_list tx utxos) in
  let d0 = ok (Sighash.bip341 ~prevouts ~input:0 ~flag:Sighash.Flag.Default ()) in
  let d1 =
    ok (Sighash.bip341 ~prevouts ~input:0 ~flag:(Sighash.Flag.Explicit Sighash.Flag.all) ())
  in
  check_bool "default differs from explicit all" false (String.equal d0 d1);
  (* An annex changes the digest, and a script path differs from a key path. *)
  let with_annex =
    ok (Sighash.bip341 ~prevouts ~input:0 ~annex:"\x50\x01" ~flag:Sighash.Flag.Default ())
  in
  check_bool "annex changes the digest" false (String.equal d0 with_annex);
  let script_path =
    ok
      (Sighash.bip341 ~prevouts ~input:0
         ~ext:(`Script_path (String.make 32 '\007', 0xffffffffl))
         ~flag:Sighash.Flag.Default ())
  in
  check_bool "script path differs from key path" false (String.equal d0 script_path)

let cache_is_transparent () =
  (* The cache is a performance device and must never change a digest. *)
  let tx = ok (Tx.parse (hex Test_tx.block170_hex)) in
  let u = { Sighash.value = sat 5_000_000_000L; script_pubkey = Script.of_octets "\x51" } in
  let prevouts = ok (Sighash.Prevouts.of_list tx [ u ]) in
  let cache = Sighash.Cache.make prevouts in
  List.iter
    (fun flag ->
      let a = ok (Sighash.bip341 ~cache ~prevouts ~input:0 ~flag ()) in
      let b = ok (Sighash.bip341 ~prevouts ~input:0 ~flag ()) in
      check_hex "bip341 cache is transparent" (unhex a) b)
    [
      Sighash.Flag.Default;
      Sighash.Flag.Explicit Sighash.Flag.all;
      Sighash.Flag.Explicit { Sighash.Flag.base = Sighash.Flag.All; anyone_can_pay = true };
    ];
  List.iter
    (fun flag ->
      let hash_type = Sighash.Flag.to_consensus flag in
      let a =
        ok
          (Sighash.bip143 ~cache ~tx ~input:0 ~script_code:u.script_pubkey ~amount:u.value
             ~hash_type ())
      in
      let b =
        ok (Sighash.bip143 ~tx ~input:0 ~script_code:u.script_pubkey ~amount:u.value ~hash_type ())
      in
      check_hex "bip143 cache is transparent" (unhex a) b)
    [
      Sighash.Flag.all;
      { Sighash.Flag.base = Sighash.Flag.None_; anyone_can_pay = false };
      { Sighash.Flag.base = Sighash.Flag.All; anyone_can_pay = true };
    ]

let bip143_commits_to_amount () =
  (* The property BIP143 was introduced for: the digest covers the value of
     the input being signed, so a lying prevout amount cannot go unnoticed. *)
  let tx = ok (Tx.parse (hex Test_tx.block170_hex)) in
  let script_code = Script.p2pkh ~hash160:(String.make 20 '\003') in
  let ht = Sighash.Flag.to_consensus Sighash.Flag.all in
  let d a = ok (Sighash.bip143 ~tx ~input:0 ~script_code ~amount:(sat a) ~hash_type:ht ()) in
  check_bool "different amounts give different digests" false (String.equal (d 1000L) (d 1001L));
  (* Legacy does not commit to the amount at all -- there is no amount to
     pass -- which is exactly the gap BIP143 closed. *)
  let l = ok (Sighash.legacy ~tx ~input:0 ~script_code ~hash_type:ht) in
  check_bool "legacy digest differs from bip143" false (String.equal l (d 1000L))

let suite =
  [
    ("sighash flags", [ Alcotest.test_case "encoding" `Quick flags_roundtrip ]);
    ( "sighash legacy",
      [
        Alcotest.test_case "Bitcoin Core sighash.json" `Quick core_sighash;
        Alcotest.test_case "SIGHASH_SINGLE bug" `Quick single_bug_directly;
        Alcotest.test_case "index bounds" `Quick index_bounds;
      ] );
    ( "sighash prevouts",
      [ Alcotest.test_case "completeness is enforced" `Quick prevouts_enforce_completeness ] );
    ( "sighash taproot",
      [
        Alcotest.test_case "BIP341 digests" `Quick bip341_sighash;
        Alcotest.test_case "default differs from explicit all" `Quick
          taproot_default_differs_from_all;
        Alcotest.test_case "cache is transparent" `Quick cache_is_transparent;
        Alcotest.test_case "BIP143 commits to the amount" `Quick bip143_commits_to_amount;
      ] );
  ]
