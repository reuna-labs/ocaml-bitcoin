open Bitcoin
open Testutil

(* ---------------------------------------------------------------- Amount *)

let amount_range () =
  is_error "negative" (Amount.of_sat (-1L));
  is_error "above the supply" (Amount.of_sat 2_100_000_000_000_001L);
  check_bool "zero" true (Amount.of_sat 0L <> Error `Invalid_range);
  check_bool "the whole supply" true (Amount.of_sat 2_100_000_000_000_000L <> Error `Invalid_range);
  check_bool "max_money is the supply" true
    (Int64.equal (Amount.to_sat Amount.max_money) 2_100_000_000_000_000L)

let amount_arithmetic () =
  let sat n = Amount.of_sat_exn n in
  check_bool "add" true (Amount.add (sat 1L) (sat 2L) = Ok (sat 3L));
  check_bool "sub" true (Amount.sub (sat 3L) (sat 1L) = Ok (sat 2L));
  is_error "sub below zero" (Amount.sub (sat 1L) (sat 2L));
  check_bool "mul" true (Amount.mul (sat 7L) 3L = Ok (sat 21L));
  check_bool "mul by zero" true (Amount.mul (sat 7L) 0L = Ok Amount.zero);
  (* The case this type exists for: a sum that would wrap int64 must be
     refused, not silently turned into a small number. *)
  is_error "add overflows the supply" (Amount.add Amount.max_money (sat 1L));
  is_error "mul overflows the supply" (Amount.mul Amount.max_money 2L);
  is_error "sum overflows" (Amount.sum [ Amount.max_money; Amount.max_money ]);
  check_bool "sum" true (Amount.sum [ sat 1L; sat 2L; sat 3L ] = Ok (sat 6L));
  check_bool "sum of nothing is zero" true (Amount.sum [] = Ok Amount.zero);
  check_bool "diff positive" true (Amount.diff (sat 5L) (sat 3L) = `Pos (sat 2L));
  check_bool "diff negative" true (Amount.diff (sat 3L) (sat 5L) = `Neg (sat 2L));
  check_bool "diff zero" true (Amount.diff (sat 3L) (sat 3L) = `Zero)

let amount_btc_strings () =
  let p s = Amount.to_sat (ok (Amount.of_btc_string s)) in
  check_bool "1 BTC" true (Int64.equal (p "1") 100_000_000L);
  check_bool "one satoshi" true (Int64.equal (p "0.00000001") 1L);
  check_bool "fractional" true (Int64.equal (p "0.00012345") 12_345L);
  check_bool "with whole part" true (Int64.equal (p "1.5") 150_000_000L);
  check_bool "zero" true (Int64.equal (p "0") 0L);
  (* Rejected rather than rounded: a rounded amount is a wrong amount. *)
  is_error "nine decimal places" (Amount.of_btc_string "0.000000001");
  is_error "not a number" (Amount.of_btc_string "abc");
  is_error "empty" (Amount.of_btc_string "");
  is_error "negative" (Amount.of_btc_string "-1");
  List.iter
    (fun s ->
      let a = ok (Amount.of_btc_string s) in
      check_str ("round trip " ^ s) s (Amount.to_btc_string a))
    [ "0"; "1"; "1.5"; "0.00000001"; "0.00012345"; "21000000" ]

(* ------------------------------------------------------------ Serialization *)

(* A real mainnet transaction: the first ever bitcoin transfer, from block
   170, Satoshi to Hal Finney. Legacy, one input, two outputs. *)
let block170_hex =
  "0100000001c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd3704000000004847304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd410220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d0901ffffffff0200ca9a3b00000000434104ae1a62fe09c5f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414e7aab37397f554a7df5f142c21c1b7303b8a0626f1baded5c72a704f7e6cd84cac00286bee0000000043410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac00000000"

let known_transaction () =
  let tx = ok (Tx.parse (hex block170_hex)) in
  check_int "version" 1 (Int32.to_int tx.Tx.version);
  check_int "inputs" 1 (List.length tx.Tx.inputs);
  check_int "outputs" 2 (List.length tx.Tx.outputs);
  check_int "lock_time" 0 (Int32.to_int tx.Tx.lock_time);
  check_str "txid" "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16"
    (Tx.txid_hex tx);
  check_bool "no witness" false (Tx.has_witness tx);
  check_bool "txid = wtxid without witness" true (String.equal (Tx.txid tx) (Tx.wtxid tx));
  check_bool "not a coinbase" false (Tx.is_coinbase tx);
  check_bool "not RBF" false (Tx.is_rbf_signalling tx);
  (* 50 BTC total, split 10 and 40. *)
  check_str "total output" "50" (Amount.to_btc_string (ok (Tx.total_output tx)));
  check_str "first output" "10" (Amount.to_btc_string (List.nth tx.Tx.outputs 0).Tx.Out.value);
  (* Re-serialization must be byte-identical. *)
  check_str "round trip" block170_hex (unhex (Tx.serialize tx));
  (* Legacy transaction, so weight is just four times the size. *)
  check_int "weight" (Tx.base_size tx * 4) (Tx.weight tx);
  check_int "vsize" (Tx.base_size tx) (Tx.vsize tx)

let core_tx_valid () =
  (* Every transaction Core considers valid must parse and re-serialize to
     exactly the same bytes. This is the strongest single statement the
     serializer can make, and it covers segwit and legacy alike. *)
  match json "core-tx_valid.json" with
  | `List rows ->
      let n = ref 0 and witnessed = ref 0 in
      List.iter
        (function
          | `List [ `List _; `String raw; `String _ ] ->
              incr n;
              let tx = ok (Tx.parse (hex raw)) in
              check_str
                (Printf.sprintf "re-serializes (%s...)" (String.sub raw 0 16))
                (String.lowercase_ascii raw)
                (unhex (Tx.serialize tx));
              if Tx.has_witness tx then (
                incr witnessed;
                (* With witnesses present the two identifiers must differ, and
               the legacy encoding must be a strict prefix-free shorter one. *)
                check_bool "txid differs from wtxid" false (String.equal (Tx.txid tx) (Tx.wtxid tx));
                check_bool "base size is smaller" true (Tx.base_size tx < Tx.total_size tx);
                check_bool "vsize is below total size" true (Tx.vsize tx < Tx.total_size tx))
          | _ -> ())
        rows;
      check_bool "transactions exercised" true (!n > 100);
      check_bool "segwit transactions exercised" true (!witnessed > 5)
  | _ -> Alcotest.fail "tx_valid: unexpected shape"

let core_tx_invalid_parsing () =
  (* Most tx_invalid entries fail at script level and parse perfectly well,
     so a blanket "must not parse" assertion would be wrong. Assert only
     what is true of every row: whatever parses must re-serialize exactly. *)
  match json "core-tx_invalid.json" with
  | `List rows ->
      let parsed = ref 0 and rejected = ref 0 in
      List.iter
        (function
          | `List [ `List _; `String raw; `String _ ] -> (
              match Tx.parse (hex raw) with
              | Ok tx ->
                  incr parsed;
                  check_str "re-serializes" (String.lowercase_ascii raw) (unhex (Tx.serialize tx))
              | Error _ -> incr rejected)
          | _ -> ())
        rows;
      check_bool "rows exercised" true (!parsed + !rejected > 50)
  | _ -> Alcotest.fail "tx_invalid: unexpected shape"

let segwit_encoding_rules () =
  let tx = ok (Tx.parse (hex block170_hex)) in
  (* Asking for the witness encoding of a transaction with no witness data
     yields the legacy bytes: the marker is written only when there is
     something to carry, which is what keeps the encoding canonical. *)
  check_str "no empty witness section"
    (unhex (Tx.serialize ~witness:false tx))
    (unhex (Tx.serialize ~witness:true tx));
  (* A witness serialization that carries no witness data is rejected, for
     the same reason. *)
  let forged =
    let w = Codec.W.create () in
    Codec.W.u32 w tx.Tx.version;
    Codec.W.u8 w 0x00;
    Codec.W.u8 w 0x01;
    Codec.W.vector w Tx.In.write tx.Tx.inputs;
    Codec.W.vector w Tx.Out.write tx.Tx.outputs;
    List.iter (fun _ -> Codec.W.vector w Codec.W.varstr []) tx.Tx.inputs;
    Codec.W.u32 w tx.Tx.lock_time;
    Codec.W.contents w
  in
  is_error "superfluous witness record" (Tx.parse forged);
  (* A zero flag byte is not a valid marker either. *)
  let bad_flag = String.mapi (fun i c -> if i = 5 then '\000' else c) forged in
  is_error "zero witness flag" (Tx.parse bad_flag);
  is_error "truncated" (Tx.parse (String.sub block170_hex 0 10));
  is_error "trailing bytes" (Tx.parse (hex block170_hex ^ "\000"))

let sequence_and_rbf () =
  let tx = ok (Tx.parse (hex block170_hex)) in
  let with_seq s =
    { tx with Tx.inputs = List.map (fun i -> { i with Tx.In.sequence = s }) tx.Tx.inputs }
  in
  check_bool "final is not RBF" false (Tx.is_rbf_signalling (with_seq Tx.In.sequence_final));
  check_bool "0xfffffffe is not RBF" false (Tx.is_rbf_signalling (with_seq 0xfffffffel));
  check_bool "0xfffffffd signals RBF" true (Tx.is_rbf_signalling (with_seq Tx.In.sequence_rbf));
  check_bool "zero signals RBF" true (Tx.is_rbf_signalling (with_seq 0l))

let fee_calculation () =
  let tx = ok (Tx.parse (hex block170_hex)) in
  let sat n = Amount.of_sat_exn n in
  (* Outputs total 50 BTC; claim a 50.001 BTC input. *)
  let inputs = [ sat 5_000_100_000L ] in
  check_str "fee" "0.001" (Amount.to_btc_string (ok (Tx.fee tx ~inputs)));
  is_error "outputs exceed inputs" (Tx.fee tx ~inputs:[ sat 1L ]);
  (* A count mismatch means the caller has the wrong prevouts; refusing is
     better than quietly computing a fee from the wrong set. *)
  is_error "too few input values" (Tx.fee tx ~inputs:[]);
  is_error "too many input values" (Tx.fee tx ~inputs:[ sat 1L; sat 2L ])

let outpoint_display () =
  let tx = ok (Tx.parse (hex block170_hex)) in
  let op = (List.hd tx.Tx.inputs).Tx.In.previous_output in
  check_str "display order" "0437cd7f8525ceed2324359c2d0ba26006d92d856a9c20fa0241106ee5a597c9:0"
    (Tx.Outpoint.to_string op);
  check_bool "not null" false (Tx.Outpoint.is_null op);
  check_bool "the null outpoint is null" true (Tx.Outpoint.is_null Tx.Outpoint.null)

(* ------------------------------------------------------------ properties *)

let prop_tx_roundtrip =
  QCheck2.Test.make ~count:2000 ~name:"tx: whatever parses re-serializes identically"
    QCheck2.Gen.(string_size (int_bound 200))
    (fun s -> match Tx.parse s with Error _ -> true | Ok tx -> String.equal (Tx.serialize tx) s)

let prop_amount_roundtrip =
  QCheck2.Test.make ~count:5000 ~name:"amount: BTC string round trip"
    QCheck2.Gen.(map Int64.of_int (int_range 0 max_int))
    (fun v ->
      let v = Int64.rem v 2_100_000_000_000_001L in
      match Amount.of_sat v with
      | Error _ -> false
      | Ok a -> Amount.of_btc_string (Amount.to_btc_string a) = Ok a)

let prop_amount_never_wraps =
  QCheck2.Test.make ~count:5000 ~name:"amount: arithmetic never produces an out-of-range value"
    QCheck2.Gen.(pair (int_range 0 max_int) (int_range 0 max_int))
    (fun (x, y) ->
      let cap v = Int64.rem (Int64.of_int v) 2_100_000_000_000_001L in
      match (Amount.of_sat (cap x), Amount.of_sat (cap y)) with
      | Ok a, Ok b ->
          let ok_or_error = function
            | Ok v -> Amount.compare v Amount.zero >= 0 && Amount.compare v Amount.max_money <= 0
            | Error _ -> true
          in
          ok_or_error (Amount.add a b)
          && ok_or_error (Amount.sub a b)
          && ok_or_error (Amount.mul a 3L)
      | _ -> false)

let suite =
  [
    ( "amount",
      [
        Alcotest.test_case "range" `Quick amount_range;
        Alcotest.test_case "checked arithmetic" `Quick amount_arithmetic;
        Alcotest.test_case "BTC strings" `Quick amount_btc_strings;
      ] );
    ( "tx",
      [
        Alcotest.test_case "a known mainnet transaction" `Quick known_transaction;
        Alcotest.test_case "Bitcoin Core tx_valid" `Quick core_tx_valid;
        Alcotest.test_case "Bitcoin Core tx_invalid" `Quick core_tx_invalid_parsing;
        Alcotest.test_case "segwit encoding rules" `Quick segwit_encoding_rules;
        Alcotest.test_case "sequence and RBF" `Quick sequence_and_rbf;
        Alcotest.test_case "fee" `Quick fee_calculation;
        Alcotest.test_case "outpoint display" `Quick outpoint_display;
      ] );
    ( "tx properties",
      List.map QCheck_alcotest.to_alcotest
        [ prop_tx_roundtrip; prop_amount_roundtrip; prop_amount_never_wraps ] );
  ]
