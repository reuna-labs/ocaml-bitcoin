open Bitcoin
open Testutil

(* The genesis block header, and block 1's, as they appear on chain. *)
let genesis_header_hex =
  "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c"

let block1_header_hex =
  "010000006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000982051fd1e4ba744bbbe680e1fee14677ba1a3c3540bf7b1cdb606e857233e0e61bc6649ffff001d01e36299"

let genesis_header () =
  let h = ok (Block.Header.parse (hex genesis_header_hex)) in
  check_str "hash" "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
    (Block.Header.hash_hex h);
  check_int "version" 1 (Int32.to_int h.Block.Header.version);
  check_int "time" 1231006505 (Int32.to_int h.Block.Header.time);
  check_int "nonce" 2083236893 (Int32.to_int h.Block.Header.nonce);
  check_hex "merkle root is the single coinbase txid"
    "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a" h.Block.Header.merkle_root;
  check_hex "no previous block"
    (String.concat "" (List.init 32 (fun _ -> "00")))
    h.Block.Header.prev_block;
  check_str "re-serializes" genesis_header_hex (unhex (Block.Header.serialize h));
  check_int "header size" 80 (String.length (Block.Header.serialize h));
  (* The proof of work: the hash is below the target the header claims. *)
  check_bool "meets its target" true (Block.Header.meets_target h);
  check_bool "difficulty is 1" true (abs_float (Block.Header.difficulty h -. 1.0) < 1e-9)

let block1_header () =
  let h = ok (Block.Header.parse (hex block1_header_hex)) in
  check_str "hash" "00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048"
    (Block.Header.hash_hex h);
  (* Its prev_block is the genesis hash, in internal byte order. *)
  let genesis = ok (Block.Header.parse (hex genesis_header_hex)) in
  check_hex "links to genesis" (unhex (Block.Header.hash genesis)) h.Block.Header.prev_block;
  check_bool "meets its target" true (Block.Header.meets_target h)

let proof_of_work_is_checked () =
  let h = ok (Block.Header.parse (hex genesis_header_hex)) in
  (* Change the nonce and the hash almost certainly stops meeting the target. *)
  let broken = { h with Block.Header.nonce = Int32.add h.Block.Header.nonce 1l } in
  check_bool "a different nonce does not" false (Block.Header.meets_target broken);
  (* A target of zero is the degenerate compact encoding; nothing meets it. *)
  check_bool "zero target" false (Block.Header.meets_target { h with Block.Header.bits = 0l })

let compact_targets () =
  (* Difficulty 1, the value in the genesis header. *)
  check_hex "0x1d00ffff" "00000000ffff0000000000000000000000000000000000000000000000000000"
    (Block.target_of_bits 0x1d00ffffl);
  check_bool "round trips" true
    (Int32.equal (Block.bits_of_target (Block.target_of_bits 0x1d00ffffl)) 0x1d00ffffl);
  (* Small exponents shift the mantissa down rather than up. *)
  check_hex "0x01003456"
    (String.concat "" (List.init 32 (fun _ -> "00")))
    (Block.target_of_bits 0x01003456l);
  check_hex "0x02008000" "0000000000000000000000000000000000000000000000000000000000000080"
    (Block.target_of_bits 0x02008000l);
  check_hex "0x04123456" "0000000000000000000000000000000000000000000000000000000012345600"
    (Block.target_of_bits 0x04123456l);
  (* A negative mantissa is not a target any header can carry. *)
  check_hex "negative mantissa"
    (String.concat "" (List.init 32 (fun _ -> "00")))
    (Block.target_of_bits 0x04923456l);
  List.iter
    (fun b ->
      check_bool
        (Printf.sprintf "round trip %08lx" b)
        true
        (Int32.equal (Block.bits_of_target (Block.target_of_bits b)) b))
    [ 0x1d00ffffl; 0x1b0404cbl; 0x170d63b0l; 0x04123456l; 0x02008000l ]

let merkle_roots () =
  let h k = Hash.sha256d (string_of_int k) in
  (* A single transaction is its own root. *)
  check_hex "one leaf" (unhex (h 1)) (Block.merkle_root [ h 1 ]);
  (* Two leaves hash together. *)
  check_hex "two leaves" (unhex (Hash.sha256d (h 1 ^ h 2))) (Block.merkle_root [ h 1; h 2 ]);
  (* An odd level duplicates its last hash -- consensus behaviour, not an
     oversight, which is why three leaves and "three plus a repeat of the
     third" give the same root. *)
  check_hex "three leaves duplicate the last"
    (unhex (Block.merkle_root [ h 1; h 2; h 3 ]))
    (Block.merkle_root [ h 1; h 2; h 3; h 3 ]);
  (* And that is exactly the CVE-2012-2459 shape. *)
  check_bool "duplication is detected" true (Block.is_merkle_mutation [ h 1; h 2; h 3; h 3 ]);
  check_bool "an honest list is not" false (Block.is_merkle_mutation [ h 1; h 2; h 3; h 4 ]);
  check_bool "nor is an odd one" false (Block.is_merkle_mutation [ h 1; h 2; h 3 ])

let genesis_block () =
  (* The whole genesis block, header plus its single coinbase. *)
  let raw =
    "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c0101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000"
  in
  let b = ok (Block.parse (hex raw)) in
  check_int "one transaction" 1 (List.length b.Block.transactions);
  check_str "block hash" "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
    (Block.Header.hash_hex b.Block.header);
  check_bool "merkle root matches its transactions" true (Block.has_valid_merkle_root b);
  check_bool "first transaction is a coinbase" true (Block.coinbase b <> None);
  check_str "re-serializes" raw (unhex (Block.serialize b));
  (* The headline in the coinbase scriptSig. *)
  let cb = Option.get (Block.coinbase b) in
  let script = Script.to_octets (List.hd cb.Tx.inputs).Tx.In.script_sig in
  let contains hay needle =
    let n = String.length needle and m = String.length hay in
    let rec go i = i + n <= m && (String.sub hay i n = needle || go (i + 1)) in
    go 0
  in
  check_bool "carries the Times headline" true
    (contains script "Chancellor on brink of second bailout for banks");
  check_bool "no witness" false (Tx.has_witness cb)

let malformed () =
  is_error "truncated header" (Block.Header.parse (String.sub (hex genesis_header_hex) 0 40));
  is_error "trailing bytes after a header" (Block.Header.parse (hex genesis_header_hex ^ "\000"));
  is_error "not a block" (Block.parse "\000\001\002")

let suite =
  [
    ( "block",
      [
        Alcotest.test_case "genesis header" `Quick genesis_header;
        Alcotest.test_case "block 1 header" `Quick block1_header;
        Alcotest.test_case "proof of work" `Quick proof_of_work_is_checked;
        Alcotest.test_case "compact targets" `Quick compact_targets;
        Alcotest.test_case "merkle roots" `Quick merkle_roots;
        Alcotest.test_case "genesis block" `Quick genesis_block;
        Alcotest.test_case "malformed input" `Quick malformed;
      ] );
  ]
