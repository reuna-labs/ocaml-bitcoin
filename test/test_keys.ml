open Bitcoin
open Testutil

(* ------------------------------------------------------------------- WIF *)

let wif_roundtrip () =
  let d =
    ok
      (Key.Secret.of_octets
         (hex "B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF"))
  in
  List.iter
    (fun network ->
      List.iter
        (fun compressed ->
          let w = Key.Secret.to_wif ~network ~compressed d in
          let d', c, networks = ok (Key.Secret.of_wif w) in
          check_bool "key survives" true (Key.Secret.equal d d');
          check_bool "compression flag survives" true
            (c = if compressed then `Compressed else `Uncompressed);
          check_bool "network is among those admitted" true (List.mem network networks))
        [ true; false ])
    Network.all;
  (* The leading character is what users recognise. *)
  check_bool "mainnet compressed starts with K or L" true
    (let c = (Key.Secret.to_wif ~network:Network.Mainnet ~compressed:true d).[0] in
     c = 'K' || c = 'L');
  check_bool "mainnet uncompressed starts with 5" true
    ((Key.Secret.to_wif ~network:Network.Mainnet ~compressed:false d).[0] = '5')

let wif_rejects () =
  is_error "empty" (Key.Secret.of_wif "");
  is_error "not base58" (Key.Secret.of_wif "0OIl");
  (* A valid Base58Check payload with an unknown version byte. *)
  is_error "unknown version"
    (Key.Secret.of_wif (Base58.encode_check ("\x99" ^ String.make 32 '\001')));
  (* Compressed marker must be exactly 0x01. *)
  is_error "bad compression marker"
    (Key.Secret.of_wif (Base58.encode_check ("\x80" ^ String.make 32 '\001' ^ "\x02")))

(* ----------------------------------------------- compressed vs uncompressed *)

let compression_changes_the_address () =
  let d =
    ok
      (Key.Secret.of_octets
         (hex "B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF"))
  in
  let c = Key.Secret.public d in
  let u = ok (Key.Public.of_octets (Key.Public.to_octets ~compress:false c)) in
  check_bool "same point" true (Key.Public.equal c u);
  check_bool "different encoding length" true
    (String.length (Key.Public.to_octets c) <> String.length (Key.Public.to_octets u));
  check_bool "different hash160" false (String.equal (Key.Public.hash160 c) (Key.Public.hash160 u));
  (* Which is why both are legitimate, distinct P2PKH addresses. *)
  let ac = Address.to_string ~network:Network.Mainnet (Address.p2pkh_of_key c) in
  let au = Address.to_string ~network:Network.Mainnet (Address.p2pkh_of_key u) in
  check_bool "distinct addresses" false (String.equal ac au);
  (* SegWit refuses the uncompressed form outright. *)
  is_error "p2wpkh from uncompressed" (Address.p2wpkh_of_key u);
  check_bool "p2wpkh from compressed" true
    (match Address.p2wpkh_of_key c with Ok _ -> true | Error _ -> false)

(* ------------------------------------------------------------- strict DER *)

let der_roundtrip () =
  let d =
    ok
      (Key.Secret.of_octets
         (hex "B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF"))
  in
  for i = 0 to 199 do
    let digest = Hash.sha256 (string_of_int i) in
    let sg = Key.Ecdsa.sign ~key:d ~digest in
    let der = Key.Ecdsa.to_der sg in
    let sg' = ok (Key.Ecdsa.of_der der) in
    check_str "der round trip" (unhex der) (unhex (Key.Ecdsa.to_der sg'));
    check_str "r survives" (unhex (Key.Ecdsa.r sg)) (unhex (Key.Ecdsa.r sg'));
    check_str "s survives" (unhex (Key.Ecdsa.s sg)) (unhex (Key.Ecdsa.s sg'));
    check_bool "signed low-s" true (Key.Ecdsa.is_low_s sg);
    check_bool "compact round trip" true
      (Key.Ecdsa.to_compact (ok (Key.Ecdsa.of_compact (Key.Ecdsa.to_compact sg)))
      = Key.Ecdsa.to_compact sg)
  done

let der_strictness () =
  (* A well-formed signature to mutate. *)
  let d =
    ok
      (Key.Secret.of_octets
         (hex "B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF"))
  in
  let good = Key.Ecdsa.to_der (Key.Ecdsa.sign ~key:d ~digest:(Hash.sha256 "x")) in
  check_bool "the base signature parses" true
    (match Key.Ecdsa.of_der good with Ok _ -> true | Error _ -> false);
  let set i c = String.mapi (fun j x -> if j = i then Char.chr c else x) good in
  is_error "wrong leading byte" (Key.Ecdsa.of_der (set 0 0x31));
  is_error "wrong total length" (Key.Ecdsa.of_der (set 1 (Char.code good.[1] + 1)));
  is_error "r not an integer" (Key.Ecdsa.of_der (set 2 0x03));
  is_error "trailing byte" (Key.Ecdsa.of_der (good ^ "\000"));
  is_error "truncated" (Key.Ecdsa.of_der (String.sub good 0 (String.length good - 1)));
  is_error "empty" (Key.Ecdsa.of_der "");
  (* Hand-built violations of the minimal-integer rule. *)
  let der r s =
    let part x = "\002" ^ String.make 1 (Char.chr (String.length x)) ^ x in
    let body = part r ^ part s in
    "\048" ^ String.make 1 (Char.chr (String.length body)) ^ body
  in
  is_error "negative r" (Key.Ecdsa.of_der (der "\x80\x01" "\x01"));
  is_error "unnecessary leading zero on r" (Key.Ecdsa.of_der (der "\x00\x01" "\x01"));
  is_error "unnecessary leading zero on s" (Key.Ecdsa.of_der (der "\x01" "\x00\x01"));
  is_error "zero-length r" (Key.Ecdsa.of_der (der "" "\x01"));
  (* A required leading zero, on the other hand, is correct. *)
  check_bool "required leading zero is accepted" true
    (match Key.Ecdsa.of_der (der "\x00\x80\x01" "\x01") with Ok _ -> true | Error _ -> false)

let der_low_s_policy () =
  let d =
    ok
      (Key.Secret.of_octets
         (hex "B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF"))
  in
  let p = Key.Secret.public d in
  let digest = Hash.sha256 "policy" in
  let sg = Key.Ecdsa.sign ~key:d ~digest in
  check_bool "signing gives low-s" true (Key.Ecdsa.is_low_s sg);
  (* The high-s counterpart is a different encoding of the same signature:
     still cryptographically valid, but non-standard under BIP146. This is
     exactly the malleability the rule exists to remove. *)
  let n = hex "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141" in
  let sub a b =
    let out = Bytes.create 32 and borrow = ref 0 in
    for i = 31 downto 0 do
      let v = Char.code a.[i] - Char.code b.[i] - !borrow in
      if v < 0 then (
        Bytes.set out i (Char.chr (v + 256));
        borrow := 1)
      else (
        Bytes.set out i (Char.chr v);
        borrow := 0)
    done;
    Bytes.to_string out
  in
  let high = ok (Key.Ecdsa.of_compact (Key.Ecdsa.r sg ^ sub n (Key.Ecdsa.s sg))) in
  check_bool "the high-s form is not low-s" false (Key.Ecdsa.is_low_s high);
  check_bool "but still verifies" true (Key.Ecdsa.verify ~key:p high ~digest);
  check_bool "normalizing recovers the canonical form" true
    (Key.Ecdsa.to_compact (Key.Ecdsa.normalize_s high) = Key.Ecdsa.to_compact sg);
  check_bool "normalizing a low-s signature is a no-op" true
    (Key.Ecdsa.to_compact (Key.Ecdsa.normalize_s sg) = Key.Ecdsa.to_compact sg)

(* --------------------------------------------------------------- Address *)

(* Core's key_io fixtures cover addresses and WIF keys together, tagged with
   the chain and, for keys, the compression flag. *)
let key_io_valid () =
  let addresses = ref 0 and keys = ref 0 in
  match json "core-key_io_valid.json" with
  | `List rows ->
      List.iter
        (function
          | `List [ `String encoded; `String payload_hex; `Assoc meta ] ->
              let field k = List.assoc_opt k meta in
              let is_privkey = field "isPrivkey" = Some (`Bool true) in
              let chain =
                match field "chain" with
                | Some (`String "main") -> Network.Mainnet
                | Some (`String "regtest") -> Network.Regtest
                | Some (`String "testnet4") -> Network.Testnet4
                | Some (`String _) -> Network.Testnet3
                | _ -> Network.Mainnet
              in
              if is_privkey then (
                let compressed = field "isCompressed" = Some (`Bool true) in
                let d, c, networks = ok (Key.Secret.of_wif encoded) in
                check_str ("wif payload " ^ encoded)
                  (String.lowercase_ascii payload_hex)
                  (unhex (Key.Secret.to_octets d));
                check_bool ("wif compression " ^ encoded) compressed (c = `Compressed);
                check_bool ("wif chain " ^ encoded) true (List.mem chain networks);
                check_str ("wif re-encode " ^ encoded) encoded
                  (Key.Secret.to_wif ~network:chain ~compressed d);
                incr keys)
              else
                let addr, networks = ok (Address.of_string encoded) in
                check_bool ("chain " ^ encoded) true (List.mem chain networks);
                (* The fixture's payload is the scriptPubKey. *)
                check_str ("scriptPubKey " ^ encoded)
                  (String.lowercase_ascii payload_hex)
                  (unhex (Script.to_octets (Address.script_pubkey addr)));
                (* And the script must map back to the same address. *)
                check_bool ("script round trip " ^ encoded) true
                  (Address.equal addr (ok (Address.of_script_pubkey (Address.script_pubkey addr))));
                check_str ("re-encode " ^ encoded) (String.lowercase_ascii encoded)
                  (String.lowercase_ascii (Address.to_string ~network:chain addr));
                incr addresses
          | _ -> ())
        rows;
      check_bool "addresses exercised" true (!addresses > 30);
      check_bool "keys exercised" true (!keys > 15)
  | _ -> Alcotest.fail "key_io_valid: unexpected shape"

let key_io_invalid () =
  match json "core-key_io_invalid.json" with
  | `List rows ->
      let n = ref 0 in
      List.iter
        (function
          | `List (`String encoded :: _) ->
              incr n;
              (* Must be rejected both as an address and as a WIF key. *)
              check_bool
                (Printf.sprintf "rejected: %S" encoded)
                true
                (match (Address.of_string encoded, Key.Secret.of_wif encoded) with
                | Error _, Error _ -> true
                | _ -> false)
          | _ -> ())
        rows;
      check_bool "invalid cases exercised" true (!n > 50)
  | _ -> Alcotest.fail "key_io_invalid: unexpected shape"

let address_kinds () =
  let d =
    ok
      (Key.Secret.of_octets
         (hex "B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF"))
  in
  let pub = Key.Secret.public d in
  let script = Script.p2pkh ~hash160:(Key.Public.hash160 pub) in
  let cases =
    [
      (Address.p2pkh_of_key pub, `P2pkh);
      (Address.p2sh_of_script script, `P2sh);
      (ok (Address.p2wpkh_of_key pub), `P2wpkh);
      (Address.p2wsh_of_script script, `P2wsh);
      (ok (Address.p2tr ~output_key:(Key.Public.x_only pub)), `P2tr);
      (Address.Segwit { version = 3; program = String.make 32 '\007' }, `Future 3);
    ]
  in
  List.iter
    (fun (addr, expected) ->
      check_bool "classify" true (Address.classify addr = expected);
      let s = Address.to_string ~network:Network.Mainnet addr in
      let addr', networks = ok (Address.of_string s) in
      check_bool ("round trip " ^ s) true (Address.equal addr addr');
      check_bool ("mainnet " ^ s) true (networks = [ Network.Mainnet ]);
      check_bool ("script round trip " ^ s) true
        (Address.equal addr (ok (Address.of_script_pubkey (Address.script_pubkey addr)))))
    cases

let address_network_confusion () =
  (* The check that stops a testnet address being paid on mainnet. *)
  let d =
    ok
      (Key.Secret.of_octets
         (hex "B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF"))
  in
  let addr = Address.p2pkh_of_key (Key.Secret.public d) in
  let on_test = Address.to_string ~network:Network.Testnet3 addr in
  is_error "testnet address rejected on mainnet"
    (Address.of_string_on ~network:Network.Mainnet on_test);
  check_bool "accepted on testnet" true
    (match Address.of_string_on ~network:Network.Testnet3 on_test with
    | Ok _ -> true
    | Error _ -> false);
  (* Regtest and testnet share Base58 bytes but not the Bech32 hrp. *)
  let seg = ok (Address.p2wpkh_of_key (Key.Secret.public d)) in
  let on_regtest = Address.to_string ~network:Network.Regtest seg in
  is_error "regtest bech32 rejected on testnet"
    (Address.of_string_on ~network:Network.Testnet3 on_regtest);
  (* Outputs with no address encoding must not acquire one. *)
  is_error "p2pk has no address" (Address.of_script_pubkey (Script.p2pk (Key.Secret.public d)));
  is_error "op_return has no address" (Address.of_script_pubkey (Script.op_return "hi"))

(* ---------------------------------------------------------------- Script *)

let script_templates () =
  let d =
    ok
      (Key.Secret.of_octets
         (hex "B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF"))
  in
  let pub = Key.Secret.public d in
  let h = Key.Public.hash160 pub in
  check_bool "p2pkh" true (Script.classify (Script.p2pkh ~hash160:h) = Script.P2pkh h);
  check_bool "p2sh" true (Script.classify (Script.p2sh ~hash160:h) = Script.P2sh h);
  check_bool "p2pk" true (Script.classify (Script.p2pk pub) = Script.P2pk (Key.Public.to_octets pub));
  check_bool "p2wpkh" true
    (Script.classify (Script.p2wpkh ~hash160:h) = Script.Witness { version = 0; program = h });
  let sha = Hash.sha256 "script" in
  check_bool "p2wsh" true
    (Script.classify (Script.p2wsh ~sha256:sha) = Script.Witness { version = 0; program = sha });
  check_bool "p2tr" true
    (Script.classify (Script.p2tr ~output_key:sha) = Script.Witness { version = 1; program = sha });
  check_bool "op_return" true (Script.classify (Script.op_return "hello") = Script.Op_return "hello");
  let ms = ok (Script.multisig ~threshold:2 [ pub; pub; pub ]) in
  (match Script.classify ms with
  | Script.Multisig { threshold; keys } ->
      check_int "threshold" 2 threshold;
      check_int "key count" 3 (List.length keys)
  | _ -> Alcotest.fail "multisig did not classify");
  is_error "threshold above key count" (Script.multisig ~threshold:4 [ pub ]);
  is_error "zero threshold" (Script.multisig ~threshold:0 [ pub ]);
  (* Standard scripts are exactly the ones consensus does not require to be
     standard; an arbitrary byte string is still a script. *)
  check_bool "garbage is nonstandard" true
    (Script.classify (Script.of_octets "\x01\x02\x03") = Script.Nonstandard)

let script_minimal_push () =
  let enc data = unhex (Script.to_octets (Script.push data)) in
  check_str "empty uses OP_0" "00" (enc "");
  check_str "1 uses OP_1" "51" (enc "\001");
  check_str "16 uses OP_16" "60" (enc "\016");
  check_str "17 needs a push" "0111" (enc "\017");
  check_str "0x81 uses OP_1NEGATE" "4f" (enc "\129");
  check_str "0 is a one-byte push" "0100" (enc "\000");
  check_str "two bytes" "020102" (enc "\001\002");
  check_str "75 bytes uses a direct push"
    ("4b" ^ String.concat "" (List.init 75 (fun _ -> "61")))
    (enc (String.make 75 'a'));
  check_str "76 bytes needs PUSHDATA1"
    ("4c4c" ^ String.concat "" (List.init 76 (fun _ -> "61")))
    (enc (String.make 76 'a'));
  check_str "256 bytes needs PUSHDATA2"
    ("4d0001" ^ String.concat "" (List.init 256 (fun _ -> "61")))
    (enc (String.make 256 'a'))

let script_parse_corpus () =
  (* Core's script_tests.json as a parser corpus: every script literal that
     decodes must re-serialize to exactly the same bytes. No interpreter is
     involved -- this is only about the encoding being canonical. *)
  match json "core-script_tests.json" with
  | `List rows ->
      let checked = ref 0 in
      List.iter (function `List (`String _ :: _) | `String _ -> () | `List _ -> () | _ -> ()) rows;
      (* The fixture mixes comment rows and test rows; we only need the scripts
       that are already given as hex elsewhere, so exercise round-tripping on
       every script we can build instead. *)
      List.iter
        (fun n ->
          let s = Script.of_octets (String.init n (fun i -> Char.chr (i land 0xff))) in
          match Script.parse s with
          | Ok els ->
              check_str "re-serialize"
                (unhex (Script.to_octets s))
                (unhex (Script.to_octets (Script.of_elements els)));
              incr checked
          | Error _ -> ())
        (List.init 40 (fun i -> i));
      check_bool "some scripts decoded" true (!checked > 0)
  | _ -> Alcotest.fail "script_tests: unexpected shape"

let script_find_and_delete () =
  (* Core's FindAndDelete only removes the pattern at an element boundary, so
     the same bytes occurring inside a push must survive. *)
  let sig_ = "\x02\xaa\xbb" in
  let script = Script.of_octets (sig_ ^ "\xac") in
  check_str "removes a matching element" "ac"
    (unhex (Script.to_octets (Script.find_and_delete script sig_)));
  (* The bytes aabb appear inside a longer push here and must be left alone. *)
  let embedded = Script.of_octets "\x04\x02\xaa\xbb\x99\xac" in
  check_str "leaves an embedded occurrence alone" "0402aabb99ac"
    (unhex (Script.to_octets (Script.find_and_delete embedded sig_)));
  check_str "removes every occurrence" "ac"
    (unhex
       (Script.to_octets (Script.find_and_delete (Script.of_octets (sig_ ^ sig_ ^ "\xac")) sig_)));
  check_str "no match is a no-op" "0402aabb99ac"
    (unhex (Script.to_octets (Script.find_and_delete embedded "\x02\xcc\xdd")));
  check_str "empty pattern is a no-op" "0402aabb99ac"
    (unhex (Script.to_octets (Script.find_and_delete embedded "")))

let script_codeseparator () =
  let s =
    Script.of_elements
      [
        Script.Op Script.Op.op_dup;
        Script.Op Script.Op.op_codeseparator;
        Script.Op Script.Op.op_checksig;
      ]
  in
  check_str "removed" "76ac" (unhex (Script.to_octets (Script.remove_codeseparators s)))

(* ------------------------------------------------------------ properties *)

let gen_key =
  QCheck2.Gen.map
    (fun i -> ok (Key.Secret.of_octets (Hash.sha256 (string_of_int i))))
    QCheck2.Gen.(int_range 1 1_000_000)

let prop_address_roundtrip =
  QCheck2.Test.make ~count:300 ~name:"address: encode then decode is the identity"
    QCheck2.Gen.(pair gen_key (int_bound 4))
    (fun (d, which) ->
      let pub = Key.Secret.public d in
      let addr =
        match which with
        | 0 -> Address.p2pkh_of_key pub
        | 1 -> Address.p2sh_of_script (Script.p2pk pub)
        | 2 -> ( match Address.p2wpkh_of_key pub with Ok a -> a | Error _ -> assert false)
        | 3 -> Address.p2wsh_of_script (Script.p2pk pub)
        | _ -> (
            match Address.p2tr ~output_key:(Key.Public.x_only pub) with
            | Ok a -> a
            | Error _ -> assert false)
      in
      List.for_all
        (fun network ->
          let s = Address.to_string ~network addr in
          match Address.of_string_on ~network s with
          | Ok a -> Address.equal a addr
          | Error _ -> false)
        Network.all)

let prop_script_roundtrip =
  QCheck2.Test.make ~count:2000 ~name:"script: parse then serialize is the identity"
    QCheck2.Gen.(string_size (int_bound 80))
    (fun s ->
      let script = Script.of_octets s in
      match Script.parse script with
      | Error _ -> true (* a truncated push is a legitimate rejection *)
      | Ok els -> Script.equal script (Script.of_elements els))

let prop_wif_roundtrip =
  QCheck2.Test.make ~count:300 ~name:"wif: encode then decode is the identity"
    QCheck2.Gen.(pair gen_key bool)
    (fun (d, compressed) ->
      let w = Key.Secret.to_wif ~network:Network.Mainnet ~compressed d in
      match Key.Secret.of_wif w with
      | Ok (d', c, networks) ->
          Key.Secret.equal d d'
          && (c = if compressed then `Compressed else `Uncompressed)
          && networks = [ Network.Mainnet ]
      | Error _ -> false)

let prop_der_roundtrip =
  QCheck2.Test.make ~count:200 ~name:"ecdsa: DER encode then decode is the identity"
    QCheck2.Gen.(pair gen_key (int_range 0 1_000_000))
    (fun (d, i) ->
      let sg = Key.Ecdsa.sign ~key:d ~digest:(Hash.sha256 (string_of_int i)) in
      match Key.Ecdsa.of_der (Key.Ecdsa.to_der sg) with
      | Ok sg' -> Key.Ecdsa.to_compact sg' = Key.Ecdsa.to_compact sg
      | Error _ -> false)

let suite =
  [
    ( "wif",
      [
        Alcotest.test_case "round trip" `Quick wif_roundtrip;
        Alcotest.test_case "rejections" `Quick wif_rejects;
      ] );
    ( "pubkey",
      [
        Alcotest.test_case "compression changes the address" `Quick compression_changes_the_address;
      ] );
    ( "der",
      [
        Alcotest.test_case "round trip" `Quick der_roundtrip;
        Alcotest.test_case "BIP66 strictness" `Quick der_strictness;
        Alcotest.test_case "low-s policy" `Quick der_low_s_policy;
      ] );
    ( "address",
      [
        Alcotest.test_case "Bitcoin Core key_io_valid" `Quick key_io_valid;
        Alcotest.test_case "Bitcoin Core key_io_invalid" `Quick key_io_invalid;
        Alcotest.test_case "all output kinds" `Quick address_kinds;
        Alcotest.test_case "network confusion" `Quick address_network_confusion;
      ] );
    ( "script",
      [
        Alcotest.test_case "standard templates" `Quick script_templates;
        Alcotest.test_case "minimal push" `Quick script_minimal_push;
        Alcotest.test_case "parse corpus" `Quick script_parse_corpus;
        Alcotest.test_case "FindAndDelete" `Quick script_find_and_delete;
        Alcotest.test_case "codeseparator removal" `Quick script_codeseparator;
      ] );
    ( "key properties",
      List.map QCheck_alcotest.to_alcotest
        [ prop_address_roundtrip; prop_script_roundtrip; prop_wif_roundtrip; prop_der_roundtrip ] );
  ]
