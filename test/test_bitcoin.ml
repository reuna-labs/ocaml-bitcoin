open Bitcoin
open Testutil

(* ------------------------------------------------------------------ Hash *)

let hash_vectors () =
  (* NIST/standard digests, plus the two Bitcoin compounds. *)
  check_hex "sha256 \"\"" "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    (Hash.sha256 "");
  check_hex "sha256 \"abc\"" "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    (Hash.sha256 "abc");
  check_hex "ripemd160 \"\"" "9c1185a5c5e9fc54612808977ee8f548b2258d31" (Hash.ripemd160 "");
  check_hex "ripemd160 \"abc\"" "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc" (Hash.ripemd160 "abc");
  check_hex "sha256d \"\"" "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456"
    (Hash.sha256d "");
  check_hex "hash160 \"\"" "b472a266d0bd89c13706a4132ccfb16f7c3b9fcb" (Hash.hash160 "")

let hash_tagged () =
  (* BIP340's definition, checked directly rather than through a signature. *)
  let tag = "TapLeaf" in
  let h = Hash.sha256 tag in
  check_hex "tagged = sha256(h||h||m)"
    (unhex (Hash.sha256 (h ^ h ^ "hello")))
    (Hash.tagged ~tag "hello");
  (* Distinct tags must not collide on the same message. *)
  check_bool "TapLeaf <> TapBranch" false
    (String.equal
       (Hash.tagged ~tag:Hash.Tag.tap_leaf "x")
       (Hash.tagged ~tag:Hash.Tag.tap_branch "x"))

(* ---------------------------------------------------------------- Base58 *)

let base58_core_vectors () =
  (* Bitcoin Core's base58_encode_decode.json: [hex, base58] pairs. *)
  match json "core-base58_encode_decode.json" with
  | `List cases ->
      List.iter
        (fun case ->
          match case with
          | `List [ `String h; `String b58 ] ->
              let raw = hex h in
              check_str ("encode " ^ h) b58 (Base58.encode raw);
              (* Core's fixtures are not consistent about hex case. *)
              check_hex ("decode " ^ b58) (String.lowercase_ascii h) (ok (Base58.decode b58))
          | _ -> ())
        cases
  | _ -> Alcotest.fail "base58 vectors: unexpected shape"

let base58_check () =
  (* A known mainnet P2PKH address: version byte 0x00 over a 20-byte hash. *)
  let addr = "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH" in
  let payload = ok (Base58.decode_check addr) in
  check_int "payload length" 21 (String.length payload);
  check_int "version byte" 0 (Char.code payload.[0]);
  check_str "round trip" addr (Base58.encode_check payload);
  (* Flipping one character must be caught by the checksum. *)
  let broken = String.mapi (fun i c -> if i = 10 then if c = 'a' then 'b' else 'a' else c) addr in
  is_error "corrupted address" (Base58.decode_check broken)

let base58_leading_zeros () =
  (* Leading zero bytes encode as leading '1's, one apiece; this is the part
     naive bignum implementations lose. *)
  check_str "three zero bytes" "111" (Base58.encode "\000\000\000");
  check_hex "decodes back" "000000" (ok (Base58.decode "111"));
  check_str "empty" "" (Base58.encode "");
  check_hex "empty decode" "" (ok (Base58.decode ""));
  (* 0x010203 = 66051 = 19*58^2 + 36*58 + 47, i.e. digits "Ldp", behind the
     three '1's standing for the three zero bytes. *)
  check_str "zeros then payload" "111Ldp" (Base58.encode "\000\000\000\001\002\003");
  check_hex "and back" "000000010203" (ok (Base58.decode "111Ldp"))

let base58_rejects () =
  is_error "character 0" (Base58.decode "0");
  is_error "character O" (Base58.decode "O");
  is_error "character I" (Base58.decode "I");
  is_error "character l" (Base58.decode "l");
  is_error "too short for checksum" (Base58.decode_check "1")

(* ---------------------------------------------------------------- Bech32 *)

let bech32_valid_checksums () =
  let check enc name s =
    match Bech32.decode s with
    | Error e -> Alcotest.failf "%s %S: %s" name s (Bitcoin.Error.to_string (e :> Bitcoin.Error.t))
    | Ok (enc', _, _) -> check_bool (name ^ " variant " ^ s) true (enc' = enc)
  in
  List.iter (check Bech32.Bech32 "bech32") Bech32_vectors.valid_bech32;
  List.iter (check Bech32.Bech32m "bech32m") Bech32_vectors.valid_bech32m

let bech32_invalid_checksums () =
  List.iter
    (fun s -> is_error (Printf.sprintf "invalid bech32 %S" s) (Bech32.decode s))
    (Bech32_vectors.invalid_bech32 @ Bech32_vectors.invalid_bech32m)

let bech32_valid_addresses () =
  List.iter
    (fun (addr, spk_hex) ->
      let hrp, version, program = ok (Bech32.decode_segwit_any addr) in
      (* Rebuild the scriptPubKey the way BIP141 defines it: the version as
         OP_0 or OP_1..OP_16, then a push of the program. *)
      let op_version = if version = 0 then 0 else 0x50 + version in
      let spk =
        Printf.sprintf "%c%c%s" (Char.chr op_version) (Char.chr (String.length program)) program
      in
      check_hex ("scriptPubKey for " ^ addr) spk_hex spk;
      (* And re-encoding must reproduce the address, modulo case. *)
      check_str ("re-encode " ^ addr) (String.lowercase_ascii addr)
        (ok (Bech32.encode_segwit ~hrp ~version ~program)))
    Bech32_vectors.valid_address

let bech32_invalid_addresses () =
  (* decode_segwit_any is deliberately agnostic about which chain an hrp
     names, so a structurally sound address under an unknown hrp ("tc") is
     rejected here by the hrp not mapping to any network -- which is what the
     address layer above will do with it. Everything else must fail outright. *)
  List.iter
    (fun s ->
      match Bech32.decode_segwit_any s with
      | Error _ -> ()
      | Ok (hrp, _, _) ->
          check_bool
            (Printf.sprintf "invalid address %S decoded under unknown hrp %S" s hrp)
            true
            (Network.of_hrp hrp = []))
    Bech32_vectors.invalid_address

let bech32_invalid_encodes () =
  List.iter
    (fun (hrp, version, len) ->
      is_error
        (Printf.sprintf "encode %S v%d len%d" hrp version len)
        (Bech32.encode_segwit ~hrp ~version ~program:(String.make len 'x')))
    Bech32_vectors.invalid_address_enc

let bech32_hrp_dispatch () =
  (* decode_segwit_any exists so an address can name its own network. *)
  let addr = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4" in
  let hrp, _, _ = ok (Bech32.decode_segwit_any addr) in
  check_str "hrp" "bc" hrp;
  check_bool "maps to mainnet" true (Network.of_hrp hrp = [ Network.Mainnet ]);
  is_error "wrong hrp is rejected" (Bech32.decode_segwit ~hrp:"tb" addr)

let bech32_length_limit () =
  (* BIP173's 90-character cap is the default, but Bech32 is reused at greater
     lengths elsewhere (Lightning), so the limit is a parameter. Build an
     over-long but otherwise valid string rather than borrowing one from the
     invalid list, whose entries fail for their own reasons. *)
  let data = Array.make 100 0 in
  let long = ok (Bech32.encode Bech32.Bech32 ~hrp:"bc" ~data) in
  check_bool "longer than the cap" true (String.length long > Bech32.max_length);
  is_error "rejected at the default limit" (Bech32.decode long);
  check_bool "accepted when the limit is raised" true
    (match Bech32.decode ~limit:200 long with Ok _ -> true | Error _ -> false);
  (* An hrp is capped at 83 characters independently of the total. *)
  is_error "84-character hrp" (Bech32.encode Bech32.Bech32 ~hrp:(String.make 84 'a') ~data:[||])

(* ----------------------------------------------------------------- Codec *)

let roundtrip name write read v =
  let s = Codec.W.to_string write v in
  match Codec.R.run read s with
  | Ok v' -> check_bool name true (v = v')
  | Error e -> Alcotest.failf "%s: %s" name (Bitcoin.Error.to_string (e :> Bitcoin.Error.t))

let codec_integers () =
  List.iter (fun v -> roundtrip "u8" Codec.W.u8 Codec.R.u8 v) [ 0; 1; 127; 128; 255 ];
  List.iter (fun v -> roundtrip "u16" Codec.W.u16 Codec.R.u16 v) [ 0; 1; 0xff; 0x100; 0xffff ];
  List.iter
    (fun v -> roundtrip "u32" Codec.W.u32 Codec.R.u32 v)
    [ 0l; 1l; 0xffl; 0x10000l; Int32.max_int; -1l ];
  List.iter
    (fun v -> roundtrip "u64" Codec.W.u64 Codec.R.u64 v)
    [ 0L; 1L; 0xffffffffL; Int64.max_int; -1L ];
  (* Little-endian is the consensus byte order. *)
  check_hex "u32 is little-endian" "78563412" (Codec.W.to_string Codec.W.u32 0x12345678l);
  check_hex "u32_be is not" "12345678" (Codec.W.to_string Codec.W.u32_be 0x12345678l)

let codec_varint_encoding () =
  let enc v = unhex (Codec.W.to_string Codec.W.varint v) in
  check_str "0" "00" (enc 0L);
  check_str "0xfc" "fc" (enc 0xfcL);
  check_str "0xfd" "fdfd00" (enc 0xfdL);
  check_str "0xffff" "fdffff" (enc 0xffffL);
  check_str "0x10000" "fe00000100" (enc 0x10000L);
  check_str "0xffffffff" "feffffffff" (enc 0xffffffffL);
  check_str "0x100000000" "ff0000000001000000" (enc 0x100000000L);
  List.iter
    (fun v -> roundtrip "varint" Codec.W.varint Codec.R.varint v)
    [ 0L; 0xfcL; 0xfdL; 0xffffL; 0x10000L; 0xffffffffL; 0x100000000L; Int64.max_int; -1L ]

let codec_varint_non_canonical () =
  (* Core rejects an encoding longer than necessary, and canonical
     re-encoding is what lets consensus hashes agree. *)
  let rejects hexs = is_error ("non-canonical " ^ hexs) (Codec.R.run Codec.R.varint (hex hexs)) in
  rejects "fd0000";
  rejects "fdfc00";
  rejects "fe00000000";
  rejects "feffff0000";
  rejects "ff0000000000000000";
  rejects "ffffffffff000000";
  (* "fd0100" is the value 1 written the long way, so it is rejected too. *)
  rejects "fd0100";
  (* The shortest form of each value is what the encoder emits and the only
     form the reader accepts. *)
  check_bool "fd0001 is minimal for 256" true (Codec.R.run Codec.R.varint (hex "fd0001") = Ok 256L);
  check_bool "fd is minimal for 253" true (Codec.R.run Codec.R.varint (hex "fdfd00") = Ok 253L)

let codec_bounds () =
  (* A hostile count must be refused before anything is allocated for it. *)
  is_error "0xff count with no payload"
    (Codec.R.run (fun r -> Codec.R.vector r Codec.R.u8) (hex "ffffffffffffffff7f"));
  is_error "count exceeds remaining"
    (Codec.R.run (fun r -> Codec.R.vector r Codec.R.u8) (hex "0501"));
  is_error "varstr longer than input" (Codec.R.run Codec.R.varstr (hex "0aff"));
  is_error "truncated u32" (Codec.R.run Codec.R.u32 (hex "0102"));
  is_error "trailing bytes" (Codec.R.run Codec.R.u8 (hex "0102"));
  check_bool "trailing allowed when inexact" true
    (Codec.R.run ~exact:false Codec.R.u8 (hex "0102") = Ok 1)

let codec_composites () =
  let s =
    Codec.W.to_string
      (fun w () ->
        Codec.W.vector w Codec.W.u16 [ 1; 2; 3 ];
        Codec.W.varstr w "hello";
        Codec.W.with_length w (fun w -> Codec.W.u32 w 7l))
      ()
  in
  let got =
    ok
      (Codec.R.run
         (fun r ->
           let v = Codec.R.vector r Codec.R.u16 in
           let str = Codec.R.varstr r in
           let inner = Codec.R.varstr r in
           (v, str, inner))
         s)
  in
  let v, str, inner = got in
  check_bool "vector" true (v = [ 1; 2; 3 ]);
  check_str "varstr" "hello" str;
  check_hex "with_length payload" "07000000" inner

let codec_sub_reader () =
  let s = hex "0401020304ff" in
  let got =
    ok
      (Codec.R.run ~exact:false
         (fun r ->
           let n = Codec.R.varint_int r in
           let sr = Codec.R.sub r n in
           let a = Codec.R.u16 sr in
           let b = Codec.R.u16 sr in
           (a, b, Codec.R.eof sr, Codec.R.remaining r))
         s)
  in
  let a, b, sub_eof, rest = got in
  check_int "first" 0x0201 a;
  check_int "second" 0x0403 b;
  check_bool "sub is exhausted" true sub_eof;
  check_int "outer advanced past the sub" 1 rest

let codec_hash_combinators () =
  let write w () = Codec.W.bytes w "abc" in
  check_hex "W.sha256" (unhex (Hash.sha256 "abc")) (Codec.W.sha256 write ());
  check_hex "W.sha256d" (unhex (Hash.sha256d "abc")) (Codec.W.sha256d write ());
  check_hex "W.tagged"
    (unhex (Hash.tagged ~tag:"TapLeaf" "abc"))
    (Codec.W.tagged ~tag:"TapLeaf" write ())

(* --------------------------------------------------------------- Network *)

let network_params () =
  List.iter
    (fun n ->
      check_bool
        ("hrp admits itself " ^ Network.to_string n)
        true
        (List.mem n (Network.of_hrp (Network.hrp n)));
      check_bool
        ("p2pkh admits itself " ^ Network.to_string n)
        true
        (List.mem n (Network.of_p2pkh_version (Network.p2pkh_version n)));
      check_bool
        ("wif admits itself " ^ Network.to_string n)
        true
        (List.mem n (Network.of_wif_version (Network.wif_version n)));
      check_bool
        ("name round trip " ^ Network.to_string n)
        true
        (Network.of_string (Network.to_string n) = Some n))
    Network.all;
  check_int "mainnet p2pkh" 0x00 (Network.p2pkh_version Network.Mainnet);
  check_int "mainnet p2sh" 0x05 (Network.p2sh_version Network.Mainnet);
  check_int "mainnet wif" 0x80 (Network.wif_version Network.Mainnet);
  check_str "mainnet hrp" "bc" (Network.hrp Network.Mainnet);
  check_str "regtest hrp" "bcrt" (Network.hrp Network.Regtest);
  check_hex "mainnet magic" "f9beb4d9" (Network.magic Network.Mainnet)

let network_testnets_are_indistinguishable () =
  (* This is why decoding yields a set of networks rather than one. *)
  List.iter
    (fun n ->
      check_str "shares tb" "tb" (Network.hrp n);
      check_int "shares p2pkh version" 0x6f (Network.p2pkh_version n))
    [ Network.Testnet3; Network.Testnet4; Network.Signet ];
  (* Regtest has its own Bech32 part but the same Base58 bytes, so Base58
     cannot separate it from the test networks at all. *)
  check_str "regtest has its own hrp" "bcrt" (Network.hrp Network.Regtest);
  check_int "but shares the p2pkh version" 0x6f (Network.p2pkh_version Network.Regtest);
  check_bool "so base58 admits regtest and every test network" true
    (List.sort compare (Network.of_p2pkh_version 0x6f)
    = List.sort compare [ Network.Testnet3; Network.Testnet4; Network.Signet; Network.Regtest ]);
  check_bool "while bcrt admits only regtest" true (Network.of_hrp "bcrt" = [ Network.Regtest ])

(* ------------------------------------------------- property-based checks *)

let prop_varint_roundtrip =
  QCheck2.Test.make ~count:5000 ~name:"varint: write then read is the identity"
    QCheck2.Gen.(oneof [ int64; map Int64.of_int (int_bound 100_000) ])
    (fun v -> Codec.R.run Codec.R.varint (Codec.W.to_string Codec.W.varint v) = Ok v)

let prop_varint_minimal =
  QCheck2.Test.make ~count:5000 ~name:"varint: the encoder always emits the shortest form"
    QCheck2.Gen.int64 (fun v ->
      let s = Codec.W.to_string Codec.W.varint v in
      (* Re-reading a canonical encoding never trips the minimality check. *)
      match Codec.R.run Codec.R.varint s with
      | Ok _ -> true
      | Error _ -> false)

let prop_reader_total =
  (* Arbitrary bytes must never make a reader raise, hang, or allocate
     without bound; they may only produce an error. This is the property
     that justifies the bounds check in varint_int. *)
  QCheck2.Test.make ~count:5000 ~name:"reader: arbitrary input never escapes as an exception"
    QCheck2.Gen.(string_size (int_bound 64))
    (fun s ->
      let parse f = match Codec.R.run f s with Ok _ | Error _ -> true in
      parse (fun r -> Codec.R.vector r Codec.R.u8)
      && parse (fun r -> Codec.R.vector r Codec.R.varstr)
      && parse Codec.R.varstr && parse Codec.R.varint
      && parse (fun r -> Codec.R.vector r (fun r -> Codec.R.vector r Codec.R.u8)))

let prop_base58_roundtrip =
  QCheck2.Test.make ~count:2000 ~name:"base58: decode after encode is the identity"
    QCheck2.Gen.(string_size (int_bound 64))
    (fun s -> Base58.decode (Base58.encode s) = Ok s)

let prop_base58_check_roundtrip =
  QCheck2.Test.make ~count:2000 ~name:"base58check: decode_check after encode_check is the identity"
    QCheck2.Gen.(string_size (int_bound 64))
    (fun s -> Base58.decode_check (Base58.encode_check s) = Ok s)

let prop_bech32_detects_mutation =
  (* The BCH code guarantees any single-character substitution is caught. *)
  QCheck2.Test.make ~count:2000 ~name:"bech32: every single-character mutation is detected"
    QCheck2.Gen.(pair (int_bound 6) (pair (int_bound 200) (int_bound 31)))
    (fun (which, (pos, repl)) ->
      let s = String.lowercase_ascii (List.nth Bech32_vectors.valid_bech32m which) in
      let sep = String.rindex s '1' in
      let n = String.length s in
      (* Mutate a data character only, so the hrp stays well-formed. *)
      let i = sep + 1 + (pos mod (n - sep - 1)) in
      let c = "qpzry9x8gf2tvdw0s3jn54khce6mua7l".[repl] in
      if s.[i] = c then true (* not a mutation *)
      else
        let m = String.mapi (fun j x -> if j = i then c else x) s in
        match Bech32.decode ~limit:200 m with Error _ -> true | Ok _ -> false)

(* ------------------------------------------------------------------ main *)

let () =
  Alcotest.run "bitcoin"
    (Test_backend.suite @ Test_keys.suite @ Test_tx.suite @ Test_taproot.suite
    @ [
        ( "hash",
          [
            Alcotest.test_case "known digests" `Quick hash_vectors;
            Alcotest.test_case "BIP340 tagged hash" `Quick hash_tagged;
          ] );
        ( "base58",
          [
            Alcotest.test_case "Bitcoin Core vectors" `Quick base58_core_vectors;
            Alcotest.test_case "Base58Check" `Quick base58_check;
            Alcotest.test_case "leading zeros" `Quick base58_leading_zeros;
            Alcotest.test_case "rejects ambiguous characters" `Quick base58_rejects;
          ] );
        ( "bech32",
          [
            Alcotest.test_case "valid checksums (BIP173/350)" `Quick bech32_valid_checksums;
            Alcotest.test_case "invalid checksums" `Quick bech32_invalid_checksums;
            Alcotest.test_case "valid segwit addresses" `Quick bech32_valid_addresses;
            Alcotest.test_case "invalid segwit addresses" `Quick bech32_invalid_addresses;
            Alcotest.test_case "invalid encode requests" `Quick bech32_invalid_encodes;
            Alcotest.test_case "hrp dispatch" `Quick bech32_hrp_dispatch;
            Alcotest.test_case "length limit" `Quick bech32_length_limit;
          ] );
        ( "codec",
          [
            Alcotest.test_case "integers" `Quick codec_integers;
            Alcotest.test_case "varint encoding" `Quick codec_varint_encoding;
            Alcotest.test_case "varint rejects non-canonical" `Quick codec_varint_non_canonical;
            Alcotest.test_case "bounds and truncation" `Quick codec_bounds;
            Alcotest.test_case "vectors, varstr, with_length" `Quick codec_composites;
            Alcotest.test_case "sub-reader" `Quick codec_sub_reader;
            Alcotest.test_case "hash combinators" `Quick codec_hash_combinators;
          ] );
        ( "network",
          [
            Alcotest.test_case "parameters" `Quick network_params;
            Alcotest.test_case "testnets are indistinguishable" `Quick
              network_testnets_are_indistinguishable;
          ] );
        ( "properties",
          List.map QCheck_alcotest.to_alcotest
            [
              prop_varint_roundtrip;
              prop_varint_minimal;
              prop_reader_total;
              prop_base58_roundtrip;
              prop_base58_check_roundtrip;
              prop_bech32_detects_mutation;
            ] );
      ])
