open Testutil
module B = Bitcoin_backend.Backend

(* ------------------------------------------------------- curve constants *)

let curve_constants () =
  check_hex "order n" "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141" B.order;
  check_hex "field prime p" "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"
    B.field_prime

(* --------------------------------------------------------- key mechanics *)

let secret_range () =
  let z32 = String.make 32 '\000' in
  is_error "zero is not a valid scalar" (B.secret_of_octets z32);
  is_error "n is not a valid scalar" (B.secret_of_octets B.order);
  is_error "too short" (B.secret_of_octets (String.make 31 '\001'));
  is_error "too long" (B.secret_of_octets (String.make 33 '\001'));
  (* n - 1 is the largest valid scalar. *)
  let n_minus_1 = Bytes.of_string B.order in
  Bytes.set n_minus_1 31 '\064';
  check_bool "n-1 is valid" true
    (match B.secret_of_octets (Bytes.to_string n_minus_1) with Ok _ -> true | Error _ -> false)

let known_keypair () =
  (* BIP340 vector 1: secret key and the x-only public key it derives. *)
  let d =
    ok (B.secret_of_octets (hex "B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF"))
  in
  let p = B.public_of_secret d in
  check_hex "x-only public key" "dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659"
    (B.public_x p);
  (* The generator: secret 1 gives G. *)
  let one =
    ok (B.secret_of_octets (hex "0000000000000000000000000000000000000000000000000000000000000001"))
  in
  check_hex "G compressed" "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    (B.public_to_octets ~compress:true (B.public_of_secret one));
  check_hex "G uncompressed"
    "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
    (B.public_to_octets ~compress:false (B.public_of_secret one))

let public_encodings () =
  let d =
    ok (B.secret_of_octets (hex "B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF"))
  in
  let p = B.public_of_secret d in
  let c = B.public_to_octets ~compress:true p in
  let u = B.public_to_octets ~compress:false p in
  check_int "compressed is 33 bytes" 33 (String.length c);
  check_int "uncompressed is 65 bytes" 65 (String.length u);
  check_bool "both decode to the same point" true
    (B.public_equal (ok (B.public_of_octets c)) (ok (B.public_of_octets u)));
  (* lift_x always yields the even-y point. *)
  let lifted = ok (B.public_of_x_only (B.public_x p)) in
  check_bool "lift_x has even y" true (B.public_has_even_y lifted);
  check_bool "lift_x agrees on x" true (String.equal (B.public_x p) (B.public_x lifted));
  is_error "x with no curve point" (B.public_of_x_only (String.make 32 '\255'));
  is_error "not a SEC1 length" (B.public_of_octets (hex "0279be66"))

let negation () =
  let d =
    ok (B.secret_of_octets (hex "B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF"))
  in
  let p = B.public_of_secret d in
  let np = B.public_negate p in
  check_bool "negation flips y parity" false (B.public_has_even_y p = B.public_has_even_y np);
  check_bool "negation preserves x" true (String.equal (B.public_x p) (B.public_x np));
  check_bool "double negation is the identity" true (B.public_equal p (B.public_negate np));
  (* (-d)*G = -(d*G). *)
  let nd = B.secret_negate d in
  check_bool "secret negation matches point negation" true
    (B.public_equal (B.public_of_secret nd) np);
  check_bool "double secret negation is the identity" true (B.secret_equal d (B.secret_negate nd))

let tweaking () =
  let d =
    ok (B.secret_of_octets (hex "B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF"))
  in
  let p = B.public_of_secret d in
  let t = hex "0000000000000000000000000000000000000000000000000000000000000007" in
  (* The homomorphism BIP32 and BIP341 both rely on: (d + t)*G = d*G + t*G. *)
  let d' = ok (B.secret_add d t) in
  let p' = ok (B.public_add_tweak p t) in
  check_bool "(d + t)*G = P + t*G" true (B.public_equal (B.public_of_secret d') p');
  (* Adding t then n - t returns to the start. *)
  let n_minus_t =
    let open B in
    let z = ok (secret_of_octets t) in
    secret_to_octets (secret_negate z)
  in
  check_bool "adding t then -t is the identity" true
    (B.secret_equal d (ok (B.secret_add d' n_minus_t)));
  is_error "tweak of zero" (B.secret_add d (String.make 32 '\000'));
  is_error "tweak at or above n" (B.secret_add d B.order);
  is_error "tweak of the wrong length" (B.secret_add d (String.make 31 '\001'))

let point_addition () =
  let mk h = B.public_of_secret (ok (B.secret_of_octets (hex h))) in
  let g = mk "0000000000000000000000000000000000000000000000000000000000000001" in
  let two_g = mk "0000000000000000000000000000000000000000000000000000000000000002" in
  let three_g = mk "0000000000000000000000000000000000000000000000000000000000000003" in
  check_bool "G + G = 2G" true (B.public_equal two_g (ok (B.public_add g g)));
  check_bool "G + 2G = 3G" true (B.public_equal three_g (ok (B.public_add g two_g)));
  (* G + (-G) is the point at infinity, which has no affine encoding. *)
  is_error "G + (-G)" (B.public_add g (B.public_negate g))

(* -------------------------------------------------------- BIP340 vectors *)

let bip340_vectors () =
  let path = vector "bip340-test-vectors.csv" in
  let ic = open_in path in
  let _header = input_line ic in
  let rows = ref [] in
  (try
     while true do
       let line = input_line ic in
       if String.trim line <> "" then rows := String.split_on_char ',' line :: !rows
     done
   with End_of_file -> ());
  close_in ic;
  let rows = List.rev !rows in
  check_bool "vectors were loaded" true (List.length rows >= 15);
  let signed = ref 0 and verified = ref 0 and rejected = ref 0 in
  List.iter
    (fun row ->
      match row with
      | idx :: sk :: pk :: aux :: msg :: sg :: result :: _ ->
          let expect = String.uppercase_ascii (String.trim result) = "TRUE" in
          let pk = hex pk and msg = hex msg and sg = hex sg in
          let name suffix = Printf.sprintf "vector %s %s" idx suffix in
          (* Signing, for the vectors that carry a secret key. *)
          if String.trim sk <> "" then (
            let d = ok (B.secret_of_octets (hex sk)) in
            check_hex (name "derived pubkey") (unhex pk) (B.public_x (B.public_of_secret d));
            check_hex (name "signature") (unhex sg)
              (B.schnorr_sign ~secret:d ~aux_rand:(hex aux) ~msg);
            incr signed);
          (* Verification, for every vector. *)
          let got = B.schnorr_verify ~x_only:pk ~signature:sg ~msg in
          check_bool (name "verify") expect got;
          if expect then incr verified else incr rejected
      | _ -> ())
    rows;
  (* Guard against the file silently changing shape and the loop doing nothing. *)
  check_bool "signing vectors ran" true (!signed >= 4);
  check_bool "accepting vectors ran" true (!verified >= 5);
  check_bool "rejecting vectors ran" true (!rejected >= 9)

(* ---------------------------------------------------------------- ECDSA *)

let ecdsa_roundtrip () =
  let d =
    ok (B.secret_of_octets (hex "B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF"))
  in
  let p = B.public_of_secret d in
  let digest = Bitcoin.Hash.sha256 "a message" in
  let r, s = B.ecdsa_sign ~secret:d ~digest in
  check_int "r is 32 bytes" 32 (String.length r);
  check_int "s is 32 bytes" 32 (String.length s);
  check_bool "verifies" true (B.ecdsa_verify ~public:p ~r ~s ~digest);
  check_bool "rejects a different digest" false
    (B.ecdsa_verify ~public:p ~r ~s ~digest:(Bitcoin.Hash.sha256 "another message"));
  (* Deterministic: RFC 6979 means the same input signs identically. *)
  let r2, s2 = B.ecdsa_sign ~secret:d ~digest in
  check_bool "deterministic" true (String.equal r r2 && String.equal s s2)

let half_n = hex "7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0"

let ecdsa_low_s () =
  (* Bitcoin requires the low-s variant (BIP62/BIP146); a high-s signature
     is valid but non-standard and will not relay. mirage-crypto-ec does not
     normalise, so the backend must, and this is the check that says so. *)
  let d =
    ok (B.secret_of_octets (hex "B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF"))
  in
  let p = B.public_of_secret d in
  let high = ref 0 in
  for i = 0 to 499 do
    let digest = Bitcoin.Hash.sha256 (string_of_int i) in
    let r, s = B.ecdsa_sign ~secret:d ~digest in
    if String.compare s half_n > 0 then incr high;
    if not (B.ecdsa_verify ~public:p ~r ~s ~digest) then
      Alcotest.failf "signature %d failed to verify" i
  done;
  check_int "signatures with high s" 0 !high

(* ----------------------------------------------------------- properties *)

let gen_secret =
  QCheck2.Gen.map
    (fun i ->
      (* Deterministic, well-spread scalars without touching an RNG. *)
      ok (B.secret_of_octets (Bitcoin.Hash.sha256 (string_of_int i))))
    QCheck2.Gen.(int_range 1 1_000_000)

let prop_pubkey_backends_agree =
  (* The tripwire for the dual-backend design: public keys are derived
     through mirage-crypto-ec's constant-time base multiplication, while
     point arithmetic runs through mirage-crypto-blockchain. If the two ever
     disagree about what d*G is, everything above silently breaks. *)
  QCheck2.Test.make ~count:300 ~name:"secp256k1: both backends agree on d*G" gen_secret (fun d ->
      let p = B.public_of_secret d in
      let sec1 = B.public_to_octets ~compress:true p in
      (* Round-tripping through the point backend must be a no-op. *)
      match B.public_of_octets sec1 with
      | Error _ -> false
      | Ok p' ->
          B.public_equal p p'
          && String.equal (B.public_to_octets ~compress:true p') sec1
          && String.length (B.public_to_octets ~compress:false p') = 65)

let prop_tweak_homomorphism =
  QCheck2.Test.make ~count:300 ~name:"secp256k1: (d + t)*G = d*G + t*G"
    QCheck2.Gen.(pair gen_secret (int_range 1 1_000_000))
    (fun (d, i) ->
      let t = Bitcoin.Hash.sha256 ("tweak" ^ string_of_int i) in
      match (B.secret_add d t, B.public_add_tweak (B.public_of_secret d) t) with
      | Ok d', Ok p' -> B.public_equal (B.public_of_secret d') p'
      | _ -> false)

let prop_ecdsa_low_s =
  QCheck2.Test.make ~count:300 ~name:"ecdsa: every signature is low-s and verifies"
    QCheck2.Gen.(pair gen_secret (int_range 0 1_000_000))
    (fun (d, i) ->
      let digest = Bitcoin.Hash.sha256 (string_of_int i) in
      let r, s = B.ecdsa_sign ~secret:d ~digest in
      String.compare s half_n <= 0 && B.ecdsa_verify ~public:(B.public_of_secret d) ~r ~s ~digest)

let prop_schnorr_roundtrip =
  QCheck2.Test.make ~count:200 ~name:"bip340: sign then verify"
    QCheck2.Gen.(pair gen_secret (int_range 0 1_000_000))
    (fun (d, i) ->
      let msg = Bitcoin.Hash.sha256 (string_of_int i) in
      let sg = B.schnorr_sign ~secret:d ~aux_rand:(String.make 32 '\000') ~msg in
      String.length sg = 64
      && B.schnorr_verify ~x_only:(B.public_x (B.public_of_secret d)) ~signature:sg ~msg
      && not
           (B.schnorr_verify
              ~x_only:(B.public_x (B.public_of_secret d))
              ~signature:sg
              ~msg:(Bitcoin.Hash.sha256 (string_of_int (i + 1)))))

let suite =
  [
    ( "backend",
      [
        Alcotest.test_case "curve constants" `Quick curve_constants;
        Alcotest.test_case "secret key range" `Quick secret_range;
        Alcotest.test_case "known keypairs" `Quick known_keypair;
        Alcotest.test_case "public key encodings" `Quick public_encodings;
        Alcotest.test_case "negation" `Quick negation;
        Alcotest.test_case "tweaking" `Quick tweaking;
        Alcotest.test_case "point addition" `Quick point_addition;
      ] );
    ("bip340", [ Alcotest.test_case "official test vectors" `Quick bip340_vectors ]);
    ( "ecdsa",
      [
        Alcotest.test_case "sign and verify" `Quick ecdsa_roundtrip;
        Alcotest.test_case "low-s normalization" `Slow ecdsa_low_s;
      ] );
    ( "crypto properties",
      List.map QCheck_alcotest.to_alcotest
        [
          prop_pubkey_backends_agree;
          prop_tweak_homomorphism;
          prop_ecdsa_low_s;
          prop_schnorr_roundtrip;
        ] );
  ]
