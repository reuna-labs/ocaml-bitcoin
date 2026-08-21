open Bitcoin
open Testutil

(* ------------------------------------------------------- derivation paths *)

let path_parsing () =
  let p s = ok (Derivation_path.of_string s) in
  check_str "master" "m" (Derivation_path.to_string (p "m"));
  check_str "simple" "m/0" (Derivation_path.to_string (p "m/0"));
  check_str "hardened" "m/0'" (Derivation_path.to_string (p "m/0'"));
  check_str "h marker is accepted" "m/0'" (Derivation_path.to_string (p "m/0h"));
  check_str "H marker is accepted" "m/0'" (Derivation_path.to_string (p "m/0H"));
  check_str "mixed markers" "m/44'/0'/0'/0/0" (Derivation_path.to_string (p "m/44h/0'/0H/0/0"));
  check_str "leading m is optional" "m/0" (Derivation_path.to_string (p "0"));
  check_str "h output on request" "m/44h/0h" (Derivation_path.to_string ~marker:`H (p "m/44'/0'"));
  check_int "depth" 5 (Derivation_path.depth (p "m/44'/0'/0'/0/0"));
  check_bool "hardened index" true (Derivation_path.is_hardened 0x80000000l);
  check_bool "normal index" false (Derivation_path.is_hardened 0x7fffffffl);
  (* The largest normal and the smallest hardened index. *)
  check_str "2147483647" "m/2147483647" (Derivation_path.to_string (p "m/2147483647"));
  check_str "2147483647'" "m/2147483647'" (Derivation_path.to_string (p "m/2147483647'"));
  (* An unmarked index at or above 2^31 would silently mean a hardened one,
     so it is refused rather than reinterpreted. *)
  is_error "unmarked 2^31" (Derivation_path.of_string "m/2147483648");
  is_error "not a number" (Derivation_path.of_string "m/abc");
  is_error "empty component" (Derivation_path.of_string "m//0");
  is_error "negative" (Derivation_path.of_string "m/-1")

let path_helpers () =
  check_str "bip84 mainnet" "m/84'/0'/0'"
    (Derivation_path.to_string
       (ok (Derivation_path.bip84 ~coin:(Derivation_path.coin_type Network.Mainnet) ~account:0l)));
  check_str "bip86 testnet" "m/86'/1'/2'"
    (Derivation_path.to_string
       (ok (Derivation_path.bip86 ~coin:(Derivation_path.coin_type Network.Testnet3) ~account:2l)));
  check_str "bip44" "m/44'/0'/0'"
    (Derivation_path.to_string (ok (Derivation_path.bip44 ~coin:0l ~account:0l)));
  check_str "bip49" "m/49'/0'/0'"
    (Derivation_path.to_string (ok (Derivation_path.bip49 ~coin:0l ~account:0l)));
  check_int "mainnet coin type" 0 (Int32.to_int (Derivation_path.coin_type Network.Mainnet));
  List.iter
    (fun n ->
      check_int
        ("test coin type " ^ Network.to_string n)
        1
        (Int32.to_int (Derivation_path.coin_type n)))
    [ Network.Testnet3; Network.Testnet4; Network.Signet; Network.Regtest ];
  let p = ok (Derivation_path.of_string "m/1/2") in
  check_str "parent" "m/1" (Derivation_path.to_string (Option.get (Derivation_path.parent p)));
  check_bool "master has no parent" true (Derivation_path.parent Derivation_path.empty = None);
  check_str "child" "m/1/2/3'"
    (Derivation_path.to_string (ok (Derivation_path.child p 3 ~hardened:true)));
  is_error "child index too large" (Derivation_path.child p 0x80000000 ~hardened:false)

(* ------------------------------------------------------------ BIP32 vectors *)

let bip32_vectors () =
  let open Yojson.Safe.Util in
  let doc = json "bip32-test-vectors.json" in
  let vectors = doc |> member "valid" |> to_list in
  check_int "vector count" 4 (List.length vectors);
  let chains = ref 0 in
  List.iteri
    (fun vi v ->
      let seed = hex (v |> member "seed" |> to_string) in
      let master = ok (Bip32.Secret.master seed) in
      List.iter
        (fun c ->
          let path_str = c |> member "path" |> to_string in
          let path = ok (Derivation_path.of_string path_str) in
          let name s = Printf.sprintf "vector %d %s %s" (vi + 1) path_str s in
          let sk = ok (Bip32.Secret.derive_path master path) in
          check_str (name "xprv")
            (c |> member "xprv" |> to_string)
            (Bip32.Secret.to_base58 ~network:Network.Mainnet sk);
          check_str (name "xpub")
            (c |> member "xpub" |> to_string)
            (Bip32.Public.to_base58 ~network:Network.Mainnet (Bip32.Secret.public sk));
          (* Parsing the vector's own strings must give the same keys back. *)
          let sk', nets = ok (Bip32.Secret.of_base58 (c |> member "xprv" |> to_string)) in
          check_bool
            (name "xprv parses to the same key")
            true
            (Key.Secret.equal sk.Bip32.key sk'.Bip32.key
            && String.equal sk.Bip32.chain_code sk'.Bip32.chain_code
            && sk.Bip32.depth = sk'.Bip32.depth
            && Int32.equal sk.Bip32.child_number sk'.Bip32.child_number
            && String.equal sk.Bip32.parent_fingerprint sk'.Bip32.parent_fingerprint);
          check_bool (name "xprv is mainnet") true (List.mem Network.Mainnet nets);
          let pk', _ = ok (Bip32.Public.of_base58 (c |> member "xpub" |> to_string)) in
          check_bool
            (name "xpub parses to the same key")
            true
            (Key.Public.equal pk'.Bip32.key (Key.Secret.public sk.Bip32.key));
          (* Public derivation must agree with private derivation wherever
             the path has no hardened step. That equivalence is what makes a
             watch-only wallet possible. *)
          (if not (List.exists Derivation_path.is_hardened (Derivation_path.to_list path)) then
             let pub_derived = ok (Bip32.Public.derive_path (Bip32.Secret.public master) path) in
             check_str (name "public derivation agrees")
               (c |> member "xpub" |> to_string)
               (Bip32.Public.to_base58 ~network:Network.Mainnet pub_derived));
          incr chains)
        (v |> member "chains" |> to_list))
    vectors;
  check_int "chains exercised" 17 !chains

let bip32_invalid_keys () =
  (* Vector 5: extended keys that must be recognised as invalid. Most
     implementations that get these wrong accept a key with the wrong
     version or a bad key prefix, which is how a public key ends up treated
     as a private one. *)
  let open Yojson.Safe.Util in
  let cases = json "bip32-test-vectors.json" |> member "invalid" |> to_list in
  check_int "invalid case count" 14 (List.length cases);
  List.iter
    (fun c ->
      let key = c |> member "key" |> to_string in
      let reason = c |> member "reason" |> to_string in
      check_bool
        (Printf.sprintf "rejected (%s)" reason)
        true
        (match (Bip32.Secret.of_base58 key, Bip32.Public.of_base58 key) with
        | Error _, Error _ -> true
        | _ -> false))
    cases

let hardened_needs_private () =
  let master = ok (Bip32.Secret.master (hex "000102030405060708090a0b0c0d0e0f")) in
  let xpub = Bip32.Secret.public master in
  (* The firewall hardened derivation exists to provide. *)
  check_bool "hardened from private works" true
    (match Bip32.Secret.derive master 0x80000000l with Ok _ -> true | Error _ -> false);
  is_error "hardened from public is refused" (Bip32.Public.derive xpub 0x80000000l);
  check_bool "normal from public works" true
    (match Bip32.Public.derive xpub 0l with Ok _ -> true | Error _ -> false);
  is_error "hardened path from public"
    (Bip32.Public.derive_path xpub (ok (Derivation_path.of_string "m/0'")))

let master_seed_bounds () =
  is_error "seed too short" (Bip32.Secret.master (String.make 15 '\001'));
  is_error "seed too long" (Bip32.Secret.master (String.make 65 '\001'));
  check_bool "16 bytes is the minimum" true
    (match Bip32.Secret.master (String.make 16 '\001') with Ok _ -> true | Error _ -> false);
  check_bool "64 bytes is the maximum" true
    (match Bip32.Secret.master (String.make 64 '\001') with Ok _ -> true | Error _ -> false);
  let m = ok (Bip32.Secret.master (String.make 32 '\002')) in
  check_int "master depth" 0 m.Bip32.depth;
  check_int "master child number" 0 (Int32.to_int m.Bip32.child_number);
  check_hex "master has no parent" "00000000" m.Bip32.parent_fingerprint

let fingerprints () =
  let master = ok (Bip32.Secret.master (hex "000102030405060708090a0b0c0d0e0f")) in
  let child = ok (Bip32.Secret.derive master 0x80000000l) in
  check_int "fingerprint is four bytes" 4 (String.length (Bip32.Secret.fingerprint master));
  check_hex "child records its parent"
    (unhex (Bip32.Secret.fingerprint master))
    child.Bip32.parent_fingerprint;
  check_int "child depth" 1 child.Bip32.depth;
  check_bool "private and public fingerprints agree" true
    (String.equal (Bip32.Secret.fingerprint master)
       (Bip32.Public.fingerprint (Bip32.Secret.public master)))

(* ------------------------------------------------------------------ BIP39 *)

let bip39_wordlist_shape () =
  check_int "2048 words" 2048 (Array.length Bip39.wordlist);
  check_str "first" "abandon" Bip39.wordlist.(0);
  check_str "last" "zoo" Bip39.wordlist.(2047);
  (* Sorted, which is what lets lookup be a binary search. *)
  let sorted = ref true in
  Array.iteri
    (fun i w -> if i > 0 && String.compare Bip39.wordlist.(i - 1) w >= 0 then sorted := false)
    Bip39.wordlist;
  check_bool "sorted and distinct" true !sorted;
  (* BIP39 guarantees the first four letters identify a word. *)
  let prefixes = Hashtbl.create 2048 in
  Array.iter
    (fun w ->
      let p = String.sub w 0 (min 4 (String.length w)) in
      Hashtbl.replace prefixes p ())
    Bip39.wordlist;
  check_int "distinct four-letter prefixes" 2048 (Hashtbl.length prefixes)

let bip39_vectors () =
  (* The Trezor vectors use the passphrase "TREZOR" and also give the xprv
     the seed derives to, so this exercises BIP39 and BIP32 together. *)
  let open Yojson.Safe.Util in
  let cases = json "bip39-vectors.json" |> member "english" |> to_list in
  check_int "vector count" 24 (List.length cases);
  List.iteri
    (fun i case ->
      match to_list case with
      | [ `String entropy_hex; `String mnemonic; `String seed_hex; `String xprv ] ->
          let name s = Printf.sprintf "vector %d %s" i s in
          let entropy = hex entropy_hex in
          let words = Bip39.normalize mnemonic in
          check_str (name "mnemonic") mnemonic (String.concat " " (ok (Bip39.of_entropy entropy)));
          check_hex (name "entropy") entropy_hex (ok (Bip39.to_entropy words));
          check_bool (name "checksum") true (Bip39.check words);
          check_hex (name "seed") seed_hex (ok (Bip39.to_seed ~passphrase:"TREZOR" words));
          (* And the seed must derive the master key the vector names. *)
          let master = ok (Bip32.Secret.master (hex seed_hex)) in
          check_str (name "xprv") xprv (Bip32.Secret.to_base58 ~network:Network.Mainnet master)
      | _ -> Alcotest.fail "bip39 vector: unexpected shape")
    cases

let bip39_rejections () =
  let good = Bip39.normalize (String.concat " " (ok (Bip39.of_entropy (String.make 16 '\000')))) in
  check_bool "baseline is valid" true (Bip39.check good);
  (* Substituting a word breaks the checksum with overwhelming probability;
     accepting it is how a typo becomes a silently different wallet. *)
  let swapped = "ability" :: List.tl good in
  check_bool "a substituted word is caught" false (Bip39.check swapped);
  is_error "and to_seed refuses it" (Bip39.to_seed swapped);
  check_bool "a word outside the list is caught" false (Bip39.check ("notaword" :: List.tl good));
  check_bool "wrong word count is caught" false (Bip39.check (List.tl good));
  is_error "entropy of the wrong size" (Bip39.of_entropy (String.make 17 '\000'));
  is_error "entropy too short" (Bip39.of_entropy (String.make 15 '\000'));
  is_error "entropy too long" (Bip39.of_entropy (String.make 33 '\000'));
  (* Non-ASCII would need NFKD normalisation, which this library does not do;
     refusing beats producing a wrong seed in silence. *)
  check_bool "non-ASCII is refused" false (Bip39.check ("\xc3\xa9" :: List.tl good));
  (* The escape hatch still works for interoperating with other wallets. *)
  check_int "unchecked still derives a seed" 64 (String.length (Bip39.to_seed_unchecked swapped))

let bip39_passphrase () =
  let words = ok (Bip39.of_entropy (String.make 16 '\007')) in
  let a = ok (Bip39.to_seed words) in
  let b = ok (Bip39.to_seed ~passphrase:"" words) in
  let c = ok (Bip39.to_seed ~passphrase:"hunter2" words) in
  check_hex "no passphrase equals the empty one" (unhex a) b;
  (* A different passphrase is a different wallet, with no error to warn
     you. That is BIP39's design, and its sharpest edge. *)
  check_bool "a passphrase changes the seed" false (String.equal a c);
  check_int "seed length" 64 (String.length a)

(* ------------------------------------------------------------- end to end *)

let bip86_taproot_wallet () =
  (* An end-to-end path: mnemonic to a Taproot receive address, the way a
     wallet would actually do it. *)
  let words =
    Bip39.normalize
      "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
       about"
  in
  check_bool "the phrase is valid" true (Bip39.check words);
  let seed = ok (Bip39.to_seed words) in
  let master = ok (Bip32.Secret.master seed) in
  let account =
    ok
      (Bip32.Secret.derive_path master
         (ok (Derivation_path.bip86 ~coin:(Derivation_path.coin_type Network.Mainnet) ~account:0l)))
  in
  let receive = ok (Bip32.Secret.derive_path account (ok (Derivation_path.of_string "m/0/0"))) in
  let internal_key = Key.Secret.public receive.Bip32.key in
  let si = ok (Taproot.spend_info ~internal_key ()) in
  let addr = Address.to_string ~network:Network.Mainnet (Taproot.address si) in
  (* BIP86's own test vector for this mnemonic. *)
  check_str "first receive address" "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"
    addr;
  (* And the whole thing must be spendable: tweak, sign, verify. *)
  let tweaked = ok (Taproot.tweak_secret receive.Bip32.key ~merkle_root:None) in
  let msg = Hash.sha256 "spend" in
  check_bool "signs for its own output key" true
    (Key.Schnorr.verify ~x_only:(Taproot.output_key si)
       (Key.Schnorr.sign ~key:tweaked ~msg ())
       ~msg)

let suite =
  [
    ( "derivation path",
      [
        Alcotest.test_case "parsing" `Quick path_parsing;
        Alcotest.test_case "helpers" `Quick path_helpers;
      ] );
    ( "bip32",
      [
        Alcotest.test_case "official vectors 1-4" `Quick bip32_vectors;
        Alcotest.test_case "vector 5: invalid keys" `Quick bip32_invalid_keys;
        Alcotest.test_case "hardened needs the private key" `Quick hardened_needs_private;
        Alcotest.test_case "master seed bounds" `Quick master_seed_bounds;
        Alcotest.test_case "fingerprints" `Quick fingerprints;
      ] );
    ( "bip39",
      [
        Alcotest.test_case "wordlist shape" `Quick bip39_wordlist_shape;
        Alcotest.test_case "Trezor vectors" `Slow bip39_vectors;
        Alcotest.test_case "rejections" `Quick bip39_rejections;
        Alcotest.test_case "passphrase" `Quick bip39_passphrase;
      ] );
    ("wallet", [ Alcotest.test_case "BIP86 taproot end to end" `Quick bip86_taproot_wallet ]);
  ]
