(* A smoke test: exercise enough of the library that the linker must pull in
   the hashing, curve, serialization and address code, then report. If this
   runs inside a Solo5 unikernel, the no-Unix claim holds end to end. *)
module Main = struct
  let start () =
    let open Bitcoin in
    let ok = function Ok x -> x | Error _ -> failwith "unexpected" in
    let secret = ok (Key.Secret.of_octets (Hash.sha256 "unikernel smoke test")) in
    let public = Key.Secret.public secret in
    let si = ok (Taproot.spend_info ~internal_key:public ()) in
    let addr = Address.to_string ~network:Network.Mainnet (Taproot.address si) in
    let digest = Hash.sha256d "message" in
    let sg = Key.Ecdsa.sign ~key:secret ~digest in
    let verified = Key.Ecdsa.verify ~key:public sg ~digest in
    let schnorr = Key.Schnorr.sign ~key:secret ~msg:digest () in
    let sverified = Key.Schnorr.verify ~x_only:(Key.Public.x_only public) schnorr ~msg:digest in
    let seed =
      ok
        (Bip39.to_seed
           (Bip39.normalize
              "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
               abandon about"))
    in
    let master = ok (Bip32.Secret.master seed) in
    Logs.info (fun f -> f "taproot address: %s" addr);
    Logs.info (fun f -> f "ecdsa verified: %b  schnorr verified: %b" verified sverified);
    Logs.info (fun f ->
        f "bip32 master xprv: %s" (Bip32.Secret.to_base58 ~network:Network.Mainnet master));
    Logs.info (fun f -> f "bitcoin library linked and ran inside a unikernel");
    Lwt.return_unit
end
