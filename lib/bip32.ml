type error =
  [ `Invalid_length
  | `Invalid_range
  | `Invalid_format
  | `Invalid_checksum
  | `Invalid_version
  | `Not_on_curve
  | `At_infinity
  | `Hardened_from_public
  | `Msg of string ]

let pp_error ppf (e : [< error ]) = Error.pp ppf (e :> Error.t)

type 'a extended = {
  key : 'a;
  chain_code : string;
  depth : int;
  parent_fingerprint : string;
  child_number : int32;
}

module Native = Mirage_crypto_bip32
module K = Mirage_crypto_secp256k1

let lift r = Result.map_error (fun (e : Native.error) -> (e :> error)) r

let key_result r =
  Result.map_error
    (fun (e : Key.error) ->
      match e with
      | `Wrong_hrp -> `Msg "unexpected key error in BIP32"
      | ( `Invalid_length | `Invalid_range | `Invalid_format | `Invalid_checksum | `Not_on_curve
        | `At_infinity | `Msg _ ) as e ->
          e)
    r

let import key (n : _ Native.extended) =
  Result.map
    (fun key ->
      {
        key;
        chain_code = n.chain_code;
        depth = n.depth;
        parent_fingerprint = n.parent_fingerprint;
        child_number = n.child_number;
      })
    key

let encode ~version key t =
  if t.depth < 0 || t.depth > 255 then Error `Invalid_range
  else if String.length t.chain_code <> 32 || String.length t.parent_fingerprint <> 4 then
    Error `Invalid_length
  else
    let b = Bytes.create 78 in
    Bytes.set_int32_be b 0 version;
    Bytes.set b 4 (Char.chr t.depth);
    Bytes.blit_string t.parent_fingerprint 0 b 5 4;
    Bytes.set_int32_be b 9 t.child_number;
    Bytes.blit_string t.chain_code 0 b 13 32;
    Bytes.blit_string key 0 b 45 33;
    Ok (Bytes.to_string b)

let unwrap = function Ok x -> x | Error _ -> invalid_arg "Bitcoin.Bip32: malformed extended key"

module Public = struct
  type t = Key.Public.t extended

  let from_native n = import (key_result (Key.Public.of_octets (K.pub_to_octets n.Native.key))) n

  let of_octets raw =
    Result.bind
      (lift (Native.Public.of_octets raw))
      (fun (n, version) -> Result.map (fun t -> (t, version)) (from_native n))

  let to_native t =
    Result.bind
      (encode ~version:0l (Key.Public.to_octets ~compress:true t.key) t)
      (fun raw -> Result.map fst (lift (Native.Public.of_octets raw)))

  let to_octets ~version t = Native.Public.to_octets ~version (unwrap (to_native t))

  let derive t i =
    Result.bind (to_native t) (fun n -> Result.bind (lift (Native.Public.derive n i)) from_native)

  let derive_path t path =
    Result.bind (to_native t) (fun n ->
        Result.bind (lift (Native.Public.derive_path n (Derivation_path.to_list path))) from_native)

  let fingerprint t = Native.Public.fingerprint (unwrap (to_native t))

  let to_base58 ~network t =
    Base58.encode_check (to_octets ~version:(Network.bip32_public network) t)

  let of_base58 s =
    match Base58.decode_check s with
    | Error e -> Error (e :> error)
    | Ok raw -> (
        match of_octets raw with
        | Error _ as e -> e
        | Ok (t, version) -> (
            match Network.of_bip32_version version with
            | Some (networks, `Public) -> Ok (t, networks)
            | Some (_, `Private) | None -> Error `Invalid_version))
end

module Secret = struct
  type t = Key.Secret.t extended

  let from_native n = import (key_result (Key.Secret.of_octets (K.priv_to_octets n.Native.key))) n

  let of_octets raw =
    Result.bind
      (lift (Native.Secret.of_octets raw))
      (fun (n, version) -> Result.map (fun t -> (t, version)) (from_native n))

  let to_native t =
    Result.bind
      (encode ~version:0l ("\000" ^ Key.Secret.to_octets t.key) t)
      (fun raw -> Result.map fst (lift (Native.Secret.of_octets raw)))

  let to_octets ~version t = Native.Secret.to_octets ~version (unwrap (to_native t))

  let derive t i =
    Result.bind (to_native t) (fun n -> Result.bind (lift (Native.Secret.derive n i)) from_native)

  let derive_path t path =
    Result.bind (to_native t) (fun n ->
        Result.bind (lift (Native.Secret.derive_path n (Derivation_path.to_list path))) from_native)

  let master seed = Result.bind (lift (Native.Secret.master seed)) from_native
  let public t = unwrap (Public.from_native (Native.Secret.public (unwrap (to_native t))))
  let fingerprint t = Native.Secret.fingerprint (unwrap (to_native t))

  let to_base58 ~network t =
    Base58.encode_check (to_octets ~version:(Network.bip32_private network) t)

  let of_base58 s =
    match Base58.decode_check s with
    | Error e -> Error (e :> error)
    | Ok raw -> (
        match of_octets raw with
        | Error _ as e -> e
        | Ok (t, version) -> (
            match Network.of_bip32_version version with
            | Some (networks, `Private) -> Ok (t, networks)
            | Some (_, `Public) | None -> Error `Invalid_version))
end
