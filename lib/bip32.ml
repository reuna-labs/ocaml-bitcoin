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

let hmac512 ~key data = Digestif.SHA512.(to_raw_string (hmac_string ~key data))
let zero_fingerprint = String.make 4 '\000'

let of_key_error : Key.error -> error = function
  | ( `Invalid_length | `Invalid_range | `Invalid_format | `Invalid_checksum | `Not_on_curve
    | `At_infinity | `Msg _ ) as e ->
      e
  | `Wrong_hrp -> `Msg "unexpected key error in derivation"

(* The 78-byte serialization shared by both kinds, before Base58Check. *)
let write_extended w ~version ~depth ~parent_fingerprint ~child_number ~chain_code ~key_data =
  Codec.W.u32_be w version;
  Codec.W.u8 w depth;
  Codec.W.bytes w parent_fingerprint;
  Codec.W.u32_be w child_number;
  Codec.W.bytes w chain_code;
  Codec.W.bytes w key_data

let parse_extended s =
  if String.length s <> 78 then Error `Invalid_length
  else
    let version = ref 0l in
    for i = 0 to 3 do
      version := Int32.logor (Int32.shift_left !version 8) (Int32.of_int (Char.code s.[i]))
    done;
    let depth = Char.code s.[4] in
    let parent_fingerprint = String.sub s 5 4 in
    let child_number =
      let v = ref 0l in
      for i = 9 to 12 do
        v := Int32.logor (Int32.shift_left !v 8) (Int32.of_int (Char.code s.[i]))
      done;
      !v
    in
    let chain_code = String.sub s 13 32 in
    let key_data = String.sub s 45 33 in
    (* A master key has depth zero, so it can have neither a parent nor an
       index; anything else is a malformed or forged key. *)
    if depth = 0 && not (String.equal parent_fingerprint zero_fingerprint) then
      Error `Invalid_format
    else if depth = 0 && not (Int32.equal child_number 0l) then Error `Invalid_format
    else Ok (!version, depth, parent_fingerprint, child_number, chain_code, key_data)

module Public = struct
  type t = Key.Public.t extended

  let fingerprint t = String.sub (Key.Public.hash160 t.key) 0 4

  let derive t i =
    if Derivation_path.is_hardened i then Error `Hardened_from_public
    else
      let data =
        Codec.W.to_string
          (fun w () ->
            Codec.W.bytes w (Key.Public.to_octets ~compress:true t.key);
            Codec.W.u32_be w i)
          ()
      in
      let hash = hmac512 ~key:t.chain_code data in
      let il = String.sub hash 0 32 and ir = String.sub hash 32 32 in
      match Key.Public.add_tweak t.key il with
      | Error e -> Error (of_key_error e)
      | Ok key ->
          Ok
            {
              key;
              chain_code = ir;
              depth = t.depth + 1;
              parent_fingerprint = fingerprint t;
              child_number = i;
            }

  let derive_path t path =
    List.fold_left
      (fun acc i -> match acc with Error _ as e -> e | Ok t -> derive t i)
      (Ok t) (Derivation_path.to_list path)

  let to_octets ~version t =
    Codec.W.to_string
      (fun w () ->
        write_extended w ~version ~depth:t.depth ~parent_fingerprint:t.parent_fingerprint
          ~child_number:t.child_number ~chain_code:t.chain_code
          ~key_data:(Key.Public.to_octets ~compress:true t.key))
      ()

  let of_octets raw =
    match parse_extended raw with
    | Error _ as e -> e
    | Ok (version, depth, parent_fingerprint, child_number, chain_code, key_data) -> (
        (* Must be a compressed point. A 0x00 prefix here is a private key
           wearing a public version, which is one of BIP32 vector 5's cases. *)
        match Key.Public.of_octets key_data with
        | Error e -> Error (of_key_error e)
        | Ok key -> Ok ({ key; chain_code; depth; parent_fingerprint; child_number }, version))

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

  let public t =
    {
      key = Key.Secret.public t.key;
      chain_code = t.chain_code;
      depth = t.depth;
      parent_fingerprint = t.parent_fingerprint;
      child_number = t.child_number;
    }

  let fingerprint t = Public.fingerprint (public t)

  let master seed =
    let n = String.length seed in
    if n < 16 || n > 64 then Error `Invalid_length
    else
      let hash = hmac512 ~key:"Bitcoin seed" seed in
      let il = String.sub hash 0 32 and ir = String.sub hash 32 32 in
      match Key.Secret.of_octets il with
      | Error _ ->
          (* BIP32: if the key is zero or beyond the curve order the seed is
           invalid. It says to pick another seed, not to adjust this one. *)
          Error `Invalid_range
      | Ok key ->
          Ok
            {
              key;
              chain_code = ir;
              depth = 0;
              parent_fingerprint = zero_fingerprint;
              child_number = 0l;
            }

  let derive t i =
    let data =
      Codec.W.to_string
        (fun w () ->
          if Derivation_path.is_hardened i then (
            (* Hardened derivation feeds the private key, which is why it
               cannot be done from an extended public key. *)
            Codec.W.u8 w 0x00;
            Codec.W.bytes w (Key.Secret.to_octets t.key))
          else Codec.W.bytes w (Key.Public.to_octets ~compress:true (Key.Secret.public t.key));
          Codec.W.u32_be w i)
        ()
    in
    let hash = hmac512 ~key:t.chain_code data in
    let il = String.sub hash 0 32 and ir = String.sub hash 32 32 in
    match Key.Secret.add_tweak t.key il with
    | Error e -> Error (of_key_error e)
    | Ok key ->
        Ok
          {
            key;
            chain_code = ir;
            depth = t.depth + 1;
            parent_fingerprint = fingerprint t;
            child_number = i;
          }

  let derive_path t path =
    List.fold_left
      (fun acc i -> match acc with Error _ as e -> e | Ok t -> derive t i)
      (Ok t) (Derivation_path.to_list path)

  let to_octets ~version t =
    Codec.W.to_string
      (fun w () ->
        write_extended w ~version ~depth:t.depth ~parent_fingerprint:t.parent_fingerprint
          ~child_number:t.child_number ~chain_code:t.chain_code
          ~key_data:("\000" ^ Key.Secret.to_octets t.key))
      ()

  let of_octets raw =
    match parse_extended raw with
    | Error _ as e -> e
    | Ok (version, depth, parent_fingerprint, child_number, chain_code, key_data) -> (
        if
          (* A private key is padded to 33 bytes with a leading zero; any other
           prefix is one of BIP32 vector 5's forgeries. *)
          key_data.[0] <> '\000'
        then Error `Invalid_format
        else
          match Key.Secret.of_octets (String.sub key_data 1 32) with
          | Error e -> Error (of_key_error e)
          | Ok key -> Ok ({ key; chain_code; depth; parent_fingerprint; child_number }, version))

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
