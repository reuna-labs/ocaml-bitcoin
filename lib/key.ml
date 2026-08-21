module B = Bitcoin_backend.Backend

type error =
  [ `Invalid_length
  | `Invalid_range
  | `Invalid_format
  | `Invalid_checksum
  | `Not_on_curve
  | `At_infinity
  | `Wrong_hrp
  | `Msg of string ]

let pp_error ppf (e : [< error ]) = Error.pp ppf (e :> Error.t)
let of_backend = function Ok v -> Ok v | Error (#B.error as e) -> Error (e :> error)

(* --- 256-bit helpers on big-endian byte strings -------------------------- *)

(* n is odd, so this is floor(n/2), which is the bound BIP146 states. *)
let half_order =
  let n = B.order in
  let out = Bytes.create 32 in
  let carry = ref 0 in
  for i = 0 to 31 do
    let v = Char.code n.[i] in
    Bytes.set out i (Char.chr ((!carry lsl 7) lor (v lsr 1)));
    carry := v land 1
  done;
  Bytes.to_string out

(* n - x, for x in [1, n). *)
let sub_from_order x =
  let out = Bytes.create 32 in
  let borrow = ref 0 in
  for i = 31 downto 0 do
    let d = Char.code B.order.[i] - Char.code x.[i] - !borrow in
    if d < 0 then (
      Bytes.set out i (Char.chr (d + 256));
      borrow := 1)
    else (
      Bytes.set out i (Char.chr d);
      borrow := 0)
  done;
  Bytes.to_string out

module Public = struct
  type t = { point : B.public; compressed : bool }

  let of_octets s =
    match B.public_of_octets s with
    | Error e -> Error (e :> error)
    | Ok point -> Ok { point; compressed = String.length s = 33 }

  let to_octets ?compress p =
    let compress = match compress with Some c -> c | None -> p.compressed in
    B.public_to_octets ~compress p.point

  let is_compressed p = p.compressed
  let compress p = { p with compressed = true }
  let equal a b = B.public_equal a.point b.point
  let hash160 p = Hash.hash160 (to_octets p)
  let x_only p = B.public_x p.point
  let has_even_y p = B.public_has_even_y p.point

  let of_x_only x =
    match B.public_of_x_only x with
    | Error e -> Error (e :> error)
    | Ok point -> Ok { point; compressed = true }

  let add_tweak p t =
    match B.public_add_tweak p.point t with
    | Error e -> Error (e :> error)
    | Ok point -> Ok { point; compressed = p.compressed }

  let negate p = { p with point = B.public_negate p.point }

  let combine = function
    | [] -> Error `Invalid_format
    | first :: rest ->
        List.fold_left
          (fun acc p ->
            match acc with
            | Error _ as e -> e
            | Ok a -> (
                match B.public_add a.point p.point with
                | Error e -> Error (e :> error)
                | Ok point -> Ok { a with point }))
          (Ok first) rest

  let make point compressed = { point; compressed }
end

module Secret = struct
  type t = B.secret

  let of_octets s = of_backend (B.secret_of_octets s)
  let to_octets = B.secret_to_octets
  let equal = B.secret_equal
  let public d = Public.make (B.public_of_secret d) true
  let add_tweak d t = of_backend (B.secret_add d t)
  let negate = B.secret_negate

  let of_wif s =
    match Base58.decode_check s with
    | Error e -> Error (e :> error)
    | Ok payload -> (
        let n = String.length payload in
        if n <> 33 && n <> 34 then Error `Invalid_length
        else
          match Network.of_wif_version (Char.code payload.[0]) with
          | [] -> Error `Invalid_format
          | networks -> (
              (* A 34-byte payload carries a trailing 0x01 meaning "the public
             key is used compressed". Any other trailing byte is malformed. *)
              let compressed =
                if n = 34 then if payload.[33] = '\001' then Some `Compressed else None
                else Some `Uncompressed
              in
              match compressed with
              | None -> Error `Invalid_format
              | Some c -> (
                  match of_octets (String.sub payload 1 32) with
                  | Error _ as e -> e
                  | Ok d -> Ok (d, c, networks))))

  let to_wif ~network ?(compressed = true) d =
    let payload =
      String.make 1 (Char.chr (Network.wif_version network))
      ^ to_octets d
      ^ if compressed then "\001" else ""
    in
    Base58.encode_check payload
end

(* --- ECDSA -------------------------------------------------------------- *)

module Ecdsa = struct
  type t = { r : string; s : string }

  let r t = t.r
  let s t = t.s

  let sign ~key ~digest =
    let r, s = B.ecdsa_sign ~secret:key ~digest in
    { r; s }

  let verify ~key t ~digest = B.ecdsa_verify ~public:key.Public.point ~r:t.r ~s:t.s ~digest

  let of_compact s =
    if String.length s <> 64 then Error `Invalid_length
    else Ok { r = String.sub s 0 32; s = String.sub s 32 32 }

  let to_compact t = t.r ^ t.s
  let is_low_s t = String.compare t.s half_order <= 0
  let normalize_s t = if is_low_s t then t else { t with s = sub_from_order t.s }

  (* DER integers are big-endian two's complement: strip leading zeros, then
     re-add one if the top bit would otherwise read as a sign bit. *)
  let der_int_of_scalar x =
    let i = ref 0 in
    while !i < 31 && x.[!i] = '\000' do
      incr i
    done;
    let body = String.sub x !i (32 - !i) in
    if Char.code body.[0] land 0x80 <> 0 then "\000" ^ body else body

  let to_der t =
    let r = der_int_of_scalar t.r and s = der_int_of_scalar t.s in
    let part x = "\002" ^ String.make 1 (Char.chr (String.length x)) ^ x in
    let body = part r ^ part s in
    "\048" ^ String.make 1 (Char.chr (String.length body)) ^ body

  (* Strict DER per BIP66. Everything not explicitly permitted is rejected:
     the laxness this replaces is what made signatures malleable. *)
  let of_der d =
    let n = String.length d in
    let byte i = Char.code d.[i] in
    let fail = Error `Invalid_format in
    (* Shortest possible is 8 bytes (two one-byte integers); longest is 72. *)
    if n < 8 || n > 72 then Error `Invalid_length
    else if byte 0 <> 0x30 then fail
    else if byte 1 <> n - 2 then fail
    else if byte 2 <> 0x02 then fail
    else
      let len_r = byte 3 in
      if len_r = 0 then fail
      else if 4 + len_r + 2 > n then fail
      else if byte (4 + len_r) <> 0x02 then fail
      else
        let len_s = byte (5 + len_r) in
        if len_s = 0 then fail
        else if 6 + len_r + len_s <> n then fail
        else
          let take off len = String.sub d off len in
          let ri = take 4 len_r and si = take (6 + len_r) len_s in
          let valid_int x =
            let l = String.length x in
            (* Not negative. *)
            Char.code x.[0] land 0x80 = 0
            (* No leading zero unless the next byte needs the sign bit. *)
            && not (l > 1 && x.[0] = '\000' && Char.code x.[1] land 0x80 = 0)
          in
          if not (valid_int ri && valid_int si) then fail
          else if String.length ri > 33 || String.length si > 33 then Error `Invalid_range
          else
            let pad x =
              let x = if String.length x = 33 then String.sub x 1 32 else x in
              String.make (32 - String.length x) '\000' ^ x
            in
            Ok { r = pad ri; s = pad si }
end

(* --- BIP340 Schnorr ----------------------------------------------------- *)

module Schnorr = struct
  type t = string

  let sign ~key ?(aux_rand = String.make 32 '\000') ~msg () =
    B.schnorr_sign ~secret:key ~aux_rand ~msg

  let verify ~x_only t ~msg = B.schnorr_verify ~x_only ~signature:t ~msg
  let of_octets s = if String.length s <> 64 then Error `Invalid_length else Ok s
  let to_octets t = t
end
