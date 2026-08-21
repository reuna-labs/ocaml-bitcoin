type error =
  [ `Invalid_format
  | `Invalid_length
  | `Invalid_checksum
  | `Invalid_version
  | `Wrong_variant
  | `Wrong_hrp ]

type encoding = Bech32 | Bech32m

let max_length = 90
let charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

let inverse =
  let t = Array.make 256 (-1) in
  String.iteri (fun i c -> t.(Char.code c) <- i) charset;
  t

let const = function Bech32 -> 1 | Bech32m -> 0x2bc830a3
let generator = [| 0x3b6a57b2; 0x26508e6d; 0x1ea119fa; 0x3d4233dd; 0x2a1462b3 |]

let polymod_step chk v =
  let top = chk lsr 25 in
  let chk = ref (((chk land 0x1ffffff) lsl 5) lxor v) in
  for i = 0 to 4 do
    if (top lsr i) land 1 <> 0 then chk := !chk lxor generator.(i)
  done;
  !chk

(* The checksum is computed over the expanded hrp followed by the data. *)
let polymod_hrp hrp =
  let n = String.length hrp in
  let chk = ref 1 in
  for i = 0 to n - 1 do
    chk := polymod_step !chk (Char.code hrp.[i] lsr 5)
  done;
  chk := polymod_step !chk 0;
  for i = 0 to n - 1 do
    chk := polymod_step !chk (Char.code hrp.[i] land 31)
  done;
  !chk

let polymod_data chk data = Array.fold_left polymod_step chk data

(* An hrp is 1..83 characters, each printable US-ASCII. *)
let valid_hrp hrp =
  let n = String.length hrp in
  n >= 1 && n <= 83
  &&
  let ok = ref true in
  String.iter
    (fun c ->
      let c = Char.code c in
      if c < 33 || c > 126 then ok := false)
    hrp;
  !ok

let has_upper s =
  let up = ref false in
  String.iter (fun c -> if c >= 'A' && c <= 'Z' then up := true) s;
  !up

let encode enc ~hrp ~data =
  (* An uppercase hrp would yield a mixed-case string, which cannot be
     decoded; BIP173 requires encoders to emit lowercase regardless. *)
  if (not (valid_hrp hrp)) || has_upper hrp then Error `Invalid_format
  else if Array.exists (fun v -> v < 0 || v > 31) data then Error `Invalid_format
  else
    let chk = polymod_data (polymod_hrp hrp) data in
    (* Six zero groups are appended before the constant is mixed in. *)
    let chk = ref chk in
    for _ = 1 to 6 do
      chk := polymod_step !chk 0
    done;
    let m = !chk lxor const enc in
    let n = Array.length data in
    let buf = Buffer.create (String.length hrp + n + 7) in
    Buffer.add_string buf hrp;
    Buffer.add_char buf '1';
    Array.iter (fun d -> Buffer.add_char buf charset.[d]) data;
    for i = 0 to 5 do
      Buffer.add_char buf charset.[(m lsr (5 * (5 - i))) land 31]
    done;
    Ok (Buffer.contents buf)

let decode ?(limit = max_length) s =
  let n = String.length s in
  let has_lower = ref false and has_up = ref false in
  String.iter
    (fun c ->
      if c >= 'a' && c <= 'z' then has_lower := true;
      if c >= 'A' && c <= 'Z' then has_up := true)
    s;
  if n > limit then Error `Invalid_length
  else if !has_lower && !has_up then Error `Invalid_format
  else
    let s = String.lowercase_ascii s in
    match String.rindex_opt s '1' with
    | None -> Error `Invalid_format
    | Some sep -> (
        if
          (* At least one hrp character before, and six checksum characters after. *)
          sep < 1 || sep + 7 > n
        then Error `Invalid_format
        else
          let hrp = String.sub s 0 sep in
          if not (valid_hrp hrp) then Error `Invalid_format
          else
            let count = n - sep - 1 in
            let values = Array.make count 0 in
            let bad = ref false in
            for i = 0 to count - 1 do
              let d = inverse.(Char.code s.[sep + 1 + i]) in
              if d < 0 then bad := true else values.(i) <- d
            done;
            if !bad then Error `Invalid_format
            else
              match polymod_data (polymod_hrp hrp) values with
              | 1 -> Ok (Bech32, hrp, Array.sub values 0 (count - 6))
              | 0x2bc830a3 -> Ok (Bech32m, hrp, Array.sub values 0 (count - 6))
              | _ -> Error `Invalid_checksum)

(* Regroup [from]-bit values into [into]-bit values, most significant first.
   Encoding pads the final group with zeroes; decoding must not, and any
   leftover bits must be zero and fewer than [from] of them. *)
let convertbits ~pad data ~from ~into =
  let maxv = (1 lsl into) - 1 in
  let out = Buffer.create (Array.length data) in
  let acc = ref 0 and bits = ref 0 and ok = ref true in
  Array.iter
    (fun v ->
      if v < 0 || v lsr from <> 0 then ok := false;
      acc := (!acc lsl from) lor v;
      bits := !bits + from;
      while !bits >= into do
        bits := !bits - into;
        Buffer.add_char out (Char.chr ((!acc lsr !bits) land maxv))
      done)
    data;
  if pad then (
    if !bits > 0 then Buffer.add_char out (Char.chr ((!acc lsl (into - !bits)) land maxv)))
  else if !bits >= from || (!acc lsl (into - !bits)) land maxv <> 0 then ok := false;
  if !ok then Some (Buffer.contents out) else None

let bytes_to_groups s = Array.init (String.length s) (fun i -> Char.code s.[i])

let check_program_length ~version ~len =
  if len < 2 || len > 40 then Error `Invalid_length
  else if version = 0 && len <> 20 && len <> 32 then Error `Invalid_length
  else Ok ()

let encode_segwit ~hrp ~version ~program =
  if version < 0 || version > 16 then Error `Invalid_version
  else
    match check_program_length ~version ~len:(String.length program) with
    | Error _ as e -> e
    | Ok () -> (
        match convertbits ~pad:true (bytes_to_groups program) ~from:8 ~into:5 with
        | None -> Error `Invalid_format
        | Some prog5 ->
            let enc = if version = 0 then Bech32 else Bech32m in
            let data =
              Array.init
                (String.length prog5 + 1)
                (fun i -> if i = 0 then version else Char.code prog5.[i - 1])
            in
            encode enc ~hrp ~data)

let decode_segwit_any s =
  match decode s with
  | Error _ as e -> e
  | Ok (_, _, [||]) -> Error `Invalid_format
  | Ok (enc, hrp, data) -> (
      let version = data.(0) in
      if version < 0 || version > 16 then Error `Invalid_version
      else if version = 0 && enc <> Bech32 then Error `Wrong_variant
      else if version <> 0 && enc <> Bech32m then Error `Wrong_variant
      else
        match convertbits ~pad:false (Array.sub data 1 (Array.length data - 1)) ~from:5 ~into:8 with
        | None -> Error `Invalid_format
        | Some program -> (
            match check_program_length ~version ~len:(String.length program) with
            | Error _ as e -> e
            | Ok () -> Ok (hrp, version, program)))

let decode_segwit ~hrp s =
  match decode_segwit_any s with
  | Error _ as e -> e
  | Ok (hrp', version, program) ->
      if String.equal hrp hrp' then Ok (version, program) else Error `Wrong_hrp
