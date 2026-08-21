type error = [ `Invalid_length | `Invalid_checksum | `Invalid_format | `Msg of string ]

let pp_error ppf (e : [< error ]) = Error.pp ppf (e :> Error.t)
let wordlist = Bip39_wordlist.words

(* The list is sorted, so a binary search avoids building a hashtable at
   module initialisation time. *)
let index_of_word w =
  let lo = ref 0 and hi = ref (Array.length wordlist - 1) and found = ref (-1) in
  while !found < 0 && !lo <= !hi do
    let mid = (!lo + !hi) / 2 in
    let c = String.compare wordlist.(mid) w in
    if c = 0 then found := mid else if c < 0 then lo := mid + 1 else hi := mid - 1
  done;
  if !found < 0 then None else Some !found

let normalize s =
  String.split_on_char ' '
    (String.map (function '\t' | '\n' | '\r' -> ' ' | c -> c) (String.lowercase_ascii s))
  |> List.filter (fun w -> w <> "")

let is_ascii s = String.for_all (fun c -> Char.code c < 128) s
let bit_at s i = (Char.code s.[i / 8] lsr (7 - (i mod 8))) land 1

let of_entropy e =
  let n = String.length e in
  if n < 16 || n > 32 || n mod 4 <> 0 then Error `Invalid_length
  else
    let checksum_bits = n * 8 / 32 in
    let checksum = Hash.sha256 e in
    let total = (n * 8) + checksum_bits in
    let bit i = if i < n * 8 then bit_at e i else bit_at checksum (i - (n * 8)) in
    let words =
      List.init (total / 11) (fun w ->
          let v = ref 0 in
          for b = 0 to 10 do
            v := (!v lsl 1) lor bit ((w * 11) + b)
          done;
          wordlist.(!v))
    in
    Ok words

let indices words =
  List.fold_left
    (fun acc w ->
      match acc with
      | Error _ as e -> e
      | Ok l -> (
          match index_of_word w with None -> Error `Invalid_format | Some i -> Ok (i :: l)))
    (Ok []) words
  |> Result.map List.rev

let to_entropy words =
  let count = List.length words in
  if count < 12 || count > 24 || count mod 3 <> 0 then Error `Invalid_length
  else if not (List.for_all is_ascii words) then Error `Invalid_format
  else
    match indices words with
    | Error _ as e -> e
    | Ok idx ->
        let total = count * 11 in
        let entropy_bits = total * 32 / 33 in
        let n = entropy_bits / 8 in
        let bits = Array.make total 0 in
        List.iteri
          (fun w v ->
            for b = 0 to 10 do
              bits.((w * 11) + b) <- (v lsr (10 - b)) land 1
            done)
          idx;
        let entropy =
          String.init n (fun i ->
              let v = ref 0 in
              for b = 0 to 7 do
                v := (!v lsl 1) lor bits.((i * 8) + b)
              done;
              Char.chr !v)
        in
        let checksum = Hash.sha256 entropy in
        let ok = ref true in
        for i = 0 to total - entropy_bits - 1 do
          if bits.(entropy_bits + i) <> bit_at checksum i then ok := false
        done;
        if !ok then Ok entropy else Error `Invalid_checksum

let check words = match to_entropy words with Ok _ -> true | Error _ -> false

(* PBKDF2-HMAC-SHA512. BIP39 fixes the iteration count at 2048 and the
   output at 64 bytes, so this is the whole of it. *)
let pbkdf2_sha512 ~password ~salt ~iterations ~dk_len =
  let hlen = 64 in
  let blocks = (dk_len + hlen - 1) / hlen in
  let buf = Buffer.create (blocks * hlen) in
  for i = 1 to blocks do
    let block_index = String.init 4 (fun k -> Char.chr ((i lsr (8 * (3 - k))) land 0xff)) in
    let u = ref Digestif.SHA512.(to_raw_string (hmac_string ~key:password (salt ^ block_index))) in
    let acc = Bytes.of_string !u in
    for _ = 2 to iterations do
      (u := Digestif.SHA512.(to_raw_string (hmac_string ~key:password !u)));
      for k = 0 to hlen - 1 do
        Bytes.set acc k (Char.chr (Char.code (Bytes.get acc k) lxor Char.code !u.[k]))
      done
    done;
    Buffer.add_bytes buf acc
  done;
  String.sub (Buffer.contents buf) 0 dk_len

let seed_of_words ?(passphrase = "") words =
  pbkdf2_sha512 ~password:(String.concat " " words) ~salt:("mnemonic" ^ passphrase) ~iterations:2048
    ~dk_len:64

let to_seed_unchecked ?passphrase words = seed_of_words ?passphrase words

let to_seed ?passphrase words =
  if not (List.for_all is_ascii words) then Error `Invalid_format
  else
    match to_entropy words with Error _ as e -> e | Ok _ -> Ok (seed_of_words ?passphrase words)
