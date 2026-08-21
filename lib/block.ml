type error = Codec.error

(* Bitcoin's compact target: an exponent byte and a 24-bit mantissa, with
   the mantissa read as signed -- a set high bit means a negative target,
   which no valid header carries. *)
let target_of_bits bits =
  let n = Int32.to_int bits land 0xffffffff in
  let exponent = n lsr 24 in
  let mantissa = n land 0x007fffff in
  let negative = n land 0x00800000 <> 0 in
  if negative || mantissa = 0 then String.make 32 '\000'
  else
    let out = Bytes.make 32 '\000' in
    (* The mantissa's least significant byte sits at position [exponent]
       counting from the low end of the 32-byte value. *)
    let place i byte =
      let pos = 32 - exponent + i in
      if pos >= 0 && pos < 32 then Bytes.set out pos (Char.chr byte)
    in
    if exponent <= 3 then (
      (* Shifted right: only the top bytes of the mantissa survive. *)
      let m = mantissa lsr (8 * (3 - exponent)) in
      Bytes.set out 31 (Char.chr (m land 0xff));
      if exponent >= 2 then Bytes.set out 30 (Char.chr ((m lsr 8) land 0xff));
      if exponent >= 3 then Bytes.set out 29 (Char.chr ((m lsr 16) land 0xff)))
    else (
      place 0 ((mantissa lsr 16) land 0xff);
      place 1 ((mantissa lsr 8) land 0xff);
      place 2 (mantissa land 0xff));
    Bytes.to_string out

let bits_of_target target =
  (* Find the first non-zero byte to get the size. *)
  let i = ref 0 in
  while !i < 32 && target.[!i] = '\000' do
    incr i
  done;
  if !i = 32 then 0l
  else
    let size = 32 - !i in
    let byte k = if !i + k < 32 then Char.code target.[!i + k] else 0 in
    let m0 = byte 0 and m1 = byte 1 and m2 = byte 2 in
    let mantissa, size =
      (* A mantissa with its top bit set would read as negative, so shift
         down a byte and grow the exponent instead. *)
      if m0 > 0x7f then ((m0 lsl 8) lor m1, size + 1) else ((m0 lsl 16) lor (m1 lsl 8) lor m2, size)
    in
    Int32.logor (Int32.shift_left (Int32.of_int size) 24) (Int32.of_int mantissa)

module Header = struct
  type t = {
    version : int32;
    prev_block : string;
    merkle_root : string;
    time : int32;
    bits : int32;
    nonce : int32;
  }

  let size = 80

  let read r =
    let version = Codec.R.u32 r in
    let prev_block = Codec.R.take r 32 in
    let merkle_root = Codec.R.take r 32 in
    let time = Codec.R.u32 r in
    let bits = Codec.R.u32 r in
    let nonce = Codec.R.u32 r in
    { version; prev_block; merkle_root; time; bits; nonce }

  let write w t =
    Codec.W.u32 w t.version;
    Codec.W.bytes w t.prev_block;
    Codec.W.bytes w t.merkle_root;
    Codec.W.u32 w t.time;
    Codec.W.u32 w t.bits;
    Codec.W.u32 w t.nonce

  let parse s = Codec.R.run read s
  let serialize t = Codec.W.to_string write t
  let hash t = Hash.sha256d (serialize t)

  let hash_hex t =
    let h = hash t in
    String.concat "" (List.init 32 (fun i -> Printf.sprintf "%02x" (Char.code h.[31 - i])))

  let target t = target_of_bits t.bits

  let meets_target t =
    (* The hash is little-endian; compare it against the big-endian target
       by reversing, then comparing as unsigned big-endian numbers. *)
    let h = hash t in
    let be = String.init 32 (fun i -> h.[31 - i]) in
    let tgt = target t in
    (* An all-zero target is the degenerate encoding and no hash meets it. *)
    if String.equal tgt (String.make 32 '\000') then false else String.compare be tgt <= 0

  let difficulty t =
    let to_float s =
      let v = ref 0.0 in
      String.iter (fun c -> v := (!v *. 256.0) +. float_of_int (Char.code c)) s;
      !v
    in
    let diff1 = to_float (target_of_bits 0x1d00ffffl) in
    let cur = to_float (target t) in
    if cur = 0.0 then infinity else diff1 /. cur
end

(* Levels are folded pairwise; an odd level duplicates its last hash. That
   is consensus behaviour, not a bug to fix -- see CVE-2012-2459 and
   is_merkle_mutation. *)
let rec merkle_level = function
  | [] -> []
  | [ h ] -> [ Hash.sha256d (h ^ h) ]
  | a :: b :: rest -> Hash.sha256d (a ^ b) :: merkle_level rest

let rec merkle_fold = function
  | [] -> String.make 32 '\000'
  | [ root ] -> root
  | level -> merkle_fold (merkle_level level)

let merkle_root txids = merkle_fold txids

let is_merkle_mutation txids =
  let rec go = function
    | [] | [ _ ] -> false
    | level ->
        let rec pairs = function a :: b :: rest -> String.equal a b || pairs rest | _ -> false in
        (* An odd level duplicates its last hash, so a level whose last two
         entries already match yields the same root as a shorter list. *)
        (List.length level mod 2 = 0 && pairs level) || go (merkle_level level)
  in
  go txids

type t = { header : Header.t; transactions : Tx.t list }

let parse s =
  Codec.R.run
    (fun r ->
      let header = Header.read r in
      let transactions = Codec.R.vector r Tx.read in
      { header; transactions })
    s

let serialize t =
  Codec.W.to_string
    (fun w () ->
      Header.write w t.header;
      Codec.W.vector w (fun w tx -> Tx.write w tx) t.transactions)
    ()

let hash t = Header.hash t.header
let txids t = List.map Tx.txid t.transactions
let computed_merkle_root t = merkle_root (txids t)
let has_valid_merkle_root t = String.equal (computed_merkle_root t) t.header.Header.merkle_root
let coinbase t = match t.transactions with tx :: _ when Tx.is_coinbase tx -> Some tx | _ -> None
let total_size t = String.length (serialize t)
let weight t = List.fold_left (fun acc tx -> acc + Tx.weight tx) (Header.size * 4) t.transactions
