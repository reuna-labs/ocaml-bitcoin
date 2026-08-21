(* Base58 by byte-array long division, following Bitcoin Core's base58.cpp.
   Deliberately not using Zarith: the numbers are small and fixed-width in
   practice, and avoiding a bignum here is one fewer dependency on the path
   to a GMP-free unikernel. *)

type error = [ `Invalid_format | `Invalid_length | `Invalid_checksum ]

let alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

let inverse =
  let t = Array.make 256 (-1) in
  String.iteri (fun i c -> t.(Char.code c) <- i) alphabet;
  t

let count_leading c s =
  let n = String.length s in
  let i = ref 0 in
  while !i < n && s.[!i] = c do
    incr i
  done;
  !i

let encode input =
  let n = String.length input in
  let zeros = count_leading '\000' input in
  (* log(256)/log(58) rounded up, as a rational: 138/100. *)
  let size = ((n - zeros) * 138 / 100) + 1 in
  let buf = Bytes.make size '\000' in
  let length = ref 0 in
  for k = zeros to n - 1 do
    let carry = ref (Char.code input.[k]) in
    let i = ref 0 in
    let j = ref (size - 1) in
    while (!carry <> 0 || !i < !length) && !j >= 0 do
      carry := !carry + (256 * Char.code (Bytes.get buf !j));
      Bytes.set buf !j (Char.chr (!carry mod 58));
      carry := !carry / 58;
      decr j;
      incr i
    done;
    length := !i
  done;
  let start = size - !length in
  String.init (zeros + !length) (fun i ->
      if i < zeros then '1' else alphabet.[Char.code (Bytes.get buf (start + i - zeros))])

let decode s =
  let n = String.length s in
  let ones = count_leading '1' s in
  (* log(58)/log(256) rounded up, as a rational: 733/1000. *)
  let size = ((n - ones) * 733 / 1000) + 1 in
  let buf = Bytes.make size '\000' in
  let length = ref 0 in
  let bad = ref false in
  let k = ref ones in
  while (not !bad) && !k < n do
    let d = inverse.(Char.code s.[!k]) in
    if d < 0 then bad := true
    else
      let carry = ref d in
      let i = ref 0 in
      let j = ref (size - 1) in
      while (!carry <> 0 || !i < !length) && !j >= 0 do
        carry := !carry + (58 * Char.code (Bytes.get buf !j));
        Bytes.set buf !j (Char.chr (!carry land 0xff));
        carry := !carry lsr 8;
        decr j;
        incr i
      done;
      length := !i;
      incr k
  done;
  if !bad then Error `Invalid_format
  else
    let start = size - !length in
    Ok
      (String.init (ones + !length) (fun i ->
           if i < ones then '\000' else Bytes.get buf (start + i - ones)))

let encode_check payload = encode (payload ^ Hash.checksum4 payload)

let decode_check s =
  match decode s with
  | Error _ as e -> e
  | Ok raw ->
      let n = String.length raw in
      if n < 4 then Error `Invalid_length
      else
        let payload = String.sub raw 0 (n - 4) in
        if String.equal (String.sub raw (n - 4) 4) (Hash.checksum4 payload) then Ok payload
        else Error `Invalid_checksum
