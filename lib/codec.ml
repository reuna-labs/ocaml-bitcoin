type error =
  [ `Eof of int
  | `Trailing of int
  | `Non_canonical_varint
  | `Overflow of string
  | `Invalid_format
  | `Msg of string ]

let pp_error ppf (e : [< error ]) = Error.pp ppf (e :> Error.t)

module W = struct
  type t = Buffer.t

  let create ?(size = 256) () = Buffer.create size
  let contents = Buffer.contents
  let length = Buffer.length
  let byte = Buffer.add_char
  let bytes = Buffer.add_string
  let u8 w n = Buffer.add_char w (Char.chr (n land 0xff))

  let u16 w n =
    u8 w n;
    u8 w (n lsr 8)

  let u32 w n =
    for i = 0 to 3 do
      Buffer.add_char w (Char.chr (Int32.to_int (Int32.shift_right_logical n (8 * i)) land 0xff))
    done

  let u64 w n =
    for i = 0 to 7 do
      Buffer.add_char w (Char.chr (Int64.to_int (Int64.shift_right_logical n (8 * i)) land 0xff))
    done

  let i64 = u64

  let u16_be w n =
    u8 w (n lsr 8);
    u8 w n

  let u32_be w n =
    for i = 3 downto 0 do
      Buffer.add_char w (Char.chr (Int32.to_int (Int32.shift_right_logical n (8 * i)) land 0xff))
    done

  (* Unsigned comparison: Bitcoin's CompactSize covers the full 64-bit range,
     so a value with the top bit set must still be treated as large. *)
  let ule a b = Int64.unsigned_compare a b <= 0

  let varint w n =
    if ule n 0xfcL then u8 w (Int64.to_int n)
    else if ule n 0xffffL then (
      u8 w 0xfd;
      u16 w (Int64.to_int n))
    else if ule n 0xffffffffL then (
      u8 w 0xfe;
      u32 w (Int64.to_int32 n))
    else (
      u8 w 0xff;
      u64 w n)

  let varstr w s =
    varint w (Int64.of_int (String.length s));
    bytes w s

  let vector w f l =
    varint w (Int64.of_int (List.length l));
    List.iter (f w) l

  let with_length w f =
    let scratch = create ~size:64 () in
    f scratch;
    varstr w (contents scratch)

  let to_string f x =
    let w = create () in
    f w x;
    contents w

  let sha256 f x = Hash.sha256 (to_string f x)
  let sha256d f x = Hash.sha256d (to_string f x)
  let tagged ~tag f x = Hash.tagged ~tag (to_string f x)
end

module R = struct
  type t = { src : string; mutable pos : int; stop : int }

  exception Parse_error of error

  let fail (e : [< error ]) = raise (Parse_error (e :> error))
  let pos r = r.pos
  let remaining r = r.stop - r.pos
  let eof r = r.pos >= r.stop
  let need r n = if remaining r < n then fail (`Eof (n - remaining r))

  let peek_byte r =
    need r 1;
    r.src.[r.pos]

  let byte r =
    need r 1;
    let c = r.src.[r.pos] in
    r.pos <- r.pos + 1;
    c

  let take r n =
    if n < 0 then fail (`Overflow "length");
    need r n;
    let s = String.sub r.src r.pos n in
    r.pos <- r.pos + n;
    s

  let u8 r = Char.code (byte r)

  let u16 r =
    let a = u8 r in
    let b = u8 r in
    a lor (b lsl 8)

  let u32 r =
    need r 4;
    let v = ref 0l in
    for i = 0 to 3 do
      v := Int32.logor !v (Int32.shift_left (Int32.of_int (Char.code r.src.[r.pos + i])) (8 * i))
    done;
    r.pos <- r.pos + 4;
    !v

  let u64 r =
    need r 8;
    let v = ref 0L in
    for i = 0 to 7 do
      v := Int64.logor !v (Int64.shift_left (Int64.of_int (Char.code r.src.[r.pos + i])) (8 * i))
    done;
    r.pos <- r.pos + 8;
    !v

  let i64 = u64

  let u16_be r =
    let a = u8 r in
    let b = u8 r in
    (a lsl 8) lor b

  let u32_be r =
    need r 4;
    let v = ref 0l in
    for i = 0 to 3 do
      v := Int32.logor (Int32.shift_left !v 8) (Int32.of_int (Char.code r.src.[r.pos + i]))
    done;
    r.pos <- r.pos + 4;
    !v

  let ult a b = Int64.unsigned_compare a b < 0

  let varint r =
    match u8 r with
    | 0xfd ->
        let v = Int64.of_int (u16 r) in
        if ult v 0xfdL then fail `Non_canonical_varint;
        v
    | 0xfe ->
        let v = Int64.logand (Int64.of_int32 (u32 r)) 0xffffffffL in
        if ult v 0x10000L then fail `Non_canonical_varint;
        v
    | 0xff ->
        let v = u64 r in
        if ult v 0x100000000L then fail `Non_canonical_varint;
        v
    | n -> Int64.of_int n

  let varint_int r =
    let v = varint r in
    (* Unsigned, so a value with the top bit set is enormous, not negative. *)
    if Int64.unsigned_compare v (Int64.of_int max_int) > 0 then fail (`Overflow "count");
    let n = Int64.to_int v in
    (* Every element costs at least one byte; a count larger than the bytes
       left cannot be satisfied, and refusing here is what prevents a hostile
       length from driving an unbounded allocation. *)
    if n > remaining r then fail (`Eof (n - remaining r));
    n

  let varstr r =
    let n = varint_int r in
    take r n

  let vector r f =
    let n = varint_int r in
    (* An explicit loop, not [List.init]: the reader is stateful and
       [List.init]'s order of application is not specified. *)
    let rec go acc i = if i = 0 then List.rev acc else go (f r :: acc) (i - 1) in
    go [] n

  let sub r n =
    need r n;
    let sr = { src = r.src; pos = r.pos; stop = r.pos + n } in
    r.pos <- r.pos + n;
    sr

  let run ?(exact = true) f s =
    let r = { src = s; pos = 0; stop = String.length s } in
    match f r with
    | v -> if exact && not (eof r) then Error (`Trailing (remaining r)) else Ok v
    | exception Parse_error e -> Error (e :> error)
end
