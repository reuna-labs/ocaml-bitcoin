type t = string

let of_octets s = s
let to_octets s = s
let length = String.length
let equal = String.equal
let is_empty s = String.length s = 0
let read r = Codec.R.varstr r
let write w s = Codec.W.varstr w s
let write_raw w s = Codec.W.bytes w s
let concat = String.concat ""

module Op = struct
  let op_0 = 0x00
  let op_pushdata1 = 0x4c
  let op_pushdata2 = 0x4d
  let op_pushdata4 = 0x4e
  let op_1negate = 0x4f
  let op_1 = 0x51
  let op_16 = 0x60
  let op_return = 0x6a
  let op_dup = 0x76
  let op_equal = 0x87
  let op_equalverify = 0x88
  let op_hash160 = 0xa9
  let op_checksig = 0xac
  let op_checksigverify = 0xad
  let op_checkmultisig = 0xae
  let op_checksigadd = 0xba
  let op_codeseparator = 0xab

  let names =
    [
      (0x00, "OP_0");
      (0x4c, "OP_PUSHDATA1");
      (0x4d, "OP_PUSHDATA2");
      (0x4e, "OP_PUSHDATA4");
      (0x4f, "OP_1NEGATE");
      (0x50, "OP_RESERVED");
      (0x61, "OP_NOP");
      (0x63, "OP_IF");
      (0x64, "OP_NOTIF");
      (0x67, "OP_ELSE");
      (0x68, "OP_ENDIF");
      (0x69, "OP_VERIFY");
      (0x6a, "OP_RETURN");
      (0x6b, "OP_TOALTSTACK");
      (0x6c, "OP_FROMALTSTACK");
      (0x6d, "OP_2DROP");
      (0x6e, "OP_2DUP");
      (0x6f, "OP_3DUP");
      (0x73, "OP_IFDUP");
      (0x74, "OP_DEPTH");
      (0x75, "OP_DROP");
      (0x76, "OP_DUP");
      (0x77, "OP_NIP");
      (0x78, "OP_OVER");
      (0x79, "OP_PICK");
      (0x7a, "OP_ROLL");
      (0x7b, "OP_ROT");
      (0x7c, "OP_SWAP");
      (0x7d, "OP_TUCK");
      (0x82, "OP_SIZE");
      (0x87, "OP_EQUAL");
      (0x88, "OP_EQUALVERIFY");
      (0x8b, "OP_1ADD");
      (0x8c, "OP_1SUB");
      (0x8f, "OP_NEGATE");
      (0x90, "OP_ABS");
      (0x91, "OP_NOT");
      (0x92, "OP_0NOTEQUAL");
      (0x93, "OP_ADD");
      (0x94, "OP_SUB");
      (0x9a, "OP_BOOLAND");
      (0x9b, "OP_BOOLOR");
      (0x9c, "OP_NUMEQUAL");
      (0x9d, "OP_NUMEQUALVERIFY");
      (0x9e, "OP_NUMNOTEQUAL");
      (0x9f, "OP_LESSTHAN");
      (0xa0, "OP_GREATERTHAN");
      (0xa1, "OP_LESSTHANOREQUAL");
      (0xa2, "OP_GREATERTHANOREQUAL");
      (0xa3, "OP_MIN");
      (0xa4, "OP_MAX");
      (0xa5, "OP_WITHIN");
      (0xa6, "OP_RIPEMD160");
      (0xa7, "OP_SHA1");
      (0xa8, "OP_SHA256");
      (0xa9, "OP_HASH160");
      (0xaa, "OP_HASH256");
      (0xab, "OP_CODESEPARATOR");
      (0xac, "OP_CHECKSIG");
      (0xad, "OP_CHECKSIGVERIFY");
      (0xae, "OP_CHECKMULTISIG");
      (0xaf, "OP_CHECKMULTISIGVERIFY");
      (0xb1, "OP_CHECKLOCKTIMEVERIFY");
      (0xb2, "OP_CHECKSEQUENCEVERIFY");
      (0xba, "OP_CHECKSIGADD");
    ]

  let name op =
    match List.assoc_opt op names with
    | Some n -> n
    | None ->
        if op >= 0x51 && op <= 0x60 then Printf.sprintf "OP_%d" (op - 0x50)
        else if op >= 0x01 && op <= 0x4b then Printf.sprintf "OP_PUSHBYTES_%d" op
        else Printf.sprintf "OP_UNKNOWN(0x%02x)" op

  let of_small_int n =
    if n = 0 then op_0
    else if n >= 1 && n <= 16 then op_1 + n - 1
    else invalid_arg "Script.Op.of_small_int: expected 0..16"

  let to_small_int op =
    if op = op_0 then Some 0 else if op >= op_1 && op <= op_16 then Some (op - op_1 + 1) else None
end

type element = Push of { opcode : int; data : string } | Op of int

(* A push whose length prefix runs past the end of the script is the only
   structural error possible; every other byte is simply an opcode. *)
let parse script =
  Codec.R.run
    (fun r ->
      let out = ref [] in
      while not (Codec.R.eof r) do
        let op = Codec.R.u8 r in
        if op >= 0x01 && op <= 0x4b then
          out := Push { opcode = op; data = Codec.R.take r op } :: !out
        else if op = Op.op_pushdata1 then
          let n = Codec.R.u8 r in
          out := Push { opcode = op; data = Codec.R.take r n } :: !out
        else if op = Op.op_pushdata2 then
          let n = Codec.R.u16 r in
          out := Push { opcode = op; data = Codec.R.take r n } :: !out
        else if op = Op.op_pushdata4 then (
          let n = Int32.to_int (Codec.R.u32 r) in
          if n < 0 || n > Codec.R.remaining r then Codec.R.fail (`Eof n);
          out := Push { opcode = op; data = Codec.R.take r n } :: !out)
        else out := Op op :: !out
      done;
      List.rev !out)
    script

let write_element w = function
  | Op op -> Codec.W.u8 w op
  | Push { opcode; data } ->
      Codec.W.u8 w opcode;
      if opcode = Op.op_pushdata1 then Codec.W.u8 w (String.length data)
      else if opcode = Op.op_pushdata2 then Codec.W.u16 w (String.length data)
      else if opcode = Op.op_pushdata4 then Codec.W.u32 w (Int32.of_int (String.length data));
      Codec.W.bytes w data

let of_elements els = Codec.W.to_string (fun w els -> List.iter (write_element w) els) els

let to_elements_exn s =
  match parse s with
  | Ok e -> e
  | Error _ -> invalid_arg "Script.to_elements_exn: script does not decode"

(* The MINIMALDATA rule: the shortest encoding that pushes this value. *)
let minimal_push data =
  let n = String.length data in
  if n = 0 then Op Op.op_0
  else if n = 1 then
    let b = Char.code data.[0] in
    if b >= 1 && b <= 16 then Op (Op.of_small_int b)
    else if b = 0x81 then Op Op.op_1negate
    else Push { opcode = 1; data }
  else if n <= 0x4b then Push { opcode = n; data }
  else if n <= 0xff then Push { opcode = Op.op_pushdata1; data }
  else if n <= 0xffff then Push { opcode = Op.op_pushdata2; data }
  else Push { opcode = Op.op_pushdata4; data }

let push data = of_elements [ minimal_push data ]

(* --- standard templates ------------------------------------------------- *)

let p2pk pub = of_elements [ minimal_push (Key.Public.to_octets pub); Op Op.op_checksig ]

let p2pkh ~hash160 =
  of_elements
    [
      Op Op.op_dup; Op Op.op_hash160; minimal_push hash160; Op Op.op_equalverify; Op Op.op_checksig;
    ]

let p2sh ~hash160 = of_elements [ Op Op.op_hash160; minimal_push hash160; Op Op.op_equal ]

let witness_program ~version ~program =
  of_elements [ Op (Op.of_small_int version); minimal_push program ]

let p2wpkh ~hash160 = witness_program ~version:0 ~program:hash160
let p2wsh ~sha256 = witness_program ~version:0 ~program:sha256
let p2tr ~output_key = witness_program ~version:1 ~program:output_key

let multisig ~threshold keys =
  let n = List.length keys in
  if threshold < 1 || threshold > n || n < 1 || n > 20 then Error `Invalid_range
  else
    Ok
      (of_elements
         (Op (Op.of_small_int threshold)
          :: List.map (fun k -> minimal_push (Key.Public.to_octets k)) keys
         @ [ Op (Op.of_small_int n); Op Op.op_checkmultisig ]))

let op_return data =
  of_elements (Op Op.op_return :: (if data = "" then [] else [ minimal_push data ]))

type kind =
  | P2pk of string
  | P2pkh of string
  | P2sh of string
  | Witness of { version : int; program : string }
  | Multisig of { threshold : int; keys : string list }
  | Op_return of string
  | Nonstandard

let classify s =
  match parse s with
  | Error _ -> Nonstandard
  | Ok els -> (
      match els with
      | [ Push { data; _ }; Op op ]
        when op = Op.op_checksig && (String.length data = 33 || String.length data = 65) ->
          P2pk data
      | [ Op d; Op h; Push { data; _ }; Op ev; Op cs ]
        when d = Op.op_dup && h = Op.op_hash160 && ev = Op.op_equalverify && cs = Op.op_checksig
             && String.length data = 20 ->
          P2pkh data
      | [ Op h; Push { data; _ }; Op eq ]
        when h = Op.op_hash160 && eq = Op.op_equal && String.length data = 20 ->
          P2sh data
      | [ Op v; Push { data; opcode } ]
        when Op.to_small_int v <> None
             && opcode >= 2 && opcode <= 40
             && String.length data >= 2
             && String.length data <= 40 -> (
          match Op.to_small_int v with
          | Some version -> Witness { version; program = data }
          | None -> Nonstandard)
      | Op r :: rest when r = Op.op_return ->
          Op_return (match rest with [ Push { data; _ } ] -> data | [] -> "" | _ -> "")
      | Op m :: rest -> (
          match (Op.to_small_int m, List.rev rest) with
          | Some threshold, Op cms :: Op n :: rev_keys when cms = Op.op_checkmultisig -> (
              match Op.to_small_int n with
              | Some n when n = List.length rev_keys && threshold >= 1 && threshold <= n ->
                  let keys =
                    List.rev_map (function Push { data; _ } -> Some data | Op _ -> None) rev_keys
                  in
                  if List.for_all (fun k -> k <> None) keys then
                    Multisig
                      {
                        threshold;
                        keys = List.map (function Some k -> k | None -> assert false) keys;
                      }
                  else Nonstandard
              | _ -> Nonstandard)
          | _ -> Nonstandard)
      | _ -> Nonstandard)

let is_witness_program s = match classify s with Witness _ -> true | _ -> false

(* --- sighash support ---------------------------------------------------- *)

(* Core's FindAndDelete walks the script one element at a time and drops the
   pattern only where it starts on an element boundary, so a byte sequence
   that happens to occur inside a push is left alone. *)
let find_and_delete script pattern =
  let plen = String.length pattern in
  if plen = 0 || String.length script < plen then script
  else
    match parse script with
    | Error _ -> script
    | Ok _ ->
        let buf = Buffer.create (String.length script) in
        let n = String.length script in
        let pos = ref 0 in
        let element_len i =
          (* Length of the element starting at [i], or None if truncated. *)
          if i >= n then None
          else
            let op = Char.code script.[i] in
            if op >= 0x01 && op <= 0x4b then if i + 1 + op <= n then Some (1 + op) else None
            else if op = Op.op_pushdata1 then
              if i + 2 <= n then
                let l = Char.code script.[i + 1] in
                if i + 2 + l <= n then Some (2 + l) else None
              else None
            else if op = Op.op_pushdata2 then
              if i + 3 <= n then
                let l = Char.code script.[i + 1] lor (Char.code script.[i + 2] lsl 8) in
                if i + 3 + l <= n then Some (3 + l) else None
              else None
            else if op = Op.op_pushdata4 then
              if i + 5 <= n then
                let l =
                  Char.code script.[i + 1]
                  lor (Char.code script.[i + 2] lsl 8)
                  lor (Char.code script.[i + 3] lsl 16)
                  lor (Char.code script.[i + 4] lsl 24)
                in
                if l >= 0 && i + 5 + l <= n then Some (5 + l) else None
              else None
            else Some 1
        in
        let continue = ref true in
        while !continue && !pos < n do
          match element_len !pos with
          | None ->
              (* Truncated tail: copy verbatim and stop. *)
              Buffer.add_substring buf script !pos (n - !pos);
              continue := false
          | Some len ->
              if len = plen && String.sub script !pos plen = pattern then pos := !pos + plen
              else (
                Buffer.add_substring buf script !pos len;
                pos := !pos + len)
        done;
        Buffer.contents buf

let remove_codeseparators script =
  match parse script with
  | Error _ -> script
  | Ok els ->
      of_elements (List.filter (function Op op -> op <> Op.op_codeseparator | _ -> true) els)

let pp ppf s =
  match parse s with
  | Error _ -> Format.fprintf ppf "<undecodable %d bytes>" (String.length s)
  | Ok els ->
      let first = ref true in
      List.iter
        (fun el ->
          if !first then first := false else Format.pp_print_char ppf ' ';
          match el with
          | Op op -> Format.pp_print_string ppf (Op.name op)
          | Push { data; _ } -> String.iter (fun c -> Format.fprintf ppf "%02x" (Char.code c)) data)
        els
