type error = [ `Invalid_range | `Invalid_format | `Prevout_mismatch | `Msg of string ]

let pp_error ppf (e : [< error ]) = Error.pp ppf (e :> Error.t)

module Flag = struct
  type base = All | None_ | Single
  type t = { base : base; anyone_can_pay : bool }

  let all = { base = All; anyone_can_pay = false }
  let base_to_int = function All -> 1 | None_ -> 2 | Single -> 3
  let to_int t = base_to_int t.base lor if t.anyone_can_pay then 0x80 else 0

  let of_int n =
    let acp = n land 0x80 <> 0 in
    match n land 0x1f with
    | 1 -> Ok { base = All; anyone_can_pay = acp }
    | 2 -> Ok { base = None_; anyone_can_pay = acp }
    | 3 -> Ok { base = Single; anyone_can_pay = acp }
    | _ -> Error `Invalid_format

  (* Consensus reads the type from the low five bits and treats anything that
     is not NONE or SINGLE as ALL, so this is total where {!of_int} is not.
     Non-standard values do occur in old transactions and still have to hash
     to the value they hashed to then. *)
  let of_consensus n =
    let n = Int32.to_int n land 0xffffffff in
    let base = match n land 0x1f with 2 -> None_ | 3 -> Single | _ -> All in
    { base; anyone_can_pay = n land 0x80 <> 0 }

  let to_consensus t = Int32.of_int (to_int t)

  type taproot = Default | Explicit of t

  let taproot_to_int = function Default -> 0 | Explicit t -> to_int t

  let taproot_of_int = function
    | 0 -> Ok Default
    | n -> ( match of_int n with Ok t -> Ok (Explicit t) | Error _ as e -> e)
end

type utxo = { value : Amount.t; script_pubkey : Script.t }

module Prevouts = struct
  type t = { tx : Tx.t; utxos : utxo array }

  let of_list tx utxos =
    if List.length utxos <> List.length tx.Tx.inputs then Error `Prevout_mismatch
    else Ok { tx; utxos = Array.of_list utxos }

  let tx t = t.tx
  let get t i = if i < 0 || i >= Array.length t.utxos then None else Some t.utxos.(i)
  let to_list t = Array.to_list t.utxos
  let length t = Array.length t.utxos
end

(* --- shared field writers ------------------------------------------------ *)

(* BIP143 and BIP341 hash the same fields but with different digests -- v0
   uses SHA256d and omits amounts and scriptPubKeys, v1 uses a single SHA256
   and adds them. Share the writers, not the hashes. *)

let write_prevouts w (tx : Tx.t) =
  List.iter (fun (i : Tx.In.t) -> Tx.Outpoint.write w i.Tx.In.previous_output) tx.Tx.inputs

let write_sequences w (tx : Tx.t) =
  List.iter (fun (i : Tx.In.t) -> Codec.W.u32 w i.Tx.In.sequence) tx.Tx.inputs

let write_outputs w (tx : Tx.t) = List.iter (fun o -> Tx.Out.write w o) tx.Tx.outputs
let write_amounts w utxos = List.iter (fun u -> Amount.write w u.value) utxos
let write_script_pubkeys w utxos = List.iter (fun u -> Script.write w u.script_pubkey) utxos

module Cache = struct
  type t = {
    (* BIP143: double SHA256. *)
    v0_prevouts : string;
    v0_sequences : string;
    v0_outputs : string;
    (* BIP341: single SHA256, plus the two fields v0 lacks. *)
    v1_prevouts : string;
    v1_amounts : string;
    v1_script_pubkeys : string;
    v1_sequences : string;
    v1_outputs : string;
  }

  let make p =
    let tx = Prevouts.tx p and utxos = Prevouts.to_list p in
    {
      v0_prevouts = Codec.W.sha256d write_prevouts tx;
      v0_sequences = Codec.W.sha256d write_sequences tx;
      v0_outputs = Codec.W.sha256d write_outputs tx;
      v1_prevouts = Codec.W.sha256 write_prevouts tx;
      v1_amounts = Codec.W.sha256 write_amounts utxos;
      v1_script_pubkeys = Codec.W.sha256 write_script_pubkeys utxos;
      v1_sequences = Codec.W.sha256 write_sequences tx;
      v1_outputs = Codec.W.sha256 write_outputs tx;
    }
end

let zero32 = String.make 32 '\000'

(* Core removes every OP_CODESEPARATOR while serializing the script code, and
   writes a length that accounts for their absence. Scanning tolerantly
   rather than through Script.parse because a script code that does not fully
   decode still has to serialize the same way Core serializes it: the scan
   stops at the malformed point and the remainder is copied verbatim. *)
let write_script_code w script =
  let s = Script.to_octets script in
  let n = String.length s in
  let ranges = ref [] and n_sep = ref 0 in
  let pos = ref 0 and stop = ref false in
  while (not !stop) && !pos < n do
    let op = Char.code s.[!pos] in
    let next =
      if op <= 0x4b then Some (!pos + 1 + op)
      else if op = 0x4c then if !pos + 1 < n then Some (!pos + 2 + Char.code s.[!pos + 1]) else None
      else if op = 0x4d then
        if !pos + 2 < n then
          Some (!pos + 3 + (Char.code s.[!pos + 1] lor (Char.code s.[!pos + 2] lsl 8)))
        else None
      else if op = 0x4e then
        if !pos + 4 < n then
          Some
            (!pos + 5
            + Char.code s.[!pos + 1]
              lor (Char.code s.[!pos + 2] lsl 8)
              lor (Char.code s.[!pos + 3] lsl 16)
              lor (Char.code s.[!pos + 4] lsl 24))
        else None
      else Some (!pos + 1)
    in
    match next with
    | Some e when e <= n && e > !pos ->
        if op = Script.Op.op_codeseparator then incr n_sep else ranges := (!pos, e) :: !ranges;
        pos := e
    | _ ->
        (* Malformed from here on: copy the tail as Core does. *)
        ranges := (!pos, n) :: !ranges;
        stop := true
  done;
  Codec.W.varint w (Int64.of_int (n - !n_sep));
  List.iter (fun (a, b) -> Codec.W.bytes w (String.sub s a (b - a))) (List.rev !ranges)

(* --- legacy -------------------------------------------------------------- *)

(* The digest returned for the SIGHASH_SINGLE bug: uint256(1), little-endian. *)
let sighash_single_bug = "\001" ^ String.make 31 '\000'

let legacy ~tx ~input ~script_code ~hash_type =
  let flag = Flag.of_consensus hash_type in
  let n_in = List.length tx.Tx.inputs and n_out = List.length tx.Tx.outputs in
  if input < 0 || input >= n_in then Error `Invalid_range
  else if flag.Flag.base = Flag.Single && input >= n_out then
    (* Core returns uint256(1) here instead of failing, and real outputs were
       spent with signatures over that value, so it has to be reproduced. *)
    Ok sighash_single_bug
  else
    let inputs = Array.of_list tx.Tx.inputs in
    let outputs = Array.of_list tx.Tx.outputs in
    let write w () =
      Codec.W.u32 w tx.Tx.version;
      (* ANYONECANPAY reduces the committed inputs to just this one. *)
      let ins =
        if flag.Flag.anyone_can_pay then [ (input, inputs.(input)) ]
        else List.init n_in (fun i -> (i, inputs.(i)))
      in
      Codec.W.varint w (Int64.of_int (List.length ins));
      List.iter
        (fun (i, (inp : Tx.In.t)) ->
          Tx.Outpoint.write w inp.Tx.In.previous_output;
          (* Only the input being signed carries a script; the others are
             blanked, which is what lets other inputs be signed separately. *)
          if i = input then write_script_code w script_code
          else Script.write w (Script.of_octets "");
          (* NONE and SINGLE also blank the other inputs' sequences, so those
             inputs stay free to change. *)
          let seq =
            if i = input then inp.Tx.In.sequence
            else
              match flag.Flag.base with
              | Flag.None_ | Flag.Single -> 0l
              | Flag.All -> inp.Tx.In.sequence
          in
          Codec.W.u32 w seq)
        ins;
      (match flag.Flag.base with
      | Flag.All -> Codec.W.vector w Tx.Out.write tx.Tx.outputs
      | Flag.None_ -> Codec.W.varint w 0L
      | Flag.Single ->
          (* Commits to the one output at this index; earlier ones are written
           as null placeholders so their positions are still covered. *)
          Codec.W.varint w (Int64.of_int (input + 1));
          for i = 0 to input do
            if i = input then Tx.Out.write w outputs.(i)
            else (
              Codec.W.i64 w (-1L);
              Script.write w (Script.of_octets ""))
          done);
      Codec.W.u32 w tx.Tx.lock_time;
      (* The full 32-bit value, not the normalised byte: old signatures were
         made over non-standard hash types and must still verify. *)
      Codec.W.u32 w hash_type
    in
    Ok (Codec.W.sha256d write ())

(* --- BIP143 -------------------------------------------------------------- *)

let bip143 ?cache ~tx ~input ~script_code ~amount ~hash_type () =
  let flag = Flag.of_consensus hash_type in
  let n_in = List.length tx.Tx.inputs and n_out = List.length tx.Tx.outputs in
  if input < 0 || input >= n_in then Error `Invalid_range
  else
    let inputs = Array.of_list tx.Tx.inputs in
    let outputs = Array.of_list tx.Tx.outputs in
    let cached f g = match cache with Some c -> f c | None -> Codec.W.sha256d g tx in
    let acp = flag.Flag.anyone_can_pay in
    let single_or_none = flag.Flag.base = Flag.Single || flag.Flag.base = Flag.None_ in
    let hash_prevouts =
      if acp then zero32 else cached (fun c -> c.Cache.v0_prevouts) write_prevouts
    in
    let hash_sequence =
      if acp || single_or_none then zero32
      else cached (fun c -> c.Cache.v0_sequences) write_sequences
    in
    let hash_outputs =
      match flag.Flag.base with
      | Flag.All -> cached (fun c -> c.Cache.v0_outputs) write_outputs
      | Flag.Single ->
          if input < n_out then Codec.W.sha256d Tx.Out.write outputs.(input) else zero32
      | Flag.None_ -> zero32
    in
    let inp = inputs.(input) in
    let write w () =
      Codec.W.u32 w tx.Tx.version;
      Codec.W.bytes w hash_prevouts;
      Codec.W.bytes w hash_sequence;
      Tx.Outpoint.write w inp.Tx.In.previous_output;
      Script.write w script_code;
      Amount.write w amount;
      Codec.W.u32 w inp.Tx.In.sequence;
      Codec.W.bytes w hash_outputs;
      Codec.W.u32 w tx.Tx.lock_time;
      Codec.W.u32 w hash_type
    in
    Ok (Codec.W.sha256d write ())

(* --- BIP341 -------------------------------------------------------------- *)

let bip341 ?cache ?annex ?(ext = `Key_path) ~prevouts ~input ~flag () =
  let tx = Prevouts.tx prevouts in
  let n_in = List.length tx.Tx.inputs and n_out = List.length tx.Tx.outputs in
  if input < 0 || input >= n_in then Error `Invalid_range
  else
    let base, acp =
      match flag with
      | Flag.Default -> (Flag.All, false)
      | Flag.Explicit t -> (t.Flag.base, t.Flag.anyone_can_pay)
    in
    (* BIP341 removed the SIGHASH_SINGLE bug rather than preserving it. *)
    if base = Flag.Single && input >= n_out then Error `Invalid_range
    else
      let inputs = Array.of_list tx.Tx.inputs in
      let outputs = Array.of_list tx.Tx.outputs in
      let utxos = Prevouts.to_list prevouts in
      let cached f g x = match cache with Some c -> f c | None -> Codec.W.sha256 g x in
      let inp = inputs.(input) in
      let ext_flag = match ext with `Key_path -> 0 | `Script_path _ -> 1 in
      let annex_present = match annex with Some _ -> 1 | None -> 0 in
      let write w () =
        (* Epoch, then the sighash type. *)
        Codec.W.u8 w 0x00;
        Codec.W.u8 w (Flag.taproot_to_int flag);
        Codec.W.u32 w tx.Tx.version;
        Codec.W.u32 w tx.Tx.lock_time;
        if not acp then (
          Codec.W.bytes w (cached (fun c -> c.Cache.v1_prevouts) write_prevouts tx);
          Codec.W.bytes w (cached (fun c -> c.Cache.v1_amounts) write_amounts utxos);
          Codec.W.bytes w (cached (fun c -> c.Cache.v1_script_pubkeys) write_script_pubkeys utxos);
          Codec.W.bytes w (cached (fun c -> c.Cache.v1_sequences) write_sequences tx));
        if base = Flag.All then
          Codec.W.bytes w (cached (fun c -> c.Cache.v1_outputs) write_outputs tx);
        (* spend_type: bit 0 is the annex flag, bit 1 the extension flag. *)
        Codec.W.u8 w ((2 * ext_flag) + annex_present);
        if acp then (
          Tx.Outpoint.write w inp.Tx.In.previous_output;
          let u = List.nth utxos input in
          Amount.write w u.value;
          Script.write w u.script_pubkey;
          Codec.W.u32 w inp.Tx.In.sequence)
        else Codec.W.u32 w (Int32.of_int input);
        (* The annex is hashed with its own length prefix, and includes the
           0x50 byte that identifies it. *)
        (match annex with
        | None -> ()
        | Some a -> Codec.W.bytes w (Codec.W.sha256 Codec.W.varstr a));
        if base = Flag.Single then Codec.W.bytes w (Codec.W.sha256 Tx.Out.write outputs.(input));
        match ext with
        | `Key_path -> ()
        | `Script_path (leaf_hash, codesep_pos) ->
            Codec.W.bytes w leaf_hash;
            (* key_version, currently always zero *)
            Codec.W.u8 w 0x00;
            Codec.W.u32 w codesep_pos
      in
      Ok (Hash.tagged ~tag:Hash.Tag.tap_sighash (Codec.W.to_string write ()))

(* --- dispatch ------------------------------------------------------------ *)

type spend =
  | P2pkh
  | P2sh of Script.t
  | P2wpkh
  | P2wsh of Script.t
  | P2tr_key
  | P2tr_script of string * int32

(* The implicit script code for a P2WPKH input: BIP143 specifies the
   equivalent P2PKH script rather than the witness program itself. *)
let p2wpkh_script_code ~hash160 = Script.p2pkh ~hash160

let of_prevouts ?cache ?annex ~prevouts ~input ~spend ~flag () =
  let tx = Prevouts.tx prevouts in
  match Prevouts.get prevouts input with
  | None -> Error `Invalid_range
  | Some u -> (
      (* SIGHASH_DEFAULT exists only under Taproot; for the older algorithms
       it means the ordinary SIGHASH_ALL. *)
      let legacy_ht () =
        Ok (Flag.to_consensus (match flag with Flag.Default -> Flag.all | Flag.Explicit t -> t))
      in
      match spend with
      | P2pkh -> (
          match legacy_ht () with
          | Error _ as e -> e
          | Ok ht -> legacy ~tx ~input ~script_code:u.script_pubkey ~hash_type:ht)
      | P2sh redeem -> (
          match legacy_ht () with
          | Error _ as e -> e
          | Ok ht -> legacy ~tx ~input ~script_code:redeem ~hash_type:ht)
      | P2wpkh -> (
          match (legacy_ht (), Script.classify u.script_pubkey) with
          | (Error _ as e), _ -> e
          | Ok ht, Script.Witness { version = 0; program } when String.length program = 20 ->
              bip143 ?cache ~tx ~input
                ~script_code:(p2wpkh_script_code ~hash160:program)
                ~amount:u.value ~hash_type:ht ()
          | _ -> Error `Invalid_format)
      | P2wsh witness_script -> (
          match legacy_ht () with
          | Error _ as e -> e
          | Ok ht ->
              bip143 ?cache ~tx ~input ~script_code:witness_script ~amount:u.value ~hash_type:ht ())
      | P2tr_key -> bip341 ?cache ?annex ~ext:`Key_path ~prevouts ~input ~flag ()
      | P2tr_script (leaf_hash, codesep) ->
          bip341 ?cache ?annex ~ext:(`Script_path (leaf_hash, codesep)) ~prevouts ~input ~flag ())
