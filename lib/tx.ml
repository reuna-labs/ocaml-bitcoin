type error = Codec.error

module Outpoint = struct
  type t = { txid : string; index : int32 }

  let null = { txid = String.make 32 '\000'; index = 0xffffffffl }
  let is_null t = Int32.equal t.index 0xffffffffl && String.equal t.txid null.txid
  let equal a b = Int32.equal a.index b.index && String.equal a.txid b.txid

  let read r =
    let txid = Codec.R.take r 32 in
    let index = Codec.R.u32 r in
    { txid; index }

  let write w t =
    Codec.W.bytes w t.txid;
    Codec.W.u32 w t.index

  (* Displayed txids are the internal bytes reversed, a convention inherited
     from Core printing a little-endian hash as a big-endian number. *)
  let reverse_hex s =
    String.concat ""
      (List.init (String.length s) (fun i ->
           Printf.sprintf "%02x" (Char.code s.[String.length s - 1 - i])))

  let to_string t = Printf.sprintf "%s:%ld" (reverse_hex t.txid) t.index
end

module Witness = struct
  type t = string list

  let empty = []
  let is_empty = function [] -> true | _ -> false
  let read r = Codec.R.vector r Codec.R.varstr
  let write w t = Codec.W.vector w Codec.W.varstr t
end

module In = struct
  type t = {
    previous_output : Outpoint.t;
    script_sig : Script.t;
    sequence : int32;
    witness : Witness.t;
  }

  let sequence_final = 0xffffffffl
  let sequence_rbf = 0xfffffffdl

  (* BIP125: any input with a sequence below 0xfffffffe opts the whole
     transaction into replaceability. *)
  let is_rbf_signalling t = Int32.unsigned_compare t.sequence 0xfffffffel < 0

  let read r =
    let previous_output = Outpoint.read r in
    let script_sig = Script.read r in
    let sequence = Codec.R.u32 r in
    { previous_output; script_sig; sequence; witness = Witness.empty }

  let write w t =
    Outpoint.write w t.previous_output;
    Script.write w t.script_sig;
    Codec.W.u32 w t.sequence
end

module Out = struct
  type t = { value : Amount.t; script_pubkey : Script.t }

  let read r =
    let value = Amount.read r in
    let script_pubkey = Script.read r in
    { value; script_pubkey }

  let write w t =
    Amount.write w t.value;
    Script.write w t.script_pubkey
end

type t = { version : int32; inputs : In.t list; outputs : Out.t list; lock_time : int32 }

let has_witness t = List.exists (fun (i : In.t) -> not (Witness.is_empty i.witness)) t.inputs

let write ?(witness = true) w t =
  let segwit = witness && has_witness t in
  Codec.W.u32 w t.version;
  if segwit then (
    (* BIP144 marker and flag. Emitted only when there is witness data to
       carry, which is what keeps the encoding canonical. *)
    Codec.W.u8 w 0x00;
    Codec.W.u8 w 0x01);
  Codec.W.vector w In.write t.inputs;
  Codec.W.vector w Out.write t.outputs;
  if segwit then List.iter (fun (i : In.t) -> Witness.write w i.witness) t.inputs;
  Codec.W.u32 w t.lock_time

let serialize ?witness t = Codec.W.to_string (fun w t -> write ?witness w t) t

let read_n r f n =
  let rec go acc i = if i = 0 then List.rev acc else go (f r :: acc) (i - 1) in
  go [] n

let read r =
  let version = Codec.R.u32 r in
  let n_in = Codec.R.varint_int r in
  if n_in = 0 then (
    (* A zero input count is the BIP144 marker: no valid legacy transaction
       has no inputs, which is what makes the encoding unambiguous. *)
    let flags = Codec.R.u8 r in
    if flags = 0 then Codec.R.fail (`Msg "transaction: witness flag must be non-zero");
    let n_in = Codec.R.varint_int r in
    let inputs = read_n r In.read n_in in
    let outputs = Codec.R.vector r Out.read in
    let inputs =
      if flags land 1 <> 0 then
        List.map (fun (i : In.t) -> { i with In.witness = Witness.read r }) inputs
      else inputs
    in
    let rest = flags land lnot 1 in
    if rest <> 0 then Codec.R.fail (`Msg "transaction: unknown witness flags");
    (* Core rejects a witness serialization that carries no witness data,
       so that every transaction has exactly one encoding. *)
    if not (List.exists (fun (i : In.t) -> not (Witness.is_empty i.witness)) inputs) then
      Codec.R.fail (`Msg "transaction: superfluous witness record");
    let lock_time = Codec.R.u32 r in
    { version; inputs; outputs; lock_time })
  else
    let inputs = read_n r In.read n_in in
    let outputs = Codec.R.vector r Out.read in
    let lock_time = Codec.R.u32 r in
    { version; inputs; outputs; lock_time }

let parse s = Codec.R.run read s
let txid t = Hash.sha256d (serialize ~witness:false t)
let wtxid t = Hash.sha256d (serialize ~witness:true t)
let txid_hex t = Outpoint.reverse_hex (txid t)
let total_size t = String.length (serialize ~witness:true t)
let base_size t = String.length (serialize ~witness:false t)

(* BIP141 weight: witness bytes count a quarter as much as base bytes. *)
let weight t = (base_size t * 3) + total_size t
let vsize t = (weight t + 3) / 4

let is_coinbase t =
  match t.inputs with [ i ] -> Outpoint.is_null i.In.previous_output | _ -> false

let is_rbf_signalling t = List.exists In.is_rbf_signalling t.inputs
let total_output t = Amount.sum (List.map (fun (o : Out.t) -> o.Out.value) t.outputs)

let fee t ~inputs =
  if List.length inputs <> List.length t.inputs then Error `Invalid_format
  else
    match (Amount.sum inputs, total_output t) with
    | Ok i, Ok o -> Amount.sub i o
    | (Error _ as e), _ | _, (Error _ as e) -> e
