type error =
  [ `Invalid_length
  | `Invalid_format
  | `Invalid_range
  | `Invalid_checksum
  | `Duplicate_key
  | `Unsupported_version
  | `Incomplete
  | `Prevout_mismatch
  | `Eof of int
  | `Trailing of int
  | `Non_canonical_varint
  | `Overflow of string
  | `Msg of string ]

let pp_error ppf (e : [< error ]) = Error.pp ppf (e :> Error.t)
let magic = "psbt\xff"

type key_origin = { fingerprint : string; path : Derivation_path.t }
type proprietary = { identifier : string; subkey : string; value : string }
type unknown = (string * string) list

(* Key types, BIP174 and BIP371. *)
module Kt = struct
  let global_unsigned_tx = 0x00
  let global_xpub = 0x01
  let global_version = 0xfb
  let global_proprietary = 0xfc
  let in_non_witness_utxo = 0x00
  let in_witness_utxo = 0x01
  let in_partial_sig = 0x02
  let in_sighash_type = 0x03
  let in_redeem_script = 0x04
  let in_witness_script = 0x05
  let in_bip32_derivation = 0x06
  let in_final_scriptsig = 0x07
  let in_final_scriptwitness = 0x08
  let in_ripemd160 = 0x0a
  let in_sha256 = 0x0b
  let in_hash160 = 0x0c
  let in_hash256 = 0x0d
  let in_tap_key_sig = 0x13
  let in_tap_script_sig = 0x14
  let in_tap_leaf_script = 0x15
  let in_tap_bip32_derivation = 0x16
  let in_tap_internal_key = 0x17
  let in_tap_merkle_root = 0x18
  let in_proprietary = 0xfc
  let out_redeem_script = 0x00
  let out_witness_script = 0x01
  let out_bip32_derivation = 0x02
  let out_tap_internal_key = 0x05
  let out_tap_tree = 0x06
  let out_tap_bip32_derivation = 0x07
  let out_proprietary = 0xfc
end

type global_xpub = { xpub : Bip32.Public.t; xpub_version : int32; xpub_origin : key_origin }

module Global = struct
  type t = {
    unsigned_tx : Tx.t;
    xpubs : global_xpub list;
    version : int32 option;
    proprietary : proprietary list;
    unknown : unknown;
  }
end

module Input = struct
  type t = {
    non_witness_utxo : Tx.t option;
    witness_utxo : Tx.Out.t option;
    partial_sigs : (Key.Public.t * string) list;
    sighash_type : int32 option;
    redeem_script : Script.t option;
    witness_script : Script.t option;
    bip32_derivation : (Key.Public.t * key_origin) list;
    final_script_sig : Script.t option;
    final_script_witness : Tx.Witness.t option;
    ripemd160 : (string * string) list;
    sha256 : (string * string) list;
    hash160 : (string * string) list;
    hash256 : (string * string) list;
    tap_key_sig : string option;
    tap_script_sig : ((string * string) * string) list;
    tap_leaf_script : ((Script.t * int) * string) list;
    tap_bip32_derivation : (string * (string list * key_origin)) list;
    tap_internal_key : string option;
    tap_merkle_root : string option;
    proprietary : proprietary list;
    unknown : unknown;
  }

  let empty =
    {
      non_witness_utxo = None;
      witness_utxo = None;
      partial_sigs = [];
      sighash_type = None;
      redeem_script = None;
      witness_script = None;
      bip32_derivation = [];
      final_script_sig = None;
      final_script_witness = None;
      ripemd160 = [];
      sha256 = [];
      hash160 = [];
      hash256 = [];
      tap_key_sig = None;
      tap_script_sig = [];
      tap_leaf_script = [];
      tap_bip32_derivation = [];
      tap_internal_key = None;
      tap_merkle_root = None;
      proprietary = [];
      unknown = [];
    }
end

module Output = struct
  type t = {
    redeem_script : Script.t option;
    witness_script : Script.t option;
    bip32_derivation : (Key.Public.t * key_origin) list;
    tap_internal_key : string option;
    tap_tree : (int * int * Script.t) list;
    tap_bip32_derivation : (string * (string list * key_origin)) list;
    proprietary : proprietary list;
    unknown : unknown;
  }

  let empty =
    {
      redeem_script = None;
      witness_script = None;
      bip32_derivation = [];
      tap_internal_key = None;
      tap_tree = [];
      tap_bip32_derivation = [];
      proprietary = [];
      unknown = [];
    }
end

type t = { global : Global.t; inputs : Input.t list; outputs : Output.t list }

(* --- key-value maps ------------------------------------------------------ *)

(* A map is a run of <key><value> pairs terminated by a zero-length key. *)
let read_map r =
  let rec go acc =
    let klen = Codec.R.varint_int r in
    if klen = 0 then List.rev acc
    else
      let key = Codec.R.take r klen in
      let value = Codec.R.varstr r in
      go ((key, value) :: acc)
  in
  go []

let write_pair w (key, value) =
  Codec.W.varstr w key;
  Codec.W.varstr w value

(* Fields are emitted in ascending key type, and within a repeated type in
   the order they were parsed. BIP174 mandates no ordering, and real PSBTs
   are not sorted -- the test vectors include partial signatures in
   non-sorted order -- so sorting on write would break exact round-tripping
   of anything produced elsewhere. *)
let write_map w pairs =
  List.iter (write_pair w) pairs;
  Codec.W.u8 w 0x00

let key_type key = if String.length key = 0 then -1 else Char.code key.[0]
let key_data key = String.sub key 1 (String.length key - 1)

(* A field that holds a single value has a key of exactly its type byte.
   Trailing key data there is malformed, not an unknown field: BIP174's
   invalid vectors include exactly this, and accepting it would let one
   input carry two "the" witness UTXOs. *)
let is_single key = String.length key = 1

let parse_origin v =
  if String.length v < 4 || (String.length v - 4) mod 4 <> 0 then Error `Invalid_length
  else
    let fingerprint = String.sub v 0 4 in
    let n = (String.length v - 4) / 4 in
    let path =
      List.init n (fun i ->
          let o = 4 + (i * 4) in
          let b k = Int32.of_int (Char.code v.[o + k]) in
          Int32.logor (b 0)
            (Int32.logor
               (Int32.shift_left (b 1) 8)
               (Int32.logor (Int32.shift_left (b 2) 16) (Int32.shift_left (b 3) 24))))
    in
    Ok { fingerprint; path = Derivation_path.of_list path }

let write_origin o =
  Codec.W.to_string
    (fun w () ->
      Codec.W.bytes w o.fingerprint;
      List.iter (fun i -> Codec.W.u32 w i) (Derivation_path.to_list o.path))
    ()

let u32_le_of_string v =
  if String.length v <> 4 then None
  else
    let b k = Int32.of_int (Char.code v.[k]) in
    Some
      (Int32.logor (b 0)
         (Int32.logor
            (Int32.shift_left (b 1) 8)
            (Int32.logor (Int32.shift_left (b 2) 16) (Int32.shift_left (b 3) 24))))

(* --- parsing ------------------------------------------------------------- *)

let check_unique pairs =
  let seen = Hashtbl.create 16 in
  List.fold_left
    (fun acc (k, _) ->
      match acc with
      | Error _ as e -> e
      | Ok () ->
          if Hashtbl.mem seen k then Error `Duplicate_key
          else (
            Hashtbl.add seen k ();
            Ok ()))
    (Ok ()) pairs

let ( let* ) = Result.bind

let parse_global pairs =
  let* () = check_unique pairs in
  let tx = ref None and xpubs = ref [] and version = ref None and prop = ref [] and unk = ref [] in
  let err = ref None in
  List.iter
    (fun (k, v) ->
      let t = key_type k in
      if t = Kt.global_unsigned_tx then
        if not (is_single k) then err := Some `Invalid_format
        else
          (* The unsigned transaction is a legacy serialization by
             definition: it carries no witnesses, so a leading 0x00 is a
             genuine input count rather than the BIP144 marker. *)
          match Tx.parse ~witness:false v with
          | Ok x -> tx := Some x
          | Error _ -> err := Some `Invalid_format
      else if t = Kt.global_xpub then
        (* The key data is the raw 78-byte extended key, version included. *)
        match (Bip32.Public.of_octets (key_data k), parse_origin v) with
        | Ok (xpub, xpub_version), Ok xpub_origin ->
            xpubs := { xpub; xpub_version; xpub_origin } :: !xpubs
        | _ -> unk := (k, v) :: !unk
      else if t = Kt.global_version then
        if not (is_single k) then err := Some `Invalid_format
        else
          match u32_le_of_string v with
          | Some n -> version := Some n
          | None -> err := Some `Invalid_format
      else if t = Kt.global_proprietary then
        prop := { identifier = key_data k; subkey = ""; value = v } :: !prop
      else unk := (k, v) :: !unk)
    pairs;
  match (!err, !tx) with
  | Some e, _ -> Error e
  | None, None -> Error `Invalid_format
  | None, Some unsigned_tx ->
      (* PSBT v2 restructures the whole format; detect and refuse rather than
       mis-reading it as v0. *)
      if !version <> None && !version <> Some 0l then Error `Unsupported_version
      else
        Ok
          {
            Global.unsigned_tx;
            xpubs = List.rev !xpubs;
            version = !version;
            proprietary = List.rev !prop;
            unknown = List.rev !unk;
          }

let parse_input pairs =
  let* () = check_unique pairs in
  let i = ref Input.empty in
  let err = ref None in
  let set f = i := f !i in
  List.iter
    (fun (k, v) ->
      let t = key_type k in
      let d = key_data k in
      if t = Kt.in_non_witness_utxo then
        if not (is_single k) then err := Some `Invalid_format
        else
          match Tx.parse v with
          | Ok x -> set (fun i -> { i with Input.non_witness_utxo = Some x })
          | Error _ -> err := Some `Invalid_format
      else if t = Kt.in_witness_utxo then
        if not (is_single k) then err := Some `Invalid_format
        else
          match Codec.R.run Tx.Out.read v with
          | Ok x -> set (fun i -> { i with Input.witness_utxo = Some x })
          | Error _ -> err := Some `Invalid_format
      else if t = Kt.in_partial_sig then
        match Key.Public.of_octets d with
        | Ok pk -> set (fun i -> { i with Input.partial_sigs = i.Input.partial_sigs @ [ (pk, v) ] })
        | Error _ -> err := Some `Invalid_format
      else if t = Kt.in_sighash_type then
        if not (is_single k) then err := Some `Invalid_format
        else
          match u32_le_of_string v with
          | Some n -> set (fun i -> { i with Input.sighash_type = Some n })
          | None -> err := Some `Invalid_format
      else if t = Kt.in_redeem_script then
        if not (is_single k) then err := Some `Invalid_format
        else set (fun i -> { i with Input.redeem_script = Some (Script.of_octets v) })
      else if t = Kt.in_witness_script then
        if not (is_single k) then err := Some `Invalid_format
        else set (fun i -> { i with Input.witness_script = Some (Script.of_octets v) })
      else if t = Kt.in_bip32_derivation then
        match (Key.Public.of_octets d, parse_origin v) with
        | Ok pk, Ok o ->
            set (fun i ->
                { i with Input.bip32_derivation = i.Input.bip32_derivation @ [ (pk, o) ] })
        | _ -> err := Some `Invalid_format
      else if t = Kt.in_final_scriptsig then
        if not (is_single k) then err := Some `Invalid_format
        else set (fun i -> { i with Input.final_script_sig = Some (Script.of_octets v) })
      else if t = Kt.in_final_scriptwitness then
        if not (is_single k) then err := Some `Invalid_format
        else
          match Codec.R.run Tx.Witness.read v with
          | Ok x -> set (fun i -> { i with Input.final_script_witness = Some x })
          | Error _ -> err := Some `Invalid_format
      else if t = Kt.in_ripemd160 then
        set (fun i -> { i with Input.ripemd160 = i.Input.ripemd160 @ [ (d, v) ] })
      else if t = Kt.in_sha256 then
        set (fun i -> { i with Input.sha256 = i.Input.sha256 @ [ (d, v) ] })
      else if t = Kt.in_hash160 then
        set (fun i -> { i with Input.hash160 = i.Input.hash160 @ [ (d, v) ] })
      else if t = Kt.in_hash256 then
        set (fun i -> { i with Input.hash256 = i.Input.hash256 @ [ (d, v) ] })
      else if t = Kt.in_tap_key_sig then
        if not (is_single k) then err := Some `Invalid_format
        else if String.length v <> 64 && String.length v <> 65 then err := Some `Invalid_length
        else set (fun i -> { i with Input.tap_key_sig = Some v })
      else if t = Kt.in_tap_script_sig then
        if
          (* Key is x-only pubkey || leaf hash; value is a BIP340 signature,
           with a trailing sighash byte unless it is SIGHASH_DEFAULT. *)
          String.length d <> 64
        then err := Some `Invalid_length
        else if String.length v <> 64 && String.length v <> 65 then err := Some `Invalid_length
        else
          let xk = String.sub d 0 32 and lh = String.sub d 32 32 in
          set (fun i ->
              { i with Input.tap_script_sig = i.Input.tap_script_sig @ [ ((xk, lh), v) ] })
      else if t = Kt.in_tap_leaf_script then
        let cb = String.length d in
        if String.length v < 1 then err := Some `Invalid_length
        else if cb < 33 || (cb - 33) mod 32 <> 0 || (cb - 33) / 32 > 128 then
          err := Some `Invalid_length
        else
          let n = String.length v in
          let leaf_version = Char.code v.[n - 1] in
          let control = d in
          set (fun i ->
              {
                i with
                Input.tap_leaf_script =
                  i.Input.tap_leaf_script
                  @ [ ((Script.of_octets (String.sub v 0 (n - 1)), leaf_version), control) ];
              })
      else if t = Kt.in_tap_bip32_derivation then
        if String.length d <> 32 then err := Some `Invalid_length
        else
          (* <n hashes><hash>*<origin> *)
          match Codec.R.run ~exact:false (fun r -> Codec.R.varint_int r) v with
          | Error _ -> err := Some `Invalid_format
          | Ok _ -> (
              match
                Codec.R.run
                  (fun r ->
                    let n = Codec.R.varint_int r in
                    let hashes = List.init n (fun _ -> Codec.R.take r 32) in
                    let rest = Codec.R.take r (Codec.R.remaining r) in
                    (hashes, rest))
                  v
              with
              | Error _ -> err := Some `Invalid_format
              | Ok (hashes, rest) -> (
                  match parse_origin rest with
                  | Error _ -> err := Some `Invalid_format
                  | Ok o ->
                      set (fun i ->
                          {
                            i with
                            Input.tap_bip32_derivation =
                              i.Input.tap_bip32_derivation @ [ (d, (hashes, o)) ];
                          })))
      else if t = Kt.in_tap_internal_key then
        if not (is_single k) then err := Some `Invalid_format
        else if String.length v <> 32 then err := Some `Invalid_length
        else set (fun i -> { i with Input.tap_internal_key = Some v })
      else if t = Kt.in_tap_merkle_root then
        if not (is_single k) then err := Some `Invalid_format
        else if String.length v <> 32 then err := Some `Invalid_length
        else set (fun i -> { i with Input.tap_merkle_root = Some v })
      else if t = Kt.in_proprietary then
        set (fun i ->
            {
              i with
              Input.proprietary =
                i.Input.proprietary @ [ { identifier = d; subkey = ""; value = v } ];
            })
      else set (fun i -> { i with Input.unknown = i.Input.unknown @ [ (k, v) ] }))
    pairs;
  match !err with Some e -> Error e | None -> Ok !i

let parse_output pairs =
  let* () = check_unique pairs in
  let o = ref Output.empty in
  let err = ref None in
  let set f = o := f !o in
  List.iter
    (fun (k, v) ->
      let t = key_type k in
      let d = key_data k in
      if t = Kt.out_redeem_script then
        if not (is_single k) then err := Some `Invalid_format
        else set (fun o -> { o with Output.redeem_script = Some (Script.of_octets v) })
      else if t = Kt.out_witness_script then
        if not (is_single k) then err := Some `Invalid_format
        else set (fun o -> { o with Output.witness_script = Some (Script.of_octets v) })
      else if t = Kt.out_bip32_derivation then
        match (Key.Public.of_octets d, parse_origin v) with
        | Ok pk, Ok org ->
            set (fun o ->
                { o with Output.bip32_derivation = o.Output.bip32_derivation @ [ (pk, org) ] })
        | _ -> err := Some `Invalid_format
      else if t = Kt.out_tap_internal_key then
        if not (is_single k) then err := Some `Invalid_format
        else if String.length v <> 32 then err := Some `Invalid_length
        else set (fun o -> { o with Output.tap_internal_key = Some v })
      else if t = Kt.out_tap_tree then
        if not (is_single k) then err := Some `Invalid_format
        else
          match
            Codec.R.run
              (fun r ->
                let acc = ref [] in
                while not (Codec.R.eof r) do
                  let depth = Codec.R.u8 r in
                  let lv = Codec.R.u8 r in
                  let script = Codec.R.varstr r in
                  acc := (depth, lv, Script.of_octets script) :: !acc
                done;
                List.rev !acc)
              v
          with
          | Ok tree -> set (fun o -> { o with Output.tap_tree = tree })
          | Error _ -> err := Some `Invalid_format
      else if t = Kt.out_tap_bip32_derivation then
        if String.length d <> 32 then err := Some `Invalid_length
        else
          match
            Codec.R.run
              (fun r ->
                let n = Codec.R.varint_int r in
                let hashes = List.init n (fun _ -> Codec.R.take r 32) in
                let rest = Codec.R.take r (Codec.R.remaining r) in
                (hashes, rest))
              v
          with
          | Error _ -> err := Some `Invalid_format
          | Ok (hashes, rest) -> (
              match parse_origin rest with
              | Error _ -> err := Some `Invalid_format
              | Ok org ->
                  set (fun o ->
                      {
                        o with
                        Output.tap_bip32_derivation =
                          o.Output.tap_bip32_derivation @ [ (d, (hashes, org)) ];
                      }))
      else if t = Kt.out_proprietary then
        set (fun o ->
            {
              o with
              Output.proprietary =
                o.Output.proprietary @ [ { identifier = d; subkey = ""; value = v } ];
            })
      else set (fun o -> { o with Output.unknown = o.Output.unknown @ [ (k, v) ] }))
    pairs;
  match !err with Some e -> Error e | None -> Ok !o

let parse s =
  let raw =
    Codec.R.run
      (fun r ->
        let m = Codec.R.take r 5 in
        if not (String.equal m magic) then Codec.R.fail `Invalid_format;
        let global = read_map r in
        let rest = ref [] in
        while not (Codec.R.eof r) do
          rest := read_map r :: !rest
        done;
        (global, List.rev !rest))
      s
  in
  let* global_pairs, maps = match raw with Ok v -> Ok v | Error e -> Error (e :> error) in
  let* global = parse_global global_pairs in
  let n_in = List.length global.Global.unsigned_tx.Tx.inputs in
  let n_out = List.length global.Global.unsigned_tx.Tx.outputs in
  (* An unsigned transaction must be genuinely unsigned. *)
  let signed =
    List.exists
      (fun (i : Tx.In.t) ->
        (not (Script.is_empty i.Tx.In.script_sig)) || not (Tx.Witness.is_empty i.Tx.In.witness))
      global.Global.unsigned_tx.Tx.inputs
  in
  if signed then Error `Invalid_format
  else if List.length maps <> n_in + n_out then Error `Invalid_format
  else
    let in_maps = List.filteri (fun i _ -> i < n_in) maps in
    let out_maps = List.filteri (fun i _ -> i >= n_in) maps in
    let* inputs =
      List.fold_left
        (fun acc m ->
          let* acc = acc in
          let* i = parse_input m in
          Ok (i :: acc))
        (Ok []) in_maps
    in
    let* outputs =
      List.fold_left
        (fun acc m ->
          let* acc = acc in
          let* o = parse_output m in
          Ok (o :: acc))
        (Ok []) out_maps
    in
    Ok { global; inputs = List.rev inputs; outputs = List.rev outputs }

(* --- serialization -------------------------------------------------------- *)

let opt_pair t v = match v with None -> [] | Some x -> [ (String.make 1 (Char.chr t), x) ]
let key1 t = String.make 1 (Char.chr t)
let keyd t d = String.make 1 (Char.chr t) ^ d

let global_pairs (g : Global.t) =
  [ (key1 Kt.global_unsigned_tx, Tx.serialize ~witness:false g.Global.unsigned_tx) ]
  @ List.map
      (fun x ->
        ( keyd Kt.global_xpub (Bip32.Public.to_octets ~version:x.xpub_version x.xpub),
          write_origin x.xpub_origin ))
      g.Global.xpubs
  @ (match g.Global.version with
    | None -> []
    | Some v -> [ (key1 Kt.global_version, Codec.W.to_string Codec.W.u32 v) ])
  @ List.map (fun p -> (keyd Kt.global_proprietary p.identifier, p.value)) g.Global.proprietary
  @ g.Global.unknown

let input_pairs (i : Input.t) =
  (match i.Input.non_witness_utxo with
  | None -> []
  | Some tx -> [ (key1 Kt.in_non_witness_utxo, Tx.serialize tx) ])
  @ (match i.Input.witness_utxo with
    | None -> []
    | Some o -> [ (key1 Kt.in_witness_utxo, Codec.W.to_string Tx.Out.write o) ])
  @ List.map
      (fun (pk, s) -> (keyd Kt.in_partial_sig (Key.Public.to_octets pk), s))
      i.Input.partial_sigs
  @ (match i.Input.sighash_type with
    | None -> []
    | Some n -> [ (key1 Kt.in_sighash_type, Codec.W.to_string Codec.W.u32 n) ])
  @ opt_pair Kt.in_redeem_script (Option.map Script.to_octets i.Input.redeem_script)
  @ opt_pair Kt.in_witness_script (Option.map Script.to_octets i.Input.witness_script)
  @ List.map
      (fun (pk, o) -> (keyd Kt.in_bip32_derivation (Key.Public.to_octets pk), write_origin o))
      i.Input.bip32_derivation
  @ opt_pair Kt.in_final_scriptsig (Option.map Script.to_octets i.Input.final_script_sig)
  @ (match i.Input.final_script_witness with
    | None -> []
    | Some wit -> [ (key1 Kt.in_final_scriptwitness, Codec.W.to_string Tx.Witness.write wit) ])
  @ List.map (fun (k, v) -> (keyd Kt.in_ripemd160 k, v)) i.Input.ripemd160
  @ List.map (fun (k, v) -> (keyd Kt.in_sha256 k, v)) i.Input.sha256
  @ List.map (fun (k, v) -> (keyd Kt.in_hash160 k, v)) i.Input.hash160
  @ List.map (fun (k, v) -> (keyd Kt.in_hash256 k, v)) i.Input.hash256
  @ opt_pair Kt.in_tap_key_sig i.Input.tap_key_sig
  @ List.map (fun ((xk, lh), s) -> (keyd Kt.in_tap_script_sig (xk ^ lh), s)) i.Input.tap_script_sig
  @ List.map
      (fun ((script, lv), control) ->
        (keyd Kt.in_tap_leaf_script control, Script.to_octets script ^ String.make 1 (Char.chr lv)))
      i.Input.tap_leaf_script
  @ List.map
      (fun (xk, (hashes, o)) ->
        ( keyd Kt.in_tap_bip32_derivation xk,
          Codec.W.to_string
            (fun w () ->
              Codec.W.varint w (Int64.of_int (List.length hashes));
              List.iter (Codec.W.bytes w) hashes;
              Codec.W.bytes w (write_origin o))
            () ))
      i.Input.tap_bip32_derivation
  @ opt_pair Kt.in_tap_internal_key i.Input.tap_internal_key
  @ opt_pair Kt.in_tap_merkle_root i.Input.tap_merkle_root
  @ List.map (fun p -> (keyd Kt.in_proprietary p.identifier, p.value)) i.Input.proprietary
  @ i.Input.unknown

let output_pairs (o : Output.t) =
  opt_pair Kt.out_redeem_script (Option.map Script.to_octets o.Output.redeem_script)
  @ opt_pair Kt.out_witness_script (Option.map Script.to_octets o.Output.witness_script)
  @ List.map
      (fun (pk, org) -> (keyd Kt.out_bip32_derivation (Key.Public.to_octets pk), write_origin org))
      o.Output.bip32_derivation
  @ opt_pair Kt.out_tap_internal_key o.Output.tap_internal_key
  @ (if o.Output.tap_tree = [] then []
     else
       [
         ( key1 Kt.out_tap_tree,
           Codec.W.to_string
             (fun w () ->
               List.iter
                 (fun (depth, lv, script) ->
                   Codec.W.u8 w depth;
                   Codec.W.u8 w lv;
                   Codec.W.varstr w (Script.to_octets script))
                 o.Output.tap_tree)
             () );
       ])
  @ List.map
      (fun (xk, (hashes, org)) ->
        ( keyd Kt.out_tap_bip32_derivation xk,
          Codec.W.to_string
            (fun w () ->
              Codec.W.varint w (Int64.of_int (List.length hashes));
              List.iter (Codec.W.bytes w) hashes;
              Codec.W.bytes w (write_origin org))
            () ))
      o.Output.tap_bip32_derivation
  @ List.map (fun p -> (keyd Kt.out_proprietary p.identifier, p.value)) o.Output.proprietary
  @ o.Output.unknown

let serialize p =
  Codec.W.to_string
    (fun w () ->
      Codec.W.bytes w magic;
      write_map w (global_pairs p.global);
      List.iter (fun i -> write_map w (input_pairs i)) p.inputs;
      List.iter (fun o -> write_map w (output_pairs o)) p.outputs)
    ()

let to_base64 p = Base64.encode_string (serialize p)

let of_base64 s =
  match Base64.decode ~pad:true s with Error _ -> Error `Invalid_format | Ok raw -> parse raw

(* --- roles ---------------------------------------------------------------- *)

let map_input p i f =
  if i < 0 || i >= List.length p.inputs then Error `Invalid_range
  else
    match f (List.nth p.inputs i) with
    | Error _ as e -> e
    | Ok inp -> Ok { p with inputs = List.mapi (fun j x -> if j = i then inp else x) p.inputs }

module Creator = struct
  let create tx =
    let signed =
      List.exists
        (fun (i : Tx.In.t) ->
          (not (Script.is_empty i.Tx.In.script_sig)) || not (Tx.Witness.is_empty i.Tx.In.witness))
        tx.Tx.inputs
    in
    if signed then Error `Invalid_format
    else
      Ok
        {
          global =
            { Global.unsigned_tx = tx; xpubs = []; version = None; proprietary = []; unknown = [] };
          inputs = List.map (fun _ -> Input.empty) tx.Tx.inputs;
          outputs = List.map (fun _ -> Output.empty) tx.Tx.outputs;
        }
end

module Updater = struct
  let set_witness_utxo p ~input o =
    map_input p input (fun i -> Ok { i with Input.witness_utxo = Some o })

  let set_non_witness_utxo p ~input tx =
    if input < 0 || input >= List.length p.inputs then Error `Invalid_range
    else
      let prevout = (List.nth p.global.Global.unsigned_tx.Tx.inputs input).Tx.In.previous_output in
      (* Without this check a signer can be handed a prevout claiming a much
         larger value and induced to sign the difference away as fee. *)
      if not (String.equal (Tx.txid tx) prevout.Tx.Outpoint.txid) then Error `Prevout_mismatch
      else map_input p input (fun i -> Ok { i with Input.non_witness_utxo = Some tx })

  let set_redeem_script p ~input s =
    map_input p input (fun i -> Ok { i with Input.redeem_script = Some s })

  let set_witness_script p ~input s =
    map_input p input (fun i -> Ok { i with Input.witness_script = Some s })

  let set_sighash_type p ~input n =
    map_input p input (fun i -> Ok { i with Input.sighash_type = Some n })

  let add_bip32_derivation p ~input pk o =
    map_input p input (fun i ->
        Ok { i with Input.bip32_derivation = i.Input.bip32_derivation @ [ (pk, o) ] })

  let set_tap_internal_key p ~input k =
    if String.length k <> 32 then Error `Invalid_length
    else map_input p input (fun i -> Ok { i with Input.tap_internal_key = Some k })

  let set_tap_merkle_root p ~input r =
    if String.length r <> 32 then Error `Invalid_length
    else map_input p input (fun i -> Ok { i with Input.tap_merkle_root = Some r })
end

module Combiner = struct
  let merge_opt a b = match a with Some _ -> a | None -> b
  let merge_assoc a b = a @ List.filter (fun (k, _) -> not (List.mem_assoc k a)) b

  let combine_input (a : Input.t) (b : Input.t) =
    {
      Input.non_witness_utxo = merge_opt a.Input.non_witness_utxo b.Input.non_witness_utxo;
      witness_utxo = merge_opt a.Input.witness_utxo b.Input.witness_utxo;
      partial_sigs =
        a.Input.partial_sigs
        @ List.filter
            (fun (pk, _) ->
              not (List.exists (fun (pk', _) -> Key.Public.equal pk pk') a.Input.partial_sigs))
            b.Input.partial_sigs;
      sighash_type = merge_opt a.Input.sighash_type b.Input.sighash_type;
      redeem_script = merge_opt a.Input.redeem_script b.Input.redeem_script;
      witness_script = merge_opt a.Input.witness_script b.Input.witness_script;
      bip32_derivation =
        a.Input.bip32_derivation
        @ List.filter
            (fun (pk, _) ->
              not (List.exists (fun (pk', _) -> Key.Public.equal pk pk') a.Input.bip32_derivation))
            b.Input.bip32_derivation;
      final_script_sig = merge_opt a.Input.final_script_sig b.Input.final_script_sig;
      final_script_witness = merge_opt a.Input.final_script_witness b.Input.final_script_witness;
      ripemd160 = merge_assoc a.Input.ripemd160 b.Input.ripemd160;
      sha256 = merge_assoc a.Input.sha256 b.Input.sha256;
      hash160 = merge_assoc a.Input.hash160 b.Input.hash160;
      hash256 = merge_assoc a.Input.hash256 b.Input.hash256;
      tap_key_sig = merge_opt a.Input.tap_key_sig b.Input.tap_key_sig;
      tap_script_sig = merge_assoc a.Input.tap_script_sig b.Input.tap_script_sig;
      tap_leaf_script = merge_assoc a.Input.tap_leaf_script b.Input.tap_leaf_script;
      tap_bip32_derivation = merge_assoc a.Input.tap_bip32_derivation b.Input.tap_bip32_derivation;
      tap_internal_key = merge_opt a.Input.tap_internal_key b.Input.tap_internal_key;
      tap_merkle_root = merge_opt a.Input.tap_merkle_root b.Input.tap_merkle_root;
      proprietary = a.Input.proprietary @ b.Input.proprietary;
      (* BIP174 requires unknown fields to survive a combine, so a newer
         signer's data is not silently dropped by an older one. *)
      unknown = merge_assoc a.Input.unknown b.Input.unknown;
    }

  let combine_output (a : Output.t) (b : Output.t) =
    {
      Output.redeem_script = merge_opt a.Output.redeem_script b.Output.redeem_script;
      witness_script = merge_opt a.Output.witness_script b.Output.witness_script;
      bip32_derivation =
        a.Output.bip32_derivation
        @ List.filter
            (fun (pk, _) ->
              not (List.exists (fun (pk', _) -> Key.Public.equal pk pk') a.Output.bip32_derivation))
            b.Output.bip32_derivation;
      tap_internal_key = merge_opt a.Output.tap_internal_key b.Output.tap_internal_key;
      tap_tree = (if a.Output.tap_tree = [] then b.Output.tap_tree else a.Output.tap_tree);
      tap_bip32_derivation = merge_assoc a.Output.tap_bip32_derivation b.Output.tap_bip32_derivation;
      proprietary = a.Output.proprietary @ b.Output.proprietary;
      unknown = merge_assoc a.Output.unknown b.Output.unknown;
    }

  let combine a b =
    if
      not (String.equal (Tx.txid a.global.Global.unsigned_tx) (Tx.txid b.global.Global.unsigned_tx))
    then Error `Invalid_format
    else
      Ok
        {
          global =
            {
              a.global with
              Global.xpubs =
                a.global.Global.xpubs
                @ List.filter
                    (fun x ->
                      not
                        (List.exists
                           (fun x' -> x'.xpub_origin = x.xpub_origin)
                           a.global.Global.xpubs))
                    b.global.Global.xpubs;
              unknown = merge_assoc a.global.Global.unknown b.global.Global.unknown;
            };
          inputs = List.map2 combine_input a.inputs b.inputs;
          outputs = List.map2 combine_output a.outputs b.outputs;
        }

  let combine_all = function
    | [] -> Error `Incomplete
    | first :: rest ->
        List.fold_left
          (fun acc p -> match acc with Error _ as e -> e | Ok a -> combine a p)
          (Ok first) rest
end

module Signer = struct
  let utxo_of_input (p : t) index (i : Input.t) =
    match i.Input.witness_utxo with
    | Some o -> Some { Sighash.value = o.Tx.Out.value; script_pubkey = o.Tx.Out.script_pubkey }
    | None -> (
        match i.Input.non_witness_utxo with
        | None -> None
        | Some tx ->
            let prevout =
              (List.nth p.global.Global.unsigned_tx.Tx.inputs index).Tx.In.previous_output
            in
            let idx = Int32.to_int prevout.Tx.Outpoint.index in
            let outs = tx.Tx.outputs in
            if idx < 0 || idx >= List.length outs then None
            else
              let o = List.nth outs idx in
              Some { Sighash.value = o.Tx.Out.value; script_pubkey = o.Tx.Out.script_pubkey })

  let prevouts p =
    let utxos = List.mapi (fun i inp -> utxo_of_input p i inp) p.inputs in
    if List.exists (fun u -> u = None) utxos then Error `Incomplete
    else
      match
        Sighash.Prevouts.of_list p.global.Global.unsigned_tx
          (List.map (function Some u -> u | None -> assert false) utxos)
      with
      | Ok pv -> Ok pv
      | Error _ -> Error `Prevout_mismatch

  let sighash p ~input ~spend =
    let* pv = prevouts p in
    let flag =
      match (List.nth p.inputs input).Input.sighash_type with
      | None -> Sighash.Flag.Default
      | Some n -> (
          match Sighash.Flag.taproot_of_int (Int32.to_int n) with
          | Ok f -> f
          | Error _ -> Sighash.Flag.Default)
    in
    match Sighash.of_prevouts ~prevouts:pv ~input ~spend ~flag () with
    | Ok d -> Ok d
    | Error e -> Error (e :> error)

  let sign_taproot_key_path p ~input key ?merkle_root ?(aux_rand = String.make 32 '\000') () =
    if input < 0 || input >= List.length p.inputs then Error `Invalid_range
    else
      let* digest = sighash p ~input ~spend:Sighash.P2tr_key in
      match Taproot.tweak_secret key ~merkle_root with
      | Error _ -> Error `Invalid_format
      | Ok tweaked ->
          let sg = Key.Schnorr.to_octets (Key.Schnorr.sign ~key:tweaked ~aux_rand ~msg:digest ()) in
          (* SIGHASH_DEFAULT is omitted from the signature; any other type is
           appended as a trailing byte. *)
          let sg =
            match (List.nth p.inputs input).Input.sighash_type with
            | None | Some 0l -> sg
            | Some n -> sg ^ String.make 1 (Char.chr (Int32.to_int n land 0xff))
          in
          map_input p input (fun i -> Ok { i with Input.tap_key_sig = Some sg })

  let sign_ecdsa p ~input key ~spend =
    if input < 0 || input >= List.length p.inputs then Error `Invalid_range
    else
      let* digest = sighash p ~input ~spend in
      let sg = Key.Ecdsa.sign ~key ~digest in
      let ht =
        match (List.nth p.inputs input).Input.sighash_type with
        | None -> 0x01
        | Some n -> Int32.to_int n land 0xff
      in
      let der = Key.Ecdsa.to_der sg ^ String.make 1 (Char.chr ht) in
      let pk = Key.Secret.public key in
      map_input p input (fun i ->
          Ok { i with Input.partial_sigs = i.Input.partial_sigs @ [ (pk, der) ] })
end

module Finalizer = struct
  let is_finalized (i : Input.t) =
    i.Input.final_script_sig <> None || i.Input.final_script_witness <> None

  let finalize_input p ~input =
    if input < 0 || input >= List.length p.inputs then Error `Invalid_range
    else
      let i = List.nth p.inputs input in
      if is_finalized i then Ok p
      else
        let clear i =
          {
            i with
            Input.partial_sigs = [];
            sighash_type = None;
            redeem_script = None;
            witness_script = None;
            bip32_derivation = [];
            tap_key_sig = None;
            tap_script_sig = [];
            tap_leaf_script = [];
            tap_bip32_derivation = [];
            tap_internal_key = None;
            tap_merkle_root = None;
          }
        in
        let spk =
          match Signer.utxo_of_input p input i with
          | Some u -> Some u.Sighash.script_pubkey
          | None -> None
        in
        match (i.Input.tap_key_sig, spk) with
        | Some sg, _ ->
            (* Taproot key path: the witness is the signature alone. *)
            map_input p input (fun i ->
                Ok { (clear i) with Input.final_script_witness = Some [ sg ] })
        | None, Some spk -> (
            match (Script.classify spk, i.Input.partial_sigs) with
            | Script.Witness { version = 0; program }, [ (pk, sg) ] when String.length program = 20
              ->
                map_input p input (fun i ->
                    Ok
                      {
                        (clear i) with
                        Input.final_script_witness = Some [ sg; Key.Public.to_octets pk ];
                      })
            | Script.P2pkh _, [ (pk, sg) ] ->
                let script_sig =
                  Script.of_elements
                    [ Script.minimal_push sg; Script.minimal_push (Key.Public.to_octets pk) ]
                in
                map_input p input (fun i ->
                    Ok { (clear i) with Input.final_script_sig = Some script_sig })
            | _ ->
                (* Everything else -- multisig, script paths, wrapped SegWit --
               needs script semantics this library deliberately does not
               have. Reporting it beats emitting a half-finalized input. *)
                Error `Incomplete)
        | None, None -> Error `Incomplete

  let finalize p =
    let rec go p i =
      if i >= List.length p.inputs then Ok p
      else match finalize_input p ~input:i with Error _ as e -> e | Ok p -> go p (i + 1)
    in
    go p 0
end

module Extractor = struct
  let extract p =
    if not (List.for_all Finalizer.is_finalized p.inputs) then Error `Incomplete
    else
      let tx = p.global.Global.unsigned_tx in
      let inputs =
        List.map2
          (fun (txin : Tx.In.t) (i : Input.t) ->
            {
              txin with
              Tx.In.script_sig =
                Option.value i.Input.final_script_sig ~default:(Script.of_octets "");
              witness = Option.value i.Input.final_script_witness ~default:[];
            })
          tx.Tx.inputs p.inputs
      in
      Ok { tx with Tx.inputs }
end
