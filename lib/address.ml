type error =
  [ `Invalid_length
  | `Invalid_format
  | `Invalid_checksum
  | `Invalid_version
  | `Wrong_variant
  | `Wrong_hrp
  | `Not_on_curve
  | `Invalid_range
  | `Msg of string ]

let pp_error ppf (e : [< error ]) = Error.pp ppf (e :> Error.t)

type t = P2pkh of string | P2sh of string | Segwit of { version : int; program : string }
type kind = [ `P2pkh | `P2sh | `P2wpkh | `P2wsh | `P2tr | `Future of int ]

let classify = function
  | P2pkh _ -> `P2pkh
  | P2sh _ -> `P2sh
  | Segwit { version = 0; program } -> if String.length program = 20 then `P2wpkh else `P2wsh
  | Segwit { version = 1; _ } -> `P2tr
  | Segwit { version; _ } -> `Future version

let equal a b =
  match (a, b) with
  | P2pkh x, P2pkh y | P2sh x, P2sh y -> String.equal x y
  | Segwit a, Segwit b -> a.version = b.version && String.equal a.program b.program
  | _ -> false

let to_string ~network = function
  | P2pkh h -> Base58.encode_check (String.make 1 (Char.chr (Network.p2pkh_version network)) ^ h)
  | P2sh h -> Base58.encode_check (String.make 1 (Char.chr (Network.p2sh_version network)) ^ h)
  | Segwit { version; program } -> (
      match Bech32.encode_segwit ~hrp:(Network.hrp network) ~version ~program with
      | Ok s -> s
      | Error _ ->
          (* Unreachable: every constructor validates its payload, so an address
         value cannot hold a program Bech32 would refuse. *)
          invalid_arg "Address.to_string: malformed address value")

let of_string s =
  (* Try Bech32 first: its alphabet overlaps Base58's, but the separator and
     checksum make a confident decision cheap. *)
  match Bech32.decode_segwit_any s with
  | Ok (hrp, version, program) -> (
      match Network.of_hrp hrp with
      | [] -> Error `Wrong_hrp
      | networks -> Ok (Segwit { version; program }, networks))
  | Error bech_err -> (
      match Base58.decode_check s with
      | Error _ ->
          (* Neither encoding accepted it. Report the Bech32 diagnosis when the
         string looked like a Bech32 attempt, since it is more specific. *)
          if String.contains s '1' && (bech_err = `Invalid_checksum || bech_err = `Wrong_variant)
          then Error (bech_err :> error)
          else Error `Invalid_format
      | Ok payload -> (
          if String.length payload <> 21 then Error `Invalid_length
          else
            let version = Char.code payload.[0] and hash = String.sub payload 1 20 in
            match Network.of_p2pkh_version version with
            | _ :: _ as networks -> Ok (P2pkh hash, networks)
            | [] -> (
                match Network.of_p2sh_version version with
                | _ :: _ as networks -> Ok (P2sh hash, networks)
                | [] -> Error `Invalid_version)))

let of_string_on ~network s =
  match of_string s with
  | Error _ as e -> e
  | Ok (addr, networks) -> if List.mem network networks then Ok addr else Error `Wrong_hrp

let script_pubkey = function
  | P2pkh h -> Script.p2pkh ~hash160:h
  | P2sh h -> Script.p2sh ~hash160:h
  | Segwit { version; program } -> Script.witness_program ~version ~program

let of_script_pubkey spk =
  match Script.classify spk with
  | Script.P2pkh h -> Ok (P2pkh h)
  | Script.P2sh h -> Ok (P2sh h)
  | Script.Witness { version; program } -> Ok (Segwit { version; program })
  | Script.P2pk _ | Script.Multisig _ | Script.Op_return _ | Script.Nonstandard ->
      (* Bare pubkey, bare multisig and OP_RETURN outputs are spendable or
       provably unspendable, but none of them has an address encoding. *)
      Error `Invalid_format

let p2pkh_of_key pub = P2pkh (Key.Public.hash160 pub)
let p2sh_of_script script = P2sh (Hash.hash160 (Script.to_octets script))
let p2wsh_of_script script = Segwit { version = 0; program = Hash.sha256 (Script.to_octets script) }

let p2wpkh_of_key pub =
  (* BIP143 makes uncompressed keys non-standard under SegWit. *)
  if not (Key.Public.is_compressed pub) then Error `Invalid_format
  else Ok (Segwit { version = 0; program = Key.Public.hash160 pub })

let p2sh_p2wpkh_of_key pub =
  match p2wpkh_of_key pub with
  | Error _ as e -> e
  | Ok inner -> Ok (p2sh_of_script (script_pubkey inner))

let p2tr ~output_key =
  if String.length output_key <> 32 then Error `Invalid_length
  else Ok (Segwit { version = 1; program = output_key })
