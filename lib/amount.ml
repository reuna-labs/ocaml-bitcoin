type t = int64
type error = [ `Overflow of string | `Invalid_range | `Invalid_format ]

let pp_error ppf (e : [< error ]) = Error.pp ppf (e :> Error.t)
let sat_per_btc = 100_000_000L
let zero = 0L
let max_money = 2_100_000_000_000_000L
let valid v = Int64.compare v 0L >= 0 && Int64.compare v max_money <= 0
let of_sat v = if valid v then Ok v else Error `Invalid_range
let to_sat v = v
let of_sat_exn v = if valid v then v else invalid_arg "Amount.of_sat_exn: outside the money range"
let compare = Int64.compare
let equal = Int64.equal

let add a b =
  let s = Int64.add a b in
  (* Both operands are non-negative and bounded, so a sum that is smaller
     than an operand can only mean overflow. *)
  if Int64.compare s a < 0 then Error (`Overflow "amount")
  else if valid s then Ok s
  else Error `Invalid_range

let sub a b = if Int64.compare a b < 0 then Error `Invalid_range else Ok (Int64.sub a b)

let mul a n =
  if Int64.compare n 0L < 0 then Error `Invalid_range
  else if Int64.equal n 0L then Ok 0L
  else
    let p = Int64.mul a n in
    if Int64.equal (Int64.div p n) a && valid p then Ok p else Error (`Overflow "amount")

let sum l =
  List.fold_left (fun acc v -> match acc with Error _ as e -> e | Ok a -> add a v) (Ok zero) l

let diff a b =
  let c = Int64.compare a b in
  if c = 0 then `Zero else if c > 0 then `Pos (Int64.sub a b) else `Neg (Int64.sub b a)

(* Decimal parsing without float: eight places exactly, no rounding. *)
let of_btc_string s =
  let n = String.length s in
  if n = 0 then Error `Invalid_format
  else
    let whole, frac =
      match String.index_opt s '.' with
      | None -> (s, "")
      | Some i -> (String.sub s 0 i, String.sub s (i + 1) (n - i - 1))
    in
    if whole = "" && frac = "" then Error `Invalid_format
    else if String.length frac > 8 then Error `Invalid_range
    else
      let digits_only x = String.for_all (fun c -> c >= '0' && c <= '9') x in
      if not (digits_only whole && digits_only frac) then Error `Invalid_format
      else
        let frac = frac ^ String.make (8 - String.length frac) '0' in
        let parse x =
          if x = "" then Ok 0L
          else
            match Int64.of_string_opt x with
            | Some v when Int64.compare v 0L >= 0 -> Ok v
            | _ -> Error (`Overflow "amount")
        in
        match (parse whole, parse frac) with
        | Ok w, Ok f -> (
            match mul w sat_per_btc with
            | Error _ as e -> e
            | Ok ws -> ( match add ws f with Error _ as e -> e | Ok v -> Ok v))
        | Error e, _ | _, Error e -> Error e

let to_btc_string v =
  let whole = Int64.div v sat_per_btc and frac = Int64.rem v sat_per_btc in
  if Int64.equal frac 0L then Printf.sprintf "%Ld" whole
  else
    let f = Printf.sprintf "%08Ld" frac in
    let last = ref (String.length f) in
    while !last > 1 && f.[!last - 1] = '0' do
      decr last
    done;
    Printf.sprintf "%Ld.%s" whole (String.sub f 0 !last)

let read r =
  let v = Codec.R.i64 r in
  if valid v then v else Codec.R.fail `Invalid_range

let write w v = Codec.W.i64 w v
let pp ppf v = Format.fprintf ppf "%s BTC" (to_btc_string v)
