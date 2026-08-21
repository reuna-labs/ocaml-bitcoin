type hardened_marker = [ `Apostrophe | `H ]
type t = int32 list

let hardened_bit = 0x80000000l
let empty = []
let of_list l = l
let to_list l = l
let append p i = p @ [ i ]
let parent p = match List.rev p with [] -> None | _ :: rest -> Some (List.rev rest)
let depth = List.length
let equal = List.equal Int32.equal
let is_hardened i = Int32.logand i hardened_bit <> 0l

let child p n ~hardened =
  if n < 0 || n >= 0x80000000 then Error `Invalid_range
  else
    let i = Int32.of_int n in
    Ok (append p (if hardened then Int32.logor i hardened_bit else i))

let to_string ?(marker = `Apostrophe) p =
  let m = match marker with `Apostrophe -> "'" | `H -> "h" in
  "m"
  ^ String.concat ""
      (List.map
         (fun i ->
           if is_hardened i then
             Printf.sprintf "/%lu%s" (Int32.logand i (Int32.lognot hardened_bit)) m
           else Printf.sprintf "/%lu" i)
         p)

let of_string s =
  let parts = String.split_on_char '/' s in
  let parts = match parts with ("m" | "M") :: rest -> rest | all -> all in
  let parse acc part =
    match acc with
    | Error _ as e -> e
    | Ok acc -> (
        if part = "" then Error `Invalid_format
        else
          let n = String.length part in
          let last = part.[n - 1] in
          let hardened = last = '\'' || last = 'h' || last = 'H' in
          let digits = if hardened then String.sub part 0 (n - 1) else part in
          if digits = "" || not (String.for_all (fun c -> c >= '0' && c <= '9') digits) then
            Error `Invalid_format
          else
            match Int64.of_string_opt digits with
            | None -> Error `Invalid_format
            (* An unmarked index at or above 2^31 would be read as hardened,
             which is not what it says; refuse rather than reinterpret. *)
            | Some v when Int64.compare v 0x80000000L >= 0 -> Error `Invalid_format
            | Some v ->
                let i = Int64.to_int32 v in
                Ok ((if hardened then Int32.logor i hardened_bit else i) :: acc))
  in
  match List.fold_left parse (Ok []) parts with Error _ as e -> e | Ok rev -> Ok (List.rev rev)

let purpose n ~coin ~account =
  let h i = Int32.logor i hardened_bit in
  if
    Int32.unsigned_compare coin hardened_bit >= 0
    || Int32.unsigned_compare account hardened_bit >= 0
  then Error `Invalid_range
  else Ok [ h (Int32.of_int n); h coin; h account ]

let bip44 = purpose 44
let bip49 = purpose 49
let bip84 = purpose 84
let bip86 = purpose 86
let coin_type = function Network.Mainnet -> 0l | _ -> 1l
