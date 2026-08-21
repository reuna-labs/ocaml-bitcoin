type t =
  [ `Eof of int
  | `Trailing of int
  | `Non_canonical_varint
  | `Overflow of string
  | `Invalid_length
  | `Invalid_range
  | `Invalid_format
  | `Invalid_checksum
  | `Invalid_version
  | `Wrong_variant
  | `Wrong_hrp
  | `Not_on_curve
  | `At_infinity
  | `Too_deep
  | `Not_in_tree
  | `Msg of string ]

let pp ppf (e : [< t ]) =
  match e with
  | `Eof n ->
      Format.fprintf ppf "unexpected end of input (wanted %d more byte%s)" n
        (if n = 1 then "" else "s")
  | `Trailing n ->
      Format.fprintf ppf "%d trailing byte%s after a complete parse" n (if n = 1 then "" else "s")
  | `Non_canonical_varint -> Format.pp_print_string ppf "non-canonical CompactSize encoding"
  | `Overflow ty -> Format.fprintf ppf "value out of range for %s" ty
  | `Invalid_length -> Format.pp_print_string ppf "invalid length"
  | `Invalid_range -> Format.pp_print_string ppf "value out of range"
  | `Invalid_format -> Format.pp_print_string ppf "invalid format"
  | `Invalid_checksum -> Format.pp_print_string ppf "invalid checksum"
  | `Invalid_version -> Format.pp_print_string ppf "unrecognised version byte"
  | `Wrong_variant -> Format.pp_print_string ppf "wrong Bech32 variant for this witness version"
  | `Wrong_hrp -> Format.pp_print_string ppf "address belongs to a different network"
  | `Not_on_curve -> Format.pp_print_string ppf "point is not on the curve"
  | `At_infinity -> Format.pp_print_string ppf "point at infinity"
  | `Too_deep -> Format.pp_print_string ppf "script tree deeper than 128 levels"
  | `Not_in_tree -> Format.pp_print_string ppf "leaf is not in this output's script tree"
  | `Msg m -> Format.pp_print_string ppf m

let to_string e = Format.asprintf "%a" pp e
