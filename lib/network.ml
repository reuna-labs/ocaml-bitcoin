type t = Mainnet | Testnet3 | Testnet4 | Signet | Regtest
type class_ = [ `Main | `Test | `Regtest ]

let all = [ Mainnet; Testnet3; Testnet4; Signet; Regtest ]

let class_of = function
  | Mainnet -> `Main
  | Testnet3 | Testnet4 | Signet -> `Test
  | Regtest -> `Regtest

let to_string = function
  | Mainnet -> "mainnet"
  | Testnet3 -> "testnet3"
  | Testnet4 -> "testnet4"
  | Signet -> "signet"
  | Regtest -> "regtest"

let of_string s =
  match String.lowercase_ascii s with
  | "mainnet" | "main" | "bitcoin" -> Some Mainnet
  | "testnet3" | "testnet" | "test" -> Some Testnet3
  | "testnet4" -> Some Testnet4
  | "signet" -> Some Signet
  | "regtest" -> Some Regtest
  | _ -> None

(* Base58 version bytes. Regtest deliberately shares testnet's, which is why
   only a class can be recovered from an address. *)

let p2pkh_version = function Mainnet -> 0x00 | Testnet3 | Testnet4 | Signet | Regtest -> 0x6f
let p2sh_version = function Mainnet -> 0x05 | Testnet3 | Testnet4 | Signet | Regtest -> 0xc4
let wif_version = function Mainnet -> 0x80 | Testnet3 | Testnet4 | Signet | Regtest -> 0xef
let of_p2pkh_version = function 0x00 -> Some `Main | 0x6f -> Some `Test | _ -> None
let of_p2sh_version = function 0x05 -> Some `Main | 0xc4 -> Some `Test | _ -> None
let of_wif_version = function 0x80 -> Some `Main | 0xef -> Some `Test | _ -> None
let hrp = function Mainnet -> "bc" | Testnet3 | Testnet4 | Signet -> "tb" | Regtest -> "bcrt"

let of_hrp s =
  match String.lowercase_ascii s with
  | "bc" -> Some `Main
  | "tb" -> Some `Test
  | "bcrt" -> Some `Regtest
  | _ -> None

let bip32_public = function
  | Mainnet -> 0x0488b21el
  | Testnet3 | Testnet4 | Signet | Regtest -> 0x043587cfl

let bip32_private = function
  | Mainnet -> 0x0488ade4l
  | Testnet3 | Testnet4 | Signet | Regtest -> 0x04358394l

let of_bip32_version v =
  if v = 0x0488b21el then Some (`Main, `Public)
  else if v = 0x0488ade4l then Some (`Main, `Private)
  else if v = 0x043587cfl then Some (`Test, `Public)
  else if v = 0x04358394l then Some (`Test, `Private)
  else None

let magic = function
  | Mainnet -> "\xf9\xbe\xb4\xd9"
  | Testnet3 -> "\x0b\x11\x09\x07"
  | Testnet4 -> "\x1c\x16\x3f\x28"
  | Signet -> "\x0a\x03\xcf\x40"
  | Regtest -> "\xfa\xbf\xb5\xda"
