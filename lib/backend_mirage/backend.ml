module Ec = Mirage_crypto_ec.P256k1
module Bc = Mirage_crypto_blockchain.Secp256k1

type error = [ `Invalid_length | `Invalid_range | `Invalid_format | `Not_on_curve | `At_infinity ]

(* mirage-crypto-ec adds `Low_order, which this curve (cofactor 1) cannot
   produce; fold it into `Invalid_range rather than widening our type. *)
let of_ec_error : Mirage_crypto_ec.error -> error = function
  | `Invalid_range | `Low_order -> `Invalid_range
  | `Invalid_format -> `Invalid_format
  | `Invalid_length -> `Invalid_length
  | `Not_on_curve -> `Not_on_curve
  | `At_infinity -> `At_infinity

let of_bc_error : Bc.error -> error = function
  | `Invalid_range -> `Invalid_range
  | `Invalid_format -> `Invalid_format
  | `Invalid_length -> `Invalid_length
  | `Not_on_curve -> `Not_on_curve
  | `At_infinity -> `At_infinity

let map_bc = function Ok x -> Ok x | Error e -> Error (of_bc_error e)

(* Big-endian 32-byte conversions. *)

let z_of_be s =
  let z = ref Z.zero in
  String.iter (fun c -> z := Z.logor (Z.shift_left !z 8) (Z.of_int (Char.code c))) s;
  !z

let z_to_be ?(len = 32) z =
  String.init len (fun i -> Char.chr (Z.to_int (Z.extract z (8 * (len - 1 - i)) 8)))

let order = z_to_be Bc.n
let field_prime = z_to_be Bc.p

(* A secret is defined by its octets; both library handles are views of the
   same 32 bytes, derived lazily. *)
type secret = { s_octets : string; ec_priv : Ec.Dsa.priv Lazy.t }

and public = {
  p_sec1 : string; (* canonical 33-byte compressed form *)
  ec_pub : Ec.Dsa.pub Lazy.t;
  point : Bc.point Lazy.t;
}

(* Both lazies below are forced only for octets already validated by the
   constructor, so the failure branches are unreachable. *)
let unreachable what = function
  | Ok v -> v
  | Error _ -> invalid_arg ("Bitcoin backend: " ^ what ^ " rejected already-validated octets")

let make_secret octets =
  {
    s_octets = octets;
    ec_priv = lazy (unreachable "priv_of_octets" (Ec.Dsa.priv_of_octets octets));
  }

let secret_of_octets octets =
  if String.length octets <> 32 then Error `Invalid_length
  else
    match Ec.Dsa.priv_of_octets octets with
    | Error e -> Error (of_ec_error e)
    | Ok _ -> Ok (make_secret octets)

let secret_to_octets s = s.s_octets

(* Constant-time comparison: a secret key is exactly the sort of value whose
   equality test should not leak where it diverges. *)
let secret_equal a b = Eqaf.equal a.s_octets b.s_octets

let make_public sec1 =
  {
    p_sec1 = sec1;
    ec_pub = lazy (unreachable "pub_of_octets" (Ec.Dsa.pub_of_octets sec1));
    point = lazy (unreachable "point_of_octets" (Bc.point_of_octets sec1));
  }

let public_of_octets octets =
  let n = String.length octets in
  if n <> 33 && n <> 65 then Error `Invalid_length
  else
    (* Validate through both backends, then canonicalise to compressed. *)
    match map_bc (Bc.point_of_octets octets) with
    | Error _ as e -> e
    | Ok pt -> (
        let sec1 = Bc.point_to_octets ~compress:true pt in
        match Ec.Dsa.pub_of_octets sec1 with
        | Error e -> Error (of_ec_error e)
        | Ok _ -> Ok (make_public sec1))

let public_to_octets ~compress p =
  if compress then p.p_sec1 else Bc.point_to_octets ~compress:false (Lazy.force p.point)

let public_equal a b = String.equal a.p_sec1 b.p_sec1
let public_x p = String.sub p.p_sec1 1 32
let public_has_even_y p = p.p_sec1.[0] = '\002'

(* BIP340 lift_x: the even-y point with this x, which is exactly the SEC1
   compressed encoding with an 0x02 prefix. *)
let public_of_x_only x =
  if String.length x <> 32 then Error `Invalid_length else public_of_octets ("\002" ^ x)

let public_of_secret s =
  (* Constant-time base multiplication, then re-import for point arithmetic. *)
  let sec1 = Ec.Dsa.pub_to_octets ~compress:true (Ec.Dsa.pub_of_priv (Lazy.force s.ec_priv)) in
  make_public sec1

let point_to_public pt = make_public (Bc.point_to_octets ~compress:true pt)

let public_add a b =
  match map_bc (Bc.add (Lazy.force a.point) (Lazy.force b.point)) with
  | Error _ as e -> e
  | Ok pt -> Ok (point_to_public pt)

(* The field prime is odd, so y and p - y always differ in parity, and the
   SEC1 prefix byte is exactly that parity. Negating a compressed point is
   therefore just flipping the prefix -- no arithmetic at all. *)
let public_negate p =
  let prefix = if p.p_sec1.[0] = '\002' then '\003' else '\002' in
  make_public (String.mapi (fun i c -> if i = 0 then prefix else c) p.p_sec1)

let public_add_tweak p t =
  match map_bc (Bc.scalar_of_octets t) with
  | Error _ as e -> e
  | Ok sc -> (
      match map_bc (Bc.scalar_mult sc Bc.g) with
      | Error _ as e -> e
      | Ok tg -> (
          match map_bc (Bc.add (Lazy.force p.point) tg) with
          | Error _ as e -> e
          | Ok pt -> Ok (point_to_public pt)))

(* Both of these are constant time, and deliberately do not go through
   Zarith: GMP branches on limb counts, and these run on secret scalars
   during BIP32 derivation and Taproot tweaking. *)
let secret_add s t =
  if String.length t <> 32 then Error `Invalid_length
  else
    match Ec.Dsa.priv_of_octets t with
    (* Rejects a tweak of zero or at/above the order, which BIP32 and BIP341
       both require the caller to treat as "try the next index". *)
    | Error e -> Error (of_ec_error e)
    | Ok tk -> (
        match Ec.Dsa.add_scalar (Lazy.force s.ec_priv) tk with
        | Error e -> Error (of_ec_error e)
        | Ok sum -> Ok (make_secret (Ec.Dsa.priv_to_octets sum)))

let secret_negate s =
  make_secret (Ec.Dsa.priv_to_octets (Ec.Dsa_bip340.negate_scalar (Lazy.force s.ec_priv)))

(* --- ECDSA ------------------------------------------------------------- *)

let half_order = Z.divexact (Z.sub Bc.n Z.one) (Z.of_int 2)

let ecdsa_sign ~secret ~digest =
  if String.length digest <> 32 then invalid_arg "Backend.ecdsa_sign: digest must be 32 bytes";
  let r, s = Ec.Dsa.sign ~key:(Lazy.force secret.ec_priv) digest in
  (* mirage-crypto-ec returns s as computed. Bitcoin requires the low
     variant (BIP62/BIP146): a high-s signature is valid but non-standard,
     so Core will not relay it. Normalising here is not optional.

     This is the one place a bignum still touches signing data, and it is
     safe: s is the signature about to be published, so timing on it reveals
     nothing that the signature itself does not. No secret reaches Zarith. *)
  let sz = z_of_be s in
  let s = if Z.gt sz half_order then z_to_be (Z.sub Bc.n sz) else s in
  (r, s)

let ecdsa_verify ~public ~r ~s ~digest =
  String.length r = 32
  && String.length s = 32
  && String.length digest = 32
  && Ec.Dsa.verify ~key:(Lazy.force public.ec_pub) (r, s) digest

(* --- BIP340 Schnorr ---------------------------------------------------- *)

let schnorr_sign ~secret ~aux_rand ~msg =
  if String.length aux_rand <> 32 then invalid_arg "Backend.schnorr_sign: aux_rand must be 32 bytes";
  let r, s = Ec.Dsa_bip340.sign_bip340 ~key:(Lazy.force secret.ec_priv) ~aux_rand msg in
  r ^ s

let schnorr_verify ~x_only ~signature ~msg =
  String.length x_only = 32
  && String.length signature = 64
  &&
  match public_of_x_only x_only with
  | Error _ -> false
  | Ok p ->
      Ec.Dsa_bip340.verify_bip340 ~key:(Lazy.force p.ec_pub)
        (String.sub signature 0 32, String.sub signature 32 32)
        msg
