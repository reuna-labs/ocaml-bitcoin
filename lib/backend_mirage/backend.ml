(* One vendored native kernel for secret and public secp256k1 arithmetic. *)
module K = Mirage_crypto_secp256k1

type error = K.error
type secret = K.priv
type public = K.pub

let order = K.n
let field_prime = K.p
let secret_of_octets = K.priv_of_octets
let secret_to_octets = K.priv_to_octets
let secret_equal a b = Eqaf.equal (K.priv_to_octets a) (K.priv_to_octets b)
let secret_add = K.priv_add_tweak
let secret_negate = K.priv_negate
let public_of_octets = K.pub_of_octets
let public_to_octets ~compress p = K.pub_to_octets ~compress p
let public_equal a b = String.equal (K.pub_to_octets a) (K.pub_to_octets b)
let public_x p = String.sub (K.pub_to_octets p) 1 32
let public_has_even_y p = (K.pub_to_octets p).[0] = '\002'

let public_of_x_only x =
  if String.length x <> 32 then Error `Invalid_length else K.pub_of_octets ("\002" ^ x)

let public_of_secret s = K.pub_of_priv s
let public_add = K.pub_add
let public_negate = K.pub_negate
let public_add_tweak = K.pub_add_tweak

let ecdsa_sign ~secret ~digest =
  let compact = K.signature_to_octets ~compact:true (K.sign ~key:secret digest) in
  (String.sub compact 0 32, String.sub compact 32 32)

let ecdsa_verify ~public ~r ~s ~digest =
  String.length r = 32
  && String.length s = 32
  && String.length digest = 32
  &&
  match K.signature_of_octets (r ^ s) with
  | Error _ -> false
  | Ok signature -> K.verify ~key:public signature digest

let schnorr_sign ~secret ~aux_rand ~msg =
  K.Bip340.signature_to_octets (K.Bip340.sign ~aux_rand ~key:secret msg)

let schnorr_verify ~x_only ~signature ~msg =
  match (K.Bip340.xonly_pub_of_octets x_only, K.Bip340.signature_of_octets signature) with
  | Ok key, Ok signature -> K.Bip340.verify ~key signature msg
  | _ -> false
