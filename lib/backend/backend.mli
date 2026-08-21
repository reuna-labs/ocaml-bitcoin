(** The secp256k1 operations this library needs, and nothing more.

    This is a {e virtual} module: the implementation is chosen at link time. It is deliberately the
    only place in the tree that names a cryptographic library, so that swapping one — or absorbing
    an upstream rename — is a single-file change.

    {1 Constant time}

    Implementations must perform every operation on a {!secret} in constant time with respect to
    that secret, with one documented exception: {!secret_add}, whose modular addition may branch on
    limb counts. See the security section of the project README.

    Operations on {!public} values act on public data and carry no such requirement.

    {1 Encodings}

    Scalars and field elements are 32-byte big-endian strings. Public keys are SEC1: 33 bytes
    compressed, 65 bytes uncompressed. ECDSA signatures are an [(r, s)] pair of 32-byte big-endian
    strings; DER lives above this layer, because BIP66's strictness rules are Bitcoin's, not the
    curve's. *)

type error = [ `Invalid_length | `Invalid_range | `Invalid_format | `Not_on_curve | `At_infinity ]

val order : string
(** The curve order [n], 32 bytes big-endian. *)

val field_prime : string
(** The field prime [p], 32 bytes big-endian. *)

(** {1 Keys}

    Both types are abstract: a {!secret} is defined by its octets and a {!public} by its curve
    point, and an implementation may cache whatever handles it needs behind them. *)

type secret
type public

(** {1 Secret scalars} *)

val secret_of_octets : string -> (secret, error) result
(** Requires exactly 32 bytes encoding a value in [\[1, n)]. *)

val secret_to_octets : secret -> string
val secret_equal : secret -> secret -> bool

val secret_add : secret -> string -> (secret, error) result
(** [secret_add d t] is [(d + t) mod n], where [t] is a 32-byte scalar. Returns [`Invalid_range] if
    [t] is not in [\[1, n)] or if the sum is zero. This is BIP32's child key derivation and BIP341's
    key tweak. *)

val secret_negate : secret -> secret
(** [n - d]. Needed because BIP340 defines signing against the even-[y] point. *)

val public_of_secret : secret -> public
(** Constant-time base point multiplication. *)

(** {1 Public points} *)

val public_of_octets : string -> (public, error) result
(** Accepts SEC1 compressed (33 bytes) or uncompressed (65 bytes). *)

val public_to_octets : compress:bool -> public -> string
val public_equal : public -> public -> bool

val public_x : public -> string
(** The x coordinate, 32 bytes big-endian — BIP340's "x-only" encoding. *)

val public_has_even_y : public -> bool

val public_of_x_only : string -> (public, error) result
(** BIP340's [lift_x]: the point with this x coordinate and even [y], or [`Not_on_curve] if there is
    none. *)

val public_add : public -> public -> (public, error) result
val public_negate : public -> public

val public_add_tweak : public -> string -> (public, error) result
(** [public_add_tweak p t] is [P + t*G]. This is BIP32 public derivation and the public half of
    BIP341's tweak. *)

(** {1 ECDSA} *)

val ecdsa_sign : secret:secret -> digest:string -> string * string
(** [ecdsa_sign ~secret ~digest] signs a 32-byte digest, returning [(r, s)] with [s] normalized low
    (BIP62/BIP146). Implementations must apply that normalization themselves; not every backend does
    it.

    @raise Invalid_argument if [digest] is not 32 bytes. *)

val ecdsa_verify : public:public -> r:string -> s:string -> digest:string -> bool
(** Accepts high-[s] signatures; enforcing low-[s] is a policy decision made above this layer. *)

(** {1 BIP340 Schnorr} *)

val schnorr_sign : secret:secret -> aux_rand:string -> msg:string -> string
(** 64-byte signature. [aux_rand] must be exactly 32 bytes and is always supplied: leaving it to the
    implementation risks reaching an unseeded RNG, which is a hard failure inside a unikernel.
    BIP340 permits 32 zero bytes.

    The BIP340 negation of a key whose point has odd [y] is the implementation's business; callers
    must not pre-negate. *)

val schnorr_verify : x_only:string -> signature:string -> msg:string -> bool
