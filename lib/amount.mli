(** Bitcoin amounts in satoshis.

    Every arithmetic operation is checked and returns a [result]. An amount that silently wraps
    [int64] — a summation of outputs, say — is a fund-loss bug, not a rounding error, so the type
    refuses to let it happen quietly.

    Values are constrained to [[0, 21_000_000 * 10^8]]. Bitcoin has no negative amounts; where a
    difference can go either way, compute it with {!diff}, which reports the sign separately. *)

type t = private int64
type error = [ `Overflow of string | `Invalid_range | `Invalid_format ]

val pp_error : Format.formatter -> [< error ] -> unit
val zero : t

val max_money : t
(** [21_000_000 * 10^8], the total supply and therefore the largest amount any single output can
    hold. *)

val sat_per_btc : int64
(** [100_000_000]. *)

(** {1 Conversion} *)

val of_sat : int64 -> (t, error) result
val to_sat : t -> int64

val of_sat_exn : int64 -> t
(** @raise Invalid_argument if out of range. Use for literals only. *)

val of_btc_string : string -> (t, error) result
(** Parses a decimal figure in BTC, such as ["0.00012345"], with at most eight decimal places.
    Rejects anything it cannot represent exactly rather than rounding: a silently rounded amount is
    a wrong amount. Deliberately does not go through [float]. *)

val to_btc_string : t -> string
(** The exact decimal figure in BTC, trailing zeros trimmed. Round-trips through {!of_btc_string}.
*)

(** {1 Arithmetic} *)

val add : t -> t -> (t, error) result

val sub : t -> t -> (t, error) result
(** Fails with [`Invalid_range] if the result would be negative. *)

val mul : t -> int64 -> (t, error) result
val sum : t list -> (t, error) result

val diff : t -> t -> [ `Pos of t | `Neg of t | `Zero ]
(** The signed difference, with the sign lifted out of the value. This is how to compare a
    transaction's inputs against its outputs without needing a signed amount type. *)

(** {1 Comparison} *)

val compare : t -> t -> int
val equal : t -> t -> bool

(** {1 Serialization} *)

val read : Codec.R.t -> t
(** An 8-byte little-endian value. Raises {!Codec.R.Parse_error} with [`Invalid_range] on a value
    outside the supply, which is what a corrupted or hostile transaction looks like here. *)

val write : Codec.W.t -> t -> unit
val pp : Format.formatter -> t -> unit
