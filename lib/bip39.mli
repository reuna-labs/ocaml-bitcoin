(** BIP39 mnemonic seed phrases, English only.

    Entropy of 128 to 256 bits becomes 12 to 24 words, with a checksum in the trailing bits. The
    seed is derived from the {e words}, not the entropy, which is why a phrase with a bad checksum
    still produces a usable seed in some wallets — this library refuses it instead, since a mistyped
    word is far likelier than a deliberate one.

    {1 Why English only}

    The other wordlists need NFKD normalisation of both the mnemonic and the passphrase, which means
    a Unicode database — a heavy dependency to carry into a unikernel for a feature most callers do
    not want. Non-ASCII input is rejected outright rather than silently producing the wrong seed. *)

type error =
  [ `Invalid_length
    (** entropy that is not 128..256 bits in 32-bit steps, or a word count that is not 12..24 in
        steps of 3 *)
  | `Invalid_checksum
  | `Invalid_format  (** a word outside the list, or non-ASCII input *)
  | `Msg of string ]

val pp_error : Format.formatter -> [< error ] -> unit

val wordlist : string array
(** The 2048 English words, in BIP39 order. Compiled in, not read from disk. *)

val of_entropy : string -> (string list, error) result
(** [of_entropy e] is the mnemonic for [e], whose length must be 16, 20, 24, 28 or 32 bytes. *)

val to_entropy : string list -> (string, error) result
(** Recovers the entropy, verifying the checksum. *)

val check : string list -> bool
(** Whether the phrase is well-formed and its checksum holds. *)

val to_seed : ?passphrase:string -> string list -> (string, error) result
(** The 64-byte seed, via PBKDF2-HMAC-SHA512 with 2048 iterations and the salt
    ["mnemonic" ^ passphrase]. Verifies the checksum first.

    The passphrase is part of the seed, so a different one silently yields a different wallet rather
    than an error. That is BIP39's design — it is what makes a plausible-deniability wallet possible
    — and it is also the most common way people lose funds with it. *)

val to_seed_unchecked : ?passphrase:string -> string list -> string
(** As {!to_seed} but without checking the checksum or the wordlist, for interoperating with a
    wallet that produced a phrase this library would reject. Prefer {!to_seed}. *)

val normalize : string -> string list
(** Splits on whitespace and lowercases. *)
