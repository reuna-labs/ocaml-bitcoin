# Security policy

This repository is unaudited alpha software. Do not use it to manage funds of
value. Report suspected vulnerabilities privately to `security@reuna.io` and
do not open a public issue before a coordinated fix is available.

## Review boundary

The highest-risk surfaces are consensus decoding, transaction/sighash
construction, Taproot tweaks, PSBT field binding, BIP32/BIP39 secret handling
and the cryptographic fork dependencies. Inputs and outputs are caller-owned;
coin selection, wallet policy, chain-state verification and secure key custody
are not provided by this library.

OCaml heap values are not reliably zeroized. Long-lived or high-value keys
should remain in an external signer. A successful vector suite or Solo5 build
is correctness evidence, not an audit or custody guarantee.
