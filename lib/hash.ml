let sha256 s = Digestif.SHA256.(to_raw_string (digest_string s))
let sha256d s = sha256 (sha256 s)
let ripemd160 s = Digestif.RMD160.(to_raw_string (digest_string s))
let hash160 s = ripemd160 (sha256 s)

let tagged ~tag msg =
  let h = sha256 tag in
  sha256 (h ^ h ^ msg)

module Tag = struct
  let tap_leaf = "TapLeaf"
  let tap_branch = "TapBranch"
  let tap_tweak = "TapTweak"
  let tap_sighash = "TapSighash"
  let bip340_challenge = "BIP0340/challenge"
  let bip340_aux = "BIP0340/aux"
  let bip340_nonce = "BIP0340/nonce"
end

let checksum4 s = String.sub (sha256d s) 0 4
