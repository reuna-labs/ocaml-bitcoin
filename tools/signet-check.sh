#!/usr/bin/env bash
# Public-testnet evidence for the published bitcoin package: signet's
# consensus and a signet node judge what it computes.
#
#   tools/signet-check.sh
#
# Installs bitcoin from the public Reuna opam overlay in a pinned container (a
# consumer's view: nothing from this checkout but tools/signet_check.ml) and
# reaches signet through an Esplora API (ESPLORA, default Blockstream's).
#
# 1. Sighash against consensus. Transactions signet has already confirmed,
#    from the latest blocks, with at least three P2WPKH and three taproot
#    key-path inputs among them, and what each input spent. For every such
#    input the package recomputes the BIP143 or BIP341 digest and the
#    signature in the chain must verify against it, and must stop verifying
#    when the input's amount is one satoshi higher. So the package's digests
#    are the ones signet's signers produced and its nodes accepted, and they
#    commit to the amount.
# 2. A node judging our bytes. A fresh key signs a P2WPKH spend of a real
#    unspent output that is someone else's: its value less 1000 sat, to the
#    fresh key's own address. A node must refuse it at the script check
#    (OP_EQUALVERIFY: the key is not the owner's), which it reaches only after
#    decoding the transaction, finding the input, and finding value, fee and
#    standardness acceptable; and the txid and wtxid it names must be the
#    package's. The same spend claiming 1000 sat more than the input holds
#    must be refused on value, before any script runs. Nothing can move.
set -euo pipefail
here=$(cd "$(dirname "$0")/.." && pwd)
IMAGE=docker.io/ocaml/opam:debian-12-ocaml-5.5@sha256:36803e379c31545ef00dfb64f8bdf3226b5e8c7b76746b636caedda811c625f3
OVERLAY=${BITCOIN_OVERLAY:-https://github.com/reuna-labs/opam-repository.git}
ESPLORA=${ESPLORA:-https://blockstream.info/signet/api}
work=$(mktemp -d)
name=signet-check-$$
cleanup() { docker rm -f "$name" >/dev/null 2>&1 || true; rm -rf "${work:?}"; }
trap cleanup EXIT

echo "== signet at height $(curl -fsS -m 30 "$ESPLORA/blocks/tip/height") ($ESPLORA)"

# Confirmed spends: one line per transaction, its raw hex then each input's
# prevout value and scriptPubKey.
python3 -c '
import json, sys, urllib.request
api = sys.argv[1]
def get(path, raw=False):
    with urllib.request.urlopen(api + path, timeout=60) as r:
        data = r.read().decode()
    return data if raw else json.loads(data)
want = {"v0_p2wpkh": 3, "v1_p2tr": 3}
got = {k: 0 for k in want}
lines, block = [], get("/blocks/tip/hash", raw=True).strip()
for _ in range(40):
    if all(got[k] >= want[k] for k in want):
        break
    for t in get("/block/%s/txs/0" % block):
        vin = t["vin"]
        if any(v.get("is_coinbase") for v in vin):
            continue
        types = [v["prevout"]["scriptpubkey_type"] for v in vin]
        if not any(k in want and got[k] < want[k] for k in types):
            continue
        prev = " ".join("%s %s" % (v["prevout"]["value"], v["prevout"]["scriptpubkey"]) for v in vin)
        lines.append(get("/tx/%s/hex" % t["txid"], raw=True).strip() + " " + prev)
        for k in types:
            if k in got:
                got[k] += 1
    block = get("/block/%s" % block)["previousblockhash"]
print("\n".join(lines))
' "$ESPLORA" >"$work/confirmed.txt"

# Someone else's unspent P2WPKH output, not a coinbase's, of at least 10000 sat.
read -r txid index value < <(python3 -c '
import json, sys, urllib.request
api = sys.argv[1]
def get(path):
    with urllib.request.urlopen(api + path, timeout=60) as r:
        return json.loads(r.read().decode())
block = get("/blocks/tip")[0]["id"]
for _ in range(10):
    for t in get("/block/%s/txs/0" % block):
        if any(v.get("is_coinbase") for v in t["vin"]):
            continue
        for i, o in enumerate(t["vout"]):
            if o.get("scriptpubkey_type") == "v0_p2wpkh" and o["value"] >= 10000:
                if not get("/tx/%s/outspend/%d" % (t["txid"], i))["spent"]:
                    print(t["txid"], i, o["value"])
                    sys.exit(0)
    block = get("/block/%s" % block)["previousblockhash"]
sys.exit("no unspent P2WPKH output found")
' "$ESPLORA")

echo "== the published bitcoin package (overlay $OVERLAY)"
docker run -d --name "$name" -e OVERLAY="$OVERLAY" -v "$here/tools/signet_check.ml:/src/signet_check.ml:ro" \
	"$IMAGE" sleep 3600 >/dev/null
docker exec "$name" sh -ec '
	opam repository add reuna "$OVERLAY" >/dev/null 2>&1
	opam install -y --confirm-level=unsafe-yes bitcoin >/tmp/install.log 2>&1 || { tail -20 /tmp/install.log >&2; exit 1; }
	opam list --installed --columns=name,version bitcoin 2>/dev/null | grep -v "^#" | sed "s/^/  /"
	mkdir -p /tmp/w && cd /tmp/w && cp /src/signet_check.ml .
	printf "(lang dune 3.0)\n" > dune-project
	printf "(executable (name signet_check) (libraries bitcoin))\n" > dune
	opam exec -- dune build ./signet_check.exe'
run() { docker exec -i "$name" /tmp/w/_build/default/signet_check.exe "$@"; }

fail=0
echo "== 1. sighash against consensus: $(wc -l <"$work/confirmed.txt" | tr -d ' ') confirmed transactions"
verdicts=$(run verify <"$work/confirmed.txt")
for kind in p2wpkh p2tr-key; do
	n=$(printf '%s\n' "$verdicts" | grep -c "^ok $kind " || true)
	if [ "$n" -ge 3 ]; then
		echo "  ok: $n $kind signatures verify against the package's digest, and not with the amount one sat higher"
	else
		echo "  FAIL: only $n $kind inputs verified"; fail=1
	fi
done
if printf '%s\n' "$verdicts" | grep -E '^(bad|tamper-verified) '; then
	echo "  FAIL: the lines above did not verify, or verified with a different amount"; fail=1
fi

echo "== 2. a node judging our bytes: spending $txid:$index ($value sat), someone else's"
out=$(run spend "$txid" "$index" "$value" 1000)
printf '%s\n' "$out" | grep -v '^wire' | sed 's/^/  /'
ours_txid=$(printf '%s\n' "$out" | awk '$1=="txid" {print $2}')
ours_wtxid=$(printf '%s\n' "$out" | awk '$1=="wtxid" {print $2}')
said=$(curl -sS -m 60 -X POST --data "$(printf '%s\n' "$out" | awk '$1=="wire" {print $2}')" "$ESPLORA/tx")
echo "  node: $said"
case $said in
*script-verify-flag-failed*OP_EQUALVERIFY*)
	echo "  ok: refused at the script check, past decoding, input lookup, value, fee and standardness" ;;
*) echo "  FAIL: not refused at the script check"; fail=1 ;;
esac
case $said in
*"input 0 of $ours_txid (wtxid $ours_wtxid)"*) echo "  ok: the node names the package's txid and wtxid" ;;
*) echo "  FAIL: the node's txid/wtxid are not the package's ($ours_txid, $ours_wtxid)"; fail=1 ;;
esac
over=$(run spend "$txid" "$index" "$((value + 1000))" 1000 | awk '$1=="wire" {print $2}')
said=$(curl -sS -m 60 -X POST --data "$over" "$ESPLORA/tx")
case $said in
*in-belowout*|*"min relay fee not met"*) echo "  ok: claiming 1000 sat more than the input holds is refused on value: $said" ;;
*) echo "  FAIL: the overspend: $said"; fail=1 ;;
esac

[ "$fail" = 0 ] && echo PASS || { echo FAIL; exit 1; }
