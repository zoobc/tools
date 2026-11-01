#!/usr/bin/env bash
# Offline smoke test of the built tools. Nothing here reaches a network.
#   tests/smoke.sh <directory holding the built binaries>
set -euo pipefail
B="${1:?directory with the built binaries}"
K=1111111111111111111111111111111111111111111111111111111111111111    # test seed, 32 bytes
ADDR=ZBC_2BFLEMTU_FO2KWOQT_NC6UMFPE_43ICESVX_DIAWXL4F_ECRTFSLX_Q43UIV2I  # its ZBC address
MSG="hello zoobc"
SIG=4cdf8cafca5d06dd6c81c5460c9affec7eada96a63943e485b673ae33da6330570885a8b3f5dd752cbbe2b4404ae9402cdd2f6c36a09941e5d8546dbdd4ef10b
ZERO32=0000000000000000000000000000000000000000000000000000000000000000
n=0
pass() { n=$((n+1)); echo "ok   $*"; }
fail() { echo "FAIL $*" >&2; exit 1; }

"$B/zbc-cli" list | grep -q 'send-zbc' || fail "zbc-cli list does not list send-zbc"
pass "zbc-cli list"

out=$("$B/zbc-account-from-key" "$K")
grep -Eq "\"account_address\": ?\"$ADDR\"" <<<"$out" || fail "address from key: $out"
pass "zbc-account-from-key derives the known address"

SIG2=2f46d85055f241f522f4282cfdfae73614a262ac66a89245fcdacd7d5d57007071f132d3903a14f03c865887da24a01c5a8600d6563ec3cb1abfd81ab3022b0d   # ZBC-MSG-v2 over genesis ZERO32
out=$("$B/zbc-cli" sign-message "$K" "$MSG" --genesis "$ZERO32")
grep -Eq "\"signature\": ?\"$SIG2\"" <<<"$out" || fail "sign-message: $out"
grep -Eq '"scheme": ?"ZBC-MSG-v2"' <<<"$out" || fail "sign-message scheme: $out"
pass "sign-message reproduces the known chain-bound signature (ZBC-MSG-v2)"

out=$("$B/zbc-cli" verify-message "$ADDR" "$MSG" "$SIG2" --genesis "$ZERO32")
grep -Eq '"valid": ?true' <<<"$out" || fail "verify-message: $out"
pass "verify-message accepts it"

out=$("$B/zbc-cli" verify-message "$ADDR" "$MSG" "$SIG" --genesis "$ZERO32")
grep -Eq '"valid": ?true' <<<"$out" || fail "verify-message v1: $out"
pass "verify-message still accepts the old ZBC-MSG-v1 signature (until 2026-12-01)"

set +e; "$B/zbc-cli" verify-message "$ADDR" "hello zoobd" "$SIG2" --genesis "$ZERO32" >/dev/null 2>&1; rc=$?; set -e
[ "$rc" -eq 10 ] || fail "tampered message: expected exit 10, got $rc"
pass "verify-message rejects a tampered message with exit 10"

set +e; "$B/zbc-send" --fee >/dev/null 2>&1; rc=$?; set -e
[ "$rc" -eq 2 ] || fail "usage error: expected exit 2, got $rc"
pass "usage error exits 2"

set +e
out=$("$B/zbc-cli" send-zbc "$K" "$ADDR" 100000000 --api http://127.0.0.1:9 --genesis "$ZERO32" --timeout 2 2>/dev/null)
rc=$?
set -e
[ "$rc" -eq 3 ] || fail "unreachable node: expected exit 3, got $rc: $out"
grep -Eq '"error_class": ?"node_unreachable"' <<<"$out" || fail "unreachable node JSON: $out"
pass "unreachable node exits 3 with error_class node_unreachable"

# Air-gap signing: an UNSIGNED file built without the key, signed by sign-tx, is the transaction --offline signs
# with the key; a file whose summary was changed is refused with exit 10 and nothing is signed.
AG=$(mktemp -d)
"$B/zbc-cli" send-zbc "$ADDR" 100000000 --unsigned --from "$ADDR" --genesis "$ZERO32" --timestamp 1790000000 > "$AG/u.json"
grep -Eq '"format": ?"zbc-unsigned-v1"' "$AG/u.json" || fail "--unsigned: $(head -c 300 "$AG/u.json")"
! grep -q "$K" "$AG/u.json" || fail "--unsigned: the key is in the file"
ZBC_KEY=$K "$B/zbc-cli" sign-tx "$AG/u.json" --yes > "$AG/s.json" 2>/dev/null || fail "sign-tx refused a good file"
off=$("$B/zbc-cli" send-zbc "$K" "$ADDR" 100000000 --offline --genesis "$ZERO32" --timestamp 1790000000 --expiry 86400)
want=$(grep -Eo '"transaction_bytes": ?"[0-9a-f]+"' <<<"$off" | grep -Eo '[0-9a-f]{64,}')
grep -Eq "\"transaction_bytes\": ?\"$want\"" "$AG/s.json" || fail "sign-tx: not the transaction --offline signs"
pass "--unsigned + sign-tx gives the transaction --offline signs with the key"
sed 's/"1.00000000 ZBC"/"9.00000000 ZBC"/' "$AG/u.json" > "$AG/t.json"
grep -q '9.00000000 ZBC' "$AG/t.json" || fail "the tampered copy was not changed"
set +e; ZBC_KEY=$K "$B/zbc-cli" sign-tx "$AG/t.json" --yes > "$AG/ts.json" 2>/dev/null; rc=$?; set -e
[ "$rc" -eq 10 ] && [ ! -s "$AG/ts.json" ] || fail "tampered summary: expected exit 10 and nothing signed, got $rc"
pass "sign-tx refuses a tampered summary with exit 10"
rm -rf "$AG"

"$B/zbc-key-gen" | grep -q '"public_key"' || fail "zbc-key-gen"
pass "zbc-key-gen emits a key"

for t in zbc-send zbc-token-issue zbc-escrow-approve zbc-multisig zbc-node-register zbc-wallet-gen; do
    [ -x "$B/$t" ] || fail "missing binary $t"
done
pass "expected binaries present"

echo "smoke: $n checks passed"
