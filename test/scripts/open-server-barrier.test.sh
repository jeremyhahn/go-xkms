#!/usr/bin/env bash
#
# Tests for .devcontainer/scripts/open-server-barrier.sh (go-xkms#1055).
#
# The compose xkms-server is initialized by `xkmsd init` before it first boots,
# and its sealed window refuses barrier initialization with HTTP 409, so the
# opener must only ever unseal, and must fail with the server's own message on
# any other answer. These tests run the script against a fake `curl` on PATH
# that serves canned barrier status bodies and unseal replies, and record every
# request it is asked to make. No Docker, no network.
set -uo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
SCRIPT="$ROOT/.devcontainer/scripts/open-server-barrier.sh"
set +e
PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); printf '  ok   %s\n' "$1"; }
no() { FAIL=$((FAIL + 1)); printf '  FAIL %s\n    want: %s\n    got:  %s\n' "$1" "$2" "$3" >&2; }
eq() { [ "$2" = "$3" ] && ok "$1" || no "$1" "$2" "$3"; }
has() { case "$3" in *"$2"*) ok "$1" ;; *) no "$1" "contains: $2" "$3" ;; esac; }
lacks() { case "$3" in *"$2"*) no "$1" "does not contain: $2" "$3" ;; *) ok "$1" ;; esac; }
section() { printf '\n%s\n' "$1"; }

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

SECRET="stub-test-so-pin"
SECRET_B64=$(printf '%s' "$SECRET" | base64 -w0)
INITIALIZED='{"sealed": true, "strategy": "passphrase", "hardware_backed": false, "cluster_seal": false, "initialized_at": "2026-10-11T00:00:00Z"}'
UNINITIALIZED='{"sealed": true, "strategy": "passphrase", "hardware_backed": false, "cluster_seal": false}'
UNSEALED='{"sealed": false, "strategy": "passphrase", "hardware_backed": false, "cluster_seal": false, "initialized_at": "2026-10-11T00:00:00Z"}'

# The fake curl. GET /v1/barrier/status prints $STUB_STATUS (or fails as
# `curl -f` does when it is empty); any POST writes $STUB_BODY to the -o file
# and prints $STUB_CODE for -w. Each request is logged as "METHOD PATH DATA".
FAKEBIN="$WORK/bin"
mkdir -p "$FAKEBIN"
cat >"$FAKEBIN/curl" <<'EOF'
#!/bin/bash
method=GET out="" data="" url=""
while [ $# -gt 0 ]; do
	case "$1" in
	-X) method=$2; shift ;;
	-o) out=$2; shift ;;
	-d) data=$2; shift ;;
	-w | -H | --cacert) shift ;;
	-*) ;;
	*) url=$1 ;;
	esac
	shift
done
echo "$method ${url#https://*/} $data" >>"$STUB_LOG"
if [ "$method" = GET ]; then
	[ -n "$STUB_STATUS" ] || exit 22
	printf '%s' "$STUB_STATUS"
	exit 0
fi
if [ -n "$out" ] && [ "$out" != /dev/null ]; then
	printf '%s' "$STUB_BODY" >"$out"
fi
printf '%s' "$STUB_CODE"
EOF
printf '#!/bin/sh\nexit 0\n' >"$FAKEBIN/sleep"
chmod +x "$FAKEBIN/curl" "$FAKEBIN/sleep"

# run STATUS CODE BODY -- run the opener with the secret set; sets out, rc, calls.
run() {
	: >"$WORK/calls"
	out=$(PATH="$FAKEBIN:$PATH" STUB_LOG="$WORK/calls" STUB_STATUS="$1" STUB_CODE="$2" STUB_BODY="$3" \
		XKMS_SERVER_STATE_DIR="$WORK/state" XKMS_SERVER_BARRIER_SECRET="$SECRET" bash "$SCRIPT" 2>&1)
	rc=$?
	calls=$(cat "$WORK/calls")
}

# posts -- the POST requests the last run made, "METHOD PATH" only.
posts() { printf '%s\n' "$calls" | grep '^POST' | cut -d' ' -f1-2; }

section "an initialized, sealed barrier is unsealed with the secret"
run "$INITIALIZED" 204 ""
eq "exit 0" 0 "$rc"
eq "the only POST is the unseal route" "POST v1/barrier/unseal" "$(posts)"
has "the unseal carries the secret, base64" "\"secret\":\"$SECRET_B64\"" "$calls"
lacks "the secret is never printed" "$SECRET" "$out"

section "an uninitialized barrier is never initialized"
run "$UNINITIALIZED" 409 '{"error":"the system barrier is not initialized"}'
eq "exit 1" 1 "$rc"
eq "the only POST is the unseal route" "POST v1/barrier/unseal" "$(posts)"
has "the error carries the server's message" "the system barrier is not initialized" "$out"
has "the error says xkmsd init did not complete" "xkmsd init did not complete" "$out"
lacks "the secret is never printed" "$SECRET" "$out"

section "a 409 from the unseal route fails with the server's message"
run "$INITIALIZED" 409 '{"error":"system barrier initialization is refused here"}'
eq "exit 1" 1 "$rc"
has "the error names the status" "HTTP 409" "$out"
has "the error carries the server's message" "system barrier initialization is refused here" "$out"
lacks "the secret is never printed" "$SECRET" "$out"

section "any other status fails with the server's message"
run "$INITIALIZED" 400 '{"error":"invalid unseal credentials"}'
eq "exit 1" 1 "$rc"
has "the error names the status" "HTTP 400" "$out"
has "the error carries the server's message" "invalid unseal credentials" "$out"

section "an unsealed barrier is left alone"
run "$UNSEALED" 500 "must not be asked"
eq "exit 0" 0 "$rc"
eq "no POST" "" "$(posts)"

section "a window that never answers fails"
run "" 204 ""
eq "exit 1" 1 "$rc"
has "the error names the status route" "/v1/barrier/status did not answer" "$out"
eq "no POST" "" "$(posts)"

section "no secret, no request"
: >"$WORK/calls"
out=$(PATH="$FAKEBIN:$PATH" STUB_LOG="$WORK/calls" STUB_STATUS="$INITIALIZED" STUB_CODE=204 STUB_BODY="" \
	XKMS_SERVER_STATE_DIR="$WORK/state" XKMS_SERVER_BARRIER_SECRET="" bash "$SCRIPT" 2>&1)
rc=$?
eq "exit 1" 1 "$rc"
has "the error names the variable" "XKMS_SERVER_BARRIER_SECRET is not set" "$out"
eq "no request" "" "$(cat "$WORK/calls")"

printf '\npassed %d, failed %d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
