#!/usr/bin/env bash
#
# Tests for build/docker/devcontainer/scripts/open-server-barrier.sh (go-xkms#1055).
#
# The compose xkms-server is initialized by `xkmsd init` before it first boots,
# and its sealed window refuses barrier initialization with HTTP 409, so the
# opener must only ever unseal, and must fail with the server's own message on
# any other answer. It verifies the server only against the anchors the server
# persisted in its state directory, never with curl -k. These tests run the
# script against a fake `curl` on PATH that models the server and records every
# request it is asked to make. No Docker, no network.
set -uo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
SCRIPT="$ROOT/build/docker/devcontainer/scripts/open-server-barrier.sh"
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

# The fake curl models xkmsd as the reproduction against a real one showed it
# (DS-3769). The sealed window serves the bootstrap certificate, refuses
# /health (503) and answers GET /v1/barrier/status with $STUB_STATUS; a POST
# writes $STUB_BODY to the -o file and prints $STUB_CODE for -w. A 204 unseal,
# or STUB_UNSEALED=1, makes it the full server: it answers /health per
# $STUB_HEALTH ("up" answers, empty never does) and answers
# /v1/barrier/status 401 to this unauthenticated caller. With STUB_SWAP=1 the
# full server serves its CA-issued certificate, after persisting the CA bundle
# beside the bootstrap certificate, as pkg/server upgradeUnifiedTLSCert does;
# STUB_IMPOSTOR=1 serves a certificate no anchor verifies. A certificate the
# --cacert anchors do not verify fails with curl's exit 60. Each request is
# logged as "METHOD PATH DATA", with INSECURE appended when it skips
# verification.
FAKEBIN="$WORK/bin"
mkdir -p "$FAKEBIN"
cat >"$FAKEBIN/curl" <<'EOF'
#!/bin/bash
method=GET out="" data="" url="" cacert="" insecure=""
while [ $# -gt 0 ]; do
	case "$1" in
	-X) method=$2; shift ;;
	-o) out=$2; shift ;;
	-d) data=$2; shift ;;
	--cacert) cacert=$2; shift ;;
	-w | -H) shift ;;
	--insecure | -[a-zA-Z]*k*) insecure=1 ;;
	-*) ;;
	*) url=$1 ;;
	esac
	shift
done
unsealed=${STUB_UNSEALED:-}
if [ "$STUB_CODE" = 204 ] && grep -q '^POST' "$STUB_LOG"; then
	unsealed=1
fi
echo "$method ${url#https://*/} $data${insecure:+ INSECURE}" >>"$STUB_LOG"
presented=stub-bootstrap-cert
if [ -n "$unsealed" ] && [ -n "${STUB_SWAP:-}" ]; then
	printf 'stub-ca-bundle' >"$XKMS_SERVER_STATE_DIR/storage/unified-tls/ca-bundle.pem"
	presented=stub-ca-bundle
fi
[ -n "${STUB_IMPOSTOR:-}" ] && presented=stub-impostor-cert
if [ -z "$insecure" ]; then
	[ -n "$cacert" ] || exit 77
	case "$(cat "$cacert")" in *"$presented"*) ;; *) exit 60 ;; esac
fi

case "$url" in
*/health)
	[ -n "$unsealed" ] || exit 22
	[ "$STUB_HEALTH" = up ] || exit 22
	exit 0
	;;
*/v1/ca/bootstrap)
	printf 'stub-ca-bundle' >"$out"
	exit 0
	;;
esac
if [ "$method" = GET ]; then
	[ -z "$unsealed" ] || exit 22
	[ -n "$STUB_STATUS" ] || exit 7
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

# run STATUS CODE BODY [HEALTH] -- run the opener with the secret set, against
# a state directory holding the bootstrap certificate; HEALTH defaults to a
# server that comes up after the unseal. STUB_UNSEALED, STUB_SWAP and
# STUB_IMPOSTOR pass through from the caller. Sets out, rc, calls.
run() {
	rm -rf "$WORK/state"
	mkdir -p "$WORK/state/storage/unified-tls"
	printf 'stub-bootstrap-cert' >"$WORK/state/storage/unified-tls/cert.pem"
	exec_opener "$@"
}

# exec_opener STATUS CODE BODY [HEALTH] -- run the opener against the state
# directory as it is.
exec_opener() {
	: >"$WORK/calls"
	out=$(PATH="$FAKEBIN:$PATH" STUB_LOG="$WORK/calls" STUB_STATUS="$1" STUB_CODE="$2" STUB_BODY="$3" \
		STUB_HEALTH="${4-up}" XKMS_SERVER_STATE_DIR="$WORK/state" XKMS_SERVER_BARRIER_SECRET="$SECRET" \
		bash "$SCRIPT" 2>&1)
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
has "it waits for the full server's /health" "GET health" "$calls"
has "it reports the barrier unsealed" "barrier unsealed" "$out"
lacks "no request skips verification" "INSECURE" "$calls"

section "a server that swaps to its CA-issued certificate after the unseal answers /health"
STUB_SWAP=1 run "$INITIALIZED" 204 ""
eq "exit 0" 0 "$rc"
has "it reports the barrier unsealed" "barrier unsealed" "$out"
lacks "it does not report /health dead" "never answered" "$out"
lacks "no request skips verification" "INSECURE" "$calls"
lacks "it fetches no CA bundle over the wire" "v1/ca/bootstrap" "$calls"

section "a server a previous suite unsealed, on its CA-issued certificate, is left alone"
STUB_UNSEALED=1 STUB_SWAP=1 run "" 500 "must not be asked"
eq "exit 0" 0 "$rc"
has "it reports the barrier already unsealed" "already unsealed" "$out"
lacks "it does not report the status route dead" "did not answer" "$out"
eq "no POST" "" "$(posts)"
lacks "no request skips verification" "INSECURE" "$calls"
lacks "it fetches no CA bundle over the wire" "v1/ca/bootstrap" "$calls"

section "an unsealed server still on its bootstrap certificate is left alone"
STUB_UNSEALED=1 run "" 500 "must not be asked"
eq "exit 0" 0 "$rc"
has "it reports the barrier already unsealed" "already unsealed" "$out"
eq "no POST" "" "$(posts)"

section "a window that reports the barrier open is waited on through /health"
run "$UNSEALED" 500 "must not be asked" ""
eq "exit 1" 1 "$rc"
eq "no POST" "" "$(posts)"
has "the error names /health" "/health never answered" "$out"

section "a server the persisted anchors do not verify is never sent the secret"
STUB_IMPOSTOR=1 run "$INITIALIZED" 204 ""
eq "exit 1" 1 "$rc"
eq "no POST" "" "$(posts)"
has "the error names the status route" "/v1/barrier/status did not answer" "$out"
lacks "no request skips verification" "INSECURE" "$calls"

section "an unreadable bootstrap certificate stops before any request"
rm -rf "$WORK/state"
exec_opener "$INITIALIZED" 204 ""
eq "exit 1" 1 "$rc"
has "the error names the certificate" "cannot read the server's bootstrap certificate" "$out"
eq "no request" "" "$calls"

section "a server that never answers /health after the unseal fails"
run "$INITIALIZED" 204 "" ""
eq "exit 1" 1 "$rc"
eq "the only POST is the unseal route" "POST v1/barrier/unseal" "$(posts)"
has "the error names /health" "/health never answered" "$out"
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
