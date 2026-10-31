#!/usr/bin/env bash
#
# Tests for build/docker/devcontainer/scripts/ensure-server-ca.sh (DS-3769).
#
# With the qrdb storage backend the script fetches the compose xkms-server's CA
# bundle from its trust-bootstrap endpoint. It verifies the server only against
# the anchors the server persisted in its state directory, never with curl -k,
# and fails with a clear message when no verified server serves a bundle.
# These tests run the script against a fake `curl` and `getent` on PATH that
# model the server and record every request. No Docker, no network.
set -uo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
SCRIPT="$ROOT/build/docker/devcontainer/scripts/ensure-server-ca.sh"
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

BUNDLE=$'-----BEGIN CERTIFICATE-----\nstub-server-ca\n-----END CERTIFICATE-----'

# The fake curl models the unsealed compose server. It presents its bootstrap
# certificate, or with STUB_SWAP=1 its CA-issued one, verified by the CA
# bundle it persisted beside the bootstrap certificate (pkg/server
# upgradeUnifiedTLSCert); STUB_IMPOSTOR=1 presents a certificate no anchor
# verifies. A certificate the --cacert anchors do not verify fails with curl's
# exit 60. GET /v1/ca/bootstrap writes $STUB_BUNDLE to the -o file. Each
# request is logged as "PATH", with INSECURE appended when it skips
# verification. The fake getent resolves only $STUB_HOST.
FAKEBIN="$WORK/bin"
mkdir -p "$FAKEBIN"
cat >"$FAKEBIN/curl" <<'EOF'
#!/bin/bash
out="" url="" cacert="" insecure=""
while [ $# -gt 0 ]; do
	case "$1" in
	-o) out=$2; shift ;;
	--cacert) cacert=$2; shift ;;
	-w | -H | -X | -d) shift ;;
	--insecure | -[a-zA-Z]*k*) insecure=1 ;;
	-*) ;;
	*) url=$1 ;;
	esac
	shift
done
echo "${url#https://*/}${insecure:+ INSECURE}" >>"$STUB_LOG"
presented=stub-bootstrap-cert
[ -n "${STUB_SWAP:-}" ] && presented=stub-ca-issued-cert
[ -n "${STUB_IMPOSTOR:-}" ] && presented=stub-impostor-cert
if [ -z "$insecure" ]; then
	[ -n "$cacert" ] || exit 77
	case "$(cat "$cacert")" in *"$presented"*) ;; *) exit 60 ;; esac
fi
case "$url" in
*/v1/ca/bootstrap)
	printf '%s' "$STUB_BUNDLE" >"$out"
	exit 0
	;;
esac
exit 22
EOF
cat >"$FAKEBIN/getent" <<'EOF'
#!/bin/sh
[ "$2" = "$STUB_HOST" ] && echo "172.18.0.2 $2"
EOF
printf '#!/bin/sh\nexit 0\n' >"$FAKEBIN/sleep"
chmod +x "$FAKEBIN/curl" "$FAKEBIN/getent" "$FAKEBIN/sleep"

# state -- a state directory holding the server's bootstrap certificate and
# its first-boot admin credential; STUB_SWAP adds the persisted CA bundle that
# verifies the CA-issued certificate.
state() {
	rm -rf "$WORK/state" "$WORK/dest"
	mkdir -p "$WORK/state/storage/unified-tls"
	printf 'stub-bootstrap-cert' >"$WORK/state/storage/unified-tls/cert.pem"
	if [ -n "${STUB_SWAP:-}" ]; then
		printf 'stub-ca-issued-cert' >"$WORK/state/storage/unified-tls/ca-bundle.pem"
	fi
	printf 'stub-admin-cert' >"$WORK/state/storage/admin-cert.pem"
	printf 'stub-admin-key' >"$WORK/state/storage/admin-key.pem"
}

# run [HOST] -- run the script against the state directory as it is, with the
# compose server resolving as HOST (xkms-server by default; empty: not
# running). STUB_SWAP, STUB_IMPOSTOR and STUB_BUNDLE pass through from the
# caller. Sets out, rc, calls.
run() {
	: >"$WORK/calls"
	out=$(PATH="$FAKEBIN:$PATH" STUB_LOG="$WORK/calls" STUB_HOST="${1-xkms-server}" \
		STUB_BUNDLE="${STUB_BUNDLE-$BUNDLE}" XKMS_SERVER_STATE_DIR="$WORK/state" \
		XKMS_TEST_DATA_DIR="$WORK/state" XKMS_TEST_REST_PORT=18443 \
		XKMS_GRPC_TLS_CA="$WORK/dest/ca.crt" bash "$SCRIPT" 2>&1)
	rc=$?
	calls=$(cat "$WORK/calls")
}

# dest -- the CA the last run published, or "none".
dest() { cat "$WORK/dest/ca.crt" 2>/dev/null || echo none; }

section "the CA bundle is fetched from a server its bootstrap certificate verifies"
state
run
eq "exit 0" 0 "$rc"
eq "it publishes the bundle the server served" "$BUNDLE" "$(dest)"
eq "the only request is the bootstrap route" "v1/ca/bootstrap" "$calls"
lacks "no request skips verification" "INSECURE" "$calls"
eq "it publishes the admin certificate" "stub-admin-cert" "$(cat "$WORK/dest/admin-cert.pem" 2>/dev/null)"
eq "it publishes the admin key" "stub-admin-key" "$(cat "$WORK/dest/admin-key.pem" 2>/dev/null)"

section "a server on its CA-issued certificate is verified by the persisted CA bundle"
STUB_SWAP=1 state
STUB_SWAP=1 run
eq "exit 0" 0 "$rc"
eq "it publishes the bundle the server served" "$BUNDLE" "$(dest)"
lacks "no request skips verification" "INSECURE" "$calls"

section "a server the persisted anchors do not verify is not trusted"
state
STUB_IMPOSTOR=1 run
eq "exit 1" 1 "$rc"
eq "nothing is published" none "$(dest)"
has "the error names the anchors" "served no CA bundle from a server the persisted anchors verify" "$out"
lacks "no request skips verification" "INSECURE" "$calls"

section "an unreadable bootstrap certificate stops before any request"
state
rm -f "$WORK/state/storage/unified-tls/cert.pem"
run
eq "exit 1" 1 "$rc"
eq "nothing is published" none "$(dest)"
has "the error names the certificate" "cannot read the server's bootstrap certificate" "$out"
eq "no request" "" "$calls"

section "a verified server that serves no certificate fails"
state
STUB_BUNDLE='not a certificate' run
eq "exit 1" 1 "$rc"
eq "nothing is published" none "$(dest)"
has "the error names the route" "v1/ca/bootstrap served no CA bundle" "$out"

section "without the compose server the fallback server's CA and admin credential are published"
state
run ""
eq "exit 0" 0 "$rc"
has "it says the compose server is not running" "xkms-server is not running" "$out"
has "it fetches from the fallback's loopback REST port" "https://localhost:18443/v1/ca/bootstrap" "$out"
eq "the only request is the bootstrap route" "v1/ca/bootstrap" "$calls"
lacks "no request skips verification" "INSECURE" "$calls"
eq "it publishes the bundle the fallback served" "$BUNDLE" "$(dest)"
eq "it publishes the fallback's admin certificate" "stub-admin-cert" "$(cat "$WORK/dest/admin-cert.pem" 2>/dev/null)"
eq "it publishes the fallback's admin key" "stub-admin-key" "$(cat "$WORK/dest/admin-key.pem" 2>/dev/null)"

printf '\npassed %d, failed %d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
