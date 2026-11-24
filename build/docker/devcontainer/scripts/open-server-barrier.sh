#!/bin/bash
# open-server-barrier.sh: unseal the compose xkms-server through its sealed window.

set -euo pipefail

STATE_DIR="${XKMS_SERVER_STATE_DIR:-/xkms-data}"
URL="${XKMS_SERVER_WINDOW_URL:-https://xkms-server:8443}"
CERT="${STATE_DIR}/storage/unified-tls/cert.pem"
CA_BUNDLE="${STATE_DIR}/storage/unified-tls/ca-bundle.pem"
ATTEMPTS=30

if [ -z "${XKMS_SERVER_BARRIER_SECRET:-}" ]; then
	echo "open-server-barrier: XKMS_SERVER_BARRIER_SECRET is not set" >&2
	exit 1
fi

# The unseal route takes {"secret": <bytes>}, which JSON carries as base64.
BODY="{\"secret\":\"$(printf '%s' "$XKMS_SERVER_BARRIER_SECRET" | base64 -w0)\"}"

reply=$(mktemp)
anchors=$(mktemp)
trap 'rm -f "$reply" "$anchors"' EXIT

# trust -- write the anchors the server is verified against to $anchors: the
# bootstrap certificate, and the CA bundle once the server has persisted it.
# Read afresh for every request, because the bundle appears after the unseal.
# Fails while the bootstrap certificate is not readable.
trust() {
	[ -r "$CERT" ] || return 1
	cat "$CERT" >"$anchors"
	if [ -r "$CA_BUNDLE" ]; then
		cat "$CA_BUNDLE" >>"$anchors"
	fi
}

# get PATH -- GET ${URL}PATH and print the body, verifying the server against
# the persisted anchors.
get() {
	trust && curl -sf --cacert "$anchors" "${URL}$1"
}

# A server past its sealed window answers /health; the window refuses it with
# 503. Otherwise the window's /v1/barrier/status says whether it waits for the
# unseal. The full server answers that route only to an authenticated caller
# (HTTP 401), so it can never tell this script that the barrier is open: every
# run_with_server suite after the first finds the server so, and the status
# probe alone never answered them (DS-3769).
status=""
for _ in $(seq 1 "$ATTEMPTS"); do
	if get /health >/dev/null; then
		echo "open-server-barrier: barrier is already unsealed"
		exit 0
	fi
	if status=$(get /v1/barrier/status); then
		break
	fi
	status=""
	sleep 2
done
if [ -z "$status" ]; then
	if [ ! -r "$CERT" ]; then
		echo "open-server-barrier: cannot read the server's bootstrap certificate ${CERT}; the passphrase goes only to a server it verifies" >&2
	else
		echo "open-server-barrier: ${URL}/v1/barrier/status did not answer" >&2
	fi
	exit 1
fi

if printf '%s' "$status" | grep -Eq '"sealed" *: *true'; then
	trust
	code=$(curl -s --cacert "$anchors" -o "$reply" -w '%{http_code}' -X POST \
		-H 'Content-Type: application/json' -d "$BODY" "${URL}/v1/barrier/unseal")
	if [ "$code" != "204" ]; then
		echo "open-server-barrier: POST /v1/barrier/unseal returned HTTP ${code}: $(cat "$reply")" >&2
		if ! printf '%s' "$status" | grep -Eq '"initialized_at" *: *"[^"]+"'; then
			echo "open-server-barrier: the barrier was never initialized; xkmsd init did not complete on this volume (see the xkms-server log)" >&2
		fi
		exit 1
	fi
fi

# The 204 comes from the sealed window, which qrdb then stops before the full
# server starts and binds the Unix socket afresh (go-qrdb pkg/server
# ServeSealedWindow). A probe of the socket in between can reach the window's
# socket on its way out. The window refuses /health and the full server answers
# it, so a 2xx from /health means the server the suites dial is up. A window
# that reported the barrier open is waited on the same way. get verifies the
# server whether or not it has swapped its certificate yet.
for _ in $(seq 1 "$ATTEMPTS"); do
	if get /health >/dev/null; then
		echo "open-server-barrier: barrier unsealed"
		exit 0
	fi
	sleep 2
done
echo "open-server-barrier: barrier unsealed, but ${URL}/health never answered; the server did not finish starting (see the xkms-server log)" >&2
exit 1
