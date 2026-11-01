#!/bin/sh
# Opens the API suite's xkms-server barrier through its sealed window, then
# waits for the full server to answer /health.
#
# Same ceremony as build/docker/devcontainer/scripts/open-server-barrier.sh,
# but this stack serves its configured certificate (tls.cert_file, signed by
# the test CA), so the client trusts that CA rather than the bootstrap
# unified-tls certificate.
set -eu

url="${XKMS_SERVER_WINDOW_URL:-https://xkms-server:8443}"
ca="${KEYSTORE_TLS_CA:-/etc/xkms/certs/ca.crt}"
secret="${XKMS_SERVER_BARRIER_SECRET:?XKMS_SERVER_BARRIER_SECRET is required}"

status=""
for _ in $(seq 1 60); do
	if status=$(curl -fsS --cacert "$ca" "$url/v1/barrier/status" 2>/dev/null); then
		break
	fi
	sleep 1
done
if [ -z "$status" ]; then
	echo "unseal-server: sealed window at $url never answered /v1/barrier/status" >&2
	exit 1
fi

case "$status" in
*'"initialized":false'*)
	echo "unseal-server: barrier is not initialized (xkmsd init did not run)" >&2
	exit 1
	;;
*'"sealed":true'*)
	body=$(printf '{"secret":"%s"}' "$(printf '%s' "$secret" | base64 -w0)")
	curl -fsS --cacert "$ca" -X POST -H 'Content-Type: application/json' \
		-d "$body" "$url/v1/barrier/unseal"
	echo "unseal-server: barrier unsealed"
	;;
esac

for _ in $(seq 1 120); do
	if curl -fsS -o /dev/null --cacert "$ca" "$url/health" 2>/dev/null; then
		echo "unseal-server: server is up"
		exit 0
	fi
	sleep 1
done
echo "unseal-server: $url/health did not answer 2xx after unseal" >&2
exit 1
