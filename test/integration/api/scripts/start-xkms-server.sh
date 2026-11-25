#!/bin/sh
# start-xkms-server.sh: init a fresh data volume, start xkmsd and unseal its barrier with the SO PIN.
#
# Environment:
#   XKMS_CONFIG      server configuration (required)
#   XKMS_SO_PIN      throwaway test SO PIN, the barrier passphrase (required)
#   XKMS_STATE_DIR   data volume; init writes the admin credential to <dir>/storage
#   CERT_DIR         TLS certificate directory for generate-test-certs.sh
set -eu

SCRIPTS="$(cd "$(dirname "$0")" && pwd)"
XKMSD="${XKMSD:-/app/xkmsd}"
STATE_DIR="${XKMS_STATE_DIR:-/data}"
STORAGE="${STATE_DIR}/storage"
CA="${CERT_DIR:-/etc/xkms/certs}/ca.crt"
URL="${XKMS_SERVER_URL:-https://localhost:8443}"
: "${XKMS_CONFIG:?XKMS_CONFIG is not set}"
: "${XKMS_SO_PIN:?XKMS_SO_PIN is not set}"

echo 2500000 >/proc/sys/net/core/rmem_max 2>/dev/null || echo "start-xkms-server: could not set rmem_max"
echo 2500000 >/proc/sys/net/core/wmem_max 2>/dev/null || echo "start-xkms-server: could not set wmem_max"

mkdir -p "${CERT_DIR:-/etc/xkms/certs}" /var/run/xkms "${STORAGE}/tenant-volumes"
"${SCRIPTS}/generate-test-certs.sh"

# The pkcs11 backend loads libsofthsm2.so in this container, so its token lives here.
mkdir -p /var/lib/softhsm/tokens
softhsm2-util --show-slots | grep -q "test-token" ||
	softhsm2-util --init-token --free --label test-token --so-pin 123456 --pin 123456 >/dev/null

# init refuses a second run once the admin exists, so its admin credential marks the volume initialized.
if [ -f "${STORAGE}/admin-cert.pem" ] && [ -f "${STORAGE}/admin-key.pem" ]; then
	echo "start-xkms-server: admin credential present; volume already initialized"
else
	"$XKMSD" init --config "$XKMS_CONFIG" --hostname xkms-server --admin-factor mtls
fi

env -u XKMS_SO_PIN "$XKMSD" -config "$XKMS_CONFIG" &
pid=$!
trap 'kill -TERM "$pid" 2>/dev/null' INT TERM

# fail MESSAGE -- stop the daemon and exit non-zero.
fail() {
	echo "start-xkms-server: $1" >&2
	kill -TERM "$pid" 2>/dev/null || true
	wait "$pid" || true
	exit 1
}

# The server is verified against the configured TLS CA, so the passphrase goes only to it.
get() {
	curl -sf --cacert "$CA" "${URL}$1"
}

status=""
for _ in $(seq 1 60); do
	kill -0 "$pid" 2>/dev/null || fail "xkmsd exited before its sealed window answered"
	if get /health >/dev/null; then
		status=open
		break
	fi
	if status=$(get /v1/barrier/status); then
		break
	fi
	status=""
	sleep 2
done
[ -n "$status" ] || fail "${URL}/v1/barrier/status did not answer"

if [ "$status" != open ]; then
	code=$(printf '{"secret":"%s"}' "$(printf '%s' "$XKMS_SO_PIN" | base64 -w0)" |
		curl -s --cacert "$CA" -o /tmp/unseal-reply -w '%{http_code}' -X POST \
			-H 'Content-Type: application/json' --data-binary @- "${URL}/v1/barrier/unseal")
	[ "$code" = 204 ] || fail "POST /v1/barrier/unseal returned HTTP ${code}: $(cat /tmp/unseal-reply)"
fi
unset XKMS_SO_PIN

for _ in $(seq 1 60); do
	kill -0 "$pid" 2>/dev/null || fail "xkmsd exited after the unseal"
	if get /health >/dev/null; then
		echo "start-xkms-server: barrier unsealed, server healthy"
		wait "$pid"
		exit $?
	fi
	sleep 2
done
fail "barrier unsealed, but ${URL}/health never answered"
