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
# The throwaway SoftHSM token PIN, which config.test.yaml names as credential://pkcs11-user-pin.
PKCS11_PIN=123456
: "${XKMS_CONFIG:?XKMS_CONFIG is not set}"
: "${XKMS_SO_PIN:?XKMS_SO_PIN is not set}"
SO_PIN="$XKMS_SO_PIN"
unset XKMS_SO_PIN

echo 2500000 >/proc/sys/net/core/rmem_max 2>/dev/null || echo "start-xkms-server: could not set rmem_max"
echo 2500000 >/proc/sys/net/core/wmem_max 2>/dev/null || echo "start-xkms-server: could not set wmem_max"

mkdir -p "${CERT_DIR:-/etc/xkms/certs}" /var/run/xkms "${STORAGE}/tenant-volumes"
"${SCRIPTS}/generate-test-certs.sh"

# The pkcs11 backend loads libsofthsm2.so in this container, so its token lives here.
mkdir -p /var/lib/softhsm/tokens
softhsm2-util --show-slots | grep -q "test-token" ||
	softhsm2-util --init-token --free --label test-token --so-pin "$PKCS11_PIN" --pin "$PKCS11_PIN" >/dev/null

pid=""
trap '[ -z "$pid" ] || kill -TERM "$pid" 2>/dev/null' INT TERM

# fail MESSAGE -- stop the daemon and exit non-zero.
fail() {
	echo "start-xkms-server: $1" >&2
	stop
	exit 1
}

# stop -- stop the daemon started by boot, if any.
stop() {
	if [ -n "$pid" ]; then
		kill -TERM "$pid" 2>/dev/null || true
		wait "$pid" || true
		pid=""
	fi
}

# get PATH -- GET ${URL}PATH, verifying the server against the stack's test CA.
get() {
	curl -sf --cacert "$CA" "${URL}$1"
}

# boot [VAR=VALUE...] -- start xkmsd with the given extra environment, unseal it and wait for /health.
boot() {
	env XKMS_CONFIG="${BOOT_CONFIG:-$XKMS_CONFIG}" "$@" "$XKMSD" -config "${BOOT_CONFIG:-$XKMS_CONFIG}" &
	pid=$!
	status=""
	for _ in $(seq 1 60); do
		kill -0 "$pid" 2>/dev/null || fail "xkmsd exited before its sealed window answered"
		if get /health >/dev/null; then
			return 0
		fi
		if status=$(get /v1/barrier/status); then
			break
		fi
		status=""
		sleep 2
	done
	[ -n "$status" ] || fail "${URL}/v1/barrier/status did not answer"
	code=$(printf '{"secret":"%s"}' "$(printf '%s' "$SO_PIN" | base64 -w0)" |
		curl -s --cacert "$CA" -o /tmp/unseal-reply -w '%{http_code}' -X POST \
			-H 'Content-Type: application/json' --data-binary @- "${URL}/v1/barrier/unseal")
	[ "$code" = 204 ] || fail "POST /v1/barrier/unseal returned HTTP ${code}: $(cat /tmp/unseal-reply)"
	for _ in $(seq 1 60); do
		kill -0 "$pid" 2>/dev/null || fail "xkmsd exited after the unseal"
		if get /health >/dev/null; then
			return 0
		fi
		sleep 2
	done
	fail "barrier unsealed, but ${URL}/health never answered"
}

# init refuses a second run once the admin exists, so its admin credential marks the volume initialized.
if [ -f "${STORAGE}/admin-cert.pem" ] && [ -f "${STORAGE}/admin-key.pem" ]; then
	echo "start-xkms-server: admin credential present; volume already initialized"
else
	XKMS_SO_PIN="$SO_PIN" "$XKMSD" init --config "$XKMS_CONFIG" --hostname xkms-server --admin-factor mtls
	# Server.New resolves the PIN reference before the submit route exists, so a first boot without it stores it.
	seed=/tmp/xkms-seed-config.yaml
	grep -v 'credential://pkcs11-user-pin' "$XKMS_CONFIG" >"$seed"
	BOOT_CONFIG="$seed"
	boot XKMS_BACKENDS_PKCS11_ENABLED=false
	# The REST surface and its auth finish composing after /health answers, so 401 and 503 are retried.
	for _ in $(seq 1 60); do
		code=$(printf '{"name":"pkcs11-user-pin","value":"%s"}' "$(printf '%s' "$PKCS11_PIN" | base64 -w0)" |
			curl -s --cacert "$CA" --cert "${STORAGE}/admin-cert.pem" --key "${STORAGE}/admin-key.pem" \
				-o /tmp/credential-reply -w '%{http_code}' -X POST -H 'Content-Type: application/json' \
				--data-binary @- "${URL}/api/v1/credentials/submit")
		case "$code" in 401 | 503) ;; *) break ;; esac
		sleep 2
	done
	case "$code" in
	2??) ;;
	*) fail "POST /api/v1/credentials/submit returned HTTP ${code}: $(cat /tmp/credential-reply)" ;;
	esac
	stop
	BOOT_CONFIG=""
	rm -f "$seed"
fi

boot
echo "start-xkms-server: barrier unsealed, server healthy"
wait "$pid"
