#!/bin/sh
# Enrol the suite's administrator client credential with the running xkmsd.
#
# generate-test-certs.sh writes admin-client.crt/.key, signed by the test CA
# that tls.ca_file names. Go TLS clients (the SDK transport, xkmsctl) only
# present a certificate whose issuer is in the server's acceptable-CA list,
# so this test-CA credential is the one the suite can authenticate with; the
# daemon's own first-boot administrator credential (admin-cert.pem, issued
# by its generated CA) is never offered by them. A client certificate only
# authenticates once it is bound to a user, and there is no config field or
# init flag that binds an external one, so this script binds it to the
# first-boot administrator after the daemon is up: it presents the first-boot
# credential with curl (OpenSSL sends it whatever CA list the server asks
# for) and POSTs /api/v1/users/<admin>/cert-bindings.
#
# On success it writes ${CERT_DIR}/admin-client.bound, which the
# xkms-server healthcheck requires, so no test starts before the binding.

set -eu

CERT_DIR="${CERT_DIR:-/etc/xkms/certs}"
DATA_DIR="${TEST_DATA_DIR:-/data}"
SERVER_URL="${ENROL_SERVER_URL:-https://localhost:8443}"
ADMIN_USER="${ENROL_ADMIN_USER:-admin}"
WAIT_SECONDS="${ENROL_WAIT_SECONDS:-120}"
MARKER="${CERT_DIR}/admin-client.bound"

rm -f "${MARKER}"

# The daemon writes the first-boot administrator credential beside its
# datastore; wait for it and for the REST listener.
i=0
first_boot_dir=""
while [ "${i}" -lt "${WAIT_SECONDS}" ]; do
    for d in "${DATA_DIR}/datastore" "${DATA_DIR}/storage" "${DATA_DIR}"; do
        if [ -f "${d}/admin-cert.pem" ] && [ -f "${d}/admin-key.pem" ]; then
            first_boot_dir="${d}"
        fi
    done
    if [ -n "${first_boot_dir}" ] &&
        curl -sf -o /dev/null --cacert "${CERT_DIR}/ca.crt" "${SERVER_URL}/health"; then
        break
    fi
    i=$((i + 1))
    sleep 1
done
if [ -z "${first_boot_dir}" ]; then
    echo "enrol-admin-client: no first-boot admin credential under ${DATA_DIR} after ${WAIT_SECONDS}s" >&2
    exit 1
fi

# The binding identifier is qrdb's SPKI SHA-256 thumbprint, base64url
# without padding (qrdbsdk.ComputeSPKIThumbprint).
thumbprint=$(openssl x509 -in "${CERT_DIR}/admin-client.crt" -pubkey -noout \
    | openssl pkey -pubin -outform DER \
    | openssl dgst -sha256 -binary \
    | openssl base64 -A \
    | tr '+/' '-_' \
    | tr -d '=')
not_after=$(date -d "$(openssl x509 -in "${CERT_DIR}/admin-client.crt" -noout -enddate | cut -d= -f2)" +%s)

status=$(curl -s -o /dev/null -w '%{http_code}' \
    --cacert "${CERT_DIR}/ca.crt" \
    --cert "${first_boot_dir}/admin-cert.pem" \
    --key "${first_boot_dir}/admin-key.pem" \
    -H 'Content-Type: application/json' \
    -d "{\"thumbprint\":\"${thumbprint}\",\"not_after_unix\":${not_after}}" \
    "${SERVER_URL}/api/v1/users/${ADMIN_USER}/cert-bindings")
if [ "${status}" != "200" ]; then
    echo "enrol-admin-client: binding admin-client.crt to ${ADMIN_USER} answered HTTP ${status}" >&2
    exit 1
fi

touch "${MARKER}"
echo "Administrator client credential bound to ${ADMIN_USER}"
