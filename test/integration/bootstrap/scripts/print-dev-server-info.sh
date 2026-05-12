#!/bin/sh
# Copyright (c) 2026 Jeremy Hahn
# Copyright (c) 2026 Automate The Things, LLC
#
# Dumps connection info for the running xkms-server (used by
# `make dev-server-info`) so a developer can wire xkey into a real
# backend. Pulls cert material directly out of the xkms-certs volume.
set -eu

CONTAINER="${CONTAINER:-bootstrap-xkms-server}"

if ! docker inspect "${CONTAINER}" >/dev/null 2>&1; then
    echo "ERROR: container ${CONTAINER} not running."
    echo "Run 'make dev-server-up' first."
    exit 1
fi

REST_PORT="$(docker port "${CONTAINER}" 8443/tcp | head -1 | awk -F: '{print $NF}' || echo 8443)"
NOISE_PORT="$(docker port "${CONTAINER}" 8445/tcp | head -1 | awk -F: '{print $NF}' || echo 8445)"

echo "=== xkms-server (dev) ==="
echo "  REST/gRPC  : https://localhost:${REST_PORT}"
echo "  Noise      : localhost:${NOISE_PORT}"
echo "  Container  : ${CONTAINER}"
echo ""
echo "=== Credentials ==="
CA_OUT="/tmp/xkms-dev-ca.crt"
docker exec "${CONTAINER}" cat /etc/xkms/certs/ca.crt > "${CA_OUT}"
echo "  CA cert    : ${CA_OUT}"
SPKI_PIN="$(docker exec "${CONTAINER}" cat /etc/xkms/certs/spki.pin)"
NOISE_KEY="$(docker exec "${CONTAINER}" cat /etc/xkms/certs/noise.pub.hex)"
echo "  SPKI pin   : ${SPKI_PIN}"
echo "  Noise key  : ${NOISE_KEY}"
echo ""
echo "=== Health check ==="
if curl --silent --cacert "${CA_OUT}" --max-time 3 "https://localhost:${REST_PORT}/health" | head -c 120; then
    echo ""
    echo "  Server is healthy."
else
    echo ""
    echo "  WARNING: server did not respond to health check."
fi
echo ""
echo "=== xkey connection hint ==="
echo "  In xkey GUI: Settings → Server"
echo "    Protocol       : grpc (or rest)"
echo "    Address        : localhost:${REST_PORT}"
echo "    TLS Enabled    : on"
echo "    TLS CA File    : ${CA_OUT}"
echo ""
echo "  For truststrap import (Trust Store → Import → Direct):"
echo "    Server URL     : https://localhost:${REST_PORT}"
echo "    Bundle Path    : /v1/ca/bootstrap"
echo ""
echo "  For truststrap import (Trust Store → Import → SPKI):"
echo "    Server URL     : https://localhost:${REST_PORT}"
echo "    SPKI pin       : ${SPKI_PIN}"
echo ""
echo "  For truststrap import (Trust Store → Import → Noise):"
echo "    Server Address : localhost:${NOISE_PORT}"
echo "    Static key     : ${NOISE_KEY}"
