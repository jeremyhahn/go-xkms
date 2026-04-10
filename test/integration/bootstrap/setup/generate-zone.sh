#!/bin/sh
# Generate a DNS zone file with TLSA records computed from the server's CA certificate.
# This runs as a one-shot container after the xkms server is healthy.
set -e

CERT_FILE="/etc/xkms/certs/ca.crt"
ZONE_FILE="/etc/coredns/zones/bootstrap.test.zone"
HOSTNAME="bootstrap.test"
PORT="8443"

# Wait for certificate to be available
for i in $(seq 1 30); do
    if [ -f "$CERT_FILE" ]; then
        break
    fi
    echo "Waiting for certificate file ($i/30)..."
    sleep 1
done

if [ ! -f "$CERT_FILE" ]; then
    echo "ERROR: Certificate file not found at $CERT_FILE"
    exit 1
fi

# Compute TLSA data using openssl
# Usage=2 (DANE-TA), Selector=0 (Full cert), MatchingType=1 (SHA-256)
TLSA_2_0_1=$(openssl x509 -in "$CERT_FILE" -outform DER 2>/dev/null | openssl dgst -sha256 -hex 2>/dev/null | awk '{print $NF}')

# Usage=2 (DANE-TA), Selector=1 (SPKI), MatchingType=1 (SHA-256)
TLSA_2_1_1=$(openssl x509 -in "$CERT_FILE" -pubkey -noout 2>/dev/null | openssl pkey -pubin -outform DER 2>/dev/null | openssl dgst -sha256 -hex 2>/dev/null | awk '{print $NF}')

# Usage=2 (DANE-TA), Selector=0 (Full cert), MatchingType=2 (SHA-512)
TLSA_2_0_2=$(openssl x509 -in "$CERT_FILE" -outform DER 2>/dev/null | openssl dgst -sha512 -hex 2>/dev/null | awk '{print $NF}')

# Usage=2 (DANE-TA), Selector=1 (SPKI), MatchingType=2 (SHA-512)
TLSA_2_1_2=$(openssl x509 -in "$CERT_FILE" -pubkey -noout 2>/dev/null | openssl pkey -pubin -outform DER 2>/dev/null | openssl dgst -sha512 -hex 2>/dev/null | awk '{print $NF}')

echo "Computed TLSA records:"
echo "  2 0 1: $TLSA_2_0_1"
echo "  2 1 1: $TLSA_2_1_1"
echo "  2 0 2: $TLSA_2_0_2"
echo "  2 1 2: $TLSA_2_1_2"

# Write zone file
cat > "$ZONE_FILE" << EOF
\$ORIGIN ${HOSTNAME}.
\$TTL 3600
@       IN SOA  ns.${HOSTNAME}. admin.${HOSTNAME}. (
            2024010101  ; Serial
            3600        ; Refresh
            900         ; Retry
            604800      ; Expire
            86400       ; Minimum TTL
        )
@       IN NS   ns.${HOSTNAME}.
@       IN A    127.0.0.1
ns      IN A    127.0.0.1

; TLSA records for _${PORT}._tcp.${HOSTNAME}.
; Generated from real server CA certificate
_${PORT}._tcp  IN TLSA 2 0 1 ${TLSA_2_0_1}
_${PORT}._tcp  IN TLSA 2 1 1 ${TLSA_2_1_1}
_${PORT}._tcp  IN TLSA 2 0 2 ${TLSA_2_0_2}
_${PORT}._tcp  IN TLSA 2 1 2 ${TLSA_2_1_2}
EOF

echo "Zone file written to $ZONE_FILE"
cat "$ZONE_FILE"
