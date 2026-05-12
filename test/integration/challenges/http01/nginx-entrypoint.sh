#!/bin/sh
# Entrypoint script for nginx in HTTP-01 E2E tests
# Generates a placeholder certificate if none exists

CERT_PATH=/etc/nginx/certs/server.crt
KEY_PATH=/etc/nginx/certs/server.key

# Check if certificate already exists
if [ ! -f "$CERT_PATH" ] || [ ! -f "$KEY_PATH" ]; then
    echo "Generating placeholder self-signed certificate..."
    mkdir -p /etc/nginx/certs

    # Generate self-signed certificate (will be replaced by test)
    openssl req -x509 -nodes -days 1 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
        -keyout "$KEY_PATH" \
        -out "$CERT_PATH" \
        -subj "/CN=placeholder.test.example.com"

    echo "Placeholder certificate generated"
fi

# Start nginx
exec nginx -g 'daemon off;'
