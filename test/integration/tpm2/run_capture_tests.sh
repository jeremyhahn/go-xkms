#!/bin/bash
# TPM2 Session Encryption Verification Test Runner
# This script runs packet capture tests to verify TPM session encryption

set -e

echo "=============================================="
echo "TPM2 Session Encryption Verification Tests"
echo "=============================================="
echo ""

# Wait for TPM simulator to be ready
echo "Waiting for TPM simulator to be ready..."
while ! nc -z ${TPM2_SIMULATOR_HOST:-localhost} ${TPM2_SIMULATOR_PORT:-2421}; do
    sleep 1
done
echo "✓ TPM simulator is ready"
echo ""

# Run encryption verification tests
echo "Running TPM2 packet capture and encryption verification tests..."
echo ""

# Run just the capture tests
go test -v \
    -tags='integration,tpm2' \
    -timeout 30m \
    -run 'TestTPMSession' \
    ./test/integration/tpm2/

EXIT_CODE=$?

echo ""
echo "=============================================="
if [ $EXIT_CODE -eq 0 ]; then
    echo "✓ All encryption verification tests passed!"
else
    echo "✗ Encryption verification tests failed with exit code $EXIT_CODE"
fi
echo "=============================================="

exit $EXIT_CODE
