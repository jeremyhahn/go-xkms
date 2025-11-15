# TPM2 Integration Tests

This directory contains comprehensive integration tests for the TPM 2.0 backend, including session encryption verification through packet capture.

## Test Files

### Core Integration Tests

- **`tpm2_integration_test.go`** - Main TPM2 integration tests
  - Key generation (RSA-2048/3072/4096, ECDSA P-256/384/521)
  - Key retrieval and deletion
  - Signing and verification
  - Encryption and decryption
  - Certificate operations
  - Backend capabilities

- **`tpm2_cert_integration_test.go`** - Certificate storage tests
  - Hardware-backed certificate storage (TPM NV RAM)
  - Hybrid storage with filesystem fallback
  - Certificate capacity management

### Session Encryption Tests

- **`capture_test.go`** - Session encryption verification
  - Packet capture of TPM traffic
  - Encryption flag detection
  - Plaintext data leak detection
  - Encrypted vs unencrypted comparison

- **`capture.go`** - Packet capture infrastructure
  - Custom transport wrapper for traffic interception
  - TPM packet parsing (headers, session areas)
  - Encryption analysis utilities

- **`capture_helper.go`** - Test setup utilities
  - TPM test environment provisioning
  - Capture transport injection

## Test Execution

### Run All TPM2 Tests

```bash
make integration-test-tpm2
```

### Run Encryption Verification Tests Only

```bash
make test-tpm2-encryption
```

### Run Locally (with TPM simulator)

```bash
# Start TPM simulator separately
docker-compose up -d tpm-simulator

# Set environment
export TPM2_SIMULATOR_HOST=localhost
export TPM2_SIMULATOR_PORT=2321

# Run tests
make test-tpm2-encryption-local
```

### Manual Test Execution

```bash
# Start simulator
cd test/integration/tpm2
docker-compose up -d tpm-simulator

# Wait for simulator
sleep 3

# Run all tests
docker-compose run --rm test

# Run encryption tests only
docker-compose run --rm test sh /app/test/integration/tpm2/run_capture_tests.sh

# Cleanup
docker-compose down -v
```

## Test Environment

### Docker Compose Services

- **`tpm-simulator`** - SWTPM TCP-based TPM 2.0 simulator
  - Port: 2321 (TPM commands)
  - Port: 2322 (Control channel)
  - State: Ephemeral (fresh state per test run)

- **`test`** - Test runner container
  - Base: golang:1.23
  - Includes: tcpdump, tpm2-tools for debugging
  - Working directory: `/app`

### Environment Variables

- `TPM2_SIMULATOR_HOST` - TPM simulator hostname (default: uses embedded simulator)
- `TPM2_SIMULATOR_PORT` - TPM simulator port (default: 2321)
- `TPM_DEVICE` - Hardware TPM device path (default: /dev/tpmrm0)

## Test Configuration

### TPM Config

Tests use the following TPM configuration:

```go
&tpm2.Config{
    CN:             "test-keystore-srk",
    SRKHandle:      0x81000001,
    EncryptSession: true,  // Enable for encryption tests
    UseSimulator:   true,
    SimulatorHost:  "tpm-simulator",
    SimulatorPort:  2321,
}
```

### Key Attributes

Common test key attributes:

```go
&backend.KeyAttributes{
    CN:           "test-key-name",
    KeyType:      backend.KEY_TYPE_TLS,
    StoreType:    backend.STORE_TPM2,
    KeyAlgorithm: backend.ALG_RSA,
    RSAAttributes: &backend.RSAAttributes{
        KeySize: 2048,
    },
}
```

## Encryption Test Details

### Test Coverage

1. **`TestTPMSessionEncryption`**
   - Verifies encryption flags in session commands
   - Validates no plaintext sensitive data leaks
   - Tests key generation and signing with encryption

2. **`TestTPMSessionNoEncryption`**
   - Baseline test without encryption
   - Provides comparison data

3. **`TestTPMSessionEncryptionComparison`**
   - Side-by-side encrypted vs unencrypted
   - Quantifies encryption effectiveness

4. **`TestTPMMultipleOperationsEncryption`**
   - Tests encryption across operations:
     - Key generation
     - Key retrieval
     - Signing
   - Ensures consistent encryption

5. **`TestTPMDecryptionEncryption`**
   - Verifies decrypted plaintext protection
   - Ensures plaintext never in transit

### Analysis Metrics

Each test reports:
- **Total Packets**: Command and response count
- **Session Commands**: Commands with session area
- **Encrypted Sessions**: Sessions with encryption flags
- **Plaintext Detections**: Sensitive patterns found (should be 0)
- **Encryption Rate**: Percentage of encrypted sessions

### Expected Output

```
TPM Traffic Analysis:
  Total Packets: 15
  Commands: 8 (Session: 6, Encrypted: 6)
  Responses: 7 (Session: 6)
  Plaintext Detections: 0
  Encryption Rate: 100.0%
```

## Debugging

### View TPM Simulator Logs

```bash
docker-compose logs -f tpm-simulator
```

### Enable TPM Debug Output

Set in TPM config:

```go
&tpm2.Config{
    Debug: true,
}
```

### Capture Packets to File

Modify capture test to save packets:

```go
packets := capture.GetPackets()
f, _ := os.Create("tpm-traffic.bin")
defer f.Close()
for _, pkt := range packets {
    f.Write(pkt.Data)
}
```

### Use tcpdump (for network simulator)

```bash
# In test container
tcpdump -i any -w /tmp/tpm2.pcap port 2321
```

## Troubleshooting

### TPM Resource Exhaustion

**Symptom**: `TPM_RC_MEMORY` errors

**Solution**: Tests properly flush transient handles. If errors persist:
- Restart TPM simulator
- Check for leaked handles in test code

### Connection Refused

**Symptom**: Cannot connect to TPM simulator

**Solutions**:
1. Check simulator is running: `docker-compose ps`
2. Verify port forwarding: `docker-compose port tpm-simulator 2321`
3. Wait longer for simulator startup (increase sleep time)

### Tests Hang

**Symptom**: Test execution freezes

**Possible Causes**:
- TPM simulator crashed
- Deadlock in transport layer
- Timeout too long

**Solution**:
- Check simulator logs
- Kill and restart: `docker-compose down -v && docker-compose up -d`

### False Test Failures

**Symptom**: Intermittent test failures

**Causes**:
- Race conditions in packet capture
- TPM simulator timing issues
- Resource cleanup incomplete

**Solutions**:
- Use `t.Cleanup()` for resource cleanup
- Add synchronization in capture code
- Increase timeouts if needed

## CI/CD Integration

### GitHub Actions Example

```yaml
name: TPM2 Tests

on: [push, pull_request]

jobs:
  tpm2-encryption:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Run TPM2 Encryption Tests
        run: make test-tpm2-encryption

      - name: Upload Test Results
        if: always()
        uses: actions/upload-artifact@v3
        with:
          name: tpm2-test-results
          path: build/coverage/
```

## Test Requirements

### Build Tags

Tests require both tags:
- `integration` - Integration test marker
- `tpm2` - TPM2 backend enabled

### Dependencies

Runtime dependencies (in Docker):
- golang:1.23 or later
- TPM 2.0 simulator (SWTPM)
- netcat (for connectivity checks)

Go dependencies (see go.mod):
- `github.com/google/go-tpm`
- `github.com/google/go-tpm-tools`
- `github.com/stretchr/testify`

## Contributing

When adding new TPM2 tests:

1. **Use build tags**: `//go:build integration && tpm2`
2. **Follow naming**: `TestTPM*` for main tests
3. **Use helpers**: `setupTPM2WithCapture()` for encryption tests
4. **Clean up**: Always use `defer cleanup()` or `t.Cleanup()`
5. **Document**: Add test purpose in comments
6. **Assertions**: Use testify assertions for clarity

### Test Template

```go
//go:build integration && tpm2

package integration

import (
    "testing"
    "github.com/stretchr/testify/require"
)

func TestTPMNewFeature(t *testing.T) {
    // Setup
    ks, capture, cleanup := setupTPM2WithCapture(t, true)
    defer cleanup()

    // Test logic
    // ...

    // Assertions
    require.NoError(t, err)
}
```

## Documentation

Comprehensive documentation available:
- [TPM2 Session Encryption Guide](../../../docs/tpm2-session-encryption.md)
- [Certificate Management Guide](../../../docs/certificates.md)

## License

See [LICENSE](../../../LICENSE) file for project licensing.

---

**Maintained by**: go-keychain project
**Last Updated**: 2025-11-09
