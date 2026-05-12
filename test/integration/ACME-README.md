# Go-TrustedCA Integration Tests

Comprehensive Docker-based integration tests for the go-trusted-ca Certificate Authority implementation.

## Overview

This test suite provides complete end-to-end testing of **all 66 methods** in the `CertificateAuthority` interface using real Docker containers, real storage backends, real certificates, and real cryptographic operations.

## Test Files

### Phase 1: Core Certificate Operations
**File:** `ca_phase1_integration_test.go`

Tests 19 core CA methods:
- Certificate issuance (RSA, ECDSA, Ed25519)
- Certificate signing requests (CSR)
- TPM certificates (EK, AK)
- TLS integration (certificates, bundles, configurations)
- Certificate revocation
- Certificate verification
- crypto.Signer interface implementation

### Phase 2: Trust Chain & Storage
**File:** `ca_phase2_integration_test.go`

Tests 22 trust chain and storage methods:
- Certificate store operations
- Trust chain building
- CA bundles and cert pools
- Cross-signing operations
- PEM import/export
- Advanced signing operations

### Phase 3: Platform Integration & Attestation
**File:** `ca_phase3_integration_test.go`

Tests 25 platform and TPM attestation methods:
- Platform key storage integration
- Configuration getters
- Initialization and loading
- TPM attestation (quotes, PCRs, event logs)
- Concurrent operations
- Error handling
- Complete end-to-end workflows

### Test Fixtures & Helpers
**File:** `ca_fixtures.go`

Provides test utilities:
- `NewTestCA()` - Creates test CA with in-memory storage
- Certificate request builders
- Mock TPM data generators
- Test key pair generators
- Common assertion helpers

### RFC 8555 Compliance Tests
**Files:** `rfc8555_*_test.go`

ACME protocol compliance tests following RFC 8555 specification.

## Running Tests

### Local Testing (Unit-Style with Real CA)

```bash
# Run all CA integration tests
go test -tags=local -v ./test/integration/

# Run specific phase
go test -tags=local -v ./test/integration/ -run TestPhase1_
go test -tags=local -v ./test/integration/ -run TestPhase2_
go test -tags=local -v ./test/integration/ -run TestPhase3_

# Run specific test
go test -tags=local -v ./test/integration/ -run TestPhase1_IssueCertificate
```

### Docker Integration Testing

```bash
# Run full Docker integration suite
make integration-test

# Or manually with docker-compose
cd /home/jhahn/sources/go-trusted-ca/test/integration
docker-compose -f docker-compose.integration.yml up --build --abort-on-container-exit

# View logs after failure
docker-compose -f docker-compose.integration.yml logs acme-server
docker-compose -f docker-compose.integration.yml logs integration-tests

# Clean up
docker-compose -f docker-compose.integration.yml down -v
```

### Makefile Targets

```bash
make integration-test              # Run all Docker integration tests
make integration-test-rfc8555      # Run RFC 8555 compliance tests
make integration-test-ca           # Run CA-specific tests (if implemented)
```

## Test Infrastructure

### Docker Compose
**File:** `test/integration/docker-compose.integration.yml`

Two-container setup:
- `acme-server`: ACME CA server under test
- `integration-tests`: Test runner with comprehensive test suite

### Dockerfiles
- `test/Dockerfile.server` - ACME server image
- `test/Dockerfile.integration` - Test runner image

### Test Runner Script
**File:** `test/scripts/run-integration-tests.sh`

Handles:
- Server health checks
- Test execution
- Result collection
- Error reporting

## Test Coverage

See [COVERAGE.md](./COVERAGE.md) for detailed coverage matrix.

**Summary:**
- **66/66 CA interface methods tested (100%)**
- **150+ individual test cases**
- **50+ test functions**
- **3 comprehensive workflow tests**
- **Concurrent operation testing**
- **Error handling testing**

## Requirements

### Local Testing
- Go 1.21 or higher
- No external dependencies (uses in-memory storage)

### Docker Testing
- Docker 20.10+
- Docker Compose v2.0+
- 2GB RAM minimum
- Network access for image downloads

## Architecture

### Storage Backends
Tests use in-memory storage backends:
- **Key Storage:** go-xkms with PKCS#8 backend (memory)
- **Certificate Storage:** go-objstore local backend (tmpfs)

### Cryptographic Algorithms
- RSA-2048, RSA-4096
- ECDSA P-256, P-384
- Ed25519 (where supported)

### Certificate Types
- Leaf certificates (TLS server, client)
- CA certificates (root, intermediate, sub-CA)
- TPM certificates (EK, AK)
- Cross-signed certificates

## Test Patterns

### Basic Test Pattern
```go
func TestPhase1_MethodName(t *testing.T) {
    caInstance, cleanup := NewTestCA(t)
    defer cleanup()

    t.Run("SubTestName", func(t *testing.T) {
        // Arrange
        request := TestCertificateRequest("test.example.com")

        // Act
        result, err := caInstance.MethodName(request)

        // Assert
        require.NoError(t, err)
        assert.NotNil(t, result)
    })
}
```

### Workflow Test Pattern
```go
t.Run("CompleteWorkflow", func(t *testing.T) {
    // 1. Issue certificate
    cert, err := caInstance.IssueCertificate(request)
    require.NoError(t, err)

    // 2. Verify it was issued
    issued, err := caInstance.Issued(cn)
    require.NoError(t, err)
    assert.True(t, issued)

    // 3. Retrieve it
    retrieved, err := caInstance.Certificate(attrs)
    require.NoError(t, err)

    // 4. Use in TLS
    tlsCert, err := caInstance.TLSCertificate(attrs)
    require.NoError(t, err)

    // 5. Revoke it
    err = caInstance.Revoke(cert, false)
    require.NoError(t, err)
})
```

## Debugging

### Enable Verbose Output
```bash
go test -tags=local -v ./test/integration/ -run TestName
```

### Check Docker Logs
```bash
# Server logs
docker logs acme-integration-server

# Test logs
docker logs acme-integration-tests

# Follow logs in real-time (from test/integration directory)
docker-compose -f docker-compose.integration.yml logs -f
```

### Run Tests in Docker with Shell Access
```bash
# Start containers (from test/integration directory)
docker-compose -f docker-compose.integration.yml up -d acme-server

# Wait for server to be healthy
docker exec acme-integration-server wget -q -O- http://localhost:8080/acme/directory

# Run tests interactively
docker-compose run integration-tests /bin/bash
# Inside container:
cd /workspace/go-trusted-ca
go test -tags=local -v ./test/integration/ -run TestPhase1_
```

## Continuous Integration

These tests are designed for CI/CD:
- ✅ Isolated Docker containers
- ✅ No external dependencies
- ✅ Deterministic results
- ✅ Fast execution (< 5 minutes)
- ✅ Clear pass/fail status
- ✅ Comprehensive logging

### CI/CD Integration Example

```yaml
# .github/workflows/integration-tests.yml
jobs:
  integration-test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run Integration Tests
        run: make integration-test
```

## Known Limitations

1. **TPM Attestation**: Mock data used (no real TPM simulator)
2. **External CRL/AIA**: No external HTTP servers for testing distribution
3. **HSM Integration**: Only PKCS#8 backend tested (no PKCS#11)
4. **Performance Tests**: Limited to basic concurrency testing

## Future Enhancements

- [ ] Add TPM simulator container for real attestation testing
- [ ] Add mock HTTP server for AIA/CRL distribution testing
- [ ] Add PKCS#11 HSM testing with SoftHSM
- [ ] Add performance benchmarks
- [ ] Add chaos/fault injection testing
- [ ] Add certificate renewal testing
- [ ] Add OCSP responder testing

## Contributing

When adding new CA methods:
1. Add tests to appropriate phase file
2. Create fixtures in `ca_fixtures.go` if needed
3. Update `COVERAGE.md` with new method coverage
4. Ensure Docker tests pass
5. Document any new requirements

## References

- [CA Interface](../../pkg/ca/interface.go)
- [CA Implementation](../../pkg/ca/ca.go)
- [ACME RFC 8555](https://tools.ietf.org/html/rfc8555)
- [TCG TPM 2.0 Keys for Device Identity](https://trustedcomputinggroup.org/resource/tpm-2-0-keys-for-device-identity-and-attestation/)
- [go-xkms](https://github.com/jeremyhahn/go-xkms)
- [go-objstore](https://github.com/jeremyhahn/go-objstore)

## Support

For issues or questions:
1. Check test logs in `/var/log/tests/integration.log`
2. Review Docker container logs
3. Run with `-v` flag for verbose output
4. Check [COVERAGE.md](./COVERAGE.md) for test details
