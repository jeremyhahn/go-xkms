# CertStore Integration Tests

Comprehensive integration tests for the `pkg/certstore` package, which provides high-level certificate management operations including certificate storage, chain management, CRL handling, and certificate verification.

## Overview

The certstore package builds on the storage layer by adding:
- Certificate validation and verification
- Certificate chain management
- Certificate Revocation List (CRL) handling
- Certificate expiration checking
- Thread-safe operations

These integration tests verify all aspects of the certstore functionality using in-memory storage.

## Test Coverage

### Basic Certificate Operations
- ✓ Store and retrieve certificates
- ✓ Store multiple certificate types (CA, leaf, server)
- ✓ Delete certificates
- ✓ List all certificates
- ✓ Handle empty certificate stores

### Certificate Chain Operations
- ✓ Store and retrieve 2-tier chains (root -> leaf)
- ✓ Store and retrieve 3-tier chains (root -> intermediate -> leaf)
- ✓ Store and retrieve complex multi-tier chains
- ✓ Verify chain ordering and integrity

### Certificate Revocation List (CRL) Tests
- ✓ Store and retrieve CRLs
- ✓ Multiple CAs with their own CRLs
- ✓ Check certificate revocation status
- ✓ Handle missing CRLs gracefully
- ✓ Validate CRL expiration

### Certificate Validation
- ✓ Verify certificates against trusted roots
- ✓ Verify certificates with intermediate CAs
- ✓ Detect untrusted root certificates
- ✓ Handle verification errors properly

### Certificate Revocation
- ✓ Check revoked certificates
- ✓ Check non-revoked certificates
- ✓ Handle missing CRLs
- ✓ Store revoked certificates with AllowRevoked flag
- ✓ Reject revoked certificates without AllowRevoked flag

### Certificate Expiration and Validity
- ✓ Reject expired certificates
- ✓ Reject not-yet-valid certificates
- ✓ Reject expired CRLs
- ✓ Validate certificate validity periods

### TLS Certificate Workflows
- ✓ Complete TLS workflow (CA, server, client certificates)
- ✓ Create TLS certificate structures
- ✓ Verify TLS certificates

### CA Certificate Management
- ✓ Manage multiple root CAs
- ✓ Cross-CA validation
- ✓ Intermediate CA chains
- ✓ Complex multi-level hierarchies

### Certificate Search and Filtering
- ✓ Search certificates by Common Name (CN)
- ✓ Filter CA certificates from leaf certificates
- ✓ List all certificates

### Composite CertStore
- ✓ Multiple independent certificate stores
- ✓ Storage isolation verification

### Error Handling and Edge Cases
- ✓ Nil certificate handling
- ✓ Empty Common Name handling
- ✓ Empty certificate chain handling
- ✓ Nil certificates in chain
- ✓ Nil CRL handling
- ✓ Closed store operations

### Concurrent Access
- ✓ Concurrent read/write operations
- ✓ Concurrent chain operations
- ✓ Concurrent CRL operations
- ✓ Thread-safety verification

### Performance Tests
- ✓ Large number of certificates (100+)
- ✓ Large certificate chains
- ✓ Performance benchmarking

## Running the Tests

### Using Make

Run the integration tests directly:

```bash
make integration-test-certstore
```

### Using Docker Compose

Run the tests in a containerized environment:

```bash
cd test/integration/certstore
docker-compose up --build
```

### Using Go Test

Run the tests directly with Go (requires build tag):

```bash
go test -v -tags=integration ./test/integration/certstore/...
```

### With Coverage

Generate code coverage report:

```bash
go test -v -tags=integration -coverprofile=coverage.out ./test/integration/certstore/...
go tool cover -html=coverage.out -o coverage.html
```

## Test Structure

Each test follows the pattern:
1. Create in-memory storage backend
2. Create certstore instance
3. Perform operations
4. Verify expected behavior
5. Clean up resources

## Key Features Tested

### Certificate Storage
- X.509 certificate storage and retrieval
- Certificate metadata extraction
- Certificate validation before storage
- Common Name (CN) based indexing

### Chain Management
- Multi-tier certificate chains (leaf -> intermediate -> root)
- Chain validation and verification
- Chain ordering (leaf to root)
- Chain retrieval by leaf CN

### CRL Management
- CRL storage per issuer
- Revocation checking
- CRL expiration validation
- Memory-based CRL cache

### Certificate Verification
- Chain of trust verification
- Signature validation
- Validity period checking
- Extended key usage validation
- Intermediate certificate handling

### Configuration Options
- Configurable verification options
- AllowRevoked flag for storing revoked certificates
- Custom verification policies

## Dependencies

- `github.com/stretchr/testify` - Test assertions and requirements
- `crypto/x509` - X.509 certificate handling
- `pkg/storage/memory` - In-memory storage backend
- `pkg/certstore` - Certificate store implementation

## Coverage Goals

These tests aim for 90%+ code coverage of the certstore package, including:
- All public APIs
- Error handling paths
- Edge cases
- Concurrent access scenarios
- Performance characteristics

## Notes

### In-Memory Storage
All tests use in-memory storage, which means:
- No disk I/O required
- Fast test execution
- Clean state for each test
- No cleanup of filesystem artifacts

### Thread Safety
The certstore implementation uses read-write mutexes for thread safety. Concurrent tests verify:
- No data races
- Consistent reads during concurrent writes
- Proper locking behavior

### Certificate Generation
Test certificates are generated with:
- RSA keys for CA certificates (2048-bit)
- ECDSA keys for leaf certificates (P-256)
- Short validity periods (24 hours)
- Realistic certificate hierarchies

### Performance Tests
Performance tests are skipped when running with `-short` flag:
```bash
go test -v -tags=integration -short ./test/integration/certstore/...
```

## Integration with CI/CD

These tests can be integrated into CI/CD pipelines:

```yaml
# Example GitHub Actions workflow
- name: Run CertStore Integration Tests
  run: |
    make integration-test-certstore
```

## Troubleshooting

### Test Failures
If tests fail, check:
1. Go version (1.21+ required)
2. Dependencies are properly installed (`go mod download`)
3. Build tags are included (`-tags=integration`)

### Performance Issues
If tests are slow:
1. Skip performance tests with `-short` flag
2. Reduce number of goroutines in concurrent tests
3. Check system resources

## Future Enhancements

Potential areas for additional testing:
- OCSP (Online Certificate Status Protocol) integration
- Certificate transparency log verification
- PKIX name constraint validation
- Policy constraint checking
- Certificate path length constraint validation
