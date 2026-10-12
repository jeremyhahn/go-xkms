# Testing Documentation

This directory contains documentation for testing go-xkms.

## Test Types

### Unit Tests
- Fast, in-memory tests
- No external dependencies
- Test individual components in isolation
- Target: 90%+ code coverage

```bash
make test
```

### Integration Tests
- End-to-end testing with real backends
- Docker-based isolated environments
- Test complete workflows

```bash
make integration-test
```

### Backend-Specific Tests
- PKCS#11: `make integration-test-pkcs11`
- TPM2: `make integration-test-tpm2`
- Software: `make integration-test-software`
- ACME challenge framework (enroll01/endorse01): `make integration-test-challenges`
- ACME + TPM end-to-end (device-attest-01/enroll-01/permanent-identifier),
  standalone only pending go-xkms#737: `make integration-test-acme-tpm`

## Testing Guides

- [Docker Testing](docker-testing.md) - Using Docker for isolated integration tests
- [Integration Tests](integration-tests.md) - Writing and running integration tests

## Test Coverage

View coverage for specific packages:

```bash
# Coverage for all packages
make coverage

# Coverage for specific package
make coverage-xkms
make coverage-backend
make coverage-certstore
```

## Testing Best Practices

1. **Unit tests** should be fast and never modify the host system
2. **Integration tests** should run in Docker containers
3. **All tests** should be meaningful and test real functionality
4. **Edge cases** should be covered with both success and failure paths
5. **Mock external services** in integration tests (don't hit real AWS/GCP/Azure)

## See Also

- [Build toggles](../crypto-backends/engineering.md#build-toggles)
- [Backend Documentation](../crypto-backends/)
