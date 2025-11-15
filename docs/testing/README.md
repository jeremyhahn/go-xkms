# Testing Documentation

This directory contains documentation for testing go-keychain.

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

## Testing Guides

- [Docker Testing](docker-testing.md) - Using Docker for isolated integration tests
- [Integration Tests](integration-tests.md) - Writing and running integration tests

## Test Coverage

View coverage for specific packages:

```bash
# Coverage for all packages
make coverage

# Coverage for specific package
make coverage-keychain
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

- [Build System](../configuration/build-system.md)
- [Backend Documentation](../backends/)
