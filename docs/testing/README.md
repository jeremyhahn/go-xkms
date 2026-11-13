# Testing Documentation

> **Status: REFERENCE** · Last verified: 2026-10-13
> Scope: index of the testing guides in this folder and the top-level test Make targets.

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

`integration-test` (`Makefile:1752`) runs the aggregate list of backend,
API, CLI and SDK suites. Any `make integration-test-<dir>` without its own
rule falls through to a pattern rule that runs `test/integration/<dir>`
(`Makefile:5107`).

### Backend-Specific Tests
- PKCS#11: `make integration-test-pkcs11` (backend suite, `Makefile:2004`)
- TPM2: `make integration-test-tpm2` (`Makefile:2328`)
- Software: `make integration-test-software` (`Makefile:1980`)
- ACME challenge framework (enroll01/endorse01): `make integration-test-challenges` (`Makefile:2380`)
- ACME + TPM end-to-end (device-attest-01/enroll-01/permanent-identifier),
  run on its own, outside the `integration-test` aggregate, pending
  go-xkms#737: `make integration-test-acme-tpm` (`Makefile:2365`)

## Testing Guides

- [Docker Testing](docker-testing.md) - Using Docker for isolated integration tests
- [Integration Tests](integration-tests.md) - Writing and running integration tests
- [Integration Inventory](integration-inventory.md) - Every test/integration directory by layer, every sleep, slice (b) verdicts (#1607)
- [Live-Backend E2E](live-e2e.md) - Playwright against a real xkey app and xkms-server
- [Parity Matrix](parity-matrix.md) - GUI / CLI / xkmsctl operations and their live-test status

## Test Coverage

View coverage for specific packages:

```bash
# Coverage for all packages (unit tests)
make coverage

# Coverage for one package: coverage-<name> covers ./pkg/<name> or
# ./cmd/<name> (pattern rule, Makefile:5115)
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
