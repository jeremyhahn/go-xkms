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

### Per-Feature Tests
A local verify runs the fast gates plus the tests of the features a change
touches (Tenant ruling 1170).
- `scripts/features.tsv`: one row per `docs/SPEC.md` feature that links a docs
  folder, with its path prefixes, unit package patterns and integration
  targets (`-` for none). `internal/buildgates/features_tsv_test.go` fails
  when the table and the SPEC, the tree or the Makefile drift apart.
- `make test-feature FEATURE=<name>` (`Makefile:1192`): the row's unit tests,
  run as `test-go` runs them (same tags, `-race`, timeout and exclusions).
- `make integration-test-feature FEATURE=<name>` (`Makefile:1203`): the row's
  integration targets, in order. An unknown or empty `FEATURE` exits 2 on
  both targets and lists the names.
- `scripts/touched-features.sh <base> <tip>`: the features whose prefixes match
  a file of `git diff --name-only <base> <tip>`, sorted; only `ALL` when a
  changed file belongs to no feature (Makefile, `.github/`, `go.mod`, a shared
  package); nothing for an empty diff; exit 2 on a bad revision.

## Testing Guides

- [Docker Testing](docker-testing.md) - Using Docker for isolated integration tests
- [Integration Tests](integration-tests.md) - Writing and running integration tests
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
