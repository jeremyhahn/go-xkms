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

### Touched Tests
A local verify runs the tests a change touches (Tenant rulings 1170 and 1171).
Both scripts read the mapping the Makefile already has; there is no second
feature list.
- `scripts/touched-features.sh <base> <tip>`: the features whose
  `make integration-test-<feature>` must run. A feature is a
  `test/integration/<feature>/` directory holding `_test.go` files. A changed
  file under it, or a package its tests import (directly or transitively,
  `go list -deps -test` under that suite's own tags), selects it. A non-test
  Go file under it is also a package: other suites that import it (as
  several import `test/integration/xkmsdtest`) are selected too. A suite's
  tags are the `-tags` of the lines that `go test` its directory in the
  recipe of `integration-test-<feature>` or its prerequisites
  (`integration-test-clusterca` adds `tpm_simulator`), expanded by make, else
  those of `integration-test-%` (from `make -n`, so conditional
  `BUILD_TAGS +=` tags count). A suite is also selected by a change to a
  binary it builds and runs, or to one of the binary's deps: a quoted
  `.../cmd/<name>` path in the suite's Go files, or a recipe line that builds
  `./cmd/<name>` (after any `cd`, so `xkey/cmd/xkey` counts) and tests
  `./test/integration/<feature>`. A suite whose explicit recipe runs no
  `go test` of it the script can read (it hands the suite to Compose, whose
  Dockerfile builds what it runs) is selected by every change that selects
  any feature.
  When the script cannot prove a suite unaffected it prints `ALL`: if none of
  a suite's tests builds under its tags, or a package or binary in the graphs
  does not load (`Error` or `DepsErrors` from `go list -e`), any package
  change prints `ALL`. A change to the
  Makefile, `.github/`, `go.mod`/`go.sum`, `test/integration/common/` or a
  file no feature reaches prints only `ALL`; a docs-only change prints nothing.
- `scripts/touched-packages.sh <base> <tip>`: the repo-relative package
  directories for `make test-pkg PKG=<dir>`, which runs `go test $(TEST_FLAGS)`
  (the unit-test tags of `TEST_TAGS`) on `./<dir>`: each changed package plus
  its direct importers in the root module, read under the same tags. If a
  package of `./...` does not load, its importers are unknown and the script
  prints only `ALL` (run `make test`).
- Both count both sides of a rename and exit 2 on a bad revision.
  `internal/buildgates/integration_targets_test.go` fails when a
  `test/integration/` directory with tests has no `integration-test-<name>`
  that runs it, or an explicit `integration-test-<name>` names a missing
  directory.

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
