# Integration Tests

> **Status: REFERENCE** · Last verified: 2026-10-13
> Scope: the backend, PKCS#11 conformance, WebAuthn and ACME integration suites under `test/integration/` and the Make targets that run them.

This document describes how to run the go-xkms backend integration tests.

## Overview

Integration suites live in `test/integration/<suite>/`. Most backend suites
run in Docker Compose; a few run in the devcontainer or on the host, as noted
per suite. For the Compose layout and execution flow, see
[docker-testing.md](docker-testing.md).

## Test Strategy

- **Unit Tests** (`make test`): Run fast, in-memory tests with no system modifications
- **Integration Tests** (`make integration-test`): Run Docker-based tests with real services
- **Compile Gate** (`make vet-integration`): Type-checks every suite under `test/integration/` — no host access, no Docker

Integration tests use Docker Compose to provide:
- Isolated test environments
- Consistent dependencies (SoftHSM, SWTPM, Floci, etc.)
- No host system modifications
- Repeatable test execution

## Compile Gate (`make vet-integration`)

`go vet ./...` from the repository root never reaches a file behind an
`integration` (or other suite) build tag, because that tag is never set —
which is how a package API change can break an integration suite with
nothing noticing until someone runs it in the devcontainer. `make
vet-integration` (`Makefile:3892`) closes that gap without running anything:
it discovers every distinct `//go:build` tag combination declared under
`test/integration/` and runs one `go vet -tags "..."` per combination,
scoped to `./test/integration/...`.

A single tag union is deliberately not used — some suites are mutually
exclusive within the same package (for example `integration && grpc` next
to `integration && !grpc`), and unioning every tag would compile both
halves of a pair together and fail on a conflict no real build
configuration ever produces. `scripts/vet-integration.sh` has the full
discovery algorithm and is called by both `make vet-integration` and CI's
Static Analysis job (`.github/workflows/ci.yml:1185`).

This gate is compile-only: it never runs a test body, dials hardware, or
touches the host. The suites themselves still run only in the devcontainer
via `make integration-test-*`.

## Test Structure

The backend suites covered here:

```
test/integration/
├── common/                    # common_test.go
├── pkcs11/                    # PKCS#11/SoftHSM
│   ├── docker-compose.yml
│   ├── Dockerfile
│   ├── pkcs11_integration_test.go
│   └── module/conformance/    # OASIS PKCS#11 v3.0 conformance suite
├── tpm2/                      # TPM2 simulator
│   ├── docker-compose.yml
│   ├── Dockerfile
│   └── tpm2_integration_test.go
├── awskms/                    # AWS KMS/Floci
│   ├── docker-compose.yml
│   ├── Dockerfile
│   └── awskms_integration_test.go
├── gcpkms/                    # GCP KMS (Floci emulator + mock)
│   ├── docker-compose.yml
│   ├── Dockerfile
│   ├── gcpkms_integration_test.go
│   └── gcpkms_emulator_integration_test.go
├── azurekv/                   # Azure Key Vault (mock)
│   ├── docker-compose.yml
│   ├── Dockerfile
│   └── azurekv_integration_test.go
├── vault/                     # HashiCorp Vault
│   ├── docker-compose.yml
│   ├── Dockerfile
│   └── vault_integration_test.go
├── webauthn-browser/          # Playwright WebAuthn RP suite
├── acme-tpm/                  # ACME device-attest-01/enroll-01/permanent-identifier over swtpm
│   ├── docker-compose.yml
│   └── *_test.go
└── challenges/                # ACME challenge-framework availability (enroll01/endorse01, no TPM)
    ├── docker-compose.yml
    └── {enroll01,endorse01}/*_test.go
```

There is no `test/integration/software/` directory; see
[Software Backend](#software-backend-integration-tests).

## Running Tests

### All Integration Tests

```bash
make integration-test
```

This runs the aggregate (`Makefile:1752`): the backends below except
acme-tpm, plus pkcs8, the PKCS#11 barrier and module suites, storage,
quantum, FROST, WebAuthn, FIDO2, the CLI, API and SDK suites, and more.

### Individual Backend Tests

```bash
# Software backend
make integration-test-software

# TPM2 simulator
make integration-test-tpm2

# PKCS#11/SoftHSM
make integration-test-pkcs11

# AWS KMS with Floci
make integration-test-awskms

# GCP KMS with Floci emulator + mock
make integration-test-gcpkms

# Azure Key Vault with mock
make integration-test-azurekv

# HashiCorp Vault
make integration-test-vault

# ACME challenge-framework availability (enroll01/endorse01, no TPM)
make integration-test-challenges

# ACME + TPM end-to-end (device-attest-01, enroll-01, permanent-identifier);
# standalone only -- see "ACME + TPM Integration Tests" below for why it is
# not part of the `make integration-test` aggregate yet
make integration-test-acme-tpm
```

Manual Compose runs below assume `make stage-gomodauth` has staged the
private-module build secret (see [docker-testing.md](docker-testing.md)).


## Software Backend Integration Tests

### Running

```bash
make integration-test-software
```

No Compose environment: the target runs
`go test -v -tags=integration ./pkg/backend/software/...` in the devcontainer
(`Makefile:1980`). No file in `pkg/backend/software` carries an
`integration` build tag, so this runs that package's regular tests.


## PKCS#11/SoftHSM Integration Tests

### Running

```bash
make integration-test-pkcs11
```

`integration-test-pkcs11` (`Makefile:2004`) runs the backend suite in
`test/integration/pkcs11`.

### Manual Execution

```bash
cd test/integration/pkcs11
docker compose run --build --rm test
docker compose down -v
```

### SoftHSM Configuration

The test image's command initializes the token
(`test/integration/pkcs11/Dockerfile`):
- Token Label: test-token
- Slot: 0
- SO PIN: 1234
- User PIN: 1234


## OASIS PKCS#11 v3.0 Conformance Suite

`test/integration/pkcs11/module/conformance` validates the module against the
OASIS PKCS#11 Base Specification v3.0 (return codes for all C_* functions,
session/object/mechanism semantics, v3.0 message-based crypto, profiles). It is
guarded by `//go:build integration && conformance`, so it only compiles when
BOTH tags are passed.

```bash
make integration-test-pkcs11-conformance
```

The target (`Makefile:2090`) runs in the devcontainer against a live
`xkms-server` (same transport env as `integration-test-pkcs11-module`) and is
part of the aggregate `make integration-test` through
`integration-test-pkcs11-module-all` (`Makefile:2272`).


## WebAuthn Integration Tests

There is one WebAuthn E2E suite: the Playwright suite in
`test/integration/webauthn-browser`. It builds and boots a real `xkmsd` and
drives Chrome's CDP virtual authenticator against the live Relying Party
(`/api/v1/webauthn/*`), covering registration and authentication,
tampered-signature rejection, `excludeCredentials` re-registration refusal,
discoverable resident-key login, unknown-session rejection, unregistered-user
login (404) and the cross-origin CORS path
(`test/integration/webauthn-browser/tests/rp-ceremony.spec.ts`).

```bash
make integration-test-webauthn           # alias of the target below (Makefile:2499)
make integration-test-webauthn-browser   # runs on the host; needs Node + Chromium (Makefile:2503)
```

A second Go/chromedp suite used to live in `test/integration/webauthn`. It was
deleted: its `TestVirtualAuthenticator_*` tests exercised Chrome's own CDP
virtual authenticator and asserted nothing about our Relying Party, and its
`TestE2E_*` tests navigated to `/webauthn/test` -- a path the server does not
serve -- while logging every failure instead of failing, so they passed whether
or not the RP worked.


## TPM2 Integration Tests

### Running

```bash
make integration-test-tpm2
```

### Manual Execution

```bash
cd test/integration/tpm2
docker compose up -d tpm-simulator
docker compose run --build --rm test
docker compose down -v
```

### SWTPM Configuration
- TPM Version: 2.0
- Service `tpm-simulator`, TCP command port `2421`, control port `2422`
- The test container reads `TPM2_SIMULATOR_HOST=tpm-simulator` and
  `TPM2_SIMULATOR_PORT=2421`


## ACME Challenge-Framework Integration Tests

### What It Tests
- enroll-01 and endorse-01 challenge availability against a real ACME server
  (no TPM involved)
- `dns-01` and `http-01` live under `test/integration/challenges/{dns01,http01}`
  as their own multi-service E2E stacks (`docker-compose.dns01.yml` /
  `docker-compose.http01.yml`) and are not part of this target

### Running

```bash
make integration-test-challenges
```

Part of the `make integration-test` aggregate (`Makefile:2380`).

### Manual Execution

```bash
cd test/integration/challenges
docker compose up -d --build acme-server
docker compose run --build --rm test
docker compose down -v
```


## ACME + TPM Integration Tests

### What It Tests
- The device-attest-01, enroll-01 and permanent-identifier ACME end-to-end
  flows: the test runner dials swtpm directly (acting as the TPM-backed
  device) and a real ACME server (xkmsd with its embedded ACME listener) over
  the network for the account/order/challenge/finalize protocol exchange

### Running

```bash
make integration-test-acme-tpm
```

**Not** part of the `make integration-test` aggregate: `device-attest-01` has
no registered server-side challenge verifier yet (go-xkms#737, pending an
owner ruling on go-xkms#828), so a subset of this suite fails against current
`main` for a known, tracked reason rather than a regression. Run it on its
own; the comment above `Makefile`'s `integration-test-acme-tpm` target
(`Makefile:2365`) explains where to add it back once #737 lands.

### Manual Execution

```bash
cd test/integration/acme-tpm
docker compose up -d --build tpm-simulator acme-server
docker compose run --build --rm test
docker compose down -v
```

### SWTPM Configuration

Not the TPM2 suite's simulator: this stack's `tpm-simulator` runs the
`go-xkms-swtpm` image on TCP command port `2321` and control port `2322`,
and the test container reads `TPM_SOCKET_HOST=tpm-simulator` and
`TPM_SOCKET_PORT=2321` (`test/integration/acme-tpm/docker-compose.yml`).


## AWS KMS Integration Tests

### Running

```bash
make integration-test-awskms
```

### Manual Execution

```bash
cd test/integration/awskms
docker compose up -d floci
docker compose run --build --rm test
docker compose down -v
```

### Floci Configuration
- Endpoint: `AWS_ENDPOINT_URL=http://floci:4566`
- Region: us-east-1
- Credentials: test/test (set in the compose file)

**Note:** These tests use Floci, not real AWS. No AWS credentials or costs required.


## Google Cloud KMS Integration Tests

### What It Tests
- GCP KMS key operations against the Floci GCP emulator
  (`gcpkms_emulator_integration_test.go`)
- Mock-client coverage (`gcpkms_integration_test.go`)

### Running

```bash
make integration-test-gcpkms
```

### Manual Execution

```bash
cd test/integration/gcpkms
docker compose run --build --rm test
docker compose down -v
```

**Note:** These tests use the Floci GCP emulator
(`GCPKMS_EMULATOR_ENDPOINT=floci-gcp:4588`) and a mock client, not real GCP.
No GCP credentials required.


## Azure Key Vault Integration Tests

### Running

```bash
make integration-test-azurekv
```

### Manual Execution

```bash
cd test/integration/azurekv
docker compose run --build --rm test
docker compose down -v
```

**Note:** These tests use a mock client, not real Azure. No Azure credentials required.


## HashiCorp Vault Integration Tests

### Running

```bash
make integration-test-vault
```

### Manual Execution

```bash
cd test/integration/vault
docker compose up -d vault
docker compose run --build --rm test
docker compose down -v
```

### Vault Configuration
- Endpoint: `VAULT_ADDR=http://vault:8200`
- Root Token: root (dev mode)
- Transit Engine: mounted at `transit` by the test image's command before the
  tests run (`test/integration/vault/Dockerfile`)


## Troubleshooting

### Tests Failing

If integration tests fail:

1. **Check Docker is running**: `docker ps`
2. **Clean up old containers**: `docker compose down -v`
3. **Rebuild images**: `docker compose build --no-cache`
4. **Check logs**: `docker compose logs`

### Permission Errors

If you encounter permission errors:

1. Ensure Docker has proper permissions
2. Check file ownership in test directories
3. Run `docker compose down -v` to clean up volumes


## Summary

Run all tests with:
```bash
make integration-test
```

Or test individual backends as needed.
