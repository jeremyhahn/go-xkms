# Integration Tests

This document describes how to run integration tests for all go-xkms backends.

## Overview

The go-xkms library includes comprehensive integration tests for all backends. Tests are organized by backend in `test/integration/{backend}/` with Docker-based execution for consistency and isolation.

**Test Statistics:**
- Total: 151 tests passing
- Coverage: 74.9%
- Backends: 9 (PKCS#8, AES, PKCS#11, TPM2, YubiKey, AWS KMS, GCP KMS, Azure KV, Vault)

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
vet-integration` closes that gap without running anything: it discovers
every distinct `//go:build` tag combination declared under
`test/integration/` and runs one `go vet -tags "..."` per combination,
scoped to `./test/integration/...`.

A single tag union is deliberately not used — some suites are mutually
exclusive within the same package (for example `integration && grpc` next
to `integration && !grpc`), and unioning every tag would compile both
halves of a pair together and fail on a conflict no real build
configuration ever produces. `scripts/vet-integration.sh` has the full
discovery algorithm and is called by both `make vet-integration` and CI's
Lint job.

This gate is compile-only: it never runs a test body, dials hardware, or
touches the host. The suites themselves still run only in the devcontainer
via `make integration-test-*`.

## Test Structure

Each backend has its own directory under `test/integration/`:

```
test/integration/
├── common/                    # Shared test utilities
├── software/                  # Software backend
│   ├── docker-compose.yml
│   ├── Dockerfile
│   └── software_integration_test.go
├── pkcs11/                    # PKCS#11/SoftHSM
│   ├── docker-compose.yml
│   ├── Dockerfile
│   └── pkcs11_integration_test.go
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
│   └── gcpkms_integration_test.go
├── azurekv/                   # Azure Key Vault (mock)
│   ├── docker-compose.yml
│   ├── Dockerfile
│   └── azurekv_integration_test.go
├── vault/                      # HashiCorp Vault
│   ├── docker-compose.yml
│   ├── Dockerfile
│   └── vault_integration_test.go
├── acme-tpm/                  # ACME device-attest-01/enroll-01/permanent-identifier over swtpm
│   ├── docker-compose.yml
│   └── *_integration_test.go
└── challenges/                 # ACME challenge-framework availability (enroll01/endorse01, no TPM)
    ├── docker-compose.yml
    └── {enroll01,endorse01}/*_test.go
```

## Running Tests

### All Integration Tests

```bash
make integration-test
```

This runs all backend integration tests sequentially.

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


## Software Backend Integration Tests

### What It Tests
- RSA key generation (2048, 3072, 4096 bits)
- ECDSA key generation (P-256, P-384, P-521)
- Ed25519 key generation
- Signing and verification
- Key storage and retrieval
- Error handling

### Running

```bash
make integration-test-software
```

### Manual Execution

```bash
cd test/integration/software
docker-compose run --rm test
docker-compose down -v
```


## PKCS#11/SoftHSM Integration Tests

### What It Tests
- SoftHSM token initialization
- RSA key generation in HSM
- ECDSA key generation in HSM
- Signing operations via HSM
- Key listing and attributes
- Error handling with HSM

### Running

```bash
make integration-test-pkcs11
```

### Manual Execution

```bash
cd test/integration/pkcs11
docker-compose run --rm test
docker-compose down -v
```


## OASIS PKCS#11 v3.0 Conformance Suite

`test/integration/pkcs11/module/conformance` validates the module against the
OASIS PKCS#11 Base Specification v3.0 (return codes for all C_* functions,
session/object/mechanism semantics, v3.0 message-based crypto, profiles). It is
guarded by `//go:build integration && conformance`, so it only compiles when
BOTH tags are passed.

```bash
make integration-test-pkcs11-conformance
```

The target runs in the devcontainer against a live `xkms-server` (same
transport env as `integration-test-pkcs11-module`) and is part of the aggregate
`make integration-test`.


## WebAuthn Integration Tests

There is one WebAuthn E2E suite: the Playwright suite in
`test/integration/webauthn-browser`. It boots a real `xkmsd` and drives
Chrome's CDP virtual authenticator against the live Relying Party
(`/api/v1/webauthn/*`), covering registration, authentication,
forged-signature rejection (401), `excludeCredentials` re-registration
refusal, discoverable resident-key login, unknown-session rejection (400),
unregistered-user login (404) and the cross-origin CORS path.

```bash
make integration-test-webauthn           # alias of the target below
make integration-test-webauthn-browser   # needs Node + Chromium
```

A second Go/chromedp suite used to live in `test/integration/webauthn`. It was
deleted: its `TestVirtualAuthenticator_*` tests exercised Chrome's own CDP
virtual authenticator and asserted nothing about our Relying Party, and its
`TestE2E_*` tests navigated to `/webauthn/test` -- a path the server does not
serve -- while logging every failure instead of failing, so they passed whether
or not the RP worked.

### SoftHSM Configuration
- Token Label: test-token
- Slot: 0
- SO PIN: 1234
- User PIN: 1234


## TPM2 Integration Tests

### What It Tests
- TPM2 simulator initialization
- RSA key generation in TPM
- ECDSA key generation in TPM
- Signing operations via TPM
- Key persistence in TPM
- Error handling with TPM

### Running

```bash
make integration-test-tpm2
```

### Manual Execution

```bash
cd test/integration/tpm2
docker-compose up -d tpm-simulator
docker-compose run --rm test
docker-compose down -v
```

### SWTPM Configuration
- TPM Version: 2.0
- Socket: /var/lib/swtpm/swtpm-sock
- State Directory: /var/lib/swtpm/state


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

Part of the `make integration-test` aggregate.

### Manual Execution

```bash
cd test/integration/challenges
docker compose up -d acme-server
docker compose run --rm test
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
own; `Makefile`'s `integration-test-acme-tpm` target explains where to add it
back once #737 lands.

### Manual Execution

```bash
cd test/integration/acme-tpm
docker compose up -d --build tpm-simulator acme-server
docker compose run --build --rm test
docker compose down -v
```

### SWTPM Configuration
Same swtpm image and socket contract as the TPM2 suite above.


## AWS KMS Integration Tests

### What It Tests
- AWS KMS key creation (using Floci)
- RSA and ECDSA key operations
- Signing via KMS
- Key management operations
- Error handling

### Running

```bash
make integration-test-awskms
```

### Manual Execution

```bash
cd test/integration/awskms
docker-compose up -d floci
docker-compose run --rm test
docker-compose down -v
```

### Floci Configuration
- Endpoint: http://floci:4566
- Region: us-east-1
- Credentials: test/test (auto-configured)

**Note:** These tests use Floci, not real AWS. No AWS credentials or costs required.


## Google Cloud KMS Integration Tests

### What It Tests
- GCP KMS key operations against the Floci GCP emulator (real gRPC, real signatures)
- RSA (RSASSA-PKCS1) and ECDSA P-256 sign/verify with local cryptographic verification
- Symmetric AES-256-GCM encrypt/decrypt round-trip
- Key management and lifecycle (list, delete)
- Mock-client coverage for algorithms the emulator lacks (EC P-384, RSA-PSS)
- Error handling

### Running

```bash
make integration-test-gcpkms
```

### Manual Execution

```bash
cd test/integration/gcpkms
docker-compose run --rm test
docker-compose down -v
```

**Note:** These tests use the Floci GCP emulator and a mock client, not real GCP. No GCP credentials required.



## Azure Key Vault Integration Tests

### What It Tests
- Azure Key Vault operations (using mock client)
- RSA and ECDSA key generation
- Signing operations
- Key management
- Error handling

### Running

```bash
make integration-test-azurekv
```

### Manual Execution

```bash
cd test/integration/azurekv
docker-compose run --rm test
docker-compose down -v
```

**Note:** These tests use a mock client, not real Azure. No Azure credentials required.



## HashiCorp Vault Integration Tests

### What It Tests
- Vault transit engine operations
- Key generation and management
- Signing and verification
- Secret management
- Error handling

### Running

```bash
make integration-test-vault
```

### Manual Execution

```bash
cd test/integration/vault
docker-compose up -d vault
docker-compose run --rm test
docker-compose down -v
```

### Vault Configuration
- Endpoint: http://vault:8200
- Root Token: root (dev mode)
- Transit Engine: Enabled automatically


## Troubleshooting

### Tests Failing

If integration tests fail:

1. **Check Docker is running**: `docker ps`
2. **Clean up old containers**: `docker-compose down -v`
3. **Rebuild images**: `docker-compose build --no-cache`
4. **Check logs**: `docker-compose logs`

### Permission Errors

If you encounter permission errors:

1. Ensure Docker has proper permissions
2. Check file ownership in test directories
3. Run `docker-compose down -v` to clean up volumes

### Slow Tests

Integration tests run in Docker and may take several minutes:
- Software: ~30 seconds
- TPM2: ~60 seconds (simulator startup)
- PKCS#11/SoftHSM: ~45 seconds
- AWS KMS/Floci: ~90 seconds (emulator initialization)
- GCP KMS: ~40 seconds (Floci emulator + mock)
- Azure KV: ~30 seconds (mock)
- Vault: ~60 seconds (Vault initialization)

Total time for all backends: ~6-8 minutes


## Summary

Integration tests validate all backend implementations:

- **151 tests** passing across 7 backends
- **74.9%** code coverage
- **Docker-based** for consistency
- **No host modifications** required
- **Automated** via make targets

Run all tests with:
```bash
make integration-test
```

Or test individual backends as needed.
