# Docker Integration Testing Guide

> **Status: REFERENCE** · Last verified: 2026-10-13
> Scope: the per-backend Docker Compose integration suites under `test/integration/` and the `integration-test-<backend>` Make targets that drive them.

This document describes how the Docker-based backend integration suites are
laid out and run.

## Overview

Most backends have a Docker Compose test environment in
`test/integration/<backend>/`. This provides:
- Consistent, isolated test environments
- No host system modifications required
- Reliable, repeatable test execution
- All dependencies included (SoftHSM, SWTPM, Floci, Vault, etc.)

## Test Organization

A backend directory with a compose environment contains:

```
test/integration/<backend>/
├── docker-compose.yml    # Service definitions
├── Dockerfile            # Test container image (copies the repo, runs go test)
└── *_test.go             # Integration tests (build tag: integration)
```

Backends covered here:

| Backend | Dependency | Make target |
|---|---|---|
| software | none; no compose file, runs `./pkg/backend/software/...` in the devcontainer | `integration-test-software` (`Makefile:2028`) |
| tpm2 | `tpm-simulator` (swtpm) | `integration-test-tpm2` (`Makefile:2376`) |
| pkcs11 | SoftHSM2 inside the test image | `integration-test-pkcs11` (`Makefile:2052`) |
| awskms | `floci` (Floci AWS emulator) | `integration-test-awskms` (`Makefile:2465`) |
| gcpkms | `floci-gcp` (Floci GCP emulator) plus a mock client | `integration-test-gcpkms` (`Makefile:2475`) |
| azurekv | none; mock client | `integration-test-azurekv` (`Makefile:2484`) |
| vault | `vault` (HashiCorp Vault, dev mode) | `integration-test-vault` (`Makefile:2493`) |

## Quick Start

### Run All Integration Tests

```bash
make integration-test
```

`integration-test` (`Makefile:1800`) runs a much longer list than the seven
backends above: pkcs8, the PKCS#11 barrier and module suites, ACME
challenges, storage, quantum, FROST, WebAuthn, FIDO2, the CLI, API and SDK
suites, and more. Read the target's prerequisites for the current list.

### In CI

CI's full-tier `integration` job (`.github/workflows/ci.yml`) runs
`make integration-test COMPOSE_RUN_ID=ci-<run>-<attempt>`. Every compose
project is then named `go-xkms-ci-<run>-<attempt>-<suite>` (`COMPOSE_NS`,
`Makefile:341`). The job's first step,
`scripts/reap-stale-ci-stacks.sh go-xkms-ci-`, removes stacks that a dead
runner left behind. Its last step, `make clean-test-containers`, runs under
`if: always()`. The job runs on a push to `main`, on `workflow_dispatch`,
and on a pull request labelled `ci:full`.

### Run Individual Backend Tests

```bash
make integration-test-software
make integration-test-tpm2
make integration-test-pkcs11
make integration-test-awskms
make integration-test-gcpkms
make integration-test-azurekv
make integration-test-vault
```

## Backend-Specific Details

The Make targets run Compose as `docker compose -p <namespace>-<backend>`
(the `compose` macro, `Makefile:341`). Running Compose by hand works too,
but the test images mount the `gomodauth` build secret from
`build/docker/devcontainer/gomodauth.env`: run `make stage-gomodauth` (`Makefile:3530`)
first.

### Software

No compose environment. The target runs the software backend's integration
tests inside the devcontainer:

```bash
make integration-test-software
```

### PKCS#11 (SoftHSM)

Uses SoftHSM2 to simulate HSM hardware: SoftHSM 2.7.0, built in every test
image from the pinned, checksum-verified release in `scripts/build-softhsm.sh`
rather than the distribution's 2.6.1 (see
[`../pkcs11-backend/engineering.md`](../pkcs11-backend/engineering.md)
§"SoftHSM version").

**Configuration** (`test/integration/pkcs11/docker-compose.yml`, `Dockerfile`):
- Token label: `test-token` (`PKCS11_TOKEN_LABEL`)
- PIN and SO PIN: `1234` (`PKCS11_PIN`)
- The image's command initializes the token in slot 0, then runs the tests.

```bash
cd test/integration/pkcs11
docker compose run --build --rm test
```

### TPM2 (SWTPM)

Uses the swtpm software TPM simulator over TCP.

**Configuration:**
- TPM version: 2.0
- Command port `2421`, control port `2422` on the `tpm-simulator` service
- The test container reads `TPM2_SIMULATOR_HOST=tpm-simulator` and
  `TPM2_SIMULATOR_PORT=2421`

```bash
cd test/integration/tpm2
docker compose up -d tpm-simulator
docker compose run --build --rm test
docker compose down -v
```

### AWS KMS (Floci)

Uses Floci to emulate AWS KMS.

**Configuration:**
- Endpoint: `AWS_ENDPOINT_URL=http://floci:4566`
- Region: `us-east-1`
- Credentials: `test` / `test`

```bash
cd test/integration/awskms
docker compose up -d floci
docker compose run --build --rm test
docker compose down -v
```

### GCP KMS (Floci GCP + mock)

Uses the Floci GCP emulator (`GCPKMS_EMULATOR_ENDPOINT=floci-gcp:4588`,
project `test-project`) alongside a mock client.

```bash
cd test/integration/gcpkms
docker compose run --build --rm test
docker compose down -v
```

### Azure Key Vault (Mock)

Uses a mock client for Azure Key Vault operations; there is no dependency
service.

```bash
cd test/integration/azurekv
docker compose run --build --rm test
```

### HashiCorp Vault

Uses a real Vault server in dev mode.

**Configuration:**
- Endpoint: `VAULT_ADDR=http://vault:8200`
- Token: `root`

```bash
cd test/integration/vault
docker compose up -d vault
docker compose run --build --rm test
docker compose down -v
```

## Docker Compose Files

Each compose file defines:

1. **Service dependencies** (e.g., Floci, Vault server), with health checks
2. **A `test` service** built from the backend's `Dockerfile` with the repo
   root as build context; the source is copied into the image (`/app`), not
   volume-mounted
3. **The `gomodauth` secret** used to resolve private modules during the build

Excerpt (`test/integration/awskms/docker-compose.yml`):

```yaml
services:
  floci:
    image: floci/floci:latest
    environment:
      - FLOCI_DEFAULT_REGION=us-east-1
      - FLOCI_STORAGE_MODE=memory
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:4566/_floci/health"]
    ports:
      - "0:4566"

  test:
    build:
      context: ../../..
      dockerfile: test/integration/awskms/Dockerfile
      secrets:
        - gomodauth
    depends_on:
      floci:
        condition: service_healthy
    environment:
      - AWS_ENDPOINT_URL=http://floci:4566
      - AWS_ACCESS_KEY_ID=test
      - AWS_SECRET_ACCESS_KEY=test
      - AWS_REGION=us-east-1
    working_dir: /app

secrets:
  gomodauth:
    file: ../../../build/docker/devcontainer/gomodauth.env
```

The test command lives in each `Dockerfile`'s `CMD` (for awskms:
`go test -v -tags='integration awskms codec_cbor codec_json codec_msgpack gms_pure_go' ./test/integration/awskms/...`).

## Manual Testing

For interactive debugging:

```bash
make stage-gomodauth
cd test/integration/pkcs11

# Open a shell in the test container instead of running its CMD
docker compose run --build --rm test sh

# Inside the container, initialize the token, then run the tests:
softhsm2-util --init-token --slot 0 --label test-token --so-pin 1234 --pin 1234
go test -v -tags='integration pkcs11 codec_cbor codec_json codec_msgpack gms_pure_go' ./test/integration/pkcs11

# Cleanup
docker compose down -v
```

## Test Execution Flow

When you run a compose-backed `make integration-test-<backend>`:

1. **Cleanup**: `docker compose down -v` removes old containers
2. **Start services**: dependency services start with `up -d` (tpm2, awskms,
   vault; the others rely on `depends_on`)
3. **Build and run**: `docker compose run --build --rm test` builds the test
   image and runs its `CMD`
4. **Cleanup**: a shell `trap` runs `docker compose down -v --remove-orphans`
   on exit, including on failure or interrupt

This ensures:
- Clean slate for each test run
- No state pollution between runs
- Isolated test environments

## Troubleshooting

### Tests Failing

```bash
docker ps

cd test/integration/<backend>
docker compose down -v
docker compose build --no-cache
docker compose logs
```

### Service Not Starting

```bash
docker compose ps
docker compose logs <service-name>

# Example: Floci not starting
docker compose logs floci
```

### Network Issues

Dependency services publish on ephemeral host ports (`"0:<port>"`); the test
container reaches them by service name on the compose network.

```bash
docker network ls
docker network inspect <network-name>
```

## CI/CD Integration

The nightly workflow runs the full suite: `XKMS_COMPOSE_SERVER=1 make
integration-test` (`.github/workflows/nightly.yml:239`). Per-PR CI does not
run the Docker integration suites.

### apt in the CI images

The images under `build/docker/` install Debian packages from the public
archive whenever a layer is rebuilt. An archive outage must not redden that
build (go-xkms#342), so every stage that runs `apt-get` first copies the shared
`build/docker/devcontainer/apt-retries.conf` to
`/etc/apt/apt.conf.d/80-retries`. It retries each failed fetch ten times with
exponential backoff capped at 60 s (about five minutes in all), and bounds each
connect and stalled transfer at 30 s. Each apt layer also runs `apt-get update`
and the `--no-install-recommends` install in one `RUN`, so a cached update
layer is never reused stale. There is no mirror fallback: no build argument
names a mirror, and none is hard-coded.

`make test-buildgates` fails any `build/docker/**/Dockerfile*` apt layer that
runs before its stage (or the stage it is built `FROM`) installs the shared
file, sets `Acquire::` options inline, splits the update from the install, or
installs recommends, and fails the shared file if a retry or timeout setting is
missing or disabled (`internal/buildgates/apt_test.go`). The file is a
`TOOLCHAIN_INPUTS` entry, so changing it rebuilds the toolchain image.

## Best Practices

1. **Use make targets**: they namespace the Compose project and always clean up
2. **Clean up manual runs**: `docker compose down -v` after tests
3. **Check logs on failure**: `docker compose logs` provides debugging info
4. **Rebuild on dependency changes**: use `--no-cache` when needed
5. **Run individual backends**: faster feedback during development

For more details on specific backends, see [Integration Tests](integration-tests.md).
