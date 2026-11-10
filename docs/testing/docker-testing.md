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

### CI images

The stages run in two images built from `build/docker/devcontainer/Dockerfile`:
the toolchain image and the integration image. Each is named by a hash of its
inputs (`make -s toolchain-image`, `make -s it-image`). One job, `ci-images`,
hands them to every job that runs a stage, through `scripts/ci-registry.sh`
(ruling 169):

- **Push to `main`** (`CI_PUBLISH=true`): `ci-images` runs on the `release`
  runner. It pushes each image whose hash main has not published yet, as
  `<registry>/<namespace>/go-xkms-ci-{toolchain,it}:<hash>-main`, a
  public namespace: only its owner or an admin can write a user namespace,
  so main's images do not live under the repository's owner (go-xkms #1730).
  The namespace is `CI_REGISTRY_OWNER` in `ci.yml`'s workflow env, which
  takes the repository variable of the same name on the forge and is empty
  on GitHub (ruling 217).
  On GHCR, where the run's token pushes, the namespace is the owner. It outputs
  `toolchain_ref` and `it_ref` as `@sha256:` digest references and validates
  each one. The forge push logs in with the runner's own `RELEASE_REGISTRY`,
  `RELEASE_REGISTRY_USER` and `RELEASE_REGISTRY_TOKEN` (ruling 173); no
  workflow env sets those names.
- **Any other event**: `ci-images` resolves `<hash>-main` to a digest.
  - If main published the same content, the consumers pull it.
  - If not, or if the registry cannot be read, the output is empty and each
    consumer builds the image on its own runner, with no push.
  - The lookup speaks the registry API with curl, not the Docker daemon. The
    scheme is `github.server_url`'s, so a forge served over plain HTTP is read
    over HTTP. Any other registry is read over HTTPS, with certificates
    verified.
  - On the forge the read is anonymous, since the namespace is public
    (ruling 217), and the run's token is never sent (Gitea refuses an
    Actions token at `/v2/token`). On GHCR a package is private when
    published, so every read step hands the script the run's token
    (`CI_REGISTRY_USER`, `CI_REGISTRY_TOKEN`, under `packages: read`) and a
    GHCR read uses it. A step with no token reads GHCR anonymously; a step
    with only one of the two fails, naming the missing one.
  - On the forge, it asks `<forge>/v2/token` for a pull token with no
    credential, for service `container_registry` and scope
    `repository:<name>:pull` (Distribution token specification, "Requesting
    a Token"). It then sends a `HEAD` of `/v2/<name>/manifests/<tag>` with
    that token as `Authorization: Bearer` ("Using the Bearer token"; OCI
    Distribution Spec v1.1.1, "Checking if content exists in the registry")
    and takes the digest from `Docker-Content-Digest`. A reply without a
    `sha256` digest is unexpected. The token reaches curl as a config on a
    pipe (`-K -`), never in its arguments, and is never logged.
  - On GHCR, it sends a `GET` of the manifest ("Pulling manifests") and
    digests the body. It answers a `401` challenge as the Distribution token
    specification describes ("How to authenticate"): a `Bearer` challenge is
    exchanged at its realm for a token, with the run's token as the `Basic`
    credential, and a `Basic` challenge is answered with the run's token.
    With no run token, a `Basic` challenge ends the read. So does an HTTPS
    registry whose realm is plain HTTP.
  - An empty output always comes with one `::warning::ci-registry: resolve:`
    line naming the case: main has not published the tag (not found), the
    registry refused the read (401/403), the registry did not
    answer, or an unexpected reply (quoted).
- **The publish log** shows each step: the login (`==> logged in to ... with
  the release runner's credential`), the lookup (`published already as
  <digest>`, or `has not published ... building and pushing it`), and
  `==> pushed <ref>:<hash>-main as <digest>`. A lookup that fails other than
  not-found is a warning, and the push goes on. A login that fails names its
  case and fails the job. When `RELEASE_REGISTRY` is not the forge's registry
  host, publish warns: pull requests resolve against the forge's host and
  would not find the image.
- **Consumers** (`image`, `lint-gates`, `static-analysis`, `build`,
  `nested-module-build`, `nested-module-test`, `build-raft`, `race`,
  `tpm2-simulator`) run `scripts/ci-registry.sh use` before their first
  stage. It runs `docker pull <registry>/<namespace>/<image>@sha256:...`
  through the runner's daemon, never with `buildx imagetools` (3 attempts).
  On the forge it pulls with no login. On GHCR it first logs in with the
  run's token in a private `DOCKER_CONFIG`; a refused login is a warning and
  the pull goes on anonymously. It refuses a reference outside that
  namespace, and holds the
  image with a never-started
  container until the job's `if: always()` teardown releases it. A consumer
  on a push to `main` never rebuilds an image `ci-images` published.

The registry is derived from `github.server_url` (GHCR on GitHub; on the
forge, the same host as its web UI), so no address is written in the tree.
`scripts/reap-stale-ci-stacks.sh` also removes stale registry-named CI images
and keeps any image a container uses, a hold included. The gate
`internal/buildgates/ci_image_digest_test.go` fails the build when a consumer
stops taking its image from `ci-images`. It also fails when an output of
`ci-images` stops naming both the `publish` step (main) and the `resolve` step
(pull requests), when either step stops writing that output, or when the
Validate step stops checking it. It fails when `ci.yml`'s `CI_REGISTRY_OWNER`
stops taking the repository variable on the forge, when `scripts/ci-registry.sh`
writes a namespace itself or a read leaves `CI_REGISTRY_OWNER`'s namespace,
when a read step stops handing the script the run's token, when the script
logs in or takes the token outside its login functions, sends it to the
forge, or stops using it for a GHCR resolve or pull, or when `imagetools`
returns.
`test/scripts/ci-registry.test.sh` covers the script.

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
    image: floci/floci:2.3.0@sha256:e0b292df4dc9559b7b1bf4f51bdda4bb8e269276236438cd03cae661260ea8a9
    environment:
      - FLOCI_DEFAULT_REGION=us-east-1
      - FLOCI_STORAGE_MODE=memory
    healthcheck:
      test: ["CMD", "/usr/local/bin/healthcheck.sh"]
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

The images CI builds install Debian packages from the public archive whenever
a layer is rebuilt: the images under `build/docker/`, `Dockerfile.cli` (the
image job, on every pull request), and the root `Dockerfile` and the backend
test images under `test/integration/` (the full-tier integration job's
`make integration-test`). An archive outage must not redden that build
(go-xkms#342), so every stage that runs `apt-get` first copies the shared
`build/docker/devcontainer/apt-retries.conf` to
`/etc/apt/apt.conf.d/80-retries`. It retries each failed fetch ten times with
exponential backoff capped at 60 s (about five minutes in all), and bounds each
connect and stalled transfer at 30 s. Each apt layer also runs `apt-get update`
and the install in one `RUN`, so a cached update layer is never reused stale.
There is no mirror fallback: no build argument names a mirror, and none is
hard-coded.

`make test-buildgates` checks every `build/docker/**/Dockerfile*` and the
CI-built files listed in `ciBuiltDockerfiles` (`internal/buildgates/apt_test.go`).
It fails an apt layer that runs before its stage (or the stage it is built
`FROM`) installs the shared file, sets `Acquire::` options inline, or splits
the update from the install, and one that installs recommends in a Dockerfile
that otherwise uses `--no-install-recommends`. It also fails the shared file if
a retry or timeout setting is missing or disabled. A new image CI builds joins
that list. The file is a
`TOOLCHAIN_INPUTS` entry, so changing it rebuilds the toolchain image.

## Best Practices

1. **Use make targets**: they namespace the Compose project and always clean up
2. **Clean up manual runs**: `docker compose down -v` after tests
3. **Check logs on failure**: `docker compose logs` provides debugging info
4. **Rebuild on dependency changes**: use `--no-cache` when needed
5. **Run individual backends**: faster feedback during development

For more details on specific backends, see [Integration Tests](integration-tests.md).
