# Testing Infrastructure

## Unit Tests
- Command: `make test`
- Flags: `-v -race -tags="codec_cbor codec_json codec_msgpack tpm_simulator"`
- Coverage threshold: 90%
- Coverage output: `build/coverage/`
- Excludes hardware backends requiring CGO/external deps from default `make test`
- Package-specific: `make test-<package>` (e.g., `make test-backend`, `make test-seal`)

## Integration Tests
- Command: `make integration-test`
- **ALWAYS** run in Docker or devcontainer, NEVER on host
- Each test suite in `test/integration/<pkg>/` has its own `docker-compose.yml`
- Two execution modes:
  1. **Docker Compose**: `docker compose run --rm test` (most suites)
  2. **Devcontainer**: `run_in_devcontainer` macro (software, webauthn, fido2)
- Integration test tags: `integration pkcs8 pkcs11 codec_cbor codec_json codec_msgpack`
- Build tag `integration` gates integration test code

## Integration Test Suites (execution order in `make integration-test`)
1. `integration-test-software` (devcontainer)
2. `integration-test-pkcs8` (Docker)
3. `integration-test-pkcs11` (Docker + SoftHSM)
4. `integration-test-tpm2` (Docker + SWTPM simulator)
5. `integration-test-awskms` (Docker + LocalStack)
6. `integration-test-gcpkms` (Docker + mock)
7. `integration-test-azurekv` (Docker + mock)
8. `integration-test-vault` (Docker + Vault server)
9. `integration-test-storage` (Docker: file, memory, hardware-pkcs11, hardware-tpm2)
10. `integration-test-utils` (signing, opaque, metrics, health, ratelimit, correlation, crypto, encoding, backend, certstore, xkms, webauthn)
11. `integration-test-quantum` (Docker)
12. `integration-test-frost` (Docker)
13. `integration-test-webauthn` (devcontainer)
14. `integration-test-fido2` (devcontainer)
15. `integration-test-cli` (Docker)
16. `integration-test-api-all` (Docker: unix, rest, grpc, quic)
17. `integration-test-sdk-go` (devcontainer)
18. `integration-test-bootstrap` (Docker: zone-generator, CoreDNS, xkms-server)

## Devcontainer
- Config: `.devcontainer/docker-compose.yml`
- Has all dev, build, and test dependencies pre-installed
- Makefile helper: `run_in_devcontainer` auto-starts container if needed
- Makefile helper: `run_with_server` starts xkms-server + devcontainer

## Docker Images Used
- `golang:bookworm` — base Go image for most test containers
- `ghcr.io/stefanberger/swtpm:latest` — TPM2 simulator
- `localstack/localstack` — AWS service emulator
- `hashicorp/vault` — HashiCorp Vault

## Important Notes
- `GOTOOLCHAIN=auto` must be set in docker-compose environments to auto-download Go 1.26.0
- Docker images need `--build` flag to avoid stale images (PKCS11, bootstrap targets)
- Port 8443 conflict: devcontainer binds 8443; must stop before CLI tests
- CoreDNS container is scratch-based (no shell available)
- Bootstrap docker-compose: sequential deps (xkms-server → zone-generator → CoreDNS → test runner)
