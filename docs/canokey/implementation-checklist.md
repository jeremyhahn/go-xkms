# CanoKey Integration Implementation Checklist

Use this checklist to track implementation progress. Update status as work progresses.

## Legend
- [ ] Not started
- [x] Completed
- [~] In progress
- [-] Skipped/Not applicable

---

## Phase 1: Documentation

### docs/canokey/
- [x] README.md - Entry point with quick start
- [x] architecture.md - System design and components
- [x] configuration.md - Configuration options
- [x] usage.md - CLI command reference
- [x] api.md - Go API documentation
- [x] security.md - Security considerations
- [x] implementation-plan.md - Detailed implementation plan
- [x] implementation-checklist.md - This file

---

## Phase 2: Devcontainer Updates

### .devcontainer/docker-compose.yml
- [x] Add canokey-qemu service definition
- [x] Add canokey-state volume
- [x] Add healthcheck for canokey service
- [x] Update devcontainer service dependencies

### .devcontainer/Dockerfile.canokey
- [x] Create Dockerfile for CanoKey QEMU build
- [x] Add CanoKey QEMU build step
- [x] Install libfido2 dependencies

### .devcontainer/devcontainer.json
- [x] Add `canokey` to go.buildTags
- [x] Add `fido2` to go.buildTags
- [x] Add `webauthn` to go.buildTags
- [x] Add CanoKey environment variables

### .devcontainer/scripts/post-create.sh
- [x] Add CanoKey QEMU initialization check
- [x] Add FIDO2 device detection check

### .devcontainer/scripts/post-start.sh
- [x] Add CanoKey QEMU health check
- [x] Display CanoKey QEMU status
- [x] Add FIDO2/libfido2 check

---

## Phase 3: CanoKey PKCS#11 Integration Tests

### test/integration/pkcs11/pkcs11_canokey_integration_test.go
- [x] Create file with build tags
- [x] Implement getCanoKeyConfig() helper
- [x] Implement device detection tests
- [x] Implement RSA key generation tests
  - [x] RSA 2048
  - [x] RSA 4096
- [x] Implement ECDSA key generation tests
  - [x] P-256
  - [x] P-384
- [-] Implement Ed25519 tests (firmware 3.0+ - future enhancement)
- [x] Implement signing tests
  - [x] RSA-PKCS1v15
  - [x] ECDSA
- [x] Implement PIV slot tests
  - [x] Authentication (0x9a)
  - [x] Signature (0x9c)
  - [x] Key Management (0x9d)
  - [x] Card Authentication (0x9e)
  - [x] Retired slots (0x82-0x95)
- [x] Implement certificate tests
- [x] Implement concurrent operations tests
- [x] Implement stress tests

---

## Phase 4: FIDO2 Integration Tests

### test/integration/fido2/doc.go
- [x] Create package documentation
- [x] Document build tags
- [x] Document test categories

### test/integration/fido2/testutil.go
- [x] Create test configuration struct
- [x] Implement QEMU device setup
- [x] Implement device availability check
- [x] Implement credential ID/salt helpers
- [x] Implement cleanup functions

### test/integration/fido2/fido2_integration_test.go
- [x] Create file with build tags
- [x] Implement TestFIDO2ListDevices
- [x] Implement TestFIDO2DeviceInfo
- [x] Implement TestFIDO2WaitForDevice
- [x] Implement TestFIDO2EnrollmentFlow
- [x] Implement TestFIDO2AuthenticationFlow
- [x] Implement TestFIDO2RepeatedAuthentication
- [x] Implement TestFIDO2EnrollmentWithUserVerification
- [x] Implement TestFIDO2ConcurrentOperations
- [x] Implement TestFIDO2ErrorHandling
- [x] Implement TestFIDO2HandlerLifecycle
- [x] Implement TestFIDO2InvalidCredential

### test/integration/fido2/cli_test.go
- [x] Create file with build tags
- [x] Implement TestCLIFIDO2ListDevices
- [x] Implement TestCLIFIDO2WaitDevice
- [x] Implement TestCLIFIDO2Register
- [x] Implement TestCLIFIDO2Authenticate
- [x] Implement TestCLIFIDO2Info
- [x] Implement TestCLIFIDO2FullWorkflow
- [x] Implement TestCLIFIDO2ErrorCases

### test/integration/fido2/cli_multiprotocol_test.go
- [x] Create file with build tags
- [x] Implement protocol detection helpers
- [x] Implement TestMultiProtocolFIDO2ListDevices
  - [x] REST
  - [x] gRPC
  - [x] QUIC
  - [x] MCP
  - [x] Unix
- [x] Implement TestMultiProtocolFIDO2Register
  - [x] REST
  - [x] gRPC
  - [x] QUIC
  - [x] MCP
  - [x] Unix
- [x] Implement TestMultiProtocolFIDO2Info
  - [x] REST
  - [x] gRPC
  - [x] QUIC
  - [x] MCP
  - [x] Unix
- [x] Implement TestMultiProtocolFIDO2FullWorkflow
- [x] Implement TestMultiProtocolFIDO2Consistency
- [x] Implement TestMultiProtocolFIDO2WaitDevice
- [x] Implement TestMultiProtocolFIDO2AuthenticateWithBase64AndHex

### test/integration/fido2/webauthn_server_test.go
- [x] Create file with build tags
- [x] Implement TestWebAuthnServerRegistrationFlow
  - [x] Begin registration
  - [x] Complete registration
  - [x] Verify credential stored
- [x] Implement TestWebAuthnServerAuthenticationFlow
  - [x] Begin authentication
  - [x] Complete authentication
  - [x] Verify assertion validated
- [x] Implement TestWebAuthnServerSessionManagement
- [x] Implement TestWebAuthnServerConcurrentSessions
- [x] Implement TestWebAuthnServerErrorHandling

---

## Phase 5: Command Definitions

### test/integration/api/commands/commands.go
- [x] Add CategoryFIDO2 constant
- [x] Add fido2-list-devices command
- [x] Add fido2-wait-device command
- [x] Add fido2-register command
- [x] Add fido2-authenticate command
- [x] Add fido2-info command
- [x] Add FIDO2Commands() function

---

## Phase 6: Makefile Targets

### Makefile
- [x] Add integration-test-canokey target
- [x] Add integration-test-fido2 target
- [x] Add integration-test-fido2-cli target
- [x] Add integration-test-fido2-webauthn target
- [x] Add integration-test-fido2-multiprotocol target
- [x] Add coverage-fido2 target
- [x] Update integration-test target (includes canokey and fido2)

---

## Phase 7: Validation

### Devcontainer Configuration
- [x] CanoKey QEMU starts automatically (no profile required)
- [x] OpenSC PKCS#11 library installed and accessible
- [x] libfido2 and fido2-tools installed
- [x] Environment variables configured for tests
- [x] Shared volume for CanoKey socket

### Test Execution (in devcontainer)
Tests SKIP (not fail) when hardware is not available.

**Test Status**:
- [ ] CanoKey PKCS#11 tests - require physical CanoKey hardware via USB
- [ ] FIDO2 tests - require physical FIDO2 authenticator (or tests inside QEMU VM with CanoKey)

**Hardware Requirements**:
- **CanoKey PKCS#11 tests** require physical CanoKey hardware connected via USB
- Tests will SKIP with a clear message when no hardware is detected
- CanoKey tests are NOT included in the default `make integration-test` target

**CanoKey QEMU** provides virtual FIDO2/USB device emulation **inside QEMU VMs** (via `-device canokey,file=...`). The CanoKey QEMU binary (`qemu-system-x86_64-canokey`) is useful for:
- Running VMs with virtual FIDO2 devices for integration testing
- Testing LUKS unlock with FIDO2 inside VMs
- Note: CanoKey QEMU creates devices inside VMs, not accessible from the host container

For **PKCS#11 testing without hardware**, use:
- **SoftHSM** - `make integration-test-pkcs11` (general PKCS#11 testing)

For **CanoKey-specific testing**:
- Connect physical CanoKey via USB
- Run `make integration-test-canokey`

### Code Coverage
- [ ] CanoKey PKCS#11 tests: 90%+
- [ ] FIDO2 core tests: 90%+
- [ ] FIDO2 CLI tests: 90%+
- [ ] WebAuthn tests: 90%+

### Documentation
- [x] All docs reviewed for accuracy
- [x] Examples tested and working
- [x] API documentation complete

---

## Notes

### Blockers
- None currently

### Decisions Made
- CanoKey tests SKIP (not fail) when hardware is not available
- CanoKey PKCS#11 tests require physical CanoKey hardware
- CanoKey QEMU provides FIDO2 emulation inside VMs only (not accessible from host container)
- Using OpenSC PKCS#11 library for CanoKey PIV operations
- CanoKey tests are NOT included in default `make integration-test` target (run separately)
- Environment variables pre-configured for test discovery
- ALL integration tests run in devcontainer via `run_in_devcontainer` Makefile helper
- For PKCS#11 testing without hardware, use SoftHSM (`make integration-test-pkcs11`)

### Open Questions
- None currently

---

## Progress Summary

| Phase | Status | Completion |
|-------|--------|------------|
| Documentation | Complete | 100% |
| Devcontainer Updates | Complete | 100% |
| CanoKey PKCS#11 Tests | Complete | 100% |
| FIDO2 Tests | Complete | 100% |
| Command Definitions | Complete | 100% |
| Makefile Targets | Complete | 100% |
| Validation | Hardware Required | N/A |

**Overall Progress: 100% (code complete)**

**Note**: CanoKey tests require physical hardware and are NOT included in the default `make integration-test` target. Run `make integration-test-canokey` separately when hardware is connected. Tests will SKIP with a clear message when no hardware is detected.

### Remaining Work
- Connect physical CanoKey hardware for testing
- Run `make integration-test-canokey` to verify tests pass
- Verify code coverage meets 90%+ targets
- CI/CD pipeline integration

### Makefile run_in_devcontainer Pattern
All integration test targets now use the `run_in_devcontainer` helper which:
- Automatically starts devcontainer if not already running
- Runs tests inside devcontainer with proper environment
- Works transparently when already inside devcontainer

Updated targets:
- integration-test-software
- integration-test-symmetric
- integration-test-webauthn
- integration-test-signing
- integration-test-opaque
- integration-test-metrics
- integration-test-health
- integration-test-ratelimit
- integration-test-crypto-rand
- integration-test-rand-hardware
- integration-test-crypto-wrapping
- integration-test-cli-local
- integration-test-canokey
- integration-test-fido2 (and variants)

---

Last Updated: 2025-12-26
