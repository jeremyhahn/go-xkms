# CanoKey Integration Implementation Plan

## Overview

This document outlines the implementation plan for adding comprehensive CanoKey PKCS#11 and FIDO2 integration tests to go-keychain.

## Goals

1. Add CanoKey PKCS#11 integration tests in `test/integration/pkcs11/`
2. Create new `test/integration/fido2/` directory with comprehensive tests
3. Test all FIDO2 CLI commands across all server protocols (REST, gRPC, QUIC, MCP, Unix)
4. Integrate CanoKey QEMU into the existing devcontainer
5. Add server-side WebAuthn ceremony tests

## Phase 1: Devcontainer Updates

### 1.1 Add CanoKey QEMU Service

**File:** `.devcontainer/docker-compose.yml`

Add new service:
```yaml
canokey-qemu:
  build:
    context: .
    dockerfile: Dockerfile.canokey
  container_name: keychain-dev-canokey
  privileged: true
  volumes:
    - canokey-state:/var/lib/canokey
  ports:
    - "5555:5555"  # QEMU monitor
  healthcheck:
    test: ["CMD", "pgrep", "qemu-system"]
    interval: 5s
    timeout: 5s
    retries: 3
```

### 1.2 Update Dockerfile

**File:** `.devcontainer/Dockerfile`

Ensure CanoKey QEMU is built:
```dockerfile
# Build CanoKey QEMU (already cloned to /opt/canokey-qemu)
WORKDIR /opt/canokey-qemu
RUN cmake -B build && cmake --build build
```

### 1.3 Update VS Code Settings

**File:** `.devcontainer/devcontainer.json`

Add build tags:
```json
"go.buildTags": "integration,frost,pkcs11,canokey,fido2,webauthn"
```

### 1.4 Update Post-Create Script

**File:** `.devcontainer/scripts/post-create.sh`

Add CanoKey initialization:
```bash
# Initialize CanoKey QEMU if not already done
if [ ! -f /var/lib/canokey/initialized ]; then
    /opt/canokey-qemu/scripts/init-device.sh
    touch /var/lib/canokey/initialized
fi
```

## Phase 2: CanoKey PKCS#11 Integration Tests

### 2.1 Create Test File

**File:** `test/integration/pkcs11/pkcs11_canokey_integration_test.go`

Build tags: `//go:build integration && canokey && pkcs11`

### 2.2 Test Structure

```go
func TestCanoKeyPKCS11Integration(t *testing.T) {
    t.Run("DeviceDetection", testDeviceDetection)
    t.Run("KeyGeneration", func(t *testing.T) {
        t.Run("RSA-2048", testRSA2048)
        t.Run("RSA-4096", testRSA4096)
        t.Run("ECDSA-P256", testECDSAP256)
        t.Run("ECDSA-P384", testECDSAP384)
        t.Run("Ed25519", testEd25519)  // Firmware 3.0+
    })
    t.Run("Signing", func(t *testing.T) {
        t.Run("RSA-PKCS1v15", testRSAPKCS1v15)
        t.Run("RSA-PSS", testRSAPSS)
        t.Run("ECDSA", testECDSA)
    })
    t.Run("PIVSlots", testPIVSlots)
    t.Run("Certificates", testCertificates)
    t.Run("SymmetricOps", testSymmetricOps)
    t.Run("RNG", testHardwareRNG)
}
```

### 2.3 Test Patterns

Follow existing YubiKey/Nitrokey patterns:
- Environment variable configuration
- Device discovery via PKCS#11
- Graceful skip when device unavailable
- Cleanup of generated keys

## Phase 3: FIDO2 Integration Tests

### 3.1 Directory Structure

```
test/integration/fido2/
├── doc.go                      # Package documentation
├── testutil.go                 # Test utilities
├── fido2_integration_test.go   # Core FIDO2 tests
├── cli_test.go                 # CLI command tests
├── cli_multiprotocol_test.go   # Multi-protocol CLI tests
└── webauthn_server_test.go     # WebAuthn server tests
```

### 3.2 Core FIDO2 Tests

**File:** `test/integration/fido2/fido2_integration_test.go`

```go
func TestFIDO2Integration(t *testing.T) {
    t.Run("ListDevices", testListDevices)
    t.Run("DeviceInfo", testDeviceInfo)
    t.Run("WaitDevice", testWaitDevice)
    t.Run("RegisterCredential", testRegisterCredential)
    t.Run("Authenticate", testAuthenticate)
    t.Run("HMACSecret", testHMACSecret)
    t.Run("UserVerification", testUserVerification)
    t.Run("MultipleCredentials", testMultipleCredentials)
    t.Run("ErrorHandling", testErrorHandling)
}
```

### 3.3 CLI Command Tests

**File:** `test/integration/fido2/cli_test.go`

Test all 5 CLI commands:
1. `fido2 list-devices`
2. `fido2 wait-device`
3. `fido2 register <username>`
4. `fido2 authenticate`
5. `fido2 info`

### 3.4 Multi-Protocol Tests

**File:** `test/integration/fido2/cli_multiprotocol_test.go`

Test each command across all protocols:
- REST (HTTPS)
- gRPC
- QUIC (HTTP/3)
- MCP (JSON-RPC 2.0)
- Unix Socket

Pattern:
```go
func TestFIDO2_MultiProtocol_Register(t *testing.T) {
    protocols := []ProtocolType{
        ProtocolREST, ProtocolGRPC, ProtocolQUIC,
        ProtocolMCP, ProtocolUnix,
    }
    for _, proto := range protocols {
        t.Run(string(proto), func(t *testing.T) {
            // Test register via this protocol
        })
    }
}
```

### 3.5 WebAuthn Server Tests

**File:** `test/integration/fido2/webauthn_server_test.go`

Test server-side ceremonies:
- Registration: Begin → Complete
- Authentication: Begin → Complete
- Credential storage and retrieval
- Multi-user scenarios
- Cross-protocol workflows

## Phase 4: FIDO2 Command Definitions

### 4.1 Add Commands

**File:** `test/integration/api/commands/commands.go`

Add FIDO2 category and commands:
```go
const CategoryFIDO2 CommandCategory = "fido2"

var FIDO2Commands = []CommandDefinition{
    {
        Name:     "fido2-list-devices",
        Category: CategoryFIDO2,
        Command:  []string{"fido2", "list-devices"},
    },
    {
        Name:     "fido2-wait-device",
        Category: CategoryFIDO2,
        Command:  []string{"fido2", "wait-device"},
        OptionalArgs: []ArgDefinition{
            {Name: "--timeout", Default: "60s"},
        },
    },
    {
        Name:     "fido2-register",
        Category: CategoryFIDO2,
        Command:  []string{"fido2", "register"},
        RequiredArgs: []ArgDefinition{
            {Name: "username"},
        },
        OptionalArgs: []ArgDefinition{
            {Name: "--rp-id"},
            {Name: "--rp-name"},
            {Name: "--user-verification"},
        },
    },
    {
        Name:     "fido2-authenticate",
        Category: CategoryFIDO2,
        Command:  []string{"fido2", "authenticate"},
        RequiredArgs: []ArgDefinition{
            {Name: "--credential-id"},
            {Name: "--salt"},
        },
    },
    {
        Name:     "fido2-info",
        Category: CategoryFIDO2,
        Command:  []string{"fido2", "info"},
    },
}
```

## Phase 5: Makefile Targets

### 5.1 Add Targets

**File:** `Makefile`

```makefile
# CanoKey PKCS#11 tests
.PHONY: integration-test-canokey
integration-test-canokey:
	go test -v -tags="integration,canokey,pkcs11" ./test/integration/pkcs11/...

# FIDO2 tests
.PHONY: integration-test-fido2
integration-test-fido2:
	go test -v -tags="integration,fido2" ./test/integration/fido2/...

.PHONY: integration-test-fido2-cli
integration-test-fido2-cli:
	go test -v -tags="integration,fido2" -run "CLI" ./test/integration/fido2/...

.PHONY: integration-test-fido2-webauthn
integration-test-fido2-webauthn:
	go test -v -tags="integration,fido2,webauthn" ./test/integration/fido2/...

.PHONY: integration-test-fido2-multiprotocol
integration-test-fido2-multiprotocol:
	go test -v -tags="integration,fido2" -run "MultiProtocol" ./test/integration/fido2/...

# Coverage
.PHONY: coverage-fido2
coverage-fido2:
	go test -v -tags="integration,fido2" -coverprofile=coverage-fido2.out ./test/integration/fido2/...
	go tool cover -html=coverage-fido2.out -o coverage-fido2.html
```

## Implementation Timeline

| Phase | Description | Files |
|-------|-------------|-------|
| 1 | Devcontainer Updates | docker-compose.yml, Dockerfile, devcontainer.json |
| 2 | CanoKey PKCS#11 Tests | pkcs11_canokey_integration_test.go |
| 3 | FIDO2 Test Directory | fido2/*.go (6 files) |
| 4 | Command Definitions | commands/commands.go |
| 5 | Makefile Targets | Makefile |

## Success Criteria

1. CanoKey QEMU starts successfully in devcontainer
2. All PKCS#11 tests pass with CanoKey QEMU
3. All 5 FIDO2 CLI commands tested
4. Each FIDO2 command works on all 5 protocols
5. WebAuthn ceremonies complete successfully
6. 90%+ code coverage on new test code
7. All tests run in CI/CD without physical hardware

## Dependencies

Already available in devcontainer:
- CanoKey QEMU sources at `/opt/canokey-qemu`
- QEMU packages (qemu-system-x86, qemu-utils)
- OpenSC PKCS#11 library
- libfido2 (to be verified)

May need to add:
- libfido2-dev if not present
- Additional QEMU configuration

## Risks and Mitigations

| Risk | Mitigation |
|------|------------|
| CanoKey QEMU build fails | Pre-build in Dockerfile, verify in CI |
| FIDO2 HID not accessible in container | Use privileged mode, USB passthrough |
| Protocol differences | Protocol parity tests catch inconsistencies |
| Flaky tests | Proper timeouts, retry logic |
