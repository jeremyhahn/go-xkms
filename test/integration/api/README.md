# Integration Tests

End-to-end integration tests for all go-keychain interfaces.

## Overview

This directory contains comprehensive integration tests that verify the complete functionality of the keychain across all interfaces:

- **REST API** - HTTP/HTTPS endpoints
- **gRPC API** - gRPC service calls
- **CLI** - Command-line interface
- **MCP** - Model Context Protocol (JSON-RPC)

## Test Structure

```
test/integration/api/
├── docker-compose.yml    # Test environment services
├── testutil.go           # Shared test utilities and helpers
├── rest_test.go          # REST API integration tests
├── grpc_test.go          # gRPC API integration tests
├── cli_test.go           # CLI integration tests
├── mcp_test.go           # MCP integration tests
├── e2e_test.go           # Cross-interface end-to-end tests
└── README.md             # This file
```

## Running Tests

### All API Integration Tests

```bash
make integration-test-api
```

This runs the full API integration test suite in Docker with all required services (SoftHSM, SWTPM).

### Individual Test Suites

```bash
# REST API tests only
go test -v -tags=integration ./test/integration/api -run TestREST

# gRPC tests only
go test -v -tags=integration ./test/integration/api -run TestGRPC

# CLI tests only
go test -v -tags=integration ./test/integration/api -run TestCLI

# MCP tests only
go test -v -tags=integration ./test/integration/api -run TestMCP

# Cross-interface E2E tests
go test -v -tags=integration ./test/integration/api -run TestE2E
```

## Test Coverage

### REST API Tests
- Health check endpoint
- List backends
- Get backend info
- Generate key (RSA, ECDSA, Ed25519)
- List keys
- Get key
- Sign data
- Verify signature
- Delete key
- Error handling

### gRPC API Tests
- Health check RPC
- List backends RPC
- Get backend info RPC
- Generate key RPC
- List keys RPC
- Get key RPC
- Sign data RPC
- Verify signature RPC
- Delete key RPC
- Error handling

### CLI Tests
- Version command
- Backend commands (list, info)
- Key generation commands
- List keys command
- Sign data command
- Verify signature command
- Delete key command
- Error handling

### MCP Tests
- JSON-RPC health check
- List backends via MCP
- Generate key via MCP
- Sign/verify via MCP
- Error handling

### E2E Tests
- Create key via REST, use via gRPC
- Create key via CLI, verify via REST
- Cross-interface key operations
- Workflow: Generate → List → Sign → Verify → Delete

## Test Environment

The tests use Docker Compose to set up a complete test environment with:

- **keychain-server** - The keychain server with all protocols enabled
- **swtpm** - TPM 2.0 simulator for TPM backend tests
- **softhsm** - PKCS#11 HSM simulator for HSM backend tests

## Requirements

- Docker and Docker Compose
- Go 1.21+
- `make` for build automation

## Test Configuration

Tests are idempotent and can run in parallel. Each test creates isolated resources using unique identifiers.

Environment variables:
- `KEYSTORE_REST_URL` - REST API base URL (default: http://localhost:8443)
- `KEYSTORE_GRPC_ADDR` - gRPC server address (default: localhost:9443)
- `KEYSTORE_CLI_BIN` - Path to CLI binary (default: build/bin/keychain)
- `KEYSTORE_MCP_ADDR` - MCP server address (default: localhost:9444)
- `INTEGRATION_TIMEOUT` - Test timeout (default: 30s)

## Writing New Tests

When adding new integration tests:

1. Use build tag `//go:build integration`
2. Use shared helpers from `testutil.go`
3. Ensure cleanup with `defer` or `t.Cleanup()`
4. Use unique test identifiers to avoid conflicts
5. Handle service unavailability gracefully
6. Add meaningful error messages

Example:
```go
//go:build integration

func TestNewFeature(t *testing.T) {
    if !isServerAvailable(t) {
        t.Skip("Server not available")
    }

    keyID := fmt.Sprintf("test-key-%d", time.Now().UnixNano())
    defer cleanupKey(t, keyID)

    // Test implementation
}
```

## Troubleshooting

### Server not starting
- Check Docker logs: `docker-compose logs keychain-server`
- Verify port availability: `netstat -tlnp | grep 8443`
- Check TLS certificates are generated

### Tests timing out
- Increase `INTEGRATION_TIMEOUT`
- Check server health: `curl http://localhost:8443/health`
- Verify network connectivity

### Random failures
- Ensure proper cleanup between tests
- Check for port conflicts
- Verify idempotent test design
