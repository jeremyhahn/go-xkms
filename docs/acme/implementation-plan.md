# cactl CLI Binary & Documentation Update

## Status

| Phase | Status | Progress |
|-------|--------|----------|
| Phase 1: Create cactl Binary | Complete | 100% |
| Phase 2: Update Documentation | Complete | 100% |
| Phase 3: Verify ACME Binaries | Complete | 100% |

---

## Overview

Create a new `cactl` CLI binary for CA administration operations supporting all protocols (Unix IPC, REST, gRPC, QUIC, MCP), following go-qrdb patterns. Update documentation to reflect current state.

---

## Current State

### Binaries
| Binary | Purpose | Protocol | Status |
|--------|---------|----------|--------|
| `trusted-acme-server` | ACME server + Admin API | REST (ACME), Multi-protocol (Admin) | Exists |
| `trusted-acme-client` | ACME client operations | REST only | Exists |
| `cactl` | CA administration CLI | All (Unix, REST, gRPC, QUIC, MCP) | **Complete** |

---

## Phase 1: Create cactl Binary - COMPLETE

### Directory Structure (Implemented)
```
cmd/cactl/
+-- main.go              # Root command, global flags, Cobra setup
+-- main_test.go         # Unit tests for main.go
+-- version.go           # Version command
+-- version_test.go      # Unit tests for version.go
+-- status.go            # Status/health commands
+-- certificates.go      # Certificate operations
+-- accounts.go          # Account operations
+-- tenants.go           # Tenant CRUD, EAB, Policy subcommands
+-- client.go            # AdminClient interface + factory
+-- client_test.go       # Unit tests for client.go
+-- output.go            # Output formatting (json/yaml/table)
+-- output_test.go       # Unit tests for output.go
+-- config.go            # Configuration handling
+-- config_test.go       # Unit tests for config.go
+-- commands_test.go     # Command configuration tests
```

### Global Flags (Implemented)
```go
var (
    cfgFile    string        // --config (-c)
    address    string        // --address (-a) (default: /run/trusted-ca-grpc.sock)
    transport  string        // --transport (-t) unix|rest|grpc|quic|mcp (default: unix)
    timeout    time.Duration // --timeout (default: 30s)
    tlsCert    string        // --tls-cert
    tlsKey     string        // --tls-key
    tlsCA      string        // --tls-ca
    authToken  string        // --token (for REST/gRPC auth)
    output     string        // --output (-o) json|yaml|table (default: table)
    logLevel   string        // --log-level (debug|info|warn|error, default: info)
)
```

### Command Groups (Implemented)

```
cactl
+-- status              # Get CA status
+-- stats               # Get CA statistics
|
+-- cert                # Certificate operations
|   +-- list           # List certificates
|   +-- get            # Get certificate by serial
|   +-- revoke         # Revoke certificate
|
+-- account             # Account operations
|   +-- list           # List ACME accounts
|   +-- get            # Get account by ID
|   +-- disable        # Disable account
|
+-- tenant              # Tenant operations (super-admin)
|   +-- create         # Create tenant
|   +-- get            # Get tenant
|   +-- update         # Update tenant
|   +-- delete         # Delete tenant
|   +-- list           # List tenants
|   +-- eab            # EAB for tenant
|   |   +-- create
|   |   +-- get
|   |   +-- delete
|   |   +-- list
|   +-- policy         # Policy for tenant
|       +-- create
|       +-- get
|       +-- update
|       +-- delete
|       +-- list
|
+-- version             # Show version
```

### Implementation Checklist - Phase 1
- [x] Create `cmd/cactl/main.go` with Cobra root command
- [x] Create `cmd/cactl/config.go` for configuration handling
- [x] Create `cmd/cactl/client.go` with client factory
- [x] Create `cmd/cactl/output.go` for formatting
- [x] Create `cmd/cactl/version.go`
- [x] Create `cmd/cactl/status.go`
- [x] Create `cmd/cactl/certificates.go`
- [x] Create `cmd/cactl/accounts.go`
- [x] Create `cmd/cactl/tenants.go` (includes EAB and Policy subcommands)
- [x] Update Makefile for cactl build
- [x] Write unit tests for testable code (config, output, client, main, version, command configs)

### Test Coverage Notes
- **Unit test coverage**: ~52% of statements
- Functions at 100% coverage: config.go, output.go, client.go, main.go validation functions, version.go
- Functions requiring integration tests: run* command handlers (runStatus, runStats, runCertList, etc.)
- Per CLAUDE.md: Integration tests should test the run* functions with real servers

### Build Commands
```bash
# Build cactl
make build-cactl

# Build all binaries
make build

# Install to ~/.local/bin
make install
```

---

## Phase 2: Update Documentation - COMPLETE

### New Documentation Files

| File | Purpose | Status |
|------|---------|--------|
| `docs/cli/README.md` | CLI overview | **Complete** |
| `docs/cli/cactl.md` | cactl command reference | **Complete** |
| `docs/protocols/README.md` | Protocol overview | **Complete** |
| `docs/protocols/unix-socket.md` | Unix socket protocol | **Complete** |

### Update Existing Files

| File | Update | Status |
|------|--------|--------|
| `docs/README.md` | Add CLI and protocol sections | **Complete** |

---

## Phase 3: Verify ACME Binaries - COMPLETE

Both ACME binaries verified and up-to-date:

- [x] `cmd/trusted-acme-server/main.go` - Multi-protocol Admin API flags correct
  - Supports: REST, gRPC, QUIC, MCP, Unix socket
  - Proper rate limiting, metrics, Swagger UI
  - Graceful shutdown handling

- [x] `cmd/trusted-acme-client/main.go` - Full-featured ACME client
  - Subcommands: register, request, renew, revoke, service, device-enroll, device-attest
  - Uses go-objstore for storage (not direct file operations)
  - Supports http-01, dns-01 challenges
  - Auto-renewal service mode

---

## Verification

1. **Build**: `make build` includes cactl binary - **WORKING**
2. **Unit tests**: Run with `go test -tags=grpc ./cmd/cactl/...` - **PASSING**
3. **Integration tests**: Multi-protocol adapter tests (in Docker)
4. **Manual testing**:
   ```bash
   # Unix socket (default)
   cactl status
   cactl cert list

   # REST
   cactl --transport rest --address https://localhost:8443 status

   # gRPC
   cactl --transport grpc --address localhost:9443 cert list
   ```
5. **Documentation**: All docs render correctly, examples work

---

## Implementation Order

1. ~~Create `cmd/cactl/` structure with Cobra~~ **DONE**
2. ~~Implement client factory with all protocols~~ **DONE**
3. ~~Add status/stats commands~~ **DONE**
4. ~~Add certificate commands~~ **DONE**
5. ~~Add account commands~~ **DONE**
6. ~~Add tenant commands with subcommands~~ **DONE**
7. ~~Add output formatting (json/yaml/table)~~ **DONE**
8. ~~Write unit tests~~ **DONE**
9. ~~Update Makefile for cactl build~~ **DONE**
10. Create CLI documentation
11. Create protocol documentation
12. Update README and quickstart
