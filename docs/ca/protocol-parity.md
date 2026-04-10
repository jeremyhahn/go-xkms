# CA Protocol Parity

All Certificate Authority operations in go-xkms are available through every server protocol. This document describes the full-stack CA wiring across REST, gRPC, QUIC, MCP, Unix (gRPC over UDS), and Embedded transports.

## Overview

The CA subsystem exposes 11 operations (7 standard + 4 TCG) through 6 server protocols. Every protocol converges at the `XKMSService` layer, which delegates to the underlying `ca.XKMSCA` (or `ca.TCGCA`) instance via duck-typed interfaces. This architecture guarantees identical behavior regardless of transport.

## Architecture

```
CLI (xkmsctl)                      SDK Client
     |                                  |
     v                                  v
+----------+  +------+  +------+  +---------+  +------+  +----------+
|   REST   |  | gRPC |  | QUIC |  |   MCP   |  | Unix |  | Embedded |
| (chi/h2) |  | (h2) |  | (h3) |  |(JSON-RPC)|  |(UDS) |  | (direct) |
+----+-----+  +--+---+  +--+---+  +----+----+  +--+---+  +----+-----+
     |           |          |           |          |            |
     |           |          |           |          |            |
     +-----------+----------+-----------+----------+------------+
                            |
                    +-------v--------+
                    |  XKMSService   |
                    | (pkg/xkms)     |
                    +-------+--------+
                            |
                    +-------v--------+
                    |   ca.XKMSCA    |
                    |   ca.TCGCA     |
                    +-------+--------+
                            |
                +-----------+-----------+
                |                       |
        +-------v-------+      +-------v-------+
        |   KeyStore    |      |   CertStore   |
        +---------------+      +---------------+
```

All six transports converge at `XKMSService`. The service layer uses duck-typed interfaces (`caMethodBundle`, `caMethodSignCSRRaw`, etc.) to call into `ca.XKMSCA` without creating an import cycle.

### Wiring Path

1. `pkg/server/server.go` initializes the CA via `initCA()` and stores it as `s.ca`.
2. During `New()`, the server calls `svc.SetCA(s.ca)` on the `XKMSService` singleton.
3. For gRPC, the server additionally calls `grpcinternal.SetCA(s.ca)` for direct CA access.
4. For REST, the `XKMSService` is passed as `restConfig.CA` and cast to `caServicer`.
5. QUIC and MCP handlers call `xkms.Get()` to retrieve the `XKMSService` singleton.
6. Embedded transport calls `XKMSService` methods directly.

## API Endpoints per Protocol

### Standard CA Operations

| Operation         | REST                            | gRPC RPC               | QUIC                            | MCP Method           | Unix     | Embedded               |
|-------------------|---------------------------------|------------------------|---------------------------------|----------------------|----------|------------------------|
| Get CA Bundle     | `GET /api/v1/ca/bundle`         | `GetCABundle`*         | `GET /api/v1/ca/bundle`         | `xkms.ca.bundle`     | via gRPC | `GetCABundle()`        |
| Get CA Cert       | `GET /api/v1/ca/certificate`    | `GetCACertificate`     | `GET /api/v1/ca/certificate`    | `xkms.ca.certificate`| via gRPC | `GetCACertificate()`   |
| Sign CSR          | `POST /api/v1/ca/sign-csr`      | `SignCSR`              | `POST /api/v1/ca/sign-csr`      | `xkms.ca.sign-csr`   | via gRPC | `SignCSR()`            |
| Issue Certificate | `POST /api/v1/ca/issue`         | `IssueCertificate`     | `POST /api/v1/ca/issue`         | `xkms.ca.issue`      | via gRPC | `IssueCertificate()`   |
| Revoke Cert       | `POST /api/v1/ca/revoke`        | `RevokeCertificate`    | `POST /api/v1/ca/revoke`        | `xkms.ca.revoke`     | via gRPC | `RevokeCertificate()`  |
| Generate CRL      | `POST /api/v1/ca/crl`           | `GenerateCRL`          | `POST /api/v1/ca/crl`           | `xkms.ca.crl`        | via gRPC | `GenerateCRL()`        |
| Is Revoked        | `GET /api/v1/ca/revoked/{serial}`| `IsRevoked`           | `GET /api/v1/ca/revoked/{serial}`| `xkms.ca.is-revoked` | via gRPC | `IsRevoked()`          |

*gRPC `GetCABundle` is handled via the CA bundler (`grpcinternal.SetCABundler`), not a distinct RPC. The gRPC proto defines 6 CA RPCs (`GetCACertificate`, `SignCSR`, `IssueCertificate`, `RevokeCertificate`, `GenerateCRL`, `IsRevoked`) in the `KeystoreService`.

### TCG CA Operations

| Operation         | REST                           | gRPC                   | QUIC                           | MCP Method               | Unix     | Embedded               |
|-------------------|--------------------------------|------------------------|--------------------------------|--------------------------|----------|------------------------|
| Issue EK Cert     | `POST /api/v1/ca/tcg/ek`      | via `XKMSService`      | `POST /api/v1/ca/tcg/ek`      | `xkms.ca.tcg.issue-ek`  | via gRPC | `IssueEKCertificate()` |
| Issue AK Cert     | `POST /api/v1/ca/tcg/ak`      | via `XKMSService`      | `POST /api/v1/ca/tcg/ak`      | `xkms.ca.tcg.issue-ak`  | via gRPC | `IssueAKCertificate()` |
| Sign TCG CSR      | `POST /api/v1/ca/tcg/sign-csr`| via `XKMSService`      | `POST /api/v1/ca/tcg/sign-csr`| `xkms.ca.tcg.sign-csr`  | via gRPC | `SignTCGCSR()`         |
| Enroll Device     | `POST /api/v1/ca/tcg/enroll`  | via `XKMSService`      | `POST /api/v1/ca/tcg/enroll`  | `xkms.ca.tcg.enroll`    | via gRPC | `EnrollDevice()`       |

TCG operations use duck-typed raw interfaces (`caMethodIssueEKCertRaw`, `caMethodIssueAKCertRaw`, `caMethodSignTCGCSRRaw`, `caMethodEnrollDeviceRaw`) in `XKMSService` to call into `ca.TCGCA` without importing the `ca` package.

## CA-Backed TLS

The server can auto-issue its own TLS certificates from the embedded CA at startup, eliminating the need for pre-generated certificate files.

### How It Works

1. The server reads the `ca:` configuration block and initializes the CA via `initCA()`.
2. If `tls.enabled: true` and `tls.server_cn` is set, the server calls `ensureTLSServerCert()`.
3. `ensureTLSServerCert()` checks if a TLS certificate already exists for the configured CN. If not, it issues one using the `server` certificate profile.
4. The issued certificate is stored in the backend's cert storage so `ca.TLSCertificate()` can retrieve it.
5. During `Start()`, the server creates a `tlsCABundler` from the CA instance (not a file) and distributes it to REST and gRPC subsystems via `rest.SetCABundler()` and `grpcinternal.SetCABundler()`.

### Bundler Modes

The `tlsCABundler` (in `pkg/server/ca_bundler.go`) implements the `CABundle()` and `CACertificate()` methods expected by all protocol subsystems. It supports two initialization modes:

| Mode             | Trigger                                          | Source                |
|------------------|--------------------------------------------------|-----------------------|
| File-based       | `tls.enabled: true` + `tls.ca_file` is set       | PEM file on disk      |
| CA-instance      | `tls.enabled: true` + `ca:` block + no `ca_file` | Live CA instance      |

The CA-instance mode is preferred for production: the server manages its own PKI with zero external certificate dependencies.

## Server Configuration

### CA-Backed TLS (recommended)

```yaml
server:
  rest_port: 8443
  grpc_port: 50051
  quic_port: 4433

tls:
  enabled: true
  server_cn: "xkms-server.example.com"
  # No cert_file, key_file, or ca_file needed.
  # The CA auto-issues a TLS certificate at startup.

ca:
  identity:
    - subject:
        cn: "Example Root CA"
        organization: "Example Corp"
        country: "US"
      valid: 10
      keys:
        - algorithm: "ECDSA"
          ecc-curve: "P-384"
          hash: "SHA-384"
      keystore-type: "software"
      is-root: true

    - subject:
        cn: "Example Intermediate CA"
        organization: "Example Corp"
        country: "US"
      valid: 5
      keys:
        - algorithm: "ECDSA"
          ecc-curve: "P-256"
          hash: "SHA-256"
      keystore-type: "software"
      is-root: false
      parent-ca: "Example Root CA"

  selected-ca: 1
  default-validity-days: 365
```

### File-Based TLS (legacy)

```yaml
tls:
  enabled: true
  cert_file: /etc/xkms/server.crt
  key_file: /etc/xkms/server.key
  ca_file: /etc/xkms/ca.crt
```

When `ca_file` is set, the bundler reads the PEM from disk instead of querying a live CA instance.

## Service Layer

All CA operations pass through `XKMSService` in `pkg/xkms/servicer_ca.go` (standard) and `pkg/xkms/servicer_ca_tcg.go` (TCG). The service layer:

- Validates request parameters (nil checks, required fields).
- Retrieves the CA instance via `s.getCA()`, returning `ErrNotConfigured` if no CA is wired.
- Type-asserts to the appropriate duck-typed interface for the operation.
- Translates between `sdk/go/transport` request/response types and the CA's raw methods.
- Wraps errors with context (e.g., `"ca: sign csr: %w"`).

This design ensures that protocol handlers never touch `ca.CA` directly, maintaining clean separation of concerns across all six transports.

## Integration Testing

All CA operations are tested across Unix, REST, gRPC, and QUIC using multiprotocol table-driven tests in `test/integration/api/ca_parity_test.go`. Each test iterates over the available CLI protocols, executes the CA command via the `xkmsctl` binary, and asserts consistent behavior:

```go
for _, protocol := range commands.CLIProtocols() {
    t.Run(string(protocol), func(t *testing.T) {
        stdout, stderr, err := runner.RunCommandWithProtocol(t, protocol, "ca", "bundle")
        // Assert PEM certificate data in output
    })
}
```

Tests cover: bundle retrieval, certificate retrieval, CSR signing, certificate issuance, revocation, CRL generation, and revocation status checks. Integration tests run inside the devcontainer against a live `xkmsd` server instance.

## Related Documentation

- [CA Package Documentation](./README.md)
- [Architecture Overview](../architecture/overview.md)
- [API Specifications](../architecture/api-specifications.md)
- [Integration Tests](../testing/integration-tests.md)
