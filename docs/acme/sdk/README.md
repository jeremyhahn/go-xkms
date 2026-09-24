# Trusted CA Go SDK

Official Go SDK for the Trusted CA ACME RFC-8555 compliant Certificate Authority. Provides programmatic access to ACME and Admin operations over multiple transport protocols.

## Installation

```bash
go get github.com/jeremyhahn/go-xkms/sdk/go
```

## Quick Start

### ACME Operations

```go
package main

import (
    "context"
    "log"

    trustedca "github.com/jeremyhahn/go-xkms/sdk/go"
)

func main() {
    client, err := trustedca.NewClient("/var/run/trusted-ca.sock",
        trustedca.WithUnix("/var/run/trusted-ca.sock"))
    if err != nil {
        log.Fatal(err)
    }
    defer client.Close()

    ctx := context.Background()

    // Get ACME directory
    dir, err := client.Directory().Get(ctx, &trustedca.GetDirectoryRequest{})
    if err != nil {
        log.Fatal(err)
    }
    log.Printf("Directory: %+v", dir.Directory)

    // Create account
    account, err := client.Account().Create(ctx, &trustedca.CreateAccountRequest{
        Contact:              []string{"mailto:admin@example.com"},
        TermsOfServiceAgreed: true,
    })
    if err != nil {
        log.Fatal(err)
    }
    log.Printf("Account ID: %s", account.Account.ID)
}
```

### Admin Operations

```go
package main

import (
    "context"
    "log"

    trustedca "github.com/jeremyhahn/go-xkms/sdk/go"
    "github.com/jeremyhahn/go-xkms/sdk/go/client/admin"
)

func main() {
    client, err := admin.NewClient("localhost:9443",
        trustedca.WithTLS(trustedca.TLSConfig{
            CertFile: "admin.crt",
            KeyFile:  "admin.key",
            CAFile:   "ca.crt",
        }),
    )
    if err != nil {
        log.Fatal(err)
    }
    defer client.Close()

    ctx := context.Background()

    // Get CA status
    status, err := client.Status().Get(ctx)
    if err != nil {
        log.Fatal(err)
    }
    log.Printf("CA Status: %+v", status)

    // List certificates
    certs, err := client.Certificate().List(ctx, &admin.ListCertificatesRequest{
        Page:    1,
        PerPage: 20,
        Status:  "valid",
    })
    if err != nil {
        log.Fatal(err)
    }
    log.Printf("Certificates: %d", len(certs.Certificates))
}
```

## Transport Options

| Protocol | Constructor | Use Case |
|----------|-------------|----------|
| Unix Socket | `NewClient("/var/run/trusted-ca.sock", WithUnix("/var/run/trusted-ca.sock"))` | Local IPC (fastest) |
| REST | `NewClient("https://host:8443", WithREST())` | Web clients, external systems |
| QUIC | `NewClient("host:9444", WithQUIC())` | Low-latency, mobile clients |
| MCP | `NewClient("host:9445", WithMCP())` | AI/LLM integration |
| Embedded | `NewClient("", WithEmbedded(svc))` | Testing, in-process scenarios |

gRPC is not a transport option for this client: RFC 8555 defines ACME as
HTTP+JWS, so there is no gRPC binding for the protocol, and `NewClient`
refuses gRPC (the zero-value default) with a typed `Unimplemented` error at
construction (go-xkms#727). Always pass one of the options above.

## Configuration via Functional Options

```go
client, err := trustedca.NewClient("acme.example.com:443",
    trustedca.WithTLS(trustedca.TLSConfig{
        CertFile:   "client.crt",
        KeyFile:    "client.key",
        CAFile:     "ca.crt",
        ServerName: "acme.example.com",
    }),
    trustedca.WithTimeout(30*time.Second),
    trustedca.WithKeepalive(10*time.Second, 5*time.Second),
    trustedca.WithRetry(3, 100*time.Millisecond),
    trustedca.WithMaxRetryBackoff(30*time.Second),
    trustedca.WithConnectionPool(10, 100),
    trustedca.WithLogger(slog.Default()),
)
```

## Error Handling

The SDK provides typed errors for programmatic handling:

```go
import "github.com/jeremyhahn/go-xkms/sdk/go/errors"

account, err := client.Account().Create(ctx, req)
if err != nil {
    if errors.IsACMEBadNonce(err) {
        // Retry with fresh nonce
    }
    if errors.IsACMERateLimited(err) {
        // Back off and retry later
    }
    if errors.IsRetryable(err) {
        // General retryable error
    }

    var tcErr *errors.TrustedCAError
    if errors.As(err, &tcErr) {
        log.Printf("Op: %s, Code: %s, Msg: %s",
            tcErr.Op, tcErr.Code, tcErr.Message)
    }
}
```

## Service Clients

### ACME Services

| Service | Method | Description |
|---------|--------|-------------|
| `Account()` | Create, Get, Update, Deactivate, KeyChange | ACME account lifecycle |
| `Order()` | Create, Get, List, Finalize | Certificate order management |
| `Authorization()` | Get, Deactivate | Domain authorization |
| `Challenge()` | Get, Respond | Challenge verification |
| `Certificate()` | Get, Revoke | Certificate issuance and revocation |
| `Directory()` | Get | ACME directory resource |
| `Nonce()` | Get | Replay protection nonces |

### Challenge Responders

Both halves of a challenge are exported, so a consumer that imports only
`sdk/go` can run an ACME client as well as talk to an ACME server.

| Symbol | Half | Description |
|--------|------|-------------|
| `NewHTTP01Responder(HTTP01ResponderConfig)` | client | Binds a listener and serves the key authorization at the well-known http-01 path. Returns a typed error if the bind fails. |
| `HTTP01Responder` | client | The bound responder: `Addr`, `KeyAuth`, `Done`, `Err`, `Shutdown(ctx)`, `Close`. |
| `ACMEVerifyHTTP01` | server | Fetches the key authorization from a client under validation. |
| `ACMEComputeDNS01ChallengeValue` | client | Computes the dns-01 TXT record value. |
| `ACMEVerifyDNS01` | server | Resolves and checks the dns-01 TXT record. |

```go
responder, err := trustedca.NewHTTP01Responder(trustedca.HTTP01ResponderConfig{
    Addr:    "80",
    KeyAuth: keyAuth,
})
if err != nil {
    return err
}
defer func() { _ = responder.Close() }()
```

The bind is eager, so a nil error means the responder is already serving and
the order may be accepted at once. Each responder owns its own listener, so
concurrent orders are safe. See
[`docs/acme/challenges.md`](../challenges.md#http-01-challenge) for the full
contract.

### Admin Services

| Service | Method | Description |
|---------|--------|-------------|
| `Status()` | Get | CA status and health |
| `Stats()` | Get | CA statistics and metrics |
| `Certificate()` | List, Get, Revoke | Certificate management |
| `Account()` | List, Get, Disable | ACME account management |
| `Tenant()` | Create, Get, Update, Delete, List | Multi-tenant management |
| `EAB()` | Create, Get, Delete, List | External Account Bindings |
| `Role()` | Create, Get, Update, Delete, List | RBAC role management |
| `User()` | Create, Get, Update, Delete, List | User management |

## Development

```bash
cd sdk/go

# Run unit tests
make test

# Generate coverage report
make coverage

# Run benchmarks
make bench

# Run integration tests (requires running server)
make integration-test
```

Or from the project root:

```bash
make test-sdk
make coverage-sdk
make bench-sdk
```
