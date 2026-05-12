# Trusted CA Go SDK

Official Go SDK for the Trusted CA ACME RFC-8555 compliant Certificate Authority.

## Installation

```bash
go get github.com/jeremyhahn/go-trusted-ca/sdk/go
```

## Quick Start

```go
package main

import (
    "context"
    "log"

    trustedca "github.com/jeremyhahn/go-trusted-ca/sdk/go"
)

func main() {
    // Create client via Unix socket (recommended for local)
    client, err := trustedca.NewClient("/var/run/trusted-ca.sock")
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
    log.Printf("ACME Directory: %+v", dir.Directory)

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

## Connection Options

### Unix Socket (Recommended for Local)

```go
client, err := trustedca.NewClient("/var/run/trusted-ca.sock")
```

### TCP with mTLS

```go
client, err := trustedca.NewClient("acme.example.com:443",
    trustedca.WithTLS(trustedca.TLSConfig{
        CertFile:   "client.crt",
        KeyFile:    "client.key",
        CAFile:     "ca.crt",
        ServerName: "acme.example.com",
    }),
)
```

### REST Transport

```go
client, err := trustedca.NewClient("https://acme.example.com:8443",
    trustedca.WithREST(),
    trustedca.WithTLS(trustedca.TLSConfig{
        CertFile: "client.crt",
        KeyFile:  "client.key",
        CAFile:   "ca.crt",
    }),
)
```

### QUIC Transport

```go
client, err := trustedca.NewClient("acme.example.com:9444",
    trustedca.WithQUIC(),
    trustedca.WithTLS(trustedca.TLSConfig{
        CertFile: "client.crt",
        KeyFile:  "client.key",
        CAFile:   "ca.crt",
    }),
)
```

### Embedded (In-Process)

```go
// For testing or embedded scenarios
client, err := trustedca.NewClient("embedded://local",
    trustedca.WithEmbedded(acmeService),
)
```

## Available Services

| Service | Description |
|---------|-------------|
| `Account()` | ACME account operations (create, get, update, deactivate, key change) |
| `Order()` | Certificate order operations (create, get, list, finalize) |
| `Authorization()` | Authorization operations (get, deactivate) |
| `Challenge()` | Challenge operations (get, respond) |
| `Certificate()` | Certificate operations (get, revoke) |
| `Directory()` | ACME directory operations |
| `Nonce()` | Nonce generation |

## Configuration Options

```go
client, err := trustedca.NewClient("acme.example.com:443",
    // TLS configuration
    trustedca.WithTLS(trustedca.TLSConfig{
        CertFile:           "client.crt",
        KeyFile:            "client.key",
        CAFile:             "ca.crt",
        ServerName:         "acme.example.com",
        InsecureSkipVerify: false, // Never use in production
    }),

    // Timeouts
    trustedca.WithTimeout(30*time.Second),
    trustedca.WithKeepalive(10*time.Second, 5*time.Second),

    // Retry configuration
    trustedca.WithRetry(3, 100*time.Millisecond),
    trustedca.WithMaxRetryBackoff(30*time.Second),

    // Connection pooling (gRPC only)
    trustedca.WithConnectionPool(10, 100),

    // Logging
    trustedca.WithLogger(slog.Default()),
)
```

## Error Handling

The SDK provides typed errors for programmatic error handling:

```go
import "github.com/jeremyhahn/go-trusted-ca/sdk/go/errors"

account, err := client.Account().Create(ctx, req)
if err != nil {
    // Check for specific ACME errors
    if errors.IsACMEBadNonce(err) {
        // Retry with fresh nonce
    }
    if errors.IsACMERateLimited(err) {
        // Back off and retry later
    }
    if errors.IsRetryable(err) {
        // General retryable error
    }

    // Get error details
    var tcErr *errors.TrustedCAError
    if errors.As(err, &tcErr) {
        log.Printf("Operation: %s, Code: %s, Message: %s",
            tcErr.Op, tcErr.Code, tcErr.Message)
    }
}
```

## Multi-Protocol Support

The SDK supports multiple transport protocols:

| Protocol | Port | Use Case |
|----------|------|----------|
| gRPC | 9443 | High-performance service-to-service |
| REST | 8443 | Web clients, external systems |
| QUIC | 9444 | Low-latency, mobile clients |
| Unix | /run/trusted-ca.sock | Local IPC, CLI |
| MCP | 9445 | AI/LLM integration |
| Embedded | - | Testing, embedded scenarios |

## Development

```bash
# Run unit tests
make test

# Run linter
make lint

# Generate coverage report
make coverage

# Run integration tests
make integration-test

# Run benchmarks
make bench
```

## License

Dual-licensed under AGPL-3.0 and Commercial License.
See [LICENSE](../../LICENSE) for details.
