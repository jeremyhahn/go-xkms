# Challenge Resolver Framework

Pluggable challenge solver framework with preference ordering for automated ACME challenge resolution.

## Overview

The Challenge Resolver Framework provides a flexible system for solving ACME challenges. It supports multiple challenge types through a pluggable solver interface, allows preference ordering to select the best available challenge type, and handles the complete solve/cleanup lifecycle.

## Architecture

```
+------------------------------------------------------------------+
|                     ChallengeResolver                             |
+------------------------------------------------------------------+
|  Preferences: [dns-01, http-01, tls-alpn-01]                     |
+------------------------------------------------------------------+
|  Solvers                                                          |
|    +-- dns-01     → DNSSolver (with DNS providers)               |
|    +-- http-01    → HTTP01Solver (HTTP server)                   |
|    +-- tls-alpn-01 → TLSALPNSolver (TLS server)                  |
+------------------------------------------------------------------+
|  Operations                                                       |
|    +-- SelectChallenge()  → Find best challenge                  |
|    +-- Solve()            → Present challenge response           |
|    +-- Cleanup()          → Remove challenge resources           |
+------------------------------------------------------------------+
```

## Quick Start

### Create Resolver with DNS Solver

```go
import (
    "github.com/jeremyhahn/go-xkms/pkg/acme/client"
    "github.com/jeremyhahn/go-xkms/pkg/acme/challenges/dns-01/providers/cloudflare"
)

// Create DNS provider
provider, _ := cloudflare.NewFromEnv(ctx)

// Create DNS solver
dnsSolver, _ := client.NewDNSSolver(provider,
    client.WithPropagationCheck(2*time.Minute, 10*time.Second),
)

// Create resolver
resolver := client.NewChallengeResolver()
resolver.RegisterSolver(dnsSolver)

// Set challenge preferences
resolver.SetPreferences("dns-01", "http-01")
```

### Solve Authorization

```go
// Get authorization from order
authz, _ := acmeClient.GetAuthorization(ctx, authzURL)

// Compute key authorization
keyAuth, _ := acmeClient.HTTP01ChallengeResponse(token)

// Solve with automatic cleanup
err := resolver.SolveWithCleanup(ctx, authz, keyAuth,
    func(ctx context.Context, challenge *acme.Challenge) error {
        // Accept the challenge with ACME server
        _, err := acmeClient.Accept(ctx, challenge)
        return err
    },
)
```

## ChallengeSolver Interface

All challenge solvers implement the `ChallengeSolver` interface:

```go
type ChallengeSolver interface {
    // Type returns the challenge type (e.g., "http-01", "dns-01")
    Type() string

    // Solve presents the challenge response for the domain
    Solve(ctx context.Context, domain string, challenge *acme.Challenge, keyAuth string) error

    // Cleanup removes resources created during Solve
    Cleanup(ctx context.Context, domain string, challenge *acme.Challenge) error
}
```

## DNS-01 Solver

The DNS solver provisions TXT records for dns-01 challenges.

### Configuration Options

```go
// Create solver with options
solver, err := client.NewDNSSolver(provider,
    // Wait 30 seconds for DNS propagation
    client.WithPropagationWait(30*time.Second),

    // Enable propagation verification
    client.WithPropagationCheck(2*time.Minute, 10*time.Second),

    // Use custom nameservers for verification
    client.WithNameservers([]string{"8.8.8.8:53", "1.1.1.1:53"}),

    // Set DNS record TTL
    client.WithRecordTTL(60),
)
```

### Available Options

| Option | Description |
|--------|-------------|
| `WithPropagationWait(d)` | Wait duration after presenting record |
| `WithPropagationCheck(timeout, interval)` | Enable DNS propagation verification |
| `WithNameservers(ns)` | Custom nameservers for propagation check |
| `WithRecordTTL(ttl)` | TTL for created DNS records |

### Provider Integration

The DNS solver works with any DNS provider implementing the `providers.Provider` interface:

```go
// Cloudflare
provider, _ := cloudflare.NewFromEnv(ctx)

// Route53
provider, _ := route53.NewFromEnv(ctx)

// Azure DNS
provider, _ := azure.NewFromEnv(ctx)

// Google Cloud DNS
provider, _ := clouddns.NewFromEnv(ctx)

// Create solver with provider
solver, _ := client.NewDNSSolver(provider)
```

## ChallengeResolver

The resolver manages multiple solvers and selects the best one for each authorization.

### Creating a Resolver

```go
// Create with default preferences (dns-01, http-01, tls-alpn-01)
resolver := client.NewChallengeResolver()
```

### Registering Solvers

```go
// Register solver (replaces existing)
err := resolver.RegisterSolver(dnsSolver)

// Register solver (error if exists)
err := resolver.RegisterSolverStrict(httpSolver)

// Unregister solver
removed := resolver.UnregisterSolver("http-01")
```

### Setting Preferences

```go
// Set challenge type order preference
resolver.SetPreferences("dns-01", "http-01", "tls-alpn-01")

// Get current preferences
prefs := resolver.GetPreferences()
```

### Selecting Challenges

```go
// Select best challenge from authorization
challenge, solver, err := resolver.SelectChallenge(authz)
if err != nil {
    // No supported challenge found
}

fmt.Printf("Selected: %s\n", challenge.Type)
```

### Solving Challenges

```go
// Basic solve (returns challenge for further processing)
challenge, err := resolver.Solve(ctx, authz, keyAuth)
if err != nil {
    log.Fatal(err)
}

// Accept challenge with ACME server
acmeClient.Accept(ctx, challenge)

// Manual cleanup
resolver.Cleanup(ctx, domain, challenge)
```

### Solve with Automatic Cleanup

```go
// Solve with guaranteed cleanup
err := resolver.SolveWithCleanup(ctx, authz, keyAuth,
    func(ctx context.Context, challenge *acme.Challenge) error {
        // This runs after Solve() succeeds
        // Cleanup runs automatically when this returns (success or failure)
        _, err := acmeClient.Accept(ctx, challenge)
        if err != nil {
            return err
        }

        // Wait for validation
        _, err = acmeClient.WaitAuthorization(ctx, authz.URI)
        return err
    },
)
```

### Checking Solver Availability

```go
// Check if solver exists
if resolver.HasSolver("dns-01") {
    fmt.Println("DNS-01 solver available")
}

// Get specific solver
solver, exists := resolver.GetSolver("dns-01")

// List all registered solvers
solverTypes := resolver.ListSolvers()

// Count registered solvers
count := resolver.SolverCount()
```

### Lifecycle Management

```go
// Close resolver (releases resources)
resolver.Close()

// Check if closed
if resolver.IsClosed() {
    fmt.Println("Resolver has been closed")
}
```

## Implementing Custom Solvers

### HTTP-01 Solver Example

```go
type HTTP01Solver struct {
    server   *http.Server
    tokens   map[string]string
    tokensMu sync.RWMutex
}

func NewHTTP01Solver(listenAddr string) *HTTP01Solver {
    s := &HTTP01Solver{
        tokens: make(map[string]string),
    }

    s.server = &http.Server{
        Addr:    listenAddr,
        Handler: s,
    }

    go s.server.ListenAndServe()
    return s
}

func (s *HTTP01Solver) Type() string {
    return "http-01"
}

func (s *HTTP01Solver) Solve(ctx context.Context, domain string, challenge *acme.Challenge, keyAuth string) error {
    s.tokensMu.Lock()
    s.tokens[challenge.Token] = keyAuth
    s.tokensMu.Unlock()
    return nil
}

func (s *HTTP01Solver) Cleanup(ctx context.Context, domain string, challenge *acme.Challenge) error {
    s.tokensMu.Lock()
    delete(s.tokens, challenge.Token)
    s.tokensMu.Unlock()
    return nil
}

func (s *HTTP01Solver) ServeHTTP(w http.ResponseWriter, r *http.Request) {
    // Handle /.well-known/acme-challenge/{token}
    token := path.Base(r.URL.Path)

    s.tokensMu.RLock()
    keyAuth, exists := s.tokens[token]
    s.tokensMu.RUnlock()

    if !exists {
        http.NotFound(w, r)
        return
    }

    w.Header().Set("Content-Type", "text/plain")
    w.Write([]byte(keyAuth))
}
```

### Register Custom Solver

```go
resolver := client.NewChallengeResolver()
resolver.RegisterSolver(NewHTTP01Solver(":80"))
resolver.RegisterSolver(dnsSolver)

// Prefer HTTP-01 for this deployment
resolver.SetPreferences("http-01", "dns-01")
```

## Complete Certificate Flow Example

```go
func RequestCertificate(ctx context.Context, acmeClient *client.Client, domains []string) error {
    // Setup resolver with DNS solver
    provider, _ := cloudflare.NewFromEnv(ctx)
    dnsSolver, _ := client.NewDNSSolver(provider,
        client.WithPropagationCheck(2*time.Minute, 10*time.Second),
    )

    resolver := client.NewChallengeResolver()
    resolver.RegisterSolver(dnsSolver)
    defer resolver.Close()

    // Create identifiers
    authzIDs := make([]acme.AuthzID, len(domains))
    for i, domain := range domains {
        authzIDs[i] = acme.AuthzID{Type: "dns", Value: domain}
    }

    // Create order
    order, err := acmeClient.AuthorizeOrder(ctx, authzIDs)
    if err != nil {
        return err
    }

    // Process each authorization
    for _, authzURL := range order.AuthzURLs {
        authz, err := acmeClient.GetAuthorization(ctx, authzURL)
        if err != nil {
            return err
        }

        if authz.Status == acme.StatusValid {
            continue // Already valid
        }

        // Select and solve challenge
        challenge, solver, err := resolver.SelectChallenge(authz)
        if err != nil {
            return err
        }

        // Get key authorization
        keyAuth, _ := acmeClient.HTTP01ChallengeResponse(challenge.Token)

        // Solve challenge
        if err := solver.Solve(ctx, authz.Identifier.Value, challenge, keyAuth); err != nil {
            return err
        }

        // Accept challenge
        if _, err := acmeClient.Accept(ctx, challenge); err != nil {
            solver.Cleanup(ctx, authz.Identifier.Value, challenge)
            return err
        }

        // Wait for validation
        if _, err := acmeClient.WaitAuthorization(ctx, authz.URI); err != nil {
            solver.Cleanup(ctx, authz.Identifier.Value, challenge)
            return err
        }

        // Cleanup
        solver.Cleanup(ctx, authz.Identifier.Value, challenge)
    }

    // Finalize order with CSR
    csr := generateCSR(domains)
    certChain, _, err := acmeClient.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
    if err != nil {
        return err
    }

    // Certificate issued!
    return nil
}
```

## Error Handling

### Solver Errors

| Error | Description |
|-------|-------------|
| `ErrNoSolverRegistered` | No solver for challenge type |
| `ErrNoChallengeSupported` | No matching challenge in authorization |
| `ErrNilAuthorization` | Nil authorization provided |
| `ErrNilChallenge` | Nil challenge provided |
| `ErrEmptyDomain` | Empty domain string |
| `ErrEmptyKeyAuth` | Empty key authorization |
| `ErrResolverClosed` | Resolver has been closed |

### DNS Solver Errors

| Error | Description |
|-------|-------------|
| `ErrNilProvider` | Nil DNS provider |
| `ErrDNSRecordNotPresent` | DNS record not found |
| `ErrDNSRecordCleanup` | Failed to cleanup record |
| `ErrDNSPropagationTimeout` | Propagation check timed out |
| `ErrDNSSolverClosed` | Solver has been closed |

## See Also

- [ACME Client](client.md) - Client configuration and usage
- [DNS-01 Providers](dns-01/) - DNS provider setup
- [RFC 8555 Section 8](https://tools.ietf.org/html/rfc8555#section-8) - Challenge Types
