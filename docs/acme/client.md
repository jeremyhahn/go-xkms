# ACME Client

Full-featured ACME client with RFC 8555 compliance, automatic renewal, and RFC 9773 ARI support.

## Overview

The ACME client package provides a complete implementation for interacting with ACME servers. It supports the full certificate lifecycle including account management, order creation, challenge resolution, certificate issuance, renewal, and revocation.

## Key Features

| Feature | Description |
|---------|-------------|
| **RFC 8555 Compliance** | Full ACME protocol implementation |
| **Account Management** | Register, update, key rollover, deactivate |
| **Order Management** | Create, list, finalize orders |
| **Challenge Resolver** | Pluggable solvers with preference ordering |
| **ARI Support** | RFC 9773 Renewal Information for smart renewal |
| **Pre-Authorization** | Batch authorization before order creation |
| **Auto-Renewal** | Configurable automatic certificate renewal |
| **Retry Logic** | Configurable retries with exponential backoff |
| **OCSP Stapling** | Fetch and validate OCSP responses for stapling |
| **Chain Selection** | Select preferred certificate chains |
| **Rate Limiting** | Client-side rate limiting with Retry-After support |
| **Renewal Helpers** | Compute optimal renewal times |

## Quick Start

### Basic Usage

```go
import (
    "github.com/jeremyhahn/go-trusted-ca/pkg/acme/client"
    "github.com/jeremyhahn/go-trusted-ca/pkg/acme/storage/objstore"
)

// Create client configuration
cfg := &client.Config{
    DirectoryURL:        "https://acme.example.com/directory",
    Timeout:             60 * time.Second,
    SystemCertPool:      true,
    RequestServerBundle: false,
    RetryAttempts:       3,
    RetryDelay:          time.Second,
    MaxRetryDelay:       30 * time.Second,
}

// Create storage (using go-objstore)
storage, _ := objstore.NewAccountDAO(ctx, storeConfig)

// Create client
acmeClient, err := client.NewClient(&client.Params{
    AccountEmail:       "admin@example.com",
    AccountSigner:      privateKey,
    Config:             cfg,
    Storage:            storage,
    CertificateStorage: certStorage,
    OrderStorage:       orderStorage,
})
```

### Register an Account

```go
account, err := acmeClient.RegisterAccount()
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Account registered: %s\n", account.URI)
```

### Request a Certificate

```go
cert, err := acmeClient.RequestCertificate(ctx, &client.CertificateRequest{
    AuthzType:     "dns",
    AuthzValue:    "example.com",
    ChallengeType: "http-01",
    CSR:           csrBytes,
    ChallengeSetup: func(challengeType, token, keyAuth string) error {
        // Present the challenge response
        return nil
    },
    ChallengeCleanup: func(challengeType string) {
        // Clean up challenge resources
    },
})
```

## Configuration

### Client Configuration

```go
type Config struct {
    // DirectoryURL is the ACME directory endpoint
    DirectoryURL string

    // Timeout for HTTP requests (default: 60s)
    Timeout time.Duration

    // SystemCertPool includes OS system certificate pool (default: false)
    // Set to true for public CAs, false for isolated/private CA environments
    SystemCertPool bool

    // RequestServerBundle fetches CA bundle from server (default: false)
    RequestServerBundle bool

    // TrustedRoots contains PEM-encoded trusted root CA certificates
    TrustedRoots []string

    // RetryAttempts for failed requests (default: 3)
    RetryAttempts int

    // RetryDelay between attempts (default: 1s)
    RetryDelay time.Duration

    // MaxRetryDelay for exponential backoff (default: 30s)
    MaxRetryDelay time.Duration
}
```

### Renewal Configuration

```go
type RenewalConfig struct {
    // Enabled indicates whether auto-renewal is enabled
    Enabled bool

    // CheckInterval for renewal checks (default: 24h)
    CheckInterval time.Duration

    // RenewalThreshold as fraction of validity (default: 0.33)
    // 0.33 means renew when 1/3 of validity remains
    RenewalThreshold float64

    // MaxRetries for renewal attempts (default: 5)
    MaxRetries int

    // RetryInterval between attempts (default: 1h)
    RetryInterval time.Duration

    // NotifyOnSuccess logs successful renewals
    NotifyOnSuccess bool

    // NotifyOnFailure logs failed renewals
    NotifyOnFailure bool
}
```

## Account Management

### Update Account Contacts

```go
// Update contact information
account, err := acmeClient.UpdateAccount(ctx, []string{
    "admin@example.com",
    "backup@example.com",
})
```

### Key Rollover

```go
// Generate new key
newKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

// Rollover to new key
err := acmeClient.AccountKeyRollover(ctx, newKey)
```

### Deactivate Account

```go
// WARNING: This is irreversible!
err := acmeClient.DeactivateAccount(ctx)
```

## Order Management

### List Orders

```go
orderURLs, err := acmeClient.ListOrders(ctx)
for _, url := range orderURLs {
    fmt.Println(url)
}
```

### Get Order Details

```go
order, err := acmeClient.GetOrder(ctx, orderURL)
fmt.Printf("Order status: %s\n", order.Status)
```

### Get Authorization

```go
authz, err := acmeClient.GetAuthorization(ctx, authzURL)
for _, challenge := range authz.Challenges {
    fmt.Printf("Challenge: %s (%s)\n", challenge.Type, challenge.Status)
}
```

### Deactivate Authorization

```go
// Abandon an authorization
err := acmeClient.DeactivateAuthorization(ctx, authzURL)
```

## ARI Support (RFC 9773)

ACME Renewal Information (ARI) provides server-recommended renewal windows.

### Check ARI Support

```go
supported, err := acmeClient.SupportsARI(ctx)
if supported {
    fmt.Println("Server supports ARI")
}
```

### Get Renewal Information

```go
// Compute certificate ID
certID := client.GetCertificateID(certificate)

// Fetch renewal info
renewalInfo, err := acmeClient.GetRenewalInfo(ctx, certID)
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Suggested renewal window: %s to %s\n",
    renewalInfo.SuggestedWindow.Start,
    renewalInfo.SuggestedWindow.End)

// Check if renewal is needed
if renewalInfo.ShouldRenewNow() {
    fmt.Println("Certificate should be renewed now")
}

// Check if renewal is needed soon (within 7 days)
if renewalInfo.ShouldRenewSoon(7 * 24 * time.Hour) {
    fmt.Println("Certificate renewal coming up")
}

// Get optimal renewal time
renewTime := renewalInfo.RandomRenewalTime()
```

### Create Replacement Order

```go
// Create order that replaces an existing certificate
order, err := acmeClient.CreateOrderWithReplaces(ctx,
    []string{"example.com"},
    certID,
)
```

### Helper Functions

```go
// Compute certificate ID from certificate
certID := client.GetCertificateID(cert)

// Fallback for certs without AKI extension
certID := client.GetCertificateIDFromHash(cert)

// Parse certificate ID into components
aki, serial, err := client.ParseCertificateID(certID)

// Validate certificate ID format
err := client.ValidateCertificateID(certID)
```

## Pre-Authorization

Pre-authorization allows obtaining authorizations before creating orders.

### Check Support

```go
if acmeClient.SupportsPreAuthorization(ctx) {
    fmt.Println("Server supports pre-authorization")
}
```

### Pre-Authorize Single Identifier

```go
authz, err := acmeClient.PreAuthorize(ctx, client.Identifier{
    Type:  "dns",
    Value: "example.com",
})
```

### Pre-Authorize Multiple Domains

```go
// Batch pre-authorization for multiple domains
authorizations, err := acmeClient.PreAuthorizeDomains(ctx,
    "example.com",
    "www.example.com",
    "api.example.com",
)
```

### Pre-Authorize IP Addresses

```go
authorizations, err := acmeClient.PreAuthorizeIPs(ctx,
    "192.168.1.1",
    "10.0.0.1",
)
```

## Certificate Operations

### Revoke Certificate

```go
err := acmeClient.RevokeCertificate(ctx, certificate, acme.CRLReasonKeyCompromise)
```

### Fetch Certificate

```go
// Fetch certificate with chain
certs, err := acmeClient.FetchCertificate(ctx, certURL, true)
```

### Renew Certificate

```go
newCert, err := acmeClient.RenewCertificate(ctx, oldCert, &client.CertificateRequest{
    AuthzType:     "dns",
    AuthzValue:    "example.com",
    ChallengeType: "dns-01",
    CSR:           newCSR,
})
```

## TLS Configuration

### Using System Certificate Pool

```go
cfg := &client.Config{
    DirectoryURL:   "https://acme-v02.api.letsencrypt.org/directory",
    SystemCertPool: true, // Include system CAs
}
```

### Private CA Environment

```go
cfg := &client.Config{
    DirectoryURL:        "https://acme.internal.example.com/directory",
    SystemCertPool:      false, // Isolated mode
    RequestServerBundle: true,  // Fetch CA bundle from server
}
```

### Custom Trusted Roots

```go
cfg := &client.Config{
    DirectoryURL:   "https://acme.example.com/directory",
    SystemCertPool: false,
    TrustedRoots: []string{
        `-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAKH...
-----END CERTIFICATE-----`,
    },
}
```

## Error Handling

The client provides typed errors for proper error handling:

```go
err := acmeClient.DeactivateAccount(ctx)
if errors.Is(err, client.ErrAccountDeactivated) {
    // Handle account already deactivated
}

_, err = acmeClient.GetOrder(ctx, orderURL)
if errors.Is(err, client.ErrOrderNotFound) {
    // Handle order not found
}
```

### Common Errors

| Error | Description |
|-------|-------------|
| `ErrAccountNotFound` | Account does not exist |
| `ErrAccountDeactivated` | Account permanently deactivated |
| `ErrOrderNotFound` | Order does not exist |
| `ErrOrderCreationFailed` | Failed to create order |
| `ErrAuthorizationFailed` | Authorization request failed |
| `ErrChallengeResolution` | Challenge resolution failed |
| `ErrARINotSupported` | Server doesn't support ARI |
| `ErrPreAuthNotSupported` | Server doesn't support pre-auth |

## OCSP Stapling Support

The client provides helpers for OCSP stapling, enabling TLS servers to include OCSP responses in the handshake.

### Fetch OCSP Response

```go
// Get OCSP response for stapling
ocspResp, err := acmeClient.GetOCSP(ctx, certificate, issuer)
if err != nil {
    log.Fatal(err)
}

// Check status
if ocspResp.IsGood() {
    // Use for stapling
    tlsConfig.OCSPStaple = ocspResp.Raw
}

// Check if response should be refreshed
if ocspResp.ShouldRefresh() {
    // Fetch a new OCSP response
}
```

### Standalone OCSP Check

```go
// Check certificate validity without client instance
err := client.CheckOCSP(ctx, certificate, issuer)
if err != nil {
    if errors.Is(err, client.ErrOCSPCertRevoked) {
        log.Fatal("Certificate has been revoked")
    }
}
```

### Check for Must-Staple Extension

```go
if client.HasMustStaple(certificate) {
    // TLS server MUST provide OCSP stapling for this certificate
}
```

## Certificate Chain Selection

When ACME servers offer multiple certificate chains (e.g., cross-signed certificates), you can select a specific chain.

### Fetch with Preferred Chain

```go
// Request a specific root CA's chain
chain, err := acmeClient.FetchCertificateWithChain(ctx, certURL, &client.ChainOption{
    PreferredChain: "ISRG Root X1",
    AllowFallback:  true, // Use default if preferred not available
})
```

### List Available Chains

```go
// Get all available chains for a certificate
chains, err := acmeClient.GetAvailableChains(ctx, certURL)
for _, chain := range chains {
    fmt.Printf("Chain: %s (length: %d)\n", chain.RootName, chain.ChainLength)
}
```

### Chain Selection Helpers

```go
// Select by root CA name
chain := client.SelectChainByRootName(chains, "ISRG Root X1")

// Select shortest chain (better performance)
chain := client.SelectShortestChain(chains)

// Select longest chain (maximum compatibility)
chain := client.SelectLongestChain(chains)
```

## Client-Side Rate Limiting

Prevent hitting server-side rate limits with built-in rate limiting.

### Configure Rate Limiting

```go
// Create rate limiter
limiter := client.NewRateLimiter(&client.RateLimiterConfig{
    Enabled:           true,
    RequestsPerSecond: 10,    // Max 10 requests/second
    BurstSize:         20,    // Allow bursts up to 20
    MaxWaitTime:       30 * time.Second,
    RetryAfterHeader:  true,  // Respect Retry-After headers
})
```

### Use with HTTP Transport

```go
// Wrap HTTP transport with rate limiting
transport := client.NewRateLimitedTransport(http.DefaultTransport, limiter)
httpClient := &http.Client{Transport: transport}
```

### Manual Rate Limiting

```go
// Wait for rate limit token
err := limiter.Wait(ctx)
if err != nil {
    if errors.Is(err, client.ErrRateLimitExceeded) {
        log.Println("Rate limit exceeded, try again later")
    }
}

// Check without waiting
if limiter.Allow() {
    // Make request
}

// Get rate limiter stats
stats := limiter.Stats()
fmt.Printf("Available tokens: %.1f\n", stats.AvailableTokens)
```

## Renewal Timing Helpers

Determine optimal renewal times for certificates.

### Get Recommended Renewal Time

```go
// Get optimal renewal time using ARI or certificate-based calculation
renewAt, err := acmeClient.ShouldRenewAt(ctx, certificate, 0.3)
if time.Now().After(renewAt) {
    // Time to renew
}
```

### Standalone Renewal Calculations

```go
// Compute renewal time based on validity period
// threshold = 0.3 means renew when 30% validity remains
renewAt := client.ComputeRenewalTime(certificate, 0.3)

// Check if renewal is needed now
if client.NeedsRenewal(certificate, 0.3) {
    // Renew the certificate
}

// Get days until expiry
days := client.DaysUntilExpiry(certificate)
fmt.Printf("Certificate expires in %d days\n", days)

// Check expiration status
if client.IsExpired(certificate) {
    log.Fatal("Certificate has expired")
}
if client.IsNotYetValid(certificate) {
    log.Fatal("Certificate is not yet valid")
}
```

## See Also

- [Challenge Resolver](challenge-resolver.md) - Pluggable challenge solving
- [DNS-01 Providers](dns-01-providers.md) - DNS provider configuration
- [RFC 8555](https://tools.ietf.org/html/rfc8555) - ACME Protocol
- [RFC 9773](https://tools.ietf.org/html/rfc9773) - ACME Renewal Information
