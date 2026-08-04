# DNS-01 Challenge Providers

This directory contains documentation for DNS-01 challenge providers used for ACME domain validation.

## Overview

DNS-01 is a challenge type defined in RFC 8555 that validates domain ownership by requiring the creation of a specific TXT record in the domain's DNS zone. This method is particularly useful for:

- **Wildcard certificates**: The only ACME challenge type that supports wildcards
- **Firewalled environments**: Works when HTTP-01 validation is not possible
- **Automated certificate management**: Scales well for large deployments

## Supported Providers

| Provider | Documentation | Status |
|----------|--------------|--------|
| [Cloudflare](provider-cloudflare.md) | API Token, API Key, Split Tokens | Production |
| [AWS Route53](provider-route53.md) | Static Credentials, IAM, STS, IRSA | Production |
| [Azure DNS](provider-azure.md) | Client Credentials, Managed Identity | Production |
| [Google Cloud DNS](provider-clouddns.md) | Service Account, ADC | Production |

## Common Features

All DNS-01 providers support:

- **Environment variable configuration**: Configure without code changes
- **Docker secrets pattern**: Use `VAR_FILE` suffix for file-based secrets
- **Configurable timeouts**: Fine-tune DNS propagation waiting
- **ProviderTimeout interface**: Query provider-specific timeout settings

## Quick Start

### Using Environment Variables

```go
import "github.com/jeremyhahn/go-xkms/pkg/acme/challenges/dns-01/providers"

// Create provider from environment variables
provider, err := providers.NewProviderFromEnv(ctx, providers.NameCloudflare)
if err != nil {
    return err
}
defer provider.CleanUp(ctx, domain, fqdn, value)

// Present the DNS challenge
err = provider.Present(ctx, domain, fqdn, value)
```

### Using Explicit Configuration

```go
import "github.com/jeremyhahn/go-xkms/pkg/acme/challenges/dns-01/providers/cloudflare"

provider, err := cloudflare.New(ctx, cloudflare.Config{
    APIToken:           "your-api-token",
    PropagationTimeout: 2 * time.Minute,
    PollingInterval:    5 * time.Second,
})
```

## Provider Interface

All providers implement the `Provider` interface:

```go
type Provider interface {
    // Present creates a TXT record for the DNS-01 challenge
    Present(ctx context.Context, domain, fqdn, value string) error

    // CleanUp removes the TXT record after challenge completion
    CleanUp(ctx context.Context, domain, fqdn, value string) error
}
```

Providers may also implement `ProviderTimeout` for custom timeout configuration:

```go
type ProviderTimeout interface {
    Provider
    Timeout() (timeout, interval time.Duration)
}
```

## Default Settings

| Setting | Default | Description |
|---------|---------|-------------|
| Propagation Timeout | 120s | Maximum time to wait for DNS propagation |
| Polling Interval | 4s | Time between propagation checks |
| TTL | Provider-specific | DNS record time-to-live |

## Adding New Providers

To add a new DNS provider:

1. Create package under `pkg/acme/challenges/dns-01/providers/<name>/`
2. Implement the `Provider` interface
3. Implement `ProviderTimeout` for custom timeouts
4. Add `NewFromEnv()` constructor for environment configuration
5. Register in `init()` with `providers.Register()` and `providers.RegisterEnvFactory()`
6. Add documentation in `docs/acme/dns-01/provider-<name>.md`

## See Also

- [RFC 8555 - ACME Protocol](https://tools.ietf.org/html/rfc8555)
- [ACME Server Documentation](../README.md)
- [Challenge Types Overview](../challenges.md)
