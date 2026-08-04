# DNS-01 Challenge Providers

DNS providers for ACME DNS-01 challenge verification with automatic record management and propagation checking.

## Overview

The DNS-01 challenge providers enable automated TXT record management for ACME domain validation. Each provider implements a common interface supporting:

- TXT record creation and cleanup
- Zone discovery (automatic or pre-configured)
- Configurable propagation timeout and polling
- Environment variable configuration
- Multiple authentication methods

## Supported Providers

| Provider | Package | Environment Prefix |
|----------|---------|-------------------|
| AWS Route53 | `route53` | `AWS_`, `ROUTE53_` |
| Cloudflare | `cloudflare` | `CLOUDFLARE_`, `CF_` |
| Azure DNS | `azure` | `AZURE_` |
| Google Cloud DNS | `clouddns` | `GCE_`, `GOOGLE_` |

## Provider Interface

All providers implement the base `Provider` interface:

```go
type Provider interface {
    Present(ctx context.Context, domain, fqdn, value string) error
    CleanUp(ctx context.Context, domain, fqdn, value string) error
}
```

Providers also implement `ProviderTimeout` for custom propagation settings:

```go
type ProviderTimeout interface {
    Provider
    Timeout() (timeout, interval time.Duration)
}
```

## Quick Start

### Using Factory (Recommended)

```go
import "github.com/jeremyhahn/go-xkms/pkg/acme/challenges/dns-01/providers"

// Create provider from environment variables
provider, err := providers.NewProviderFromEnv(ctx, providers.ProviderCloudflare)
if err != nil {
    return err
}

// Present TXT record
err = provider.Present(ctx, "example.com", "_acme-challenge.example.com.", "token-value")
if err != nil {
    return err
}
defer provider.CleanUp(ctx, "example.com", "_acme-challenge.example.com.", "token-value")
```

---

## Cloudflare

### Authentication Methods

| Method | Required Fields | Description |
|--------|-----------------|-------------|
| API Token | `APIToken` | Scoped token (recommended) |
| API Key | `Email`, `APIKey` | Global API key |
| Split Tokens | `APIToken`, `ZoneAPIToken` | Separate tokens for DNS and zone ops |

### Configuration

```go
import "github.com/jeremyhahn/go-xkms/pkg/acme/challenges/dns-01/providers/cloudflare"

provider, err := cloudflare.New(ctx, cloudflare.Config{
    APIToken:           "your-api-token",
    PropagationTimeout: 2 * time.Minute,
    PollingInterval:    4 * time.Second,
    TTL:                120,
})
```

### Environment Variables

| Variable | Alias | Description | Default |
|----------|-------|-------------|---------|
| `CLOUDFLARE_DNS_API_TOKEN` | `CF_DNS_API_TOKEN` | Scoped API token | - |
| `CLOUDFLARE_ZONE_API_TOKEN` | `CF_ZONE_API_TOKEN` | Optional zone listing token | - |
| `CLOUDFLARE_EMAIL` | `CF_EMAIL` | Account email (API key auth) | - |
| `CLOUDFLARE_API_KEY` | `CF_API_KEY` | Global API key | - |
| `CLOUDFLARE_ZONE_ID` | `CF_ZONE_ID` | Pre-configured zone ID | Auto-detect |
| `CLOUDFLARE_PROPAGATION_TIMEOUT` | `CF_PROPAGATION_TIMEOUT` | Max propagation wait | `120s` |
| `CLOUDFLARE_POLLING_INTERVAL` | `CF_POLLING_INTERVAL` | Check interval | `4s` |
| `CLOUDFLARE_TTL` | `CF_TTL` | Record TTL (seconds) | `120` |
| `CLOUDFLARE_HTTP_TIMEOUT` | `CF_HTTP_TIMEOUT` | HTTP request timeout | `30s` |

### Required Permissions

For API Token authentication, create a token with:
- **Zone:DNS:Edit** - For DNS record management
- **Zone:Zone:Read** - For zone discovery (if not using `CLOUDFLARE_ZONE_ID`)

### Usage with Environment Variables

```bash
export CLOUDFLARE_DNS_API_TOKEN="your-api-token"
```

```go
provider, err := cloudflare.NewFromEnv(ctx)
```

---

## AWS Route53

### Authentication Methods

| Method | Required Fields | Description |
|--------|-----------------|-------------|
| Static Credentials | `AccessKeyID`, `SecretAccessKey` | IAM user credentials |
| Ambient | `Ambient: true` | EC2 instance profile, ECS task role |
| Assume Role | `Role`, `AccessKeyID`, `SecretAccessKey` | Cross-account access |
| Web Identity | `Role`, `WebIdentityToken` | EKS/IRSA workload identity |

### Configuration

```go
import "github.com/jeremyhahn/go-xkms/pkg/acme/challenges/dns-01/providers/route53"

provider, err := route53.New(ctx, route53.Config{
    AccessKeyID:        "AKIAIOSFODNN7EXAMPLE",
    SecretAccessKey:    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    Region:             "us-east-1",
    HostedZoneID:       "Z1234567890ABC",  // Optional
    PropagationTimeout: 2 * time.Minute,
    PollingInterval:    4 * time.Second,
    TTL:                10,
})
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `AWS_ACCESS_KEY_ID` | AWS access key ID | - |
| `AWS_SECRET_ACCESS_KEY` | AWS secret access key | - |
| `AWS_HOSTED_ZONE_ID` | Route53 hosted zone ID | Auto-detect |
| `AWS_REGION` | AWS region | - |
| `AWS_PROPAGATION_TIMEOUT` / `ROUTE53_PROPAGATION_TIMEOUT` | Max propagation wait | `120s` |
| `AWS_POLLING_INTERVAL` / `ROUTE53_POLLING_INTERVAL` | Check interval | `4s` |
| `AWS_TTL` / `ROUTE53_TTL` | Record TTL (seconds) | `10` |

### Required IAM Permissions

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "route53:GetChange",
                "route53:ChangeResourceRecordSets",
                "route53:ListHostedZonesByName"
            ],
            "Resource": "*"
        }
    ]
}
```

### Usage with Ambient Credentials

```go
// Uses EC2 instance profile or ECS task role
provider, err := route53.New(ctx, route53.Config{
    Ambient:      true,
    HostedZoneID: "Z1234567890ABC",
})
```

---

## Azure DNS

### Authentication Methods

| Method | Required Fields | Description |
|--------|-----------------|-------------|
| Client Credentials | `ClientID`, `ClientSecret`, `TenantID` | Service principal |
| Managed Identity | `Ambient: true` | Azure VM/AKS managed identity |
| Workload Identity | `Ambient: true` | AKS with AAD workload identity |

### Configuration

```go
import "github.com/jeremyhahn/go-xkms/pkg/acme/challenges/dns-01/providers/azure"

provider, err := azure.New(ctx, azure.Config{
    ClientID:          "your-client-id",
    ClientSecret:      "your-client-secret",
    TenantID:          "your-tenant-id",
    SubscriptionID:    "your-subscription-id",
    ResourceGroupName: "your-resource-group",
    ZoneName:          "example.com",  // Optional
    PropagationTimeout: 2 * time.Minute,
    PollingInterval:    4 * time.Second,
    TTL:                60,
})
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `AZURE_CLIENT_ID` | Service principal client ID | - |
| `AZURE_CLIENT_SECRET` | Service principal secret | - |
| `AZURE_TENANT_ID` | Azure AD tenant ID | - |
| `AZURE_SUBSCRIPTION_ID` | Azure subscription ID | Required |
| `AZURE_RESOURCE_GROUP` | Resource group with DNS zone | Required |
| `AZURE_ZONE_NAME` | DNS zone name | Auto-detect |
| `AZURE_ENVIRONMENT` | Cloud environment | `AzurePublicCloud` |
| `AZURE_PROPAGATION_TIMEOUT` | Max propagation wait | `120s` |
| `AZURE_POLLING_INTERVAL` | Check interval | `4s` |
| `AZURE_TTL` | Record TTL (seconds) | `60` |

### Azure Environments

| Value | Description |
|-------|-------------|
| `AzureCloud` / `AzurePublicCloud` | Azure public cloud (default) |
| `AzureUSGovernment` | Azure US Government |
| `AzureChinaCloud` | Azure China (21Vianet) |

### Required Azure Roles

Assign the service principal one of:
- **DNS Zone Contributor** - Full DNS management
- **Reader** + custom role with:
  - `Microsoft.Network/dnsZones/TXT/read`
  - `Microsoft.Network/dnsZones/TXT/write`
  - `Microsoft.Network/dnsZones/TXT/delete`

### Usage with Managed Identity

```go
provider, err := azure.New(ctx, azure.Config{
    SubscriptionID:    "your-subscription-id",
    ResourceGroupName: "your-resource-group",
    Ambient:           true,
})
```

---

## Google Cloud DNS

### Authentication Methods

| Method | Required Fields | Description |
|--------|-----------------|-------------|
| Service Account | `ServiceAccountJSON` | JSON key file data |
| ADC | `Ambient: true` | Application default credentials |
| Workload Identity | `Ambient: true` | GKE workload identity |

### Configuration

```go
import "github.com/jeremyhahn/go-xkms/pkg/acme/challenges/dns-01/providers/clouddns"

provider, err := clouddns.New(ctx, clouddns.Config{
    Project:            "my-gcp-project",
    ServiceAccountJSON: serviceAccountKeyData,
    HostedZoneName:     "example-zone",  // Optional
    PropagationTimeout: 2 * time.Minute,
    PollingInterval:    4 * time.Second,
    TTL:                120,
})
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `GCE_PROJECT` | GCP project ID | Required |
| `GCE_SERVICE_ACCOUNT_FILE` | Path to service account JSON | - |
| `GOOGLE_APPLICATION_CREDENTIALS` | Alternative SA file path | - |
| `GCE_ZONE_NAME` | Cloud DNS managed zone name | Auto-detect |
| `GCE_PROPAGATION_TIMEOUT` | Max propagation wait | `120s` |
| `GCE_POLLING_INTERVAL` | Check interval | `4s` |
| `GCE_TTL` | Record TTL (seconds) | `120` |

### Required IAM Roles

- **roles/dns.admin** - Full Cloud DNS management

Or custom role with:
- `dns.changes.create`
- `dns.changes.get`
- `dns.managedZones.list`
- `dns.resourceRecordSets.create`
- `dns.resourceRecordSets.delete`
- `dns.resourceRecordSets.list`
- `dns.resourceRecordSets.update`

### Usage with ADC

```bash
# Authenticate with gcloud
gcloud auth application-default login
```

```go
provider, err := clouddns.New(ctx, clouddns.Config{
    Project: "my-gcp-project",
    Ambient: true,
})
```

---

## Common Configuration

### Propagation Settings

All providers support configurable propagation timeout and polling interval:

| Setting | Description | Default |
|---------|-------------|---------|
| PropagationTimeout | Maximum time to wait for DNS propagation | `120s` |
| PollingInterval | Time between propagation checks | `4s` |
| TTL | Time-to-live for created TXT records | Provider-specific |

### Docker Secrets Pattern

All environment variables support a `_FILE` suffix for Docker secrets:

```bash
# Instead of:
export CLOUDFLARE_DNS_API_TOKEN="secret-value"

# Use file:
export CLOUDFLARE_DNS_API_TOKEN_FILE="/run/secrets/cloudflare_token"
```

### Custom Nameservers

All providers support custom nameservers for zone discovery:

```go
config := cloudflare.Config{
    APIToken:    "token",
    Nameservers: []string{"8.8.8.8:53", "1.1.1.1:53"},
}
```

---

## Troubleshooting

### Common Errors

| Error | Cause | Solution |
|-------|-------|----------|
| `zone not found` | Zone discovery failed | Set zone ID/name explicitly or check permissions |
| `missing credentials` | No authentication configured | Provide credentials or enable ambient auth |
| `propagation timeout` | DNS record not visible | Increase timeout or check DNS configuration |
| `record not found` | Cleanup of non-existent record | Usually safe to ignore |

### Debugging Tips

1. **Enable verbose logging** - Set environment variables for provider-specific debug output

2. **Verify zone discovery** - Pre-configure zone ID/name to skip auto-discovery

3. **Check DNS propagation** - Use external tools like `dig` to verify records

4. **Verify permissions** - Ensure credentials have required permissions for DNS operations

### Provider-Specific Issues

#### Cloudflare
- **Split token issues**: Ensure ZoneAPIToken has `Zone:Zone:Read` permission
- **Rate limits**: Cloudflare has rate limits on API calls; increase polling interval if needed

#### Route53
- **Change propagation**: Route53 changes may take up to 60 seconds to propagate internally
- **Multi-value records**: Uses `SetIdentifier` for multiple TXT records

#### Azure
- **Optimistic concurrency**: Uses etags for record updates; conflicts may require retry

#### Cloud DNS
- **Zone visibility**: Prefers public zones over private when multiple exist

## See Also

- [ACME Client](client.md) - Client configuration and usage
- [Challenge Resolver](challenge-resolver.md) - Pluggable challenge solving
- [RFC 8555 Section 8.4](https://tools.ietf.org/html/rfc8555#section-8.4) - DNS Challenge
