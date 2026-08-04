# Cloudflare DNS Provider

The Cloudflare provider manages DNS-01 challenge records using the Cloudflare API.

## Authentication Methods

### API Token (Recommended)

Scoped API tokens provide fine-grained access control with minimal permissions.

**Required permissions:**
- `Zone:Read` - List zones
- `DNS:Edit` - Create/delete TXT records

```go
provider, err := cloudflare.New(ctx, cloudflare.Config{
    APIToken: "your-api-token",
})
```

### API Key + Email (Legacy)

Global API key with account email. Has full account access - **not recommended for production**.

```go
provider, err := cloudflare.New(ctx, cloudflare.Config{
    Email:  "user@example.com",
    APIKey: "your-global-api-key",
})
```

### Split Token Support

For enterprise setups requiring separate permissions for zone listing and DNS editing:

```go
provider, err := cloudflare.New(ctx, cloudflare.Config{
    APIToken:     "dns-edit-token",      // For DNS record operations
    ZoneAPIToken: "zone-read-token",     // For zone listing only
})
```

## Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `CLOUDFLARE_DNS_API_TOKEN` | API token for DNS operations | Yes (or API Key) |
| `CLOUDFLARE_API_KEY` | Global API key | No |
| `CLOUDFLARE_EMAIL` | Account email (with API Key) | With API Key |
| `CLOUDFLARE_ZONE_API_TOKEN` | Separate token for zone listing | No |
| `CLOUDFLARE_ZONE_ID` | Pre-configured zone ID | No |
| `CLOUDFLARE_PROPAGATION_TIMEOUT` | DNS propagation timeout | No (default: 120s) |
| `CLOUDFLARE_POLLING_INTERVAL` | Propagation check interval | No (default: 4s) |
| `CLOUDFLARE_TTL` | DNS record TTL | No (default: 120) |
| `CLOUDFLARE_HTTP_TIMEOUT` | HTTP request timeout | No (default: 30s) |

All variables support `CF_*` aliases (e.g., `CF_DNS_API_TOKEN`). The `CLOUDFLARE_*` prefix takes precedence.

## Configuration

```go
type Config struct {
    // Authentication
    Email         string  // Account email (with API Key)
    APIKey        string  // Global API key (legacy)
    APIToken      string  // Scoped API token (recommended)
    ZoneAPIToken  string  // Separate token for zone listing

    // Zone configuration
    ZoneID        string  // Pre-configured zone ID (skips lookup)

    // Timeouts
    PropagationTimeout time.Duration  // Default: 120s
    PollingInterval    time.Duration  // Default: 4s
    HTTPTimeout        time.Duration  // Default: 30s

    // DNS settings
    TTL     int     // Record TTL (default: 120)
    BaseURL string  // Custom API endpoint (enterprise)
}
```

## Usage Examples

### With Environment Variables

```bash
export CLOUDFLARE_DNS_API_TOKEN="your-token"
```

```go
provider, err := cloudflare.NewFromEnv(ctx)
if err != nil {
    return err
}
```

### With Explicit Configuration

```go
provider, err := cloudflare.New(ctx, cloudflare.Config{
    APIToken:           "your-api-token",
    PropagationTimeout: 3 * time.Minute,
    PollingInterval:    10 * time.Second,
    TTL:                60,
})
```

### Using Provider Factory

```go
import "github.com/jeremyhahn/go-xkms/pkg/acme/challenges/dns-01/providers"

provider, err := providers.NewProviderFromEnv(ctx, providers.NameCloudflare)
```

## Creating an API Token

1. Go to [Cloudflare API Tokens](https://dash.cloudflare.com/profile/api-tokens)
2. Click "Create Token"
3. Use "Edit zone DNS" template or create custom:
   - **Permissions**: Zone > DNS > Edit
   - **Zone Resources**: Include > Specific zone > your-domain.com
4. Copy the token (shown only once)

## Troubleshooting

### Zone Not Found

If the provider cannot find your zone:

1. Verify the API token has `Zone:Read` permission
2. Check that the domain matches an existing zone
3. Try explicitly setting `CLOUDFLARE_ZONE_ID`

### Permission Denied

If API calls fail with 403:

1. Verify token permissions include `DNS:Edit`
2. Check zone resources are correctly scoped
3. Ensure token hasn't expired

### Propagation Timeout

If challenges fail with propagation timeout:

1. Increase `CLOUDFLARE_PROPAGATION_TIMEOUT`
2. Check Cloudflare dashboard for record creation
3. Verify nameservers are correctly configured

## See Also

- [Cloudflare API Documentation](https://developers.cloudflare.com/api/)
- [DNS-01 Providers Overview](README.md)
