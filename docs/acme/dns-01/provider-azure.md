# Azure DNS Provider

The Azure DNS provider manages DNS-01 challenge records in Azure DNS zones.

## Authentication Methods

### Client Credentials

Azure AD application with client ID, client secret, and tenant ID.

```go
provider, err := azure.New(ctx, azure.Config{
    ClientID:          "your-client-id",
    ClientSecret:      "your-client-secret",
    TenantID:          "your-tenant-id",
    SubscriptionID:    "your-subscription-id",
    ResourceGroupName: "your-resource-group",
})
```

### Managed Identity

For Azure VMs and AKS - automatically uses the assigned managed identity.

```go
provider, err := azure.New(ctx, azure.Config{
    SubscriptionID:    "your-subscription-id",
    ResourceGroupName: "your-resource-group",
    Ambient:           true,
})
```

### Workload Identity

For AKS with Azure AD Workload Identity - uses federated credentials.

```go
provider, err := azure.New(ctx, azure.Config{
    SubscriptionID:    "your-subscription-id",
    ResourceGroupName: "your-resource-group",
    Ambient:           true,
    // Workload Identity automatically detected
})
```

## Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `AZURE_CLIENT_ID` | Azure AD application client ID | No (ambient) |
| `AZURE_CLIENT_SECRET` | Azure AD application client secret | With client ID |
| `AZURE_TENANT_ID` | Azure AD tenant ID | With client credentials |
| `AZURE_SUBSCRIPTION_ID` | Azure subscription ID | Yes |
| `AZURE_RESOURCE_GROUP` | Resource group containing DNS zone | Yes |
| `AZURE_ZONE_NAME` | DNS zone name | No (auto-discover) |
| `AZURE_ENVIRONMENT` | Cloud environment | No (default: AzurePublicCloud) |
| `AZURE_PROPAGATION_TIMEOUT` | DNS propagation timeout | No (default: 120s) |
| `AZURE_POLLING_INTERVAL` | Propagation check interval | No (default: 4s) |
| `AZURE_TTL` | DNS record TTL | No (default: 60) |

## Configuration

```go
type Config struct {
    // Authentication
    ClientID     string  // Azure AD application client ID
    ClientSecret string  // Azure AD application client secret
    TenantID     string  // Azure AD tenant ID

    // Azure resources
    SubscriptionID    string  // Azure subscription ID (required)
    ResourceGroupName string  // Resource group (required)
    ZoneName          string  // DNS zone name (auto-discover if empty)

    // Ambient credentials
    Ambient bool  // Use managed identity or workload identity

    // Cloud environment
    Environment string  // AzurePublicCloud, AzureChinaCloud, AzureGovernmentCloud

    // Timeouts
    PropagationTimeout time.Duration  // Default: 120s
    PollingInterval    time.Duration  // Default: 4s
    HTTPTimeout        time.Duration  // Default: 30s

    // DNS settings
    TTL int64  // Record TTL (default: 60)
}
```

## Supported Environments

| Environment | Description |
|-------------|-------------|
| `AzurePublicCloud` | Standard Azure (default) |
| `AzureChinaCloud` | Azure China (21Vianet) |
| `AzureGovernmentCloud` | Azure Government |

## Required Azure Permissions

The identity needs the following role assignment on the DNS zone:

**DNS Zone Contributor** role or custom role with:
- `Microsoft.Network/dnsZones/read`
- `Microsoft.Network/dnsZones/TXT/read`
- `Microsoft.Network/dnsZones/TXT/write`
- `Microsoft.Network/dnsZones/TXT/delete`

### Assigning Permissions via Azure CLI

```bash
# Get the DNS zone resource ID
ZONE_ID=$(az network dns zone show \
    --name example.com \
    --resource-group my-rg \
    --query id -o tsv)

# Assign DNS Zone Contributor role
az role assignment create \
    --role "DNS Zone Contributor" \
    --assignee $CLIENT_ID \
    --scope $ZONE_ID
```

## Usage Examples

### With Environment Variables

```bash
export AZURE_CLIENT_ID="your-client-id"
export AZURE_CLIENT_SECRET="your-client-secret"
export AZURE_TENANT_ID="your-tenant-id"
export AZURE_SUBSCRIPTION_ID="your-subscription-id"
export AZURE_RESOURCE_GROUP="your-resource-group"
```

```go
provider, err := azure.NewFromEnv(ctx)
if err != nil {
    return err
}
```

### With Managed Identity on Azure VM

```go
provider, err := azure.New(ctx, azure.Config{
    SubscriptionID:    "your-subscription-id",
    ResourceGroupName: "your-resource-group",
    Ambient:           true,
})
```

### Using Provider Factory

```go
import "github.com/jeremyhahn/go-trusted-ca/pkg/acme/challenges/dns-01/providers"

provider, err := providers.NewProviderFromEnv(ctx, providers.NameAzure)
```

## Troubleshooting

### Authentication Failed

If authentication fails:

1. Verify client ID, secret, and tenant ID are correct
2. Check the application registration in Azure AD
3. Ensure the secret hasn't expired

### Zone Not Found

If the provider cannot find your DNS zone:

1. Verify subscription ID and resource group are correct
2. Check that the DNS zone exists in the specified resource group
3. Try explicitly setting `AZURE_ZONE_NAME`

### Permission Denied

If API calls fail with authorization errors:

1. Verify role assignment on the DNS zone
2. Check that the identity has required permissions
3. For managed identity, ensure it's enabled on the resource

### Managed Identity Not Working

For Azure VMs:
1. Verify managed identity is enabled on the VM
2. Check if system-assigned or user-assigned identity is configured
3. Ensure role assignment is on the correct identity

For AKS:
1. Verify workload identity is configured
2. Check service account annotations
3. Ensure federated identity credential is set up

## See Also

- [Azure DNS Documentation](https://docs.microsoft.com/azure/dns/)
- [Managed Identities](https://docs.microsoft.com/azure/active-directory/managed-identities-azure-resources/)
- [AKS Workload Identity](https://docs.microsoft.com/azure/aks/workload-identity-overview)
- [DNS-01 Providers Overview](README.md)
