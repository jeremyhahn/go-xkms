# Google Cloud DNS Provider

The Cloud DNS provider manages DNS-01 challenge records in Google Cloud DNS managed zones.

## Authentication Methods

### Service Account JSON

JSON key file for a service account with DNS permissions.

```go
provider, err := clouddns.New(ctx, clouddns.Config{
    Project:            "my-project",
    ServiceAccountJSON: []byte(`{"type": "service_account", ...}`),
})
```

### Service Account File

Path to a service account JSON file.

```go
import "os"

saJSON, _ := os.ReadFile("/path/to/service-account.json")
provider, err := clouddns.New(ctx, clouddns.Config{
    Project:            "my-project",
    ServiceAccountJSON: saJSON,
})
```

### Application Default Credentials (ADC)

Automatically uses credentials from:

1. `GOOGLE_APPLICATION_CREDENTIALS` environment variable
2. gcloud CLI authentication (`gcloud auth application-default login`)
3. GCE metadata service (on Compute Engine)
4. GKE Workload Identity (on Kubernetes)

```go
provider, err := clouddns.New(ctx, clouddns.Config{
    Project: "my-project",
    Ambient: true,
})
```

## Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `GCE_PROJECT` | GCP project ID | Yes |
| `GCE_SERVICE_ACCOUNT_FILE` | Path to service account JSON | No (ADC) |
| `GOOGLE_APPLICATION_CREDENTIALS` | Alternative to above | No |
| `GCE_ZONE_NAME` | Cloud DNS managed zone name | No (auto-discover) |
| `GCE_PROPAGATION_TIMEOUT` | DNS propagation timeout | No (default: 120s) |
| `GCE_POLLING_INTERVAL` | Propagation check interval | No (default: 4s) |
| `GCE_TTL` | DNS record TTL | No (default: 120) |

## Configuration

```go
type Config struct {
    // GCP settings
    Project            string  // GCP project ID (required)
    ServiceAccountJSON []byte  // Service account JSON credentials

    // Zone configuration
    HostedZoneName string    // Cloud DNS managed zone name
    Nameservers    []string  // Custom nameservers for zone lookup

    // Ambient credentials
    Ambient bool  // Use Application Default Credentials

    // Timeouts
    PropagationTimeout time.Duration  // Default: 120s
    PollingInterval    time.Duration  // Default: 4s
    HTTPTimeout        time.Duration  // Default: 30s

    // DNS settings
    TTL int64  // Record TTL (default: 120)
}
```

## Required IAM Roles

The service account needs one of these roles on the project or DNS zone:

**DNS Administrator** (`roles/dns.admin`) - Full DNS management

Or a custom role with these permissions:
- `dns.changes.create`
- `dns.changes.get`
- `dns.managedZones.list`
- `dns.resourceRecordSets.create`
- `dns.resourceRecordSets.delete`
- `dns.resourceRecordSets.list`
- `dns.resourceRecordSets.update`

### Assigning Permissions via gcloud

```bash
# Grant DNS Admin role to service account
gcloud projects add-iam-policy-binding my-project \
    --member="serviceAccount:dns-manager@my-project.iam.gserviceaccount.com" \
    --role="roles/dns.admin"

# Or for specific zone only (using custom role)
gcloud dns managed-zones add-iam-policy-binding my-zone \
    --member="serviceAccount:dns-manager@my-project.iam.gserviceaccount.com" \
    --role="roles/dns.admin"
```

## Usage Examples

### With Environment Variables

```bash
export GCE_PROJECT="my-project"
export GOOGLE_APPLICATION_CREDENTIALS="/path/to/service-account.json"
```

```go
provider, err := clouddns.NewFromEnv(ctx)
if err != nil {
    return err
}
```

### With Service Account JSON

```go
saJSON := []byte(`{
    "type": "service_account",
    "project_id": "my-project",
    "private_key_id": "...",
    "private_key": "...",
    "client_email": "dns-manager@my-project.iam.gserviceaccount.com",
    ...
}`)

provider, err := clouddns.New(ctx, clouddns.Config{
    Project:            "my-project",
    ServiceAccountJSON: saJSON,
})
```

### With GKE Workload Identity

On GKE with Workload Identity configured:

```go
provider, err := clouddns.New(ctx, clouddns.Config{
    Project: "my-project",
    Ambient: true,  // Uses Workload Identity automatically
})
```

### Using Provider Factory

```go
import "github.com/jeremyhahn/go-xkms/pkg/acme/challenges/dns-01/providers"

provider, err := providers.NewProviderFromEnv(ctx, providers.NameCloudDNS)
```

## Setting Up Workload Identity

For GKE deployments:

```bash
# Enable Workload Identity on cluster
gcloud container clusters update my-cluster \
    --workload-pool=my-project.svc.id.goog

# Create Kubernetes service account
kubectl create serviceaccount dns-manager

# Create IAM service account
gcloud iam service-accounts create dns-manager

# Grant DNS permissions
gcloud projects add-iam-policy-binding my-project \
    --member="serviceAccount:dns-manager@my-project.iam.gserviceaccount.com" \
    --role="roles/dns.admin"

# Bind Kubernetes SA to IAM SA
gcloud iam service-accounts add-iam-policy-binding \
    dns-manager@my-project.iam.gserviceaccount.com \
    --role="roles/iam.workloadIdentityUser" \
    --member="serviceAccount:my-project.svc.id.goog[default/dns-manager]"

# Annotate Kubernetes SA
kubectl annotate serviceaccount dns-manager \
    iam.gke.io/gcp-service-account=dns-manager@my-project.iam.gserviceaccount.com
```

## Troubleshooting

### Authentication Failed

If authentication fails:

1. Verify service account JSON is valid
2. Check `GOOGLE_APPLICATION_CREDENTIALS` path exists
3. For ADC, run `gcloud auth application-default login`

### Zone Not Found

If the provider cannot find your managed zone:

1. Verify project ID is correct
2. Check that the managed zone exists
3. Try explicitly setting `GCE_ZONE_NAME`

### Permission Denied

If API calls fail with permission errors:

1. Verify service account has `dns.admin` role
2. Check IAM policy bindings
3. For Workload Identity, verify SA annotation

### Change Pending Too Long

Cloud DNS changes usually propagate quickly, but if timing out:

1. Check Google Cloud Console for change status
2. Increase `GCE_PROPAGATION_TIMEOUT`
3. Verify no conflicting records exist

## See Also

- [Cloud DNS Documentation](https://cloud.google.com/dns/docs)
- [Workload Identity](https://cloud.google.com/kubernetes-engine/docs/concepts/workload-identity)
- [Service Account Keys](https://cloud.google.com/iam/docs/keys-create-delete)
- [DNS-01 Providers Overview](README.md)
