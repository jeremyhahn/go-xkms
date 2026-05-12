# AWS Route53 DNS Provider

The Route53 provider manages DNS-01 challenge records in AWS Route53 hosted zones.

## Authentication Methods

### Static Credentials

Direct access key ID and secret access key.

```go
provider, err := route53.New(ctx, route53.Config{
    AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
    SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    Region:          "us-east-1",
})
```

### Ambient Credentials

Automatically uses the AWS credential chain:

1. Environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`)
2. Shared credentials file (`~/.aws/credentials`)
3. EC2 instance profile
4. ECS task role
5. EKS IRSA (IAM Roles for Service Accounts)

```go
provider, err := route53.New(ctx, route53.Config{
    Region:  "us-east-1",
    Ambient: true,
})
```

### STS Assume Role

For cross-account access, assume an IAM role:

```go
provider, err := route53.New(ctx, route53.Config{
    Region:  "us-east-1",
    Ambient: true,
    Role:    "arn:aws:iam::123456789012:role/Route53Access",
})
```

### Web Identity (IRSA)

For EKS workloads using IAM Roles for Service Accounts:

```go
provider, err := route53.New(ctx, route53.Config{
    Region:           "us-east-1",
    Role:             "arn:aws:iam::123456789012:role/Route53Access",
    WebIdentityToken: os.Getenv("AWS_WEB_IDENTITY_TOKEN_FILE"),
})
```

## Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `AWS_ACCESS_KEY_ID` | AWS access key ID | No (ambient) |
| `AWS_SECRET_ACCESS_KEY` | AWS secret access key | No (ambient) |
| `AWS_REGION` | AWS region | No |
| `AWS_HOSTED_ZONE_ID` | Route53 hosted zone ID | No (auto-discover) |
| `AWS_PROPAGATION_TIMEOUT` | DNS propagation timeout | No (default: 120s) |
| `AWS_POLLING_INTERVAL` | Propagation check interval | No (default: 4s) |
| `AWS_TTL` | DNS record TTL | No (default: 10) |

Route53-specific variables take precedence:
- `ROUTE53_PROPAGATION_TIMEOUT`
- `ROUTE53_POLLING_INTERVAL`
- `ROUTE53_TTL`

## Configuration

```go
type Config struct {
    // Authentication
    AccessKeyID     string  // AWS access key ID
    SecretAccessKey string  // AWS secret access key
    Region          string  // AWS region

    // Role assumption
    Role             string  // IAM role ARN for cross-account
    WebIdentityToken string  // Web identity token for IRSA

    // Ambient credentials
    Ambient bool  // Use AWS credential chain

    // Zone configuration
    HostedZoneID string    // Pre-configured zone ID
    Nameservers  []string  // Custom nameservers for zone lookup

    // Timeouts
    PropagationTimeout time.Duration  // Default: 120s
    PollingInterval    time.Duration  // Default: 4s
    HTTPTimeout        time.Duration  // Default: 30s

    // DNS settings
    TTL int  // Record TTL (default: 10)
}
```

## Required IAM Permissions

Minimum IAM policy for Route53 DNS-01 challenges:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "route53:GetChange",
                "route53:ChangeResourceRecordSets"
            ],
            "Resource": [
                "arn:aws:route53:::hostedzone/YOUR_ZONE_ID",
                "arn:aws:route53:::change/*"
            ]
        },
        {
            "Effect": "Allow",
            "Action": [
                "route53:ListHostedZonesByName"
            ],
            "Resource": "*"
        }
    ]
}
```

For automatic zone discovery, `ListHostedZonesByName` on all resources is required.

## Usage Examples

### With Environment Variables

```bash
export AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"
export AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
export AWS_REGION="us-east-1"
```

```go
provider, err := route53.NewFromEnv(ctx)
if err != nil {
    return err
}
```

### With EC2 Instance Profile

```go
provider, err := route53.New(ctx, route53.Config{
    Region:  "us-east-1",
    Ambient: true,
})
```

### Using Provider Factory

```go
import "github.com/jeremyhahn/go-trusted-ca/pkg/acme/challenges/dns-01/providers"

provider, err := providers.NewProviderFromEnv(ctx, providers.NameRoute53)
```

## Troubleshooting

### Zone Not Found

If the provider cannot find your hosted zone:

1. Verify IAM permissions include `ListHostedZonesByName`
2. Check that the domain matches an existing public hosted zone
3. Try explicitly setting `AWS_HOSTED_ZONE_ID`

### Access Denied

If API calls fail with access denied:

1. Verify IAM policy includes required actions
2. Check resource ARNs are correctly scoped
3. For cross-account, verify trust relationship on the role

### Propagation Issues

Route53 changes can take 60+ seconds to propagate:

1. The provider waits for Route53's `INSYNC` status
2. Increase `ROUTE53_PROPAGATION_TIMEOUT` if needed
3. Monitor change status in AWS Console

## See Also

- [AWS Route53 Documentation](https://docs.aws.amazon.com/route53/)
- [IAM Roles for Service Accounts](https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html)
- [DNS-01 Providers Overview](README.md)
