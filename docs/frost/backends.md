# FROST Backend Integration Guide

This guide covers how to configure different go-keychain backends for storing FROST secret key shares.

## Backend Overview

| Backend | Type | Security | Latency | Use Case |
|---------|------|----------|---------|----------|
| TPM2 | Hardware | High | Low | On-premise servers |
| PKCS#11 | Hardware | High | Low | Enterprise HSM |
| SmartCard-HSM | Hardware | High | Low | Portable tokens |
| AWS KMS | Cloud | High | Medium | AWS deployments |
| GCP KMS | Cloud | High | Medium | GCP deployments |
| Azure Key Vault | Cloud | High | Medium | Azure deployments |
| HashiCorp Vault | Software | Medium-High | Medium | Multi-cloud |
| Software/PKCS#8 | Software | Medium | Low | Development |

## TPM2 Backend

Trusted Platform Module 2.0 provides hardware-backed key protection with PCR binding.

### Prerequisites

```bash
# Install TPM2 tools
sudo apt install tpm2-tools

# Verify TPM availability
tpm2_getcap properties-fixed
```

### Configuration

```go
import (
    "github.com/jeremyhahn/go-keychain/pkg/backend/frost"
    "github.com/jeremyhahn/go-keychain/pkg/backend/tpm2"
    "github.com/jeremyhahn/go-keychain/pkg/storage/file"
)

func tpm2Config() (*frost.Config, error) {
    // Create TPM2 backend
    tpmBackend, err := tpm2.NewBackend(&tpm2.Config{
        // TPM device path
        Device: "/dev/tpmrm0",

        // Owner hierarchy password (optional)
        OwnerPassword: []byte(os.Getenv("TPM_OWNER_PASSWORD")),

        // PCR selection for key sealing (optional)
        PCRSelection: &tpm2.PCRSelection{
            Hash: tpm2.TPMAlgSHA256,
            PCRs: []int{0, 1, 2, 3, 7}, // Boot measurements
        },

        // Key storage hierarchy
        Hierarchy: tpm2.TPMRHOwner,
    })
    if err != nil {
        return nil, err
    }

    return &frost.Config{
        PublicStorage:       file.NewBackend("/var/lib/frost/public"),
        SecretBackend:       tpmBackend,
        Algorithm:           types.FrostAlgorithmP256,
        EnableNonceTracking: true,
    }, nil
}
```

### CLI Usage

```bash
# Generate keys with TPM storage
keychain frost keygen \
  --secret-backend tpm2 \
  --threshold 3 \
  --total 5 \
  --participants "node1,node2,node3,node4,node5"
```

### Security Features

- **Sealed Storage**: Keys are sealed to specific PCR values
- **Hardware Protection**: Keys never leave the TPM in plaintext
- **Attestation**: Remote attestation of key provenance
- **Boot Binding**: Keys become inaccessible if boot config changes

## PKCS#11 Backend

For Hardware Security Modules (HSMs) supporting the PKCS#11 standard.

### Prerequisites

```bash
# Install SoftHSM for testing
sudo apt install softhsm2

# Initialize token
softhsm2-util --init-token --slot 0 --label "frost-token" --pin 1234 --so-pin 12345678
```

### Configuration

```go
import (
    "github.com/jeremyhahn/go-keychain/pkg/backend/frost"
    "github.com/jeremyhahn/go-keychain/pkg/backend/pkcs11"
    "github.com/jeremyhahn/go-keychain/pkg/storage/file"
)

func pkcs11Config() (*frost.Config, error) {
    // Create PKCS#11 backend
    hsmBackend, err := pkcs11.NewBackend(&pkcs11.Config{
        // PKCS#11 library path
        Library: "/usr/lib/softhsm/libsofthsm2.so",

        // Token configuration
        TokenLabel: "frost-token",
        PIN:        os.Getenv("HSM_PIN"),

        // Slot selection (optional, uses first available if not set)
        SlotID: 0,
    })
    if err != nil {
        return nil, err
    }

    return &frost.Config{
        PublicStorage:       file.NewBackend("/var/lib/frost/public"),
        SecretBackend:       hsmBackend,
        Algorithm:           types.FrostAlgorithmP256,
        EnableNonceTracking: true,
    }, nil
}
```

### Supported HSMs

| HSM | Library Path | Notes |
|-----|--------------|-------|
| SoftHSM2 | `/usr/lib/softhsm/libsofthsm2.so` | Testing only |
| Thales Luna | `/usr/lib/libCryptoki2_64.so` | Production |
| AWS CloudHSM | `/opt/cloudhsm/lib/libcloudhsm_pkcs11.so` | AWS |
| Yubico YubiHSM2 | `/usr/lib/libyubihsm_pkcs11.so` | Edge devices |
| Utimaco | `/opt/utimaco/lib/libcs_pkcs11_R2.so` | Enterprise |

### CLI Usage

```bash
# Generate keys with HSM storage
keychain frost keygen \
  --secret-backend pkcs11 \
  --pkcs11-library /usr/lib/softhsm/libsofthsm2.so \
  --pkcs11-token frost-token \
  --threshold 3 \
  --total 5
```

## AWS KMS Backend

For AWS deployments using Key Management Service.

### Prerequisites

```bash
# Configure AWS credentials
aws configure

# Create KMS key for envelope encryption
aws kms create-key --description "FROST master key"
```

### Configuration

```go
import (
    "github.com/jeremyhahn/go-keychain/pkg/backend/awskms"
    "github.com/jeremyhahn/go-keychain/pkg/backend/frost"
    "github.com/jeremyhahn/go-objstore/pkg/s3"
)

func awsConfig() (*frost.Config, error) {
    // S3 for public storage
    s3Storage, err := s3.NewBackend(&s3.Config{
        Bucket: "my-frost-public-bucket",
        Region: "us-east-1",
        Prefix: "frost/",
    })
    if err != nil {
        return nil, err
    }

    // AWS KMS for secret storage
    kmsBackend, err := awskms.NewBackend(&awskms.Config{
        Region: "us-east-1",

        // KMS key for envelope encryption
        KeyID: "alias/frost-master-key",

        // Optional: Custom endpoint for LocalStack testing
        // Endpoint: "http://localhost:4566",
    })
    if err != nil {
        return nil, err
    }

    return &frost.Config{
        PublicStorage:       s3Storage,
        SecretBackend:       kmsBackend,
        Algorithm:           types.FrostAlgorithmP256,
        EnableNonceTracking: true,
    }, nil
}
```

### IAM Policy

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "kms:Encrypt",
                "kms:Decrypt",
                "kms:GenerateDataKey"
            ],
            "Resource": "arn:aws:kms:us-east-1:123456789012:key/frost-master-key"
        },
        {
            "Effect": "Allow",
            "Action": [
                "s3:GetObject",
                "s3:PutObject",
                "s3:DeleteObject",
                "s3:ListBucket"
            ],
            "Resource": [
                "arn:aws:s3:::my-frost-public-bucket",
                "arn:aws:s3:::my-frost-public-bucket/*"
            ]
        }
    ]
}
```

### CLI Usage

```bash
# Generate keys with AWS KMS
keychain frost keygen \
  --secret-backend awskms \
  --aws-region us-east-1 \
  --aws-kms-key alias/frost-master-key \
  --threshold 3 \
  --total 5
```

## GCP KMS Backend

For Google Cloud Platform deployments.

### Prerequisites

```bash
# Authenticate with GCP
gcloud auth application-default login

# Create key ring and key
gcloud kms keyrings create frost-keyring --location global
gcloud kms keys create frost-master-key \
  --keyring frost-keyring \
  --location global \
  --purpose encryption
```

### Configuration

```go
import (
    "github.com/jeremyhahn/go-keychain/pkg/backend/frost"
    "github.com/jeremyhahn/go-keychain/pkg/backend/gcpkms"
    "github.com/jeremyhahn/go-objstore/pkg/gcs"
)

func gcpConfig() (*frost.Config, error) {
    // GCS for public storage
    gcsStorage, err := gcs.NewBackend(&gcs.Config{
        Bucket:    "my-frost-public-bucket",
        Prefix:    "frost/",
        ProjectID: "my-project",
    })
    if err != nil {
        return nil, err
    }

    // GCP KMS for secret storage
    kmsBackend, err := gcpkms.NewBackend(&gcpkms.Config{
        ProjectID: "my-project",
        Location:  "global",
        KeyRing:   "frost-keyring",
        KeyName:   "frost-master-key",
    })
    if err != nil {
        return nil, err
    }

    return &frost.Config{
        PublicStorage:       gcsStorage,
        SecretBackend:       kmsBackend,
        Algorithm:           types.FrostAlgorithmP256,
        EnableNonceTracking: true,
    }, nil
}
```

### CLI Usage

```bash
# Generate keys with GCP KMS
keychain frost keygen \
  --secret-backend gcpkms \
  --gcp-project my-project \
  --gcp-keyring frost-keyring \
  --gcp-key frost-master-key \
  --threshold 3 \
  --total 5
```

## Azure Key Vault Backend

For Microsoft Azure deployments.

### Prerequisites

```bash
# Login to Azure
az login

# Create Key Vault
az keyvault create \
  --name frost-keyvault \
  --resource-group my-resource-group \
  --location eastus
```

### Configuration

```go
import (
    "github.com/jeremyhahn/go-keychain/pkg/backend/azurekv"
    "github.com/jeremyhahn/go-keychain/pkg/backend/frost"
    "github.com/jeremyhahn/go-objstore/pkg/azureblob"
)

func azureConfig() (*frost.Config, error) {
    // Azure Blob for public storage
    blobStorage, err := azureblob.NewBackend(&azureblob.Config{
        AccountName:   "mystorageaccount",
        ContainerName: "frost-public",
    })
    if err != nil {
        return nil, err
    }

    // Azure Key Vault for secret storage
    kvBackend, err := azurekv.NewBackend(&azurekv.Config{
        VaultURL: "https://frost-keyvault.vault.azure.net/",

        // Authentication (uses DefaultAzureCredential)
        TenantID: os.Getenv("AZURE_TENANT_ID"),
        ClientID: os.Getenv("AZURE_CLIENT_ID"),
    })
    if err != nil {
        return nil, err
    }

    return &frost.Config{
        PublicStorage:       blobStorage,
        SecretBackend:       kvBackend,
        Algorithm:           types.FrostAlgorithmP256,
        EnableNonceTracking: true,
    }, nil
}
```

### CLI Usage

```bash
# Generate keys with Azure Key Vault
keychain frost keygen \
  --secret-backend azurekv \
  --azure-vault-url https://frost-keyvault.vault.azure.net/ \
  --threshold 3 \
  --total 5
```

## HashiCorp Vault Backend

For multi-cloud and on-premise deployments.

### Prerequisites

```bash
# Start Vault (dev mode for testing)
vault server -dev

# Enable transit engine
vault secrets enable transit

# Create encryption key
vault write -f transit/keys/frost-master
```

### Configuration

```go
import (
    "github.com/jeremyhahn/go-keychain/pkg/backend/frost"
    "github.com/jeremyhahn/go-keychain/pkg/backend/vault"
    "github.com/jeremyhahn/go-keychain/pkg/storage/file"
)

func vaultConfig() (*frost.Config, error) {
    // HashiCorp Vault for secret storage
    vaultBackend, err := vault.NewBackend(&vault.Config{
        Address: "https://vault.example.com:8200",

        // Authentication
        Token: os.Getenv("VAULT_TOKEN"),
        // Or use AppRole:
        // RoleID:   os.Getenv("VAULT_ROLE_ID"),
        // SecretID: os.Getenv("VAULT_SECRET_ID"),

        // Transit engine path
        TransitPath: "transit",
        KeyName:     "frost-master",

        // Secret storage path
        SecretPath: "secret/data/frost",
    })
    if err != nil {
        return nil, err
    }

    return &frost.Config{
        PublicStorage:       file.NewBackend("/var/lib/frost/public"),
        SecretBackend:       vaultBackend,
        Algorithm:           types.FrostAlgorithmEd25519,
        EnableNonceTracking: true,
    }, nil
}
```

### Vault Policy

```hcl
# frost-policy.hcl
path "transit/encrypt/frost-master" {
  capabilities = ["update"]
}

path "transit/decrypt/frost-master" {
  capabilities = ["update"]
}

path "secret/data/frost/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
```

### CLI Usage

```bash
# Generate keys with Vault
keychain frost keygen \
  --secret-backend vault \
  --vault-addr https://vault.example.com:8200 \
  --vault-token $VAULT_TOKEN \
  --threshold 3 \
  --total 5
```

## Software Backend (Development)

For development and testing only. **Not recommended for production.**

### Configuration

```go
import (
    "github.com/jeremyhahn/go-keychain/pkg/backend/frost"
    "github.com/jeremyhahn/go-keychain/pkg/backend/pkcs8"
    "github.com/jeremyhahn/go-keychain/pkg/storage/file"
)

func softwareConfig() (*frost.Config, error) {
    // PKCS#8 encrypted file storage
    secretBackend, err := pkcs8.NewBackend(&pkcs8.Config{
        Directory: "./frost-secrets",
        Password:  []byte(os.Getenv("FROST_SECRET_PASSWORD")),
    })
    if err != nil {
        return nil, err
    }

    return &frost.Config{
        PublicStorage:       file.NewBackend("./frost-public"),
        SecretBackend:       secretBackend,
        Algorithm:           types.FrostAlgorithmEd25519,
        EnableNonceTracking: true,
    }, nil
}
```

### CLI Usage

```bash
# Generate keys with software storage
keychain frost keygen \
  --secret-backend software \
  --threshold 2 \
  --total 3 \
  --participants "dev1,dev2,dev3"
```

## Custom Storage Adapters

Implement `storage.Backend` for custom storage solutions.

```go
type Backend interface {
    Get(key string) ([]byte, error)
    Put(key string, value []byte, opts *Options) error
    Delete(key string) error
    Exists(key string) (bool, error)
    List(prefix string) ([]string, error)
    Close() error
}
```

### Example: Redis Storage

```go
type RedisBackend struct {
    client *redis.Client
    prefix string
}

func (r *RedisBackend) Get(key string) ([]byte, error) {
    return r.client.Get(context.Background(), r.prefix+key).Bytes()
}

func (r *RedisBackend) Put(key string, value []byte, opts *storage.Options) error {
    return r.client.Set(context.Background(), r.prefix+key, value, 0).Err()
}

func (r *RedisBackend) Delete(key string) error {
    return r.client.Del(context.Background(), r.prefix+key).Err()
}

func (r *RedisBackend) Exists(key string) (bool, error) {
    n, err := r.client.Exists(context.Background(), r.prefix+key).Result()
    return n > 0, err
}

func (r *RedisBackend) List(prefix string) ([]string, error) {
    keys, err := r.client.Keys(context.Background(), r.prefix+prefix+"*").Result()
    if err != nil {
        return nil, err
    }
    // Strip prefix from keys
    result := make([]string, len(keys))
    for i, k := range keys {
        result[i] = strings.TrimPrefix(k, r.prefix)
    }
    return result, nil
}

func (r *RedisBackend) Close() error {
    return r.client.Close()
}

// Usage
config := &frost.Config{
    PublicStorage: &RedisBackend{
        client: redis.NewClient(&redis.Options{Addr: "localhost:6379"}),
        prefix: "frost:public:",
    },
    SecretBackend: tpmBackend, // Still use hardware for secrets
}
```

## Backend Comparison Matrix

| Feature | TPM2 | PKCS#11 | AWS KMS | GCP KMS | Azure KV | Vault | Software |
|---------|------|---------|---------|---------|----------|-------|----------|
| Hardware Protection | Yes | Yes | Yes* | Yes* | Yes* | No | No |
| FIPS 140-2 | L2+ | Varies | L2 | L2 | L2 | No | No |
| Key Export | No | Varies | No | No | No | Yes | Yes |
| Multi-Region | No | No | Yes | Yes | Yes | Yes | No |
| Offline Operation | Yes | Yes | No | No | No | No | Yes |
| Cost | $0 | $$$ | $ | $ | $ | $$ | $0 |

*Cloud KMS uses HSMs internally but keys transit over network
