# FROST Configuration Reference

This document covers all configuration options for the FROST backend.

## Config Structure

```go
type Config struct {
    // Storage for public components (group public key, verification shares, metadata)
    PublicStorage storage.Backend

    // Backend for secret key share storage (any go-keychain backend)
    SecretBackend types.Backend

    // Optional: Custom DKG implementation (if nil, uses TrustedDealer)
    DKG KeyGenerator

    // Default ciphersuite for new keys
    Algorithm types.FrostAlgorithm

    // This node's participant ID (1 to Total)
    ParticipantID uint32

    // Default threshold for new keys (minimum 2)
    DefaultThreshold int

    // Default total participants for new keys
    DefaultTotal int

    // Participant identifiers for new keys
    Participants []string

    // Storage for tracking used nonces (uses PublicStorage if nil)
    NonceStorage storage.Backend

    // Enable nonce reuse prevention (default: true)
    EnableNonceTracking bool
}
```

## Configuration Options

### PublicStorage (Required)

Storage backend for public components that don't require protection.

**Stored Components:**
- Group public key
- Verification shares for all participants
- Key metadata and attributes
- Used nonce markers (if NonceStorage not specified)
- Session state for signing

**Supported Backends:**
- File-based storage
- Memory storage (testing only)
- go-objstore backends (S3, GCS, etc.)
- Custom implementations

```go
// File-based storage
publicStorage := file.NewBackend("/var/lib/frost/public")

// Memory storage (testing)
publicStorage := memory.NewBackend()

// S3 storage via go-objstore
publicStorage := objstore.NewS3Backend(s3Config)
```

### SecretBackend (Required)

Backend for storing the secret key share. This should be a secure backend.

**Supported Backends:**

| Backend | Type | Security Level |
|---------|------|----------------|
| TPM2 | Hardware | High (PCR-bound) |
| PKCS#11 | Hardware | High (HSM) |
| SmartCard-HSM | Hardware | High |
| AWS KMS | Cloud | High (envelope encryption) |
| GCP KMS | Cloud | High |
| Azure Key Vault | Cloud | High |
| HashiCorp Vault | Software/Cloud | Medium-High |
| Software/PKCS#8 | Software | Medium |

```go
// TPM2 backend
tpmBackend, _ := tpm2.NewBackend(&tpm2.Config{
    Device: "/dev/tpmrm0",
    // ... TPM config
})

// PKCS#11 backend
pkcs11Backend, _ := pkcs11.NewBackend(&pkcs11.Config{
    Library:    "/usr/lib/softhsm/libsofthsm2.so",
    TokenLabel: "frost-token",
    PIN:        "1234",
})

// AWS KMS backend
awsBackend, _ := awskms.NewBackend(&awskms.Config{
    Region: "us-east-1",
    KeyID:  "alias/frost-master-key",
})

// Software backend (development)
softwareBackend, _ := pkcs8.NewBackend(&pkcs8.Config{
    Directory: "/var/lib/frost/secrets",
    Password:  []byte("secret-password"),
})
```

### DKG (Optional)

Custom Distributed Key Generation implementation. If nil, uses the built-in `TrustedDealer`.

```go
// Use trusted dealer (default)
config := &frost.Config{
    DKG: nil,  // Uses TrustedDealer
}

// Use custom DKG
config := &frost.Config{
    DKG: &MyCustomDKG{
        // Custom DKG configuration
    },
}
```

See [DKG Integration Guide](dkg-integration.md) for implementing custom DKG.

### Algorithm

Default ciphersuite for new keys.

| Algorithm | Value | Description |
|-----------|-------|-------------|
| Ed25519 | `types.FrostAlgorithmEd25519` | `FROST-Ed25519-SHA512` |
| ristretto255 | `types.FrostAlgorithmRistretto255` | `FROST-ristretto255-SHA512` |
| Ed448 | `types.FrostAlgorithmEd448` | `FROST-Ed448-SHAKE256` |
| P-256 | `types.FrostAlgorithmP256` | `FROST-P256-SHA256` |
| secp256k1 | `types.FrostAlgorithmSecp256k1` | `FROST-secp256k1-SHA256` |

```go
config := &frost.Config{
    Algorithm: types.FrostAlgorithmEd25519,
}
```

### ParticipantID

This node's participant identifier (1 to Total).

```go
config := &frost.Config{
    ParticipantID: 1,  // This is participant 1
}
```

### DefaultThreshold

Minimum number of participants required to sign (M in M-of-N).

**Constraints:**
- Minimum: 2
- Maximum: 255
- Must be ≤ DefaultTotal

```go
config := &frost.Config{
    DefaultThreshold: 3,  // 3-of-5 threshold
    DefaultTotal:     5,
}
```

### DefaultTotal

Total number of participants (N in M-of-N).

**Constraints:**
- Minimum: DefaultThreshold
- Maximum: 255

```go
config := &frost.Config{
    DefaultThreshold: 3,
    DefaultTotal:     5,  // 5 total participants
}
```

### Participants

Identifiers for each participant. Length must equal DefaultTotal.

```go
config := &frost.Config{
    DefaultTotal: 5,
    Participants: []string{
        "alice",
        "bob",
        "charlie",
        "dave",
        "eve",
    },
}
```

### NonceStorage (Optional)

Separate storage for used nonce tracking. If nil, uses PublicStorage.

```go
// Use separate nonce storage
config := &frost.Config{
    PublicStorage: mainStorage,
    NonceStorage:  fastStorage,  // Optimized for O(1) lookups
}

// Use PublicStorage for nonces (default)
config := &frost.Config{
    PublicStorage: mainStorage,
    NonceStorage:  nil,  // Uses PublicStorage
}
```

### EnableNonceTracking

Enable nonce reuse prevention. **Strongly recommended to keep enabled.**

```go
config := &frost.Config{
    EnableNonceTracking: true,  // Default: true
}
```

**Warning:** Disabling nonce tracking removes protection against nonce reuse attacks, which can lead to full private key recovery.

## FrostAttributes

Per-key attributes that can override Config defaults.

```go
type FrostAttributes struct {
    // Threshold for this key (overrides DefaultThreshold)
    Threshold int

    // Total participants for this key (overrides DefaultTotal)
    Total int

    // Algorithm for this key (overrides Config.Algorithm)
    Algorithm FrostAlgorithm

    // Participant identifiers for this key
    Participants []string

    // This participant's ID for this key
    ParticipantID uint32
}
```

### Usage in KeyAttributes

```go
attrs := &types.KeyAttributes{
    CN:      "my-frost-key",
    KeyType: types.KeyTypeFrost,
    FrostAttributes: &types.FrostAttributes{
        Threshold:     2,
        Total:         3,
        Algorithm:     types.FrostAlgorithmP256,
        Participants:  []string{"signer1", "signer2", "signer3"},
        ParticipantID: 1,
    },
}

privateKey, err := backend.GenerateKey(attrs)
```

## Complete Configuration Examples

### Development Configuration

```go
package main

import (
    "github.com/jeremyhahn/go-keychain/pkg/backend/frost"
    "github.com/jeremyhahn/go-keychain/pkg/storage/file"
    "github.com/jeremyhahn/go-keychain/pkg/storage/memory"
    "github.com/jeremyhahn/go-keychain/pkg/types"
)

func developmentConfig() *frost.Config {
    return &frost.Config{
        // Use file storage for public data
        PublicStorage: file.NewBackend("./frost-data/public"),

        // Use file storage for secrets (development only!)
        SecretBackend: file.NewBackend("./frost-data/secrets"),

        // Use trusted dealer
        DKG: nil,

        // Ed25519 for performance
        Algorithm: types.FrostAlgorithmEd25519,

        // Single participant for local testing
        ParticipantID:    1,
        DefaultThreshold: 2,
        DefaultTotal:     3,
        Participants:     []string{"dev1", "dev2", "dev3"},

        // Enable nonce tracking
        EnableNonceTracking: true,
    }
}
```

### Production Configuration (TPM2)

```go
package main

import (
    "github.com/jeremyhahn/go-keychain/pkg/backend/frost"
    "github.com/jeremyhahn/go-keychain/pkg/backend/tpm2"
    "github.com/jeremyhahn/go-keychain/pkg/storage/file"
    "github.com/jeremyhahn/go-keychain/pkg/types"
)

func productionTPMConfig() (*frost.Config, error) {
    // TPM2 backend for secrets
    tpmBackend, err := tpm2.NewBackend(&tpm2.Config{
        Device:        "/dev/tpmrm0",
        OwnerPassword: []byte(os.Getenv("TPM_OWNER_PASSWORD")),
    })
    if err != nil {
        return nil, err
    }

    return &frost.Config{
        // File storage for public data
        PublicStorage: file.NewBackend("/var/lib/frost/public"),

        // TPM2 for secrets
        SecretBackend: tpmBackend,

        // FIPS-compliant algorithm
        Algorithm: types.FrostAlgorithmP256,

        // 3-of-5 threshold
        ParticipantID:    1,
        DefaultThreshold: 3,
        DefaultTotal:     5,
        Participants: []string{
            "node-east-1",
            "node-east-2",
            "node-west-1",
            "node-west-2",
            "node-central-1",
        },

        EnableNonceTracking: true,
    }, nil
}
```

### Production Configuration (AWS KMS)

```go
package main

import (
    "github.com/jeremyhahn/go-keychain/pkg/backend/awskms"
    "github.com/jeremyhahn/go-keychain/pkg/backend/frost"
    "github.com/jeremyhahn/go-keychain/pkg/types"
    "github.com/jeremyhahn/go-objstore/pkg/s3"
)

func productionAWSConfig() (*frost.Config, error) {
    // S3 for public data
    s3Storage, err := s3.NewBackend(&s3.Config{
        Bucket: "my-frost-public",
        Region: "us-east-1",
    })
    if err != nil {
        return nil, err
    }

    // AWS KMS for secrets
    kmsBackend, err := awskms.NewBackend(&awskms.Config{
        Region: "us-east-1",
        KeyID:  "alias/frost-master-key",
    })
    if err != nil {
        return nil, err
    }

    return &frost.Config{
        PublicStorage: s3Storage,
        SecretBackend: kmsBackend,
        Algorithm:     types.FrostAlgorithmP256,

        ParticipantID:    1,
        DefaultThreshold: 3,
        DefaultTotal:     5,
        Participants: []string{
            "signer-1",
            "signer-2",
            "signer-3",
            "signer-4",
            "signer-5",
        },

        EnableNonceTracking: true,
    }, nil
}
```

### Multi-Cloud Configuration

```go
package main

import (
    "github.com/jeremyhahn/go-keychain/pkg/backend/frost"
    "github.com/jeremyhahn/go-keychain/pkg/backend/vault"
    "github.com/jeremyhahn/go-keychain/pkg/storage/file"
    "github.com/jeremyhahn/go-keychain/pkg/types"
)

func multiCloudConfig() (*frost.Config, error) {
    // HashiCorp Vault for secrets (works across clouds)
    vaultBackend, err := vault.NewBackend(&vault.Config{
        Address: "https://vault.example.com:8200",
        Token:   os.Getenv("VAULT_TOKEN"),
        Path:    "frost/secrets",
    })
    if err != nil {
        return nil, err
    }

    return &frost.Config{
        PublicStorage: file.NewBackend("/var/lib/frost/public"),
        SecretBackend: vaultBackend,
        Algorithm:     types.FrostAlgorithmEd25519,

        ParticipantID:    1,
        DefaultThreshold: 3,
        DefaultTotal:     5,

        EnableNonceTracking: true,
    }, nil
}
```

## Environment Variables

The FROST backend respects these environment variables when applicable:

| Variable | Description | Used By |
|----------|-------------|---------|
| `TPM_DEVICE` | TPM device path | TPM2 backend |
| `TPM_OWNER_PASSWORD` | TPM owner password | TPM2 backend |
| `PKCS11_LIBRARY` | PKCS#11 library path | PKCS#11 backend |
| `PKCS11_PIN` | Token PIN | PKCS#11 backend |
| `AWS_REGION` | AWS region | AWS KMS backend |
| `AWS_KMS_KEY_ID` | KMS key ID/alias | AWS KMS backend |
| `GOOGLE_APPLICATION_CREDENTIALS` | GCP credentials | GCP KMS backend |
| `AZURE_TENANT_ID` | Azure tenant | Azure KV backend |
| `AZURE_CLIENT_ID` | Azure client | Azure KV backend |
| `VAULT_ADDR` | Vault address | Vault backend |
| `VAULT_TOKEN` | Vault token | Vault backend |

## Validation Rules

The FROST backend validates configuration on initialization:

1. **PublicStorage** must not be nil
2. **SecretBackend** must not be nil
3. **ParticipantID** must be 1 to DefaultTotal (if DefaultTotal > 0)
4. **DefaultThreshold** must be ≥ 2 (if specified)
5. **DefaultTotal** must be ≥ DefaultThreshold (if specified)
6. **Participants** length must equal DefaultTotal (if both specified)
7. **Algorithm** must be a valid FrostAlgorithm constant
