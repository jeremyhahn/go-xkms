# GCP KMS Backend Documentation

## Overview

The GCP (Google Cloud Platform) KMS (Key Management Service) backend provides cloud-based cryptographic key management using Google Cloud's fully managed service. This backend offers FIPS 140-2 Level 3 validated Hardware Security Modules (HSMs) for key storage and cryptographic operations, making it ideal for production workloads requiring the highest levels of security and regulatory compliance.

GCP KMS handles key generation, automatic rotation, and lifecycle management while providing centralized access control through Cloud IAM. All cryptographic operations are performed server-side within Google's infrastructure, ensuring keys never leave the KMS service boundary. The service supports both software-protected and HSM-protected keys, multi-region key replication, and seamless integration with other Google Cloud services.

## Features and Capabilities

### Key Management

- Automatic key generation with Google-managed entropy sources
- Customer-managed automatic rotation policies
- Key versioning with automatic version management
- Multi-region key replication for disaster recovery
- Automatic key material backup and durability
- Key import from external sources (BYOK)
- Scheduled key destruction with recovery period

### Cryptographic Operations

- Asymmetric sign/verify for digital signatures
- Asymmetric encrypt/decrypt for data protection
- Raw RSA decrypt for migration scenarios
- Cloud External Key Manager (EKM) support
- Hardware-backed key operations
- FIPS 140-2 Level 3 validated HSMs

### Security Features

- FIPS 140-2 Level 3 compliance (HSM protection level)
- Automatic key material protection
- Cloud Audit Logs integration
- VPC Service Controls for network security
- Customer-managed encryption keys (CMEK)
- External key management (EKM)
- Data residency controls
- IAM-based access control with fine-grained permissions

### Operational Features

- Global availability with multi-region support
- Automatic scaling and high availability
- Pay-per-use pricing model
- Cloud Monitoring integration
- Automated backup and disaster recovery
- Key usage audit trails
- Integrated with Google Cloud services

## Resource Hierarchy

GCP KMS uses a hierarchical resource structure:

```
Project: my-project
  └─ Location: us-central1 (or global, us, eu, asia)
      └─ KeyRing: my-keyring
          └─ CryptoKey: my-signing-key
              ├─ CryptoKeyVersion: 1 (primary)
              ├─ CryptoKeyVersion: 2
              └─ CryptoKeyVersion: 3
```

Resource names follow this format:
```
projects/{project}/locations/{location}/keyRings/{keyring}/cryptoKeys/{key}/cryptoKeyVersions/{version}
```

### Location Types

- **Global**: Keys accessible from anywhere
- **Regional**: Single region (e.g., us-central1, europe-west1)
- **Multi-regional**: Automatic replication across regions (us, eu, asia)
- **Dual-regional**: Two specific regions (e.g., nam4, eur4)

## Configuration Options

### Config Structure

```go
type Config struct {
    // GCP Project ID
    ProjectID string

    // Location for key resources (e.g., "us-central1", "global")
    Location string

    // KeyRing name for organizing keys
    KeyRing string

    // Authentication credentials path (optional)
    CredentialsFile string

    // Protection level: SOFTWARE or HSM
    ProtectionLevel string

    // Existing KMS client (optional)
    Client KMSClient
}
```

### Configuration Parameters

**ProjectID** (required)
- Google Cloud Project ID where keys will be created
- Example: `"my-project-123456"`
- Must have KMS API enabled
- Billing must be enabled

**Location** (required)
- Geographic location for key storage
- Regional: `"us-central1"`, `"europe-west1"`, `"asia-east1"`
- Multi-regional: `"us"`, `"eu"`, `"asia"`
- Global: `"global"`
- Affects latency, compliance, and pricing

**KeyRing** (required)
- Logical grouping for keys
- Example: `"production-keys"`, `"dev-keys"`
- Cannot be deleted once created
- Used for organizing keys and IAM policies

**CredentialsFile** (optional)
- Path to service account JSON key file
- Example: `"/path/to/service-account.json"`
- If not provided, uses Application Default Credentials
- Service account needs Cloud KMS CryptoKey Signer/Verifier role

**ProtectionLevel** (optional)
- `"SOFTWARE"`: Software-protected keys (default, lower cost)
- `"HSM"`: FIPS 140-2 Level 3 HSM-protected keys
- HSM provides higher security at higher cost
- Cannot be changed after key creation

**Client** (optional)
- Pre-initialized KMS client
- Allows external client management
- Overrides CredentialsFile if provided

## Authentication Methods

### Application Default Credentials (Recommended)

```go
// Uses Application Default Credentials automatically
config := &gcpkms.Config{
    ProjectID: "my-project",
    Location:  "us-central1",
    KeyRing:   "production",
}

store, err := gcpkms.NewBackend(config)
```

Application Default Credentials checks in this order:
1. `GOOGLE_APPLICATION_CREDENTIALS` environment variable
2. Google Cloud SDK credentials (`gcloud auth application-default login`)
3. Compute Engine/GKE/Cloud Run metadata server
4. App Engine metadata server

### Service Account Key File

```go
config := &gcpkms.Config{
    ProjectID:       "my-project",
    Location:        "us-central1",
    KeyRing:         "production",
    CredentialsFile: "/path/to/service-account.json",
}

store, err := gcpkms.NewBackend(config)
```

### Environment Variable

```bash
export GOOGLE_APPLICATION_CREDENTIALS="/path/to/service-account.json"
```

```go
config := &gcpkms.Config{
    ProjectID: "my-project",
    Location:  "us-central1",
    KeyRing:   "production",
}

store, err := gcpkms.NewBackend(config)
```

### Workload Identity (GKE)

For GKE clusters with Workload Identity:

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: my-app
  annotations:
    iam.gke.io/gcp-service-account: my-app@my-project.iam.gserviceaccount.com
```

```go
// No credentials needed, uses Workload Identity
config := &gcpkms.Config{
    ProjectID: "my-project",
    Location:  "us-central1",
    KeyRing:   "production",
}

store, err := gcpkms.NewBackend(config)
```

## IAM Permissions

### Required Roles

For signing operations:
```
roles/cloudkms.signerVerifier
```

For key management:
```
roles/cloudkms.admin
```

For read-only access:
```
roles/cloudkms.viewer
```

### Custom IAM Policy

Create a custom role with minimal permissions:

```bash
gcloud iam roles create kmsOperator --project=my-project \
  --title="KMS Operator" \
  --description="Minimal KMS permissions for signing" \
  --permissions=cloudkms.cryptoKeyVersions.useToSign,cloudkms.cryptoKeyVersions.viewPublicKey,cloudkms.cryptoKeys.get
```

Bind to service account:

```bash
gcloud kms keys add-iam-policy-binding my-key \
  --location=us-central1 \
  --keyring=production \
  --member=serviceAccount:my-app@my-project.iam.gserviceaccount.com \
  --role=roles/cloudkms.signerVerifier
```

### Key-Level IAM

Grant permissions on specific keys:

```bash
gcloud kms keys add-iam-policy-binding signing-key \
  --location=us-central1 \
  --keyring=production \
  --member=serviceAccount:app@project.iam.gserviceaccount.com \
  --role=roles/cloudkms.signerVerifier
```

## Supported Algorithms

### RSA Signing

| Algorithm | Key Size | Signature Scheme | Hash Functions |
|-----------|----------|------------------|----------------|
| RSA_SIGN_PKCS1_2048_SHA256 | 2048 bits | PKCS#1 v1.5 | SHA-256 |
| RSA_SIGN_PKCS1_3072_SHA256 | 3072 bits | PKCS#1 v1.5 | SHA-256 |
| RSA_SIGN_PKCS1_4096_SHA256 | 4096 bits | PKCS#1 v1.5 | SHA-256 |
| RSA_SIGN_PKCS1_4096_SHA512 | 4096 bits | PKCS#1 v1.5 | SHA-512 |
| RSA_SIGN_PSS_2048_SHA256 | 2048 bits | PSS | SHA-256 |
| RSA_SIGN_PSS_3072_SHA256 | 3072 bits | PSS | SHA-256 |
| RSA_SIGN_PSS_4096_SHA256 | 4096 bits | PSS | SHA-256 |
| RSA_SIGN_PSS_4096_SHA512 | 4096 bits | PSS | SHA-512 |

**Note**: All 10 backends support RSA 2048, 3072, and 4096-bit keys with full integration test coverage (151/151 tests passing).

### RSA Encryption

| Algorithm | Key Size | Encryption Scheme |
|-----------|----------|-------------------|
| RSA_DECRYPT_OAEP_2048_SHA256 | 2048 bits | OAEP with SHA-256 |
| RSA_DECRYPT_OAEP_3072_SHA256 | 3072 bits | OAEP with SHA-256 |
| RSA_DECRYPT_OAEP_4096_SHA256 | 4096 bits | OAEP with SHA-256 |
| RSA_DECRYPT_OAEP_4096_SHA512 | 4096 bits | OAEP with SHA-512 |

### Elliptic Curve Signing

| Algorithm | Curve | Key Size | Hash Function |
|-----------|-------|----------|---------------|
| EC_SIGN_P256_SHA256 | P-256 (secp256r1) | 256 bits | SHA-256 |
| EC_SIGN_P384_SHA384 | P-384 (secp384r1) | 384 bits | SHA-384 |
| EC_SIGN_SECP256K1_SHA256 | secp256k1 | 256 bits | SHA-256 |

**Note**: All 10 backends support ECDSA P-256, P-384, and P-521 curves with full integration test coverage (151/151 tests passing).

### Not Supported

- Ed25519 (use EC_SIGN_P256_SHA256 instead)
- Symmetric encryption (use Google Cloud encryption instead)

## Complete Working Examples

### Example 1: Basic Setup and Key Generation

```go
package main

import (
    "context"
    "crypto"
    "crypto/sha256"
    "fmt"
    "log"

    "github.com/jeremyhahn/go-keychain/pkg/backend"
    "github.com/jeremyhahn/go-keychain/pkg/backend/gcpkms"
)

func main() {
    ctx := context.Background()

    // Configure GCP KMS backend
    config := &gcpkms.Config{
        ProjectID: "my-project-123456",
        Location:  "us-central1",
        KeyRing:   "production-keys",
    }

    store, err := gcpkms.NewBackend(config)
    if err != nil {
        log.Fatalf("Failed to initialize GCP KMS: %v", err)
    }
    defer store.Close(ctx)

    // Generate RSA signing key
    keyID := "api-signing-key"
    params := &backend.KeyParams{
        Algorithm: backend.AlgorithmRSA,
        KeySize:   2048,
    }

    if err := store.GenerateKey(ctx, keyID, params); err != nil {
        log.Fatalf("Failed to generate key: %v", err)
    }

    fmt.Println("RSA key generated in GCP KMS")

    // Sign data
    data := []byte("Hello, GCP KMS!")
    hash := sha256.Sum256(data)

    signature, err := store.Sign(ctx, keyID, hash[:], crypto.SHA256)
    if err != nil {
        log.Fatalf("Failed to sign: %v", err)
    }

    fmt.Printf("Signature created: %d bytes\n", len(signature))

    // Get public key
    publicKey, err := store.GetPublicKey(ctx, keyID)
    if err != nil {
        log.Fatalf("Failed to get public key: %v", err)
    }

    fmt.Printf("Public key retrieved: %T\n", publicKey)
}
```

### Example 2: HSM-Protected Keys

```go
func hsmProtectedExample() {
    ctx := context.Background()

    config := &gcpkms.Config{
        ProjectID:       "my-project",
        Location:        "us-central1",
        KeyRing:         "hsm-keys",
        ProtectionLevel: "HSM", // FIPS 140-2 Level 3
    }

    store, err := gcpkms.NewBackend(config)
    if err != nil {
        log.Fatal(err)
    }
    defer store.Close(ctx)

    // Generate HSM-protected key
    params := &backend.KeyParams{
        Algorithm: backend.AlgorithmRSA,
        KeySize:   4096,
    }

    if err := store.GenerateKey(ctx, "hsm-signing-key", params); err != nil {
        log.Fatal(err)
    }

    fmt.Println("HSM-protected key generated")
}
```

### Example 3: Multi-Regional Deployment

```go
func multiRegionalExample() {
    ctx := context.Background()

    // Use multi-regional location for automatic replication
    config := &gcpkms.Config{
        ProjectID: "my-project",
        Location:  "us", // Multi-region: replicates across US
        KeyRing:   "global-keys",
    }

    store, err := gcpkms.NewBackend(config)
    if err != nil {
        log.Fatal(err)
    }
    defer store.Close(ctx)

    // Generate key with automatic multi-region replication
    params := &backend.KeyParams{
        Algorithm: backend.AlgorithmECDSA,
        Curve:     backend.CurveP256,
    }

    if err := store.GenerateKey(ctx, "global-api-key", params); err != nil {
        log.Fatal(err)
    }

    fmt.Println("Multi-regional key created")
}
```

### Example 4: Service Account Authentication

```go
func serviceAccountExample() {
    ctx := context.Background()

    config := &gcpkms.Config{
        ProjectID:       "my-project",
        Location:        "europe-west1",
        KeyRing:         "eu-keys",
        CredentialsFile: "/secrets/gcp-sa-key.json",
    }

    store, err := gcpkms.NewBackend(config)
    if err != nil {
        log.Fatal(err)
    }
    defer store.Close(ctx)

    // Use with specific credentials
    params := &backend.KeyParams{
        Algorithm: backend.AlgorithmECDSA,
        Curve:     backend.CurveP384,
    }

    if err := store.GenerateKey(ctx, "eu-signing-key", params); err != nil {
        log.Fatal(err)
    }

    fmt.Println("Key created with service account")
}
```

### Example 5: Multiple Algorithm Keys

```go
func multiAlgorithmExample() {
    ctx := context.Background()

    config := &gcpkms.Config{
        ProjectID: "my-project",
        Location:  "us-central1",
        KeyRing:   "algorithm-test",
    }

    store, err := gcpkms.NewBackend(config)
    if err != nil {
        log.Fatal(err)
    }
    defer store.Close(ctx)

    // RSA 2048
    rsa2048 := &backend.KeyParams{
        Algorithm: backend.AlgorithmRSA,
        KeySize:   2048,
    }
    store.GenerateKey(ctx, "rsa-2048", rsa2048)

    // RSA 4096
    rsa4096 := &backend.KeyParams{
        Algorithm: backend.AlgorithmRSA,
        KeySize:   4096,
    }
    store.GenerateKey(ctx, "rsa-4096", rsa4096)

    // ECDSA P-256
    ecdsaP256 := &backend.KeyParams{
        Algorithm: backend.AlgorithmECDSA,
        Curve:     backend.CurveP256,
    }
    store.GenerateKey(ctx, "ecdsa-p256", ecdsaP256)

    // ECDSA P-384
    ecdsaP384 := &backend.KeyParams{
        Algorithm: backend.AlgorithmECDSA,
        Curve:     backend.CurveP384,
    }
    store.GenerateKey(ctx, "ecdsa-p384", ecdsaP384)

    fmt.Println("Multiple algorithm keys generated")
}
```

### Example 6: Production Signing Service

```go
type GCPSigningService struct {
    store  backend.Backend
    keyID  string
}

func NewGCPSigningService(project, location, keyring, keyID string) (*GCPSigningService, error) {
    config := &gcpkms.Config{
        ProjectID: project,
        Location:  location,
        KeyRing:   keyring,
    }

    store, err := gcpkms.NewBackend(config)
    if err != nil {
        return nil, fmt.Errorf("GCP KMS init failed: %w", err)
    }

    return &GCPSigningService{
        store: store,
        keyID: keyID,
    }, nil
}

func (s *GCPSigningService) SignData(ctx context.Context, data []byte) ([]byte, error) {
    hash := sha256.Sum256(data)

    signature, err := s.store.Sign(ctx, s.keyID, hash[:], crypto.SHA256)
    if err != nil {
        return nil, fmt.Errorf("signing failed: %w", err)
    }

    return signature, nil
}

func (s *GCPSigningService) GetPublicKey(ctx context.Context) (crypto.PublicKey, error) {
    return s.store.GetPublicKey(ctx, s.keyID)
}

func (s *GCPSigningService) Close() error {
    return s.store.Close(context.Background())
}

func productionExample() {
    service, err := NewGCPSigningService(
        "production-project",
        "us-central1",
        "api-keys",
        "primary-signer",
    )
    if err != nil {
        log.Fatal(err)
    }
    defer service.Close()

    data := []byte("Important message")
    signature, err := service.SignData(context.Background(), data)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Signed: %d bytes\n", len(signature))
}
```

## Common Use Cases

### API Token Signing

```go
func apiTokenSigningExample() {
    ctx := context.Background()

    config := &gcpkms.Config{
        ProjectID: os.Getenv("GCP_PROJECT_ID"),
        Location:  "us-central1",
        KeyRing:   "api-tokens",
    }

    store, err := gcpkms.NewBackend(config)
    if err != nil {
        log.Fatal(err)
    }
    defer store.Close(ctx)

    // Generate ECDSA P-256 for JWT
    params := &backend.KeyParams{
        Algorithm: backend.AlgorithmECDSA,
        Curve:     backend.CurveP256,
    }

    store.GenerateKey(ctx, "jwt-signing-key", params)

    // Sign JWT payload
    payload := []byte("header.payload")
    hash := sha256.Sum256(payload)

    signature, err := store.Sign(ctx, "jwt-signing-key", hash[:], crypto.SHA256)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("JWT signed: %d bytes\n", len(signature))
}
```

### Certificate Authority

```go
func caOperationsExample() {
    ctx := context.Background()

    config := &gcpkms.Config{
        ProjectID:       "ca-project",
        Location:        "us-central1",
        KeyRing:         "certificate-authority",
        ProtectionLevel: "HSM",
    }

    store, err := gcpkms.NewBackend(config)
    if err != nil {
        log.Fatal(err)
    }
    defer store.Close(ctx)

    // Generate CA root key (HSM-protected)
    params := &backend.KeyParams{
        Algorithm: backend.AlgorithmRSA,
        KeySize:   4096,
    }

    store.GenerateKey(ctx, "root-ca-key", params)

    // Sign certificate
    certData := []byte("certificate to sign")
    hash := sha256.Sum256(certData)

    signature, err := store.Sign(ctx, "root-ca-key", hash[:], crypto.SHA256)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Certificate signed: %d bytes\n", len(signature))
}
```

### Code Signing

```go
func codeSigningExample() {
    ctx := context.Background()

    config := &gcpkms.Config{
        ProjectID: "build-project",
        Location:  "us-central1",
        KeyRing:   "code-signing",
    }

    store, err := gcpkms.NewBackend(config)
    if err != nil {
        log.Fatal(err)
    }
    defer store.Close(ctx)

    // Generate code signing key
    params := &backend.KeyParams{
        Algorithm: backend.AlgorithmRSA,
        KeySize:   3072,
    }

    store.GenerateKey(ctx, "release-signing-key", params)

    // Sign release artifact
    artifactHash := sha256.Sum256([]byte("binary content"))
    signature, err := store.Sign(ctx, "release-signing-key", artifactHash[:], crypto.SHA256)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Artifact signed: %d bytes\n", len(signature))
}
```

### Multi-Environment Setup

```go
type EnvironmentConfig struct {
    Environment string
    ProjectID   string
    Location    string
    KeyRing     string
}

func getEnvironmentStore(env string) (backend.Backend, error) {
    configs := map[string]EnvironmentConfig{
        "dev": {
            Environment: "development",
            ProjectID:   "dev-project",
            Location:    "us-central1",
            KeyRing:     "dev-keys",
        },
        "staging": {
            Environment: "staging",
            ProjectID:   "staging-project",
            Location:    "us-central1",
            KeyRing:     "staging-keys",
        },
        "prod": {
            Environment: "production",
            ProjectID:   "prod-project",
            Location:    "us", // Multi-region
            KeyRing:     "production-keys",
        },
    }

    cfg, ok := configs[env]
    if !ok {
        return nil, fmt.Errorf("unknown environment: %s", env)
    }

    gcpConfig := &gcpkms.Config{
        ProjectID: cfg.ProjectID,
        Location:  cfg.Location,
        KeyRing:   cfg.KeyRing,
    }

    return gcpkms.NewBackend(gcpConfig)
}

func multiEnvExample() {
    env := os.Getenv("ENVIRONMENT")
    store, err := getEnvironmentStore(env)
    if err != nil {
        log.Fatal(err)
    }
    defer store.Close(context.Background())

    fmt.Printf("Using %s environment keys\n", env)
}
```

## Security Considerations

### IAM Best Practices

Use principle of least privilege:

```go
// Bad: Using owner role
// roles/owner - Too broad

// Good: Specific KMS roles
// roles/cloudkms.signerVerifier - For signing operations
// roles/cloudkms.publicKeyViewer - For public key access only
```

Grant permissions at key level, not keyring level:

```bash
# Good: Key-level permission
gcloud kms keys add-iam-policy-binding my-key \
  --location=us-central1 \
  --keyring=production \
  --member=serviceAccount:app@project.iam.gserviceaccount.com \
  --role=roles/cloudkms.signerVerifier

# Avoid: Keyring-level permission (too broad)
gcloud kms keyrings add-iam-policy-binding production \
  --location=us-central1 \
  --member=serviceAccount:app@project.iam.gserviceaccount.com \
  --role=roles/cloudkms.admin
```

### Service Account Security

Use Workload Identity instead of service account keys:

```go
// Best: Workload Identity (no credentials file)
config := &gcpkms.Config{
    ProjectID: "my-project",
    Location:  "us-central1",
    KeyRing:   "production",
}

// Avoid: Service account key file
config := &gcpkms.Config{
    ProjectID:       "my-project",
    Location:        "us-central1",
    KeyRing:         "production",
    CredentialsFile: "/path/to/key.json", // Security risk
}
```

Rotate service account keys regularly:

```bash
# Create new key
gcloud iam service-accounts keys create new-key.json \
  --iam-account=my-app@my-project.iam.gserviceaccount.com

# Update application
# Delete old key
gcloud iam service-accounts keys delete old-key-id \
  --iam-account=my-app@my-project.iam.gserviceaccount.com
```

### Network Security

Use VPC Service Controls:

```bash
# Create service perimeter
gcloud access-context-manager perimeters create kms_perimeter \
  --title="KMS Perimeter" \
  --resources=projects/123456 \
  --restricted-services=cloudkms.googleapis.com \
  --policy=policy-id
```

Use Private Google Access for VPC:

```bash
gcloud compute networks subnets update my-subnet \
  --region=us-central1 \
  --enable-private-ip-google-access
```

### Audit Logging

Enable Cloud Audit Logs:

```go
// All KMS operations are automatically logged to Cloud Audit Logs
// View logs in Cloud Console or query with:
```

```bash
gcloud logging read "resource.type=cloudkms_cryptokey \
  AND protoPayload.methodName=google.cloud.kms.v1.KeyManagementService.AsymmetricSign" \
  --limit 50 \
  --format json
```

Monitor key usage:

```bash
# Create log-based metric
gcloud logging metrics create kms_sign_operations \
  --description="Count of KMS sign operations" \
  --log-filter='resource.type="cloudkms_cryptokey" AND protoPayload.methodName="google.cloud.kms.v1.KeyManagementService.AsymmetricSign"'

# Create alert
gcloud alpha monitoring policies create \
  --notification-channels=CHANNEL_ID \
  --display-name="High KMS Usage" \
  --condition-display-name="Sign operations > 1000/hour" \
  --condition-threshold-value=1000 \
  --condition-threshold-duration=3600s
```

### Key Protection Levels

Choose appropriate protection level:

```go
// Production: Use HSM for critical keys
config := &gcpkms.Config{
    ProjectID:       "prod-project",
    Location:        "us-central1",
    KeyRing:         "critical-keys",
    ProtectionLevel: "HSM", // FIPS 140-2 Level 3
}

// Development: Use SOFTWARE for cost savings
config := &gcpkms.Config{
    ProjectID:       "dev-project",
    Location:        "us-central1",
    KeyRing:         "dev-keys",
    ProtectionLevel: "SOFTWARE",
}
```

## Best Practices

### Resource Organization

Organize keys logically:

```
Project: production-project
  ├─ Location: us (multi-region)
  │   └─ KeyRing: api-keys
  │       ├─ CryptoKey: jwt-signing-key
  │       ├─ CryptoKey: api-token-key
  │       └─ CryptoKey: webhook-signing-key
  │
  ├─ Location: us-central1
  │   └─ KeyRing: ca-keys
  │       ├─ CryptoKey: root-ca
  │       └─ CryptoKey: intermediate-ca
  │
  └─ Location: europe-west1
      └─ KeyRing: eu-compliance-keys
          └─ CryptoKey: gdpr-signing-key
```

Use naming conventions:

```go
// Good naming
keyID := "production-api-jwt-signer-v2"
keyID := "staging-webhook-ecdsa-p256"
keyID := "ca-root-rsa4096-2024"

// Avoid generic names
keyID := "key1"
keyID := "test"
```

### Error Handling

Handle errors appropriately:

```go
store, err := gcpkms.NewBackend(config)
if err != nil {
    return fmt.Errorf("GCP KMS initialization failed: %w", err)
}
defer func() {
    if err := store.Close(ctx); err != nil {
        log.Printf("Error closing GCP KMS: %v", err)
    }
}()

signature, err := store.Sign(ctx, keyID, digest, crypto.SHA256)
if err != nil {
    // Check for specific errors
    if strings.Contains(err.Error(), "PERMISSION_DENIED") {
        return fmt.Errorf("insufficient IAM permissions: %w", err)
    }
    if strings.Contains(err.Error(), "NOT_FOUND") {
        return fmt.Errorf("key not found: %s: %w", keyID, err)
    }
    return fmt.Errorf("signing failed: %w", err)
}
```

### Context Management

Use timeouts and cancellation:

```go
func signWithTimeout(store backend.Backend, keyID string, data []byte) ([]byte, error) {
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()

    hash := sha256.Sum256(data)
    return store.Sign(ctx, keyID, hash[:], crypto.SHA256)
}
```

### Caching and Performance

Cache Backend instances:

```go
var (
    gcpStore backend.Backend
    storeOnce sync.Once
)

func getGCPStore() (backend.Backend, error) {
    var err error
    storeOnce.Do(func() {
        config := &gcpkms.Config{
            ProjectID: os.Getenv("GCP_PROJECT_ID"),
            Location:  os.Getenv("GCP_LOCATION"),
            KeyRing:   os.Getenv("GCP_KEYRING"),
        }
        gcpStore, err = gcpkms.NewBackend(config)
    })
    return gcpStore, err
}
```

### Integration Testing

The GCP KMS backend has full integration test coverage using mock/emulator testing:

```bash
# Run GCP KMS integration tests (recommended)
make integration-test-gcpkms

# This executes tests in Docker with mocked GCP KMS service
# Tests all supported algorithms: RSA 2048/3072/4096, ECDSA P-256/P-384/P-521
# Part of the full integration test suite (151/151 tests passing)
```

### Running Tests Manually

```bash
# View test configuration
cat test/integration/gcpkms/docker-compose.yml

# Run tests manually
cd test/integration/gcpkms
docker-compose run --rm test
docker-compose down -v
```

### Testing Strategy

Use separate projects for environments:

```go
func getTestBackend(t *testing.T) backend.Backend {
    config := &gcpkms.Config{
        ProjectID: "test-project",
        Location:  "us-central1",
        KeyRing:   fmt.Sprintf("test-%s", t.Name()),
    }

    store, err := gcpkms.NewBackend(config)
    require.NoError(t, err)

    t.Cleanup(func() {
        store.Close(context.Background())
    })

    return store
}
```

### Cost Optimization

Optimize for cost:

```go
// Use SOFTWARE protection for non-critical keys
config := &gcpkms.Config{
    ProjectID:       "my-project",
    Location:        "us-central1",
    KeyRing:         "dev-keys",
    ProtectionLevel: "SOFTWARE", // Lower cost
}

// Use HSM only for critical production keys
prodConfig := &gcpkms.Config{
    ProjectID:       "prod-project",
    Location:        "us-central1",
    KeyRing:         "critical-keys",
    ProtectionLevel: "HSM", // Higher cost, higher security
}
```

Monitor costs:

```bash
# View KMS costs
gcloud billing accounts get-iam-policy BILLING_ACCOUNT_ID

# Set budget alerts
gcloud billing budgets create \
  --billing-account=BILLING_ACCOUNT_ID \
  --display-name="KMS Budget" \
  --budget-amount=100 \
  --threshold-rule=percent=90
```

### Key Versioning

GCP KMS automatically manages key versions:

```go
// Generate key creates version 1
store.GenerateKey(ctx, "my-key", params)

// Subsequent operations use primary version automatically
signature1, _ := store.Sign(ctx, "my-key", digest, crypto.SHA256)

// Rotate key (creates new version, makes it primary)
// Done via gcloud or Cloud Console
// gcloud kms keys update my-key --location=us-central1 --keyring=production --rotation-period=90d

// Old versions remain available
// New operations use new primary version
signature2, _ := store.Sign(ctx, "my-key", digest, crypto.SHA256)
```

## Troubleshooting

### Permission Denied

```
Error: rpc error: code = PermissionDenied desc = Permission 'cloudkms.cryptoKeyVersions.useToSign' denied
```

Solutions:
- Verify service account has `roles/cloudkms.signerVerifier`
- Check IAM policy: `gcloud kms keys get-iam-policy KEY_NAME --location=LOCATION --keyring=KEYRING`
- Grant permission: `gcloud kms keys add-iam-policy-binding KEY_NAME --member=serviceAccount:SA --role=roles/cloudkms.signerVerifier`
- Wait up to 60 seconds for IAM changes to propagate

### Key Not Found

```
Error: rpc error: code = NotFound desc = CryptoKey not found
```

Solutions:
- Verify key exists: `gcloud kms keys list --location=LOCATION --keyring=KEYRING`
- Check project, location, keyring, and key name are correct
- Ensure key hasn't been scheduled for destruction
- Verify service account has access to the project

### Authentication Failed

```
Error: google: could not find default credentials
```

Solutions:
- Set `GOOGLE_APPLICATION_CREDENTIALS`: `export GOOGLE_APPLICATION_CREDENTIALS=/path/to/key.json`
- Run `gcloud auth application-default login` for local development
- For GKE, enable Workload Identity
- For Compute Engine, attach service account to instance

### API Not Enabled

```
Error: Cloud Key Management Service (KMS) API has not been used in project PROJECT_ID before
```

Solutions:
```bash
gcloud services enable cloudkms.googleapis.com --project=PROJECT_ID
```

### Resource Exhausted

```
Error: rpc error: code = ResourceExhausted desc = Quota exceeded
```

Solutions:
- Check quota limits: `gcloud compute project-info describe --project=PROJECT_ID`
- Request quota increase in Cloud Console
- Implement retry logic with exponential backoff
- Use multiple keys to distribute load

### Invalid Argument

```
Error: rpc error: code = InvalidArgument desc = Invalid digest length
```

Solutions:
- Ensure digest matches hash algorithm (SHA-256 = 32 bytes, SHA-512 = 64 bytes)
- Verify you're passing the hash, not raw data
- Check algorithm compatibility with key type

## Performance Considerations

### Operation Latency

Typical latencies for GCP KMS operations:

- **Sign operation**: 50-200ms
- **Get public key**: 20-100ms
- **Generate key**: 200-500ms
- **List keys**: 100-300ms

Latency varies by:
- Geographic location (choose location near compute)
- Network connectivity
- Protection level (HSM vs SOFTWARE similar)

### Throughput Limits

Default quotas (per project per minute):

- **Sign operations**: 60,000
- **Get public key**: 60,000
- **Generate key**: 300
- **Admin operations**: 300

Request quota increases for higher limits.

### Optimization Tips

1. **Collocate compute and keys**: Use same region for lowest latency
2. **Cache public keys**: Public keys don't change, cache them locally
3. **Batch operations**: Group operations when possible
4. **Use connection pooling**: Reuse KMS client connections
5. **Implement retries**: Use exponential backoff for transient errors

```go
func signWithRetry(store backend.Backend, keyID string, digest []byte, maxRetries int) ([]byte, error) {
    var signature []byte
    var err error

    for i := 0; i < maxRetries; i++ {
        signature, err = store.Sign(context.Background(), keyID, digest, crypto.SHA256)
        if err == nil {
            return signature, nil
        }

        if !isRetryable(err) {
            return nil, err
        }

        time.Sleep(time.Duration(math.Pow(2, float64(i))) * time.Second)
    }

    return nil, fmt.Errorf("max retries exceeded: %w", err)
}

func isRetryable(err error) bool {
    return strings.Contains(err.Error(), "UNAVAILABLE") ||
           strings.Contains(err.Error(), "DEADLINE_EXCEEDED") ||
           strings.Contains(err.Error(), "ResourceExhausted")
}
```

## Advanced Topics

### External Key Manager (EKM)

Use keys stored in external systems:

```bash
gcloud kms keys create ekm-key \
  --location=us-central1 \
  --keyring=production \
  --protection-level=EXTERNAL \
  --external-key-uri="https://example.com/keys/my-key"
```

### Import Existing Keys

Import your own key material:

```bash
# Create import job
gcloud kms import-jobs create my-import-job \
  --location=us-central1 \
  --keyring=production \
  --import-method=rsa-oaep-3072-sha256-aes-256

# Import key
gcloud kms keys import my-imported-key \
  --location=us-central1 \
  --keyring=production \
  --import-job=my-import-job \
  --wrapped-key-file=wrapped-key.bin \
  --algorithm=rsa-sign-pkcs1-2048-sha256
```

### Automated Key Rotation

Configure automatic rotation:

```bash
gcloud kms keys update my-key \
  --location=us-central1 \
  --keyring=production \
  --rotation-period=90d \
  --next-rotation-time=2024-12-31T00:00:00Z
```

### Cross-Project Access

Grant access from another project:

```bash
gcloud kms keys add-iam-policy-binding my-key \
  --location=us-central1 \
  --keyring=production \
  --member=serviceAccount:app@other-project.iam.gserviceaccount.com \
  --role=roles/cloudkms.signerVerifier
```

## Cost Estimation

### Pricing Components

**Key versions (per month)**:
- SOFTWARE: $0.06/key version
- HSM: $1.00/key version
- EXTERNAL: $2.50/key version

**Operations (per 10,000)**:
- Sign/Verify: $0.03
- Encrypt/Decrypt: $0.03
- Public key access: Free

**Example monthly cost**:

```
10 HSM keys x $1.00 = $10.00
100,000 sign operations x ($0.03/10,000) = $0.30
Total: $10.30/month
```

### Cost Optimization Strategies

1. Use SOFTWARE protection for dev/test environments
2. Delete unused key versions
3. Cache public keys to avoid API calls
4. Use regional keys instead of multi-regional when possible
5. Monitor usage with Cloud Billing reports

## Compliance and Certifications

GCP KMS compliance:

- **FIPS 140-2 Level 3** (HSM protection level)
- **ISO 27001**, **ISO 27017**, **ISO 27018**
- **SOC 2/3**
- **PCI DSS**
- **HIPAA** (with BAA)
- **FedRAMP High** (GovCloud)

Data residency options:
- Regional keys stay in specified region
- Multi-regional keys replicate across defined geography
- Customer-managed encryption for data at rest

## Migration Guide

### From PKCS#8 to GCP KMS

```go
func migrateTOGCPKMS() error {
    ctx := context.Background()

    // Old PKCS#8 backend
    pkcs8Config := &pkcs8.Config{
        StoragePath: "./keys",
        Password:    os.Getenv("KEYSTORE_PASSWORD"),
    }
    oldStore, err := pkcs8.NewBackend(pkcs8Config)
    if err != nil {
        return err
    }
    defer oldStore.Close(ctx)

    // New GCP KMS backend
    gcpConfig := &gcpkms.Config{
        ProjectID: "my-project",
        Location:  "us-central1",
        KeyRing:   "migrated-keys",
    }
    newStore, err := gcpkms.NewBackend(gcpConfig)
    if err != nil {
        return err
    }
    defer newStore.Close(ctx)

    // Generate new keys in GCP KMS
    params := &backend.KeyParams{
        Algorithm: backend.AlgorithmRSA,
        KeySize:   2048,
    }

    if err := newStore.GenerateKey(ctx, "migrated-key", params); err != nil {
        return err
    }

    // Update application configuration to use GCP KMS
    // Re-sign data with new keys
    // Retire old PKCS#8 keys after transition

    return nil
}
```

## References

- [GCP KMS Documentation](https://cloud.google.com/kms/docs)
- [GCP KMS API Reference](https://cloud.google.com/kms/docs/reference/rest)
- [IAM Roles for KMS](https://cloud.google.com/kms/docs/iam)
- [Key Management Best Practices](https://cloud.google.com/kms/docs/key-management)
- [GCP Security Command Center](https://cloud.google.com/security-command-center)
- [Cloud Audit Logs](https://cloud.google.com/logging/docs/audit)
- [VPC Service Controls](https://cloud.google.com/vpc-service-controls)

## Limitations

The GCP KMS backend has the following limitations:

- Ed25519 not supported (use ECDSA P-256 instead)
- Keys cannot be exported (security by design)
- KeyRings cannot be deleted once created
- Maximum 100 key versions per key recommended
- API rate limits apply (60,000 operations/minute default)
- Costs scale with number of key versions and operations
- Some operations require internet connectivity
- HSM protection level cannot be changed after creation

For on-premises HSM requirements, consider the PKCS#11 backend. For offline key storage, consider the PKCS#8 or TPM backends.
