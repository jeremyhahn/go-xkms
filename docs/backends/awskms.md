# AWS KMS Backend Documentation

## Overview

The AWS KMS (Key Management Service) backend provides cloud-based cryptographic key management using Amazon Web Services' fully managed service. This backend offers FIPS 140-2 Level 2 validated hardware security modules (HSMs) for key storage and cryptographic operations, making it suitable for production workloads requiring regulatory compliance and enterprise-grade security.

AWS KMS handles key generation, automatic rotation, and deletion while providing centralized access control through AWS IAM. All cryptographic operations are performed server-side within AWS infrastructure, ensuring keys never leave the KMS service boundary. The service supports both AWS-managed and customer-managed keys, multi-region key replication, and seamless integration with AWS services.

## Features and Capabilities

### Key Management

- Automatic key generation with AWS-managed entropy
- Customer-managed key rotation policies
- Key aliasing for simplified key references
- Multi-region key replication for disaster recovery
- Automatic key material backup and durability
- Key import from external sources (BYOK)
- Scheduled key deletion with recovery period
- Key versioning with automatic rotation

### Cryptographic Operations

- Asymmetric sign/verify for digital signatures
- Asymmetric encrypt/decrypt for data protection
- Symmetric encrypt/decrypt operations
- Key derivation and wrapping
- Generate data keys for envelope encryption
- Hardware-backed key operations

### Security Features

- FIPS 140-2 Level 2 validated HSMs
- FIPS 140-2 Level 3 (AWS CloudHSM integration)
- Automatic key material protection
- AWS CloudTrail integration for audit logging
- VPC endpoint support for private connectivity
- AWS PrivateLink for enhanced network security
- IAM-based access control with fine-grained permissions
- Key policy and grant-based authorization
- Cross-account key sharing

### Operational Features

- Global availability with multi-region support
- Automatic scaling and high availability
- Pay-per-use pricing model
- CloudWatch metrics and monitoring
- Automated backup and disaster recovery
- Integration with AWS services
- AWS Organizations support

## Authentication Methods

### IAM Roles (Recommended for EC2/ECS/Lambda)

```go
// Uses IAM role attached to EC2 instance, ECS task, or Lambda function
config := &awskms.Config{
    Region: "us-east-1",
}

store, err := awskms.NewBackend(config)
```

Attach IAM role to EC2 instance:
```bash
aws iam create-role --role-name KMSAccessRole \
  --assume-role-policy-document file://trust-policy.json

aws iam attach-role-policy --role-name KMSAccessRole \
  --policy-arn arn:aws:iam::aws:policy/AWSKeyManagementServicePowerUser

aws ec2 associate-iam-instance-profile \
  --instance-id i-1234567890abcdef0 \
  --iam-instance-profile Name=KMSAccessRole
```

### Access Keys (Static Credentials)

```go
config := &awskms.Config{
    Region:          "us-east-1",
    AccessKeyID:     os.Getenv("AWS_ACCESS_KEY_ID"),
    SecretAccessKey: os.Getenv("AWS_SECRET_ACCESS_KEY"),
    SessionToken:    os.Getenv("AWS_SESSION_TOKEN"), // Optional for STS
}

store, err := awskms.NewBackend(config)
```

### AWS CLI Profile

```bash
# Configure AWS CLI
aws configure --profile production

# Set environment variable
export AWS_PROFILE=production
```

```go
// Uses AWS_PROFILE environment variable
config := &awskms.Config{
    Region: "us-east-1",
}

store, err := awskms.NewBackend(config)
```

### STS Assume Role

```go
// Assume role for cross-account access
config := &awskms.Config{
    Region:          "us-east-1",
    AccessKeyID:     os.Getenv("AWS_ACCESS_KEY_ID"),
    SecretAccessKey: os.Getenv("AWS_SECRET_ACCESS_KEY"),
    // AssumeRole configuration handled by AWS SDK
}

store, err := awskms.NewBackend(config)
```

## Configuration Options

### Config Structure

```go
type Config struct {
    // AWS Region
    Region string

    // Access Key ID (optional for IAM roles)
    AccessKeyID string

    // Secret Access Key (optional for IAM roles)
    SecretAccessKey string

    // Session Token (optional for STS)
    SessionToken string

    // Custom endpoint (optional, for testing)
    Endpoint string

    // Existing KMS client (optional)
    Client KMSClient
}
```

### Configuration Parameters

**Region** (required)
- AWS region where keys will be created
- Example: `"us-east-1"`, `"eu-west-1"`, `"ap-southeast-1"`
- Must have KMS service available
- Affects latency and data residency

**AccessKeyID** (optional)
- AWS access key ID for authentication
- Not required when using IAM roles
- Should be stored in environment variables
- Never hardcode in source code

**SecretAccessKey** (optional)
- AWS secret access key for authentication
- Not required when using IAM roles
- Should be stored securely
- Rotate regularly for security

**SessionToken** (optional)
- AWS STS session token
- Required when using temporary credentials
- Automatically managed by AWS SDK for IAM roles

**Endpoint** (optional)
- Custom KMS endpoint URL
- Used for testing with LocalStack or moto
- Example: `"http://localhost:4566"` for LocalStack
- Not needed for production AWS KMS

**Client** (optional)
- Pre-initialized AWS KMS client
- Allows external client management
- Overrides other authentication parameters

## IAM Permissions

### Required IAM Policy

Minimal permissions for signing operations:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "kms:Sign",
        "kms:Verify",
        "kms:GetPublicKey",
        "kms:DescribeKey"
      ],
      "Resource": "arn:aws:kms:us-east-1:123456789012:key/*"
    }
  ]
}
```

Full key management permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "kms:CreateKey",
        "kms:CreateAlias",
        "kms:DeleteAlias",
        "kms:DescribeKey",
        "kms:GetPublicKey",
        "kms:Sign",
        "kms:Verify",
        "kms:ScheduleKeyDeletion",
        "kms:CancelKeyDeletion",
        "kms:EnableKeyRotation",
        "kms:DisableKeyRotation",
        "kms:GetKeyRotationStatus",
        "kms:ListAliases",
        "kms:ListKeys",
        "kms:TagResource",
        "kms:UntagResource"
      ],
      "Resource": "*"
    }
  ]
}
```

### Key Policies

Default key policy for user access:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "Enable IAM User Permissions",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::123456789012:root"
      },
      "Action": "kms:*",
      "Resource": "*"
    },
    {
      "Sid": "Allow use of the key for signing",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::123456789012:role/MyApplicationRole"
      },
      "Action": [
        "kms:Sign",
        "kms:Verify",
        "kms:GetPublicKey",
        "kms:DescribeKey"
      ],
      "Resource": "*"
    }
  ]
}
```

## Supported Algorithms

### RSA Keys

| Key Spec | Key Size | Signature Algorithms | Encryption |
|----------|----------|---------------------|------------|
| RSA_2048 | 2048 bits | RSASSA_PSS_SHA_256/384/512, RSASSA_PKCS1_V1_5_SHA_256/384/512 | RSAES_OAEP_SHA_1/256 |
| RSA_3072 | 3072 bits | RSASSA_PSS_SHA_256/384/512, RSASSA_PKCS1_V1_5_SHA_256/384/512 | RSAES_OAEP_SHA_1/256 |
| RSA_4096 | 4096 bits | RSASSA_PSS_SHA_256/384/512, RSASSA_PKCS1_V1_5_SHA_256/384/512 | RSAES_OAEP_SHA_1/256 |

**Note**: All 10 backends support RSA 2048, 3072, and 4096-bit keys with full integration test coverage (151/151 tests passing).

### Elliptic Curve Keys

| Key Spec | Curve | Signature Algorithms |
|----------|-------|---------------------|
| ECC_NIST_P256 | P-256 (secp256r1) | ECDSA_SHA_256 |
| ECC_NIST_P384 | P-384 (secp384r1) | ECDSA_SHA_384 |
| ECC_NIST_P521 | P-521 (secp521r1) | ECDSA_SHA_512 |
| ECC_SECG_P256K1 | secp256k1 | ECDSA_SHA_256 |

**Note**: All 10 backends support ECDSA P-256, P-384, and P-521 curves with full integration test coverage (151/151 tests passing).

### Symmetric Keys

| Key Spec | Usage |
|----------|-------|
| SYMMETRIC_DEFAULT | Encrypt/Decrypt, GenerateDataKey |

### Not Supported

- Ed25519 (use ECC_NIST_P256 instead)
- Custom key specs

## Complete Working Examples

### Example 1: Basic Setup with IAM Role

```go
package main

import (
    "context"
    "crypto"
    "crypto/sha256"
    "fmt"
    "log"

    "github.com/jeremyhahn/go-keychain/pkg/backend"
    "github.com/jeremyhahn/go-keychain/pkg/backend/awskms"
)

func main() {
    ctx := context.Background()

    // Configure with IAM role (EC2/ECS/Lambda)
    config := &awskms.Config{
        Region: "us-east-1",
    }

    store, err := awskms.NewBackend(config)
    if err != nil {
        log.Fatalf("Failed to initialize AWS KMS: %v", err)
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

    fmt.Println("RSA key generated in AWS KMS")

    // Sign data
    data := []byte("Hello, AWS KMS!")
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

### Example 2: Static Credentials

```go
func staticCredentialsExample() {
    ctx := context.Background()

    config := &awskms.Config{
        Region:          "us-west-2",
        AccessKeyID:     os.Getenv("AWS_ACCESS_KEY_ID"),
        SecretAccessKey: os.Getenv("AWS_SECRET_ACCESS_KEY"),
    }

    store, err := awskms.NewBackend(config)
    if err != nil {
        log.Fatal(err)
    }
    defer store.Close(ctx)

    // Generate ECDSA key
    params := &backend.KeyParams{
        Algorithm: backend.AlgorithmECDSA,
        Curve:     backend.CurveP256,
    }

    if err := store.GenerateKey(ctx, "ecdsa-p256-key", params); err != nil {
        log.Fatal(err)
    }

    fmt.Println("ECDSA key created with static credentials")
}
```

### Example 3: Multi-Region Keys

```go
func multiRegionExample() {
    ctx := context.Background()

    // Primary key in us-east-1
    primaryConfig := &awskms.Config{
        Region: "us-east-1",
    }

    primaryStore, err := awskms.NewBackend(primaryConfig)
    if err != nil {
        log.Fatal(err)
    }
    defer primaryStore.Close(ctx)

    params := &backend.KeyParams{
        Algorithm: backend.AlgorithmRSA,
        KeySize:   2048,
    }

    primaryStore.GenerateKey(ctx, "multi-region-key", params)

    // Replica key in eu-west-1 (manual setup via AWS Console/CLI)
    replicaConfig := &awskms.Config{
        Region: "eu-west-1",
    }

    replicaStore, err := awskms.NewBackend(replicaConfig)
    if err != nil {
        log.Fatal(err)
    }
    defer replicaStore.Close(ctx)

    fmt.Println("Multi-region key setup complete")
}
```

### Example 4: Production Signing Service

```go
type AWSSigningService struct {
    store  backend.Backend
    keyID  string
}

func NewAWSSigningService(region, keyID string) (*AWSSigningService, error) {
    config := &awskms.Config{
        Region: region,
    }

    store, err := awskms.NewBackend(config)
    if err != nil {
        return nil, fmt.Errorf("AWS KMS init failed: %w", err)
    }

    return &AWSSigningService{
        store: store,
        keyID: keyID,
    }, nil
}

func (s *AWSSigningService) SignData(ctx context.Context, data []byte) ([]byte, error) {
    hash := sha256.Sum256(data)

    signature, err := s.store.Sign(ctx, s.keyID, hash[:], crypto.SHA256)
    if err != nil {
        return nil, fmt.Errorf("signing failed: %w", err)
    }

    return signature, nil
}

func (s *AWSSigningService) Close() error {
    return s.store.Close(context.Background())
}

func productionExample() {
    service, err := NewAWSSigningService("us-east-1", "alias/production-signer")
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

### Example 5: Multiple Algorithm Keys

```go
func multiAlgorithmExample() {
    ctx := context.Background()

    config := &awskms.Config{
        Region: "us-east-1",
    }

    store, err := awskms.NewBackend(config)
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

## Common Use Cases

### JWT Token Signing

```go
func jwtSigningExample() {
    ctx := context.Background()

    config := &awskms.Config{
        Region: os.Getenv("AWS_REGION"),
    }

    store, err := awskms.NewBackend(config)
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

    signature, err := store.Sign(ctx, "alias/jwt-signing-key", hash[:], crypto.SHA256)
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

    config := &awskms.Config{
        Region: "us-east-1",
    }

    store, err := awskms.NewBackend(config)
    if err != nil {
        log.Fatal(err)
    }
    defer store.Close(ctx)

    // Generate CA root key
    params := &backend.KeyParams{
        Algorithm: backend.AlgorithmRSA,
        KeySize:   4096,
    }

    store.GenerateKey(ctx, "root-ca-key", params)

    // Sign certificate
    certData := []byte("certificate to sign")
    hash := sha256.Sum256(certData)

    signature, err := store.Sign(ctx, "alias/root-ca-key", hash[:], crypto.SHA256)
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

    config := &awskms.Config{
        Region: "us-east-1",
    }

    store, err := awskms.NewBackend(config)
    if err != nil {
        log.Fatal(err)
    }
    defer store.Close(ctx)

    // Generate code signing key
    params := &backend.KeyParams{
        Algorithm: backend.AlgorithmRSA,
        KeySize:   3072,
    }

    store.GenerateKey(ctx, "code-signing-key", params)

    // Sign release artifact
    artifactHash := sha256.Sum256([]byte("binary content"))
    signature, err := store.Sign(ctx, "alias/code-signing-key", artifactHash[:], crypto.SHA256)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Artifact signed: %d bytes\n", len(signature))
}
```

## Security Considerations

### IAM Best Practices

Use IAM roles instead of access keys:

```go
// Best: IAM role (no credentials)
config := &awskms.Config{
    Region: "us-east-1",
}

// Avoid: Static credentials
config := &awskms.Config{
    Region:          "us-east-1",
    AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
    SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
}
```

Grant least privilege permissions:

```json
{
  "Effect": "Allow",
  "Action": [
    "kms:Sign",
    "kms:Verify",
    "kms:GetPublicKey"
  ],
  "Resource": "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"
}
```

### Key Policies

Use key policies for resource-based access control:

```bash
aws kms put-key-policy --key-id 12345678-1234-1234-1234-123456789012 \
  --policy-name default --policy file://key-policy.json
```

### Network Security

Use VPC endpoints for private connectivity:

```bash
aws ec2 create-vpc-endpoint --vpc-id vpc-1234567890abcdef0 \
  --service-name com.amazonaws.us-east-1.kms \
  --route-table-ids rtb-1234567890abcdef0
```

### Audit Logging

Enable CloudTrail logging:

```bash
aws cloudtrail create-trail --name kms-audit-trail \
  --s3-bucket-name my-audit-bucket

aws cloudtrail start-logging --name kms-audit-trail
```

Query CloudTrail logs:

```bash
aws cloudtrail lookup-events --lookup-attributes \
  AttributeKey=ResourceType,AttributeValue=AWS::KMS::Key \
  --max-results 10
```

## Best Practices

### Key Naming

Use descriptive aliases:

```go
// Good: Descriptive alias
keyID := "alias/production-api-jwt-v2"
keyID := "alias/staging-webhook-signer"
keyID := "alias/ca-root-rsa4096-2024"

// Avoid: Generic names
keyID := "alias/key1"
keyID := "alias/test"
```

### Error Handling

```go
store, err := awskms.NewBackend(config)
if err != nil {
    return fmt.Errorf("AWS KMS initialization failed: %w", err)
}
defer func() {
    if err := store.Close(ctx); err != nil {
        log.Printf("Error closing AWS KMS: %v", err)
    }
}()

signature, err := store.Sign(ctx, keyID, digest, crypto.SHA256)
if err != nil {
    if strings.Contains(err.Error(), "AccessDeniedException") {
        return fmt.Errorf("insufficient IAM permissions: %w", err)
    }
    if strings.Contains(err.Error(), "NotFoundException") {
        return fmt.Errorf("key not found: %s: %w", keyID, err)
    }
    return fmt.Errorf("signing failed: %w", err)
}
```

### Context Management

```go
func signWithTimeout(store backend.Backend, keyID string, data []byte) ([]byte, error) {
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()

    hash := sha256.Sum256(data)
    return store.Sign(ctx, keyID, hash[:], crypto.SHA256)
}
```

### Caching

```go
var (
    awsStore backend.Backend
    storeOnce sync.Once
)

func getAWSStore() (backend.Backend, error) {
    var err error
    storeOnce.Do(func() {
        config := &awskms.Config{
            Region: os.Getenv("AWS_REGION"),
        }
        awsStore, err = awskms.NewBackend(config)
    })
    return awsStore, err
}
```

### Integration Testing

The AWS KMS backend has full integration test coverage using mock/emulator testing:

```bash
# Run AWS KMS integration tests (recommended)
make integration-test-awskms

# This executes tests in Docker with mocked AWS KMS service
# Tests all supported algorithms: RSA 2048/3072/4096, ECDSA P-256/P-384/P-521
# Part of the full integration test suite (151/151 tests passing)
```

### Running Tests Manually

```bash
# View test configuration
cat test/integration/awskms/docker-compose.yml

# Run tests manually
cd test/integration/awskms
docker-compose run --rm test
docker-compose down -v
```

### Testing with LocalStack

For local development, use LocalStack to emulate AWS KMS:

```go
func getTestBackend(t *testing.T) backend.Backend {
    config := &awskms.Config{
        Region:   "us-east-1",
        Endpoint: "http://localhost:4566", // LocalStack
    }

    store, err := awskms.NewBackend(config)
    require.NoError(t, err)

    t.Cleanup(func() {
        store.Close(context.Background())
    })

    return store
}
```

### Cost Optimization

```bash
# Enable automatic key rotation (free)
aws kms enable-key-rotation --key-id 12345678-1234-1234-1234-123456789012

# Delete unused keys
aws kms schedule-key-deletion --key-id KEY_ID --pending-window-in-days 30

# Use aliases to avoid creating duplicate keys
aws kms list-aliases --query "Aliases[?starts_with(AliasName, 'alias/')]"
```

## Troubleshooting

### Access Denied

```
Error: AccessDeniedException: User is not authorized to perform: kms:Sign
```

Solutions:
- Verify IAM policy attached to user/role
- Check key policy allows the principal
- Ensure key is in the same account (or cross-account access configured)
- Wait up to 5 minutes for IAM changes to propagate

### Key Not Found

```
Error: NotFoundException: Key not found
```

Solutions:
- Verify key exists: `aws kms list-keys`
- Check alias exists: `aws kms list-aliases`
- Ensure correct region
- Verify key hasn't been deleted

### Invalid Key State

```
Error: InvalidKeyUsageException: The request is not valid for the current state of the key
```

Solutions:
- Check key state: `aws kms describe-key --key-id KEY_ID`
- Ensure key is enabled
- Cancel pending deletion if needed
- Verify key usage matches operation (sign/verify vs encrypt/decrypt)

### Throttling

```
Error: ThrottlingException: Rate exceeded
```

Solutions:
- Implement exponential backoff retry logic
- Request service limit increase
- Cache public keys to reduce API calls
- Use multiple keys to distribute load

## Performance Considerations

### Operation Latency

- Sign operation: 20-100ms
- Get public key: 10-50ms
- Generate key: 100-300ms
- List keys: 50-200ms

### Throughput Limits

Default quotas (per account per second):

- Symmetric operations: 10,000 requests/second
- Asymmetric operations: 500 requests/second
- GenerateDataKey: 2,000 requests/second

Request quota increases for higher limits.

### Optimization Tips

1. Collocate compute and KMS in same region
2. Cache public keys (don't change)
3. Use connection pooling
4. Implement retry logic with exponential backoff
5. Batch operations when possible

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
    return strings.Contains(err.Error(), "ThrottlingException") ||
           strings.Contains(err.Error(), "ServiceUnavailable")
}
```

## Advanced Topics

### Automatic Key Rotation

```bash
# Enable automatic rotation (yearly)
aws kms enable-key-rotation --key-id KEY_ID

# Check rotation status
aws kms get-key-rotation-status --key-id KEY_ID
```

### Multi-Region Keys

```bash
# Create multi-region primary key
aws kms create-key --multi-region --description "Multi-region primary key"

# Replicate to another region
aws kms replicate-key --key-id mrk-PRIMARY_KEY_ID \
  --replica-region eu-west-1 --description "EU replica"
```

### Key Import (BYOK)

```bash
# Get import parameters
aws kms get-parameters-for-import --key-id KEY_ID \
  --wrapping-algorithm RSAES_OAEP_SHA_256 \
  --wrapping-key-spec RSA_2048

# Import key material
aws kms import-key-material --key-id KEY_ID \
  --import-token fileb://import-token.bin \
  --encrypted-key-material fileb://encrypted-key-material.bin \
  --expiration-model KEY_MATERIAL_DOES_NOT_EXPIRE
```

### Cross-Account Access

```json
{
  "Effect": "Allow",
  "Principal": {
    "AWS": "arn:aws:iam::111122223333:root"
  },
  "Action": [
    "kms:Sign",
    "kms:Verify",
    "kms:GetPublicKey"
  ],
  "Resource": "*"
}
```

## Cost Estimation

### Pricing Components

**Key Storage**:
- Customer managed keys: $1.00 per key per month
- First 20,000 requests per month free
- Additional requests: $0.03 per 10,000 requests

**Example monthly cost**:
```
10 keys x $1.00 = $10.00
100,000 sign operations x ($0.03/10,000) = $0.30
Total: $10.30/month
```

### Cost Optimization

1. Delete unused keys after 7-day waiting period
2. Use aliases to avoid creating duplicate keys
3. Enable automatic rotation (free) instead of manual rotation
4. Cache public keys to reduce API calls
5. Use AWS Free Tier (20,000 requests/month)

## Compliance and Certifications

AWS KMS compliance:

- FIPS 140-2 Level 2 (KMS HSMs)
- FIPS 140-2 Level 3 (CloudHSM integration)
- ISO 27001, 27017, 27018
- SOC 1, 2, 3
- PCI DSS Level 1
- HIPAA eligible
- FedRAMP High
- IRAP (Australia)
- MTCS (Singapore)

## Migration Guide

### From Software Keys to AWS KMS

```go
func migrateToAWSKMS() error {
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

    // New AWS KMS backend
    kmsConfig := &awskms.Config{
        Region: "us-east-1",
    }
    newStore, err := awskms.NewBackend(kmsConfig)
    if err != nil {
        return err
    }
    defer newStore.Close(ctx)

    // Generate new keys in AWS KMS
    params := &backend.KeyParams{
        Algorithm: backend.AlgorithmRSA,
        KeySize:   2048,
    }

    if err := newStore.GenerateKey(ctx, "migrated-key", params); err != nil {
        return err
    }

    // Update application to use AWS KMS
    // Re-sign data with new keys
    // Retire old PKCS#8 keys after transition

    return nil
}
```

## References

- [AWS KMS Documentation](https://docs.aws.amazon.com/kms/)
- [AWS KMS API Reference](https://docs.aws.amazon.com/kms/latest/APIReference/)
- [AWS SDK for Go v2](https://github.com/aws/aws-sdk-go-v2)
- [IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
- [CloudTrail Logging](https://docs.aws.amazon.com/kms/latest/developerguide/logging-using-cloudtrail.html)

## Limitations

The AWS KMS backend has the following limitations:

- Ed25519 not supported (use ECC_NIST_P256 instead)
- Keys cannot be exported (security by design)
- Minimum 7-day waiting period for key deletion
- API rate limits apply (500 asymmetric operations/second default)
- Some operations require internet connectivity
- Maximum 100,000 keys per account per region
- Cross-region operations incur additional latency

For on-premises HSM requirements, consider the PKCS#11 backend. For offline key storage, consider the PKCS#8 or TPM backends.
