# Azure Key Vault Backend Documentation

## Overview

The Azure Key Vault backend provides cloud-based cryptographic key management using Microsoft Azure's fully managed service. This backend offers FIPS 140-2 Level 2 validated Hardware Security Modules (HSMs) for standard tiers and FIPS 140-2 Level 3 validated managed HSMs for premium tiers, making it suitable for production workloads requiring enterprise-grade security and regulatory compliance.

Azure Key Vault handles key generation, automatic rotation, and lifecycle management while providing centralized access control through Azure Role-Based Access Control (RBAC) and Access Policies. All cryptographic operations are performed server-side within Azure's infrastructure, ensuring keys never leave the Key Vault service boundary. The service supports both software-protected and HSM-protected keys, geo-replication for disaster recovery, and seamless integration with Azure services and hybrid cloud environments.

## Features and Capabilities

### Key Management

- Automatic key generation with Azure-managed entropy
- Customer-managed automatic rotation policies
- Key versioning with historical version management
- Geo-replication across Azure regions for disaster recovery
- Soft-delete and purge protection
- Key import from external sources (BYOK)
- Scheduled key deletion with recovery period
- Key backup and restore operations

### Cryptographic Operations

- Asymmetric sign/verify for digital signatures
- Asymmetric encrypt/decrypt for data protection
- Key wrapping and unwrapping
- Secret storage and retrieval
- Certificate management
- Hardware-backed key operations
- FIPS 140-2 Level 2/3 validated HSMs

### Security Features

- FIPS 140-2 Level 2 compliance (standard vault)
- FIPS 140-2 Level 3 compliance (managed HSM)
- Automatic key material protection
- Azure Monitor integration for audit logging
- Virtual Network service endpoints
- Private Link support for private connectivity
- Customer-managed keys (CMK) for Azure services
- Azure AD authentication and authorization
- RBAC and access policy support
- Key access policy with granular permissions

### Operational Features

- Global availability with regional deployment
- Automatic scaling and high availability
- Pay-per-use pricing model
- Azure Monitor and Log Analytics integration
- Automated backup and disaster recovery
- Soft-delete with configurable retention period
- Integration with Azure DevOps and CI/CD pipelines
- Support for Azure Arc for hybrid scenarios

## Configuration Options

### Config Structure

```go
type Config struct {
    // Azure Key Vault URL
    VaultURL string

    // Azure AD Tenant ID (optional for managed identity)
    TenantID string

    // Azure AD Client ID (service principal)
    ClientID string

    // Azure AD Client Secret (service principal)
    ClientSecret string

    // Use Managed Identity instead of service principal
    UseManagedIdentity bool

    // Existing Azure Key Vault client (optional)
    Client KeyVaultClient
}
```

### Configuration Parameters

**VaultURL** (required)
- Full URL to Azure Key Vault
- Format: `https://{vault-name}.vault.azure.net/`
- Example: `"https://my-production-vault.vault.azure.net/"`
- Vault must exist before use
- Must be accessible from application network

**TenantID** (required for service principal)
- Azure AD tenant identifier
- Example: `"12345678-1234-1234-1234-123456789012"`
- Found in Azure Portal under Azure Active Directory
- Not required when using managed identity

**ClientID** (required for service principal)
- Service principal application ID
- Example: `"87654321-4321-4321-4321-210987654321"`
- Created when registering application in Azure AD
- Not required when using managed identity

**ClientSecret** (required for service principal)
- Service principal secret/password
- Should be stored in environment variables or Azure Key Vault
- Never hardcode in source code
- Not required when using managed identity

**UseManagedIdentity** (optional, default: false)
- Enable managed identity authentication
- Recommended for Azure VMs, App Service, Functions, AKS
- No credentials required when enabled
- More secure than service principal

**Client** (optional)
- Pre-initialized Azure Key Vault client
- Allows external client management
- Overrides other authentication parameters

## Authentication Methods

### Managed Identity (Recommended for Azure Resources)

```go
// Best practice for Azure VMs, App Service, Functions, AKS
config := &azurekv.Config{
    VaultURL:           "https://my-vault.vault.azure.net/",
    UseManagedIdentity: true,
}

store, err := azurekv.NewBackend(config)
```

Enable managed identity:
```bash
# For VM
az vm identity assign --name myVM --resource-group myResourceGroup

# For App Service
az webapp identity assign --name myApp --resource-group myResourceGroup

# Grant access to Key Vault
az keyvault set-policy --name myVault \
  --object-id $(az vm identity show --name myVM --resource-group myResourceGroup --query principalId -o tsv) \
  --key-permissions get list create delete sign verify \
  --secret-permissions get list
```

### Service Principal

```go
config := &azurekv.Config{
    VaultURL:     "https://my-vault.vault.azure.net/",
    TenantID:     os.Getenv("AZURE_TENANT_ID"),
    ClientID:     os.Getenv("AZURE_CLIENT_ID"),
    ClientSecret: os.Getenv("AZURE_CLIENT_SECRET"),
}

store, err := azurekv.NewBackend(config)
```

Create service principal:
```bash
# Create service principal
az ad sp create-for-rbac --name myapp-keyvault-sp

# Output:
# {
#   "appId": "CLIENT_ID",
#   "password": "CLIENT_SECRET",
#   "tenant": "TENANT_ID"
# }

# Grant Key Vault access
az keyvault set-policy --name myVault \
  --spn CLIENT_ID \
  --key-permissions get list create delete sign verify
```

### DefaultAzureCredential (Automatic)

```go
// Automatically tries multiple authentication methods in order:
// 1. Environment variables
// 2. Managed Identity
// 3. Azure CLI
// 4. Visual Studio Code
// 5. Azure PowerShell

config := &azurekv.Config{
    VaultURL: "https://my-vault.vault.azure.net/",
}

store, err := azurekv.NewBackend(config)
```

### Azure CLI Authentication (Development)

```bash
# Login with Azure CLI
az login

# Set subscription
az account set --subscription "My Subscription"
```

```go
// No credentials needed, uses Azure CLI token
config := &azurekv.Config{
    VaultURL: "https://my-vault.vault.azure.net/",
}

store, err := azurekv.NewBackend(config)
```

## Access Control

### RBAC (Recommended)

Use Azure RBAC for Key Vault:

```bash
# Enable RBAC
az keyvault update --name myVault --enable-rbac-authorization true

# Assign roles
az role assignment create \
  --role "Key Vault Crypto Officer" \
  --assignee USER_OR_SP_ID \
  --scope /subscriptions/SUBSCRIPTION_ID/resourceGroups/RESOURCE_GROUP/providers/Microsoft.KeyVault/vaults/VAULT_NAME

# Key Vault roles:
# - Key Vault Administrator: Full admin access
# - Key Vault Crypto Officer: Manage keys
# - Key Vault Crypto User: Use keys for cryptographic operations
# - Key Vault Secrets Officer: Manage secrets
# - Key Vault Secrets User: Read secrets
```

### Access Policies (Legacy)

Use access policies for granular permissions:

```bash
az keyvault set-policy --name myVault \
  --spn CLIENT_ID \
  --key-permissions \
    get list create delete update import backup restore recover \
    sign verify encrypt decrypt wrapKey unwrapKey
```

## Supported Algorithms

### RSA Keys

| Key Size | Signature Schemes | Encryption | HSM Support |
|----------|-------------------|------------|-------------|
| 2048 bits | RS256, RS384, RS512, PS256, PS384, PS512 | RSA-OAEP | Yes |
| 3072 bits | RS256, RS384, RS512, PS256, PS384, PS512 | RSA-OAEP | Yes |
| 4096 bits | RS256, RS384, RS512, PS256, PS384, PS512 | RSA-OAEP | Yes |

**Note**: All 10 backends support RSA 2048, 3072, and 4096-bit keys with full integration test coverage (151/151 tests passing).

### Elliptic Curve Keys

| Curve | Azure Name | Signature Schemes | HSM Support |
|-------|------------|-------------------|-------------|
| P-256 | P-256 | ES256 | Yes |
| P-384 | P-384 | ES384 | Yes |
| P-521 | P-521 | ES512 | Yes |
| secp256k1 | P-256K | ES256K | Yes |

**Note**: All 10 backends support ECDSA P-256, P-384, and P-521 curves with full integration test coverage (151/151 tests passing).

### Signature Algorithms

- **RS256**: RSA PKCS#1 v1.5 with SHA-256
- **RS384**: RSA PKCS#1 v1.5 with SHA-384
- **RS512**: RSA PKCS#1 v1.5 with SHA-512
- **PS256**: RSA PSS with SHA-256
- **PS384**: RSA PSS with SHA-384
- **PS512**: RSA PSS with SHA-512
- **ES256**: ECDSA with P-256 and SHA-256
- **ES384**: ECDSA with P-384 and SHA-384
- **ES512**: ECDSA with P-521 and SHA-512
- **ES256K**: ECDSA with secp256k1 and SHA-256

### Not Supported

- Ed25519 (use ES256 instead)
- Symmetric encryption keys (use Azure Storage encryption)

## Complete Working Examples

### Example 1: Basic Setup with Managed Identity

```go
package main

import (
    "context"
    "crypto"
    "crypto/sha256"
    "fmt"
    "log"

    "github.com/jeremyhahn/go-keychain/pkg/backend"
    "github.com/jeremyhahn/go-keychain/pkg/backend/azurekv"
)

func main() {
    ctx := context.Background()

    // Configure with managed identity
    config := &azurekv.Config{
        VaultURL:           "https://production-vault.vault.azure.net/",
        UseManagedIdentity: true,
    }

    store, err := azurekv.NewBackend(config)
    if err != nil {
        log.Fatalf("Failed to initialize Azure Key Vault: %v", err)
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

    fmt.Println("RSA key generated in Azure Key Vault")

    // Sign data
    data := []byte("Hello, Azure Key Vault!")
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

### Example 2: Service Principal Authentication

```go
func servicePrincipalExample() {
    ctx := context.Background()

    config := &azurekv.Config{
        VaultURL:     "https://my-vault.vault.azure.net/",
        TenantID:     os.Getenv("AZURE_TENANT_ID"),
        ClientID:     os.Getenv("AZURE_CLIENT_ID"),
        ClientSecret: os.Getenv("AZURE_CLIENT_SECRET"),
    }

    store, err := azurekv.NewBackend(config)
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

    fmt.Println("ECDSA key created with service principal auth")
}
```

### Example 3: HSM-Protected Keys

```go
func hsmProtectedExample() {
    ctx := context.Background()

    // Use managed HSM for FIPS 140-2 Level 3
    config := &azurekv.Config{
        VaultURL:           "https://my-managedhsm.managedhsm.azure.net/",
        UseManagedIdentity: true,
    }

    store, err := azurekv.NewBackend(config)
    if err != nil {
        log.Fatal(err)
    }
    defer store.Close(ctx)

    // Generate HSM-protected key
    params := &backend.KeyParams{
        Algorithm: backend.AlgorithmRSA,
        KeySize:   4096,
    }

    if err := store.GenerateKey(ctx, "hsm-root-ca-key", params); err != nil {
        log.Fatal(err)
    }

    fmt.Println("HSM-protected key generated in managed HSM")
}
```

### Example 4: Multi-Environment Configuration

```go
type Environment struct {
    Name     string
    VaultURL string
}

func getEnvironmentStore(env string) (backend.Backend, error) {
    environments := map[string]Environment{
        "dev": {
            Name:     "development",
            VaultURL: "https://dev-vault.vault.azure.net/",
        },
        "staging": {
            Name:     "staging",
            VaultURL: "https://staging-vault.vault.azure.net/",
        },
        "prod": {
            Name:     "production",
            VaultURL: "https://prod-vault.vault.azure.net/",
        },
    }

    e, ok := environments[env]
    if !ok {
        return nil, fmt.Errorf("unknown environment: %s", env)
    }

    config := &azurekv.Config{
        VaultURL:           e.VaultURL,
        UseManagedIdentity: true,
    }

    return azurekv.NewBackend(config)
}

func multiEnvExample() {
    env := os.Getenv("ENVIRONMENT")
    store, err := getEnvironmentStore(env)
    if err != nil {
        log.Fatal(err)
    }
    defer store.Close(context.Background())

    fmt.Printf("Using %s environment vault\n", env)
}
```

### Example 5: Multiple Algorithm Keys

```go
func multiAlgorithmExample() {
    ctx := context.Background()

    config := &azurekv.Config{
        VaultURL:           "https://my-vault.vault.azure.net/",
        UseManagedIdentity: true,
    }

    store, err := azurekv.NewBackend(config)
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
type AzureSigningService struct {
    store  backend.Backend
    keyID  string
}

func NewAzureSigningService(vaultURL, keyID string) (*AzureSigningService, error) {
    config := &azurekv.Config{
        VaultURL:           vaultURL,
        UseManagedIdentity: true,
    }

    store, err := azurekv.NewBackend(config)
    if err != nil {
        return nil, fmt.Errorf("Azure Key Vault init failed: %w", err)
    }

    return &AzureSigningService{
        store: store,
        keyID: keyID,
    }, nil
}

func (s *AzureSigningService) SignData(ctx context.Context, data []byte) ([]byte, error) {
    hash := sha256.Sum256(data)

    signature, err := s.store.Sign(ctx, s.keyID, hash[:], crypto.SHA256)
    if err != nil {
        return nil, fmt.Errorf("signing failed: %w", err)
    }

    return signature, nil
}

func (s *AzureSigningService) GetPublicKey(ctx context.Context) (crypto.PublicKey, error) {
    return s.store.GetPublicKey(ctx, s.keyID)
}

func (s *AzureSigningService) Close() error {
    return s.store.Close(context.Background())
}

func productionExample() {
    service, err := NewAzureSigningService(
        "https://production-vault.vault.azure.net/",
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

### JWT Token Signing

```go
func jwtSigningExample() {
    ctx := context.Background()

    config := &azurekv.Config{
        VaultURL:           os.Getenv("AZURE_VAULT_URL"),
        UseManagedIdentity: true,
    }

    store, err := azurekv.NewBackend(config)
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

### Certificate Authority Operations

```go
func caOperationsExample() {
    ctx := context.Background()

    config := &azurekv.Config{
        VaultURL:           "https://ca-vault.vault.azure.net/",
        UseManagedIdentity: true,
    }

    store, err := azurekv.NewBackend(config)
    if err != nil {
        log.Fatal(err)
    }
    defer store.Close(ctx)

    // Generate CA root key (HSM-protected in managed HSM)
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

### API Authentication

```go
func apiAuthExample() {
    ctx := context.Background()

    config := &azurekv.Config{
        VaultURL:           "https://api-vault.vault.azure.net/",
        UseManagedIdentity: true,
    }

    store, err := azurekv.NewBackend(config)
    if err != nil {
        log.Fatal(err)
    }
    defer store.Close(ctx)

    // Generate API signing key
    params := &backend.KeyParams{
        Algorithm: backend.AlgorithmECDSA,
        Curve:     backend.CurveP256,
    }

    store.GenerateKey(ctx, "api-auth-key", params)

    // Sign API request
    requestData := []byte("GET /api/v1/resource")
    hash := sha256.Sum256(requestData)

    signature, err := store.Sign(ctx, "api-auth-key", hash[:], crypto.SHA256)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("API request signed: %d bytes\n", len(signature))
}
```

### Document Signing

```go
type DocumentSigner struct {
    store backend.Backend
}

func NewDocumentSigner(vaultURL string) (*DocumentSigner, error) {
    config := &azurekv.Config{
        VaultURL:           vaultURL,
        UseManagedIdentity: true,
    }

    store, err := azurekv.NewBackend(config)
    if err != nil {
        return nil, err
    }

    return &DocumentSigner{store: store}, nil
}

func (d *DocumentSigner) SignDocument(ctx context.Context, documentHash []byte) ([]byte, error) {
    return d.store.Sign(ctx, "document-signing-key", documentHash, crypto.SHA256)
}

func (d *DocumentSigner) Close() error {
    return d.store.Close(context.Background())
}

func documentSigningExample() {
    signer, err := NewDocumentSigner("https://doc-vault.vault.azure.net/")
    if err != nil {
        log.Fatal(err)
    }
    defer signer.Close()

    docHash := sha256.Sum256([]byte("Important document"))
    signature, err := signer.SignDocument(context.Background(), docHash[:])
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Document signed: %d bytes\n", len(signature))
}
```

## Security Considerations

### Authentication Best Practices

Use Managed Identity whenever possible:

```go
// Best: Managed Identity (no credentials)
config := &azurekv.Config{
    VaultURL:           "https://my-vault.vault.azure.net/",
    UseManagedIdentity: true,
}

// Avoid: Service Principal with secrets
config := &azurekv.Config{
    VaultURL:     "https://my-vault.vault.azure.net/",
    ClientSecret: "hardcoded-secret", // NEVER DO THIS
}
```

Rotate service principal credentials:

```bash
# Create new secret
az ad sp credential reset --name myapp-sp --append

# Update application
# Delete old credential
az ad sp credential delete --name myapp-sp --key-id OLD_KEY_ID
```

### Network Security

Use Private Link for private connectivity:

```bash
# Create private endpoint
az network private-endpoint create \
  --name myVaultEndpoint \
  --resource-group myResourceGroup \
  --vnet-name myVNet \
  --subnet mySubnet \
  --private-connection-resource-id /subscriptions/SUBSCRIPTION_ID/resourceGroups/RESOURCE_GROUP/providers/Microsoft.KeyVault/vaults/VAULT_NAME \
  --connection-name myConnection \
  --location eastus
```

Use virtual network service endpoints:

```bash
# Enable service endpoint
az network vnet subnet update \
  --name mySubnet \
  --vnet-name myVNet \
  --resource-group myResourceGroup \
  --service-endpoints Microsoft.KeyVault

# Configure Key Vault network rules
az keyvault network-rule add \
  --name myVault \
  --subnet /subscriptions/SUBSCRIPTION_ID/resourceGroups/RESOURCE_GROUP/providers/Microsoft.Network/virtualNetworks/VNET_NAME/subnets/SUBNET_NAME
```

### Audit Logging

Enable diagnostic logging:

```bash
# Create Log Analytics workspace
az monitor log-analytics workspace create \
  --name myLogAnalytics \
  --resource-group myResourceGroup

# Enable diagnostics
az monitor diagnostic-settings create \
  --name KeyVaultDiagnostics \
  --resource /subscriptions/SUBSCRIPTION_ID/resourceGroups/RESOURCE_GROUP/providers/Microsoft.KeyVault/vaults/VAULT_NAME \
  --workspace /subscriptions/SUBSCRIPTION_ID/resourceGroups/RESOURCE_GROUP/providers/Microsoft.OperationalInsights/workspaces/WORKSPACE_NAME \
  --logs '[{"category": "AuditEvent", "enabled": true}]' \
  --metrics '[{"category": "AllMetrics", "enabled": true}]'
```

Query audit logs:

```kusto
AzureDiagnostics
| where ResourceProvider == "MICROSOFT.KEYVAULT"
| where OperationName == "VaultGet" or OperationName == "SecretGet"
| project TimeGenerated, OperationName, CallerIPAddress, identity_claim_http_schemas_xmlsoap_org_ws_2005_05_identity_claims_name_s
| order by TimeGenerated desc
```

### Key Protection

Enable soft-delete and purge protection:

```bash
# Enable soft-delete (enabled by default)
az keyvault update --name myVault --enable-soft-delete true

# Enable purge protection
az keyvault update --name myVault --enable-purge-protection true

# Set retention period
az keyvault update --name myVault --retention-days 90
```

Use managed HSM for highest security:

```bash
# Create managed HSM (FIPS 140-2 Level 3)
az keyvault create --hsm-name myManagedHSM \
  --resource-group myResourceGroup \
  --location eastus \
  --administrators USER_OBJECT_ID
```

## Best Practices

### Vault Organization

Organize vaults by environment and purpose:

```
Production Subscription
  ├─ prod-api-vault (API keys)
  ├─ prod-ca-vault (CA keys)
  └─ prod-secrets-vault (application secrets)

Development Subscription
  ├─ dev-api-vault
  └─ dev-secrets-vault
```

Use naming conventions:

```go
// Good naming
keyID := "production-api-jwt-v2"
keyID := "staging-webhook-ecdsa"
keyID := "ca-root-rsa4096-2024"

// Avoid generic names
keyID := "key1"
keyID := "test"
```

### Error Handling

Handle errors appropriately:

```go
store, err := azurekv.NewBackend(config)
if err != nil {
    return fmt.Errorf("Azure Key Vault initialization failed: %w", err)
}
defer func() {
    if err := store.Close(ctx); err != nil {
        log.Printf("Error closing Azure Key Vault: %v", err)
    }
}()

signature, err := store.Sign(ctx, keyID, digest, crypto.SHA256)
if err != nil {
    if strings.Contains(err.Error(), "Forbidden") {
        return fmt.Errorf("insufficient permissions: %w", err)
    }
    if strings.Contains(err.Error(), "NotFound") {
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
    azureStore backend.Backend
    storeOnce  sync.Once
)

func getAzureStore() (backend.Backend, error) {
    var err error
    storeOnce.Do(func() {
        config := &azurekv.Config{
            VaultURL:           os.Getenv("AZURE_VAULT_URL"),
            UseManagedIdentity: true,
        }
        azureStore, err = azurekv.NewBackend(config)
    })
    return azureStore, err
}
```

### Integration Testing

The Azure Key Vault backend has full integration test coverage using mock/emulator testing:

```bash
# Run Azure Key Vault integration tests (recommended)
make integration-test-azurekv

# This executes tests in Docker with mocked Azure Key Vault service
# Tests all supported algorithms: RSA 2048/3072/4096, ECDSA P-256/P-384/P-521
# Part of the full integration test suite (151/151 tests passing)
```

### Running Tests Manually

```bash
# View test configuration
cat test/integration/azurekv/docker-compose.yml

# Run tests manually
cd test/integration/azurekv
docker-compose run --rm test
docker-compose down -v
```

### Testing Strategy

Use separate vaults for testing:

```go
func getTestBackend(t *testing.T) backend.Backend {
    config := &azurekv.Config{
        VaultURL:           "https://test-vault.vault.azure.net/",
        UseManagedIdentity: true,
    }

    store, err := azurekv.NewBackend(config)
    require.NoError(t, err)

    t.Cleanup(func() {
        store.Close(context.Background())
    })

    return store
}
```

### Cost Optimization

Optimize for cost:

```bash
# Use standard vault for non-critical keys (lower cost)
az keyvault create --name dev-vault --resource-group dev-rg --sku standard

# Use premium vault for HSM-protected keys
az keyvault create --name prod-vault --resource-group prod-rg --sku premium

# Use managed HSM only for highest security requirements
az keyvault create --hsm-name critical-hsm --resource-group prod-rg
```

Monitor costs:

```bash
# View cost analysis in Azure Portal
# Cost Management + Billing > Cost Analysis

# Set budget alerts
az consumption budget create \
  --amount 100 \
  --budget-name KeyVaultBudget \
  --category Cost \
  --time-grain Monthly \
  --time-period start=2024-01-01 \
  --resource-group myResourceGroup
```

## Troubleshooting

### Permission Denied

```
Error: Caller is not authorized to perform action on resource
```

Solutions:
- Verify access policy or RBAC assignment
- Check access policy: `az keyvault show --name myVault --query properties.accessPolicies`
- Grant permissions: `az keyvault set-policy --name myVault --spn CLIENT_ID --key-permissions get list sign`
- For RBAC: `az role assignment create --role "Key Vault Crypto User" --assignee USER_OR_SP_ID --scope VAULT_RESOURCE_ID`
- Wait up to 5 minutes for permission changes to propagate

### Key Not Found

```
Error: Key not found: my-key
```

Solutions:
- Verify key exists: `az keyvault key list --vault-name myVault`
- Check vault URL is correct
- Ensure key hasn't been deleted (check deleted keys)
- Verify you're querying the correct vault

### Authentication Failed

```
Error: Authentication failed: AADSTS700016: Application not found
```

Solutions:
- Verify tenant ID, client ID, and client secret are correct
- Ensure service principal exists: `az ad sp show --id CLIENT_ID`
- Check service principal hasn't expired
- For managed identity, verify it's enabled: `az vm identity show --name myVM`
- Verify environment variables are set correctly

### Vault Not Found

```
Error: The Resource 'Microsoft.KeyVault/vaults/myVault' under resource group 'myResourceGroup' was not found
```

Solutions:
- Verify vault exists: `az keyvault list`
- Check vault name and resource group
- Ensure correct subscription: `az account show`
- Verify vault hasn't been deleted (check soft-deleted vaults)

### Network Access Denied

```
Error: Client address is not authorized and caller is not a trusted service
```

Solutions:
- Check firewall rules: `az keyvault network-rule list --name myVault`
- Add client IP: `az keyvault network-rule add --name myVault --ip-address CLIENT_IP`
- Configure virtual network: `az keyvault update --name myVault --default-action Deny`
- Use private endpoint or service endpoint

## Performance Considerations

### Operation Latency

Typical latencies for Azure Key Vault operations:

- **Sign operation**: 50-150ms
- **Get public key**: 20-80ms
- **Generate key**: 200-400ms
- **List keys**: 100-300ms

Latency varies by:
- Geographic region (choose region near compute)
- Network connectivity (use private link for lowest latency)
- Vault tier (premium vs standard similar for operations)

### Throughput Limits

Default service limits (per vault per 10 seconds):

- **Key operations**: 2,000 transactions
- **Secrets operations**: 2,000 transactions
- **Certificate operations**: 2,000 transactions

Request service limit increase if needed.

### Optimization Tips

1. **Collocate vault and compute**: Use same region for lowest latency
2. **Cache public keys**: Public keys don't change, cache them
3. **Use connection pooling**: Reuse client connections
4. **Implement retry logic**: Use exponential backoff for throttling
5. **Batch operations**: Group operations when possible

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
    return strings.Contains(err.Error(), "TooManyRequests") ||
           strings.Contains(err.Error(), "ServiceUnavailable") ||
           strings.Contains(err.Error(), "Timeout")
}
```

## Advanced Topics

### Bring Your Own Key (BYOK)

Import your own key material:

```bash
# Generate key locally
openssl genrsa -out mykey.pem 2048

# Create key exchange key
az keyvault key create --vault-name myVault \
  --name KEK --kty RSA-HSM --size 2048 --protection hsm

# Download public key
az keyvault key download --vault-name myVault \
  --name KEK --file kek_public.pem

# Wrap your key (requires Azure Key Vault Key Encryptioni Toolkit)
# Import wrapped key
az keyvault key import --vault-name myVault \
  --name imported-key --pem-file mykey.pem --protection hsm
```

### Automated Key Rotation

Configure automatic rotation:

```bash
# Enable auto-rotation (90 days)
az keyvault key rotation-policy update \
  --vault-name myVault \
  --name my-key \
  --value '{
    "lifetimeActions": [{
      "trigger": {"timeAfterCreate": "P90D"},
      "action": {"type": "rotate"}
    }],
    "attributes": {"expiryTime": "P2Y"}
  }'
```

### Disaster Recovery

Configure geo-replication:

```bash
# Azure Key Vault automatically replicates to paired region
# No additional configuration required

# For cross-region disaster recovery:
# 1. Use ARM templates to recreate vault
# 2. Backup and restore keys
az keyvault key backup --vault-name myVault --name my-key --file key-backup.blob
az keyvault key restore --vault-name newVault --file key-backup.blob
```

### Integration with Azure Services

Use with Azure App Service:

```bash
# Enable managed identity
az webapp identity assign --name myApp --resource-group myResourceGroup

# Grant Key Vault access
az keyvault set-policy --name myVault \
  --object-id $(az webapp identity show --name myApp --resource-group myResourceGroup --query principalId -o tsv) \
  --key-permissions get sign verify
```

Use with AKS:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: my-pod
  labels:
    aadpodidbinding: my-identity
spec:
  containers:
  - name: app
    image: myapp:latest
    env:
    - name: AZURE_VAULT_URL
      value: "https://my-vault.vault.azure.net/"
```

## Cost Estimation

### Pricing Components

**Key Vault Operations**:
- Standard tier key operations: $0.03 per 10,000 transactions
- Premium tier (HSM) key operations: $1.00 per 10,000 transactions
- Managed HSM operations: $5.00 per 10,000 transactions

**Key Storage**:
- Standard tier: First 1,000 keys free, then minimal cost
- Premium tier HSM keys: $1.00 per key per month
- Managed HSM: $5.00 per pool per hour

**Example monthly cost** (Standard tier):
```
10 keys x free = $0.00
100,000 sign operations x ($0.03/10,000) = $0.30
Total: $0.30/month
```

**Example monthly cost** (Premium HSM):
```
10 HSM keys x $1.00 = $10.00
100,000 sign operations x ($1.00/10,000) = $10.00
Total: $20.00/month
```

### Cost Optimization Strategies

1. Use standard tier for dev/test environments
2. Delete unused key versions
3. Cache public keys to reduce operations
4. Use managed HSM only for highest security requirements
5. Monitor usage with Azure Cost Management

## Compliance and Certifications

Azure Key Vault compliance:

- **FIPS 140-2 Level 2** (Standard and Premium tiers)
- **FIPS 140-2 Level 3** (Managed HSM)
- **ISO/IEC 27001**, **27018**, **27701**
- **SOC 1**, **SOC 2**, **SOC 3**
- **PCI DSS**
- **HIPAA/HITECH**
- **FedRAMP** (High)
- **IRAP** (Australia)
- **MTCS** (Singapore)

Data residency:
- Keys stored in specified Azure region
- Automatically replicated to paired region
- Customer-controlled geographic boundaries

## Migration Guide

### From On-Premises HSM to Azure Key Vault

```go
func migrateToAzureKeyVault() error {
    ctx := context.Background()

    // Source: PKCS#11 HSM
    pkcs11Config := &pkcs11.Config{
        LibraryPath: "/usr/lib/hsm.so",
        TokenLabel:  "production",
        PIN:         os.Getenv("HSM_PIN"),
    }
    oldStore, err := pkcs11.NewBackend(pkcs11Config)
    if err != nil {
        return err
    }
    defer oldStore.Close(ctx)

    // Target: Azure Key Vault
    azureConfig := &azurekv.Config{
        VaultURL:           "https://prod-vault.vault.azure.net/",
        UseManagedIdentity: true,
    }
    newStore, err := azurekv.NewBackend(azureConfig)
    if err != nil {
        return err
    }
    defer newStore.Close(ctx)

    // Generate new keys in Azure Key Vault
    params := &backend.KeyParams{
        Algorithm: backend.AlgorithmRSA,
        KeySize:   2048,
    }

    if err := newStore.GenerateKey(ctx, "migrated-key", params); err != nil {
        return err
    }

    // Update application to use Azure Key Vault
    // Re-sign data with new keys
    // Retire old HSM keys after transition

    return nil
}
```

## References

- [Azure Key Vault Documentation](https://docs.microsoft.com/en-us/azure/key-vault/)
- [Azure Key Vault REST API](https://docs.microsoft.com/en-us/rest/api/keyvault/)
- [Azure SDK for Go](https://github.com/Azure/azure-sdk-for-go)
- [Azure RBAC Documentation](https://docs.microsoft.com/en-us/azure/role-based-access-control/)
- [Managed Identity Documentation](https://docs.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/)
- [Azure Key Vault Best Practices](https://docs.microsoft.com/en-us/azure/key-vault/general/best-practices)

## Limitations

The Azure Key Vault backend has the following limitations:

- Ed25519 not supported (use ECDSA P-256 instead)
- Keys cannot be exported (security by design)
- Maximum 25 key versions recommended per key
- API rate limits apply (2,000 operations per 10 seconds per vault)
- Some operations require internet connectivity
- Service limits on number of vaults per subscription
- Soft-delete retention period minimum 7 days, maximum 90 days

For on-premises HSM requirements, consider the PKCS#11 backend. For offline key storage, consider the PKCS#8 or TPM backends.
