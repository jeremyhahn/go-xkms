# Key Migration Guide

This guide explains how to migrate cryptographic keys between different backends using go-xkms's service API and migration tools.

## Overview

Key migration enables you to move keys from one storage backend to another while maintaining security and verifying that the migrated keys work correctly in the destination backend.

go-xkms provides two approaches:
1. **Service API**: Use `xkms.CopyKey()` or `xkms.ExportKey()` + `xkms.ImportKey()` for programmatic migration
2. **Migration API**: Use the `migration` package for batch operations with planning, filtering, and verification

### Supported Migration Paths

- **PKCS#8 (Software) to AES** - Convert asymmetric keys to symmetric encryption
- **PKCS#8 to PKCS#11** - Move software keys to hardware security modules
- **PKCS#11 to TPM2** - Migrate between different hardware backends
- **Cloud KMS to Local** - Export keys from AWS KMS, GCP KMS, Azure Key Vault to local storage
- **Any backend pair** - Migrate between any two backends that support import/export

## Simple Migration with CopyKey

The simplest approach for migrating individual keys between backends:

```go
package main

import (
    "fmt"
    "log"

    "github.com/jeremyhahn/go-xkms/pkg/types"
    "github.com/jeremyhahn/go-xkms/pkg/xkms"
)

func main() {
    // Initialize with multiple backends
    if err := xkms.AutoInitialize(&xkms.AutoConfig{
        DataDir: "/var/lib/xkms",
    }); err != nil {
        log.Fatal(err)
    }
    defer xkms.Close()

    // Copy a key from software to PKCS#11
    // CopyKey handles export, wrapping, and import automatically
    err := xkms.CopyKey(
        "software:::my-signing-key", // source key ID
        "pkcs11",                     // destination backend
        nil,                          // nil = same attributes as source
    )
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("Key copied to PKCS#11")

    // Verify the key works in the destination
    sig, err := xkms.Sign("pkcs11:::my-signing-key", []byte("test"), nil)
    if err != nil {
        log.Fatal("verification failed:", err)
    }
    fmt.Printf("Signed with migrated key: %x\n", sig)
}
```

### CopyKey with Custom Destination Attributes

```go
// Copy with different attributes in the destination
destAttrs := &types.KeyAttributes{
    CN:      "new-key-name",
    KeyType: types.KeyTypeSigning,
}

err := xkms.CopyKey("software:::old-key", "pkcs11", destAttrs)
```

## Explicit Export + Import

For more control over the migration process, use the export/import steps separately:

```go
package main

import (
    "fmt"
    "log"

    "github.com/jeremyhahn/go-xkms/pkg/backend"
    "github.com/jeremyhahn/go-xkms/pkg/types"
    "github.com/jeremyhahn/go-xkms/pkg/xkms"
)

func main() {
    if err := xkms.AutoInitialize(&xkms.AutoConfig{
        DataDir: "/var/lib/xkms",
    }); err != nil {
        log.Fatal(err)
    }
    defer xkms.Close()

    // Step 1: Export from source
    wrapped, err := xkms.ExportKey(
        "software:::my-key",
        backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
    )
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Exported: %d bytes wrapped\n", len(wrapped.WrappedKey))

    // Step 2: Import to destination
    destAttrs := &types.KeyAttributes{
        CN:      "my-key",
        KeyType: types.KeyTypeSigning,
    }

    err = xkms.ImportKey("pkcs11", destAttrs, wrapped)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("Import successful")

    // Step 3: Verify in destination
    sig, err := xkms.Sign("pkcs11:::my-key", []byte("test data"), nil)
    if err != nil {
        log.Fatal("verification failed:", err)
    }
    fmt.Printf("Verified: signature %x\n", sig)

    // Step 4 (optional): Delete from source
    err = xkms.DeleteKeyByID("software:::my-key")
    if err != nil {
        log.Printf("warning: failed to delete source key: %v", err)
    }
}
```

## Batch Migration with the Migration API

For large-scale migrations, use the `migration` package:

### Basic Batch Migration

```go
package main

import (
    "log"

    "github.com/jeremyhahn/go-xkms/pkg/migration"
    "github.com/jeremyhahn/go-xkms/pkg/xkms"
)

func main() {
    if err := xkms.AutoInitialize(&xkms.AutoConfig{
        DataDir: "/var/lib/xkms",
    }); err != nil {
        log.Fatal(err)
    }
    defer xkms.Close()

    // Get backend instances for the migrator
    sourceBackend, _ := xkms.GetBackend("software")
    destBackend, _ := xkms.GetBackend("pkcs11")

    // Create migrator
    migrator, err := migration.NewMigrator(
        sourceBackend.KeyProvider(),
        destBackend.KeyProvider(),
    )
    if err != nil {
        log.Fatal(err)
    }
    defer migrator.Close()

    // Get a migration plan (dry-run)
    plan, err := migrator.MigrationPlan(nil)
    if err != nil {
        log.Fatal(err)
    }
    log.Printf("Will migrate %d keys\n", len(plan.Keys))

    // Execute the migration
    result, err := migrator.MigrateAll(nil, &migration.MigrateOptions{})
    if err != nil {
        log.Fatal(err)
    }

    log.Printf("Migrated: %d success, %d failed\n",
        result.SuccessCount, result.FailureCount)
}
```

### Filtering Keys

```go
// Migrate only signing keys created in the last month
filter := &migration.KeyFilter{
    KeyTypes: []types.KeyType{types.KeyTypeSigning},
    CreatedAfter: &time.Time{
        // Time 30 days ago
    },
}

result, err := migrator.MigrateAll(filter, &migration.MigrateOptions{})
```

### Migration Options

```go
opts := &migration.MigrateOptions{
    // Delete key from source after successful verification
    DeleteSourceAfterVerification: true,

    // Skip verification of migrated keys (not recommended)
    SkipVerification: false,

    // Stop entire migration if any key fails
    StopOnError: false,

    // Number of concurrent migrations
    Parallel: 4,

    // Timeout for each key migration
    Timeout: &time.Duration{/* 30 seconds */},

    // Retry failed migrations
    RetryCount: 2,
}

result, err := migrator.MigrateAll(filter, opts)
```

## Using the CLI

### Plan a Migration (Dry-Run)

```bash
xkmsctl migrate plan --from software --to pkcs11 \
  --key-types signing encryption hmac
```

Options:
- `--from` - Source backend (required)
- `--to` - Destination backend (required)
- `--key-types` - Filter by key type (signing, encryption, hmac, secret, tls, ca, endorsement, attestation, storage, idevid, ldevid, tpm)
- `--store-types` - Filter by store type
- `--partitions` - Filter by partition
- `--cn-pattern` - Regex pattern for Common Names
- `--created-before` - Filter keys created before (RFC3339)
- `--created-after` - Filter keys created after (RFC3339)

### Execute a Migration

```bash
xkmsctl migrate execute --from software --to pkcs11 \
  --key-types signing
```

The CLI will:
1. Show the migration plan
2. Ask for confirmation before proceeding
3. Execute the migration
4. Report results

Options in addition to filtering options:
- `--delete-source` - Delete keys from source after verification
- `--skip-verify` - Skip post-migration verification (not recommended)
- `--stop-on-error` - Stop if any key fails
- `--parallel N` - Number of concurrent migrations (default: 1)
- `--force` - Skip confirmation prompt

### Validate Migrated Keys

```bash
xkmsctl migrate validate --from software --to pkcs11 \
  --key-id "api.example.com"
```

## Migration Process Details

### Step 1: Key Export

The source backend exports the key using a wrapping algorithm:

1. Source backend generates or retrieves the key
2. Key is wrapped using the specified algorithm (RSA-OAEP or hybrid RSA+AES)
3. Wrapped key is returned with metadata

### Step 2: Key Import

The destination backend imports the wrapped key:

1. Destination backend provides import parameters (wrapping public key)
2. Wrapped key is unwrapped using the destination's private key
3. Unwrapped key is stored in the destination backend
4. Key is associated with the provided attributes

### Step 3: Validation (Optional)

Post-migration validation ensures the key works:

1. Key is retrieved from destination backend
2. For asymmetric keys: a test signing operation is performed
3. For symmetric keys: existence check is performed
4. Validation result is returned

### Step 4: Source Cleanup (Optional)

If requested, the source key is deleted:

1. Key is deleted from source backend after successful validation
2. This ensures no duplicate exists

## Wrapping Algorithms

Different algorithms are used to wrap keys during export:

### RSA-OAEP Algorithms
- `RSAES_OAEP_SHA_1` - RSA with SHA-1 (legacy)
- `RSAES_OAEP_SHA_256` - RSA with SHA-256 (recommended for small keys)

### Hybrid Algorithms (RSA + AES-KWP)
- `RSA_AES_KEY_WRAP_SHA_1` - Hybrid with SHA-1
- `RSA_AES_KEY_WRAP_SHA_256` - Hybrid with SHA-256 (recommended for large keys)

The migrator automatically selects an appropriate algorithm based on the key type.

## Backend Support Matrix

| Source | PKCS#8 | PKCS#11 | TPM2 | AWS KMS | GCP KMS | Azure KV | Vault |
|--------|--------|---------|------|---------|---------|----------|-------|
| PKCS#8 | Yes    | Yes     | Yes  | Yes     | Yes     | Yes      | Yes   |
| PKCS#11| Yes    | Yes     | Yes  | Yes     | Yes     | Yes      | Yes   |
| TPM2   | Yes    | Yes     | Yes  | Yes     | Yes     | Yes      | Yes   |
| AWS KMS| No     | Yes     | Yes  | No      | Yes     | Yes      | Yes   |
| GCP KMS| No     | Yes     | Yes  | Yes     | No      | Yes      | Yes   |
| Azure KV|No     | Yes     | Yes  | Yes     | Yes     | No       | Yes   |
| Vault  | Yes    | Yes     | Yes  | Yes     | Yes     | Yes      | No    |

Yes = Export supported, No = Export not supported

## Best Practices

### 1. Always Plan Before Executing

```go
plan, err := migrator.MigrationPlan(filter)
if len(plan.Warnings) > 0 {
    // Address warnings before proceeding
}
```

### 2. Verify After Migration

```go
// Verify the key works in the destination via the service API
sig, err := xkms.Sign("pkcs11:::migrated-key", testData, nil)
if err != nil {
    log.Fatal("migration verification failed:", err)
}
```

### 3. Backup Source Keys First

Always keep a backup of source keys before deleting:

```go
opts := &migration.MigrateOptions{
    DeleteSourceAfterVerification: false, // Manually verify first
}
```

### 4. Use Appropriate Parallelism

- Sequential (Parallel=1) for small migrations
- Parallel for large migrations with hardware backends
- Monitor resource usage when using high parallelism

### 5. Test with Non-Critical Keys First

Always test migration with a few non-critical keys before migrating production keys.

## Troubleshooting

### Migration Fails with "Export Not Supported"

The source backend doesn't support key export. Check capabilities:

```go
caps, err := xkms.GetBackendCapabilities("awskms")
if !caps.SupportsImportExport {
    log.Fatal("backend doesn't support export")
}
```

### "Verification Failed" Error

The migrated key doesn't work in the destination backend. Common causes:

1. **Incompatible Key Type** - Destination backend doesn't support the key algorithm
2. **Algorithm Mismatch** - Wrapping algorithm not supported by destination
3. **Corruption** - Key data was corrupted during transport

**Solution**:
- Check destination backend capabilities
- Try with different wrapping algorithm
- Verify network/storage integrity

### Timeout During Migration

Cloud KMS backends may timeout for large keys or slow connections.

**Solution**:
- Increase `Timeout` value
- Reduce `Parallel` count
- Check network connectivity

### Destination Backend Full

Destination backend ran out of storage during migration.

**Solution**:
- Free up space in destination backend
- Resume migration with retry

## CLI Examples

### Migrate All Signing Keys from Software to PKCS#11

```bash
xkmsctl migrate execute \
  --from software \
  --to pkcs11 \
  --key-types signing \
  --delete-source
```

### Migrate Keys Matching Pattern

```bash
xkmsctl migrate execute \
  --from awskms \
  --to azurekv \
  --cn-pattern "^prod-.*" \
  --parallel 4
```

### Migrate Keys Created in Last Week

```bash
xkmsctl migrate execute \
  --from gcpkms \
  --to vault \
  --created-after "$(date -u -d '1 week ago' +%Y-%m-%dT%H:%M:%SZ)"
```

## Security Considerations

1. **Key Material Never Exposed**: During wrapped export, key material is always encrypted
2. **Transport Security**: Ensure HTTPS/TLS for remote backends
3. **Source Cleanup**: Enable `DeleteSourceAfterVerification` after successful migration
4. **Backup**: Keep backup of source keys until migration is verified
5. **Audit Logging**: Log all migration operations for compliance

## Performance Tuning

### Parallel Migrations

Use parallel migrations for better throughput with local backends:

```go
opts := &migration.MigrateOptions{
    Parallel: 8, // Adjust based on system resources
}
```

### Batch Migrations

For large-scale migrations, process in batches:

```go
const batchSize = 100
for i := 0; i < len(allKeys); i += batchSize {
    batch := allKeys[i:min(i+batchSize, len(allKeys))]
    // Migrate batch
}
```

### Monitor Progress

For long-running migrations, monitor progress:

```go
result, err := migrator.MigrateAll(filter, opts)
if err != nil {
    log.Printf("Migration failed after %d successes: %v",
        result.SuccessCount, err)
}
```

## See Also

- [Key Import/Export Guide](key-import-export.md)
- [Backend Configuration Guide](../backends/README.md)
- [Backend Registry](../architecture/backend-registry.md)
