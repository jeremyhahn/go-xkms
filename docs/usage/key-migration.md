# Key Migration Guide

This guide explains how to migrate cryptographic keys between different backends using go-keychain's migration tools.

## Overview

Key migration enables you to move keys from one storage backend to another while maintaining security and verifying that the migrated keys work correctly in the destination backend.

### Supported Migration Paths

- **PKCS#8 (Software) to AES** - Convert asymmetric keys to symmetric encryption
- **PKCS#8 to PKCS#11** - Move software keys to hardware security modules
- **PKCS#11 to TPM2** - Migrate between different hardware backends
- **Cloud KMS to Local** - Export keys from AWS KMS, GCP KMS, Azure Key Vault to local storage
- **Any backend pair** - Migrate between any two backends that support import/export

## Prerequisites

1. Both source and destination backends must be properly configured
2. Backends must support the `ImportExportBackend` interface
3. Source keys must be accessible from the source backend
4. Destination backend must have sufficient storage capacity

## Using the Migration API

### Basic Migration Example

```go
package main

import (
	"log"

	"github.com/jeremyhahn/go-keychain/pkg/backend/software"
	"github.com/jeremyhahn/go-keychain/pkg/migration"
	"github.com/jeremyhahn/go-keychain/pkg/storage/fs"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

func main() {
	// Create source backend (e.g., software backend)
	memfs := fs.NewMemFS()
	store, _ := file.New(memfs)
	sourceBackend, _ := software.NewBackend(&software.Config{KeyStorage: store})
	defer sourceBackend.Close()

	// Create destination backend
	destFS := fs.NewMemFS()
	destStore, _ := file.New(destFS)
	destBackend, _ := software.NewBackend(&software.Config{KeyStorage: destStore})
	defer destBackend.Close()

	// Create migrator
	migrator, err := migration.NewMigrator(sourceBackend, destBackend)
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

	log.Printf("Successfully migrated %d keys\n", result.SuccessCount)
	log.Printf("Failed migrations: %d\n", result.FailureCount)
}
```

### Filtering Keys

You can filter which keys to migrate using the `KeyFilter` structure:

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

Control migration behavior with `MigrateOptions`:

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

Before executing a migration, always create a plan to see what will be migrated:

```bash
keychain migrate plan --from pkcs8 --to pkcs11 \
  --key-types signing encryption
```

Options:
- `--from` - Source backend (required)
- `--to` - Destination backend (required)
- `--key-types` - Filter by key type (signing, encryption, ca, tls)
- `--store-types` - Filter by store type
- `--partitions` - Filter by partition
- `--cn-pattern` - Regex pattern for Common Names
- `--created-before` - Filter keys created before (RFC3339)
- `--created-after` - Filter keys created after (RFC3339)

### Execute a Migration

```bash
keychain migrate execute --from pkcs8 --to pkcs11 \
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

After migration, validate that keys work in the destination:

```bash
keychain migrate validate --from pkcs8 --to pkcs11 \
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
| PKCS#8 | ✓      | ✓       | ✓    | ✓       | ✓       | ✓        | ✓     |
| PKCS#11| ✓      | ✓       | ✓    | ✓       | ✓       | ✓        | ✓     |
| TPM2   | ✓      | ✓       | ✓    | ✓       | ✓       | ✓        | ✓     |
| AWS KMS| ✗      | ✓       | ✓    | ✗       | ✓       | ✓        | ✓     |
| GCP KMS| ✗      | ✓       | ✓    | ✓       | ✗       | ✓        | ✓     |
| Azure KV|✗      | ✓       | ✓    | ✓       | ✓       | ✗        | ✓     |
| Vault  | ✓      | ✓       | ✓    | ✓       | ✓       | ✓        | ✗     |

✓ = Export supported, ✗ = Export not supported

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
opts := &migration.MigrateOptions{
	SkipVerification: false, // Always verify
}
result, err := migrator.MigrateAll(filter, opts)
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

The source backend doesn't support key export. Check if the backend implements `ImportExportBackend`.

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

## Examples

### Migrate All Signing Keys from PKCS#8 to PKCS#11

```bash
keychain migrate execute \
  --from pkcs8 \
  --to pkcs11 \
  --key-types signing \
  --delete-source
```

### Migrate Keys Matching Pattern

```bash
keychain migrate execute \
  --from awskms \
  --to azurekv \
  --cn-pattern "^prod-.*" \
  --parallel 4
```

### Migrate Keys Created in Last Week

```bash
keychain migrate execute \
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

- [Backend Configuration Guide](../backends/README.md)
- [Key Management API](../api/keys.md)
- [Security Best Practices](../security/best-practices.md)
