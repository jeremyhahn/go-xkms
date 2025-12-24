# CLI Reference: migrate Command Group

The `migrate` command group provides tools for migrating cryptographic keys between different backend storage systems. It supports safe, verified migrations with comprehensive validation and rollback capabilities.

## Overview

Key migration enables you to move cryptographic keys from one backend to another while maintaining security and ensuring that migrated keys function correctly in the destination backend. The migration process uses secure key wrapping algorithms to protect key material during transit.

## Commands

### migrate plan

Shows what would be migrated without executing the actual migration (dry-run).

**Usage:**
```bash
keychain migrate plan --from <source-backend> --to <dest-backend> [flags]
```

**Required Flags:**
- `--from` - Source backend name (e.g., pkcs8, pkcs11, tpm2, awskms, gcpkms, azurekv, vault)
- `--to` - Destination backend name

**Filter Flags:**
- `--key-types` - Filter by key types (comma-separated). **General Purpose Keys:** signing, encryption, hmac, secret, tls, ca **TPM 2.0 Keys:** endorsement, attestation, storage, idevid, ldevid, tpm
- `--store-types` - Filter by store types (comma-separated)
- `--partitions` - Filter by partitions (comma-separated)
- `--cn-pattern` - Regex pattern to match common names
- `--created-before` - Only keys created before timestamp (RFC3339 format)
- `--created-after` - Only keys created after timestamp (RFC3339 format)

**Examples:**

Show migration plan for all keys:
```bash
keychain migrate plan --from pkcs8 --to pkcs11
```

Plan migration for only signing keys:
```bash
keychain migrate plan --from pkcs8 --to tpm2 \
  --key-types signing
```

Plan migration for keys matching pattern:
```bash
keychain migrate plan --from awskms --to azurekv \
  --cn-pattern "^prod-.*"
```

Plan migration for recently created keys:
```bash
keychain migrate plan --from gcpkms --to vault \
  --created-after "2024-01-01T00:00:00Z"
```

**Output (Text Format):**
```
Migration Plan
==============
Source Backend:        pkcs8
Destination Backend:   pkcs11
Keys to Migrate:       15
Estimated Duration:    45s
Analysis Timestamp:    2025-12-24T10:30:00Z

Keys:
  1. api.example.com (Type: signing, Algorithm: RSA-2048)
  2. tls.example.com (Type: tls, Algorithm: ECDSA-P256)
  3. ca.example.com (Type: ca, Algorithm: RSA-4096)
  ...

Warnings:
  - Key 'large-key' is 8192 bits, migration may be slower
  - Some keys have associated certificates
```

**Output (JSON Format):**
```bash
keychain migrate plan --from pkcs8 --to pkcs11 --output json
```
```json
{
  "source_backend": "pkcs8",
  "dest_backend": "pkcs11",
  "keys_count": 15,
  "estimated_duration": "45s",
  "timestamp": "2025-12-24T10:30:00Z",
  "warnings": [
    "Key 'large-key' is 8192 bits, migration may be slower"
  ],
  "errors": []
}
```

---

### migrate execute

Executes the actual key migration from source to destination backend.

**Usage:**
```bash
keychain migrate execute --from <source-backend> --to <dest-backend> [flags]
```

**Required Flags:**
- `--from` - Source backend name
- `--to` - Destination backend name

**Migration Behavior Flags:**
- `--delete-source` - Delete keys from source after successful migration and verification (default: false)
- `--skip-verify` - Skip post-migration verification (NOT RECOMMENDED, default: false)
- `--stop-on-error` - Stop entire migration if any key fails (default: false)
- `--parallel` - Number of concurrent migrations (default: 1)
- `--force` - Skip confirmation prompt (default: false)

**Filter Flags:**
Same as `migrate plan` command (see above).

**Examples:**

Basic migration with confirmation:
```bash
keychain migrate execute --from pkcs8 --to pkcs11
```

Migration with automatic confirmation:
```bash
keychain migrate execute --from pkcs8 --to pkcs11 --force
```

Migrate and delete source keys after verification:
```bash
keychain migrate execute --from pkcs8 --to tpm2 \
  --delete-source
```

Parallel migration for better performance:
```bash
keychain migrate execute --from awskms --to azurekv \
  --parallel 4
```

Migrate only signing keys:
```bash
keychain migrate execute --from pkcs11 --to tpm2 \
  --key-types signing
```

Migrate keys matching pattern:
```bash
keychain migrate execute --from gcpkms --to vault \
  --cn-pattern "^staging-.*" \
  --parallel 2 \
  --force
```

Stop on first error:
```bash
keychain migrate execute --from pkcs8 --to pkcs11 \
  --stop-on-error
```

**Interactive Confirmation:**

Without `--force`, the command shows a plan and asks for confirmation:
```
Migration Plan:
  Source: pkcs8
  Destination: pkcs11
  Keys to migrate: 15
  Warnings:
    - Key 'large-key' is 8192 bits, migration may be slower

Proceed with migration? (yes/no): yes
```

**Output (Text Format):**
```
Migration Result
================
Successful:    14
Failed:        1
Skipped:       0
Total Time:    42.5s

Successfully Migrated Keys:
  1. api.example.com
  2. tls.example.com
  3. ca.example.com
  ...

Failed Migrations:
  1. corrupted-key: failed to export key: key not found
```

**Output (JSON Format):**
```bash
keychain migrate execute --from pkcs8 --to pkcs11 --output json --force
```
```json
{
  "successful_count": 14,
  "failure_count": 1,
  "skipped_count": 0,
  "successful_keys": [
    "api.example.com",
    "tls.example.com",
    "ca.example.com"
  ],
  "failed_keys": {
    "corrupted-key": "failed to export key: key not found"
  },
  "start_time": "2025-12-24T10:30:00Z",
  "end_time": "2025-12-24T10:30:42Z",
  "duration": "42.5s"
}
```

---

### migrate validate

Validates that a migrated key works correctly in the destination backend.

**Usage:**
```bash
keychain migrate validate --key-id <key-id> --from <source> --to <dest>
```

**Required Flags:**
- `--key-id` - Key identifier (Common Name) to validate
- `--from` - Source backend name
- `--to` - Destination backend name

**Examples:**

Validate single key migration:
```bash
keychain migrate validate \
  --key-id "api.example.com" \
  --from pkcs8 \
  --to pkcs11
```

**Output (Text Format - Success):**
```
✓ Validation successful: Key 'api.example.com' migrated correctly and is functional
```

**Output (Text Format - Failure):**
```
✗ Validation failed: Key signature verification failed

Errors:
  - Source signature: valid
  - Destination signature: invalid
  - Keys do not match

Warnings:
  - Consider re-running migration for this key
```

**Output (JSON Format):**
```bash
keychain migrate validate \
  --key-id "api.example.com" \
  --from pkcs8 \
  --to pkcs11 \
  --output json
```
```json
{
  "is_valid": true,
  "message": "Key 'api.example.com' migrated correctly and is functional",
  "errors": [],
  "warnings": []
}
```

## Supported Migration Paths

### Local to Local
- **PKCS#8 → PKCS#11** - Software to hardware migration
- **PKCS#8 → TPM2** - Software to TPM chip
- **PKCS#11 → TPM2** - HSM to TPM migration

### Cloud to Local
- **AWS KMS → PKCS#11** - Cloud to hardware
- **GCP KMS → TPM2** - Cloud to TPM
- **Azure Key Vault → PKCS#8** - Cloud to software

### Cloud to Cloud
- **AWS KMS → GCP KMS** - Cross-cloud migration
- **GCP KMS → Azure Key Vault** - Cross-cloud migration
- **Any Cloud → Vault** - Cloud to HashiCorp Vault

### Local to Cloud
- **PKCS#8 → AWS KMS** - Software to cloud
- **PKCS#11 → GCP KMS** - Hardware to cloud
- **TPM2 → Azure Key Vault** - TPM to cloud

### Backend Support Matrix

| Source     | PKCS#8 | PKCS#11 | TPM2 | AWS KMS | GCP KMS | Azure KV | Vault |
|------------|--------|---------|------|---------|---------|----------|-------|
| PKCS#8     | ✓      | ✓       | ✓    | ✓       | ✓       | ✓        | ✓     |
| PKCS#11    | ✓      | ✓       | ✓    | ✓       | ✓       | ✓        | ✓     |
| TPM2       | ✓      | ✓       | ✓    | ✓       | ✓       | ✓        | ✓     |
| AWS KMS    | ✗      | ✓       | ✓    | ✗       | ✓       | ✓        | ✓     |
| GCP KMS    | ✗      | ✓       | ✓    | ✓       | ✗       | ✓        | ✓     |
| Azure KV   | ✗      | ✓       | ✓    | ✓       | ✓       | ✗        | ✓     |
| Vault      | ✓      | ✓       | ✓    | ✓       | ✓       | ✓        | ✗     |

✓ = Migration supported, ✗ = Export from source not supported

## Migration Process

### Step 1: Planning
The migration tool analyzes source and destination backends to determine:
- Which keys can be migrated
- Compatibility between backends
- Estimated migration time
- Potential issues or warnings

### Step 2: Validation
Pre-migration validation checks:
- Source keys are accessible
- Destination backend has capacity
- Key types are compatible
- Required permissions are available

### Step 3: Export
For each key being migrated:
1. Key is exported from source using secure wrapping
2. Wrapping algorithm selected based on key size and type
3. Key material is encrypted during export

### Step 4: Import
Wrapped keys are imported to destination:
1. Destination provides import parameters
2. Wrapped key is securely unwrapped
3. Key is stored with original attributes
4. Associated metadata is preserved

### Step 5: Verification
Unless `--skip-verify` is specified:
1. Key is retrieved from destination
2. Test operations are performed (signing for asymmetric keys)
3. Results are compared with source operations
4. Validation result is recorded

### Step 6: Cleanup (Optional)
If `--delete-source` is specified:
1. Only runs after successful verification
2. Source key is permanently deleted
3. Cleanup is skipped if verification fails

## Wrapping Algorithms

The migration system automatically selects appropriate wrapping algorithms:

### RSA-OAEP
- **RSAES_OAEP_SHA_1** - Legacy, SHA-1 based
- **RSAES_OAEP_SHA_256** - Recommended for keys up to 190 bytes

### Hybrid (RSA + AES-KWP)
- **RSA_AES_KEY_WRAP_SHA_1** - Legacy hybrid approach
- **RSA_AES_KEY_WRAP_SHA_256** - Recommended for large keys (>190 bytes)

The migrator automatically selects the best algorithm based on key size and backend capabilities.

## Common Scenarios

### Scenario 1: Moving from Software to Hardware

Migrate all keys from software (PKCS#8) to hardware security module (PKCS#11):

```bash
# 1. Review migration plan
keychain migrate plan --from pkcs8 --to pkcs11

# 2. Execute migration
keychain migrate execute --from pkcs8 --to pkcs11

# 3. Validate critical keys
keychain migrate validate \
  --key-id "production-ca" \
  --from pkcs8 \
  --to pkcs11

# 4. After confirming all works, delete source keys
keychain migrate execute --from pkcs8 --to pkcs11 \
  --delete-source --force
```

### Scenario 2: Cloud to On-Premise Migration

Migrate keys from AWS KMS to local TPM2:

```bash
# 1. Migrate with parallel processing
keychain migrate execute --from awskms --to tpm2 \
  --parallel 4 \
  --force

# 2. Validate a sample of keys
keychain migrate validate \
  --key-id "api-key-1" \
  --from awskms \
  --to tpm2
```

### Scenario 3: Selective Migration

Migrate only production signing keys created in the last 90 days:

```bash
# Calculate date 90 days ago
DATE_90_DAYS_AGO=$(date -u -d '90 days ago' +%Y-%m-%dT%H:%M:%SZ)

# Plan migration
keychain migrate plan --from pkcs8 --to pkcs11 \
  --key-types signing \
  --cn-pattern "^prod-.*" \
  --created-after "$DATE_90_DAYS_AGO"

# Execute
keychain migrate execute --from pkcs8 --to pkcs11 \
  --key-types signing \
  --cn-pattern "^prod-.*" \
  --created-after "$DATE_90_DAYS_AGO" \
  --parallel 2
```

### Scenario 4: Cross-Cloud Migration

Migrate from GCP KMS to Azure Key Vault:

```bash
# 1. Plan with staging keys first
keychain migrate plan --from gcpkms --to azurekv \
  --cn-pattern "^staging-.*"

# 2. Test with staging
keychain migrate execute --from gcpkms --to azurekv \
  --cn-pattern "^staging-.*" \
  --force

# 3. Migrate production after validation
keychain migrate execute --from gcpkms --to azurekv \
  --cn-pattern "^prod-.*" \
  --parallel 3 \
  --stop-on-error
```

## Best Practices

### 1. Always Plan First
```bash
# Review what will be migrated
keychain migrate plan --from pkcs8 --to pkcs11
```

### 2. Test with Non-Critical Keys
```bash
# Migrate test keys first
keychain migrate execute --from pkcs8 --to pkcs11 \
  --cn-pattern "^test-.*"
```

### 3. Use Appropriate Parallelism
- **Sequential (--parallel 1)**: For small migrations or when testing
- **Low (--parallel 2-4)**: For cloud backends (rate limits)
- **High (--parallel 8-16)**: For local backends with good I/O

### 4. Verify Before Deleting Source
```bash
# First migration without deletion
keychain migrate execute --from pkcs8 --to pkcs11

# Validate critical keys
keychain migrate validate --key-id "critical-key" \
  --from pkcs8 --to pkcs11

# Then delete after verification
keychain migrate execute --from pkcs8 --to pkcs11 \
  --delete-source --force
```

### 5. Use Filtering for Large Migrations
```bash
# Migrate in batches by date
keychain migrate execute --from pkcs8 --to pkcs11 \
  --created-after "2024-01-01T00:00:00Z" \
  --created-before "2024-06-30T23:59:59Z"
```

### 6. Monitor Long-Running Migrations
```bash
# Use verbose output to track progress
keychain migrate execute --from awskms --to azurekv \
  --parallel 4 --verbose
```

## Troubleshooting

### Migration Fails: "Export Not Supported"

**Problem:** Source backend doesn't support key export.

**Solution:** Check the Backend Support Matrix. Some cloud providers restrict key export for compliance reasons.

### "Verification Failed" Error

**Problem:** Migrated key doesn't work in destination backend.

**Causes:**
- Incompatible key algorithm in destination
- Wrapping algorithm not supported
- Key corruption during transfer
- Destination backend configuration issue

**Solutions:**
```bash
# 1. Check backend capabilities
keychain backend info --name pkcs11

# 2. Retry migration with different options
keychain migrate execute --from pkcs8 --to pkcs11 \
  --key-types signing --parallel 1

# 3. Validate individual key
keychain migrate validate --key-id "problem-key" \
  --from pkcs8 --to pkcs11
```

### Timeout During Migration

**Problem:** Migration times out, especially with cloud backends.

**Solutions:**
```bash
# 1. Reduce parallelism
keychain migrate execute --from awskms --to azurekv \
  --parallel 1

# 2. Use filtering to migrate in smaller batches
keychain migrate execute --from awskms --to azurekv \
  --cn-pattern "^batch1-.*" --parallel 2
```

### Destination Backend Full

**Problem:** Destination backend runs out of storage space.

**Solutions:**
```bash
# 1. Check destination capacity
keychain backend status --name pkcs11

# 2. Free up space or increase capacity

# 3. Migrate in smaller batches
keychain migrate execute --from pkcs8 --to pkcs11 \
  --key-types signing  # Migrate only signing keys first
```

### Partial Migration Failure

**Problem:** Some keys migrated successfully, others failed.

**Solutions:**
```bash
# 1. Review the failure report
keychain migrate execute --from pkcs8 --to pkcs11 \
  --output json > migration-result.json

# 2. Re-run migration for failed keys only
# Extract failed key names from JSON and create pattern

# 3. Investigate specific key failures
keychain migrate validate --key-id "failed-key" \
  --from pkcs8 --to pkcs11
```

## Security Considerations

### Key Material Protection
- Keys are always wrapped during export using secure algorithms
- Wrapping uses RSA-OAEP or hybrid RSA+AES encryption
- Key material is never exposed in plaintext during transit

### Transport Security
- Use TLS/HTTPS for all remote backend connections
- Verify certificates for cloud KMS providers
- Use VPC/VPN for cloud-to-cloud migrations

### Audit and Compliance
- All migrations are logged with timestamps
- Failed migrations are recorded for audit purposes
- Use `--verbose` for detailed operation logging

### Cleanup Best Practices
- Verify migration before using `--delete-source`
- Keep backups of source keys until validation is complete
- Test disaster recovery procedures after migration

### Access Control
- Ensure appropriate permissions on both source and destination
- Use separate credentials for source and destination when possible
- Follow principle of least privilege

## Performance Tuning

### Parallel Migration Settings

```bash
# Local backends: Higher parallelism
keychain migrate execute --from pkcs8 --to pkcs11 \
  --parallel 8

# Cloud backends: Lower parallelism (respect rate limits)
keychain migrate execute --from awskms --to azurekv \
  --parallel 2

# Mixed (local to cloud): Moderate parallelism
keychain migrate execute --from pkcs11 --to gcpkms \
  --parallel 4
```

### Batch Processing

For very large migrations (1000+ keys):
```bash
# Migrate in monthly batches
for month in 01 02 03 04 05 06; do
  keychain migrate execute --from pkcs8 --to pkcs11 \
    --created-after "2024-${month}-01T00:00:00Z" \
    --created-before "2024-${month}-31T23:59:59Z" \
    --parallel 4 --force
done
```

## Output Formats

Both text and JSON output formats are supported via the global `--output` flag:

```bash
# Text output (default, human-readable)
keychain migrate plan --from pkcs8 --to pkcs11

# JSON output (machine-readable, for automation)
keychain migrate plan --from pkcs8 --to pkcs11 --output json
```

JSON output is useful for:
- CI/CD pipeline integration
- Automated reporting
- Parsing with jq or other tools
- Long-term audit logs

## Exit Codes

- `0` - Success (all keys migrated successfully)
- `1` - Failure (migration failed or some keys failed without --stop-on-error)
- `2` - Invalid arguments or configuration error

## See Also

- [Key Migration Guide](../key-migration.md) - Detailed migration concepts and API usage
- [Backend Configuration](../../backends/README.md) - Backend setup and configuration
- [Key Import/Export](../key-import-export.md) - Manual import/export operations
- [Getting Started](../getting-started.md) - Initial setup and basic usage
