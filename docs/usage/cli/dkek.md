# DKEK CLI Command

The `dkek` command manages Device Key Encryption Key (DKEK) operations for SmartCard-HSM devices using Shamir's Secret Sharing.

## Overview

DKEK (Device Key Encryption Key) is a security mechanism that uses Shamir's Secret Sharing to split a device encryption key into multiple shares. These shares can be distributed to multiple administrators for secure key backup and restore operations.

**Key Features:**
- Split master key into N shares
- Reconstruct key from any M of N shares (threshold)
- Distributed key custody among multiple administrators
- Secure backup and disaster recovery
- PKCS#11 SmartCard-HSM integration

**Build Requirement:**
This command requires the `pkcs11` build tag and is only available when compiled with PKCS#11 support.

```bash
# Build with PKCS#11 support
make build WITH_PKCS11=1

# Verify DKEK command is available
keychain dkek --help
```

## Available Commands

### dkek generate

Generate a new DKEK and split it into shares using Shamir's Secret Sharing.

```bash
keychain dkek generate [flags]
```

**Flags:**
- `--shares, -n <count>` - Total number of shares to create (default: 5)
- `--threshold, -t <count>` - Minimum shares needed to reconstruct DKEK (default: 3)

**Examples:**

```bash
# Generate DKEK with default settings (5 shares, threshold 3)
keychain dkek generate

# Generate with custom share configuration
keychain dkek generate --shares 7 --threshold 4

# Generate with minimum security (3 of 5)
keychain dkek generate -n 5 -t 3

# Generate with high security (5 of 7)
keychain dkek generate -n 7 -t 5
```

**Output (text format):**
```
Successfully generated 5 DKEK shares
Threshold: 3 shares required for reconstruction
```

**Output (JSON format):**
```bash
keychain --output json dkek generate --shares 5 --threshold 3
```

```json
{
  "shares": 5,
  "threshold": 3,
  "message": "Successfully generated 5 DKEK shares",
  "share_indices": [
    {"index": 1, "stored": true},
    {"index": 2, "stored": true},
    {"index": 3, "stored": true},
    {"index": 4, "stored": true},
    {"index": 5, "stored": true}
  ]
}
```

### dkek list

List all DKEK shares stored in the backend.

```bash
keychain dkek list
```

**Examples:**

```bash
# List shares in text format
keychain dkek list

# List shares in JSON format
keychain --output json dkek list
```

**Output (text format):**
```
Total shares: 5
Threshold: 3 shares required
```

**Output (JSON format):**
```json
{
  "total_shares": 5,
  "threshold": 3,
  "shares": [
    {"index": 1},
    {"index": 2},
    {"index": 3},
    {"index": 4},
    {"index": 5}
  ]
}
```

**Security Note:** Share values are never displayed in CLI output for security reasons. Only share indices are shown.

### dkek verify

Verify that DKEK shares are valid and sufficient for reconstruction.

```bash
keychain dkek verify
```

This command checks the integrity of stored shares without actually reconstructing the DKEK.

**Examples:**

```bash
# Verify shares
keychain dkek verify

# Verify with JSON output
keychain --output json dkek verify
```

**Output (text format):**
```
DKEK shares are valid and sufficient for reconstruction
Shares count: 5
Threshold: 3
```

**Output (JSON format):**
```json
{
  "valid": true,
  "shares_count": 5,
  "threshold": 3,
  "message": "DKEK shares are valid and sufficient for reconstruction"
}
```

**Failure Output:**
```bash
keychain dkek verify
# Error: DKEK share verification failed: insufficient shares (have: 2, need: 3)
```

### dkek delete

Delete one or all DKEK shares.

```bash
keychain dkek delete [share-index] [flags]
```

**Arguments:**
- `[share-index]` - Index of the share to delete (optional)

**Flags:**
- `--all, -a` - Delete all DKEK shares

**Examples:**

```bash
# Delete a specific share
keychain dkek delete 3

# Delete all shares
keychain dkek delete --all

# Delete all shares (short flag)
keychain dkek delete -a
```

**Output:**
```
# Single share deletion
Successfully deleted DKEK share 3

# All shares deletion
Successfully deleted all DKEK shares
```

**Error Handling:**
```bash
# Must specify share index or --all flag
keychain dkek delete
# Error: must specify either a share index or --all flag

# Invalid share index
keychain dkek delete 99
# Error: failed to delete DKEK share: share not found: 99
```

## Shamir's Secret Sharing

DKEK uses Shamir's Secret Sharing Scheme (SSSS) to split the master key into multiple shares.

### How It Works

1. **Generate:** Master key is split into N shares
2. **Distribute:** Each share is given to a different administrator
3. **Reconstruct:** Any M of N shares can reconstruct the original key
4. **Security:** M-1 shares reveal nothing about the master key

### Share Configuration

Choose your share configuration based on security and availability requirements:

| Configuration | Shares (N) | Threshold (M) | Security | Availability | Use Case |
|---------------|------------|---------------|----------|--------------|----------|
| 3-of-5 | 5 | 3 | Medium | High | Standard deployments |
| 5-of-7 | 7 | 5 | High | Medium | High-security environments |
| 2-of-3 | 3 | 2 | Low | Very High | Small teams |
| 4-of-6 | 6 | 4 | Medium-High | Medium | Balanced approach |
| 6-of-9 | 9 | 6 | Very High | Medium-Low | Maximum security |

**Guidelines:**
- **Security:** Higher threshold (M) = more security (more shares required)
- **Availability:** Lower threshold = easier key recovery (fewer shares needed)
- **Total Shares (N):** Should be larger than threshold to allow for lost shares
- **Recommended:** N = M + 2 (allows loss of 2 shares)

## Complete Workflow

### Initial Setup

```bash
# 1. Verify PKCS#11 backend is available
keychain backends info pkcs11

# 2. Configure SmartCard-HSM backend
keychain --backend pkcs11 init

# 3. Generate DKEK shares
keychain dkek generate --shares 5 --threshold 3

# 4. Verify shares were created
keychain dkek list

# 5. Validate share integrity
keychain dkek verify
```

### Share Distribution

After generating shares, distribute them to different administrators:

```bash
# Each administrator should securely receive their share
# Shares are stored in the backend's secure storage
# Physical distribution depends on your HSM's capabilities

# Example workflow:
# 1. Administrator 1 receives share 1
# 2. Administrator 2 receives share 2
# 3. Administrator 3 receives share 3
# 4. Administrator 4 receives share 4
# 5. Administrator 5 receives share 5

# Verify distribution
keychain dkek list
```

### Key Recovery

When you need to recover the DKEK (disaster recovery):

```bash
# 1. Collect threshold number of shares from administrators
# (At least 3 shares for default 3-of-5 configuration)

# 2. Verify shares are sufficient
keychain dkek verify

# 3. Reconstruct DKEK (performed automatically during restore operations)
# The HSM will use available shares to reconstruct the master key
```

### Share Rotation

Periodically rotate DKEK shares for security:

```bash
# 1. Generate new DKEK shares
keychain dkek generate --shares 5 --threshold 3

# 2. Distribute new shares to administrators

# 3. Delete old shares after confirmation
keychain dkek delete --all

# 4. Verify new shares
keychain dkek verify
```

## Backend Requirements

The DKEK command requires:

1. **Build Tag:** Compiled with `pkcs11` build tag
2. **Backend:** SmartCard-HSM PKCS#11 backend configured
3. **Hardware:** SmartCard-HSM device (or compatible HSM)

### Supported Devices

DKEK operations are supported on:
- SmartCard-HSM (USB and card form factors)
- Nitrokey HSM
- Compatible PKCS#11 devices with DKEK support

### Backend Configuration

```bash
# Configure PKCS#11 backend for SmartCard-HSM
cat > keychain.yaml <<EOF
backend: pkcs11
pkcs11:
  library_path: /usr/lib/opensc-pkcs11.so
  token_label: SmartCard-HSM
  pin: $HSM_PIN
EOF

# Use configuration file
keychain --config keychain.yaml dkek generate
```

## Security Considerations

### Share Protection

- **Never** store all shares in one location
- Distribute shares to different physical locations
- Use secure channels for share transmission
- Document share custody (who has which shares)
- Implement share rotation policies

### Threshold Selection

- **Too Low:** Compromises security (easy to reconstruct)
- **Too High:** Reduces availability (hard to recover)
- **Recommended:** At least 3 shares required (threshold ≥ 3)

### Access Control

- Limit DKEK operations to administrators only
- Audit all DKEK operations
- Implement multi-person authorization for sensitive operations
- Use RBAC to control access to DKEK commands

### Disaster Recovery

- **Document** share distribution and custody
- **Test** recovery procedures regularly
- **Maintain** secure offline backups of share locations
- **Plan** for share holder unavailability

## Error Handling

### Backend Not Supported

```bash
keychain dkek generate
# Error: backend does not support DKEK operations (not a SmartCard-HSM backend)
```

**Solution:** Ensure you're using the SmartCard-HSM backend:
```bash
keychain --backend pkcs11 dkek generate
```

### Build Tag Missing

```bash
keychain dkek
# Error: command not found
```

**Solution:** Rebuild with PKCS#11 support:
```bash
make clean
make build WITH_PKCS11=1
```

### Insufficient Shares

```bash
keychain dkek verify
# Error: DKEK share verification failed: insufficient shares (have: 2, need: 3)
```

**Solution:** Generate missing shares or reduce threshold:
```bash
# Regenerate with current shares present
keychain dkek generate --threshold 2  # Lower threshold
# or
keychain dkek generate --shares 5 --threshold 3  # Generate new shares
```

### Share Not Found

```bash
keychain dkek delete 10
# Error: failed to delete DKEK share: share not found: 10
```

**Solution:** List available shares first:
```bash
keychain dkek list
keychain dkek delete 3  # Use valid share index
```

## Global Flags

All DKEK commands support these global flags:

```bash
--output <format>     Output format: text, json (default: text)
--config <path>       Configuration file path
--backend <name>      Backend to use (must be pkcs11)
--verbose             Enable verbose logging
```

## Examples

### Development Environment

```bash
# Quick setup with default settings
keychain --backend pkcs11 dkek generate
keychain dkek list
keychain dkek verify
```

### Production Environment

```bash
# High-security configuration
keychain --config /etc/keychain/prod.yaml dkek generate \
  --shares 7 \
  --threshold 5

# Verify and document share distribution
keychain --config /etc/keychain/prod.yaml dkek list > shares-inventory.txt

# Verify before going live
keychain --config /etc/keychain/prod.yaml dkek verify
```

### Disaster Recovery Test

```bash
# 1. List current shares
keychain dkek list

# 2. Delete test shares (non-production only!)
keychain dkek delete 4
keychain dkek delete 5

# 3. Verify remaining shares are sufficient
keychain dkek verify  # Should succeed with 3-of-5 configuration

# 4. Regenerate full share set
keychain dkek generate --shares 5 --threshold 3
```

### Share Rotation Procedure

```bash
# 1. Backup current share information
keychain --output json dkek list > dkek-backup-$(date +%Y%m%d).json

# 2. Generate new shares
keychain dkek generate --shares 5 --threshold 3

# 3. Distribute new shares to administrators
# (Implementation-specific)

# 4. Verify new shares
keychain dkek verify

# 5. Document rotation in audit log
echo "$(date): DKEK shares rotated" >> /var/log/keychain/audit.log
```

## Best Practices

### Operational Security

1. **Minimize Exposure:** Only generate shares when necessary
2. **Secure Storage:** Store shares in tamper-evident containers
3. **Physical Security:** Use safes, safety deposit boxes, or secure facilities
4. **Access Logging:** Audit all DKEK operations
5. **Regular Testing:** Verify recovery procedures periodically

### Share Management

1. **Documentation:** Maintain secure registry of share custody
2. **Escrow:** Consider using professional escrow services
3. **Redundancy:** Generate more shares than minimum required
4. **Rotation:** Rotate shares on regular schedule or after personnel changes
5. **Recovery Testing:** Test key reconstruction annually

### Compliance

For regulated environments:

```bash
# Enable audit logging
keychain --verbose --audit-log /var/log/keychain/audit.log \
  dkek generate --shares 7 --threshold 5

# Document compliance requirements in configuration
cat > /etc/keychain/compliance.yaml <<EOF
dkek:
  shares: 7
  threshold: 5
  rotation_days: 90
  audit_required: true
EOF
```

## Troubleshooting

### Device Not Found

```bash
keychain dkek generate
# Error: failed to create backend: PKCS#11 device not found
```

**Solution:**
```bash
# Check device connection
pkcs11-tool --module /usr/lib/opensc-pkcs11.so --list-slots

# Verify library path
ls -l /usr/lib/opensc-pkcs11.so

# Test with verbose logging
keychain --verbose --backend pkcs11 dkek list
```

### PIN Required

```bash
keychain dkek generate
# Error: PIN required for PKCS#11 device
```

**Solution:**
```bash
# Provide PIN via config file
keychain --config /etc/keychain/config.yaml dkek generate

# Or via environment variable
export PKCS11_PIN="123456"
keychain --backend pkcs11 dkek generate
```

### Share Verification Failed

```bash
keychain dkek verify
# Error: DKEK share verification failed: corrupted share data
```

**Solution:**
```bash
# Delete corrupted shares
keychain dkek delete --all

# Regenerate fresh shares
keychain dkek generate --shares 5 --threshold 3

# Verify integrity
keychain dkek verify
```

## See Also

- [PKCS#11 Backend](../../backends/pkcs11.md) - PKCS#11 backend configuration
- [SmartCard-HSM Backend](../../backends/smartcardhsm.md) - SmartCard-HSM specific features
- [Nitrokey HSM Backend](../../backends/nitrokey-hsm.md) - Nitrokey HSM integration
- [Build System](../../configuration/build-system.md) - Enabling PKCS#11 build tag
