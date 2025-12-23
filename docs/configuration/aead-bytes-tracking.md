# AEAD Bytes Tracking

## Overview

AEAD bytes tracking enforces usage limits on symmetric encryption keys to prevent security degradation per NIST SP 800-38D guidelines. This feature automatically tracks the total volume of data encrypted with a single key and prevents exceeding safe limits.

**Important:** AEAD tracking is **enabled by default** for all backends with symmetric encryption support. This provides automatic protection against nonce reuse and excessive data encryption with a single key.

## Quick Start

### Default Behavior (Recommended)

All backends automatically enable AEAD tracking with these defaults:
- **Nonce tracking**: Enabled (prevents nonce reuse)
- **Bytes tracking**: Enabled (enforces 350GB limit per NIST guidelines)
- **Default limit**: 350GB per key

No configuration needed - just use the backend:

```go
// All backends enable AEAD tracking automatically
backend, err := symmetric.NewBackend(storage, password, nil)
// or
backend, err := pkcs11.NewBackend(config)
// or
backend, err := tpm2.NewTPM2KeyStore(config, nil, keyStorage, certStorage, nil)

// AEAD tracking is active - no additional configuration required
key, err := backend.GenerateSymmetricKey(attrs)
```

### Customizing Limits

Configure custom limits per backend using the `Tracker` field:

```go
import "github.com/jeremyhahn/go-keychain/pkg/backend"

// Create custom tracker with 100GB limit
tracker := backend.NewMemoryAEADTracker()

// For AES backend
config := &symmetric.Config{
    Tracker: tracker,
}
backend, err := symmetric.NewBackend(storage, password, config)

// For PKCS11 backend
pkcs11Config := &pkcs11.Config{
    Tracker: tracker,
    // ... other config
}
backend, err := pkcs11.NewBackend(pkcs11Config)

// For TPM2 backend
tpm2Config := &tpm2.Config{
    Tracker: tracker,
    // ... other config
}
backend, err := tpm2.NewTPM2KeyStore(tpm2Config, nil, keyStorage, certStorage, nil)

// For cloud backends (AWS KMS, GCP KMS, Azure KV, Vault)
cloudConfig := &awskms.Config{
    Tracker: tracker,
    // ... other config
}
backend, err := awskms.NewBackend(cloudConfig)

// Then set custom options per key
keyID := attrs.ID()
customOpts := &types.AEADOptions{
    NonceTracking:      true,
    BytesTracking:      true,
    BytesTrackingLimit: 100 * 1024 * 1024 * 1024, // 100GB
    NonceSize:          12,
}
err = tracker.SetAEADOptions(keyID, customOpts)
```

### Disabling AEAD Tracking

⚠️ **WARNING**: Disabling AEAD tracking removes critical security protections. Only disable for:
- Development/testing environments
- Non-production use cases
- When you have alternative safety mechanisms

**DO NOT disable in production systems.**

```go
// Option 1: Disable for specific key after generation
keyID := attrs.ID()
opts := &types.AEADOptions{
    NonceTracking:      false,  // Removes nonce reuse protection
    BytesTracking:      false,  // Removes byte limit enforcement
}
err = tracker.SetAEADOptions(keyID, opts)

// Option 2: Use backend without tracker (not recommended)
config := &symmetric.Config{
    Tracker: nil,  // Creates default tracker - cannot fully disable
}
// NOTE: Even with nil, a default memory tracker is created for safety

// Option 3: Disable bytes tracking only (keep nonce tracking)
opts := &types.AEADOptions{
    NonceTracking:      true,   // Still prevent nonce reuse
    BytesTracking:      false,  // Remove byte limits (not recommended)
}
```

### Supported Backends

AEAD tracking is available on all backends with symmetric encryption:

| Backend | Tracking Type | Default Enabled |
|---------|---------------|-----------------|
| AES | Full (nonce + bytes) | ✅ Yes |
| Software | Full (nonce + bytes) | ✅ Yes |
| PKCS11 | Full (nonce + bytes) | ✅ Yes |
| SmartCard-HSM | Full (nonce + bytes) | ✅ Yes (via PKCS11) |
| TPM2 | Full (nonce + bytes) | ✅ Yes |
| Azure Key Vault | Full (nonce + bytes) | ✅ Yes |
| AWS KMS | Bytes only* | ✅ Yes |
| GCP KMS | Bytes only* | ✅ Yes |
| Vault | Bytes only* | ✅ Yes |

*Cloud backends with server-side nonce management only track bytes (nonce reuse is prevented by the service).

## Security Rationale

### Why Limit Bytes Encrypted?

NIST SP 800-38D provides clear guidelines on the maximum amount of data that should be encrypted with a single AEAD key:

1. **Random 96-bit IVs**: Maximum ~68GB (birthday paradox limit)
   - After ~2^32 invocations, nonce collisions become probable
   - Nonce collision breaks AEAD security guarantees

2. **Deterministic IVs with Nonce Tracking**: Up to 350GB is conservative
   - With nonce uniqueness guaranteed, higher limits are acceptable
   - 350GB provides strong security margins

3. **Security Degradation**: Encrypting excessive data reduces security margins
   - Increases probability of statistical attacks
   - May violate cryptographic assumptions

## Features

### Automatic Bytes Counting
- Tracks total plaintext bytes encrypted per key
- Thread-safe using atomic operations
- Zero performance overhead (single atomic increment)

### Configurable Limits
- Default: 350GB (conservative for AEAD with nonce tracking)
- Custom limits per key
- Option to disable (not recommended for production)

### Error Handling
- Encryption fails before exceeding limit
- Clear error messages with usage statistics
- Automatic rollback on limit violation

### Usage Monitoring
- Get total bytes encrypted
- Get remaining capacity
- Get usage percentage
- Warning threshold at 90%

## Usage

### Using Default Settings (Recommended)

The default AEAD options enable bytes tracking with a 350GB limit:

```go
import (
    "github.com/jeremyhahn/go-keychain/pkg/backend"
    "github.com/jeremyhahn/go-keychain/pkg/backend/symmetric"
)

// Create backend with default AEAD safety tracking
backend, err := symmetric.NewBackend(storage, password, nil)
if err != nil {
    return err
}

// Generate key - bytes tracking enabled by default
attrs := &backend.KeyAttributes{
    CN:           "my-encryption-key",
    KeyType:      backend.KEY_TYPE_SECRET,
    StoreType:    backend.STORE_SW,
    KeyAlgorithm: backend.ALG_AES256_GCM,
}

key, err := backend.GenerateSymmetricKey(attrs)
if err != nil {
    return err
}

// Get encrypter
encrypter, err := backend.SymmetricEncrypter(attrs)
if err != nil {
    return err
}

// Encrypt data - bytes automatically tracked
data := []byte("sensitive information")
encrypted, err := encrypter.Encrypt(data, nil)
if err != nil {
    // Will fail if limit exceeded
    return err
}
```

### Custom Bytes Limit

Configure a custom limit for specific keys:

```go
// Create AEAD options with 100GB limit
opts := &backend.AEADOptions{
    NonceTracking:      true,
    BytesTracking:      true,
    BytesTrackingLimit: 100 * 1024 * 1024 * 1024, // 100GB
}

// Set options for the key
tracker := backend.GetAEADTracker() // Get from backend
err = tracker.SetAEADOptions(attrs.ID(), opts)
if err != nil {
    return err
}

// Now encryption will enforce the 100GB limit
```

### Monitoring Usage

Track encryption usage to plan key rotation:

```go
tracker := backend.GetAEADTracker()

// Get current usage
bytesEncrypted, err := tracker.GetBytesEncrypted(attrs.ID())
if err != nil {
    return err
}

// Get remaining capacity
opts, err := tracker.GetAEADOptions(attrs.ID())
if err != nil {
    return err
}
remaining := opts.BytesTrackingLimit - bytesEncrypted
usagePercent := (float64(bytesEncrypted) / float64(opts.BytesTrackingLimit)) * 100

fmt.Printf("Key usage: %.1f%% (%d / %d bytes)\n",
    usagePercent, bytesEncrypted, opts.BytesTrackingLimit)

// Check if rotation recommended
if usagePercent > 90 {
    log.Println("WARNING: Key usage >90% - plan rotation soon")
}
```

### Using the BytesTracker Directly

For custom integrations, you can use the standalone `BytesTracker`:

```go
import (
    "github.com/jeremyhahn/go-keychain/pkg/crypto/aead"
)

// Create tracker with 350GB limit (default)
tracker := aead.NewBytesTracker(true, 0)

// Or with custom limit
tracker := aead.NewBytesTracker(true, 100*1024*1024*1024) // 100GB

// Check and increment before encryption
plaintext := []byte("data to encrypt")
err := tracker.CheckAndIncrementBytes(int64(len(plaintext)))
if err != nil {
    // Limit exceeded - rotate key
    log.Printf("Key rotation required: %v", err)
    return err
}

// Perform encryption...

// Monitor usage
stats := tracker.GetUsageStats()
log.Printf("Encryption stats: %+v", stats)

// Check if warning threshold reached
if tracker.ShouldWarnUser() {
    log.Println("WARNING: Key usage >90%")
}
```

## Key Rotation

When bytes limit is exceeded, rotate to a new key:

```go
// Detect limit exceeded
encrypted, err := encrypter.Encrypt(data, nil)
if err != nil {
    if errors.Is(err, backend.ErrBytesLimitExceeded) {
        // Rotate to new key
        newAttrs := &backend.KeyAttributes{
            CN:           "my-encryption-key-v2", // New version
            KeyType:      backend.KEY_TYPE_SECRET,
            StoreType:    backend.STORE_SW,
            KeyAlgorithm: backend.ALG_AES256_GCM,
        }

        newKey, err := backend.GenerateSymmetricKey(newAttrs)
        if err != nil {
            return err
        }

        // Use new key for future encryptions
        encrypter, err = backend.SymmetricEncrypter(newAttrs)
        if err != nil {
            return err
        }

        // Optionally: re-encrypt old data with new key
        // Keep old key available for decryption of existing ciphertexts
    }
}
```

## Configuration Reference

### AEADOptions

```go
type AEADOptions struct {
    // NonceTracking enables nonce uniqueness checking
    // Default: true
    NonceTracking bool

    // BytesTracking enables bytes encrypted tracking
    // Default: true
    BytesTracking bool

    // BytesTrackingLimit is max bytes before rotation
    // Default: 350GB (375809638400 bytes)
    // Set to 0 for default, -1 to disable
    BytesTrackingLimit int64

    // NonceSize in bytes (default: 12 for GCM)
    NonceSize int
}
```

### Constants

```go
const (
    // Default limit: 350GB
    DefaultBytesTrackingLimit = 350 * 1024 * 1024 * 1024

    // Conservative limit for random nonces: 68GB
    Conservative68GB = 68 * 1024 * 1024 * 1024
)
```

## Best Practices

### 1. Use Default Settings
Always enable bytes tracking in production:
```go
// Good: Use defaults
opts := backend.DefaultAEADOptions()

// Bad: Disable tracking
opts := &backend.AEADOptions{
    BytesTracking: false, // DON'T DO THIS IN PRODUCTION
}
```

### 2. Monitor Usage
Implement monitoring to detect when rotation is needed:
```go
// Check usage periodically
go func() {
    ticker := time.NewTicker(1 * time.Hour)
    for range ticker.C {
        stats := tracker.GetUsageStats()
        if warn, _ := stats["warn"].(bool); warn {
            alertOps("Key rotation needed")
        }
    }
}()
```

### 3. Plan Key Rotation
Rotate keys before hitting the limit:
```go
// Rotate at 90% to avoid disruption
if tracker.GetUsagePercentage() >= 90.0 {
    rotateKey()
}
```

### 4. Use Conservative Limits
If nonce tracking is disabled, use the conservative limit:
```go
opts := &backend.AEADOptions{
    NonceTracking:      false, // Random nonces only
    BytesTracking:      true,
    BytesTrackingLimit: aead.Conservative68GB, // Use 68GB limit
}
```

### 5. Persist Tracking State
For production systems, use persistent storage for tracking:
```go
// Use file-based or database tracker instead of in-memory
// This ensures tracking survives process restarts
```

## Performance Impact

Bytes tracking has **minimal performance impact**:

- **Atomic increment**: Single CPU instruction (~1-2 nanoseconds)
- **No locks** on encryption path (only atomic operations)
- **Negligible overhead**: <0.1% compared to actual encryption

Benchmark results:
```
BenchmarkBytesTracker_CheckAndIncrement-8        100000000    12.3 ns/op
BenchmarkBytesTracker_Parallel-8                 50000000     24.1 ns/op
BenchmarkAESEncryption (without tracking)        1000000      1200 ns/op
BenchmarkAESEncryption (with tracking)           1000000      1201 ns/op
```

## Error Handling

### ErrBytesLimitExceeded

When the limit is exceeded:

```go
encrypted, err := encrypter.Encrypt(data, nil)
if err != nil {
    if errors.Is(err, backend.ErrBytesLimitExceeded) {
        // Specific handling for limit exceeded
        log.Printf("Key rotation required")
        rotateKey()
    } else {
        // Other encryption errors
        return err
    }
}
```

Error message format:
```
AEAD key usage limit exceeded: encrypted 375809638400 bytes,
limit 375809638400 bytes (exceeded by 1024 bytes)
```

## Thread Safety

All bytes tracking operations are **thread-safe**:

- Uses `atomic.Int64` for counter
- No mutexes on hot path
- Safe for concurrent encryption operations

```go
// Safe to call from multiple goroutines
var wg sync.WaitGroup
for i := 0; i < 100; i++ {
    wg.Add(1)
    go func() {
        defer wg.Done()
        encrypter.Encrypt(data, nil) // Thread-safe
    }()
}
wg.Wait()
```

## Integration with Nonce Tracking

Bytes tracking works seamlessly with nonce tracking:

```go
// Both features enabled (recommended)
opts := &backend.AEADOptions{
    NonceTracking:      true,  // Prevent nonce reuse
    BytesTracking:      true,  // Enforce data limits
    BytesTrackingLimit: 350 * 1024 * 1024 * 1024,
}

// Security checks during encryption:
// 1. Check bytes limit (before encryption)
// 2. Check nonce uniqueness (before encryption)
// 3. Perform encryption
// 4. Record nonce (after successful encryption)
```

## Testing

Disable tracking for tests when appropriate:

```go
func TestEncryption(t *testing.T) {
    // Disable tracking for faster tests
    opts := &backend.AEADOptions{
        NonceTracking: false,
        BytesTracking: false,
    }

    // Or use short limit for testing rotation logic
    opts := &backend.AEADOptions{
        NonceTracking:      true,
        BytesTracking:      true,
        BytesTrackingLimit: 1024, // 1KB for testing
    }
}
```

## See Also

- [AEAD Auto Selection](aead-auto-selection.md)
- [Symmetric Encryption Guide](symmetric-encryption.md)
- [NIST SP 800-38D](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf)
