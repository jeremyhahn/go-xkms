# PCR Policy Management

PCR (Platform Configuration Register) policies capture expected TPM2 digests for automatic barrier unsealing. This document covers named policy creation, lifecycle, and auto-unseal configuration.

## Concepts

A **PCR policy** defines expected platform state by specifying:
- **Bank**: Hash algorithm (SHA1, SHA256, SHA384)
- **PCRs**: Mapping of PCR index → expected digest bytes
- **AutoUnseal**: Whether this policy triggers barrier auto-unseal on startup

Policies are persisted with deterministic IDs derived from policy names, enabling idempotent create/update operations.

## Creating a Policy

```go
import "github.com/jeremyhahn/go-xkms/xkey/pkg/pcr_policy"

store, err := pcrpolicy.NewDAOStore(kvStore)

// Define PCR digests for your platform
pcrs := map[uint][]byte{
    0: digest0,  // Boot code
    1: digest1,  // Configuration
    7: digest7,  // Secure boot
}

policy, err := store.Create(ctx, "production", "SHA256", pcrs)
// policy.ID is deterministically computed from name
// Idempotent: calling again with same name overwrites
```

Supported banks: `SHA1`, `SHA256`, `SHA384`

## Policy Lifecycle

### Retrieve a Policy

```go
policy, err := store.Get(ctx, "production")
if pcrpolicy.IsNotFound(err) {
    // policy doesn't exist
}
```

### List All Policies

```go
policies, err := store.List(ctx)  // sorted by name
```

### Update PCRs

```go
existing, _ := store.Get(ctx, "production")
existing.PCRs[0] = newDigest0
existing.UpdatedAt = time.Now()
// Re-save with same name - ID remains same
policy, _ := store.Create(ctx, "production", "SHA256", existing.PCRs)
```

### Delete a Policy

```go
err := store.Delete(ctx, "production")
if err == pcrpolicy.ErrDeleteAutoUnseal {
    // Can't delete while it's the active auto-unseal policy
    store.ClearAutoUnseal(ctx)
    err = store.Delete(ctx, "production")
}
```

Deletion fails if the policy is currently designated for auto-unseal.

## Auto-Unseal Configuration

Auto-unseal allows the barrier to automatically unlock on startup if the platform PCRs match an expected policy.

### Enable Auto-Unseal

```go
// Designate a policy for auto-unseal
err := store.SetAutoUnseal(ctx, "production")
// Any previously designated auto-unseal policy is cleared
```

### Check Auto-Unseal Status

```go
policy, err := store.GetAutoUnsealPolicy(ctx)
if err != nil {
    // No policy designated
}
fmt.Printf("Auto-unseal policy: %s\n", policy.Name)
```

### Disable Auto-Unseal

```go
err := store.ClearAutoUnseal(ctx)
// All auto-unseal flags cleared
```

## Typical Workflow

1. **Capture platform state:**
   ```go
   // During initial setup, capture PCR digests
   digests := tpm.ReadPCRs(bank)
   ```

2. **Create policy:**
   ```go
   policy, _ := store.Create(ctx, "baseline", "SHA256", digests)
   ```

3. **Enable auto-unseal:**
   ```go
   store.SetAutoUnseal(ctx, "baseline")
   ```

4. **On startup, barrier uses policy:**
   - Barrier checks if auto-unseal is configured
   - Reads current PCRs from TPM
   - Compares against policy
   - Automatically unseals if they match

5. **Update after platform changes:**
   ```go
   // Platform config changed, recapture
   newDigests := tpm.ReadPCRs(bank)
   store.Create(ctx, "baseline", "SHA256", newDigests)
   // Auto-unseal continues to work with updated policy
   ```

## Pagination

For systems with many policies:

```go
pageResult, err := store.Page(ctx, dao.PageQuery{
    Page:     1,
    PageSize: 50,
})

fmt.Printf("Got %d policies\n", len(pageResult.Entities))
fmt.Printf("Total: %d\n", pageResult.Total)
```

## Error Handling

```go
policy, err := store.Get(ctx, "unknown")
if pcrpolicy.IsNotFound(err) {
    // Handle missing policy
}

err = store.Delete(ctx, "auto-unseal-policy")
if err == pcrpolicy.ErrDeleteAutoUnseal {
    // Clear auto-unseal first
}

err = store.Create(ctx, "", "SHA256", pcrs)
if err == pcrpolicy.ErrInvalidName {
    // Empty name
}

err = store.Create(ctx, "test", "INVALID", pcrs)
if err == pcrpolicy.ErrInvalidBank {
    // Invalid bank
}

err = store.Create(ctx, "test", "SHA256", map[uint][]byte{})
if err == pcrpolicy.ErrNoPCRs {
    // PCR map is empty
}
```

## Storage Details

Policies are stored with namespace `pcr_policies` in the underlying kvstore. Entity IDs are deterministically computed from policy names using `FieldHashGenerator`, ensuring the same name always produces the same ID.

Deleting and recreating a policy with the same name reuses the same storage key.
