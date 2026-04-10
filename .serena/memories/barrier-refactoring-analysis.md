# Storage & Barrier Refactoring Analysis Report
**Date: Feb 26, 2026 | Goal: Unify barrier implementations across three projects**

## EXECUTIVE SUMMARY

### Current State
- **go-quicraft** (12,124 LOC): Defines `StorageBackend` interface with `Put(key, data []byte) error` (NO Options)
- **go-qrdb** (36 seal files): Re-exports quicraft's `StorageBackend`, adds extensive barrier features (recovery, tenant, manager, etc.)
- **go-xkms** (34 seal files): Duplicate of go-qrdb + hardware strategies (TPM2, PKCS#11, cloud KMS), already modified to use storage.Options
- **go-xkms/pkg/storage**: Defines `Backend` interface with `Put(key, value []byte, opts *Options) error` with Options struct

### The Problem
- go-quicraft's `StorageBackend.Put()` lacks the `*Options` parameter that go-xkms storage layer requires
- go-xkms's `Barrier` already passes `opts` (line 394: `b.base.Put(key, ciphertext, opts)`)
- This breaks the abstraction: go-qrdb barriers call `Put(key, ciphertext)` but go-xkms barriers call `Put(key, ciphertext, opts)`
- go-xkms duplicates ~12k LOC that should be re-exported from go-qrdb

### The Solution (3-Phase Plan)
1. **Phase 1**: Add `*Options` to go-quicraft's `StorageBackend.Put()` signature
2. **Phase 2**: Update go-qrdb to flow `opts` through all Put() calls
3. **Phase 3**: Delete go-xkms barrier duplicate, re-export from go-qrdb

---

## DETAILED FINDINGS

### 1. go-quicraft/pkg/seal/interfaces.go (Lines 17-27)
**Current StorageBackend interface:**
```go
type StorageBackend interface {
    Get(key string) ([]byte, error)
    Put(key string, data []byte) error                    // ← NO OPTIONS
    Delete(key string) error
    List(prefix string) ([]string, error)
    Exists(key string) (bool, error)
    Close() error
}
```

**Current barrier.go (Line 386):**
```go
// Only passes 2 args
return b.base.Put(key, ciphertext)
```

---

### 2. go-xkms/pkg/storage/interface.go (Lines 23-59)
**Current Backend interface (ALREADY HAS OPTIONS):**
```go
type Backend interface {
    Get(key string) ([]byte, error)
    Put(key string, value []byte, opts *Options) error    // ← HAS OPTIONS!
    Delete(key string) error
    List(prefix string) ([]string, error)
    Exists(key string) (bool, error)
    Close() error
}

type Options struct {
    Path        string
    Permissions fs.FileMode
    Metadata    map[string]string
}

func DefaultOptions() *Options { ... }
```

---

### 3. go-xkms/pkg/seal/barrier.go (Line 385-394)
**Current implementation (ALREADY USES OPTIONS):**
```go
func (b *Barrier) Put(key string, value []byte, opts *storage.Options) error {
    enc, err := b.getEncryptor()
    if err != nil {
        return err
    }
    ciphertext, err := enc.Encrypt(value)
    if err != nil {
        return err
    }
    return b.base.Put(key, ciphertext, opts)  // ← PASSES opts!
}
```

Note: Lines 150 & 394 both pass `opts` to `base.Put()`.

---

### 4. go-qrdb/pkg/seal/barrier.go (Line 142 & 386)
**Current implementation (NO OPTIONS):**
```go
// Line 142 in Initialize():
if err := b.base.Put(b.config.RootKeyPath, blob); err != nil {

// Line 386 in Put():
return b.base.Put(key, ciphertext)
```

All 57 Put() calls in go-qrdb seal/ are `Put(key, data)` without options.

---

### 5. Storage Implementations & Options Flow

**go-xkms storage implementations (ALL use Options):**
- `/home/jhahn/sources/go-xkms/pkg/storage/memory.go` (Line 69)
- `/home/jhahn/sources/go-xkms/pkg/storage/file/storage.go` (need to check Put signature)
- `/home/jhahn/sources/go-xkms/pkg/storage/sealed/backend.go` (need to check)
- `/home/jhahn/sources/go-xkms/pkg/storage/hardware/*`
- `/home/jhahn/sources/go-xkms/pkg/storage/qrdb/adapter.go` (adapter pattern)
- `/home/jhahn/sources/go-xkms/pkg/storage/namespace.go` (wraps Backend)

**go-xkms memory.go Put signature (Line 69):**
```go
func (m *MemoryBackend) Put(key string, value []byte, opts *storage.Options) error
```

---

### 6. Test Mocks & Their Put() Signatures

**go-qrdb/pkg/seal/barrier_test.go (Lines 131-150):**
```go
type failingPutBackend struct {
    inner    StorageBackend
    failKey  string
    failErr  error
    putCalls int
}

func (f *failingPutBackend) Put(key string, data []byte) error {  // ← 2 ARGS
    f.putCalls++
    if key == f.failKey {
        return f.failErr
    }
    return f.inner.Put(key, data)  // ← Calls inner with 2 args
}
```

**go-xkms/pkg/seal/barrier_test.go (Lines 33-68):**
```go
type memoryBackend struct {
    mu     sync.RWMutex
    data   map[string][]byte
    closed bool
}

func (m *memoryBackend) Put(key string, value []byte, opts *storage.Options) error {  // ← 3 ARGS
    m.mu.Lock()
    defer m.mu.Unlock()
    if m.closed {
        return storage.ErrClosed
    }
    buf := make([]byte, len(value))
    copy(buf, value)
    m.data[key] = buf
    return nil
}
```

**go-xkms/pkg/seal/barrier_test.go (Lines 374-399):**
```go
type errBackend struct {
    ...
}

func (e *errBackend) Put(key string, value []byte, opts *storage.Options) error {  // ← 3 ARGS
    return e.putErr
}
```

---

### 7. All Put() Call Sites in go-qrdb/pkg/seal (57 TOTAL)

**Key calls in core barrier logic:**
- `barrier.go:142` - Initialize: `b.base.Put(b.config.RootKeyPath, blob)`
- `barrier.go:386` - Put: `b.base.Put(key, ciphertext)`
- `rekey.go:82` - Rekey: `b.base.Put(b.config.RootKeyPath, updatedBlob)`
- `recovery.go:70` - Recovery: `b.base.Put(recoveryMetaKey, metaBytes)`
- `strategy_shamir.go:262` - Shamir: `s.storage.Put(key, data)`
- `tenant_barrier.go:103` & `150` - TenantBarrier: forwards to barrier or namespaced backend
- `root_token.go` - Multiple calls in recovery ops
- `manager.go` - Manager lifecycle ops

**All 57 calls follow pattern:** `obj.Put(key, data)` with NO options argument

---

### 8. All Put() Call Sites in go-xkms/pkg/seal (62+ TOTAL)

**Key calls in core logic:**
- `barrier.go:150` - Initialize: `b.base.Put(b.config.RootKeyPath, blob, nil)`
- `barrier.go:394` - Put: `b.base.Put(key, ciphertext, opts)` ← **Propagates opts!**
- `rekey.go:103` - Rekey: `b.base.Put(b.config.RootKeyPath, updatedBlob, nil)`
- `recovery.go:86` - Recovery: `b.base.Put(recoveryMetaKey, metaBytes, nil)`
- `strategy_shamir.go:305` - Shamir: `s.storage.Put(key, data, nil)`
- `tenant_barrier.go:119` - TenantBarrier: `tb.barrier.Put(key, value, opts)` ← **Already flows opts!**
- `platform_store.go:114` - Platform: `s.backend.Put(platformStorePrefix+name, secret, nil)`

**All 62+ calls follow pattern:** `obj.Put(key, value, opts)` where opts is passed or nil

---

### 9. Files Unique to go-xkms/pkg/seal (Hardware & Cloud Strategies)

These are **NOT** in go-qrdb and would need to stay:
- `strategy_tpm2.go` - TPM 2.0 strategy implementation
- `strategy_tpm2_test.go`
- `strategy_pkcs11.go` - PKCS#11/HSM strategy implementation
- `strategy_pkcs11_test.go`
- `strategy_cloud.go` - Cloud KMS strategies (base)
- `strategy_cloud_test.go`
- `strategy_helpers_test.go`
- `platform_sealer.go` - Platform-specific sealing orchestration
- `platform_sealer_test.go`
- `platform_store.go` - Platform key storage integration
- `platform_store_test.go`
- `barrier_encryption_test.go` - Encryption validation (hardware-specific)
- `barrier_encryptor.go` - Hardware encryptor wrapper (xkms-specific)
- `hardware_encryptor.go` - Hardware encryptor traits
- `policy/` - Policy directory (xkms-specific)

**Total: 14 files + policy/ (NOT deletion candidates)**

---

### 10. Files Candidate for Deletion from go-xkms/pkg/seal (Duplicates of go-qrdb)

**Core duplicate files to DELETE:**
1. `barrier.go` - Duplicates go-qrdb/pkg/seal/barrier.go (only adds Options flow)
2. `barrier_test.go` - Test fixtures (duplicated)
3. `barrier_registry.go` - Duplicates go-qrdb version
4. `barrier_registry_test.go`
5. `recovery.go` - Duplicates go-qrdb version
6. `recovery_test.go`
7. `rekey.go` - Duplicates go-qrdb version
8. `rekey_test.go`
9. `root_token.go` - Duplicates go-qrdb version
10. `root_token_test.go`
11. `tenant_barrier.go` - Duplicates go-qrdb version (only adds Options flow)
12. `tenant_barrier_test.go`
13. `shamir.go` - Duplicates (thin re-export from go-qrdb)
14. `shamir_test.go` - Duplicates go-qrdb version
15. `strategy_shamir.go` - Duplicates go-qrdb version
16. `strategy_shamir_test.go`
17. `strategy_software.go` - Duplicates go-qrdb version
18. `strategy_software_test.go`
19. `config.go` - Mostly duplicated (audit logger is xkms-specific though)
20. `errors.go` - Duplicates go-qrdb version
21. `audit.go` - XKMS-SPECIFIC, DO NOT DELETE (audit integration)
22. `types.go` - Mostly duplicated (barrier status, etc.)

**Conservative estimate: ~20-22 files can be deleted (excluding hardware & platform)**

---

### 11. KEY TECHNICAL DIFFERENCES

**go-quicraft vs go-xkms/go-qrdb barriers:**

| Aspect | go-quicraft | go-qrdb | go-xkms |
|--------|-------------|---------|---------|
| **StorageBackend.Put() sig** | `(key, data []byte)` | `(key, data []byte)` | `(key, data, opts)` ✓ |
| **Barrier.Put() sig** | `(key, value []byte)` | `(key, value []byte)` | `(key, value, opts)` ✓ |
| **Options support** | ✗ | ✗ | ✓ |
| **Tenant barriers** | ✗ | ✓ (StorageBarrier + TenantBarrier) | ✓ (duplicated) |
| **Hardware strategies** | ✗ (external module) | ✗ (external module) | ✓ (native) |
| **Platform sealer** | ✗ | ✗ | ✓ (xkms-specific) |
| **Recovery ops** | ✓ (basic) | ✓ (enhanced) | ✓ (duplicated) |
| **Audit logger** | ✗ | ✓ (config.AuditLogger) | ✓ (xkms adapter) |
| **Encryption implementation** | Epoch-based HKDF DEK | Epoch-based HKDF DEK | SymmetricEncrypter wrapper |

---

### 12. Import Dependencies

**go-xkms/pkg/seal imports:**
```go
import (
    "github.com/jeremyhahn/go-xkms/pkg/audit"
    "github.com/jeremyhahn/go-xkms/pkg/crypto/mem"
    "github.com/jeremyhahn/go-xkms/pkg/keyprovider/symmetric"
    "github.com/jeremyhahn/go-xkms/pkg/storage"              // ← XKMS-SPECIFIC
    "github.com/jeremyhahn/go-xkms/pkg/types"               // ← XKMS-SPECIFIC
    qrdbseal "github.com/jeremyhahn/go-qrdb/pkg/seal"       // ← RE-EXPORT SOURCE
)
```

Critical: `go-xkms/pkg/storage` is NOT in go-qrdb. The refactor MUST maintain the storage.Backend contract.

---

## PHASE 1: go-quicraft/pkg/seal/interfaces.go (1 FILE)

**Change required:**
```go
// BEFORE:
type StorageBackend interface {
    Get(key string) ([]byte, error)
    Put(key string, data []byte) error
    ...
}

// AFTER:
type StorageBackend interface {
    Get(key string) ([]byte, error)
    Put(key string, data []byte, opts any) error  // ← 3rd param added
    ...
}
```

**Impact:** Any code implementing StorageBackend must add the 3rd parameter.

---

## PHASE 2: go-qrdb/pkg/seal (57 CALLS TO UPDATE)

**Pattern change:** All 57 Put() calls must propagate opts:

```go
// BEFORE:
return b.base.Put(key, ciphertext)

// AFTER:
return b.base.Put(key, ciphertext, nil)  // or pass opts if available
```

**Files to update (14 files with Put() calls):**
1. `barrier.go` - 2 calls
2. `rekey.go` - 2 calls
3. `recovery.go` - 2 calls
4. `root_token_test.go` - 5 calls
5. `strategy_shamir.go` - 1 call
6. `strategy_shamir_test.go` - 10 calls
7. `barrier_test.go` - 30 calls
8. `rekey_test.go` - 3 calls
9. `recovery_test.go` - 2 calls
10. `tenant_barrier.go` - 2 calls
11. `tenant_barrier_test.go` - 15 calls
12. And more in remaining test files

---

## PHASE 3: go-xkms/pkg/seal (DELETE 20+ FILES)

**After Phases 1-2 complete:**

1. Delete all duplicate barrier files (keep hardware-specific ones)
2. Create re-export file in go-xkms/pkg/seal/storage_adapter.go:
```go
package seal

import qrdbseal "github.com/jeremyhahn/go-qrdb/pkg/seal"

// Re-export Barrier and related types
type Barrier = qrdbseal.StorageBarrier
type BarrierRegistry = qrdbseal.BarrierRegistry
...
```

3. Update go-xkms imports in rest of codebase:
   - Anywhere importing `github.com/jeremyhahn/go-xkms/pkg/seal` continues to work
   - But underlying implementation comes from go-qrdb

---

## CRITICAL CONTEXT

From project memory:
- **Phase 3 of xkey architecture plan**: Per-Tenant DEK + Auth Context
  - TenantBarrier has independent DEK (not shared with system)
  - BarrierRegistry has `RegisterTenant()` + `RegisterTenantWithConfig()`
  - These are ALREADY implemented in go-qrdb, so refactoring aligns!
  
- **CA-backed TLS**: ensureTLSServerCert() calls `backend.SaveCert()` + `backend.SaveCertChain()`
  - Storage already supports Options for cert handling
  
- **Bootstrap infrastructure**: SPKI pinning in SDK + xkmsctl CLI
  - No seal/barrier dependencies here

---

## RISK ASSESSMENT

**LOW RISK:**
- go-quicraft only adds a parameter (backward compatible with default nil)
- go-qrdb just adds opts to existing calls (all calls pass nil initially)
- go-xkms deletion is safe because go-qrdb is more feature-complete

**MEDIUM RISK:**
- 57 Put() call sites in go-qrdb must all be updated consistently
- Test fixtures must be updated in parallel
- Integration tests must pass before/after each phase

**HIGH RISK (MITIGATED BY PLANNING):**
- go-xkms's hardware strategy implementations must stay intact
- Platform sealer integration must be tested thoroughly
- Tenant barrier isolation must be verified post-refactor

---

## RECOMMENDED APPROACH

1. **Phase 1**: Update go-quicraft StorageBackend interface (1 file, 1 LOC change)
2. **Phase 2**: Update go-qrdb Put() calls via find/replace + grep (14 files, 57 calls)
3. **Phase 3a**: Create go-xkms re-export file (new file, ~20 LOC)
4. **Phase 3b**: Delete duplicate go-xkms files (22 files, ~8k LOC removed)
5. **Integration**: Run full test suite for all 3 projects

---

## FILE INVENTORY

**go-quicraft/pkg/seal: 21 files (12,124 LOC)**
- Core: interfaces.go, barrier.go, strategy.go, types.go, errors.go, kdf.go, memprotect.go, shamir*.go, strategy_software.go
- Tests: Multiple *_test.go files

**go-qrdb/pkg/seal: 36 files (~15k LOC)**
- Core: barrier.go, barrier_registry.go, recovery.go, rekey.go, root_token.go, strategy*.go, tenant_barrier.go, manager.go, encryption_barrier.go
- Adapters: file_share_store.go, software_keystore.go
- Support: audit.go, config.go, encryptor.go, types.go, errors.go
- Tests: 16+ test files

**go-xkms/pkg/seal: 34 files (~12k LOC)**
- **Duplicates from go-qrdb** (candidates for deletion):
  - barrier.go, barrier_test.go
  - barrier_registry.go, barrier_registry_test.go
  - recovery.go, recovery_test.go
  - rekey.go, rekey_test.go
  - root_token.go, root_token_test.go
  - tenant_barrier.go, tenant_barrier_test.go
  - shamir.go, shamir_test.go
  - strategy_shamir.go, strategy_shamir_test.go
  - strategy_software.go, strategy_software_test.go
  - config.go, errors.go, types.go
  
- **Hardware/Platform specifics** (KEEP):
  - strategy_tpm2.go, strategy_tpm2_test.go
  - strategy_pkcs11.go, strategy_pkcs11_test.go
  - strategy_cloud.go, strategy_cloud_test.go
  - strategy_helpers_test.go
  - platform_sealer.go, platform_sealer_test.go
  - platform_store.go, platform_store_test.go
  - barrier_encryptor.go, hardware_encryptor.go
  - barrier_encryption_test.go
  - audit.go (XKMS adapter, KEEP)
  - policy/ (XKMS-specific)

---

## NEXT STEPS

This analysis is complete and ready for implementation planning. Each phase has clear scope, measurable outcomes, and identified risk points.

