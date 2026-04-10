# Barrier/Seal Implementation Analysis for go-qrdb Migration

**Date**: February 2026  
**Purpose**: Identify what code moves to go-qrdb vs what stays in go-xkms

---

## 1. ARCHITECTURE OVERVIEW

### Core Pattern: Pluggable Strategies

The barrier uses a **strategy pattern** with multiple pluggable sealing strategies:

```
Barrier (storage.Backend decorator)
  ├─ Hardware-backed strategies:
  │  ├─ StrategyTPM2 (tpm2/sealer) → uses types.Sealer for seal/unseal
  │  ├─ StrategyPKCS11 (HSM tokens) → uses types.Sealer
  │  ├─ StrategyAWSKMS (AWS KMS) → uses types.Sealer
  │  ├─ StrategyGCPKMS (Google Cloud KMS) → uses types.Sealer
  │  ├─ StrategyAzureKV (Azure Key Vault) → uses types.Sealer
  │  └─ StrategyVault (HashiCorp Vault) → uses types.Sealer
  │
  ├─ Shamir secret sharing (StrategyShamir):
  │  └─ Uses M-of-N reconstruction without passwords
  │
  └─ Software fallback (StrategySoftware):
     └─ Password + Argon2id/PBKDF2-SHA256 + AES-256-GCM
```

### Barrier Lifecycle

```
1. NewBarrier(logger, baseBackend, config, strategies...) → Sealed barrier
2. Initialize(ctx, creds) → generates root key, seals, obtains encryptor → Unsealed
3. Unseal(ctx, creds) → loads sealed key, unseals, obtains encryptor → Unsealed
4. Get/Put/Delete/List → Transparent encrypt/decrypt via encryptor
5. Seal() → Releases encryptor, zeros DEK, transitions to sealed → Sealed
6. Close() → Seal() + base.Close()
```

---

## 2. CORE BARRIER FILES (pkg/seal/)

### Critical: Must Port to go-qrdb

**Core abstractions and types (ALWAYS PORTABLE)**:

- **errors.go** (180 lines)
  - Typed errors: ErrSealed, ErrAlreadyInitialized, ErrInvalidCredentials, etc.
  - Shamir-specific: ErrShamirQuorumExpired, ErrShamirCombineFailed
  - Tenant-specific: ErrTenantNotFound, ErrTenantSealed
  
- **strategy.go** (134 lines)
  - `type StrategyID string` with 8 constants (tpm2, pkcs11, awskms, gcpkms, azurekv, vault, shamir, software)
  - `type SealingStrategy interface` (6 methods: ID, Available, HardwareBacked, SealRootKey, UnsealRootKey, BarrierEncryptor)
  - `type Credentials struct { Secret string }`
  - `type SealedRootKey struct` (JSON-serializable envelope with sealed data + metadata)
  - `DefaultPreferenceOrder` slice
  - Shamir metadata fields: ShamirThreshold, ShamirTotal

- **config.go** (83 lines)
  - `type BarrierConfig struct` (PreferenceOrder, RootKeyPath, AuditLogger, Shamir)
  - `type ShamirConfig struct` (Threshold, TotalShares)
  - `type SealerConfig struct` (for PlatformSealer)
  - `type TenantBarrierConfig struct` (multi-tenancy feature flag)

- **barrier.go** (542 lines)
  - `type Barrier struct` (core storage.Backend decorator)
  - `type BarrierStatus struct` (Sealed, Strategy, HardwareBacked, InitializedAt)
  - Core methods: Initialize, Unseal, Seal, IsSealed, Status, Get, Put, Delete, List, Exists, Close
  - Helper methods: GetMasterKey, Encryptor, ActiveStrategy, ShamirStrategy, SetShamirConfig
  - Shamir-specific: unsealDirect
  - Private helpers: getEncryptor, bestStrategy, deriveDEK (HKDF), barrierEncrypt/Decrypt
  - **State**: atomic.Int32 (sealed/unsealed), atomic.Value (encryptor, activeStrategy, accumulator)

- **barrier_encryptor.go** (134 lines)
  - `type softwareBarrierEncryptor struct` (implements types.SymmetricEncrypter)
  - Implements: Encrypt (AES-256-GCM), Decrypt, DEK(), Zero()
  - Used for software strategies and hardware strategies without hardware encryptor

### Important: Strategy Implementations (PORTABLE)

- **strategy_software.go** (172 lines)
  - `type SoftwareStrategy struct` (password + KDF)
  - SealRootKey: password → Argon2id/PBKDF2 → AES-256-GCM
  - UnsealRootKey: password + stored salt/nonce → plaintext
  - BarrierEncryptor: derives DEK from root key via HKDF-SHA256
  - Uses: `pkg/crypto/kdf` (PasswordHasher), `pkg/crypto/mem` (Zero)

- **strategy_tpm2.go** (114 lines)
  - `type TPM2Strategy struct` (wraps types.Sealer + optional types.SymmetricEncrypter)
  - SealRootKey: delegates to sealer.Seal()
  - UnsealRootKey: delegates to sealer.Unseal()
  - BarrierEncryptor: returns hardware encryptor if available, else software DEK

- **strategy_pkcs11.go** (113 lines)
  - Similar pattern to TPM2: wraps types.Sealer

- **strategy_cloud.go** (119 lines)
  - Pattern: AWS KMS, GCP KMS, Azure KV, Vault
  - Similar pattern to TPM2: wraps types.Sealer

- **strategy_shamir.go** (311 lines)
  - `type ShamirStrategy struct` (M-of-N secret sharing, no password)
  - SealRootKey: splits root key into N shares, persists to storage backend
  - UnsealRootKey: combines M shares to reconstruct root key
  - `type ShamirShare struct` (Index, Value, CreatedAt)
  - Methods: SaveShare, LoadShare, LoadAllShares, DeleteShare, DeleteAllShares
  - Quorum handling: share accumulator with TTL
  - Uses: `pkg/threshold/shamir` (Combine, Split)

### Advanced: Multi-Tenant Barriers (PORTABLE)

- **tenant_barrier.go** (142 lines)
  - `type TenantBarrier struct` (wraps Barrier with tenantID)
  - Each tenant has **independent DEK** (own sealed root key blob in own storage)
  - Implements: storage.Backend interface (Get, Put, Delete, List, Exists, Close)
  - Lifecycle: Initialize, Unseal, Seal per tenant
  - Storage backend expected to be pre-scoped (e.g., namespace-prefixed)

- **barrier_registry.go** (222 lines)
  - `type BarrierRegistry struct` (manages system barrier + tenant barriers)
  - System barrier is required (always exists)
  - Methods: Tenant, RegisterTenant, RegisterTenantWithConfig, UnregisterTenant
  - Batch operations: InitializeTenant, UnsealTenant, SealTenant, TenantStatus, ListTenants
  - Uses sync.RWMutex for thread-safe map access
  - RegisterTenant: auto-creates in-memory storage for tenant

### Shamir Share Lifecycle (PORTABLE)

- **shamir.go** (311 lines)
  - `type ShamirInitResult struct` (Shares, Threshold, TotalShares)
  - Quorum handling: accumulator with TTL, share collection
  - Methods on Barrier: InitializeShamir, UnsealWithShare, UnsealWithShares

- **recovery.go** (187 lines)
  - Shamir recovery operations when DEK is split into shares
  - Used by disaster recovery scenarios

- **rekey.go** (143 lines)
  - `Barrier.Rekey(ctx, newThreshold, newTotal)` 
  - Rotates Shamir shares without changing root key
  - Updates sealed root key blob with new metadata

### TPM-Specific: PCR Policy Management (PORTABLE TO go-qrdb IF TPM SUPPORT NEEDED)

- **policy/types.go** (92 lines)
  - `type PolicyDefinition struct` (Name, Bank, PCRIndices, PCRValues, timestamps)
  - `type PCRReader interface` (ReadPCRs)
  - `type PolicyStore interface` (SavePolicy, LoadPolicy, DeletePolicy, ListPolicies)

- **policy/manager.go** (173 lines)
  - `type Manager struct` (manages PCR policies for TPM sealing)

- **platform_sealer.go** (185 lines)
  - `type PlatformSealer struct` (auto-selects best available sealing strategy)
  - Methods: NewFromConfig, SelectStrategy

- **platform_store.go** (219 lines)
  - Storage layer for sealed root key blobs

---

## 3. STORAGE LAYER (pkg/storage/)

### Core Interfaces (PORTABLE)

- **interface.go** (69 lines)
  - `type Backend interface` (Get, Put, Delete, List, Exists, Close)
  - `type Options struct` (Path, Permissions, Metadata)
  - All barrier operations delegate through this interface

### Implementations (CAN PORT OR KEEP)

- **memory.go** (in-memory backend, trivial)
- **file/storage.go** (file-based storage)
- **namespace.go** (prefix-based virtual namespacing)
- **namespace_tenant_test.go** (tenant-scoped namespacing)

### Sealed Storage Backend (OPTIONAL FOR go-qrdb)

- **sealed/backend.go** (117 lines)
  - `type Backend struct` (wraps storage.Backend, seals values via types.Sealer)
  - Not used by core barrier (barrier does own encryption)
  - Different pattern: seals individual values, not the root key

---

## 4. MEMORY PROTECTION (pkg/crypto/mem/)

### Must Port to go-qrdb (SECURITY-CRITICAL)

- **mem.go** (30 lines)
  - `Zero(b []byte)` - simple byte slice zeroing

- **guarded.go** (121 lines)
  - `type GuardedBuffer struct` (OS-protected memory)
  - Platform-agnostic interface with platform-specific implementations
  - Methods: NewGuardedBuffer, Bytes, Size, IsFreed, Clone, Write, Zero, Free, ZeroAndFree
  - Uses atomic.Bool for lock-free freed flag

- **guarded_linux.go** (platform-specific)
  - mmap + guard pages + mlock implementation for Linux
  - Detects buffer overflows, prevents disk swapping

- **guarded_stub.go** (fallback for non-Linux)
  - Plain heap allocation with guaranteed zeroing

- **errors.go** (56 lines)
  - ErrInvalidSize, ErrMmapFailed, ErrMprotectFailed (typed errors)

---

## 5. AUDIT & RECOVERY

### Audit Logging

- **audit.go** (minimal)
  - Emits audit events for Initialize/Unseal/Seal/Rekey operations
  - Uses AuditLogger from config

### Recovery

- **recovery.go** (187 lines)
  - DEK recovery when split across Shamir shares
  - Specific to Shamir strategy

---

## 6. KEY DESIGN PATTERNS

### 1. Strategy Pattern (Pluggable Seal/Unseal)

```go
type SealingStrategy interface {
    ID() StrategyID
    Available() bool
    HardwareBacked() bool
    SealRootKey(ctx context.Context, rootKey []byte, creds Credentials) (*SealedRootKey, error)
    UnsealRootKey(ctx context.Context, sealed *SealedRootKey, creds Credentials) ([]byte, error)
    BarrierEncryptor(ctx context.Context, rootKey []byte) (types.SymmetricEncrypter, error)
}
```

- Each strategy encapsulates its own seal/unseal logic
- Barrier is agnostic to which strategy is used
- Strategies can be swapped or disabled dynamically

### 2. Lock-Free State Management

```go
type Barrier struct {
    state atomic.Int32        // 0=sealed, 1=unsealed
    encryptor atomic.Value    // types.SymmetricEncrypter
    activeStrategy atomic.Value // StrategyID
    accumulator atomic.Value  // Shamir quorum
}
```

- No mutexes; all state transitions via atomics
- Safe for concurrent reads (sealed check via Load())
- Writes (Unseal/Seal) are non-concurrent operations anyway

### 3. Wire Format: [version byte][symmetric.Marshal(EncryptedData)]

```go
const barrierVersion byte = 0x01

// Encrypt
ciphertext := [0x01] + symmetric.Marshal(enc.Encrypt())

// Decrypt
version := data[0]
ed := symmetric.Unmarshal(data[1:])
plaintext := enc.Decrypt(ed)
```

- Version byte allows future format evolution
- Delegate to `pkg/keyprovider/symmetric` for EncryptedData marshaling

### 4. DEK Derivation: HKDF-SHA256

```go
const hkdfInfo = "go-xkms/barrier/v1"

dek := HKDF-SHA256(rootKey, salt=nil, info=hkdfInfo, length=32)
```

- Deterministic: same root key → same DEK
- Used by both software and hardware strategies for data encryption

### 5. Multi-Tenant Isolation

```
BarrierRegistry
  ├─ System barrier (sealed root key at "seal:barrier:root")
  └─ Tenant barriers (each with independent DEK)
      └─ Each tenant barrier seals root key separately
```

- Tenant barriers are NOT namespaced within system storage
- Each tenant gets dedicated TenantBarrier wrapping its own Barrier
- Tenant storage is externally scoped (e.g., via Namespace)

---

## 7. USAGE ACROSS CODEBASE

### Server-Level Integration

- **pkg/server/server.go**
  - Creates system barrier with all strategies
  - Creates BarrierRegistry after barrier init
  - Wires to: REST, gRPC, QUIC, MCP, Embedded SDK

- **pkg/xkms/servicer_barrier.go**
  - RPC handlers for seal/unseal operations
  - Delegates to barrier + barrier registry

### GUI Integration (xkey)

- **xkey/pkg/gui/services/barrier_service.go**
  - Wraps seal.Barrier for GUI
  - Manages user password + strategy selection
  - Post-unseal hooks for dependent services

### CLI Integration

- **cmd/xkmsd/init.go**
  - Server initialization flow
  - Barrier setup from config

### SDK Integration

- **sdk/go/transport/embedded/transport.go**
  - Embedded transport uses server's barrier registry

---

## 8. WHAT MOVES TO go-qrdb vs STAYS IN go-xkms

### MOVES TO go-qrdb (Core Barrier Implementation)

1. **Core barrier logic** (`pkg/seal/barrier.go`)
   - Transparent storage encryption
   - State management (sealed/unsealed)
   - Barrier lifecycle (Initialize/Unseal/Seal)

2. **Strategy interface + software strategy** (`strategy.go`, `strategy_software.go`)
   - Pluggable sealing strategies
   - Password-based fallback
   - Essential for portable barrier

3. **Memory protection** (`pkg/crypto/mem/`)
   - Zero, GuardedBuffer, platform-specific safety
   - Security-critical for any key management

4. **Storage interface** (`pkg/storage/interface.go`)
   - Backend abstraction (minimal)
   - Options struct

5. **Multi-tenant barriers** (`tenant_barrier.go`, `barrier_registry.go`)
   - Per-tenant DEK isolation
   - Tenant lifecycle management

6. **Shamir secret sharing** (if go-qrdb needs it)
   - `shamir.go`, `strategy_shamir.go`
   - Share accumulator, quorum TTL
   - Recovery operations

### STAYS IN go-xkms (Hardware + Integration)

1. **Hardware strategy implementations**
   - `strategy_tpm2.go`, `strategy_pkcs11.go`, `strategy_cloud.go`
   - These depend on go-xkms backends (types.Sealer)
   - Integrated into server.go, cmd/xkmsd

2. **PCR policy management** (`policy/`)
   - TPM-specific, not generic barrier feature
   - Only needed if go-xkms does TPM sealing

3. **PlatformSealer/PlatformStore** (`platform_*.go`)
   - Auto-strategy selection (server-specific concern)
   - Can be re-implemented in go-xkms

4. **Audit logging integration**
   - Server wires AuditLogger into BarrierConfig
   - go-xkms maintains audit hooks

5. **Server-level barrier registry wiring**
   - Barrier initialization at server startup
   - Strategy factory based on config
   - Protocol-specific middleware (REST, gRPC, etc.)

---

## 9. TYPES DEPENDENCIES

### go-qrdb Needs (From go-xkms/pkg/types/)

- `type SymmetricEncrypter interface` (Encrypt, Decrypt)
- `type Sealer interface` (Seal, Unseal, CanSeal)
- `type EncryptedData struct` (Ciphertext, Nonce, Tag, Algorithm)
- `type SealOptions struct`
- `type DecryptOptions struct`

### go-xkms Provides to go-qrdb

- `type Barrier struct` (storage.Backend wrapper)
- `type SealingStrategy interface` (strategy pattern)
- All strategy implementations
- `type TenantBarrier`, `type BarrierRegistry`
- `pkg/crypto/mem` (GuardedBuffer, Zero)

---

## 10. MIGRATION CHECKLIST FOR go-qrdb

- [ ] Define minimal `types.go` with SymmetricEncrypter, EncryptedData
- [ ] Port `pkg/crypto/mem/` (memory safety layer)
- [ ] Port `pkg/storage/interface.go` (Backend abstraction)
- [ ] Port `pkg/seal/` core files:
  - [ ] errors.go
  - [ ] strategy.go
  - [ ] config.go
  - [ ] barrier.go
  - [ ] barrier_encryptor.go
  - [ ] strategy_software.go
- [ ] Port Shamir (optional, depending on use case):
  - [ ] shamir.go, strategy_shamir.go, recovery.go, rekey.go
  - [ ] Depends on `pkg/threshold/shamir` library
- [ ] Port multi-tenant (optional):
  - [ ] tenant_barrier.go, barrier_registry.go
- [ ] go-xkms can still use go-qrdb barrier + add its own hardware strategies

---

## 11. KEY FILES SUMMARY TABLE

| File | Lines | Moves? | Reason |
|------|-------|--------|--------|
| errors.go | 180 | YES | Core error types |
| strategy.go | 134 | YES | Strategy interface |
| config.go | 83 | YES | Config types |
| barrier.go | 542 | YES | Core barrier |
| barrier_encryptor.go | 134 | YES | Software encryptor |
| strategy_software.go | 172 | YES | Fallback strategy |
| strategy_tpm2.go | 114 | NO | Hardware-specific |
| strategy_pkcs11.go | 113 | NO | Hardware-specific |
| strategy_cloud.go | 119 | NO | Hardware-specific |
| strategy_shamir.go | 311 | MAYBE | Optional for qrdb |
| tenant_barrier.go | 142 | YES | Multi-tenancy |
| barrier_registry.go | 222 | YES | Registry |
| shamir.go | 311 | MAYBE | Optional |
| recovery.go | 187 | MAYBE | Shamir only |
| rekey.go | 143 | MAYBE | Shamir only |
| policy/*.go | ~400 | NO | TPM-specific |
| platform_*.go | ~700 | NO | Server integration |
| storage/interface.go | 69 | YES | Storage abstraction |
| crypto/mem/*.go | ~300 | YES | Memory safety |

