# Backend Selection Architecture

## Overview

xkey supports multiple concurrent cryptographic backends (software, TPM2, PKCS#11, cloud KMS, etc.). The backend selection system provides:

1. **System-wide default backend** — configured during setup, changeable via Settings/Admin
2. **Per-operation backend routing** — each app view filters and routes to specific backends
3. **Capability-based filtering** — views only show backends that support their feature set

## System-Wide Default Backend

### Flow

```
Setup Wizard → GUIConfig.SealerBackend → AdminService.SetDefaultBackend()
                                              ↓
                                    BackendRegistry.SetDefault()
                                    SealService.SetDefaultBackend()
                                    GUIConfig persistence (gui.json)
```

### Components

| Component | Role |
|-----------|------|
| `SetupWizardService.ApplySetup()` | Auto-fills `SealerBackend` from `SealService.BestSealer()` if not explicitly chosen |
| `AdminService.SetDefaultBackend()` | Validates backend, updates registry defaults for all supported capabilities, syncs SealService, persists to config |
| `AdminService.GetSystemDefaultBackend()` | Returns current default (SealService priority > registry > "software") |
| `SealService` | Manages sealers, auto-selects by `SecurityLevel` (TPM2 VeryHigh > PKCS11 High > Software Low) |
| `GUIConfig.SealerBackend` | Persistent storage in `gui.json` |

### Auto-Selection Priority

1. User's explicit choice (setup wizard or Settings/Admin)
2. `SealService.BestSealer()` — highest `SecurityLevel` among available sealers
3. Fallback: `"software"`

## Per-Operation Backend Routing

### Reference Implementation: Keys

```
Keys.svelte (filter chips + dialog selector)
  → KeyService.ListKeys(source, backend)
    → SDK transport.Client.ListKeys(ctx, backend)
      → go-xkms server backend routing
```

The `source` parameter selects local vs remote client. The `backend` parameter routes to a specific backend within the server.

### Pattern for Each App View

| View | Capability Filter | Backend Selection |
|------|-------------------|-------------------|
| Keys | `signing` | Filter chips + dialog selector |
| Certificates | `signing` | BackendSelector component + client-side filtering |
| FIDO2 | `fido2` | BackendSelector filter chips |
| Passwords | `passwords` | BackendSelector chips + dialog backend field |
| PIV | `piv` | BackendSelector (connected only, no "All") |
| OATH | `oath` | BackendSelector filter chips |

### Service Layer

Each GUI service routes operations to the SDK transport layer:

```go
// KeyService pattern (reference)
func (s *KeyService) ListKeys(source, backend string) ([]RemoteKeyInfo, error) {
    client, err := s.getClient(source)
    // ...
    resp, err := client.ListKeys(ctx, backend)
    // ...
}
```

- `CertificateService.ListCertificates(backend)` — single-backend query
- `CertificateService.ListAllCertificates()` — aggregates all backends
- `PIVService.SetBackend(backend)` / `GetBackend()` — runtime backend switching

## Capability-Based Filtering

The `BackendSelector` component filters backends by capability:

```svelte
<BackendSelector capability="fido2" bind:selected={selectedBackend} />
```

Capabilities are defined in `pkg/backendregistry/types.go`:

| Capability | Description |
|------------|-------------|
| `CapSigning` | Digital signature operations |
| `CapEncryption` | Encryption/decryption |
| `CapSealing` | Data sealing (TPM, software) |
| `CapAttestation` | Key attestation |
| `CapFIDO2` | FIDO2/WebAuthn credentials |
| `CapPIV` | PIV smart card operations |
| `CapOATH` | OATH TOTP/HOTP tokens |
| `CapPasswords` | Static password storage |

## BackendSelector Component

Shared Svelte component at `frontend/src/lib/components/BackendSelector.svelte`:

```svelte
<BackendSelector
  capability="signing"      <!-- Filter by capability -->
  bind:selected={backend}   <!-- Two-way binding -->
  showAll={true}            <!-- "All Backends" chip -->
  connectedOnly={false}     <!-- Only show connected -->
  compact={false}           <!-- Smaller chips -->
/>
```

- Queries `AdminService.ListBackends()` for backend info
- Filters by capability
- Dispatches `change` event with selected backend ID
- Exposes `refresh()` and `getBackends()` for programmatic access

## Data Flow: Setting Default Backend

```
User clicks "Set as Default" in Admin Backends view
  → callBackend('AdminService', 'SetDefaultBackend', backendId)
    → AdminService.SetDefaultBackend(backendId)
      → registry.Get(backendId)           // Validate exists
      → backend.State() == StateReady     // Validate connected
      → registry.SetDefault(cap, id)      // For each matching capability
      → sealSvc.SetDefaultBackend(id)     // Sync seal service
      → configUpdateFunc(id)              // Persist to gui.json
```

## Data Flow: Per-Operation Routing

```
User selects "tpm2" backend in Keys view filter chips
  → selectedBackend = 'tpm2'
  → KeyService.ListKeys('local', 'tpm2')
    → client.ListKeys(ctx, 'tpm2')
      → SDK transport routes to TPM2 backend
        → TPM2 backend returns keys
```
