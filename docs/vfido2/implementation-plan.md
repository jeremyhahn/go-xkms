# VirtualFIDO Security Key Backend Implementation Plan

## Objective
Create a virtual security key backend within go-keychain by wrapping the `github.com/bulwarkid/virtual-fido` library:
1. Implements `types.Backend` interface (like YubiKey, CanoKey, TPM2)
2. Supports PIV operations (slots, certificates, signing)
3. Supports FIDO2 operations (WebAuthn, hmac-secret)
4. Supports key-specific operations (PIN, PUK, management key)
5. Can be used by applications embedding go-keychain as a library
6. Enables integration testing without hardware security keys

## Architecture Overview

### Wrapping github.com/bulwarkid/virtual-fido

We wrap the existing `virtual-fido` library which provides:
- Complete FIDO2/U2F protocol implementation
- `CTAPClient` interface for authenticator operations
- `CTAPServer` for processing CTAP protocol messages
- `DefaultFIDOClient` with credential management, PIN, attestation
- USB/IP layer for virtual device creation

### Two-Layer Architecture

**Layer 1: Backend (pkg/backend/virtualfido/)**
- Wraps `virtual-fido.DefaultFIDOClient` for FIDO2 operations
- Implements `types.Backend` interface (standard keychain operations)
- Implements `VirtualFIDOBackend` interface (key-specific operations)
- PIV slot management using Go crypto packages
- State persistence (memory or file)

**Layer 2: FIDO2 Device Adapter (pkg/fido2/virtual_*.go)**
- Adapts `virtual-fido` to go-keychain's `HIDDevice` interface
- Adapts to go-keychain's `HIDDeviceEnumerator` interface
- Used by existing fido2.Handler seamlessly

**Key Insight**: We leverage virtual-fido for CTAP/FIDO2 complexity while adding go-keychain Backend interface.

## Dependencies

Add to go.mod:
```
require github.com/bulwarkid/virtual-fido v0.0.0-latest
```

The virtual-fido library provides:
- `ctap.CTAPClient` interface
- `ctap.CTAPServer` for protocol handling
- `fido_client.DefaultFIDOClient` - full authenticator implementation
- `ctap_hid` - CTAP HID protocol layer

## Files to Create

### Backend Layer (pkg/backend/virtualfido/)

#### 1. `config.go` - Configuration
```go
import "github.com/jeremyhahn/go-keychain/pkg/storage"

type Config struct {
    // Storage backend (go-objstore compatible)
    // Uses storage.Backend interface for persistence
    // If nil, uses in-memory storage (ephemeral, for tests)
    Storage storage.Backend

    // Virtual device identity
    SerialNumber string
    Manufacturer string
    Product      string

    // PIV configuration
    PIN          string  // Default: "123456"
    PUK          string  // Default: "12345678"
    MgmtKey      []byte  // 24-byte management key

    // Encryption passphrase for credential storage
    Passphrase   string  // For encrypting FIDO2 credentials at rest

    Logger       *logging.Logger
}
```

#### 2. `storage_adapter.go` - Storage Adapter
Adapts go-keychain's storage.Backend to virtual-fido's credential storage interface.

**Storage Keys Layout:**
```
virtualfido/
├── credentials/          # FIDO2 credentials (encrypted)
│   ├── {credentialID}   # Each credential stored by ID
├── piv/                  # PIV slot data
│   ├── 9a               # Authentication slot
│   ├── 9c               # Signature slot
│   ├── 9d               # Key Management slot
│   ├── 9e               # Card Auth slot
│   └── 82-95            # Retired slots
├── counters/            # Sign counters
└── config/              # Device configuration (PIN hash, etc)
```

#### 3. `backend.go` - Main Backend
Implements `types.Backend`, `types.SymmetricBackend`, `types.KeyAgreement`, `types.AttestingBackend`.

#### 4. `slots.go` - PIV Slot Management
```go
type PIVSlot uint8

const (
    SlotAuthentication PIVSlot = 0x9a  // PIV Authentication
    SlotSignature      PIVSlot = 0x9c  // Digital Signature
    SlotKeyManagement  PIVSlot = 0x9d  // Key Management
    SlotCardAuth       PIVSlot = 0x9e  // Card Authentication
)
```

#### 5. `signer.go` - crypto.Signer implementation
#### 6. `decrypter.go` - crypto.Decrypter implementation
#### 7. `symmetric.go` - SymmetricBackend implementation
#### 8. `keyagreement.go` - KeyAgreement implementation
#### 9. `attestation.go` - AttestingBackend implementation
#### 10. `keyops.go` - Key-specific operations (PIN/PUK/MgmtKey)

### FIDO2 Layer (pkg/fido2/)

#### 11. `virtual_device.go` - Virtual HID Device Adapter
Adapts virtual-fido to go-keychain's HIDDevice interface.

#### 12. `virtual_enumerator.go` - Device Enumerator
Implements HIDDeviceEnumerator for virtual devices.

#### 13. `virtual_approver.go` - Auto-Approver for Tests
Auto-approves all FIDO2 requests for non-interactive testing.

## Implementation Order

### Phase 1: Add Dependency & Backend Foundation
1. Add `github.com/bulwarkid/virtual-fido` to go.mod
2. `pkg/backend/virtualfido/config.go`
3. `pkg/backend/virtualfido/storage_adapter.go`
4. `pkg/backend/virtualfido/slots.go`
5. `pkg/backend/virtualfido/backend.go`
6. `pkg/backend/virtualfido/signer.go`
7. `pkg/backend/virtualfido/keyops.go`
8. Unit tests

### Phase 2: FIDO2 Device Adapter Layer
1. `pkg/fido2/virtual_approver.go`
2. `pkg/fido2/virtual_device.go`
3. `pkg/fido2/virtual_enumerator.go`
4. Unit tests

### Phase 3: HMAC-Secret Extension
1. Check virtual-fido hmac-secret support
2. Implement or fork if needed
3. Integration tests

### Phase 4: Integration & Tests
1. Wire backend to FIDO2 device adapter
2. Update `test/integration/fido2/testutil.go`
3. Verify all FIDO2 tests pass
4. Add `test/integration/virtualfido/` tests

### Phase 5: Documentation
1. Complete docs/virtualfido/ documentation
2. Update docs/fido2/ documentation

## Success Criteria

1. Virtual backend implements full `types.Backend` interface
2. Virtual backend implements `types.SymmetricBackend` interface
3. Virtual backend implements `types.KeyAgreement` interface
4. Virtual backend implements `types.AttestingBackend` interface
5. PIV slot operations work (generate, sign, decrypt, rotate)
6. FIDO2 operations work (EnrollKey, UnlockWithKey, ListDevices)
7. HMAC-secret extension produces consistent derived keys
8. Both persistence modes work (memory and storage.Backend)
9. All existing FIDO2 integration tests pass with virtual backend
10. Applications can use VirtualFIDO backend same as YubiKey/CanoKey
11. No hardware required for any FIDO2 integration tests
