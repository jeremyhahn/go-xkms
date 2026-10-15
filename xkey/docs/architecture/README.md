# Xkey Architecture

> **Status: REFERENCE** · Last verified: 2026-10-13
> Cross-cutting overview of the virtual FIDO2 authenticator's layers; the [virtual-authenticator](../virtual-authenticator/) and [fido2](../fido2/) feature folders are normative.

This document describes the architecture of xkey and its component interfaces.

## Overview

xkey is a virtual FIDO2/WebAuthn authenticator that exposes itself as a USB HID device via Linux UHID. It consists of several layered components.

```
+-------------------+
|   WebAuthn/FIDO2  |  Browser / Application
|      Client       |
+-------------------+
         |
         | USB HID Protocol
         v
+-------------------+
|    Linux UHID     |  Kernel HID Subsystem
+-------------------+
         |
         | /dev/uhid
         v
+-------------------+
|    fido2Device    |  xkey/cmd/xkey/cmd
|                   |
+-------------------+
         |
         v
+-------------------+
|  CTAPHIDHandler   |  HID Packet Framing
+-------------------+
         |
         | CTAP2 Commands
         v
+-------------------+
|   Authenticator   |  CTAP2 Protocol
+-------------------+
    |         |
    v         v
+--------+ +--------+
| Storage| |KeyBack-|
|        | |  end   |
+--------+ +--------+
```

## Key Hierarchy and Security Architecture

Xkey implements a hierarchical key management system that provides separate access paths for Security Officers (SO) and regular users while maintaining credential security.

### Key Hierarchy Diagram

```
+------------------+                    +------------------+
|     SO PIN       |                    |    User PIN      |
+--------+---------+                    +--------+---------+
         |                                       |
         v (Argon2id KDF)                        v (Argon2id KDF)
+--------+---------+                    +--------+---------+
|  SMK (SO Master  |                    |  UMK (User Master|
|      Key)        |                    |      Key)        |
+--------+---------+                    +--------+---------+
         |                                       |
         v (AES-GCM unwrap)                      |
+--------+---------+                             |
|   AK (Admin Key) |                             |
+--------+---------+                             |
         |                                       |
    +----+----+                                  |
    |         |                                  |
    v         v (AES-GCM unwrap)                 v (AES-GCM unwrap)
+---+---+   +-+-------------+           +-------+-------+
|Attest |   |     CMK       |<----------+  CMK (dual    |
|Key    |   | (via AK wrap) |           |   wrapped)    |
+-------+   +-------+-------+           +-------+-------+
                    |                           |
                    +-------------+-------------+
                                  |
                                  v (AES-GCM unwrap)
                    +-------------+-------------+
                    |      Credential Keys      |
                    +---------------------------+
```

### Key Components

| Key | Purpose | Protected By | Wrapped By |
|-----|---------|--------------|------------|
| **SMK** | SO Master Key | Argon2id(SO PIN) | Derived, not stored |
| **AK** | Admin Key - protects attestation and enables SO access to CMK | SMK | SMK (AES-GCM) |
| **UMK** | User Master Key | Argon2id(User PIN) | Derived, not stored |
| **CMK** | Credential Master Key - protects all credential keys | AK or UMK | Dual-wrapped by both |
| **Attestation Key** | Signs attestation statements | AK | AK (AES-GCM) |
| **Credential Keys** | Per-credential signing keys | CMK | CMK (AES-GCM) |

### Dual-Wrap Mechanism

The Credential Master Key (CMK) is wrapped twice, once by the Admin Key (AK) derived from SO PIN, and once by the User Master Key (UMK) derived from User PIN. This enables:

- **User operations**: User PIN derives UMK, unwraps CMK, accesses credentials
- **SO operations**: SO PIN derives SMK, unwraps AK, unwraps CMK, can reset User PIN
- **Recovery**: SO can reset locked User PIN without losing credentials

### KeyManager Component

`KeyManager` (`pkg/fido2/authenticator/key_manager.go:93`) orchestrates all key
derivation, wrapping, and unwrapping. It holds the unwrapped AK, CMK, SMK, and
UMK in go-enclave-backed `*secure.Buffer`s (mlocked, wiped on `Lock`) and never
caches the attestation key unwrapped: `AttestationSigner` unwraps it for each
signature.

**Key Methods:**

- `UnlockWithSOPIN(pin string) error` - Derive SMK, unwrap AK, unwrap the SO copy of CMK
- `UnlockWithUserPIN(pinHash []byte) error` - Derive UMK from the CTAP2 PIN hash, unwrap the user copy of CMK
- `InitializeSOPIN(soPin string) error` - Generate AK, CMK, and the attestation key and wrap them
- `InitializeUserPIN(pinHash []byte) error` - Wrap CMK under the UMK (SO-unlocked only)
- `WrapCredentialKey(privateKeyPKCS8 *secure.Buffer) ([]byte, error)` - Wrap a credential key with CMK
- `UnwrapCredentialKey(wrapped []byte) ([]byte, error)` - Unwrap a credential key with CMK
- `AttestationSigner() (crypto.Signer, error)` - Signer over the wrapped attestation key
- `ChangeSOPIN(currentSMK []byte, newPIN string) error` - Re-wrap AK with the new SMK
- `ResetUserPIN(newPINHash []byte) error` - SO re-wraps CMK under a new UMK
- `Lock()` - Destroy all cached key material

### Key Derivation Parameters

The UMK is derived with Argon2id using these parameters (`umk*` constants,
`pkg/fido2/authenticator/key_manager.go:67-79`); the SMK is derived by the SO
PIN manager:

| Parameter | Value | Description |
|-----------|-------|-------------|
| Memory | 64 MB | Memory cost (64 * 1024 KB) |
| Time | 3 | Number of iterations |
| Parallelism | 4 | Degree of parallelism |
| Salt | 32 bytes | Set by `SetUMKSalt`, else derived from the SO PIN salt (or the AAGUID when no SO PIN is set) |
| Key Length | 32 bytes | AES-256 key size |

## Component Details

### fido2Device

**Location**: `xkey/cmd/xkey/cmd/fido2.go:747`

The top-level component behind `xkey fido2` that manages the virtual FIDO2 device lifecycle.

**Responsibilities**:
- Opens and manages the UHID device (or the Chrome DevTools bridge with `--cdp`)
- Creates and configures the authenticator
- Runs the HID event loop
- Handles graceful shutdown

It holds the UHID device, the `*authenticator.Authenticator`, the
`*authenticator.CTAPHIDHandler`, the `StatefulCredentialStorage`, and the
`keybackend.FIDO2KeyBackend`, plus the keyboard, IPC server, password store,
notifier, and CDP bridge.

**Key Methods**:
- `newFIDO2Device(ctx, cfg, logger)` - Creates the device from a `*FIDO2Config` (`fido2.go:766`)
- `Run(ctx)` - Starts the event loop (blocking)
- `Close()` - Stops device and releases resources

### CTAPHIDHandler

**Location**: `pkg/fido2/authenticator/hid_adapter.go`

Handles CTAP-HID protocol framing over the 64-byte HID packets.

**Responsibilities**:
- Parses CTAP-HID initialization and continuation packets
- Assembles multi-packet messages
- Routes commands to the Authenticator
- Frames responses into HID packets

### Authenticator

**Location**: `pkg/fido2/authenticator/authenticator.go`

The core CTAP2 authenticator implementation.

**Responsibilities**:
- Processes CTAP2 commands (MakeCredential, GetAssertion, etc.)
- Manages credential storage
- Handles PIN protocol
- Coordinates user presence and verification
- Generates attestation statements

```go
type Authenticator struct {
    config     *Config
    storage    StatefulCredentialStorage
    state      *AuthenticatorState
    keyBackend keybackend.FIDO2KeyBackend
    upHandler  UserPresenceHandler
    keyManager *KeyManager
    // ...
}
```

**CTAP2 Commands Supported** (`Cmd*` constants, `authenticator.go:33-43`):
- `0x01` MakeCredential - Register a new credential
- `0x02` GetAssertion - Authenticate with a credential
- `0x04` GetInfo - Get authenticator capabilities
- `0x06` ClientPIN - PIN management
- `0x07` Reset - Factory reset (requires SO PIN when enabled)
- `0x08` GetNextAssertion - Continue multi-credential assertion
- `0x09` BioEnrollment
- `0x0A` CredentialManagement - Manage stored credentials
- `0x0B` Selection
- `0x0C` LargeBlobs
- `0x0D` AuthenticatorConfig - Device configuration (CTAP2.1)

### AuthenticatorConfig Command (0x0D)

The CTAP2.1 `authenticatorConfig` command provides device configuration management with standard and vendor-specific subcommands.

**Standard Subcommands:**

| ID | Name | Description |
|----|------|-------------|
| 0x01 | EnableEnterpriseAttestation | Enable enterprise attestation mode |
| 0x02 | ToggleAlwaysUv | Toggle always-require-user-verification |
| 0x03 | SetMinPINLength | Set minimum PIN length policy |

**Vendor Subcommands (Xkey Extensions):**

Vendor operations travel under the single `vendorPrototype` subcommand `0x80`
(`AuthConfigCmdVendorPrototype`), which carries a vendor command ID
(`VendorCmd*` constants, `pkg/fido2/authenticator/cmd_config.go:44-79`,
dispatched by the map at `cmd_config.go:167`):

| ID | Name | Description | Requires |
|----|------|-------------|----------|
| 0x01 | VendorCmdSetSOPIN | Initialize SO PIN (first-time) | — |
| 0x02 | VendorCmdChangeSOPIN | Change existing SO PIN | Current SO PIN |
| 0x03 | VendorCmdUnlockWithSOPIN | Unlock the KeyManager | SO PIN |
| 0x04 | VendorCmdResetUserPIN | Reset user PIN | SO unlock |
| 0x05 | VendorCmdReplaceAttestKey | Replace attestation key | SO unlock |
| 0x06 | VendorCmdGetTokenInfo | Token lifecycle state | — |
| 0x07 | VendorCmdSetRPPolicy | Set a per-RP policy | SO unlock |
| 0x08 | VendorCmdGetRPPolicy | Get a per-RP policy | — |
| 0x09 | VendorCmdDeleteRPPolicy | Delete a per-RP policy | SO unlock |
| 0x0A | VendorCmdListRPPolicies | List per-RP policies | — |
| 0x0B | VendorCmdSetProfile | Set the authenticator profile | SO unlock |
| 0x0C | VendorCmdSetAttestCert | Install the attestation certificate chain | SO unlock |

**Command Flow:**

```
1. Client sends authenticatorConfig command (0x0D)
2. Authenticator parses subCommand and params
3. For vendor subcommands (0x80+):
   a. Validate SO PIN if required
   b. Execute vendor operation
   c. Return result
4. For standard subcommands:
   a. Validate PIN token if required
   b. Execute standard CTAP2.1 operation
   c. Return result
```

### deviceConfig Extension

Xkey implements the `deviceConfig` extension for relying party configuration verification.

**Extension Processing:**

`DeviceConfigExtension` (`pkg/fido2/authenticator/ext_deviceconfig.go:47`):

```go
type DeviceConfigExtension struct {
    MinPINLength int                    `cbor:"minPINLength,omitempty"`
    AlwaysUV     bool                   `cbor:"alwaysUV,omitempty"`
    PINProtocol  int                    `cbor:"pinProtocol,omitempty"`
    AttestedHash []byte                 `cbor:"attestedHash,omitempty"`
    CurrentHash  []byte                 `cbor:"currentHash,omitempty"`
    Tampered     bool                   `cbor:"tampered,omitempty"`
    Vendor       map[string]interface{} `cbor:"vendor,omitempty"`
}
```

**Hash Computation:**

`ComputeConfigHash(cfg *Config)` (`ext_deviceconfig.go:100`) builds a canonical
`ConfigForHash` from `PINMinLength`, `AlwaysUV`, and the PIN protocol version,
marshals it to JSON, and returns its SHA-256.

**Tamper Detection Flow:**

```
1. When the Security Officer installs the attestation key, the configuration
   hash is recorded as attestedHash (the baseline)
2. Each response computes currentHash from the current configuration
3. tampered is set when the two hashes differ
4. Relying party receives tampered status in the extension output
```

## UserPresenceHandler Interface

**Location**: `pkg/fido2/authenticator/user_presence.go`

Abstracts user presence and verification handling, allowing different implementations for automation vs. interactive use.

```go
type UserPresenceHandler interface {
    // RequestUserPresence requests user presence confirmation (touch simulation).
    RequestUserPresence(ctx context.Context, req *UserPresenceRequest) (*UserPresenceResult, error)

    // RequestUserVerification requests user verification (PIN entry).
    RequestUserVerification(ctx context.Context, req *UserVerificationRequest) (*UserVerificationResult, error)
}
```

### Request/Result Types

```go
type UserPresenceRequest struct {
    RPID      string        // Relying party identifier
    RPName    string        // Human-readable RP name
    UserName  string        // User name for display
    Operation string        // "register" or "authenticate"
    Timeout   time.Duration // Request timeout
}

type UserPresenceResult struct {
    Approved bool // Whether user approved
}

type UserVerificationRequest struct {
    RPID        string
    RPName      string
    UserName    string
    Operation   string
    Timeout     time.Duration
    PINRequired bool // Whether PIN entry is required
}

type UserVerificationResult struct {
    Verified bool // Whether verification succeeded
}
```

### AutoGrantHandler

**Location**: `pkg/fido2/authenticator/user_presence_auto.go`

Automatically approves all user presence and verification requests. Default for automation scenarios.

```go
type AutoGrantHandler struct{}

func NewAutoGrantHandler() *AutoGrantHandler
```

Behavior:
- `RequestUserPresence` always returns `Approved: true`
- `RequestUserVerification` always returns `Verified: true`

### InteractiveHandler

**Location**: `pkg/fido2/authenticator/user_presence_interactive.go`

Prompts the user via terminal for presence confirmation and PIN entry.

```go
type InteractiveHandler struct {
    mu     sync.Mutex
    reader io.Reader
    writer io.Writer
    fd     int // Terminal file descriptor
}

func NewInteractiveHandler() (*InteractiveHandler, error)
func NewInteractiveHandlerWithIO(reader io.Reader, writer io.Writer, fd int) *InteractiveHandler
```

Behavior:
- `RequestUserPresence` displays prompt, waits for ENTER key
- `RequestUserVerification` displays prompt, reads PIN with hidden input
- Returns error on timeout or cancellation

## FIDO2KeyBackend Interface

**Location**: `pkg/fido2/authenticator/keybackend/keybackend.go`

Abstracts cryptographic key operations, allowing different backend implementations.

```go
type FIDO2KeyBackend interface {
    // Type returns the backend type identifier.
    Type() xkms.BackendType

    // Capabilities returns what this backend supports.
    Capabilities() FIDO2KeyCapabilities

    // HandlesUserVerificationFor / HandlesUserPresenceFor report whether the
    // backend that holds a given credential's key verifies the user or
    // collects presence inside the key operation.
    HandlesUserVerificationFor(backendID xkms.BackendType) bool
    HandlesUserPresenceFor(backendID xkms.BackendType) bool

    // GenerateCredentialKey creates a new key pair.
    GenerateCredentialKey(algorithm int, credentialID []byte) (KeyHandle, []byte, error)

    // Sign creates a signature over the data.
    Sign(handle KeyHandle, algorithm int, data []byte) ([]byte, error)

    // LoadKey loads a previously generated key by credential ID.
    LoadKey(credentialID []byte, algorithm int) (KeyHandle, error)

    // DeleteKey removes a key from the backend.
    DeleteKey(handle KeyHandle) error

    // ExportPrivateKey exports the private key in PKCS#8 format.
    ExportPrivateKey(handle KeyHandle) ([]byte, error)

    // ImportPrivateKey imports a PKCS#8 encoded private key.
    ImportPrivateKey(credentialID []byte, algorithm int, pkcs8Key []byte) (KeyHandle, error)

    // Close releases backend resources.
    Close() error
}
```

### Capabilities

```go
type FIDO2KeyCapabilities struct {
    SupportedAlgorithms []int // COSE algorithm IDs
    SupportsExport      bool  // Can export private keys
    SupportsImport      bool  // Can import private keys
    SupportsAttestation bool  // Can provide attestation
    HardwareBacked      bool  // Keys stored in hardware
    HandlesUserPresence     bool // Backend collects presence itself (e.g. phone biometric)
    HandlesUserVerification bool // Backend verifies the user inside its key operations
}
```

### BackendAdapter

**Location**: `pkg/fido2/authenticator/keybackend/adapter.go`

There are no per-backend FIDO2 implementations. A single adapter wraps any
go-xkms `KeyProvider` and implements `FIDO2KeyBackend` on top of it, translating
between FIDO2 credential IDs / COSE algorithms and go-xkms `KeyAttributes` and
handling COSE public key encoding. Any provider that supports EC key generation
and signing works automatically, so software, TPM 2.0, PKCS#11, and the cloud
KMS backends are all reached through the same type, selected by `BackendType`.

```go
type BackendAdapter struct {
    provider    xkms.KeyProvider
    backendType xkms.BackendType
    slotModel   xkms.PIVSlotModel // nil for non-slot backends
    // ...
}

func NewBackendAdapter(provider xkms.KeyProvider, backendType xkms.BackendType) *BackendAdapter
```

`xkms` here is `github.com/jeremyhahn/go-xkms/sdk/go`. Backend selection uses the
`BackendType` constants re-exported by that SDK (`sdk/go/types.go:280-290`), among them
`BackendTypeSoftware`, `BackendTypeTPM2`, `BackendTypePKCS11`, `BackendTypeAWSKMS`,
and `BackendTypePhone`.

Per-backend capabilities are reported at runtime by `Capabilities()`, and the
algorithm set is derived from the backend type by `algorithmsForBackend`
(`adapter.go:99`, `adapter.go:129`) rather than being fixed per implementation.

### Attestation Interface

For backends that support attestation:

```go
type FIDO2AttestingKeyBackend interface {
    FIDO2KeyBackend

    // GenerateAttestationKey creates or loads the attestation signing key.
    GenerateAttestationKey() (KeyHandle, []byte, error)

    // GetAttestationStatement generates an attestation statement.
    GetAttestationStatement(format string, authData, clientDataHash []byte) (*FIDO2AttestationStatement, error)

    // AttestationCertificateChain returns the attestation certificate chain.
    AttestationCertificateChain() ([]*x509.Certificate, error)
}
```

## Storage Architecture

### Layered Encryption Model

Xkey uses a layered storage architecture where the barrier ALWAYS wraps the base backend, and LUKS is an optional base layer underneath.

```
Without LUKS:   App --> Barrier (AES-256-GCM) --> filestorage.Backend --> disk
With LUKS:      App --> Barrier (AES-256-GCM) --> luks.Backend --> filestorage.Backend --> LUKS volume
```

| Layer | Encryption | Key Protection |
|-------|-----------|----------------|
| Barrier (always active) | AES-256-GCM per-value | Root key sealed by strategy (TPM2, software, cloud KMS) |
| LUKS (optional base) | AES-256-XTS full-volume | Passphrase + Argon2id (kernel dm-crypt) |

The barrier is initialized during the setup wizard regardless of whether LUKS is selected. When LUKS is selected as the storage type, the barrier writes its encrypted data into the LUKS mount point, providing dual-layer encryption. The root module's `luks.Backend` (`pkg/storage/luks/backend.go:43`) implements `storage.Backend` by delegating to a `pkg/storage/file` store rooted at the LUKS mount point when unlocked (`backend.go:89`).

The GUI's TPM auto-unseal records the sealed passphrase's blob ID in `gui.auto_unseal_blob_id` (`AutoUnsealBlobID`, `xkey/pkg/gui/config.go:109`). For a returning user the `App` tries it at startup (`xkey/pkg/gui/app.go:2966`) and reseals the blob with current PCR values on shutdown (`app.go:3573`).

Static passwords and other sensitive data stored through the barrier backend are transparently encrypted by the barrier's AES-256-GCM layer before reaching the base storage.

For full details on the barrier, barrier auto-unseal, and LUKS integration, see [Seal & Auto-Unseal Architecture](../../docs/seal/architecture.md).

### CredentialStorage Interface

**Location**: `pkg/fido2/authenticator/config.go`

Basic credential persistence interface.

```go
type CredentialStorage interface {
    Store(credential *StoredCredential) error
    Load(credentialID []byte) (*StoredCredential, error)
    LoadByRPID(rpID string) ([]*StoredCredential, error)
    Delete(credentialID []byte) error
    Count() (int, error)
    CountDiscoverable() (int, error)
}
```

### StatefulCredentialStorage Interface

**Location**: `pkg/fido2/authenticator/storage.go`

Extended interface with authenticator state persistence.

```go
type StatefulCredentialStorage interface {
    CredentialStorage

    SaveState(state *AuthenticatorState) error
    LoadState() (*AuthenticatorState, error)
    Close() error
}
```

### Implementations

**MemoryStorage** (`pkg/fido2/authenticator/storage_memory.go:25`): In-memory implementation for testing.

**BackendStorage** (`pkg/fido2/authenticator/storage_backend.go:83`): Wraps a storage backend for persistent storage.

## Data Flow

### Registration (MakeCredential)

```
1. Browser sends MakeCredential request
2. UHID receives HID packets
3. CTAPHIDHandler assembles CTAP message
4. Authenticator.HandleMakeCredential processes request:
   a. Validates parameters
   b. Requests user presence via UserPresenceHandler
   c. Generates credential key via FIDO2KeyBackend
   d. Stores credential via CredentialStorage
   e. Generates attestation statement
   f. Returns authenticator data + attestation
5. Response flows back through layers
```

### Authentication (GetAssertion)

```
1. Browser sends GetAssertion request
2. UHID receives HID packets
3. CTAPHIDHandler assembles CTAP message
4. Authenticator.handleGetAssertion processes request:
   a. Finds matching credentials
   b. Requests user presence via UserPresenceHandler
   c. Loads credential key via FIDO2KeyBackend
   d. Signs assertion
   e. Increments sign counter
   f. Returns assertion
5. Response flows back through layers
```

## Thread Safety

All components are designed for concurrent use:

- `Authenticator`: Uses `sync.RWMutex` for state protection
- `Storage`: Implementations must be thread-safe
- `FIDO2KeyBackend`: Implementations must be thread-safe
- `UserPresenceHandler`: Implementations must be thread-safe
- Atomic operations used for closed flags and counters

## Error Handling

Errors are mapped to CTAP2 status codes:

| Error | Status Code |
|-------|-------------|
| `ErrUserPresenceDenied` | `0x27` CTAP2_ERR_OPERATION_DENIED |
| `ErrUserPresenceTimeout` | `0x2F` CTAP2_ERR_USER_ACTION_TIMEOUT |
| `ErrPINInvalid` | `0x31` CTAP2_ERR_PIN_INVALID |
| `ErrPINBlocked` | `0x32` CTAP2_ERR_PIN_BLOCKED |
| `ErrNoCredentials` | `0x2E` CTAP2_ERR_NO_CREDENTIALS |

## Extension Points

### Custom User Presence Handler

Implement `UserPresenceHandler` for custom approval flows:

```go
type MyHandler struct{}

func (h *MyHandler) RequestUserPresence(ctx context.Context, req *UserPresenceRequest) (*UserPresenceResult, error) {
    // Custom logic (GUI prompt, remote approval, etc.)
    return &UserPresenceResult{Approved: true}, nil
}

func (h *MyHandler) RequestUserVerification(ctx context.Context, req *UserVerificationRequest) (*UserVerificationResult, error) {
    // Custom verification logic
    return &UserVerificationResult{Verified: true}, nil
}
```

### Custom Key Backend

Implement `FIDO2KeyBackend` for alternative key storage:

```go
type MyBackend struct{}

func (b *MyBackend) GenerateCredentialKey(algorithm int, credentialID []byte) (keybackend.KeyHandle, []byte, error) {
    // Generate key in HSM, cloud KMS, etc.
}

// Implement remaining interface methods...
```

### Custom Storage Backend

Implement `StatefulCredentialStorage` for alternative storage:

```go
type MyStorage struct{}

func (s *MyStorage) Store(credential *StoredCredential) error {
    // Store in database, cloud storage, etc.
}

// Implement remaining interface methods...
```

## Other Components

Key backends are selected through the `BackendAdapter` above; see
[Backend Selection](backend-selection.md). The SSH agent, key store, and
connect/console live in the [ssh](../ssh/) feature folder.
