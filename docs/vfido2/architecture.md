# vfido2 Architecture

This document describes the architecture of vfido2 and its component interfaces.

## Overview

vfido2 is a virtual FIDO2/WebAuthn authenticator that exposes itself as a USB HID device via Linux UHID. It consists of several layered components.

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
|   VirtualFIDO2    |  cmd/vfido2
|      Device       |
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

## Component Details

### VirtualFIDO2Device

**Location**: `cmd/vfido2/device.go`

The top-level component that manages the virtual FIDO2 device lifecycle.

**Responsibilities**:
- Opens and manages the UHID device
- Creates and configures the authenticator
- Runs the HID event loop
- Handles graceful shutdown

```go
type VirtualFIDO2Device struct {
    cfg        *Config
    logger     *slog.Logger
    uhidDevice *uhid.Device
    auth       *authenticator.Authenticator
    hidHandler *authenticator.CTAPHIDHandler
    storage    authenticator.StatefulCredentialStorage
    keyBackend keybackend.FIDO2KeyBackend
    running    atomic.Bool
}
```

**Key Methods**:
- `NewVirtualFIDO2Device(cfg, logger)` - Creates device with configuration
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
    config    *Config
    storage   StatefulCredentialStorage
    state     *AuthenticatorState
    upHandler UserPresenceHandler
    // ...
}
```

**CTAP2 Commands Supported**:
- `0x01` MakeCredential - Register a new credential
- `0x02` GetAssertion - Authenticate with a credential
- `0x04` GetInfo - Get authenticator capabilities
- `0x06` ClientPIN - PIN management
- `0x07` Reset - Factory reset
- `0x08` GetNextAssertion - Continue multi-credential assertion
- `0x0A` CredentialManagement - Manage stored credentials

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
    Verified bool   // Whether verification succeeded
    PIN      string // Entered PIN (if required)
}
```

### AutoGrantHandler

**Location**: `pkg/fido2/authenticator/user_presence_auto.go`

Automatically approves all user presence and verification requests. Default for automation scenarios.

```go
type AutoGrantHandler struct {
    simulatedPIN string // PIN to return for verification requests
}

func NewAutoGrantHandler() *AutoGrantHandler
func NewAutoGrantHandlerWithPIN(pin string) *AutoGrantHandler
```

Behavior:
- `RequestUserPresence` always returns `Approved: true`
- `RequestUserVerification` always returns `Verified: true` with configured PIN

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
func NewInteractiveHandlerWithIO(reader, writer io.Writer, fd int) *InteractiveHandler
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
    Type() FIDO2KeyBackendType

    // Capabilities returns what this backend supports.
    Capabilities() FIDO2KeyCapabilities

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
}
```

### SoftwareKeyBackend

**Location**: `pkg/fido2/authenticator/keybackend/software/software.go`

In-memory key storage with PKCS#8 serialization support.

```go
type SoftwareKeyBackend struct {
    mu     sync.RWMutex
    keys   map[string]*softwareKeyHandle
    closed atomic.Bool
}

func NewSoftwareKeyBackend() *SoftwareKeyBackend
```

Capabilities:
- Algorithms: ES256 (-7), ES384 (-35), ES512 (-36), EdDSA (-8)
- Export: Yes (PKCS#8)
- Import: Yes (PKCS#8)
- Hardware Backed: No

### TPM2KeyBackend

**Location**: `pkg/fido2/authenticator/keybackend/tpm2/tpm2.go`

Hardware-backed keys via TPM 2.0.

```go
type TPM2KeyBackend struct {
    mu         sync.RWMutex
    tpm        TPMInterface
    devicePath string
    keys       map[string]*tpm2KeyHandle
    closed     atomic.Bool
}

type TPM2Config struct {
    DevicePath string       // TPM device path
    TPM        TPMInterface // Pre-initialized TPM interface
}

func NewTPM2KeyBackend(cfg *TPM2Config) (*TPM2KeyBackend, error)
```

Capabilities:
- Algorithms: ES256 (-7), ES384 (-35)
- Export: No (hardware-protected)
- Import: No
- Hardware Backed: Yes

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
    ListRPIDs() ([]string, error)
    Close() error
}
```

### Implementations

**MemoryStorage**: In-memory implementation for testing.

**BackendStorage**: Wraps a file backend for persistent storage.

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
    return &UserVerificationResult{Verified: true, PIN: "..."}, nil
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
