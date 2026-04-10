# Xkey Architecture

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
|   VirtualFIDO2    |  cmd/xkey
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

The `KeyManager` orchestrates all key derivation, wrapping, and unwrapping operations.

```go
type KeyManager struct {
    storage    KeyStorage
    config     *KeyManagerConfig
    smk        []byte           // Cached SO Master Key (cleared after use)
    umk        []byte           // Cached User Master Key (cleared after use)
    cmk        []byte           // Cached Credential Master Key
    ak         []byte           // Cached Admin Key
    attestKey  crypto.PrivateKey // Cached attestation signing key
    mu         sync.RWMutex
}
```

**Key Methods:**

- `DeriveSOKey(sopin []byte) ([]byte, error)` - Derive SMK from SO PIN
- `DeriveUserKey(pin []byte) ([]byte, error)` - Derive UMK from User PIN
- `UnwrapAdminKey(smk []byte) ([]byte, error)` - Unwrap AK using SMK
- `UnwrapCMK(key []byte, isAdmin bool) ([]byte, error)` - Unwrap CMK using AK or UMK
- `WrapCredentialKey(cmk, credKey []byte) ([]byte, error)` - Wrap credential key
- `UnwrapCredentialKey(cmk, wrappedKey []byte) ([]byte, error)` - Unwrap credential key
- `InitializeSOPIN(sopin []byte) error` - Set up SO key hierarchy
- `ChangeSOPIN(oldPIN, newPIN []byte) error` - Re-wrap AK with new SO PIN
- `ResetUserPIN(smk, newPIN []byte) error` - SO resets user PIN

### Key Derivation Parameters

Xkey uses Argon2id for PIN-to-key derivation with these default parameters:

| Parameter | Value | Description |
|-----------|-------|-------------|
| Memory | 64 MB | Memory cost (64 * 1024 KB) |
| Time | 3 | Number of iterations |
| Parallelism | 4 | Degree of parallelism |
| Salt | 32 bytes | Random, stored with wrapped keys |
| Key Length | 32 bytes | AES-256 key size |

## Component Details

### VirtualFIDO2Device

**Location**: `cmd/xkey/device.go`

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
- `0x07` Reset - Factory reset (requires SO PIN when enabled)
- `0x08` GetNextAssertion - Continue multi-credential assertion
- `0x0A` CredentialManagement - Manage stored credentials
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

| ID | Name | Description | Requires |
|----|------|-------------|----------|
| 0x80 | VendorSetSOPIN | Initialize SO PIN (first-time) | No auth |
| 0x81 | VendorChangeSOPIN | Change existing SO PIN | Current SO PIN |
| 0x82 | VendorUnlockWithSOPIN | Unlock authenticator | SO PIN |
| 0x83 | VendorResetUserPIN | Reset user PIN | SO PIN |
| 0x84 | VendorReplaceAttestKey | Replace attestation key | SO PIN |
| 0x85 | VendorGetSOPINRetries | Query SO PIN retry count | No auth |

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

```go
type DeviceConfigExtension struct {
    MinPINLength uint            `cbor:"1,keyasint"`
    AlwaysUV     bool            `cbor:"2,keyasint"`
    PINProtocol  uint            `cbor:"3,keyasint"`
    AttestedHash []byte          `cbor:"4,keyasint"`
    CurrentHash  []byte          `cbor:"5,keyasint"`
    Tampered     bool            `cbor:"6,keyasint"`
    Vendor       map[string]any  `cbor:"7,keyasint,omitempty"`
}
```

**Hash Computation:**

```go
// ConfigHash computes SHA-256 of canonical config representation
func (c *DeviceConfig) Hash() []byte {
    data := struct {
        MinPINLength uint
        AlwaysUV     bool
        PINProtocol  uint
        // ... other config fields
    }{
        MinPINLength: c.MinPINLength,
        AlwaysUV:     c.AlwaysUV,
        PINProtocol:  c.PINProtocol,
    }
    encoded, _ := cbor.Marshal(data)
    hash := sha256.Sum256(encoded)
    return hash[:]
}
```

**Tamper Detection Flow:**

```
1. During MakeCredential, attestedHash is computed and stored with credential
2. During GetAssertion, currentHash is computed from current config
3. Extension compares hashes and sets tampered flag
4. Relying party receives tampered status in authenticator data
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

Hardware-backed keys via TPM 2.0 persistent handles. All credentials share a single
persistent TPM key -- the private key never leaves the TPM.

```go
type TPM2KeyBackend struct {
    tpm        TPMSigner
    handle     uint32 // persistent TPM handle
    devicePath string
    closed     atomic.Bool
}

type TPM2Config struct {
    DevicePath string    // TPM device path
    Handle     uint32    // Persistent TPM handle (default: 0x81020001 = IAK)
    TPM        TPMSigner // Pre-initialized TPM signer
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

The barrier is initialized during the setup wizard regardless of whether LUKS is selected. When LUKS is selected as the storage type, the barrier writes its encrypted data into the LUKS mount point, providing dual-layer encryption. The `luks.Backend` (`pkg/storage/luks/`) implements `storage.Backend` by delegating to a `filestorage.Backend` rooted at the LUKS mount point when unlocked.

Barrier auto-unseal is configured via `BarrierAutoUnsealBlobID`. When using the software sealing strategy, the barrier password is TPM-sealed so the barrier can unlock automatically on boot if the PCR state matches. The blob is re-sealed with current PCR values on shutdown.

Static passwords and other sensitive data stored through the barrier backend are transparently encrypted by the barrier's AES-256-GCM layer before reaching the base storage.

For full details on the barrier and LUKS integration, see [Barrier Encryption Architecture](../../docs/seal/README.md) and [LUKS + Barrier Layered Architecture](../../docs/seal/barrier.md).

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

## TPM2 Backend Integration

The virtual FIDO2 device wires up a real TPM2 backend via the `TPMSignerAdapter`:

```
createKeyBackend(cfg)
    |
    +-- "software" → SoftwareKeyBackend (default)
    |
    +-- "tpm2" → createTPM2KeyBackend()
        |
        +-- pkgtpm2.NewTPM2(device) → TrustedPlatformModule
        +-- tpm2backend.NewTPMSignerAdapter(tpm)
        +-- tpm2backend.NewTPM2KeyBackend(config)
```

**Configuration flags**:
- `--backend tpm2` -- selects TPM2 key backend
- `--tpm-device /dev/tpmrm0` -- TPM device path (default: `/dev/tpmrm0`)

**Error handling**:
- `ErrTPMOpenFailed` -- TPM device could not be opened
- `ErrTPMBackendCreationFailed` -- TPM2 backend initialization failed

## Planned: Cloud KMS Backends

Future backends will support cloud KMS services for FIDO2 credential key management:

- **AWS KMS** (`--backend awskms`) -- ECDSA signing keys via AWS KMS
- **GCP KMS** (`--backend gcpkms`) -- ECDSA signing keys via Google Cloud KMS
- **Azure Key Vault** (`--backend azurekv`) -- ECDSA signing keys via Azure Key Vault

Each uses build tags to avoid unnecessary cloud SDK dependencies.

## Planned: Proxy Backend

A proxy backend (`--backend proxy`) delegates key operations to a remote xkmsd service:

```
xkey → SDK Transport → xkmsd → Backend (TPM2, KMS, etc.)
```

Supports multiple transport protocols: Unix socket, gRPC, REST, QUIC, and MCP.

---

## SSH Agent Architecture

The SSH agent provides a Unix socket-based agent compatible with standard SSH clients (`ssh-agent` protocol).

### Overview

```
+-------------------+
|   SSH Client      |  ssh, git, etc.
+-------------------+
         |
         | SSH Agent Protocol
         v
+-------------------+
|   Xkey Agent      |  xkey/pkg/ssh/agent
|      Server       |
+-------------------+
         |
         v
+-------------------+
|    KeyBackend     |  Abstract key operations
+-------------------+
    |           |
    v           v
+--------+ +-----------+
| Local  | | Xkmsd |
|Backend | |  Backend  |
+--------+ +-----------+
    |           |
    v           v
+--------+ +-----------+
|  File  | |  xkmsd|
|Storage | |  Service  |
+--------+ +-----------+
               |
               v
          +--------+
          |Backend |
          |(TPM2,  |
          | KMS,   |
          | etc.)  |
          +--------+
```

### Components

#### Agent Server

**Location**: `xkey/pkg/ssh/agent/server.go`

The agent server listens on a Unix socket and handles SSH agent protocol requests.

```go
type Server struct {
    agent      *Agent
    listener   net.Listener
    socketPath string
    logger     *slog.Logger
}

func NewServer(agent *Agent, cfg *ServerConfig) (*Server, error)
func (s *Server) Serve(ctx context.Context) error
func (s *Server) Close() error
```

#### Agent

**Location**: `xkey/pkg/ssh/agent/agent.go`

The agent implements the `golang.org/x/crypto/ssh/agent.Agent` interface.

```go
type Agent struct {
    backend KeyBackend
    logger  *slog.Logger
}

// Implements ssh/agent.Agent interface
func (a *Agent) List() ([]*agent.Key, error)
func (a *Agent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error)
func (a *Agent) Add(key agent.AddedKey) error
func (a *Agent) Remove(key ssh.PublicKey) error
func (a *Agent) RemoveAll() error
func (a *Agent) Lock(passphrase []byte) error
func (a *Agent) Unlock(passphrase []byte) error
func (a *Agent) Signers() ([]ssh.Signer, error)
```

#### KeyBackend Interface

**Location**: `xkey/pkg/ssh/agent/backend.go`

Abstracts key storage and cryptographic operations for the SSH agent.

```go
type KeyBackend interface {
    ListKeys(ctx context.Context) ([]*KeyInfo, error)
    GetPublicKey(ctx context.Context, keyID string) (ssh.PublicKey, error)
    Sign(ctx context.Context, keyID string, data []byte, algorithm string) ([]byte, error)
    GenerateKey(ctx context.Context, keyID string, keyType KeyType, opts *GenerateOptions) (*KeyInfo, error)
    ImportKey(ctx context.Context, keyID string, privateKeyPEM []byte) (*KeyInfo, error)
    DeleteKey(ctx context.Context, keyID string) error
    Close() error
}
```

### Backend Implementations

#### LocalBackend

**Location**: `xkey/pkg/ssh/agent/backend_local.go`

Stores keys locally using the `storage.Backend` interface. Keys are serialized as PKCS#8 PEM.

- **Default path**: `~/.config/xkey/ssh/keys/`
- **Key format**: PKCS#8 PEM for private keys
- **Supported types**: Ed25519, RSA (2048-4096), ECDSA (P-256, P-384, P-521)

#### XkmsdBackend

**Location**: `xkey/pkg/ssh/agent/backend_xkmsd.go`

Delegates key operations to xkmsd via the Go SDK. Supports BYOK (Bring Your Own Key) import protocol.

- **Transport**: Unix socket or gRPC
- **Backends**: Software, TPM2, PKCS#11, cloud KMS
- **Import**: Uses BYOK protocol with RSA-AES key wrapping

### Data Flow

#### Key Signing

```
1. SSH client connects to agent socket
2. Client requests signature for authentication
3. Agent looks up key by public key fingerprint
4. Agent calls KeyBackend.Sign(keyID, data, algorithm)
5. Backend performs signing (local or via xkmsd)
6. Signature returned to SSH client
7. SSH client uses signature for authentication
```

#### Key Generation (Server Mode)

```
1. User runs: xkey ssh keys generate --id my-key
2. CLI calls XkmsdBackend.GenerateKey()
3. Backend calls xkmsd SDK to generate key
4. xkmsd creates key in configured backend (TPM2, KMS, etc.)
5. Public key returned to CLI and displayed
```

#### Key Import (Server Mode with BYOK)

```
1. User runs: xkey ssh keys import ~/.ssh/id_ed25519 --id my-key
2. CLI reads private key from file
3. Backend calls xkmsd.GetImportParameters() for wrapping key
4. Backend wraps private key using RSA-AES key wrap
5. Backend calls xkmsd.ImportKey() with wrapped material
6. xkmsd unwraps and stores key in backend
7. Public key returned to CLI
```
