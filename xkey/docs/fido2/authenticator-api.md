# API Reference

This document provides the complete API reference for the native FIDO2 authenticator package.

## Authenticator

### Constructor

#### NewAuthenticator

Creates a new FIDO2 authenticator instance.

```go
func NewAuthenticator(config *Config) (*Authenticator, error)
```

**Parameters:**
- `config` - Authenticator configuration

**Returns:**
- `*Authenticator` - Initialized authenticator
- `error` - ErrStorageRequired, ErrNoAlgorithms, validation errors

**Example:**
```go
config := authenticator.DefaultConfig()
config.Storage = authenticator.NewMemoryStorage()

auth, err := authenticator.NewAuthenticator(config)
if err != nil {
    log.Fatal(err)
}
defer auth.Close()
```

### Methods

#### ProcessCBOR

Processes a CTAP2 CBOR command.

```go
func (a *Authenticator) ProcessCBOR(cmd byte, data []byte) ([]byte, error)
```

**Parameters:**
- `cmd` - CTAP2 command byte
- `data` - CBOR-encoded command parameters (may be nil)

**Returns:**
- `[]byte` - Response bytes (first byte is status code)
- `error` - Processing errors

**Commands:**
| Command | Code | Data Required |
|---------|------|---------------|
| CmdGetInfo | 0x04 | No |
| CmdMakeCredential | 0x01 | Yes |
| CmdGetAssertion | 0x02 | Yes |
| CmdGetNextAssertion | 0x08 | No |
| CmdClientPIN | 0x06 | Yes |
| CmdCredentialManagement | 0x0A | Yes |
| CmdReset | 0x07 | No |
| CmdSelection | 0x0B | No |

#### MakeCredential

High-level credential creation API.

```go
func (a *Authenticator) MakeCredential(
    clientDataHash []byte,
    rp RelyingParty,
    user User,
    pubKeyCredParams []PublicKeyCredentialParam,
    opts *MakeCredentialOptions,
) (*MakeCredentialResponse, error)
```

**Parameters:**
- `clientDataHash` - SHA-256 hash of client data (32 bytes)
- `rp` - Relying party information
- `user` - User account information
- `pubKeyCredParams` - Acceptable public key algorithms
- `opts` - Optional parameters (may be nil)

**Returns:**
- `*MakeCredentialResponse` - Credential attestation
- `error` - Creation errors

#### GetAssertion

High-level assertion generation API.

```go
func (a *Authenticator) GetAssertion(
    clientDataHash []byte,
    rpId string,
    allowList []CredentialDescriptor,
    opts *GetAssertionOptions,
) (*GetAssertionResponse, error)
```

**Parameters:**
- `clientDataHash` - SHA-256 hash of client data (32 bytes)
- `rpId` - Relying party identifier
- `allowList` - Acceptable credential IDs (nil for discoverable)
- `opts` - Optional parameters (may be nil)

**Returns:**
- `*GetAssertionResponse` - Assertion response
- `error` - Assertion errors

#### Close

Releases authenticator resources.

```go
func (a *Authenticator) Close() error
```

**Notes:**
- Closes underlying storage
- Clears sensitive state
- Idempotent

#### AAGUID

Returns the authenticator's AAGUID.

```go
func (a *Authenticator) AAGUID() [16]byte
```

#### IsClosed

Checks if authenticator has been closed.

```go
func (a *Authenticator) IsClosed() bool
```

#### ClearAssertionState

Clears stored assertion session state.

```go
func (a *Authenticator) ClearAssertionState()
```

**Notes:**
- Called automatically after assertion timeout
- Clears GetNextAssertion context

### Testing Methods

#### SetPINForTesting

Sets PIN directly for testing.

```go
func (a *Authenticator) SetPINForTesting(pin string) error
```

**Parameters:**
- `pin` - Plain text PIN

**Returns:**
- `error` - ErrPINPolicyViolation if too short

**Notes:**
- Bypasses PIN protocol for testing
- Not for production use

#### GetPinUvAuthToken

Returns current PIN token for testing.

```go
func (a *Authenticator) GetPinUvAuthToken() []byte
```

#### VerifyPinUvAuthToken

Verifies PIN auth parameter.

```go
func (a *Authenticator) VerifyPinUvAuthToken(clientDataHash, authParam []byte) bool
```

---

## Types

### Config

```go
type Config struct {
    AAGUID                     [16]byte
    SupportedAlgorithms        []int
    MaxCredentials             int
    MaxResidentCredentials     int
    PINMinLength               int
    PINMaxRetries              int
    EnablePIN                  bool
    EnableResidentKey          bool
    EnableCredentialManagement bool
    EnableHMACSecret           bool
    UserPresenceHandler        UserPresenceHandler
    UserPresenceTimeout        time.Duration
    KeyBackend                 keybackend.FIDO2KeyBackend
    AttestationFormat          string
    Storage                    CredentialStorage
}
```

#### Methods

```go
func DefaultConfig() *Config
func (c *Config) SetDefaults()
func (c *Config) Validate() error
```

### RelyingParty

```go
type RelyingParty struct {
    ID   string // Required: domain name
    Name string // Display name
    Icon string // Optional icon URL
}
```

### User

```go
type User struct {
    ID          []byte // Required: user handle (max 64 bytes)
    Name        string // Username
    DisplayName string // Display name
    Icon        string // Optional icon URL
}
```

### PublicKeyCredentialParam

```go
type PublicKeyCredentialParam struct {
    Type string // "public-key"
    Alg  int    // COSE algorithm ID
}
```

### CredentialDescriptor

```go
type CredentialDescriptor struct {
    Type       string   // "public-key"
    ID         []byte   // Credential ID
    Transports []string // Optional transport hints
}
```

### MakeCredentialOptions

```go
type MakeCredentialOptions struct {
    ExcludeList []CredentialDescriptor
    Extensions  map[string]interface{}
    Options     map[string]bool // "rk", "uv", "up"
}
```

### MakeCredentialResponse

```go
type MakeCredentialResponse struct {
    Fmt      string // Attestation format ("packed", "none")
    AuthData []byte // Authenticator data
    AttStmt  map[string]interface{}
}
```

### GetAssertionOptions

```go
type GetAssertionOptions struct {
    Extensions map[string]interface{}
    Options    map[string]bool // "uv", "up"
}
```

### GetAssertionResponse

```go
type GetAssertionResponse struct {
    Credential          *CredentialDescriptor
    AuthData            []byte
    Signature           []byte
    User                *User
    NumberOfCredentials uint
}
```

---

## Storage Interfaces

### CredentialStorage

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

### StatefulCredentialStorage

```go
type StatefulCredentialStorage interface {
    CredentialStorage
    SaveState(state *AuthenticatorState) error
    LoadState() (*AuthenticatorState, error)
    Close() error
}
```

### Optional Interfaces

```go
type CredentialEnumerator interface {
    EnumerateDiscoverable() ([]*StoredCredential, error)
}

type ClearableStorage interface {
    Clear() error
}

type ListableStorage interface {
    ListAll() ([][]byte, error)
}
```

### StoredCredential

```go
type StoredCredential struct {
    CredentialID    []byte
    RPID            string
    RPName          string
    UserID          []byte
    UserName        string
    UserDisplayName string
    PrivateKey      []byte // PKCS#8 encoded
    PublicKeyCOSE   []byte // CBOR COSE_Key
    Algorithm       int
    SignCount       uint32
    Discoverable    bool
    HMACSecretKey   []byte // 32 bytes
    CredProtect     uint8  // Credential protection level (0-3)
    CreatedAt       int64
}
```

### AuthenticatorState

```go
type AuthenticatorState struct {
    AAGUID          [16]byte
    PINHash         []byte // SHA-256(PIN)[:16]
    PINSet          bool
    AttestationKey  *ecdsa.PrivateKey
    AttestationCert []byte
}
```

#### Methods

```go
func NewAuthenticatorState() *AuthenticatorState
func (s *AuthenticatorState) PINRetries() int32
func (s *AuthenticatorState) SetPINRetries(retries int32)
func (s *AuthenticatorState) DecrementPINRetries()
func (s *AuthenticatorState) UVRetries() int32
func (s *AuthenticatorState) SetUVRetries(retries int32)
func (s *AuthenticatorState) DecrementUVRetries()
```

---

## MemoryStorage

### Constructor

```go
func NewMemoryStorage() *MemoryStorage
```

### Methods

Implements: `StatefulCredentialStorage`, `CredentialEnumerator`, `ClearableStorage`, `ListableStorage`

---

## Key Backend (keybackend package)

### FIDO2KeyBackend

```go
type FIDO2KeyBackend interface {
    Type() FIDO2KeyBackendType
    Capabilities() FIDO2KeyCapabilities
    GenerateCredentialKey(algorithm int, credentialID []byte) (KeyHandle, []byte, error)
    Sign(handle KeyHandle, algorithm int, data []byte) ([]byte, error)
    LoadKey(credentialID []byte, algorithm int) (KeyHandle, error)
    DeleteKey(handle KeyHandle) error
    ExportPrivateKey(handle KeyHandle) ([]byte, error)
    ImportPrivateKey(credentialID []byte, algorithm int, pkcs8Key []byte) (KeyHandle, error)
    Close() error
}
```

### FIDO2AttestingKeyBackend

```go
type FIDO2AttestingKeyBackend interface {
    FIDO2KeyBackend
    GenerateAttestationKey() (KeyHandle, []byte, error)
    GetAttestationStatement(format string, authData, clientDataHash []byte) (*FIDO2AttestationStatement, error)
    AttestationCertificateChain() ([]*x509.Certificate, error)
}
```

### KeyHandle

```go
type KeyHandle interface {
    CredentialID() []byte
    Algorithm() int
}
```

### FIDO2KeyCapabilities

```go
type FIDO2KeyCapabilities struct {
    SupportedAlgorithms []int
    SupportsExport      bool
    SupportsImport      bool
    SupportsAttestation bool
    HardwareBacked      bool
}
```

### SoftwareKeyBackend (keybackend/software)

```go
func NewSoftwareKeyBackend() *SoftwareKeyBackend
```

Implements `FIDO2KeyBackend`. In-process software keys with PKCS#8 export/import support. Algorithms: ES256, ES384, ES512, EdDSA.

### TPM2KeyBackend (keybackend/tpm2)

```go
func NewTPM2KeyBackend(cfg *TPM2Config) (*TPM2KeyBackend, error)
```

Implements `FIDO2KeyBackend`. Hardware-backed keys via TPM 2.0. Algorithms: ES256, ES384. No export/import.

---

## User Presence

### UserPresenceHandler

```go
type UserPresenceHandler interface {
    RequestUserPresence(ctx context.Context, req *UserPresenceRequest) (*UserPresenceResult, error)
    RequestUserVerification(ctx context.Context, req *UserVerificationRequest) (*UserVerificationResult, error)
}
```

### UserPresenceRequest

```go
type UserPresenceRequest struct {
    RPID      string
    RPName    string
    UserName  string
    Operation string        // "register", "authenticate", "reset"
    Timeout   time.Duration // zero uses default (30s)
}
```

### UserPresenceResult

```go
type UserPresenceResult struct {
    Approved bool
}
```

### UserVerificationRequest

```go
type UserVerificationRequest struct {
    RPID        string
    RPName      string
    UserName    string
    Operation   string
    Timeout     time.Duration
    PINRequired bool
}
```

### UserVerificationResult

```go
type UserVerificationResult struct {
    Verified bool
    PIN      string // populated when PINRequired was true
}
```

### AutoGrantHandler

```go
func NewAutoGrantHandler() *AutoGrantHandler
func NewAutoGrantHandlerWithPIN(pin string) *AutoGrantHandler
```

Automatically approves all user presence and verification requests. Default handler when none configured.

### InteractiveHandler

```go
func NewInteractiveHandler() (*InteractiveHandler, error)
func NewInteractiveHandlerWithIO(reader io.Reader, writer io.Writer, fd int) *InteractiveHandler
```

Terminal-based handler. Returns `ErrTerminalUnavailable` if stdin is not a terminal.

---

## CTAP-HID Handler

### Constructor

```go
func NewCTAPHIDHandler(auth *Authenticator) *CTAPHIDHandler
```

### Methods

#### HandleMessage

Processes a single HID packet.

```go
func (h *CTAPHIDHandler) HandleMessage(packet []byte)
```

#### SetResponseHandler

Sets callback for response packets.

```go
func (h *CTAPHIDHandler) SetResponseHandler(handler func([]byte))
```

#### Close

Closes the HID handler.

```go
func (h *CTAPHIDHandler) Close() error
```

---

## Cryptographic Functions

### GenerateCredentialKey

```go
func GenerateCredentialKey(algorithm int) (crypto.PrivateKey, []byte, error)
```

**Parameters:**
- `algorithm` - COSE algorithm ID

**Returns:**
- `crypto.PrivateKey` - Generated private key
- `[]byte` - CBOR-encoded COSE public key
- `error` - Generation errors

### EncodeCOSEPublicKey

```go
func EncodeCOSEPublicKey(pub crypto.PublicKey, algorithm int) ([]byte, error)
```

### DecodeCOSEPublicKey

```go
func DecodeCOSEPublicKey(data []byte) (crypto.PublicKey, int, error)
```

**Returns:**
- `crypto.PublicKey` - Decoded public key
- `int` - Algorithm ID
- `error` - Decoding errors

### Sign

```go
func Sign(key crypto.PrivateKey, algorithm int, data []byte) ([]byte, error)
```

### GenerateCredentialID

```go
func GenerateCredentialID() ([]byte, error)
```

**Returns:**
- `[]byte` - 32-byte random credential ID

### GenerateHMACSecretKey

```go
func GenerateHMACSecretKey() ([]byte, error)
```

**Returns:**
- `[]byte` - 32-byte random HMAC key

### AlgorithmName

```go
func AlgorithmName(algorithm int) string
```

---

## Constants

### COSE Algorithms

```go
const (
    COSEAlgES256 = -7   // ECDSA w/ SHA-256 on P-256
    COSEAlgES384 = -35  // ECDSA w/ SHA-384 on P-384
    COSEAlgES512 = -36  // ECDSA w/ SHA-512 on P-521
    COSEAlgEdDSA = -8   // EdDSA (Ed25519)
)
```

### CTAP2 Commands

```go
const (
    CmdMakeCredential        = 0x01
    CmdGetAssertion          = 0x02
    CmdGetInfo               = 0x04
    CmdClientPIN             = 0x06
    CmdReset                 = 0x07
    CmdGetNextAssertion      = 0x08
    CmdCredentialManagement  = 0x0A
    CmdSelection             = 0x0B
)
```

### CTAP2 Status Codes

```go
const (
    StatusOK                 = 0x00
    StatusInvalidCommand     = 0x01
    StatusInvalidParameter   = 0x02
    StatusInvalidLength      = 0x03
    StatusInvalidSeq         = 0x04
    StatusTimeout            = 0x05
    StatusChannelBusy        = 0x06
    StatusPINInvalid         = 0x31
    StatusPINBlocked         = 0x32
    StatusPINAuthInvalid     = 0x33
    StatusNoCredentials      = 0x2E
    StatusOperationDenied    = 0x27
    StatusCredentialExcluded = 0x19
)
```

### Authenticator Data Flags

```go
const (
    FlagUP = 0x01 // User Present
    FlagUV = 0x04 // User Verified
    FlagAT = 0x40 // Attested Credential Data
    FlagED = 0x80 // Extension Data
)
```

### PIN Protocol

```go
const (
    PINProtocol1          = 1
    PINMinLength          = 4
    PINHashSize           = 16
    PINTokenSize          = 32
)
```

---

## Errors

### Core Errors (errors.go)

```go
var (
    ErrInvalidCommand            = errors.New("authenticator: invalid command")
    ErrInvalidParameter          = errors.New("authenticator: invalid parameter")
    ErrCredentialNotFound        = errors.New("authenticator: credential not found")
    ErrOperationDenied           = errors.New("authenticator: operation denied")
    ErrPINRequired               = errors.New("authenticator: PIN required")
    ErrPINInvalid                = errors.New("authenticator: PIN invalid")
    ErrPINBlocked                = errors.New("authenticator: PIN blocked")
    ErrPINAuthInvalid            = errors.New("authenticator: PIN auth invalid")
    ErrPINPolicyViolation        = errors.New("authenticator: PIN policy violation")
    ErrNoCredentials             = errors.New("authenticator: no credentials")
    ErrUnsupportedExtension      = errors.New("authenticator: unsupported extension")
    ErrUserPresenceRequired      = errors.New("authenticator: user presence required")
    ErrUserVerificationRequired  = errors.New("authenticator: user verification required")
    ErrStorageError              = errors.New("authenticator: storage error")
    ErrCryptoError               = errors.New("authenticator: crypto error")
    ErrInvalidRPID               = errors.New("authenticator: invalid relying party ID")
    ErrCredentialExcluded        = errors.New("authenticator: credential excluded")
)
```

### Configuration Errors (config.go)

```go
var (
    ErrNilConfig               = errors.New("authenticator: config is nil")
    ErrInvalidAAGUID           = errors.New("authenticator: AAGUID must be exactly 16 bytes")
    ErrNoAlgorithms            = errors.New("authenticator: at least one algorithm must be supported")
    ErrUnsupportedAlgorithm    = errors.New("authenticator: unsupported algorithm specified")
    ErrInvalidMaxCredentials   = errors.New("authenticator: max credentials must be positive")
    ErrInvalidMaxResidentCreds = errors.New("authenticator: max resident credentials must be positive and not exceed max credentials")
    ErrInvalidPINMinLength     = errors.New("authenticator: PIN min length must be at least 4")
    ErrInvalidPINMaxRetries    = errors.New("authenticator: PIN max retries must be positive")
    ErrNilStorage              = errors.New("authenticator: storage backend is required")
)
```

### Lifecycle Errors (authenticator.go)

```go
var (
    ErrAuthenticatorClosed = errors.New("authenticator: authenticator closed")
)
```

### User Presence Errors (user_presence.go)

```go
var (
    ErrUserPresenceDenied     = errors.New("authenticator: user presence denied")
    ErrUserPresenceTimeout    = errors.New("authenticator: user presence timeout")
    ErrUserVerificationDenied = errors.New("authenticator: user verification denied")
    ErrTerminalUnavailable    = errors.New("authenticator: terminal unavailable")
    ErrInvalidPIN             = errors.New("authenticator: invalid PIN")
)
```

### Key Backend Errors (keybackend/errors.go)

```go
var (
    ErrKeyNotFound             = errors.New("keybackend: key not found")
    ErrUnsupportedAlgorithm    = errors.New("keybackend: unsupported algorithm")
    ErrExportNotSupported      = errors.New("keybackend: export not supported")
    ErrImportNotSupported      = errors.New("keybackend: import not supported")
    ErrInvalidKeyHandle        = errors.New("keybackend: invalid key handle")
    ErrKeyGenerationFailed     = errors.New("keybackend: key generation failed")
    ErrSigningFailed           = errors.New("keybackend: signing failed")
    ErrAttestationNotSupported = errors.New("keybackend: attestation not supported")
    ErrBackendClosed           = errors.New("keybackend: backend closed")
    ErrInvalidCredentialID     = errors.New("keybackend: invalid credential ID")
    ErrInvalidPKCS8Key         = errors.New("keybackend: invalid PKCS#8 key")
)
```
