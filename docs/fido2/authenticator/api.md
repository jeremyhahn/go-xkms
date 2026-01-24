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
    PINMaxLength               int
    PINMaxRetries              int
    EnablePIN                  bool
    EnableResidentKey          bool
    EnableCredentialManagement bool
    EnableHMACSecret           bool
    Transports                 []string
    Storage                    StatefulCredentialStorage
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

### Storage Errors

```go
var (
    ErrStorageError       = errors.New("authenticator: storage error")
    ErrStorageClosed      = errors.New("authenticator: storage closed")
    ErrCredentialNotFound = errors.New("authenticator: credential not found")
    ErrStateNotFound      = errors.New("authenticator: state not found")
    ErrInvalidCredentialID = errors.New("authenticator: invalid credential ID")
)
```

### Cryptographic Errors

```go
var (
    ErrCryptoError                = errors.New("authenticator: cryptographic error")
    ErrUnsupportedCryptoAlgorithm = errors.New("authenticator: unsupported algorithm")
    ErrInvalidPublicKey           = errors.New("authenticator: invalid public key")
    ErrInvalidPrivateKey          = errors.New("authenticator: invalid private key")
    ErrKeyGenerationFailed        = errors.New("authenticator: key generation failed")
    ErrSigningFailed              = errors.New("authenticator: signing failed")
)
```

### Protocol Errors

```go
var (
    ErrInvalidParameter    = errors.New("authenticator: invalid parameter")
    ErrInvalidCommand      = errors.New("authenticator: invalid command")
    ErrCBOREncodingFailed  = errors.New("authenticator: CBOR encoding failed")
    ErrCBORDecodingFailed  = errors.New("authenticator: CBOR decoding failed")
    ErrNotImplemented      = errors.New("authenticator: not implemented")
)
```

### Credential Errors

```go
var (
    ErrNoCredentials               = errors.New("authenticator: no credentials")
    ErrCredentialExcluded          = errors.New("authenticator: credential excluded")
    ErrResidentKeyLimitReached     = errors.New("authenticator: resident key limit")
    ErrNoMatchingAlgorithm         = errors.New("authenticator: no matching algorithm")
)
```

### PIN Errors

```go
var (
    ErrPINNotSet          = errors.New("authenticator: PIN not set")
    ErrPINInvalid         = errors.New("authenticator: PIN invalid")
    ErrPINBlocked         = errors.New("authenticator: PIN blocked")
    ErrPINAuthInvalid     = errors.New("authenticator: PIN auth invalid")
    ErrPINPolicyViolation = errors.New("authenticator: PIN policy violation")
    ErrPINRequired        = errors.New("authenticator: PIN required")
)
```

### Lifecycle Errors

```go
var (
    ErrAuthenticatorClosed = errors.New("authenticator: closed")
    ErrOperationDenied     = errors.New("authenticator: operation denied")
)
```
