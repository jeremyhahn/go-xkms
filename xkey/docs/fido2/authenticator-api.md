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
- `error` - ErrNilConfig, ErrNilStorage, ErrNoAlgorithms,
  ErrUserPresenceHandlerRequired, other validation errors

`Config.UserPresenceHandler` is required. There is no default: auto-granting
would fabricate a passing verification and denying everything would silently
disable the authenticator, so the caller states its user-presence policy
explicitly. A nil handler fails construction with
`ErrUserPresenceHandlerRequired`.

**Example:**
```go
config := authenticator.DefaultConfig()
config.Storage = authenticator.NewMemoryStorage()

// Required: state the user-presence policy explicitly. Use an interactive
// handler for attended use; NewAutoGrantHandler() only where unattended
// auto-approval is a deliberate, understood choice.
handler, err := authenticator.NewInteractiveHandler()
if err != nil {
    log.Fatal(err)
}
config.UserPresenceHandler = handler

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

`ProcessCBORWithContext` is the cancellable variant; the context is propagated
to user presence requests so external cancellation (e.g. CTAPHID_CANCEL) can
abort a blocking operation:

```go
func (a *Authenticator) ProcessCBORWithContext(ctx context.Context, cmd byte, data []byte) ([]byte, error)
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
| CmdBioEnrollment | 0x09 | Yes |
| CmdLargeBlobs | 0x0C | Yes |
| CmdConfig | 0x0D | Yes |

**ClientPIN (0x06) subcommand notes:**
- `getPinToken` (0x05) rejects the `permissions` (0x09) and `rpId` (0x0A)
  parameters with `CTAP1_ERR_INVALID_PARAMETER`, per CTAP 2.1 §6.5.5.7.1. The
  token it issues always carries the default `mc` and `ga` permissions and no
  permissions RP ID, so accepting either parameter would let a platform believe
  it had requested a scope the authenticator ignored. Use
  `getPinUvAuthTokenUsingPinWithPermissions` (0x09) to request a scope.

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
- Saves final state, then closes the key backend if one is configured
- Does NOT close the underlying storage — the storage lifecycle is owned by
  the caller
- Idempotent; subsequent `ProcessCBOR` calls return `ErrAuthenticatorClosed`

#### AAGUID

Returns the authenticator's AAGUID.

```go
func (a *Authenticator) AAGUID() [16]byte
```

#### ClearAssertionState

Clears stored assertion session state.

```go
func (a *Authenticator) ClearAssertionState()
```

**Notes:**
- Called automatically after assertion timeout
- Clears GetNextAssertion context

#### VerifyPinUvAuthToken

Verifies the PIN auth parameter against the current pinUvAuthToken and confirms
the token is still within its CTAP 2.1 §6.5.2.1 usage timers. It says nothing
about permissions or the permissions RP ID.

```go
func (a *Authenticator) VerifyPinUvAuthToken(clientDataHash, authParam []byte) bool
```

#### AuthorizePinUvAuthToken

Authorizes one makeCredential or getAssertion request. It checks the token's
lifetime, the HMAC, the required permission bit, the permissions RP ID, and the
token's `userVerified` flag, binding the request's RP ID to the token on first
use. Every failure returns `ErrPINAuthInvalid` (`CTAP2_ERR_PIN_AUTH_INVALID`),
so a caller cannot tell a wrong HMAC from a missing permission, an RP ID
mismatch, or a cleared flag.

The `userVerified` check is what makes a token stop authorizing further
credential operations. Once an operation sets the `up` bit in its response, the
authenticator clears that flag and every permission except `lbw`, per CTAP 2.1
§6.1.2 step 14 and §6.2.2 — so the next `AuthorizePinUvAuthToken` for `mc` or
`ga` fails until the platform obtains a fresh token. The token is not
invalidated: `lbw` deliberately survives. A getAssertion with `up=false` sets no
`up` bit and clears nothing.

Commands that require a permission must use this rather than
`VerifyPinUvAuthToken`.

```go
func (a *Authenticator) AuthorizePinUvAuthToken(
    clientDataHash, authParam []byte, permission uint8, rpID string) error
```

#### CanAuthorizePinUvAuthToken

Reports whether `AuthorizePinUvAuthToken` would succeed, running the same five
checks without mutating anything: it binds no permissions RP ID, refreshes no
timer, and discards no expired token.

getAssertion uses it to decide whether a request counts as user-verified
*before* it selects credentials, because CTAP 2.1 §12.1 credProtect filtering
and excludeList answers depend on that answer. Because it shares the check with
the authoritative call, it also reports a token whose `userVerified` flag has
been cleared as unauthorized — a cleared token cannot unlock a credProtect
credential or answer an excludeList.

```go
func (a *Authenticator) CanAuthorizePinUvAuthToken(
    clientDataHash, authParam []byte, permission uint8, rpID string) error
```

#### SetUserPresenceHandler

Replaces the user presence handler and returns the handler it replaced, so a
service that installs a handler for its own lifetime can restore the previous
one instead of forcing a default on an authenticator it shares with other
consumers. Safe to call while a command is in flight.

```go
func (a *Authenticator) SetUserPresenceHandler(handler UserPresenceHandler) UserPresenceHandler
```

#### UserPresenceHandler

Returns the handler currently collecting user presence.

```go
func (a *Authenticator) UserPresenceHandler() UserPresenceHandler
```

#### SetInitialPIN

Establishes the authenticator's PIN when none is set. It is the in-process
counterpart of the CTAP `ClientPIN` `setPIN` subcommand for a caller that
already holds the operator's authority — the `xkey fido2 --set-pin` seeding
and a first-run wizard — and it is a production API, not a test hook.

```go
func (a *Authenticator) SetInitialPIN(pin string) error
```

**Parameters:**
- `pin` - Plain text PIN

**Returns:**
- `error` - `ErrPINAlreadySet` if a PIN exists; `ErrPINPolicyViolation` if
  shorter than `Config.PINMinLength`; `ErrStorageError` (with the backend's
  cause joined) if the new state could not be persisted

**Contract:**
- Runs the same establishment path as `setPIN`: minimum length enforced,
  retry counter reset to `Config.PINMaxRetries`, any outstanding
  `pinUvAuthToken` invalidated and wiped (CTAP 2.1 §6.5.2.1) before the state
  is persisted.
- Skips only the wire ceremony — ECDH key agreement and the `pinUvAuthParam`
  proof over the encrypted PIN — which exists to authenticate a remote
  platform; an in-process caller is already on the authenticator's side of
  that boundary.
- Never replaces an existing PIN. That is `changePIN`'s job, and it proves the
  current PIN first.

### Testing Methods

#### GetPinUvAuthToken

Returns current PIN token for testing.

```go
func (a *Authenticator) GetPinUvAuthToken() []byte
```

---

## Types

### Config

```go
type Config struct {
    AAGUID                      [16]byte
    SupportedAlgorithms         []int
    MaxCredentials              int
    MaxResidentCredentials      int
    PINMinLength                int
    PINMaxRetries               int
    EnablePIN                   bool
    EnableResidentKey           bool
    EnableCredentialManagement  bool
    EnableHMACSecret            bool
    AlwaysUV                    bool
    UserPresenceHandler         UserPresenceHandler // Required; nil fails NewAuthenticator
    TokenInitWindow             time.Duration       // TOFU window for SO PIN init (0 = default)
    UserPresenceTimeout         time.Duration
    RequireUserPresence         bool
    EnableUserIntentCheck       bool
    KeyBackend                  keybackend.FIDO2KeyBackend
    AttestationFormat           string // "none", "packed", "tpm"
    Storage                     CredentialStorage // Required
    Logger                      *slog.Logger
    OnCredentialCreated         func(cred *StoredCredential)
    OnAssertionCompleted        func(rpID string)
    UnifiedPIN                  bool
    PolicyIntegrityProvider     PolicyIntegrityProvider
    RPPolicyStore               RPPolicyStore
    Transports                  []string // GetInfo transports, default ["usb"]
    EnableEnterpriseAttestation bool
    EnableLargeBlobs            bool
    FirmwareVersion             uint32
}
```

`UserPresenceHandler` and `Storage` are required. `DefaultConfig()` sets
neither: construction fails with `ErrUserPresenceHandlerRequired` or
`ErrNilStorage` until the caller supplies them.

#### Methods

```go
func DefaultConfig() *Config
func (c *Config) SetDefaults()
func (c *Config) Validate() error
func (c *Config) SupportsAlgorithm(algorithm int) bool
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

    RPUVPolicy          string // RP userVerification requirement at creation
    RPUPPolicy          bool   // whether the RP required user presence at creation
    RPResidentKeyPolicy string // RP resident-key requirement at creation
    RPAttestationPref   string // RP attestation preference at creation
    BackendID           xkms.BackendType // key backend owning the private key
}
```

### AuthenticatorState

```go
type AuthenticatorState struct {
    AAGUID               [16]byte
    PINHash              []byte // the PIN itself is never stored
    PINSet               bool
    AttestationCert      []byte   // DER-encoded attestation leaf certificate
    AttestationCertChain [][]byte // DER intermediates, leaf-to-root, root excluded

    // SO PIN protection
    SOPINManager       *SOPINManager
    WrappedAK          []byte // Admin Key wrapped with the SO PIN-derived SMK
    WrappedCMKUser     []byte // Credential Master Key wrapped with the user PIN-derived UMK
    WrappedCMKSO       []byte // Credential Master Key wrapped with the Admin Key
    WrappedAttestUser  []byte // attestation key wrapped with the CMK
    WrappedAttestSO    []byte // attestation key wrapped with the Admin Key
    AttestedConfigHash []byte
    PINSyncPending     bool

    // Policy HMAC integrity
    PolicyHMACTag      []byte
    SignedPolicyFields *PolicyFields
}
```

The device attestation signing key is deliberately absent: it is held only as
the AES-GCM wrapped copies above and unwrapped into protected memory for the
duration of each signature.

#### Methods

```go
func NewAuthenticatorState() *AuthenticatorState
func (s *AuthenticatorState) PINRetries() int
func (s *AuthenticatorState) SetPINRetries(retries int)
func (s *AuthenticatorState) DecrementPINRetries() int
func (s *AuthenticatorState) ResetPINRetries()
func (s *AuthenticatorState) UVRetries() int
func (s *AuthenticatorState) SetUVRetries(retries int)
func (s *AuthenticatorState) DecrementUVRetries() int
func (s *AuthenticatorState) ResetUVRetries()
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

Automatically approves all user presence and verification requests. Never
installed by default: `NewAuthenticator` fails with
`ErrUserPresenceHandlerRequired` when `Config.UserPresenceHandler` is nil, so
unattended auto-approval only happens where a caller asked for it explicitly.

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
    CmdMakeCredential       = 0x01
    CmdGetAssertion         = 0x02
    CmdGetInfo              = 0x04
    CmdClientPIN            = 0x06
    CmdReset                = 0x07
    CmdGetNextAssertion     = 0x08
    CmdBioEnrollment        = 0x09
    CmdCredentialManagement = 0x0A
    CmdSelection            = 0x0B
    CmdLargeBlobs           = 0x0C
    CmdConfig               = 0x0D
)
```

### CTAP2 Status Codes

```go
const (
    StatusOK                   = 0x00
    StatusInvalidCommand       = 0x01
    StatusInvalidParameter     = 0x02
    StatusInvalidLength        = 0x03
    StatusInvalidSeq           = 0x04
    StatusTimeout              = 0x05
    StatusChannelBusy          = 0x06
    StatusLockRequired         = 0x0A
    StatusInvalidChannel       = 0x0B
    StatusCBORUnexpectedType   = 0x11
    StatusInvalidCBOR          = 0x12
    StatusMissingParameter     = 0x14
    StatusLimitExceeded        = 0x15
    StatusUnsupportedExtension = 0x16
    StatusFPDatabaseFull       = 0x17
    StatusLargeBlobStorageFull = 0x18
    StatusCredentialExcluded   = 0x19
    StatusProcessing           = 0x21
    StatusInvalidCredential    = 0x22
    StatusUserActionPending    = 0x23
    StatusOperationPending     = 0x24
    StatusNoOperations         = 0x25
    StatusUnsupportedAlgorithm = 0x26
    StatusOperationDenied      = 0x27
    StatusKeyStoreFull         = 0x28
    StatusNotBusy              = 0x29
    StatusNoOperationPending   = 0x2A
    StatusUnsupportedOption    = 0x2B
    StatusInvalidOption        = 0x2C
    StatusKeepaliveCancel      = 0x2D
    StatusNoCredentials        = 0x2E
    StatusUserActionTimeout    = 0x2F
    StatusNotAllowed           = 0x30
    StatusPINInvalid           = 0x31
    StatusPINBlocked           = 0x32
    StatusPINAuthInvalid       = 0x33
    StatusPINAuthBlocked       = 0x34
    StatusPINNotSet            = 0x35
    StatusPINRequired          = 0x36
    StatusPINPolicyViolation   = 0x37
    StatusPINTokenExpired      = 0x38
    StatusRequestTooLarge      = 0x39
    StatusActionTimeout        = 0x3A
    StatusUPRequired           = 0x3B
    StatusUVBlocked            = 0x3C
    StatusIntegrityFailure     = 0x3D
    StatusInvalidSubcommand    = 0x3E
    StatusUVInvalid            = 0x3F
    StatusOtherError           = 0x7F
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
    PINProtocol2          = 2
    PINMinLength          = 4
    PINHashSize           = 16
    PINAuthSizeV1         = 16
    PINAuthSizeV2         = 32
    PINTokenSize          = 32
    AESBlockSize          = 16
    EncryptedPINMinLength = 64
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
    ErrPINAlreadySet             = errors.New("authenticator: PIN already set")
    ErrNoCredentials             = errors.New("authenticator: no credentials")
    ErrUnsupportedExtension      = errors.New("authenticator: unsupported extension")
    ErrUserPresenceRequired      = errors.New("authenticator: user presence required")
    ErrUserVerificationRequired  = errors.New("authenticator: user verification required")
    ErrUVBlocked                 = errors.New("authenticator: UV blocked")
    ErrStorageError              = errors.New("authenticator: storage error")
    ErrCryptoError               = errors.New("authenticator: crypto error")
    ErrInvalidRPID               = errors.New("authenticator: invalid relying party ID")
    ErrCredentialExcluded        = errors.New("authenticator: credential excluded")

    ErrAttestationOverrideUnsupported   = errors.New("authenticator: attestation override cannot be honoured")
    ErrAttestationUnavailable           = errors.New("authenticator: attestation statement unavailable")
    ErrEnterpriseAttestationNotEntitled = errors.New("authenticator: enterprise attestation not entitled for this RP")
    ErrPolicyTamperLocked               = errors.New("authenticator: policy tamper detected, user operations locked until the SO re-signs the policy")
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
    ErrCBOREncodingFailed  = errors.New("authenticator: CBOR encoding failed")
    ErrCBORDecodingFailed  = errors.New("authenticator: CBOR decoding failed")
    ErrNotImplemented      = errors.New("authenticator: command not implemented")
    ErrLimitExceeded       = errors.New("authenticator: limit exceeded")
)
```

### User Presence Errors (user_presence.go)

```go
var (
    ErrUserPresenceHandlerRequired = errors.New("authenticator: config.UserPresenceHandler is required")

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
