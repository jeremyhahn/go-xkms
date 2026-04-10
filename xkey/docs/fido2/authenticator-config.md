# Authenticator Configuration

This document describes all configuration options for the native FIDO2 authenticator.

## Configuration Structure

```go
type Config struct {
    // Identity
    AAGUID              [16]byte

    // Algorithm Support
    SupportedAlgorithms []int

    // Capacity Limits
    MaxCredentials          int
    MaxResidentCredentials  int

    // PIN Settings
    PINMinLength   int
    PINMaxRetries  int

    // Feature Flags
    EnablePIN                  bool
    EnableResidentKey          bool
    EnableCredentialManagement bool
    EnableHMACSecret           bool

    // User Presence
    UserPresenceHandler UserPresenceHandler
    UserPresenceTimeout time.Duration

    // Key Backend
    KeyBackend keybackend.FIDO2KeyBackend

    // Attestation
    AttestationFormat string

    // Storage Backend
    Storage CredentialStorage
}
```

## Configuration Options

### Identity

#### AAGUID

The Authenticator Attestation GUID uniquely identifies the authenticator model.

```go
config.AAGUID = [16]byte{
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
}
```

| Property | Value |
|----------|-------|
| Type | [16]byte |
| Default | DefaultAAGUID (ASCII "go-xkms" + padding + v1) |
| Required | No (DefaultAAGUID used if zero) |

**Notes:**
- Production authenticators should use a registered AAGUID
- The AAGUID is included in attestation statements
- Zero AAGUID is acceptable for testing

### Algorithm Support

#### SupportedAlgorithms

List of COSE algorithm identifiers the authenticator supports.

```go
config.SupportedAlgorithms = []int{
    authenticator.COSEAlgES256,  // -7
    authenticator.COSEAlgES384,  // -35
    authenticator.COSEAlgES512,  // -36
    authenticator.COSEAlgEdDSA,  // -8
}
```

| Property | Value |
|----------|-------|
| Type | []int |
| Default | [ES256] |
| Required | No |

**Supported Algorithms:**

| Algorithm | COSE ID | Curve | Hash |
|-----------|---------|-------|------|
| ES256 | -7 | P-256 | SHA-256 |
| ES384 | -35 | P-384 | SHA-384 |
| ES512 | -36 | P-521 | SHA-512 |
| EdDSA | -8 | Ed25519 | (intrinsic) |

**Notes:**
- Order determines preference when multiple algorithms are acceptable
- At least one algorithm must be configured
- RS256 is defined but not implemented

### Capacity Limits

#### MaxCredentials

Maximum total number of credentials the authenticator can store.

```go
config.MaxCredentials = 100
```

| Property | Value |
|----------|-------|
| Type | int |
| Default | 100 |
| Minimum | 1 |
| Required | No |

**Notes:**
- Applies to both discoverable and non-discoverable credentials
- MakeCredential returns error when limit reached

#### MaxResidentCredentials

Maximum number of discoverable (resident) credentials.

```go
config.MaxResidentCredentials = 25
```

| Property | Value |
|----------|-------|
| Type | int |
| Default | 25 |
| Minimum | 1 |
| Maximum | MaxCredentials |
| Required | No |

**Notes:**
- Discoverable credentials are stored on the authenticator
- Required for usernameless authentication
- Reported in GetInfo response

### PIN Settings

#### PINMinLength

Minimum required PIN length in characters.

```go
config.PINMinLength = 4
```

| Property | Value |
|----------|-------|
| Type | int |
| Default | 4 |
| Minimum | 4 (CTAP2 spec) |
| Maximum | 63 |
| Required | No |

**Notes:**
- CTAP2 requires minimum of 4 characters
- Longer PINs recommended for security

#### PINMaxRetries

Number of consecutive failed PIN attempts before lockout.

```go
config.PINMaxRetries = 8
```

| Property | Value |
|----------|-------|
| Type | int |
| Default | 8 |
| Minimum | 1 |
| Required | No |

**Notes:**
- Counter resets on successful PIN verification
- Authenticator blocks when retries exhausted
- Requires factory reset to recover from lockout

### Feature Flags

#### EnablePIN

Enables PIN protocol and ClientPIN command.

```go
config.EnablePIN = true
```

| Property | Value |
|----------|-------|
| Type | bool |
| Default | true |
| Required | No |

**Notes:**
- Required for user verification via PIN
- Advertised in GetInfo options

#### EnableResidentKey

Enables discoverable credential (resident key) creation.

```go
config.EnableResidentKey = true
```

| Property | Value |
|----------|-------|
| Type | bool |
| Default | true |
| Required | No |

**Notes:**
- Required for usernameless authentication
- Required for credential management
- Advertised in GetInfo options as "rk"

#### EnableCredentialManagement

Enables CTAP2.1 credential management commands.

```go
config.EnableCredentialManagement = true
```

| Property | Value |
|----------|-------|
| Type | bool |
| Default | true |
| Required | No |

**Notes:**
- Requires EnablePIN = true
- Requires EnableResidentKey = true
- Allows enumeration and deletion of credentials
- Advertised in GetInfo extensions as "credentialMgmtPreview"

#### EnableHMACSecret

Enables hmac-secret extension for key derivation.

```go
config.EnableHMACSecret = true
```

| Property | Value |
|----------|-------|
| Type | bool |
| Default | true |
| Required | No |

**Notes:**
- Creates 32-byte HMAC key per credential
- Enables symmetric secret derivation during GetAssertion
- Critical for go-xkms key derivation
- Advertised in GetInfo extensions

### User Presence

#### UserPresenceHandler

The handler for user presence and verification requests.

```go
config.UserPresenceHandler = authenticator.NewAutoGrantHandler()
```

| Property | Value |
|----------|-------|
| Type | UserPresenceHandler |
| Default | nil (AutoGrantHandler created internally) |
| Required | No |

**Built-in Implementations:**

| Handler | Description |
|---------|-------------|
| AutoGrantHandler | Automatically approves all UP/UV requests (default) |
| InteractiveHandler | Terminal-based prompts requiring user input |

**Notes:**
- When nil, an `AutoGrantHandler` is created internally
- `AutoGrantHandler` supports optional simulated PIN via `NewAutoGrantHandlerWithPIN(pin)`
- `InteractiveHandler` requires a terminal (returns `ErrTerminalUnavailable` if unavailable)

#### UserPresenceTimeout

Timeout for user presence and verification requests.

```go
config.UserPresenceTimeout = 30 * time.Second
```

| Property | Value |
|----------|-------|
| Type | time.Duration |
| Default | 30 seconds |
| Required | No |

**Notes:**
- Only meaningful when using InteractiveHandler
- AutoGrantHandler responds immediately regardless of timeout

### Key Backend

#### KeyBackend

The pluggable key backend for credential key operations.

```go
config.KeyBackend = software.NewSoftwareKeyBackend()
```

| Property | Value |
|----------|-------|
| Type | keybackend.FIDO2KeyBackend |
| Default | nil (legacy crypto.go path) |
| Required | No |

**Built-in Implementations:**

| Backend | Package | Description |
|---------|---------|-------------|
| SoftwareKeyBackend | `keybackend/software` | In-process keys, supports export/import |
| TPM2KeyBackend | `keybackend/tpm2` | Hardware-backed via TPM 2.0 |

**Notes:**
- When nil, the authenticator uses the legacy `crypto.go` path for key operations
- The software backend supports all four algorithms (ES256, ES384, ES512, EdDSA)
- The TPM2 backend supports ES256 and ES384 only
- Hardware-backed keys cannot be exported or imported

### Attestation

#### AttestationFormat

The attestation statement format for credential creation.

```go
config.AttestationFormat = "none"
```

| Property | Value |
|----------|-------|
| Type | string |
| Default | "none" |
| Required | No |

**Valid Values:**

| Format | Description |
|--------|-------------|
| "none" | No attestation statement |
| "packed" | Self-attestation with packed format |
| "tpm" | TPM attestation (requires TPM2 key backend) |

### Storage Backend

#### Storage

The credential storage implementation.

```go
config.Storage = authenticator.NewMemoryStorage()
```

| Property | Value |
|----------|-------|
| Type | CredentialStorage |
| Default | nil (required) |
| Required | Yes |

**Notes:**
- The storage must also implement `StatefulCredentialStorage` at runtime
- Both `MemoryStorage` and `BackendStorage` implement `StatefulCredentialStorage`

**Built-in Implementations:**

1. **MemoryStorage** - In-memory, ephemeral
2. **BackendStorage** - Persistent via go-xkms backends

## Default Configuration

```go
func DefaultConfig() *Config {
    return &Config{
        AAGUID:                     DefaultAAGUID,
        SupportedAlgorithms:        []int{COSEAlgES256},
        MaxCredentials:             100,
        MaxResidentCredentials:     25,
        PINMinLength:               4,
        PINMaxRetries:              8,
        EnablePIN:                  true,
        EnableResidentKey:          true,
        EnableCredentialManagement: true,
        EnableHMACSecret:           true,
        UserPresenceTimeout:        30 * time.Second,
        AttestationFormat:          "none",
        Storage:                    nil, // must be set before use
    }
}
```

## Configuration Validation

The `Validate()` method checks configuration consistency:

```go
func (c *Config) Validate() error {
    if c == nil {
        return ErrNilConfig
    }

    // At least one algorithm, all must be supported
    if len(c.SupportedAlgorithms) == 0 {
        return ErrNoAlgorithms
    }
    for _, alg := range c.SupportedAlgorithms {
        if !isSupportedAlgorithm(alg) {
            return ErrUnsupportedAlgorithm
        }
    }

    // Credential limits
    if c.MaxCredentials <= 0 {
        return ErrInvalidMaxCredentials
    }
    if c.MaxResidentCredentials <= 0 || c.MaxResidentCredentials > c.MaxCredentials {
        return ErrInvalidMaxResidentCreds
    }

    // PIN constraints
    if c.PINMinLength < 4 {
        return ErrInvalidPINMinLength
    }
    if c.PINMaxRetries <= 0 {
        return ErrInvalidPINMaxRetries
    }

    // Storage required
    if c.Storage == nil {
        return ErrNilStorage
    }

    return nil
}
```

## GetInfo Response

Configuration affects the GetInfo response:

```json
{
  "versions": ["FIDO_2_0", "FIDO_2_1_PRE"],
  "extensions": ["hmac-secret", "credentialMgmtPreview"],
  "aaguid": "...",
  "options": {
    "plat": true,
    "rk": true,
    "clientPin": true,
    "credMgmt": true
  },
  "maxMsgSize": 1200,
  "pinUvAuthProtocols": [1],
  "maxCredentialCountInList": 100,
  "maxCredentialIdLength": 128,
  "algorithms": [
    {"type": "public-key", "alg": -7}
  ],
  "maxSerializedLargeBlobArray": 0,
  "remainingDiscoverableCredentials": 25
}
```

## Configuration Examples

### Minimal Configuration

```go
config := &authenticator.Config{
    SupportedAlgorithms: []int{authenticator.COSEAlgES256},
    Storage:             authenticator.NewMemoryStorage(),
}
config.SetDefaults()
```

### High-Security Configuration

```go
config := &authenticator.Config{
    SupportedAlgorithms: []int{
        authenticator.COSEAlgES384, // Higher security curve
    },
    MaxCredentials:         50,
    MaxResidentCredentials: 10,
    PINMinLength:           8,    // Longer minimum PIN
    PINMaxRetries:          3,    // Fewer retry attempts
    EnablePIN:              true,
    EnableResidentKey:      true,
    EnableCredentialManagement: true,
    EnableHMACSecret:       true,
    Storage:                persistentStorage,
}
```

### Testing Configuration

```go
config := &authenticator.Config{
    AAGUID: [16]byte{}, // Zero AAGUID for tests
    SupportedAlgorithms: []int{
        authenticator.COSEAlgES256,
        authenticator.COSEAlgEdDSA,
    },
    MaxCredentials:         1000,
    MaxResidentCredentials: 100,
    PINMinLength:           4,
    PINMaxRetries:          8,
    EnablePIN:              true,
    EnableResidentKey:      true,
    EnableCredentialManagement: true,
    EnableHMACSecret:       true,
    UserPresenceHandler:    authenticator.NewAutoGrantHandlerWithPIN("1234"),
    Storage:                authenticator.NewMemoryStorage(),
}
```

### With Software Key Backend

```go
import "github.com/jeremyhahn/go-xkms/xkey/pkg/fido2/authenticator/keybackend/software"

config := authenticator.DefaultConfig()
config.Storage = authenticator.NewMemoryStorage()
config.KeyBackend = software.NewSoftwareKeyBackend()
```

### With Interactive User Presence

```go
handler, err := authenticator.NewInteractiveHandler()
if err != nil {
    log.Fatal(err) // terminal not available
}

config := authenticator.DefaultConfig()
config.Storage = authenticator.NewMemoryStorage()
config.UserPresenceHandler = handler
config.UserPresenceTimeout = 60 * time.Second
```

### Key Derivation Focus (hmac-secret)

```go
config := &authenticator.Config{
    SupportedAlgorithms: []int{authenticator.COSEAlgES256},
    MaxResidentCredentials: 50, // Focus on resident keys
    EnablePIN:              true,
    EnableResidentKey:      true,
    EnableHMACSecret:       true, // Required for key derivation
    EnableCredentialManagement: true,
    Storage:                persistentStorage,
}
```
