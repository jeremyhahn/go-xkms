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
    PINMaxLength   int
    PINMaxRetries  int

    // Feature Flags
    EnablePIN                  bool
    EnableResidentKey          bool
    EnableCredentialManagement bool
    EnableHMACSecret           bool

    // Transport Hints
    Transports []string

    // Storage Backend
    Storage StatefulCredentialStorage
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
| Default | Random UUID (generated) |
| Required | No (generated if zero) |

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
| Default | [ES256, EdDSA] |
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

#### PINMaxLength

Maximum allowed PIN length in characters.

```go
config.PINMaxLength = 63
```

| Property | Value |
|----------|-------|
| Type | int |
| Default | 63 |
| Minimum | PINMinLength |
| Maximum | 63 (CTAP2 spec) |
| Required | No |

#### PINMaxRetries

Number of consecutive failed PIN attempts before lockout.

```go
config.PINMaxRetries = 8
```

| Property | Value |
|----------|-------|
| Type | int |
| Default | 8 |
| Minimum | 3 |
| Maximum | 255 |
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
- Critical for go-keychain key derivation
- Advertised in GetInfo extensions

### Transport Hints

#### Transports

Transport types to report in attestation.

```go
config.Transports = []string{"internal"}
```

| Property | Value |
|----------|-------|
| Type | []string |
| Default | ["internal"] |
| Required | No |

**Valid Values:**

| Transport | Description |
|-----------|-------------|
| "internal" | Platform authenticator |
| "usb" | USB roaming authenticator |
| "nfc" | NFC roaming authenticator |
| "ble" | Bluetooth Low Energy |
| "hybrid" | caBLE (cross-device) |

### Storage Backend

#### Storage

The credential storage implementation.

```go
config.Storage = authenticator.NewMemoryStorage()
```

| Property | Value |
|----------|-------|
| Type | StatefulCredentialStorage |
| Default | nil (required) |
| Required | Yes |

**Built-in Implementations:**

1. **MemoryStorage** - In-memory, ephemeral
2. **BackendStorage** - Persistent via go-keychain backends

## Default Configuration

```go
func DefaultConfig() *Config {
    return &Config{
        AAGUID: generateRandomAAGUID(),
        SupportedAlgorithms: []int{
            COSEAlgES256,
            COSEAlgEdDSA,
        },
        MaxCredentials:             100,
        MaxResidentCredentials:     25,
        PINMinLength:               4,
        PINMaxLength:               63,
        PINMaxRetries:              8,
        EnablePIN:                  true,
        EnableResidentKey:          true,
        EnableCredentialManagement: true,
        EnableHMACSecret:           true,
        Transports:                 []string{"internal"},
    }
}
```

## Configuration Validation

The `Validate()` method checks configuration consistency:

```go
func (c *Config) Validate() error {
    // Storage required
    if c.Storage == nil {
        return ErrStorageRequired
    }

    // At least one algorithm
    if len(c.SupportedAlgorithms) == 0 {
        return ErrNoAlgorithms
    }

    // PIN constraints
    if c.PINMinLength < 4 || c.PINMinLength > 63 {
        return ErrInvalidPINLength
    }
    if c.PINMaxLength < c.PINMinLength || c.PINMaxLength > 63 {
        return ErrInvalidPINLength
    }
    if c.PINMaxRetries < 3 {
        return ErrInvalidRetries
    }

    // Credential limits
    if c.MaxCredentials < 1 {
        return ErrInvalidMaxCredentials
    }
    if c.MaxResidentCredentials > c.MaxCredentials {
        return ErrInvalidMaxResidentCredentials
    }

    // Feature dependencies
    if c.EnableCredentialManagement && !c.EnablePIN {
        return ErrCredMgmtRequiresPIN
    }
    if c.EnableCredentialManagement && !c.EnableResidentKey {
        return ErrCredMgmtRequiresResidentKey
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
  "transports": ["internal"],
  "algorithms": [
    {"type": "public-key", "alg": -7},
    {"type": "public-key", "alg": -8}
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
    Storage:                authenticator.NewMemoryStorage(),
}
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
