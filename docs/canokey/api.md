# CanoKey Go API

## PIV Backend API

### Creating the Backend

```go
import "github.com/go-keychain/keychain/pkg/backend/canokey"

// Create with config
config := &canokey.Config{
    Library:    "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so",
    PIN:        "123456",
    TokenLabel: "CanoKey PIV",
}

backend, err := canokey.NewBackend(config)
if err != nil {
    log.Fatalf("Failed to create backend: %v", err)
}
defer backend.Close()

// Initialize if needed
if err := backend.Initialize(config.SOPIN, config.PIN); err != nil {
    if err != canokey.ErrAlreadyInitialized {
        log.Fatalf("Failed to initialize: %v", err)
    }
}
```

### Key Generation

```go
// ECDSA P-256
ecdsaAttrs := &types.KeyAttributes{
    CN:           "my-ecdsa-key",
    KeyAlgorithm: x509.ECDSA,
    ECDSAAttributes: &types.ECDSAAttributes{
        Curve: elliptic.P256(),
    },
    PIVSlot: canokey.SlotAuthentication, // 0x9a
}
ecdsaKey, err := backend.GenerateECDSA(ecdsaAttrs)

// RSA 2048
rsaAttrs := &types.KeyAttributes{
    CN:           "my-rsa-key",
    KeyAlgorithm: x509.RSA,
    RSAAttributes: &types.RSAAttributes{
        KeySize: 2048,
    },
    PIVSlot: canokey.SlotSignature, // 0x9c
}
rsaKey, err := backend.GenerateRSA(rsaAttrs)

// Ed25519 (Firmware 3.0+)
ed25519Attrs := &types.KeyAttributes{
    CN:           "my-ed25519-key",
    KeyAlgorithm: x509.Ed25519,
    PIVSlot:      canokey.SlotKeyManagement, // 0x9d
}
ed25519Key, err := backend.GenerateEd25519(ed25519Attrs)
```

### Signing Operations

```go
// Get key as crypto.Signer
key, err := backend.GetKey(attrs)
signer, ok := key.(crypto.Signer)
if !ok {
    log.Fatal("Key does not implement crypto.Signer")
}

// Sign with SHA-256
digest := sha256.Sum256([]byte("message to sign"))
signature, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
if err != nil {
    log.Fatalf("Signing failed: %v", err)
}

// Verify
ecdsaPub := signer.Public().(*ecdsa.PublicKey)
valid := ecdsa.VerifyASN1(ecdsaPub, digest[:], signature)
```

### Certificate Operations

```go
// Create self-signed certificate
template := &x509.Certificate{
    SerialNumber: big.NewInt(1),
    Subject: pkix.Name{
        CommonName:   "My Certificate",
        Organization: []string{"My Org"},
    },
    NotBefore: time.Now(),
    NotAfter:  time.Now().AddDate(1, 0, 0),
    KeyUsage:  x509.KeyUsageDigitalSignature,
}

cert, err := backend.CreateCertificate(attrs, template)

// Store certificate
err = backend.StoreCertificate(attrs, cert)

// Retrieve certificate
storedCert, err := backend.GetCertificate(attrs)
```

### Symmetric Encryption (Envelope)

```go
// Encrypt data using hardware-derived key
plaintext := []byte("sensitive data")
ciphertext, err := backend.Encrypt(attrs, plaintext)

// Decrypt
decrypted, err := backend.Decrypt(attrs, ciphertext)
```

### Sealing Operations

```go
// Seal data (hardware-bound)
sealed, err := backend.Seal(attrs, plaintext)

// Unseal (requires same hardware key)
unsealed, err := backend.Unseal(attrs, sealed)
```

## FIDO2 Handler API

### Creating the Handler

```go
import "github.com/go-keychain/keychain/pkg/fido2"

config := &fido2.Config{
    Timeout:                 30 * time.Second,
    UserPresenceTimeout:     60 * time.Second,
    RetryCount:              3,
    RetryDelay:              100 * time.Millisecond,
    RelyingPartyID:          "example.com",
    RelyingPartyName:        "Example Application",
    RequireUserVerification: false,
    WorkaroundCanoKey:       true,
}

handler, err := fido2.NewHandler(config)
if err != nil {
    log.Fatalf("Failed to create handler: %v", err)
}
defer handler.Close()
```

### Device Enumeration

```go
// List all connected FIDO2 devices
devices, err := handler.ListDevices()
if err != nil {
    log.Fatalf("Failed to list devices: %v", err)
}

for _, device := range devices {
    fmt.Printf("Device: %s\n", device.Path)
    fmt.Printf("  Manufacturer: %s\n", device.Manufacturer)
    fmt.Printf("  Product: %s\n", device.Product)
    fmt.Printf("  Vendor ID: 0x%04X\n", device.VendorID)
    fmt.Printf("  Product ID: 0x%04X\n", device.ProductID)
}

// Wait for device connection
ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
defer cancel()

device, err := handler.WaitForDevice(ctx)
if err != nil {
    log.Fatalf("No device connected: %v", err)
}
```

### Credential Enrollment

```go
enrollConfig := &fido2.EnrollmentConfig{
    RelyingParty: fido2.RelyingParty{
        ID:   "example.com",
        Name: "Example Application",
    },
    User: fido2.User{
        ID:          []byte("user-unique-id"),
        Name:        "alice@example.com",
        DisplayName: "Alice Smith",
    },
    RequireUserVerification: false,
    Timeout:                 60 * time.Second,
}

result, err := handler.EnrollKey(enrollConfig)
if err != nil {
    log.Fatalf("Enrollment failed: %v", err)
}

// Store these for later authentication
credentialID := result.CredentialID  // []byte
salt := result.Salt                  // []byte
publicKey := result.PublicKey        // []byte (CBOR encoded)
aaguid := result.AAGUID              // [16]byte
```

### Authentication & Key Derivation

```go
authConfig := &fido2.AuthenticationConfig{
    RelyingPartyID:          "example.com",
    CredentialID:            credentialID,  // From enrollment
    Salt:                    salt,          // From enrollment
    RequireUserVerification: false,
    Timeout:                 60 * time.Second,
}

authResult, err := handler.UnlockWithKey(authConfig)
if err != nil {
    log.Fatalf("Authentication failed: %v", err)
}

// Derived secret (32 bytes by default)
derivedKey := authResult  // []byte

// Use for encryption, HKDF, etc.
```

### HMAC-Secret Extension

```go
// Direct HMAC-secret usage
hmacExt := fido2.NewHMACSecretExtension(handler.Authenticator())

// Enroll with HMAC-secret
enrollResult, err := hmacExt.EnrollCredential(&fido2.EnrollmentConfig{
    RelyingParty: fido2.RelyingParty{ID: "example.com"},
    User:         fido2.User{ID: []byte("user1"), Name: "user1"},
})

// Derive secret
derivedSecret, err := hmacExt.DeriveSecret(&fido2.AuthenticationConfig{
    CredentialID: enrollResult.CredentialID,
    Salt:         enrollResult.Salt,
})
```

## Error Handling

### PIV Backend Errors

```go
import "github.com/go-keychain/keychain/pkg/backend/canokey"

switch {
case errors.Is(err, canokey.ErrDeviceNotFound):
    // CanoKey not connected
case errors.Is(err, canokey.ErrInvalidPIN):
    // Wrong PIN
case errors.Is(err, canokey.ErrPINLocked):
    // Too many wrong attempts
case errors.Is(err, canokey.ErrSlotOccupied):
    // Key already in slot
case errors.Is(err, canokey.ErrUnsupportedAlgorithm):
    // Firmware doesn't support algorithm
case errors.Is(err, canokey.ErrAlreadyInitialized):
    // Token already initialized
}
```

### FIDO2 Errors

```go
import "github.com/go-keychain/keychain/pkg/fido2"

switch {
case errors.Is(err, fido2.ErrNoDevice):
    // No FIDO2 device found
case errors.Is(err, fido2.ErrDeviceTimeout):
    // User didn't respond in time
case errors.Is(err, fido2.ErrUserCancelled):
    // User cancelled operation
case errors.Is(err, fido2.ErrInvalidCredential):
    // Credential not found
case errors.Is(err, fido2.ErrPINRequired):
    // UV required but not provided
case errors.Is(err, fido2.ErrPINInvalid):
    // Wrong PIN
case errors.Is(err, fido2.ErrPINBlocked):
    // Too many wrong PIN attempts
}
```

## Complete Example

```go
package main

import (
    "context"
    "crypto/sha256"
    "fmt"
    "log"
    "time"

    "github.com/go-keychain/keychain/pkg/backend/canokey"
    "github.com/go-keychain/keychain/pkg/fido2"
)

func main() {
    // === PIV Example ===
    pivConfig := &canokey.Config{
        Library: "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so",
        PIN:     "123456",
    }

    pivBackend, err := canokey.NewBackend(pivConfig)
    if err != nil {
        log.Fatal(err)
    }
    defer pivBackend.Close()

    // Generate signing key
    key, _ := pivBackend.GenerateECDSA(&types.KeyAttributes{
        CN:           "signing-key",
        KeyAlgorithm: x509.ECDSA,
        PIVSlot:      canokey.SlotSignature,
    })

    // Sign something
    signer := key.(crypto.Signer)
    digest := sha256.Sum256([]byte("hello"))
    sig, _ := signer.Sign(nil, digest[:], crypto.SHA256)
    fmt.Printf("Signature: %x\n", sig)

    // === FIDO2 Example ===
    fido2Handler, err := fido2.NewHandler(&fido2.Config{
        RelyingPartyID:    "example.com",
        WorkaroundCanoKey: true,
    })
    if err != nil {
        log.Fatal(err)
    }
    defer fido2Handler.Close()

    // Wait for device
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()

    device, _ := fido2Handler.WaitForDevice(ctx)
    fmt.Printf("Device connected: %s\n", device.Product)

    // Register credential
    result, _ := fido2Handler.EnrollKey(&fido2.EnrollmentConfig{
        RelyingParty: fido2.RelyingParty{ID: "example.com"},
        User:         fido2.User{ID: []byte("user1"), Name: "user1"},
    })
    fmt.Printf("Credential ID: %x\n", result.CredentialID)

    // Authenticate
    derivedKey, _ := fido2Handler.UnlockWithKey(&fido2.AuthenticationConfig{
        CredentialID: result.CredentialID,
        Salt:         result.Salt,
    })
    fmt.Printf("Derived Key: %x\n", derivedKey)
}
```
