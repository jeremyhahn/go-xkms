# Authenticator Usage Guide

This guide provides comprehensive examples for using the native FIDO2 authenticator in various scenarios.

## Creating an Authenticator

### Basic Setup with Memory Storage

```go
package main

import (
    "log"

    "github.com/jeremyhahn/go-xkms/xkey/pkg/fido2/authenticator"
)

func main() {
    // Create in-memory storage (ephemeral)
    storage := authenticator.NewMemoryStorage()

    // Use default configuration
    config := authenticator.DefaultConfig()
    config.Storage = storage

    // Create the authenticator
    auth, err := authenticator.NewAuthenticator(config)
    if err != nil {
        log.Fatal(err)
    }
    defer auth.Close()

    log.Printf("Authenticator ready with AAGUID: %x", auth.AAGUID())
}
```

### Custom Configuration

```go
config := &authenticator.Config{
    AAGUID: [16]byte{
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
    },
    SupportedAlgorithms: []int{
        authenticator.COSEAlgES256,  // P-256
        authenticator.COSEAlgES384,  // P-384
        authenticator.COSEAlgEdDSA,  // Ed25519
    },
    MaxCredentials:             100,
    MaxResidentCredentials:     25,
    PINMinLength:               6,
    PINMaxRetries:              8,
    EnablePIN:                  true,
    EnableResidentKey:          true,
    EnableCredentialManagement: true,
    EnableHMACSecret:           true,
    Storage:                    storage,
}

config.SetDefaults() // Apply defaults for zero values
if err := config.Validate(); err != nil {
    log.Fatal(err)
}

auth, err := authenticator.NewAuthenticator(config)
```

## Registering Credentials

### Basic Registration

```go
import (
    "crypto/sha256"
)

func registerCredential(auth *authenticator.Authenticator) error {
    // Client data hash (would come from browser/client)
    clientData := []byte(`{"type":"webauthn.create","challenge":"..."}`)
    clientDataHash := sha256.Sum256(clientData)

    // Relying party information
    rp := authenticator.RelyingParty{
        ID:   "example.com",
        Name: "Example Corp",
    }

    // User information
    user := authenticator.User{
        ID:          []byte("unique-user-id-123"),
        Name:        "user@example.com",
        DisplayName: "Example User",
    }

    // Acceptable algorithms (client preference order)
    pubKeyParams := []authenticator.PublicKeyCredentialParam{
        {Type: "public-key", Alg: authenticator.COSEAlgES256},
        {Type: "public-key", Alg: authenticator.COSEAlgEdDSA},
    }

    // Create the credential
    resp, err := auth.MakeCredential(
        clientDataHash[:],
        rp,
        user,
        pubKeyParams,
        nil, // no options
    )
    if err != nil {
        return err
    }

    log.Printf("Created credential with format: %s", resp.Fmt)
    log.Printf("Auth data length: %d bytes", len(resp.AuthData))

    return nil
}
```

### Registration with Resident Key (Discoverable Credential)

```go
func registerDiscoverableCredential(auth *authenticator.Authenticator) error {
    clientDataHash := sha256.Sum256([]byte("client-data"))

    rp := authenticator.RelyingParty{
        ID:   "example.com",
        Name: "Example Corp",
    }

    user := authenticator.User{
        ID:          []byte("user-456"),
        Name:        "user@example.com",
        DisplayName: "Example User",
    }

    pubKeyParams := []authenticator.PublicKeyCredentialParam{
        {Type: "public-key", Alg: authenticator.COSEAlgES256},
    }

    // Request a discoverable credential (resident key)
    opts := &authenticator.MakeCredentialOptions{
        Options: map[string]bool{
            "rk": true, // resident key
            "uv": true, // user verification
        },
    }

    resp, err := auth.MakeCredential(
        clientDataHash[:],
        rp,
        user,
        pubKeyParams,
        opts,
    )
    if err != nil {
        return err
    }

    log.Printf("Created discoverable credential")
    return nil
}
```

### Registration with hmac-secret Extension

```go
func registerWithHMACSecret(auth *authenticator.Authenticator) error {
    clientDataHash := sha256.Sum256([]byte("client-data"))

    rp := authenticator.RelyingParty{
        ID:   "example.com",
        Name: "Example Corp",
    }

    user := authenticator.User{
        ID:          []byte("user-789"),
        Name:        "user@example.com",
        DisplayName: "User with hmac-secret",
    }

    pubKeyParams := []authenticator.PublicKeyCredentialParam{
        {Type: "public-key", Alg: authenticator.COSEAlgES256},
    }

    // Request hmac-secret extension
    opts := &authenticator.MakeCredentialOptions{
        Extensions: map[string]interface{}{
            "hmac-secret": true,
        },
        Options: map[string]bool{
            "rk": true, // often used with hmac-secret
        },
    }

    resp, err := auth.MakeCredential(
        clientDataHash[:],
        rp,
        user,
        pubKeyParams,
        opts,
    )
    if err != nil {
        return err
    }

    log.Printf("Created credential with hmac-secret support")
    return nil
}
```

### Registration with Exclude List

```go
func registerWithExcludeList(auth *authenticator.Authenticator, existingCredIDs [][]byte) error {
    clientDataHash := sha256.Sum256([]byte("client-data"))

    rp := authenticator.RelyingParty{
        ID:   "example.com",
        Name: "Example Corp",
    }

    user := authenticator.User{
        ID:          []byte("user-existing"),
        Name:        "user@example.com",
        DisplayName: "Existing User",
    }

    pubKeyParams := []authenticator.PublicKeyCredentialParam{
        {Type: "public-key", Alg: authenticator.COSEAlgES256},
    }

    // Build exclude list from existing credentials
    var excludeList []authenticator.CredentialDescriptor
    for _, credID := range existingCredIDs {
        excludeList = append(excludeList, authenticator.CredentialDescriptor{
            Type: "public-key",
            ID:   credID,
        })
    }

    opts := &authenticator.MakeCredentialOptions{
        ExcludeList: excludeList,
    }

    resp, err := auth.MakeCredential(
        clientDataHash[:],
        rp,
        user,
        pubKeyParams,
        opts,
    )
    if err != nil {
        if errors.Is(err, authenticator.ErrCredentialExcluded) {
            log.Printf("User already has a credential for this RP")
            return nil
        }
        return err
    }

    log.Printf("Created new credential")
    return nil
}
```

## Authenticating (GetAssertion)

### Basic Authentication with AllowList

```go
func authenticate(auth *authenticator.Authenticator, credentialID []byte) error {
    clientData := []byte(`{"type":"webauthn.get","challenge":"..."}`)
    clientDataHash := sha256.Sum256(clientData)

    // Provide the credential ID in the allow list
    allowList := []authenticator.CredentialDescriptor{
        {
            Type: "public-key",
            ID:   credentialID,
        },
    }

    // Build CBOR request
    reqData := map[int]interface{}{
        0x01: "example.com",      // rpId
        0x02: clientDataHash[:],  // clientDataHash
        0x03: allowList,          // allowList
    }

    cborData, _ := cbor.Marshal(reqData)

    // Process through CTAP interface
    response, err := auth.ProcessCBOR(authenticator.CmdGetAssertion, cborData)
    if err != nil {
        return err
    }

    // Parse response (first byte is status)
    if response[0] != authenticator.StatusOK {
        return fmt.Errorf("assertion failed with status: %d", response[0])
    }

    log.Printf("Authentication successful")
    return nil
}
```

### Discoverable Credential Authentication (No AllowList)

```go
func authenticateDiscoverable(auth *authenticator.Authenticator, rpID string) error {
    clientDataHash := sha256.Sum256([]byte("client-data"))

    // No allow list - use discoverable credentials
    reqData := map[int]interface{}{
        0x01: rpID,              // rpId
        0x02: clientDataHash[:], // clientDataHash
        // no allowList - will use resident credentials
    }

    cborData, _ := cbor.Marshal(reqData)

    response, err := auth.ProcessCBOR(authenticator.CmdGetAssertion, cborData)
    if err != nil {
        return err
    }

    if response[0] != authenticator.StatusOK {
        return fmt.Errorf("assertion failed")
    }

    // Parse response to get user info
    var respMap map[int]interface{}
    cbor.Unmarshal(response[1:], &respMap)

    if userInfo, ok := respMap[0x04]; ok {
        log.Printf("Authenticated user: %v", userInfo)
    }

    return nil
}
```

### Authentication with hmac-secret

```go
func authenticateWithHMACSecret(auth *authenticator.Authenticator, credentialID []byte) error {
    // Create platform-side helper for hmac-secret
    helper, err := authenticator.NewHMACSecretPlatformHelper()
    if err != nil {
        return err
    }
    defer helper.Reset()

    // Get platform public key for key agreement
    platformCOSEKey, err := helper.GetCOSEPublicKey()
    if err != nil {
        return err
    }

    // Generate salt (32 bytes)
    salt := make([]byte, 32)
    rand.Read(salt)

    // Note: In a real flow, you would first establish shared secret
    // with the authenticator's key agreement key from GetInfo

    // For this example, we'll show the extension input structure:
    hmacSecretInput := map[interface{}]interface{}{
        0x01: platformCOSEKey,   // keyAgreement
        0x02: encryptedSalt,     // saltEnc (encrypted salt)
        0x03: saltAuth,          // saltAuth (HMAC)
        0x04: 1,                 // pinUvAuthProtocol
    }

    extensions := map[string]interface{}{
        "hmac-secret": hmacSecretInput,
    }

    reqData := map[int]interface{}{
        0x01: "example.com",
        0x02: clientDataHash,
        0x03: []map[string]interface{}{
            {"type": "public-key", "id": credentialID},
        },
        0x04: extensions,
    }

    cborData, _ := cbor.Marshal(reqData)

    response, err := auth.ProcessCBOR(authenticator.CmdGetAssertion, cborData)
    if err != nil {
        return err
    }

    // The hmac-secret output is in the extensions of authData
    // Decrypt with helper.DecryptOutput(encryptedOutput)

    return nil
}
```

## Using with HID Layer

### Virtual USB Device Simulation

```go
func setupVirtualDevice(auth *authenticator.Authenticator) {
    // Create HID handler
    hidHandler := authenticator.NewCTAPHIDHandler(auth)

    // Set up response callback
    hidHandler.SetResponseHandler(func(packet []byte) {
        // Send packet to virtual USB endpoint
        log.Printf("Response packet: %x", packet)
    })

    // Process incoming HID packets
    incomingPacket := make([]byte, 64)
    // ... receive from USB endpoint
    hidHandler.HandleMessage(incomingPacket)

    // Cleanup
    hidHandler.Close()
}
```

### HID Protocol Example

```go
func hidExample(auth *authenticator.Authenticator) {
    handler := authenticator.NewCTAPHIDHandler(auth)
    defer handler.Close()

    var responses [][]byte
    handler.SetResponseHandler(func(packet []byte) {
        responses = append(responses, packet)
    })

    // Build INIT packet to get channel
    initPacket := make([]byte, 64)
    binary.BigEndian.PutUint32(initPacket[0:4], 0xFFFFFFFF) // broadcast CID
    initPacket[4] = 0x86 // CTAPHID_INIT
    binary.BigEndian.PutUint16(initPacket[5:7], 8) // nonce length
    copy(initPacket[7:15], []byte{1, 2, 3, 4, 5, 6, 7, 8}) // nonce

    handler.HandleMessage(initPacket)

    // Parse INIT response to get channel ID
    initResp := responses[0]
    cid := binary.BigEndian.Uint32(initResp[8:12])
    log.Printf("Allocated channel: %08x", cid)

    // Now send CBOR command on allocated channel
    cborPacket := make([]byte, 64)
    binary.BigEndian.PutUint32(cborPacket[0:4], cid)
    cborPacket[4] = 0x90 // CTAPHID_CBOR
    // ... add GetInfo command
}
```

## PIN Management

### Setting Initial PIN

```go
func setInitialPIN(auth *authenticator.Authenticator, pin string) error {
    // For testing, use the helper method
    return auth.SetPINForTesting(pin)
}
```

### Full PIN Protocol Flow

```go
func setPINWithProtocol(auth *authenticator.Authenticator, pin string) error {
    // Step 1: Get authenticator's key agreement key
    getKeyReq := map[int]interface{}{
        0x02: uint8(2), // subCommand: getKeyAgreement
    }
    reqData, _ := cbor.Marshal(getKeyReq)

    response, err := auth.ProcessCBOR(authenticator.CmdClientPIN, reqData)
    if err != nil {
        return err
    }

    var respMap map[int]interface{}
    cbor.Unmarshal(response[1:], &respMap)

    authKeyAgreement := respMap[0x01].([]byte)

    // Step 2: Generate platform key pair and derive shared secret
    // (Implementation would use ECDH with P-256)

    // Step 3: Encrypt PIN and compute auth parameter
    // newPinEnc = AES-256-CBC(sharedSecret, padded(PIN))
    // pinUvAuthParam = HMAC-SHA-256(sharedSecret, newPinEnc)[:16]

    // Step 4: Send SetPIN request
    setPINReq := map[int]interface{}{
        0x01: uint8(1),           // pinUvAuthProtocol
        0x02: uint8(3),           // subCommand: setPIN
        0x03: platformKeyAgreement,
        0x04: pinUvAuthParam,
        0x05: newPinEnc,
    }
    reqData, _ = cbor.Marshal(setPINReq)

    response, err = auth.ProcessCBOR(authenticator.CmdClientPIN, reqData)
    if err != nil {
        return err
    }

    if response[0] == authenticator.StatusOK {
        log.Printf("PIN set successfully")
    }

    return nil
}
```

### Getting PIN Token

```go
func getPINToken(auth *authenticator.Authenticator, pin string) ([]byte, error) {
    // Similar ECDH key exchange flow...

    getPINTokenReq := map[int]interface{}{
        0x01: uint8(1),           // pinUvAuthProtocol
        0x02: uint8(5),           // subCommand: getPinToken
        0x03: platformKeyAgreement,
        0x06: encryptedPinHash,   // LEFT16(SHA-256(PIN)), encrypted
    }
    reqData, _ := cbor.Marshal(getPINTokenReq)

    response, err := auth.ProcessCBOR(authenticator.CmdClientPIN, reqData)
    if err != nil {
        return nil, err
    }

    var respMap map[int]interface{}
    cbor.Unmarshal(response[1:], &respMap)

    encryptedToken := respMap[0x02].([]byte)
    // Decrypt with sharedSecret to get PIN token

    return pinToken, nil
}
```

## Credential Management

### List Credentials

```go
func listCredentials(auth *authenticator.Authenticator) error {
    // Get credentials metadata
    metaReq := map[int]interface{}{
        0x01: uint8(1), // getCredsMetadata
    }
    reqData, _ := cbor.Marshal(metaReq)

    response, _ := auth.ProcessCBOR(authenticator.CmdCredentialManagement, reqData)

    var respMap map[int]interface{}
    cbor.Unmarshal(response[1:], &respMap)

    existing := respMap[0x01].(int)
    remaining := respMap[0x02].(int)

    log.Printf("Stored credentials: %d, Remaining capacity: %d", existing, remaining)

    return nil
}
```

### Enumerate RPs and Credentials

```go
func enumerateCredentials(auth *authenticator.Authenticator, pinToken []byte) error {
    // Enumerate RPs (requires PIN token with credentialMgmt permission)
    enumRPsReq := map[int]interface{}{
        0x01: uint8(2),    // enumerateRPsBegin
        0x03: 1,           // pinUvAuthProtocol
        0x04: pinUvAuthParam, // HMAC of subcommand
    }
    reqData, _ := cbor.Marshal(enumRPsReq)

    response, err := auth.ProcessCBOR(authenticator.CmdCredentialManagement, reqData)
    if err != nil {
        return err
    }

    var respMap map[int]interface{}
    cbor.Unmarshal(response[1:], &respMap)

    rpInfo := respMap[0x03]
    rpIdHash := respMap[0x04].([]byte)
    totalRPs := respMap[0x05].(int)

    log.Printf("Found %d RPs", totalRPs)

    // Enumerate credentials for this RP
    enumCredsReq := map[int]interface{}{
        0x01: uint8(4),    // enumerateCredentialsBegin
        0x02: map[int]interface{}{
            0x01: rpIdHash,
        },
        0x03: 1,
        0x04: pinUvAuthParam,
    }
    // ... process credentials

    return nil
}
```

## Reset Authenticator

```go
func resetAuthenticator(auth *authenticator.Authenticator) error {
    response, err := auth.ProcessCBOR(authenticator.CmdReset, nil)
    if err != nil {
        return err
    }

    if response[0] == authenticator.StatusOK {
        log.Printf("Authenticator reset complete")
    }

    return nil
}
```

## Using Key Backends

### Software Key Backend

```go
import (
    "github.com/jeremyhahn/go-xkms/xkey/pkg/fido2/authenticator"
    "github.com/jeremyhahn/go-xkms/xkey/pkg/fido2/authenticator/keybackend/software"
)

func setupWithSoftwareBackend() (*authenticator.Authenticator, error) {
    config := authenticator.DefaultConfig()
    config.Storage = authenticator.NewMemoryStorage()
    config.KeyBackend = software.NewSoftwareKeyBackend()

    return authenticator.NewAuthenticator(config)
}
```

### TPM2 Key Backend

```go
import (
    "github.com/jeremyhahn/go-xkms/xkey/pkg/fido2/authenticator"
    "github.com/jeremyhahn/go-xkms/xkey/pkg/fido2/authenticator/keybackend/tpm2"
)

func setupWithTPM2Backend() (*authenticator.Authenticator, error) {
    tpmBackend, err := tpm2.NewTPM2KeyBackend(&tpm2.TPM2Config{
        DevicePath: "/dev/tpmrm0",
    })
    if err != nil {
        return nil, err
    }

    config := authenticator.DefaultConfig()
    config.Storage = authenticator.NewMemoryStorage()
    config.KeyBackend = tpmBackend
    config.AttestationFormat = "tpm"

    return authenticator.NewAuthenticator(config)
}
```

## User Presence Handlers

### Auto-Grant (Default)

```go
func setupAutoGrant() (*authenticator.Authenticator, error) {
    config := authenticator.DefaultConfig()
    config.Storage = authenticator.NewMemoryStorage()
    // UserPresenceHandler defaults to AutoGrantHandler when nil

    return authenticator.NewAuthenticator(config)
}
```

### Auto-Grant with Simulated PIN

```go
func setupAutoGrantWithPIN() (*authenticator.Authenticator, error) {
    config := authenticator.DefaultConfig()
    config.Storage = authenticator.NewMemoryStorage()
    config.UserPresenceHandler = authenticator.NewAutoGrantHandlerWithPIN("123456")

    return authenticator.NewAuthenticator(config)
}
```

### Interactive Terminal Handler

```go
func setupInteractive() (*authenticator.Authenticator, error) {
    handler, err := authenticator.NewInteractiveHandler()
    if err != nil {
        // Terminal not available, fall back to auto-grant
        log.Printf("No terminal available, using auto-grant: %v", err)
        handler = nil
    }

    config := authenticator.DefaultConfig()
    config.Storage = authenticator.NewMemoryStorage()
    config.UserPresenceHandler = handler
    config.UserPresenceTimeout = 60 * time.Second

    return authenticator.NewAuthenticator(config)
}
```

## Error Handling Best Practices

```go
func handleAuthenticatorError(err error) {
    switch {
    case errors.Is(err, authenticator.ErrCredentialNotFound):
        log.Printf("Credential not found - user needs to register")

    case errors.Is(err, authenticator.ErrNoCredentials):
        log.Printf("No matching credentials for this RP")

    case errors.Is(err, authenticator.ErrPINRequired):
        log.Printf("PIN verification required")

    case errors.Is(err, authenticator.ErrPINBlocked):
        log.Printf("PIN blocked - authenticator locked")

    case errors.Is(err, authenticator.ErrPINInvalid):
        log.Printf("Invalid PIN - check retry count")

    case errors.Is(err, authenticator.ErrCredentialExcluded):
        log.Printf("Credential already registered for this user/RP")

    case errors.Is(err, authenticator.ErrResidentKeyLimitReached):
        log.Printf("Maximum discoverable credentials reached")

    case errors.Is(err, authenticator.ErrAuthenticatorClosed):
        log.Printf("Authenticator has been closed")

    default:
        log.Printf("Authenticator error: %v", err)
    }
}
```
