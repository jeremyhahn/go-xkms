# Native FIDO2 Authenticator

The go-keychain native FIDO2 authenticator provides a software-based implementation of the FIDO2/CTAP2 specification for credential creation, authentication, and key management. This authenticator is designed for testing, development, and production scenarios where hardware security keys are not available.

## Overview

The authenticator implements the Client to Authenticator Protocol version 2 (CTAP2) as specified by the FIDO Alliance. It supports the core WebAuthn operations along with optional extensions for enhanced functionality.

## Key Features

- **Full CTAP2 Compliance**: Implements all mandatory CTAP2 commands
- **Multiple Algorithms**: ECDSA P-256/P-384/P-521 and Ed25519 (EdDSA)
- **Discoverable Credentials**: Support for resident keys (passkeys)
- **PIN Protocol**: CTAP2.0 PIN Protocol v1 for user verification
- **hmac-secret Extension**: Enables symmetric key derivation from credentials
- **credProtect Extension**: Per-credential protection levels
- **Credential Management**: Full CTAP2.1 credential enumeration and deletion
- **Pluggable Storage**: Memory, file-backed, or custom storage backends
- **HID Layer Integration**: CTAP-HID protocol for virtual device simulation

## When to Use Native vs Virtual-FIDO

| Use Case | Native Authenticator | Virtual-FIDO Backend |
|----------|---------------------|---------------------|
| Unit testing | Recommended | Supported |
| Integration testing | Recommended | Recommended |
| Key derivation (hmac-secret) | Recommended | Limited |
| Credential management | Full support | Limited |
| Virtual USB device | Via HID adapter | Native support |
| PIV operations | Not supported | Full support |
| Production (hardware unavailable) | Supported | Supported |

**Choose Native Authenticator when:**
- You need full hmac-secret extension support for key derivation
- You need credential management capabilities
- You want fine-grained control over authenticator behavior
- You are building a pure software authentication solution

**Choose Virtual-FIDO Backend when:**
- You need USB HID device emulation
- You need combined PIV and FIDO2 operations
- You want compatibility with the virtual-fido library ecosystem

## Quick Start

```go
package main

import (
    "crypto/sha256"
    "log"

    "github.com/jeremyhahn/go-keychain/pkg/fido2/authenticator"
)

func main() {
    // Create authenticator with in-memory storage
    storage := authenticator.NewMemoryStorage()

    config := authenticator.DefaultConfig()
    config.Storage = storage
    config.EnablePIN = true
    config.EnableHMACSecret = true

    auth, err := authenticator.NewAuthenticator(config)
    if err != nil {
        log.Fatal(err)
    }
    defer auth.Close()

    // Create a credential
    clientDataHash := sha256.Sum256([]byte("example-client-data"))

    rp := authenticator.RelyingParty{
        ID:   "example.com",
        Name: "Example Corp",
    }

    user := authenticator.User{
        ID:          []byte("user-123"),
        Name:        "user@example.com",
        DisplayName: "Example User",
    }

    pubKeyParams := []authenticator.PublicKeyCredentialParam{
        {Type: "public-key", Alg: authenticator.COSEAlgES256},
    }

    resp, err := auth.MakeCredential(
        clientDataHash[:],
        rp,
        user,
        pubKeyParams,
        nil, // options
    )
    if err != nil {
        log.Fatal(err)
    }

    log.Printf("Credential created with format: %s", resp.Fmt)
}
```

## Supported CTAP2 Commands

| Command | Code | Status |
|---------|------|--------|
| authenticatorMakeCredential | 0x01 | Implemented |
| authenticatorGetAssertion | 0x02 | Implemented |
| authenticatorGetInfo | 0x04 | Implemented |
| authenticatorClientPIN | 0x06 | Implemented |
| authenticatorReset | 0x07 | Implemented |
| authenticatorGetNextAssertion | 0x08 | Implemented |
| authenticatorCredentialManagement | 0x0A | Implemented |
| authenticatorSelection | 0x0B | Implemented |
| authenticatorBioEnrollment | 0x09 | Not supported |
| authenticatorLargeBlobs | 0x0C | Not implemented |
| authenticatorConfig | 0x0D | Not implemented |

## Supported Extensions

| Extension | MakeCredential | GetAssertion | Notes |
|-----------|---------------|--------------|-------|
| hmac-secret | Input: boolean | Input: encrypted salts | Full support |
| credProtect | Input: 1-3 | Output: level | Full support |

## Documentation

- [Architecture](authenticator/architecture.md) - Component design and data flow
- [Usage](authenticator/usage.md) - Detailed usage examples
- [Configuration](authenticator/configuration.md) - All configuration options
- [API Reference](authenticator/api.md) - Complete API documentation
- [Security](authenticator/security.md) - Security considerations

## Package Structure

```
pkg/fido2/authenticator/
    authenticator.go     # Main authenticator implementation
    config.go           # Configuration types and defaults
    types.go            # Core data types
    errors.go           # Typed error definitions
    storage.go          # Storage interfaces
    storage_memory.go   # In-memory storage implementation
    storage_backend.go  # Persistent storage adapter
    crypto.go           # COSE key and signature operations
    authdata.go         # Authenticator data builder
    cmd_getinfo.go      # GetInfo command handler
    cmd_makecredential.go  # MakeCredential handler
    cmd_getassertion.go    # GetAssertion handler
    cmd_clientpin.go       # ClientPIN handler
    cmd_credmgmt.go        # Credential management
    cmd_reset.go           # Reset handler
    pin_protocol.go        # PIN protocol interface
    pin_protocol_v1.go     # PIN Protocol v1 implementation
    ext_hmac_secret.go     # hmac-secret extension
    hid_adapter.go         # CTAP-HID protocol layer
```

## Requirements

- Go 1.21+
- github.com/fxamacker/cbor/v2 (CBOR encoding)

## License

This module is part of go-keychain and is dual-licensed under AGPL-3.0 and Commercial licenses.
