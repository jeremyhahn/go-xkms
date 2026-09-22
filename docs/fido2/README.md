# FIDO2 Client Library

The go-xkms FIDO2 package (`pkg/fido2/`) provides a client library for communicating with FIDO2/CTAP2 security keys over USB HID. It handles device discovery, enrollment, authentication, and extension support including hmac-secret for symmetric key derivation.

## Overview

The FIDO2 client library implements the Client to Authenticator Protocol version 2 (CTAP2) as specified by the FIDO Alliance. It communicates with hardware security keys (or the xkey virtual authenticator) to perform WebAuthn registration and authentication ceremonies.

## Key Features

- **Device Discovery**: Enumerate and wait for FIDO2 USB HID devices
- **CTAP2 Protocol**: Full CTAP2 message encoding/decoding over USB HID
- **Key Enrollment**: Register new FIDO2 credentials with security keys
- **Authentication**: Authenticate using enrolled FIDO2 credentials
- **hmac-secret Extension**: Symmetric key derivation from FIDO2 credentials
- **PIN Support**: PIN-based user verification
- **Cross-Platform**: Linux HID support with stub fallback for other platforms

## Package Structure

```
pkg/fido2/
    fido2.go          # Handler interface and FIDO2Handler implementation
    config.go         # Configuration types
    types.go          # Error types, CTAP2 constants, and status codes
    device.go         # HID device interface and USB HID communication
    ctap2.go          # CTAP2 message encoding/decoding
    hmac_secret.go    # hmac-secret extension support
    authdata.go       # Authenticator data / extension map parsing
    pinuvauth.go      # PIN/UV auth protocols one and two (ECDH shared secret)
    hid_linux.go      # Linux USB HID device enumeration
    hid_stub.go       # Stub for non-Linux platforms
```

## Quick Start

```go
package main

import (
    "context"
    "log"

    "github.com/jeremyhahn/go-xkms/pkg/fido2"
)

func main() {
    // Create a FIDO2 handler with default configuration
    config := fido2.DefaultConfig()

    enumerator := fido2.NewLinuxHIDEnumerator()

    handler, err := fido2.NewHandler(config, enumerator)
    if err != nil {
        log.Fatal(err)
    }
    defer handler.Close()

    // List available FIDO2 devices
    devices, err := handler.ListDevices()
    if err != nil {
        log.Fatal(err)
    }

    for _, dev := range devices {
        log.Printf("Found device: %s (%s)", dev.Product, dev.Path)
    }

    // Wait for a device to be inserted
    ctx := context.Background()
    device, err := handler.WaitForDevice(ctx)
    if err != nil {
        log.Fatal(err)
    }
    log.Printf("Device ready: %s", device.Product)
}
```

## hmac-secret Key Derivation

The hmac-secret extension is how a FIDO2 credential produces a symmetric key
(for example a LUKS volume key). The derivation is a CTAP 2.1 12.5 exchange,
and every step matters:

1. The platform fetches the authenticator's key agreement key with
   `authenticatorClientPIN` / `getKeyAgreement`, generates an ephemeral P-256
   key pair, and derives a **PIN/UV auth shared secret** by ECDH.
   Protocol two is used when the authenticator advertises it, protocol one
   otherwise.
2. The 32-byte salt is encrypted under that shared secret (`saltEnc`) and
   authenticated (`saltAuth`), then sent as the hmac-secret extension input
   of `authenticatorGetAssertion`.
3. The authenticator answers with `HMAC-SHA-256(CredRandom, salt)`, encrypted
   under the same shared secret, inside the **CBOR extension map that
   terminates the authenticator data**.
4. The platform locates that map with `ParseAuthDataExtensions` (which honors
   the AT and ED flags and measures the COSE public key rather than assuming
   a fixed offset) and decrypts the output.

`CredRandom` never leaves the authenticator, so the derived key exists only
in the physical token's presence.

```go
config := fido2.DefaultAuthenticationConfig(credentialID, salt)
config.RelyingPartyID = "go-xkms"

// Optional: a second 32-byte salt yields a second 32-byte output.
config.Salt2 = otherSalt

key, err := handler.UnlockWithKey(config) // 64-byte derived key
```

Any failure to obtain the genuine output — no extension map, no hmac-secret
entry, a malformed entry, or an output of the wrong length — is a typed
error (`ErrHMACSecretMissing`, `ErrHMACSecretOutputInvalid`,
`ErrInvalidExtensions`, ...). No key is returned. A value that is not the
authenticator's secret is not a key.

### BREAKING (2026-09-22): legacy derivation removed

Releases before this derivation was corrected read 32 raw bytes from a fixed
offset in the authenticator data and, failing that, used
`SHA-256(credentialID || salt)`. Both credential ID and salt are public and
are normally stored beside the encrypted volume, so a key derived that way was
**not hardware-bound** and could be recomputed without the token.

That derivation, its `DerivationModeLegacyInsecure` mode, and the
`xkmsctl fido2 authenticate --legacy-hmac-derivation` flag that selected it
have been deleted outright — `DerivationModeCTAP2` is the only mode. A volume
still keyed with the legacy derivation cannot be unlocked through this SDK;
re-enroll it against a release that still carries the removed mode, then
re-enroll again on the current release.

## Virtual Authenticator

For development and testing, the xkey virtual authenticator (`xkey/cmd/xkey/`) can expose a software-based FIDO2 authenticator as a USB HID device via Linux UHID. See the [xkey FIDO2 documentation](../../xkey/docs/fido2/overview.md) for details.

## Documentation

- [xkey FIDO2 Virtual Authenticator](../../xkey/docs/fido2/overview.md) - Virtual FIDO2 device for development
- [xkey Architecture](../../xkey/docs/fido2/authenticator-architecture.md) - xkey FIDO2 component design
- [WebAuthn Usage](../../xkey/docs/usage/webauthn.md) - Server-side WebAuthn integration

## Requirements

- Go 1.21+
- github.com/fxamacker/cbor/v2 (CBOR encoding)
- Linux for USB HID device access (other platforms use stub)

## License

This module is part of go-xkms and is dual-licensed under AGPL-3.0 and Commercial licenses.
