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

## Virtual Authenticator

For development and testing, the xkey virtual authenticator (`xkey/cmd/xkey/`) can expose a software-based FIDO2 authenticator as a USB HID device via Linux UHID. See the [xkey FIDO2 documentation](../xkey/fido2.md) for details.

## Documentation

- [xkey FIDO2 Virtual Authenticator](../xkey/fido2.md) - Virtual FIDO2 device for development
- [xkey Architecture](../xkey/fido2-architecture.md) - xkey FIDO2 component design
- [WebAuthn Usage](../usage/webauthn.md) - Server-side WebAuthn integration

## Requirements

- Go 1.21+
- github.com/fxamacker/cbor/v2 (CBOR encoding)
- Linux for USB HID device access (other platforms use stub)

## License

This module is part of go-xkms and is dual-licensed under AGPL-3.0 and Commercial licenses.
