# VirtualFIDO Backend

VirtualFIDO is a software-based virtual security key backend for go-keychain that wraps the [virtual-fido](https://github.com/bulwarkid/virtual-fido) library.

## Features

- **Full Backend Interface**: Implements `types.Backend` like YubiKey, CanoKey, TPM2
- **PIV Operations**: Support for PIV slots (0x9a, 0x9c, 0x9d, 0x9e) with key generation and signing
- **FIDO2 Operations**: WebAuthn enrollment and authentication via virtual-fido
- **Key-Specific Operations**: PIN, PUK, and management key management
- **Flexible Storage**: Uses `storage.Backend` interface (go-objstore compatible)
- **No Hardware Required**: Pure software implementation for testing and development

## Quick Start

```go
import (
    "github.com/jeremyhahn/go-keychain/pkg/backend/virtualfido"
    "github.com/jeremyhahn/go-keychain/pkg/storage"
    "github.com/jeremyhahn/go-keychain/pkg/fido2"
)

// Create VirtualFIDO backend with in-memory storage (for tests)
cfg := &virtualfido.Config{
    PIN:          "123456",
    SerialNumber: "virtualfido-001",
}
backend, err := virtualfido.NewBackend(cfg)
if err != nil {
    log.Fatal(err)
}
defer backend.Close()

// Use for PIV operations
signer, err := backend.Signer(&types.KeyAttributes{
    CN:      "my-signing-key",
    KeyType: types.KeyTypeSigning,
})

// Use for FIDO2 operations
enumerator := backend.FIDO2Enumerator()
handler, err := fido2.NewHandler(&fido2.Config{}, enumerator)
result, err := handler.EnrollKey(&fido2.EnrollmentConfig{
    User: fido2.User{Name: "user@example.com"},
})
```

## Storage Options

### In-Memory (Ephemeral)
```go
cfg := &virtualfido.Config{
    // Storage: nil = in-memory (default)
    PIN: "123456",
}
```

### File-Backed (Persistent)
```go
fileStorage := storage.NewFileBackend("/var/lib/go-keychain/virtualfido")
cfg := &virtualfido.Config{
    Storage:    fileStorage,
    PIN:        "123456",
    Passphrase: "encryption-passphrase",
}
```

### Custom Backend (go-objstore compatible)
```go
customStorage := myAdapter.NewBackend(...)  // Implements storage.Backend
cfg := &virtualfido.Config{
    Storage:    customStorage,
    PIN:        "123456",
    Passphrase: "encryption-passphrase",
}
```

## Documentation

- [Architecture](architecture.md) - Design decisions and component overview
- [Usage](usage.md) - Detailed usage examples
- [PIV Operations](piv-operations.md) - PIV slot management guide
- [FIDO2 Operations](fido2-operations.md) - FIDO2 enrollment and authentication
- [Implementation Plan](implementation-plan.md) - Full implementation details
- [Implementation Checklist](implementation-checklist.md) - Progress tracking

## Dependencies

- [github.com/bulwarkid/virtual-fido](https://github.com/bulwarkid/virtual-fido) - Virtual FIDO2/U2F authenticator
