# PKCS#11 Manager

The PKCS#11 Manager provides high-level multi-token management for go-xkms applications. It handles module registration, slot enumeration, session management, and token lifecycle operations.

## Overview

The manager package (`pkg/pkcs11/manager`) supports:

- **Module Registration**: Load and initialize PKCS#11 libraries
- **Slot Enumeration**: Discover slots and tokens with hot-plug support
- **Token Initialization**: Initialize new tokens with SO PIN and User PIN
- **Session Management**: Open authenticated sessions with automatic login
- **Connection Tracking**: Track active connections across multiple tokens

## Build Requirements

The manager requires the `pkcs11` build tag:

```bash
go build -tags pkcs11 ./...
```

Without this tag, a stub implementation is used that returns `ErrPKCS11Disabled` for all operations.

## Basic Usage

### Creating a Manager

```go
import (
    "log/slog"
    "github.com/jeremyhahn/go-xkms/pkg/pkcs11/manager"
)

// Create manager with default options
mgr := manager.New()
defer mgr.Close()

// Or with custom logger
logger := slog.Default()
mgr := manager.New(manager.WithLogger(logger))
```

### Registering PKCS#11 Modules

```go
// Register a PKCS#11 library
moduleID, err := mgr.RegisterModule(
    "/usr/lib/softhsm/libsofthsm2.so",  // Library path
    "SoftHSM2",                          // Display name
)
if err != nil {
    log.Fatal(err)
}

// List all registered modules
modules := mgr.ListModules()
for _, mod := range modules {
    fmt.Printf("Module %s: %s (%d slots)\n",
        mod.ID, mod.DisplayName, len(mod.Slots))
}
```

### Discovering Tokens

```go
// Auto-detect available PKCS#11 libraries
probed := manager.ProbeModulesWithNames()
for _, p := range probed {
    fmt.Printf("Found: %s at %s\n", p.DisplayName, p.LibraryPath)
}

// List all tokens across all modules
tokens := mgr.ListTokens()
for _, token := range tokens {
    fmt.Printf("Token: %s (Slot %d, %s)\n",
        token.Label, token.SlotID, token.ModuleName)
}
```

### Initializing a Token

```go
// Initialize a new token with PINs
err := mgr.InitializeToken(
    moduleID,       // Module ID from registration
    0,              // Slot ID
    "MyToken",      // Token label
    "12345678",     // Security Officer PIN
    "1234",         // User PIN
)
if err != nil {
    log.Fatal(err)
}
```

### Connecting to a Token

```go
// Connect to an initialized token
backend, err := mgr.Connect(moduleID, slotID, "1234")  // User PIN
if err != nil {
    log.Fatal(err)
}

// Use the backend for cryptographic operations
attrs := &types.KeyAttributes{
    CN:        "my-key",
    Algorithm: types.AlgorithmECDSAP256,
}
privateKey, err := backend.GenerateKey(attrs)

// Disconnect when done
err = mgr.Disconnect(moduleID, slotID)
```

## API Reference

### Manager Interface

```go
type Manager interface {
    // Module management
    RegisterModule(libraryPath, displayName string) (string, error)
    UnregisterModule(moduleID string) error
    GetModule(moduleID string) (*ModuleInfo, error)
    ListModules() []ModuleInfo
    RefreshSlots(moduleID string) ([]SlotInfo, error)

    // Token discovery
    ListTokens() []TokenInfo

    // Token lifecycle
    InitializeToken(moduleID string, slotID uint, label, soPin, userPin string) error

    // Connection management
    Connect(moduleID string, slotID uint, userPin string) (Backend, error)
    Disconnect(moduleID string, slotID uint) error
    GetConnection(moduleID string, slotID uint) (*Connection, error)
    ListConnections() []*Connection

    // Cleanup
    Close() error
}
```

### Types

#### ModuleInfo

```go
type ModuleInfo struct {
    ID          string       // Unique module identifier
    DisplayName string       // Human-readable name
    LibraryPath string       // Path to PKCS#11 library
    State       ModuleState  // loaded, unloaded, error
    Slots       []SlotInfo   // Available slots
    ErrorMsg    string       // Error message if state is error
}
```

#### SlotInfo

```go
type SlotInfo struct {
    SlotID          uint   // PKCS#11 slot identifier
    Label           string // Token label
    Serial          string // Token serial number
    Manufacturer    string // Token manufacturer
    Model           string // Token model
    TokenPresent    bool   // Whether token is inserted
    Initialized     bool   // Whether token is initialized
    HardwareVersion string // Hardware version
    FirmwareVersion string // Firmware version
}
```

#### TokenInfo

```go
type TokenInfo struct {
    ModuleID     string // Module containing this token
    ModuleName   string // Module display name
    SlotID       uint   // Slot identifier
    Label        string // Token label
    Manufacturer string // Token manufacturer
    Model        string // Token model
    Serial       string // Token serial
    Initialized  bool   // Whether initialized
    Connected    bool   // Whether currently connected
}
```

#### Connection

```go
type Connection struct {
    ModuleID      string  // Module identifier
    SlotID        uint    // Slot identifier
    TokenLabel    string  // Token label
    Backend       Backend // Cryptographic backend
    SessionHandle uint    // PKCS#11 session handle
}
```

## Module Probing

The manager can auto-detect installed PKCS#11 libraries:

```go
// Get just paths
paths := manager.ProbeModulePaths()

// Get paths with suggested names
modules := manager.ProbeModulesWithNames()
```

Common module paths checked:

| Platform | Libraries |
|----------|-----------|
| Linux | SoftHSM2, OpenSC, YubiKey, Nitrokey, SafeNet |
| macOS | SoftHSM2, OpenSC, YubiKey |
| Windows | SoftHSM2, OpenSC, YubiKey |

## Error Handling

The manager defines typed errors for precise error handling:

```go
import "github.com/jeremyhahn/go-xkms/pkg/pkcs11/manager"

backend, err := mgr.Connect(moduleID, slotID, pin)
if err != nil {
    switch err {
    case manager.ErrModuleNotFound:
        log.Println("Module not registered")
    case manager.ErrSlotNotFound:
        log.Println("Slot does not exist")
    case manager.ErrTokenNotPresent:
        log.Println("No token in slot")
    case manager.ErrTokenNotInitialized:
        log.Println("Token needs initialization")
    case manager.ErrLoginFailed:
        log.Println("Invalid PIN")
    default:
        log.Printf("Connection error: %v", err)
    }
}
```

## CLI Integration

The manager is used by `xkmsctl` for token management:

```bash
# List available modules
xkmsctl pkcs11 list-modules

# List all tokens
xkmsctl pkcs11 list-tokens

# Initialize a token
xkmsctl pkcs11 init-token \
    --module /usr/lib/softhsm/libsofthsm2.so \
    --slot 0 \
    --label "MyToken" \
    --so-pin 12345678 \
    --user-pin 1234

# Connect and generate a key
xkmsctl pkcs11 keygen \
    --module /usr/lib/softhsm/libsofthsm2.so \
    --slot 0 \
    --pin 1234 \
    --algorithm ecdsa-p256 \
    --label my-signing-key
```

## GUI Integration

The xkey GUI uses the manager through a service wrapper:

```go
// In xkey/pkg/gui/services/pkcs11_service.go
type PKCS11Service struct {
    manager *manager.Manager
}

func (s *PKCS11Service) ListTokens() ([]manager.TokenInfo, error) {
    return s.manager.ListTokens()
}
```

The GUI provides:
- Token browser with connection status
- Token initialization wizard
- PIN entry dialogs
- Backend selection in setup wizard

## Thread Safety

The manager is safe for concurrent use. All methods are protected by appropriate locks:
- Read operations use read locks for parallel access
- Write operations use exclusive locks
- Connections are tracked atomically

## See Also

- [PKCS#11 Backend](../backends/pkcs11.md)
- [Security Levels](../architecture/security-levels.md)
- [Backend Architecture](../architecture/overview.md)
