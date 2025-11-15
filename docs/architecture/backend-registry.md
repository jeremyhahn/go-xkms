# Backend Registry

The backend registry provides runtime discovery of available keychain backends compiled into the binary.

## Overview

The registry enables:
- Query available backends at runtime
- Check backend availability before instantiation
- Conditional compilation via build tags
- Thread-safe backend registration

## API Reference

### GetAvailableBackends

Returns list of registered backend names.

```go
import "github.com/jeremyhahn/go-keychain/pkg/backend"

backends := backend.GetAvailableBackends()
// Returns: []BackendInfo with name, type, description, features
```

### GetBackendInfo

Get details for a specific backend.

```go
info, err := backend.GetBackendInfo("pkcs8")
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Backend: %s\n", info.Name)
fmt.Printf("Type: %s\n", info.Type)
fmt.Printf("Description: %s\n", info.Description)
fmt.Printf("Features: %v\n", info.Features)
```

### IsBackendAvailable

Check if a backend is registered.

```go
if backend.IsBackendAvailable("tpm2") {
    // TPM2 backend is available
}
```

## Backend Registration

Backends self-register during package initialization:

```go
//go:build pkcs8

package pkcs8

import "github.com/jeremyhahn/go-keychain/pkg/backend"

func init() {
    backend.RegisterBackend(backend.BackendInfo{
        Name:        "pkcs8",
        Type:        "software",
        Description: "PKCS#8 file-based keychain",
        Features:    []string{"rsa", "ecdsa", "ed25519", "aes"},
        Available:   true,
    })
}
```

## Build Tags

Use build tags to control which backends are compiled:

```bash
# Build with specific backends
go build -tags "pkcs8 tpm2"

# Build with all backends (default)
make build

# Query at runtime
backends := keychain.GetAvailableBackends()
```

## Thread Safety

All registry operations are thread-safe using `sync.RWMutex`:

```go
var (
    registry = make(map[string]BackendInfo)
    mu       sync.RWMutex
)
```

## Example Usage

```go
package main

import (
    "fmt"
    "github.com/jeremyhahn/go-keychain/pkg/backend"
)

func main() {
    // List all available backends
    backends := backend.GetAvailableBackends()

    fmt.Println("Available Backends:")
    for _, b := range backends {
        fmt.Printf("  - %s (%s): %s\n",
            b.Name,
            b.Type,
            b.Description)
        fmt.Printf("    Features: %v\n", b.Features)
    }

    // Check specific backend
    if backend.IsBackendAvailable("pkcs8") {
        info, _ := backend.GetBackendInfo("pkcs8")
        fmt.Printf("\nUsing %s backend\n", info.Name)
    }
}
```

## See Also

- [Storage Abstraction](storage-abstraction.md)
- [Architecture Overview](architecture/overview.md)
- [Build System](build-system.md)
