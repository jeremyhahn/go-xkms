# PKCS#11 IPC Transport

IPC protocol extension enabling external processes (PKCS#11 module, crypto.Signer) to perform cryptographic operations through a running xkey instance via Unix domain socket.

**Packages:**
- `xkey/pkg/ipc/` - Protocol definition and server
- `xkey/pkg/pkcs11/ipc_transport.go` - Client-side transport
- `xkey/pkg/gui/services/pkcs11_ipc_handler.go` - Server-side handler

## Overview

The PKCS#11 IPC transport extends xkey's existing IPC protocol with a `MessageTypePKCS11` message type. External processes send JSON-encoded requests over a Unix domain socket, and xkey dispatches them to the appropriate handler via action-based routing.

```
PKCS#11 Module / crypto.Signer
        |
        v  (JSON over Unix socket)
   IPCTransport
        |
        v
   IPC Server (xkey)
        |
        v
   PKCS11IPCHandler
        |
        v
   EmbeddedTransport -> go-xkms backend
```

## API

### Wire Format

JSON messages over Unix domain socket. Each request opens a fresh connection.

| Field | Type | Description |
|-------|------|-------------|
| `type` | string | `"pkcs11"` |
| `pkcs11.action` | string | Operation to perform |
| `pkcs11.*` | object | Action-specific parameters |

### PKCS#11 Actions

| Action | Description | Requires Unsealed Barrier |
|--------|-------------|---------------------------|
| `sign` | Sign data with a key | Yes |
| `get_piv_certificate` | Retrieve certificate from PIV slot | Yes |
| `list_piv_slots` | List all PIV slots with status | Yes |
| `barrier_status` | Check barrier seal status | No |

### PKCS11Handler Interface

```go
type PKCS11Handler interface {
    HandlePKCS11Sign(params *SignParams) (*SignResult, error)
    HandlePKCS11GetPIVCertificate(params *PIVCertParams) (*PIVCertResult, error)
    HandlePKCS11ListPIVSlots(params *PIVSlotsParams) (*PIVSlotsResult, error)
    HandlePKCS11BarrierStatus() (*BarrierStatusResult, error)
}
```

### IPCTransport (Client)

Implements `module.PKCS11Transport` for use by the PKCS#11 module and crypto.Signer.

| Method | Status | Description |
|--------|--------|-------------|
| `Connect` | Implemented | Verify socket reachable via barrier_status |
| `Sign` | Implemented | Sign data (base64 encoded over wire) |
| `ListPIVSlots` | Implemented | List PIV slot status |
| `GetPIVCertificate` | Implemented | Retrieve certificate from slot |
| `Close` | Implemented | No-op (per-request connections) |
| Other operations | Not implemented | Return `ErrIPCNotImplemented` |

### PKCS11IPCHandler (Server)

Bridges IPC requests to `EmbeddedTransport`. Checks barrier seal status before operations that access protected keys.

## Configuration

### Socket Path Resolution

1. Constructor argument (if non-empty)
2. `XKEY_IPC_SOCKET` environment variable
3. `~/.xkey/run/xkey.sock` (default)

### Timeouts

| Parameter | Value |
|-----------|-------|
| IPC operation timeout | 10 seconds |
| Connection dial timeout | 10 seconds |

### Key Types

| Type | Fields |
|------|--------|
| `SignParams` | Backend, KeyID, Data (base64), Hash |
| `PIVCertParams` | Backend, Slot, Format (pem/der) |
| `PIVSlotsParams` | Backend |
| `BarrierStatusResult` | Sealed, Strategy, HardwareBacked |

## Cross-References

- [PKCS#11 Module](../../docs/pkcs11/module/README.md) - PKCS#11 module that uses this transport
