# PKCS#11 — API

> **Status: NORMATIVE** · Feature: `pkcs11` · Module: `go-xkms/xkey` · Last verified: 2026-09-27

No REST/gRPC/QUIC/MCP transport surface. This feature is reachable through
two xkey-local capabilities: Wails GUI bindings, and a Unix-socket IPC
protocol for out-of-process callers. Neither is network-facing.

## GUI bindings: `PKCS11Service`

Wails-bound methods on `xkey/pkg/gui/services.PKCS11Service`
(`pkcs11_service.go`):

| Capability | Method |
|---|---|
| Availability | `IsAvailable() bool`, `Close() error` |
| Module discovery | `ProbeModules() []ProbeResult`, `DetectYubiKey() YubiKeyDetectionResult` |
| Module registration | `RegisterModule(libraryPath, displayName string) (string, error)`, `RegisterModuleFromConfig(moduleID, libraryPath, displayName string) (string, error)`, `UnregisterModule(moduleID string) error` |
| Slot enumeration | `RefreshSlots(moduleID string) ([]PKCS11SlotInfo, error)`, `GetModuleSlots(moduleID string) ([]PKCS11SlotInfo, error)`, `ProbeSlots(libraryPath string) ([]PKCS11SlotInfo, error)` |
| Module/token listing | `GetModule(moduleID string) (*PKCS11ModuleInfo, error)`, `ListModules() []PKCS11ModuleInfo`, `ListTokens() []PKCS11TokenInfo` |
| Token initialization | `InitializeToken(moduleID string, slotID uint, label, soPin, userPin string) error` |
| Session lifecycle | `Connect(moduleID string, slotID uint, userPin, soPin string) error`, `Disconnect(moduleID string, slotID uint) error`, `GetConnection(moduleID string, slotID uint) (*PKCS11ConnectionInfo, error)`, `ListConnections() []PKCS11ConnectionInfo` |
| Connectivity testing | `TestConnection(libraryPath string, slotID uint, userPIN string) error` |
| PIV slot occupancy | `GetSlotOccupancy(moduleID string, slotID uint) ([]SlotOccupancyInfo, error)`, `HasSlotModel(moduleID string, slotID uint) bool` |
| Wiring (not Wails-bound) | `SetContext`, `SetConnectHook`, `SetDisconnectHook`, `SetManager`, `GetManager`, `SetRegistry` |

`Connect` refuses a YubiKey library with an empty `soPin`
(`ErrPKCS11SOPINRequired`) before it reaches the manager — see
[engineering.md](engineering.md#invariants). On success it updates the
injected `backendregistry.Registry` (state `Ready`, with the connected
slot/library/token-label recorded as metadata) and fires the
`PKCS11ConnectHook`, if one was set, so a caller can register the token as
an `xkms` backend. `Disconnect` mirrors this in reverse (`Offline` state,
`PKCS11DisconnectHook`).

Response types (`PKCS11ModuleInfo`, `PKCS11SlotInfo`, `PKCS11TokenInfo`,
`PKCS11ConnectionInfo`, `ProbeResult`, `SlotOccupancyInfo`,
`YubiKeyDetectionResult`) are plain JSON-tagged structs — see
`pkcs11_service.go` for exact fields.

## IPC wire protocol (Unix domain socket)

Server: `xkey/pkg/ipc.Server` with a `PKCS11IPCHandler` registered
(`xkey/pkg/gui/services/pkcs11_ipc_handler.go`). Client:
`xkey/pkg/pkcs11.IPCTransport`. Transport: newline-free JSON, one request
per connection, over the socket resolved as described in
[engineering.md](engineering.md#configuration).

Request envelope (`xkey/pkg/ipc.Message`):

```json
{"type": "pkcs11", "pkcs11": {"action": "<action>", "...": "..."}}
```

| Action | Request fields (`pkcs11.*`) | Requires unsealed barrier |
|---|---|---|
| `sign` | `backend`, `key_id`, `data` (base64), `hash` | Yes |
| `get_piv_certificate` | `backend`, `slot`, `format` (`pem`/`der`, default `pem`) | Yes |
| `list_piv_slots` | `backend` | Yes |
| `barrier_status` | *(none)* | No |

Response envelope (`xkey/pkg/ipc.Response`): `status` (`ok`/`error`),
`error` (message, when `status == "error"`), and one of
`pkcs11.sign.signature` (base64), `pkcs11.piv_cert.{certificate,slot}`,
`pkcs11.piv_slots.slots[]` (`slot`, `algorithm`, `subject`, `has_cert`,
`not_after`), or `pkcs11.barrier_status.sealed` (bool). `BarrierStatusResult`
is shared with the unrelated `state` message type and also carries
`initialized`, `strategy`, and `hardware_backed` fields, but
`HandlePKCS11BarrierStatus` populates only `sealed` — the other three are
always their zero value on a `pkcs11`/`barrier_status` response.

Every action other than the four above (key generation, encrypt/decrypt,
wrap/unwrap, import/export, PIV key/certificate mutation) has no wire
representation — `IPCTransport`'s corresponding Go method returns
`ErrIPCNotImplemented` locally, without a round trip, and there is no
server-side handler for it to reach even if one were sent.

## In-process: `xkms.PKCS11Transport`

Anything already running inside the xkey binary (e.g. `xkey usb device
start`) constructs a `pkcs11.EmbeddedTransport` directly and calls its
methods as plain Go — there is no serialization boundary. All 20
`xkms.PKCS11Transport` operations are available this way; see
[engineering.md](engineering.md#exported-surface).

## See also

- [Architecture](architecture.md) — why the GUI, IPC, and in-process paths
  exist separately
- [Engineering](engineering.md) — exported surface, invariants, tests
- [CLI](cli.md) — the flag-driven surface (no IPC/GUI involved)
