# PKCS#11 — API

> **Status: NORMATIVE** · Feature: `pkcs11` · Module: `go-xkms/xkey` · Last verified: 2026-10-09

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
[engineering.md](engineering.md#configuration). The GUI serves it only
while local app access is on and xKey is unlocked; otherwise there is no
socket and the client's `Connect` fails with `ErrIPCConnectionFailed`.

Request envelope (`xkey/pkg/ipc.Message`):

```json
{"type": "pkcs11", "pkcs11": {"action": "<action>", "...": "..."}}
```

Every `xkms.PKCS11Transport` operation has an action. The request body sits
under `pkcs11.<action>` and is the SDK request type for that operation
(`go-xkms/sdk/go/transport`), field for field; the result comes back under
the same key in the response's `pkcs11` object, as the SDK response type.
Byte fields (`data`, `signature`, `ciphertext`, `certificate`, ...) are
base64, as `encoding/json` encodes `[]byte`.

| Action | Request / result type | Required fields |
|---|---|---|
| `generate_key` | `GenerateKeyRequest` / `GenerateKeyResponse` | `key_id` |
| `sign` | `SignRequest` / `SignResponse` | `key_id`, `data` |
| `verify` | `VerifyRequest` / `VerifyResponse` | `key_id` |
| `encrypt` | `EncryptRequest` / `EncryptResponse` | `key_id` |
| `encrypt_asym` | `EncryptAsymRequest` / `EncryptAsymResponse` | `key_id` |
| `decrypt` | `DecryptRequest` / `DecryptResponse` | `key_id` |
| `derive_key` | `DeriveKeyRequest` / `DeriveKeyResponse` | *(request only)* |
| `derive_key_ecdh` | `DeriveKeyECDHRequest` / `DeriveKeyECDHResponse` | `key_id` |
| `wrap_key_by_id` | `WrapKeyByIDRequest` / `WrapKeyByIDResponse` | `wrapping_key_id` |
| `unwrap_key_by_id` | `UnwrapKeyByIDRequest` / `UnwrapKeyByIDResponse` | `unwrapping_key_id` |
| `export_key_material` | `ExportKeyMaterialRequest` / `ExportKeyMaterialResponse` | `key_id` |
| `get_import_parameters` | `GetImportParametersRequest` / `GetImportParametersResponse` | `key_id` |
| `import_key` | `ImportKeyRequest` / `ImportKeyResponse` | `key_id` |
| `list_piv_slots` | `ListPIVSlotsRequest` / `ListPIVSlotsResponse` | *(request optional)* |
| `get_piv_certificate` | `GetPIVCertificateRequest` / `GetPIVCertificateResponse` | `slot` |
| `generate_piv_key` | `GeneratePIVKeyRequest` / `GeneratePIVKeyResponse` | `slot` |
| `store_piv_certificate` | `StorePIVCertificateRequest` / *(none)* | `slot` |
| `delete_piv_certificate` | `DeletePIVCertificateRequest` / *(none)* | `slot` |
| `import_piv_certificate` | `StorePIVCertificateRequest` / *(none)* | `slot` |
| `export_piv_certificate` | `GetPIVCertificateRequest` / `GetPIVCertificateResponse` | `slot` |
| `generate_piv_csr` | `GeneratePIVCSRRequest` / `GeneratePIVCSRResponse` | `slot` |
| `barrier_status` | *(none)* / `BarrierStatusResult` | — |

Example:

```json
{"type": "pkcs11", "pkcs11": {"action": "sign",
  "sign": {"backend": "software", "key_id": "k1", "data": "aGVsbG8=", "hash": "SHA-256"}}}
```

```json
{"status": "ok", "pkcs11": {"sign": {"signature": "MEUCIQ..."}}}
```

`sign` and `verify` hash `data` with `hash` (default SHA-256) unless
`data_is_digest` is true, in which case `data` is that digest and is signed
as is. RSA keys take `padding` (`pkcs1v15`, the default, or `pss`) and
`salt_length` for PSS (0 = auto, -1 = hash length). Ed25519 signs the
message itself and refuses `data_is_digest`; `pre_hash` selects Ed25519ph.
A signed digest:

```json
{"type": "pkcs11", "pkcs11": {"action": "sign",
  "sign": {"key_id": "piv-9a", "data": "<base64 SHA-256 digest>", "hash": "SHA-256",
           "data_is_digest": true, "padding": "pss", "salt_length": -1}}}
```

The server validates the request before dispatch: a missing request body or
required field fails with `invalid IPC message` and never reaches the
handler. Every action except `barrier_status` requires an unsealed
barrier; a sealed one fails with `barrier is sealed`. `IPCTransport` asks
for PEM when a `get_piv_certificate` or `export_piv_certificate` request
names no format.

Response envelope (`xkey/pkg/ipc.Response`): `status` (`ok`/`error`),
`error` (message, when `status == "error"`), and the action's result in
`pkcs11`. Error text is sanitized: only the invalid-message, sealed-barrier
and autofill-disabled messages reach the client; any other handler failure
reads `handler returned error`, and the cause stays in the GUI's log.
`BarrierStatusResult` is shared with the unrelated `state` message type and
also carries `initialized`, `strategy`, and `hardware_backed` fields, but
`HandlePKCS11BarrierStatus` populates only `sealed` — the other three are
always their zero value on a `pkcs11`/`barrier_status` response.

The socket adds no export path. `export_key_material` returns exactly what
`EmbeddedTransport.ExportKeyMaterial` returns, so a key the backend marks
non-exportable is refused over the socket as it is in-process.

## In-process: `xkms.PKCS11Transport`

Anything already running inside the xkey binary (e.g. `xkey usb device
start` with local app access off) constructs a `pkcs11.EmbeddedTransport` directly and calls its
methods as plain Go — there is no serialization boundary. All 21
`xkms.PKCS11Transport` operations are available this way; see
[engineering.md](engineering.md#exported-surface).

## See also

- [Architecture](architecture.md) — why the GUI, IPC, and in-process paths
  exist separately
- [Engineering](engineering.md) — exported surface, invariants, tests
- [CLI](cli.md) — the flag-driven surface (no IPC/GUI involved)
