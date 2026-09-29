# PKCS#11 — Engineering Contract

> **Status: NORMATIVE** · Feature: `pkcs11` · Module: `go-xkms/xkey` · Last verified: 2026-09-28

## Exported surface

### Package `xkey/pkg/pkcs11`

- `EmbeddedTransport` — in-process `xkms.PKCS11Transport` implementation.
  `NewEmbeddedTransport()` fails with `ErrServiceNotInitialized` unless
  `xkms.IsInitialized()`. Implements all 20 `PKCS11Transport` operations
  (`service.go`): `GenerateKey`, `Sign`, `Verify`, `Encrypt`, `EncryptAsym`,
  `Decrypt`, `DeriveKey`, `DeriveKeyECDH`, `WrapKeyByID`, `UnwrapKeyByID`,
  `ExportKeyMaterial`, `GetImportParameters`, `ImportKey`,
  `ListPIVSlots`, `GetPIVCertificate`, `GeneratePIVKey`,
  `StorePIVCertificate`, `DeletePIVCertificate`, `ImportPIVCertificate`,
  `ExportPIVCertificate`, `GeneratePIVCSR`; plus no-op `Connect`/`Close`.
- `IPCTransport` — Unix-socket `xkms.PKCS11Transport` implementation.
  `NewIPCTransport(socketPath string) *IPCTransport` (empty path falls
  back to `ipc.DefaultSocketPath()`: `XKEY_IPC_SOCKET`, then the
  `XKEY_HOME`-derived instance socket, then the XDG runtime default).
  `SocketPath() string`. Implements `Connect`, `Sign`, `ListPIVSlots`,
  `GetPIVCertificate`; every other operation returns `ErrIPCNotImplemented`
  (`ipc_transport.go`).
- Typed errors (`errors.go`): package sentinels (`ErrServiceNotInitialized`,
  `ErrBackendNotFound`, `ErrKeyNotFound`, `ErrNilRequest`,
  `ErrSigningFailed`, `ErrVerifyFailed`, `ErrEncryptionFailed`,
  `ErrDecryptionFailed`, `ErrDerivationFailed`, `ErrWrappingFailed`,
  `ErrExportFailed`, `ErrImportFailed`, `ErrGetImportParamsFailed`,
  `ErrImportTemplateUnsupported`, `ErrImportKeyFailed`,
  `ErrIPCConnectionFailed`, `ErrIPCNotImplemented`) plus four composable
  error types: `DetailError{Err, Detail}` (appends text after a wrapped
  sentinel), `MessageError{Msg}` (a preformatted message, no wrapped
  cause), `SentinelCauseError{Sentinel, Cause}` (`Unwrap() []error` — both
  match `errors.Is`), `WrappedError{Msg, Err}`.

### Package `xkey/pkg/gui/services` (PKCS#11 surface)

- `PKCS11Service` — Wails-bound module/slot/token manager
  (`pkcs11_service.go`). `NewPKCS11Service() *PKCS11Service` wraps a fresh
  `xkms.NewPKCS11Manager()`. See [api.md](api.md) for every method.
- `PKCS11IPCHandler` — server side of the IPC wire protocol
  (`pkcs11_ipc_handler.go`). `NewPKCS11IPCHandler(transport
  *pkcs11.EmbeddedTransport, logger *slog.Logger, isSealed func() bool)
  *PKCS11IPCHandler`; implements `ipc.PKCS11Handler`.
- `PKCS11ConnectHook func(moduleID, libraryPath string, slotID uint,
  userPIN, soPin, tokenLabel string)` / `PKCS11DisconnectHook
  func(moduleID string, slotID uint)` — fired by `PKCS11Service.Connect` /
  `.Disconnect` so a caller (the GUI app wiring) can register/unregister
  the connected token as an `xkms` backend for PIV key generation.
- Errors: `ErrPKCS11ServiceNotInitialized`, `ErrPKCS11ModuleRequired`,
  `ErrPKCS11LabelRequired`, `ErrPKCS11SOPINRequired`,
  `ErrPKCS11UserPINRequired`, `ErrPKCS11NoSlotsAvailable`,
  `ErrPKCS11SlotNotFound`, `ErrPKCS11ConfigPersistFailed`.

## Root types consumed, not redefined

`xkms.PKCS11Manager` (`sdk/go/pkcs11_manager.go:30`) is a type alias for
`pkcs11manager.Manager` (root `pkg/pkcs11/manager`), and
`xkms.PKCS11Transport` (`:85`) is a type alias for
`pkcs11module.PKCS11Transport` (root `pkg/pkcs11/module`). Neither type is
redeclared in xkey — `PKCS11Service.SetManager` /
`.GetManager` and the two transports' compile-time assertions
(`var _ xkms.PKCS11Transport = (*EmbeddedTransport)(nil)`, same for
`IPCTransport`) all reference the root aliases directly.

## Invariants

- `EmbeddedTransport` requires `xkms.IsInitialized()` at construction
  time; it never lazily initializes the service.
- `EmbeddedTransport.WrapKeyByID`/`UnwrapKeyByID` (`service.go`) are the
  in-process routes for the PKCS#11 `C_WrapKey`/`C_UnwrapKey` primitives.
  They delegate directly to the `sdk/go` re-exports `xkms.WrapKeyByID` /
  `xkms.UnwrapKeyByID` (`sdk/go/xkms_service.go`), which are process-
  singleton wrappers over `pkg/xkms.WrapKeyByID`/`UnwrapKeyByID`
  (`pkg/xkms/service.go:1916,1930`) and in turn over
  `XKMSService.WrapKeyByID`/`UnwrapKeyByID`
  (`pkg/xkms/servicer_key.go:854,998`). That implementation encrypts the
  target key material directly under the caller-designated wrapping key
  (`wrapKeyMaterial`/`unwrapKeyMaterial`, `pkg/xkms/servicer_wrapkey.go`).
  It is deliberately independent of the key-IMPORT ceremony
  (`xkms.ExportKey`/`WrapKey`/`GetImportParameters`), which serves an
  unrelated feature (bringing externally generated material into a
  backend) and always wraps under a freshly generated ephemeral key pair
  — never the caller's own wrapping key — so it can never produce or
  consume a `C_WrapKey`/`C_UnwrapKey` blob (go-xkms#1195).
- `IPCTransport.Close` and `EmbeddedTransport.Close`/`Connect` are no-ops
  by contract: the embedded transport has no connection to hold, and the
  IPC transport opens and closes a fresh socket connection per request
  (`sendMessage`), so there is nothing persistent to tear down.
- Every `IPCTransport` method not in {`Connect`, `Sign`, `ListPIVSlots`,
  `GetPIVCertificate`} returns `ErrIPCNotImplemented` and performs no I/O.
- `PKCS11IPCHandler` calls `checkBarrier()` (which calls the injected
  `isSealed` callback) before every operation except
  `HandlePKCS11BarrierStatus`; a sealed barrier fails the request with
  `ipc.ErrBarrierSealed` before the embedded transport is touched.
- `PKCS11Service.Connect` refuses a YubiKey library
  (`isYubiKeyLibraryPath`) with an empty `soPin`
  (`ErrPKCS11SOPINRequired`) — YubiKey PIV rejects certificate writes
  under `CKU_USER` without the management key supplied as the SO PIN.
- `PKCS11Service.RegisterModuleFromConfig` never calls `persistModule` —
  only `RegisterModule` (the interactive, user-initiated path) writes to
  config — so restoring modules at startup cannot re-trigger its own
  persistence write.

## Configuration

| Source | Key / variable | Read by |
|---|---|---|
| Environment | `XKEY_IPC_SOCKET` | `pkcs11.NewIPCTransport` — overrides the default socket path when the constructor argument is empty (`ipc_transport.go:54`) |
| Environment | `SOFTHSM2_CONF` | `PKCS11Service.ensureSoftHSM2Config` — if already set, xkey does not write a SoftHSM2 config of its own |
| Config file | `backends.local[].category == "pkcs11"`, `backends.local[].pkcs11.library_path` | `PKCS11Service.persistModule` (write) / `App.restorePKCS11Modules` (read) — `xkey/pkg/config.LocalBackendConfig` / `PKCS11BackendConfig` |
| CLI flags | `--pkcs11-library`, `--pkcs11-token`, `--pkcs11-pin`, `--pkcs11-so-pin` (on `xkey piv`) | see [cli.md](cli.md) — bound to viper but not read from a config-file section of their own |

No other environment variable or config-file key drives this feature's
behavior; in particular there is no `pkcs11:` config-file section — the
only persisted state is the `backends.local[]` module-registration entry
above.

## Known gaps

- **IPC transport is an intentional MVP subset**, not the full
  `PKCS11Transport` contract — see
  [architecture.md](architecture.md#shape-chosen-the-ipc-wire-surface-is-a-deliberate-subset-not-the-full-20).
  Any caller reaching xkey over the IPC socket for `GenerateKey`,
  `Encrypt`/`Decrypt`, key wrap/unwrap, import/export, or PIV
  key/certificate mutation receives `ErrIPCNotImplemented`.

## Tests

- `xkey/pkg/pkcs11/ipc_transport_test.go` — socket-path resolution
  (explicit, env var, default), `Connect` (found/not-found/success),
  `Sign`/`ListPIVSlots`/`GetPIVCertificate` (success, nil request, server
  error, connection refused, malformed response, default format), and
  every not-implemented method.
- `xkey/pkg/pkcs11/service_test.go`,
  `service_derivekey_test.go`, `service_exportkeymaterial_test.go` —
  `applyKeyTemplate` (shared by `GetImportParameters`/`ImportKey`,
  symmetric opt-out, unknown-type rejection), `DeriveKey` (SP800-108 vs.
  HKDF dispatch, stored-key vs. raw-material base keys, non-exportable
  keys, unknown algorithm / two base keys / inapplicable parameter /
  missing base key / nil request / uninitialized service), and
  `ExportKeyMaterial` (canonical algorithm-family reporting, unexportable
  key refusal, bad requests).
- `xkey/pkg/pkcs11/service_embeddedtransport_test.go` —
  `WrapKeyByID`/`UnwrapKeyByID` round trips under RFC 3394 AES Key Wrap
  and RSA-OAEP-SHA-256 (wrapped blob differs from the plaintext, unwrapped
  material matches the original via `ExportKeyMaterial`), and their error
  paths (nil request, unresolvable target/wrapping/unwrapping key,
  unsupported algorithm — every failure surfaces as `ErrWrappingFailed`
  with the `pkg/xkms` cause attached and reachable through
  `errors.Is`/`errors.As`). `pkg/xkms/service_wrapkeybyid_test.go` covers
  the `pkg/xkms.WrapKeyByID`/`UnwrapKeyByID` free functions these delegate
  through: success against an initialized service and `ErrNotInitialized`
  before one.
- `xkey/pkg/gui/services/pkcs11_service_test.go`,
  `pkcs11_service_coverage_test.go`, `pkcs11_service_yubikey_test.go` —
  construction, validation errors, module/slot/token/connection CRUD
  (success and manager-error paths for each), the YubiKey SO-PIN
  requirement, and `TestConnection`'s tested-module cache reuse.
- `xkey/pkg/gui/services/pkcs11_ipc_handler_test.go` — every handler
  method's barrier-sealed rejection, nil-transport rejection, and (for
  `Sign`) invalid-base64 rejection, plus the `ipc.PKCS11Handler`
  interface-compliance check.

## See also

- [Architecture](architecture.md) — why there are two transports and a
  separate GUI manager
- [CLI](cli.md) — `--backend pkcs11` / `--pkcs11-*` flags, by command
- [API](api.md) — GUI bindings and the IPC wire protocol
