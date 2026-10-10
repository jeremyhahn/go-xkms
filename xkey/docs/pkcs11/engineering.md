# PKCS#11 — Engineering Contract

> **Status: NORMATIVE** · Feature: `pkcs11` · Module: `go-xkms/xkey` · Last verified: 2026-10-10

## Exported surface

### Package `xkey/pkg/pkcs11`

- `EmbeddedTransport` — in-process `xkms.PKCS11Transport` implementation.
  `NewEmbeddedTransport()` fails with `ErrServiceNotInitialized` unless
  `xkms.IsInitialized()`. Implements all 21 `PKCS11Transport` operations
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
  `SocketPath() string`. Implements every operation `EmbeddedTransport`
  does, each as one IPC action (see [api.md](api.md#ipc-wire-protocol-unix-domain-socket));
  `Connect` round-trips `barrier_status` (`ipc_transport.go`).
- Typed errors (`errors.go`): package sentinels (`ErrServiceNotInitialized`,
  `ErrBackendNotFound`, `ErrKeyNotFound`, `ErrNilRequest`,
  `ErrKeyGenerationFailed`, `ErrSigningFailed`, `ErrVerifyFailed`,
  `ErrEncryptionFailed`, `ErrDecryptionFailed`, `ErrDerivationFailed`,
  `ErrWrappingFailed`, `ErrExportFailed`, `ErrImportFailed`,
  `ErrGetImportParamsFailed`, `ErrImportKeyFailed`,
  `ErrIPCConnectionFailed`, `ErrIPCRequestCanceled`) plus two composable
  error types: `DetailError{Err, Detail}` (appends text after a wrapped
  sentinel) and `SentinelCauseError{Sentinel, Cause}` (`Unwrap() []error` —
  both match `errors.Is`).

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
- `EmbeddedTransport` holds no key logic of its own. Each of the thirteen
  key operations (`GenerateKey` through `ImportKey`) is one `callService`
  call (`service.go`): refuse a nil request with `ErrNilRequest`, look up
  the singleton with `xkms.Get()`, and call the matching `XKMSService`
  method (`pkg/xkms/servicer_*.go`) with the request unchanged. So a
  request means the same in-process, over IPC and over every server
  transport. Failures map one way for all of them (`serviceError`): a
  missing key or backend is `ErrKeyNotFound` / `ErrBackendNotFound`; an
  uninitialized service is the operation's sentinel plus
  `ErrServiceNotInitialized`; anything else is the operation's sentinel
  (`ErrKeyGenerationFailed`, `ErrSigningFailed`, …). Every error carries
  the service error. An earlier local key-generation switch knew only RSA,
  ECDSA and Ed25519, so `C_GenerateKey` for an AES or generic secret key
  failed. A local export path also released `CKA_SENSITIVE` keys. With
  delegation, secret keys (`Algorithm: "Symmetric"`, AES-128/192/256)
  generate, and the service's export refusal of sensitive and
  non-exportable keys applies. The PIV operations call the `sdk/go` PIV
  functions directly.
- `EmbeddedTransport.WrapKeyByID`/`UnwrapKeyByID` (`service.go`) are the
  in-process routes for the PKCS#11 `C_WrapKey`/`C_UnwrapKey` primitives,
  through `XKMSService.WrapKeyByID`/`UnwrapKeyByID`
  (`pkg/xkms/servicer_key.go`). That implementation encrypts the
  target key material directly under the caller-designated wrapping key
  (`wrapKeyMaterial`/`unwrapKeyMaterial`, `pkg/xkms/servicer_wrapkey.go`).
  It is deliberately independent of the key-IMPORT ceremony
  (`xkms.ExportKey`/`WrapKey`/`GetImportParameters`), which serves an
  unrelated feature (bringing externally generated material into a
  backend) and always wraps under a freshly generated ephemeral key pair
  — never the caller's own wrapping key — so it can never produce or
  consume a `C_WrapKey`/`C_UnwrapKey` blob (go-xkms#1195).
- `EmbeddedTransport.Sign`/`Verify` (`service.go`) carry no signing rules
  of their own: each is one call to the xkms service's `Sign`/`Verify`
  (`pkg/xkms/servicer_crypto.go`), so a request means the same in-process,
  over IPC and over every server transport. `data_is_digest` signs the
  bytes as the digest `hash` names (wrong length refused); otherwise the
  data is hashed with `hash` (default SHA-256). `padding` selects RSA
  PKCS#1 v1.5 (default) or PSS with `salt_length` (0 = auto, -1 = hash
  length). Ed25519 signs the message, so `data_is_digest` on an Ed25519
  key fails with `xkms.ServiceErrEd25519DigestInput` (use `pre_hash` for
  Ed25519ph). A missing key or backend is reported as `ErrKeyNotFound` /
  `ErrBackendNotFound`; every other failure as `ErrSigningFailed` /
  `ErrVerifyFailed`, with the service error attached.
- `EmbeddedTransport.Encrypt`/`EncryptAsym`/`Decrypt` (`service.go`) are
  likewise one call each to the xkms service's `Encrypt`/`EncryptAsym`/
  `Decrypt`, so every request field reaches the cipher: the AES mode
  (`cbc`, `cbc-pad`, default GCM), IV, nonce, additional data and tag size;
  the OAEP hash and label; and on decrypt the RSA padding (`oaep`, or
  PKCS#1 v1.5 only where the service allows legacy key wrap). Errors map
  as for `Sign`, under `ErrEncryptionFailed` / `ErrDecryptionFailed`.
- `IPCTransport.Close` and `EmbeddedTransport.Close`/`Connect` are no-ops
  by contract: the embedded transport has no connection to hold, and the
  IPC transport opens and closes a fresh socket connection per request
  (`sendMessage`), so there is nothing persistent to tear down.
- `IPCTransport` bounds dialing and each request with
  `defaultIPCTimeout` (10 s), except `generate_key` and `generate_piv_key`,
  which wait `keyGenerationTimeout` (3 min): on-card RSA-4096 generation on
  a YubiKey or smart-card HSM commonly takes a minute or more, and giving
  up early would leave a generated key the caller never received
  (`operationTimeout`, `ipc_transport.go`). Neither is configurable;
  `IPCTransport` has no constructor options. The server bounds only the
  read of the request, never the handler, so a long generation completes.
- Every `IPCTransport` operation honours its caller's context: a context
  that has already ended sends nothing, and one that ends mid-request
  abandons the connection; both fail with `ErrIPCRequestCanceled`, the
  context's error attached. The server runs each handler under a request
  context that ends when the client hangs up or the server stops
  (`requestContext`, `xkey/pkg/ipc/server.go`), and `PKCS11IPCHandler`
  passes it to `EmbeddedTransport`.
- Every `IPCTransport` method rejects a nil request with `ErrNilRequest`
  before dialing, and wraps every failure in its operation's sentinel
  (`ErrSigningFailed`, `ErrWrappingFailed`, ...; `ipc.ErrPKCS11Operation`
  for `GenerateKey` and the PIV operations) with the transport cause
  attached — `ErrIPCConnectionFailed` when no GUI is answering. An `ok`
  response without the operation's result is an error, never a nil success.
- The IPC path never releases more than `EmbeddedTransport` does: each
  `PKCS11IPCHandler` method is one call to the matching embedded method, so
  `export_key_material` refuses a non-exportable key exactly as the
  in-process call does.
- The only xkey caller that picks a transport, `xkey usb device start`,
  picks it from the local app access setting and never falls back: off
  means `EmbeddedTransport`, on means `IPCTransport` plus a `Connect`
  probe, and a failed probe is `ErrUSBDeviceGUINotListening`
  (`usbDevicePKCS11Transport`, `cmd/xkey/cmd/usb_device.go`). The GUI's
  socket, and so the IPC transport, exists only while the setting is on
  and xKey is unlocked ([../gui/architecture.md](../gui/architecture.md)).
- `PKCS11IPCHandler` calls `checkBarrier()` (which calls the injected
  `isSealed` callback) before every operation except
  `HandlePKCS11BarrierStatus`; a sealed barrier fails the request with
  `ipc.ErrBarrierSealed` before the embedded transport is touched. Embedded
  failures return wrapped in `ipc.ErrPKCS11Operation` and are logged; the
  socket peer sees only the sanitized `handler returned error`.
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
| GUI settings | `local_app_access_enabled` (`$XDG_CONFIG_HOME/xkey/gui.json`, default off) | `xkey usb device start` — selects `IPCTransport` when on, `EmbeddedTransport` when off; the GUI opens its socket only when on |
| Environment | `SOFTHSM2_CONF` | `PKCS11Service.ensureSoftHSM2Config` — if already set, xkey does not write a SoftHSM2 config of its own |
| Config file | `backends.local[].category == "pkcs11"`, `backends.local[].pkcs11.library_path` | `PKCS11Service.persistModule` (write) / `App.restorePKCS11Modules` (read) — `xkey/pkg/config.LocalBackendConfig` / `PKCS11BackendConfig` |
| CLI flags | `--pkcs11-library`, `--pkcs11-token`, `--pkcs11-pin`, `--pkcs11-so-pin` (on `xkey piv`) | see [cli.md](cli.md) — bound to viper but not read from a config-file section of their own |

No other environment variable or config-file key drives this feature's
behavior; in particular there is no `pkcs11:` config-file section — the
only persisted state is the `backends.local[]` module-registration entry
above.

## Known gaps

None: every `PKCS11Transport` operation is complete on both transports.

## Tests

- `xkey/pkg/pkcs11/ipc_transport_test.go` — socket-path resolution
  (explicit, env var, default), `Connect` (found/not-found/success),
  `Sign`/`ListPIVSlots`/`GetPIVCertificate` wire shapes, PEM defaulting
  without mutating the caller's request, and for every operation: the
  action sent, nil-request rejection, server error and missing-result
  handling, plus malformed responses; the timeout each action gets, and
  against a slow server a signature timing out while a key generation
  completes under its longer timeout; a context canceled mid-request or
  expiring before the operation's timeout returning `ErrIPCRequestCanceled`.
- `xkey/pkg/ipc/pkcs11_types_test.go`, `pkcs11_server_test.go` — every
  action's validation (missing request, missing required field), JSON
  round trip, dispatch to its handler method, and sanitized handler errors;
  the request context live while the client waits, and canceled when the
  client hangs up or the server shuts down.
- `xkey/pkg/gui/services/pkcs11_ipc_roundtrip_test.go` — every operation
  end to end through a real socket in a temporary directory against the
  real handler and `EmbeddedTransport`: generate/sign/verify, AES-256 keys
  generated with the module's `CKM_AES_KEY_GEN` request (a non-AES size and
  DSA refused), encrypt and
  decrypt (GCM with additional data and a truncated tag, CBC and CBC-PAD
  under the caller's IV, CBC refusing additional data), RSA-OAEP with a
  label decrypted back (a wrong label refused) and PKCS#1 v1.5 decrypt
  refused, HKDF and ECDH derivation, AES key wrap/unwrap with
  export equality, non-exportable key refusal, import parameters for a key
  pair and a secret key, an unknown template and a corrupt import, PIV failures without a card, a canceled key generation
  never dispatched; and for every operation the sealed barrier, no GUI
  answering, a canceled context never dialing, and server-side validation.
- `xkey/pkg/pkcs11/service_sign_test.go` — RSA PKCS#1 v1.5, RSA-PSS (auto
  and hash-length salt) and ECDSA each signed as raw data and as a SHA-384
  digest, every signature checked with the standard library verifier and
  with `Verify`; Ed25519 raw signing, and its refusal of a digest on sign
  and verify; a wrong-length digest and PSS on an ECDSA key refused.
- `xkey/pkg/pkcs11/service_test.go`,
  `service_derivekey_test.go`, `service_exportkeymaterial_test.go` —
  `ErrNilRequest` from every delegated operation, `DeriveKey` (SP800-108 vs.
  HKDF dispatch, stored-key vs. raw-material base keys, non-exportable
  keys, unknown algorithm / two base keys / inapplicable parameter /
  missing base key / nil request / uninitialized service), and
  `ExportKeyMaterial` (canonical algorithm-family reporting, unexportable
  key refusal, bad requests).
- `xkey/pkg/pkcs11/service_embeddedtransport_test.go` — `GenerateKey`
  for RSA, ECDSA, Ed25519 and an AES-256 key that then encrypts and
  decrypts, a non-AES size and an unknown algorithm refused with
  `ErrKeyGenerationFailed`, and a sensitive secret key refused by
  `ExportKeyMaterial`; `WrapKeyByID`/`UnwrapKeyByID` round trips under
  RFC 3394 AES Key Wrap and RSA-OAEP-SHA-256 (wrapped blob differs from the
  plaintext, unwrapped material matches the original via
  `ExportKeyMaterial`), and their error paths (nil request, an unknown
  target, wrapping or unwrapping key as `ErrKeyNotFound`, an unsupported
  algorithm as `ErrWrappingFailed`, the service cause reachable through
  `errors.Is`/`errors.As`).
- `xkey/pkg/gui/services/pkcs11_service_test.go`,
  `pkcs11_service_coverage_test.go`, `pkcs11_service_yubikey_test.go` —
  construction, validation errors, module/slot/token/connection CRUD
  (success and manager-error paths for each), the YubiKey SO-PIN
  requirement, and `TestConnection`'s tested-module cache reuse.
- `xkey/pkg/gui/services/pkcs11_ipc_handler_test.go` — every handler
  method's barrier-sealed rejection, nil-transport and nil-request
  rejection, and wrapping of embedded failures, plus the
  `ipc.PKCS11Handler` interface-compliance check.

## See also

- [Architecture](architecture.md) — why there are two transports and a
  separate GUI manager
- [CLI](cli.md) — `--backend pkcs11` / `--pkcs11-*` flags, by command
- [API](api.md) — GUI bindings and the IPC wire protocol
