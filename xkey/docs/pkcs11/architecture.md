# PKCS#11 — Architecture

> **Status: NORMATIVE** · Feature: `pkcs11` · Module: `go-xkms/xkey` · Last verified: 2026-09-27

## Scope

This folder covers xkey's own PKCS#11 surface: the GUI's module/slot/token
lifecycle management (`PKCS11Service`), the two `PKCS11Transport`
implementations xkey contributes (in-process and IPC-socket), and the
IPC server side that answers them. It does not cover the PKCS#11 module
itself (`cmd/pkcs11-module`, a cgo shared library other applications
`dlopen`) or the PKCS#11 crypto **backend** (a way to store xkms keys on an
HSM) — both are root-owned and documented at
[`../../../docs/pkcs11-provider-module/`](../../../docs/pkcs11-provider-module/)
and [`../../../docs/pkcs11/backend/`](../../../docs/pkcs11/backend/)
respectively. There is no `xkey pkcs11` CLI verb group; PKCS#11 is a
`--backend pkcs11` (or `--device-backend pkcs11`) option accepted by
several unrelated commands — see [cli.md](cli.md).

## The problem

A PKCS#11 module (`cmd/pkcs11-module`) is loaded by a *third-party*
process — Firefox, OpenSSL, `ssh` via an engine, an unrelated crypto.Signer
helper — that has no relationship to xkey beyond dlopen'ing the `.so`. That
process needs to reach whichever xkms instance actually holds the keys and
PKCS#11/HSM sessions. Two shapes of caller exist:

- **In-process**: code running inside the xkey binary itself, where an
  `xkms` service singleton is already initialized in the same address
  space (e.g. `xkey usb device start`, which bridges CCID APDUs to PKCS#11
  operations).
- **Out-of-process**: a module instance loaded into a *different* process
  that needs to reach the one xkey desktop instance holding the unsealed
  barrier and the already-authenticated hardware token session, rather
  than opening (and authenticating) its own competing session against the
  same physical token.

Both shapes need to satisfy the same contract the root module already
defines: `pkcs11module.PKCS11Transport` (`pkg/pkcs11/module/transport.go`),
re-exported as `xkms.PKCS11Transport` (`sdk/go/pkcs11_manager.go:85`). xkey
owns two implementations of it.

## Shape chosen: two `PKCS11Transport` implementations, one per call site

`xkey/pkg/pkcs11.EmbeddedTransport` (`service.go`) delegates every
operation directly to the local `xkms` singleton (`xkms.Get()` /
`xkms.GetBackend()`) — no IPC, no socket. It implements all 20 operations
of `xkms.PKCS11Transport`: key generation, sign/verify, symmetric and
asymmetric encrypt/decrypt, key derivation (HKDF / ECDH), key wrap/unwrap
and import/export, and the seven PIV slot operations. It is the transport
`xkey usb device start` hands to `ccid.NewPKCS11Bridge`
(`xkey/cmd/xkey/cmd/usb_device.go`) so the virtual CCID smartcard device
translates APDUs into PKCS#11 calls in-process, and it is what
`PKCS11IPCHandler` (below) delegates to on the server side.

`xkey/pkg/pkcs11.IPCTransport` (`ipc_transport.go`) is a JSON-over-Unix-socket
client for the out-of-process case: a caller that is not the xkey process
dials the socket a *running* xkey instance already listens on and asks it
to perform the operation using the session that instance holds. Socket
resolution, in order: the constructor argument, the `XKEY_IPC_SOCKET`
environment variable, `~/.xkey/run/xkey.sock`. Each request opens a fresh
connection (`sendMessage`) and closes it; `Close` is a no-op because there
is no persistent connection to release.

## Shape chosen: the IPC wire surface is a deliberate subset, not the full 20

`IPCTransport` implements only `Connect` (round-trips a `barrier_status`
request to prove the socket is live), `Sign`, `ListPIVSlots`, and
`GetPIVCertificate`. Every other method — `GenerateKey`, `Verify`,
`Encrypt`, `EncryptAsym`, `Decrypt`, `DeriveKey`, `DeriveKeyECDH`,
`WrapKeyByID`, `UnwrapKeyByID`, `ExportKeyMaterial`,
`GetImportParameters`, `ImportKey`, `GeneratePIVKey`,
`Store`/`Delete`/`Import`/`ExportPIVCertificate`, `GeneratePIVCSR` —
returns the typed sentinel `ErrIPCNotImplemented`. This mirrors the wire
protocol exactly: `xkey/pkg/ipc`'s `PKCS11Payload` and `PKCS11Handler`
interface (`pkg/ipc/protocol.go`, `pkg/ipc/server.go`) define only four
actions (`ActionSign`, `ActionGetPIVCertificate`, `ActionListPIVSlots`,
`ActionBarrierStatus`) — the operations an out-of-process signing helper
and the PIV/CCID bridge actually need today. Widening the IPC surface to
match `EmbeddedTransport`'s full 20 operations means growing the wire
protocol (a new `PKCS11Payload` field, handler method, and dispatch entry)
per operation; that has not been done for the operations this MVP does not
carry. This is a scope gap, not a design decision to leave unfinished —
see the note in [engineering.md](engineering.md#known-gaps).

## Shape chosen: barrier-gated on the server side, not the client side

`PKCS11IPCHandler` (`xkey/pkg/gui/services/pkcs11_ipc_handler.go`) is the
IPC-server-side counterpart: it implements `ipc.PKCS11Handler` by
delegating to an `EmbeddedTransport` it holds, decoding/encoding the
base64 payload fields the wire format uses. Every handler method except
`HandlePKCS11BarrierStatus` calls `checkBarrier()` first and fails closed
with `ipc.ErrBarrierSealed` when the caller-supplied `isSealed` callback
reports the barrier sealed — `barrier_status` itself must never require an
unsealed barrier, or a caller could never distinguish "sealed" from
"unreachable." The check lives in the handler (the trust boundary
between an untrusted socket peer and the running xkey process), not in
`IPCTransport` on the client side, which has no way to know the remote
barrier's state ahead of a round trip.

## Shape chosen: GUI-only, interactive token/slot lifecycle management

`PKCS11Service` (`xkey/pkg/gui/services/pkcs11_service.go`) is a Wails
binding, not part of the `PKCS11Transport` contract at all. It operates
the root-owned `pkg/pkcs11/manager.Manager` directly (aliased
`xkms.PKCS11Manager` in `sdk/go/pkcs11_manager.go:30`) to register PKCS#11
shared libraries, enumerate slots and tokens, initialize a fresh token (SO
PIN + user PIN), and open/track authenticated sessions per (module, slot).
This stays GUI-only by design: it is an inherently interactive,
credential-entry workflow — PIN and SO PIN prompts, YubiKey
management-key handling, SoftHSM2 auto-configuration — that the CLI's
headless PIV verbs do not need. The CLI instead takes a token's library
path, label, and PIN directly as flags (`xkey piv --backend pkcs11
--pkcs11-library ... --pkcs11-token ... --pkcs11-pin ...`) and lets
`xkms.AutoInitialize` open the session non-interactively; see
[cli.md](cli.md).

`PKCS11Service` does not duplicate the manager's slot-enumeration or
session logic — it is a thin adapter that converts `xkms.PKCS11ModuleInfo`
/ `xkms.PKCS11SlotInfo` into frontend-facing JSON-tagged structs, adds
SoftHSM2 auto-configuration, YubiKey management-key validation, and a
`testedModules` cache so a `TestConnection` probe (used by the setup
wizard to validate a library before committing to it) does not pay a
second `C_Initialize` cost — YubiKey's `libykcs11` enumerates USB/CCID on
every load, which is measurably slow.

## Persistence: config-file backed, not barrier-routed

A registered PKCS#11 module is persisted to the unified xkey config file
as a `config.LocalBackendConfig{Category: "pkcs11", PKCS11: &PKCS11BackendConfig{LibraryPath}}`
entry (`xkey/pkg/config/config.go:220`, `:247`) via `config.Load()` /
`config.Save()`. At GUI startup, `App.restorePKCS11Modules`
(`xkey/pkg/gui/app.go:496`) re-registers every persisted `pkcs11`-category
entry through `PKCS11Service.RegisterModuleFromConfig`, which — unlike
`RegisterModule` — does not re-persist, avoiding a write-on-every-restore
loop. This is plaintext config, not barrier-encrypted state: it holds a
library path and display name, never a PIN or SO PIN, so it carries no
secret to protect.

## Rejected alternative: a parallel GUI-side slot registry

`PKCS11Service` could have kept its own module/slot bookkeeping instead of
calling into `pkg/pkcs11/manager.Manager`. That would duplicate slot
enumeration, hot-plug refresh, and session tracking the root package
already owns for every `xkms` PKCS#11 consumer — exactly the kind of
second implementation this repository's ownership rules forbid. Every
xkey PKCS#11 capability, GUI or CLI, reaches the same root manager or the
same root `PKCS11Transport` contract.

## See also

- [Engineering](engineering.md) — exported surface, invariants, errors, tests
- [CLI](cli.md) — every `--backend pkcs11` / `--pkcs11-*` flag, by command
- [API](api.md) — GUI Wails bindings and the IPC wire protocol
- [User Guide](user.md) — task-oriented usage
- Root PKCS#11 module: [`../../../docs/pkcs11-provider-module/`](../../../docs/pkcs11-provider-module/)
- Root PKCS#11 manager and backend: [`../../../docs/pkcs11/manager.md`](../../../docs/pkcs11/manager.md), [`../../../docs/pkcs11/backend/`](../../../docs/pkcs11/backend/)
