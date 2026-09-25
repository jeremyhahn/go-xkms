# xkeysigner — Architecture

> **Status: NORMATIVE** · Feature: `xkeysigner` · Module: `go-xkms/xkey` · Last verified: 2026-09-24

## Scope

`pkg/xkeysigner` implements Go's `crypto.Signer` by delegating to the
**xKey GUI application** over a Unix domain socket, so a go-xkms process
can authenticate with an mTLS client certificate backed by a PIV key the
GUI holds — without importing any `xkey/pkg/*` package (no import cycle:
`pkg/xkeysigner` lives in the **root `go-xkms` module**, not the `xkey`
submodule, and only talks to xkey over IPC bytes).

```
Application (go-xkms SDK client, xkmsd, CLI, ...)
      |
crypto.Signer (xkeysigner.Signer)
      |
Unix domain socket, JSON messages ($XKEY_IPC_SOCKET or platform default)
      |
xKey GUI app's IPC server (pkg/gui/services.PKCS11IPCHandler)
      |
PIV slot (9a / 9c / 9d / 9e) via the embedded PKCS#11 transport
      |
Hardware or software backend (YubiKey, SoftHSM, TPM2, ...)
```

## The daemon on the other end is the GUI app, not `xkey fido2`

This is the one fact the superseded `xkey/docs/xkeysigner/README.md` left
implicit and worth stating precisely, because it is easy to assume any
running xkey process answers this socket:

- `xkey/pkg/ipc.Handler` (the base interface every IPC server handler must
  satisfy) does **not** include the PKCS#11 methods. A separate,
  optional interface, `ipc.PKCS11Handler`
  (`HandlePKCS11Sign`, `HandlePKCS11GetPIVCertificate`,
  `HandlePKCS11ListPIVSlots`, `HandlePKCS11BarrierStatus`), carries them,
  and the server type-asserts for it per message
  (`xkey/pkg/ipc/server.go:119-130`): `MessageTypePKCS11` fails with
  `ErrHandlerFailed` ("handler does not implement PKCS11Handler") if the
  registered handler doesn't provide it.
- **Only the GUI app registers a handler that implements it.**
  `pkg/gui/app.go`'s `startIPCServer` constructs a `guiIPCHandler`
  wrapping `services.PKCS11IPCHandler`
  (`pkg/gui/services/pkcs11_ipc_handler.go`), which delegates to the GUI's
  embedded PKCS#11 transport. The headless `xkey fido2` daemon
  (`cmd/xkey/cmd/fido2.go`) starts its **own** IPC server on the same
  default socket path with a `fido2Device` handler that implements only
  the base `ipc.Handler` (touch/type-password/status) — sending it a
  `pkcs11` message fails.

Practically: `xkeysigner.NewSigner` only succeeds while the **xKey GUI
application is running** (desktop session, or a headless Wails/GUI process
if one is started that way). A host running only `xkey fido2` cannot serve
xkeysigner requests.

## Why IPC instead of a Go import

The alternative — importing an `xkey/pkg/*` PKCS#11 client type directly —
would create a dependency from the root `go-xkms` module onto `xkey`,
inverting the ownership boundary `xkey/CLAUDE.md`'s SDK-boundary rule
protects (`xkey` consumes `go-xkms` via `sdk/go`; nothing in `go-xkms`
should need to import `xkey`). A small JSON-over-Unix-socket protocol
avoids that entirely: `pkg/xkeysigner` depends on nothing from `xkey`, and
the wire contract (`xkey/pkg/ipc`) is the only coupling.

## Where it's consumed

`sdk/go/xkey_auth.go`'s `xkeyAuthResolver` wraps `xkeysigner.TLSClientConfig`
and `xkeysigner.NewSigner`, and is reached through the public SDK option
`xkms.WithXKeyAuth(socketPath)` (`sdk/go/options.go:255-275`): a go-xkms
SDK client can authenticate to `xkmsd` via mTLS using whatever PIV 9a
certificate the local xKey GUI is presenting, with no certificate or key
material handled by the calling process directly — every signing operation
crosses the socket to the GUI, which is the only thing that ever touches
the private key.

## PIV slots

| Slot | Name | Typical use |
|---|---|---|
| `9a` | Authentication | TLS client auth (the default, and what `WithXKeyAuth` always requests) |
| `9c` | Digital Signature | Document/code signing |
| `9d` | Key Management | Key agreement/wrapping |
| `9e` | Card Authentication | Physical access, contactless |

`SignerConfig.Slot` accepts any of the four; `NewSigner` validates against
`validPIVSlots` and returns `ErrInvalidSlot` for anything else
(`pkg/xkeysigner/signer.go:38-44, 144-150`).

## Trust and failure model

- Each `Sign` call opens a **fresh** socket connection, sends one JSON
  request, reads one response, and closes — there is no persistent session
  or connection pooling (`signer.go:280-306`).
- A 5-second IPC deadline (`ipcTimeout`) applies to the whole
  connect+send+receive round trip, so a hung or absent GUI process fails
  fast rather than blocking a caller indefinitely.
- The barrier gates every operation on the GUI side: `PKCS11IPCHandler`
  calls `checkBarrier()` before delegating to the embedded transport
  (`pkg/gui/services/pkcs11_ipc_handler.go:56-59, 87-90`), so a sealed
  barrier makes `xkeysigner` fail exactly as any other PKCS#11 consumer of
  a sealed key would — there is no separate bypass for this path.
- The private key itself never crosses the socket in either direction;
  only signatures (for `sign`) and the certificate (for
  `get_piv_certificate`) do.
