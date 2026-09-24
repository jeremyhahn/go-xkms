# Virtual FIDO2 Authenticator — Engineering Contract

> **Status: NORMATIVE** · Feature: `virtual-authenticator` · Module: `go-xkms/xkey` · Last verified: 2026-09-21

## Exported surface

### `xkey/pkg/uhid`

Linux UHID device creation and the HID report wire format:
`uhid_linux.go` (real), `uhid_stub.go` (non-Linux builds), `types.go`,
`serialize.go`, `errors.go`.

### `xkey/pkg/authenticator`

The CTAP2 implementation. One file per command:

| Command | File |
|---|---|
| `authenticatorMakeCredential` | `cmd_makecredential.go` |
| `authenticatorGetAssertion` | `cmd_getassertion.go` |
| `authenticatorGetInfo` | `cmd_getinfo.go` |
| `authenticatorClientPIN` | `cmd_clientpin.go` |
| `authenticatorCredentialManagement` | `cmd_credmgmt.go` |
| `authenticatorConfig` | `cmd_config.go` |
| `authenticatorReset` | `cmd_reset.go` |

Supporting: `authenticator.go`, `authdata.go`, `crypto.go`, `config.go`,
`errors.go`, `hid_adapter.go`, `pin_protocol.go`,
`pin_protocol_v1.go`, `migration.go`.

Extensions: `ext_hmac_secret.go`, `ext_deviceconfig.go`.

Storage seams: `storage.go` (the `StatefulCredentialStorage` /
`ListableStorage` / `ClearableStorage` interfaces), `storage_memory.go`
(`NewMemoryStorage`, the `--storage memory` default), `storage_backend.go`
(`BackendStorage`, adapting any `xkms.StorageBackend` — file or
barrier — to credential storage; this is the one type both the GUI and the
standalone daemon construct, so there is no separate DAO-backed store to
diverge from it), and `dao_rp_policy_store.go` (RP policy storage; unrelated
to credentials). `entity.go` and `dao_credential_store.go` — an unused
`GenericDAO`-backed credential store with zero non-test callers — were
deleted (#181); `BackendStorage` was always the production seam for both the
GUI and the daemon.

Key material: `key_manager.go`, `key_wrapper.go`, `keybackend/`.

PIN state lives on the authenticator as `state.PINHash` with a fixed
`PINHashSize` (`cmd_config.go:474`), and `key_manager.go:253` carries a
`PINSyncPending` path that re-initializes the user PIN when a sync was deferred.

## Configuration — `xkey fido2` flags

Defaults are constants at `xkey/cmd/xkey/cmd/fido2.go:164-170`.

| Flag | Default | Meaning |
|---|---|---|
| `--storage` | `memory` | `memory`, `file`, or `barrier` |
| `--storage-path` | `./data` | path for file storage |
| `--barrier-password` | `""` | barrier password for encrypted storage |
| `--barrier-password-file` | `""` | read it from a file's first line |
| `--name` | `xKey (go-xkms)` | device name the OS sees |
| `--serial` | `""` | device serial; generated when empty |
| `--pin` | `true` | require a PIN |
| `--set-pin` | `""` | establish the initial PIN when the store has none (needs `--pin`; refused if a PIN is already set) |
| `--interactive` | `false` | interactive setup |
| `--require-touch` | `true` | require user presence |
| `--timeout` | `30s` | operation timeout |
| `--backend` | `software` | `software`, `tpm2`, or `phone` |
| `--tpm-device` | `/dev/tpmrm0` | TPM device path |
| `--attestation` | `none` | `none`, `packed`, or `tpm` |
| `--phone-device` | `""` | specific paired phone; default is the default phone |
| `--password-store` | `./data/staticpw` | static password store path |
| `--socket` | `$XDG_RUNTIME_DIR/xkey/xkey.sock` | IPC socket |
| `--default-password` | `""` | password name typed on a bare touch |
| `--notify-command` | `""` | custom notification command |
| `--notify` | `dialog` | `dialog`, `passive`, `log`, or `none` |
| `--unified-pin` | `true` | propagate the host PIN service's user PIN to this authenticator's CTAP2 PIN hash on set/change/verify (`authenticator.Config.UnifiedPIN`); not a PKCS#11 or file PIN sync — go-xkms has one governing PIN backend per device, see go-xkms#307 |
| `--cdp` | `false` | Chrome DevTools virtual-authenticator bridge |
| `--cdp-host` | `localhost` | DevTools host |
| `--cdp-port` | `9222` | DevTools debugging port |

**`--storage memory` is the default**, which means credentials do not survive a
restart unless you choose `file` or `barrier`. That is a safe default for a
first run and the wrong one for daily use.

## Invariants

- **The device is a real CTAP2 authenticator**, not an emulation of a specific
  vendor's. `--attestation` reports what it is.
- **User presence is required, and the handler that collects it is named,
  never defaulted.** `NewAuthenticator` returns
  `ErrUserPresenceHandlerRequired` without one. The daemon installs a
  `SocketHandler` (answered by a dialog or `xkey touch`) or, under
  `--interactive`, an `InteractiveHandler`; a programmatic device passes
  `NewAutoGrantHandler()` explicitly at its construction site.
  `--require-touch` defaults true and only ever narrows the request: off, a
  verified PIN stands in for the touch, and a ceremony with no PIN still asks.
- **User verification is performed, never asserted.** The UV flag is set when
  the ceremony carried a verified PIN or the key backend verified a human
  itself; `getInfo` reports `uv=false` where a PIN is the verification method
  so a browser collects it. No flag or setting reports verification the
  authenticator did not do.
- **The relying party cannot distinguish backends.** `software`, `tpm2` and
  `phone` present identically over CTAP2, so the strength claim is the
  operator's to make honestly.
- **Credential storage and key material are separate seams.** `BackendStorage`
  holds credential records; `keybackend` holds key material. Do not merge them.
- **Key material never transits the ordinary Go heap through the wrapper.**
  `KeyWrapper` has no method that takes or returns a plaintext slice:
  `WrapFrom(src *secure.Buffer)` reads from protected memory the caller owns
  (#387) and `UnwrapInto(wrapped, dst)` writes into a destination the caller
  sized before any borrow (#291). Protected-buffer borrows must not nest, so a
  wrap of one protected key under another goes through `wrapFromProtected`,
  which releases the key borrow before the plaintext borrow is taken. The
  invariants and the deadlock rule are spelled out in
  [`fido2/engineering.md`](../fido2/engineering.md#key-material-handling-in-memory).
- **`--storage memory` loses credentials on exit.** No warning is emitted; it is
  the documented default.
- **go-qrdb's seal barrier is the only at-rest encryption in this stack; xkey
  adds no per-credential wrap of its own on top of it (#181).** `--storage
  barrier` and the GUI's barrier-backed branch construct `BackendStorage`
  over the barrier's `xkms.StorageBackend`, so credential JSON is encrypted
  by the barrier exactly like every other barrier-routed store. `--storage
  file` and the GUI's pre-`barrier init` fallback construct the same
  `BackendStorage` over a plain file backend instead — a `0600` file with no
  encryption of its own, which is a legitimate configuration, not a bug.
  Both plain-file construction sites (`createFIDO2Storage`'s
  `FIDO2StorageTypeFile` case in `xkey/cmd/xkey/cmd/fido2.go`, and the
  no-barrier branch of `initializeDataDir` in `xkey/pkg/gui/app.go`) log one
  `slog.Warn` naming the exposure and pointing at `xkey barrier init` every
  time the store is opened — never a refusal, never a silent fallback.
  `--storage memory` never touches disk and is exempt. `BackendStorage`
  itself (`storage_backend.go`) carries no logger and emits no warning of its
  own; the warning is deliberately at the two call sites that know whether a
  barrier is present, not inside the shared storage type. `xkey fido2
  status`'s `EncryptedAtRest` field (`fido2_status.go`) reports this
  per-store: `true` for `barrier`, `false` for `file` and `memory`.
- **CTAP2 is one command at a time per channel, and the authenticator itself
  now enforces it, not just the transport.** `Authenticator.cmdMu`
  (`authenticator.go`) is held for the whole of `ProcessCBORWithContext` —
  including any user-presence wait the command performs — so a second command
  cannot begin until the first has fully returned. This closes a TOCTOU gap
  (#323): `AuthorizePinUvAuthToken`'s check (`checkPinUvAuthTokenLocked`) and
  its spend (`consumePinUvAuthToken`, `cmd_clientpin.go`) are two separate
  acquisitions of `mu` with a possible user-presence prompt in between, so two
  concurrent commands presenting the same `pinUvAuthToken` could previously
  both pass authorization before either consumed it — a race the detector
  cannot see, because every individual access to the token state is correctly
  synchronized under `mu`; the flaw was that the check and the use were two
  critical sections instead of one. `cmdMu` closes the window by construction
  instead of narrowing it, which also makes the `cmdCtx.Store`/`defer
  Store(nil)` single-command assumption true. The accepted trade: a command
  blocked on user presence blocks every other queued command for the whole
  wait, not just its own critical section — matching how a real CTAP
  authenticator behaves, since it never processes a second command while
  waiting on the first's touch. Every `requestUserPresence` call site releases
  `mu` before it blocks, so `cmdMu` is the only lock held across the wait — see
  `ProcessCBORWithContext`'s doc comment. The HID adapter's own per-channel
  serialization above `cmdMu` is unaffected and still applies.
- **PIN state is `state.PINHash` with a fixed size** — treat it as the
  authenticator's own credential, distinct from the barrier or the OS.
- **A first PIN has one establishment path.** The CTAP `setPIN` subcommand
  (after its wire-level `pinUvAuthParam` proof) and the in-process
  `Authenticator.SetInitialPIN` (the `--set-pin` seeding) both end in
  `establishPINLocked` (`cmd_clientpin.go`): minimum length, retry-counter
  reset, outstanding `pinUvAuthToken` invalidation, then persistence. Neither
  replaces an existing PIN — `SetInitialPIN` refuses with `ErrPINAlreadySet`,
  and the daemon surfaces that as `ErrFIDO2PINAlreadySet` — so a restart with
  `--set-pin` against a persistent store cannot silently rewrite the PIN or
  reset its retry counter. There is no testing-only PIN setter (#377).
- **A first SO PIN has one establishment path too.** The CTAP
  `authenticatorConfig` vendor subcommand `setSOPIN` and the in-process
  `Authenticator.InitializeToken` (which `xkey fido2 init-token` calls) are the
  same method: `handleVendorSetSOPIN` passes straight through to it. It refuses
  an initialized token with `ErrKeyManagerAlreadyInitialized` under the state
  lock, so establishment never replaces. `Authenticator.ChangeSOPIN`
  (`xkey fido2 change-so-pin`, vendor `changeSOPIN`) is the only successor path
  and proves the current PIN by authenticated decryption of the wrapped Admin
  Key, spending a persisted retry on failure. `authenticatorReset` is the only
  way back to uninitialized (#233).
- **`state.SOPINManager.IsSet` is the single source of truth for "initialized".**
  Initialization *is* establishing the SO PIN; a second boolean would only be a
  second thing to disagree. `Authenticator.TokenFlags` derives the PKCS#11
  `CKF_TOKEN_INITIALIZED` / `CKF_SO_PIN_*` view from it, and renders an
  uninitialized token as `uninitialized` rather than as an empty flag set — "no
  flags" and "no Security Officer required" must never read alike.
- **The SO PIN is never stored in the device's own password store.** That store
  is unlocked by the user PIN, and the SO PIN's job is to reset a forgotten user
  PIN; keeping one inside the other makes the recovery credential recoverable
  only by the credential it recovers (#290). It is entered at the prompt and
  held nowhere else.
- **CTAP 2.1 §6.9's bounds on first initialization are real over a transport and
  vacuous on the offline CLI path.** `poweredUpAt` is set in
  `NewAuthenticator`, so a command that constructs the authenticator opens the
  window itself, and the presence prompt asks the operator who just typed the
  PIN. `xkey fido2 init-token` therefore names the control that does apply —
  file permissions on the state directory — instead of reporting a bound that
  cannot fire. Its presence handler is still explicit and interactive, never an
  auto-grant, so a denial refuses.

## Error semantics

`xkey/pkg/authenticator/errors.go` and `xkey/pkg/uhid/errors.go`. CTAP2 status
codes are returned to the consumer, so failures surface as `CTAP2_ERR_*` in a
browser's console rather than as Go errors.

**Fail closed:** no user presence within `--timeout`, wrong PIN, PIN retries
exhausted, an unavailable backend (TPM absent, phone unpaired), or a credential
not present. None of them fall back to a weaker path — in particular, a `tpm2`
backend that cannot reach its TPM does not silently become `software`.

## Persistence

- **`memory`** — nothing survives the process. `storage_memory.go`.
- **`file`** — under `--storage-path` (default `./data`). `BackendStorage`
  over a plain `xkms.StorageBackend`; plaintext at rest (see the at-rest
  invariant above).
- **`barrier`** — the same `BackendStorage` over the barrier's
  `xkms.StorageBackend` instead; encrypted, keyed by the barrier password.

Credential records go through `storage_backend.go`'s `BackendStorage`; key
material through `keybackend` to software, TPM or phone. RP policies are
`dao_rp_policy_store.go`.

`migration.go` handles moving between earlier PIN-state layouts —
`xkey/pkg/gui/migration.go` documents the historical paths
(`<dataDir>/pin-state.json` for the CLI path, `<dataDir>/tpm/pin_state.json`
for the GUI/TPM path) and the deprecated `FilePINManager` they came from.

## Test strategy

- **Unit** — per-command suites in `xkey/pkg/authenticator`, plus PIN protocol,
  extensions, key wrapping, `BackendStorage`, and the RP policy DAO store.
- **UHID** — `xkey/pkg/uhid` serialization and device tests; the stub build is
  compiled on non-Linux.
- **Browser end to end** — Playwright specs against the CDP bridge, and
  `go-xkms/test/integration/webauthn-browser`.
- **Cross-module** — `go-xkms/test/integration/logins` drives xkey against a
  real relying party.

## Observability

`--notify` selects how the user-presence prompt reaches a human: `dialog`
(interactive), `passive` (desktop notification), `log`, or `none`.
**`--notify none` combined with `--require-touch true` produces an
authenticator that waits silently for a touch nobody was asked for** — the
symptom is a browser that hangs until the timeout. `--notify-command` overrides
with a custom command.
