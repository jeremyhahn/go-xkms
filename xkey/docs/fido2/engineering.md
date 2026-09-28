# FIDO2 Daemon and GUI Device Host — Engineering Contract

> **Status: NORMATIVE** · Feature: `fido2` · Module: `go-xkms/xkey` · Last verified: 2026-09-28

This file has two halves. The first documents the exported surface this
folder actually owns: the daemon and GUI process composition. The second is a
protocol/security reference for `xkey/pkg/authenticator` — PIN protocol wire
behavior, hmac-secret, credential-management enforcement and the SO/tamper
security model — kept here rather than in
[`virtual-authenticator/engineering.md`](../virtual-authenticator/engineering.md)
because that file documents the package's exported Go surface and CLI
configuration, not its wire-level protocol behavior. Both files describe the
same package; neither repeats the other's tables.

## Exported surface: process composition

### `xkey/cmd/xkey/cmd` (CLI daemon)

`fido2Device` (`fido2.go:634`) is the daemon's composition root:

| Field | Type | Role |
|---|---|---|
| `uhidDevice` | `uhid.Device` | The virtual USB HID device |
| `auth` | `authenticator.Authenticator` | The CTAP2 engine (virtual-authenticator) |
| `hidHandler` | `authenticator.CTAPHIDHandler` | CTAPHID framing on the UHID device |
| `storage` | `authenticator.StatefulCredentialStorage` | Credential persistence |
| `keyBackend` | `keybackend.FIDO2KeyBackend` | Where private keys live |
| `keyboard` | `keyboard.Keyboard` | Types stored passwords |
| `ipcServer` | `ipc.Server` | The daemon's IPC socket |
| `pwStore` | `xkms.StaticPasswordBackendStore` | Backs `xkey touch --password` and browser-extension autofill |
| `socketHandler` | `authenticator.SocketHandler` | Turns an IPC `touch` into a CTAP2 presence answer |
| `notifier` | `notify.Notifier` | Tells a human a touch is pending |
| `cdpBridge` | `cdp.Bridge` | Alternative to UHID under `--cdp` |

CLI verbs this folder owns (see [`cli.md`](cli.md) for flags):

| Verb | File | Purpose |
|---|---|---|
| `xkey touch` | `touch.go` | Approve a pending presence request, or type a password |
| `xkey unlock` | `unlock.go` | Unlock a running instance with a PIN over IPC |
| `xkey fido2 status` | `fido2_status.go` | Report whether the daemon is up and what it stores |
| `xkey fido2 provision-attestation` | `fido2_provision_attestation.go` | Provision the device's attestation identity via the xkms enterprise CA |

`xkey fido2 policy`, `profile`, `init-token` and `change-so-pin` are also
registered on `fido2Cmd` (`fido2_policy.go`, `fido2_init_token.go`), but they
administer the CTAP2 authenticator's SO-gated state, not the daemon process —
they are documented in
[`virtual-authenticator/cli.md`](../virtual-authenticator/cli.md#the-token-lifecycle--init-token-and-change-so-pin).

### `xkey/pkg/ipc`

The daemon's Unix socket protocol (`socket.go`, `protocol.go`, `server.go`,
`client.go`). Message types relevant to this folder:
`MessageTypeTouch`, `MessageTypeTypePassword`, `MessageTypeStatus`,
`MessageTypeUnlock` (`protocol.go:20-27`), served by `ipc.Client`'s `Touch`,
`TypePassword`, `Status` and `Unlock` methods (`client.go:46-134`).
`MessageTypeAutofill`, `MessageTypePKCS11`, `MessageTypePairing` and
`MessageTypeState` share the same socket and server but belong to other
features — autofill to the password vault, `pkcs11` to
[`pkcs11/ipc.md`](../pkcs11/ipc.md), `pairing` to device pairing, `state` to
whichever subsystem (`StatePIN`, `StateBarrier`, `StatePasswordStore`,
`StatePasswordList`) the query names.

Typed errors: `ErrDaemonNotRunning`, `ErrConnectionFailed`,
`ErrSocketPermission`, `ErrTimeout`, `ErrUnlockRefused`,
`ErrUnlockNoResult`, `ErrBarrierSealed` (`errors.go`).

### `xkey/pkg/notify`

`Notifier` (`notifier.go:51`): `NotifyTouchRequired(req *TouchRequest) error`
and `Close() error`. Implementations: `DBusNotifier`, `CommandNotifier`,
`LogNotifier`, `WailsNotifier` (the GUI's event bus), and `MultiNotifier`,
which fans out to several without one failure blocking the rest. Selected by
`--notify` / `--notify-command` (virtual-authenticator owns the flags).

### `xkey/pkg/keyboard`

`Keyboard` (`keyboard.go:79`), constructed by `New` (real `/dev/uinput`
device) or `NewWithDevice` (an injected `DeviceWriter`, for tests). Used by
the daemon and the GUI to type stored passwords via `xkey touch --password`
and default-password-on-bare-touch.

### `xkey/pkg/gui/services` (GUI device host)

`FIDO2DeviceService` (`fido2_device_service.go:80`) runs the UHID bridge
inside the GUI process:

| Method | Purpose |
|---|---|
| `Start(storage, notifier)` / `Stop()` | Bring the UHID device up or down |
| `AttachPresenceHandler(notifier)` | Install a `SocketHandler`, saving the authenticator's prior handler in `priorUPHandler` |
| `ApproveTouchRequest` / `DenyTouchRequest` / `HasPendingTouch` | Answer a pending presence request from the GUI |
| `GetStatus() *FIDO2DeviceStatus` | `Running`, `DeviceName`, `VendorID`, `ProductID`, `HasPending`, `AuthenticatorAvailable` |
| `GetRequireUserPresence` / `SetRequireUserPresence`, `GetUserIntentCheck` / `SetUserIntentCheck` | The GUI's equivalent of `--require-touch` and the user-intent policy |
| `FixUHIDPermissions()` | Best-effort remediation for a `/dev/uhid` permission failure |

`FIDO2Service` (`fido2_service.go:130`) is the management plane behind the
GUI's FIDO2 settings screen — no UHID involvement:

| Method group | Purpose |
|---|---|
| `ListCredentials`, `GetCredential`, `DeleteCredential` | Credential inventory |
| `GetRelyingParties`, `ListRPPolicies`, `GetRPPolicy`, `SetRPPolicy`, `DeleteRPPolicy` | Per-RP policy, same store `virtual-authenticator` documents |
| `ListKeyBackends`, `SetDefaultBackend`, `DefaultBackend` | Selects among `keybackend.CompositeBackend` members |
| `StartPhoneBridge`, `StopPhoneBridge`, `GetBridgeStatus`, `HandleBridgeRequest` | The phone pairing bridge — [`phone-hsm`](../phone-hsm/engineering.md) owns this, not `fido2` |
| `StoreAuthResponse`, `GetAuthResponses`, `GetLatestToken` | Records completed WebAuthn ceremonies for the GUI's own history view |

### `xkey/pkg/virtualdevice`

`NativeVirtualDevice` (`native_virtual_device.go:121`), constructed by
`NewNativeVirtualDevice`. It is the GUI's equivalent of the CLI daemon's
`uhidDevice` + `hidHandler` pair: it owns a UHID device and a
`CTAPHIDHandler`, and exposes `Authenticator() *authenticator.Authenticator`
and `HIDHandler() *authenticator.CTAPHIDHandler` so `FIDO2DeviceService` can
wire the GUI's authenticator instance to it.

## Invariants

- **Two hosts, one engine, never both at once against the same store.**
  Nothing in the code refuses to start a second host — the daemon and the
  GUI simply each construct their own `authenticator.Authenticator`. Running
  both against the same data directory produces two authenticators with two
  independent PIN states and no coordination between them.
- **`Stop` restores the prior presence handler, not a default one.**
  `FIDO2DeviceService.Stop` puts back `priorUPHandler` rather than leaving
  the shared authenticator's presence handler unset, so stopping the UHID
  bridge from GUI settings does not silently downgrade autofill or the
  browser-extension ceremony to no presence handler.
- **`xkey unlock` reports success only from the unlock result, never from
  transport status alone**, and then re-confirms against the daemon's own
  `status` action (`runUnlock`, `confirmUnlocked` in `unlock.go`). A daemon
  that grants the app-lock release but leaves a governed subsystem (for
  example the barrier) still locked reports `ErrUnlockIncomplete` naming
  which subsystems opened and which did not, rather than a bare "unlocked".
- **Attestation provisioning fails closed before touching the device.**
  `connectAttestationCA` dials and completes the CA handshake before any key
  is generated, so an unreachable CA is reported as
  `ErrAttestProvisionCAUnreachable` with the device left untouched, not as a
  half-provisioned identity.
- **`provision-attestation` refuses on volatile storage.** `--storage
  memory` would discard a provisioned identity the moment the daemon exits,
  so the command refuses up front with
  `ErrAttestProvisionVolatileStorage` rather than provisioning something
  that cannot survive a restart.

## Protocol reference: `xkey/pkg/authenticator`

The exported Go surface (types, storage seams, key wrapping) is
`virtual-authenticator`'s to document. What follows is wire-level and
security behavior that has no other home in the five-file docs.

### PIN protocol v1 and v2

The CTAP path implements both in `cmd_clientpin.go`: `agreeSharedSecret`
(`cmd_clientpin.go:1060`) performs ECDH against the key `getKeyAgreement`
handed out and applies the protocol's kdf, returning a `pinSharedSecret`
(`cmd_clientpin.go:1034`); `verifyPinAuth` (`:1152`), `encryptData` (`:1279`)
and `decryptData` (`:1323`) are the protocol's `verify`, `encrypt` and
`decrypt`. `deriveSharedSecret` (`:1135`) is the clientPin wrapper that also
records the session's active protocol and keys. `authenticatorGetInfo`
advertises `pinUvAuthProtocols: [2, 1]` — the client picks per request.

| | Protocol 1 (CTAP 2.0) | Protocol 2 (FIDO 2.1, preferred) |
|---|---|---|
| Shared secret | `SHA-256(ECDH(a, bG).x)` | `HKDF-SHA-256(Z)`, separate HMAC and AES keys |
| Encryption | AES-256-CBC, zero IV | AES-256-CBC, random IV prepended to ciphertext |
| Authentication | HMAC-SHA-256, truncated to 16 bytes | HMAC-SHA-256, full 32 bytes |

### pinUvAuthToken authorization and lifetime

Every command that consumes a `pinUvAuthToken` checks, in order: the token's
lifetime timers, the authenticity of `pinUvAuthParam`, the permission bit the
command needs (`mc`, `ga`, `cm`, `acfg`), and — if the token is RP-bound — that
the request's RP ID matches. Any failure returns the same
`CTAP2_ERR_PIN_AUTH_INVALID`, so a caller cannot distinguish which check
refused it (`cmd_clientpin.go`).

A token has two independent expiries (CTAP 2.1 §6.5.2.1): 30 seconds of
inactivity, and 10 minutes of total life regardless of use. It is wiped, not
merely dereferenced, when either elapses, and does not survive
`authenticatorReset` or a process restart.

**Clearing after a presence-testing operation.** After a `makeCredential`, or
a `getAssertion` that collected presence, the token retains only the `lbw`
permission and its `userVerified` flag is cleared (CTAP 2.1 §6.1.2, §6.2.2,
§6.5.5.7) — one user verification authorizes one credential operation, and
the platform must obtain a fresh token for the next one. A silent assertion
(`up=false`) spends nothing, which is what lets conditional UI keep
discovering credentials on one token.

### Minting a pinUvAuthToken: PIN only (go-xkms#1145)

A token comes from exactly one place, `getPinUvAuthTokenUsingPinWithPermissions`
(subcommand `0x09`, `cmd_clientpin.go:725`), and every mint goes through
`beginUsingPinUvAuthTokenLocked` (`cmd_clientpin.go:1286`), which sets the
token's `userVerified` flag.

`getPinUvAuthTokenUsingUvWithPermissions` (subcommand `0x06`) is refused with
`CTAP2_ERR_INVALID_SUBCOMMAND` for every backend (`cmd_clientpin.go:278`). It
used to treat a backend's `HandlesUserVerification` capability as an implicit
successful verification. The phone backend reports that capability
(`pkg/phone/phone.go:459`), so any local HID client could mint a `cm`, `acfg`
or `lbw` token without anyone being verified, then enumerate or delete
resident credentials or change configuration. The capability means the backend
verifies the user *inside its own key operation*: the phone's biometric gates
`Sign` and `GenerateCredentialKey`. It is not a verification that can be run
on demand (`keybackend/keybackend.go:65`), and the pairing protocol has no
biometric-gated "verify user" call whose result the authenticator could check.
Until one exists, the capability sets the UV flag on the `makeCredential` or
`getAssertion` whose signature the phone produced and nothing else; see the
next section for how that is decided per credential.

`getInfo` keeps the two consistent. `supportsPinUvAuthToken`
(`cmd_getinfo.go:322`) gates `FIDO_2_1`, `credMgmt` and `pinUvAuthToken` on the
PIN alone. `uv=true` is advertised for a verifying backend only when there is no
`pinUvAuthToken` surface (`cmd_getinfo.go:231`), because CTAP 2.1 §6.4 reads
`uv=true` next to `pinUvAuthToken=true` as a promise that subcommand `0x06`
works. `xkey fido2` always enables credential management, which forces the PIN
on (`config.go:594`), so the phone daemon reports `uv=false`,
`pinUvAuthToken=true`: the browser collects the PIN, and the phone still asks
for the biometric on every signature.

### Backend UP and UV are per credential (go-xkms#1162)

A key backend can collect user presence (UP) and verify the user (UV) inside
its own key operation, as the phone's biometric prompt does. The authenticator
relies on that only for the backend that owns the credential key, never for
the key backend as a whole. It asks
`FIDO2KeyBackend.HandlesUserPresenceFor(backendID)` and
`HandlesUserVerificationFor(backendID)` (`keybackend/keybackend.go:127`,
`:134`) with the credential's `BackendID`, through
`backendHandlesUserPresenceFor` and `backendHandlesUserVerificationFor`
(`cmd_getinfo.go:360`, `:342`).

- getAssertion skips its local presence check, including the user-intent
  check, only when the owning backend collects presence
  (`cmd_getassertion.go:833`, `:896`). It sets UV without a `pinUvAuthParam`
  only when the owning backend verifies (`cmd_getassertion.go:973`).
- makeCredential sets UV without a `pinUvAuthParam` only when the backend
  that created the key verifies. That backend is the `handle.BackendID()`
  returned by `generateCredentialKeyPair` (`cmd_makecredential.go:434`, and
  `:1687` for the Go API).

`CompositeBackend` routes both questions to the member registered under
`backendID`, the same routing `Sign` uses. An empty or unregistered ID answers
false (`keybackend/composite.go:138`, `:150`), so the local presence check runs
and no UV is claimed. The phone answers true only for its own backend type
(`pkg/phone/phone.go:440`, `:446`). `BackendAdapter` answers from its
capabilities, and no go-xkms provider claims either
(`keybackend/adapter.go:88`, `:95`). Previously the composite OR-merged both
capabilities, so registering a phone skipped the local presence check and set
UP and UV on every software- and TPM-held credential as well.

On a composite, `Capabilities().HandlesUserPresence` and
`HandlesUserVerification` are now the AND across its members, and false when
it has none (`keybackend/composite.go:97`, `:122`, `:125`). This is a lower
bound that holds for every credential, so it is used only where the owning
backend is not known yet:

- makeCredential's presence and user-intent checks run before the key exists
  (`cmd_makecredential.go:300`, `:348`, `:1606`). A mixed composite always runs
  the local check, even when a phone is the default and will then prompt for
  its biometric as well. Only a composite whose every member collects presence
  skips it.
- The `excludeList` credProtect check also runs before key generation
  (`cmd_makecredential.go:357`, `:1618`). In a mixed composite, a
  `userVerificationRequired` credential is matched only with platform UV.
- `getInfo`'s `uv` and `makeCredUvNotRqd` options (`cmd_getinfo.go:231`,
  `:265`). A software-plus-phone composite does not advertise `uv=true`.
  `getInfo` makes no presence claim, and `up` keeps its default.

`getNextAssertion` replays the first assertion's UP and UV flags for the rest
of the batch, as CTAP 2.1 §6.3 requires. This is unchanged.

These tests in `cmd_composite_gesture_test.go` cover this over CTAP:
`TestCompositeUV_FlagComesFromOwningMember`,
`TestCompositeUV_UnknownOwnerClaimsNothing`,
`TestCompositeUV_GetInfoDoesNotAdvertiseUV`,
`TestCompositeUP_LocalCheckUnlessOwnerCollectsPresence` and
`TestCompositeUP_UnknownOwnerRunsLocalCheck`.

### Brute-force PIN retry ordering (go-xkms#686)

`changePIN`, `getPinToken` and `getPinUvAuthTokenUsingPinWithPermissions` all
funnel through `verifyPinHashAndConsumeRetryLocked`
(`cmd_clientpin.go:926`), which decrements and **persists** the retry
counter before comparing the guess, and fails the whole operation closed if
that persist fails — a caller cannot learn whether an untested guess was
right by racing a flaky store. A correct guess resets the budget to
`PINMaxRetries` (default 8) and persists that too, before returning. The
budget survives a restart because every step persists before the caller ever
sees a result.

### hmac-secret extension

`processHMACSecret` (`ext_hmac_secret.go:122`) implements the getAssertion
processing of CTAP 2.1 §12.5. It is the only hmac-secret code path; it runs
from `processAssertionExtensions` (`cmd_getassertion.go:1132`), which
`buildSignedAssertion` (`cmd_getassertion.go:982`) calls **before** it spends a
`signCount` value, so a refused input does not advance the counter.

The input is an integer-keyed map (`parseHMACSecretInput`,
`ext_hmac_secret.go:196`): `1` keyAgreement (the platform's COSE_Key), `2`
saltEnc, `3` saltAuth, `4` pinUvAuthProtocol (optional, default 1). The
WebAuthn client input — plaintext `salt1`/`salt2` — is never an authenticator
input and is refused.

| Step | Behavior | Refusal (CTAP status) |
|---|---|---|
| User presence | The assertion must set UP; `up=false` is refused, as §12.5 requires ("If "up" is set to false, authenticator returns CTAP2_ERR_UNSUPPORTED_OPTION") | `ErrHMACSecretUserPresenceRequired` (`UNSUPPORTED_OPTION`) |
| Parse | integer keys, byte-string saltEnc/saltAuth, protocol 1 or 2 | `ErrHMACSecretInvalidInput` (`INVALID_PARAMETER`) |
| decapsulate | `agreeSharedSecret` against the current `getKeyAgreement` key — the same ECDH and kdf the clientPin subcommands use, without touching the clientPin session's state | `ErrHMACSecretInvalidInput` (`INVALID_PARAMETER`) |
| verify | `saltAuth == authenticate(shared secret, saltEnc)`, constant time | `ErrHMACSecretSaltAuthMismatch` (`PIN_AUTH_INVALID`) |
| decrypt | `decryptData` must yield exactly 32 or 64 bytes | `ErrHMACSecretInvalidSalt` (`INVALID_PARAMETER`) |
| CredRandom | `CredRandomWithUV` if the assertion's UV bit is set, else `CredRandomWithoutUV`; a credential with no hmac-secret key gets no output (§12.5: the extension is ignored) | — |
| Output | `HMAC-SHA-256(CredRandom, salt1)`, followed by `HMAC-SHA-256(CredRandom, salt2)` when a second salt was sent, encrypted under the shared secret with the protocol's `encrypt` (`encryptData`) | — |

**CredRandom derivation.** A credential stores one 32-byte random secret,
`StoredCredential.HMACSecretKey`, generated at makeCredential
(`cmd_makecredential.go:414`). `deriveCredRandom` (`ext_hmac_secret.go:180`)
derives the two CredRandom values from it with HKDF-Expand-SHA-256 under the
distinct info labels `xkey hmac-secret CredRandomWithUV` and
`xkey hmac-secret CredRandomWithoutUV` (`ext_hmac_secret.go:42`). The two are
independent pseudorandom keys, so a secret obtained without UV reveals nothing
about the one released only with UV. Storing two secrets instead would widen
the credential record and every storage backend for no security gain.

The credential secret, CredRandom, the shared secret, the salts and the
plaintext outputs are wiped after use; only the encrypted output leaves the
authenticator. The refusal sentinels unwrap to the status sentinel they map to
(`hmacSecretError`, `ext_hmac_secret.go:50`), so `errors.Is` matches both.

Tests (`ext_hmac_secret_test.go`) drive the authenticator with the repository's
own client, `pkg/fido2` (`DeriveSecret`, `PINUVAuthSession`), over an in-memory
CTAPHID loopback: protocols 1 and 2, with and without UV, one and two salts,
output stability, every refusal above, and that a refusal leaves `signCount`
unchanged.

### credProtect enforcement and the no-oracle guarantee

Per CTAP 2.1 §12.1, applied identically on the assertion path, the
`excludeList` check, and the transport's no-credentials deferral heuristic
(`authenticator.go:729`):

| Level | Usable when |
|---|---|
| 1 (`userVerificationOptional`) | Always |
| 2 (`userVerificationOptionalWithList`) | Named in an allowList, or user-verified |
| 3 (`userVerificationRequired`) | User-verified, however named |

A credential the request may not use is reported as **absent**
(`CTAP2_ERR_NO_CREDENTIALS`), indistinguishable from not holding it — because
reporting "exists but protected" would turn the protection level into the
existence oracle it exists to prevent. The same filtering governs whether a
multi-authenticator deployment defers a `getAssertion` to another device:
deferral is observable on the wire, so a deferral that ignored protection
levels would be a second oracle beside the assertion path.

### Tamper lock

`Authenticator.TamperDetected` (`authenticator.go:208`, an `atomic.Bool`) is
set when the SO-signed policy HMAC fails verification at authenticator
startup. `requirePolicyIntegrity` (`authenticator.go:609`) gates every
user-mode CTAP command and the Go API `MakeCredential`/`GetAssertion` behind
it, refusing with `ErrPolicyTamperLocked` (`CTAP2_ERR_INTEGRITY_FAILURE`,
`errors.go:40`) while it is set. `getInfo` and `selection` still answer —
refusing discovery would make a locked device indistinguishable from a dead
one — and `getInfo` reports the vendor option `policyTamperLocked: true`
while locked (`cmd_getinfo.go:45-49,288-289`).

A policy signed under an older field-set schema reports
`ErrPolicySchemaChanged` instead (`policy.go:315`) and does **not** set
`TamperDetected` — a routine upgrade must never read as an attack.

**Recovery**: the Security Officer re-signs the policy over the
configuration the device actually has and re-opens the authenticator.
Nothing clears the flag at runtime; verification is a startup-only event.

### SO PIN and the token lifecycle: security reference

The CLI-facing lifecycle (`init-token`, `change-so-pin`, the
uninitialized/initialized state machine) is documented in
[`virtual-authenticator/engineering.md`](../virtual-authenticator/engineering.md)
and [`cli.md`](../virtual-authenticator/cli.md#the-token-lifecycle--init-token-and-change-so-pin).
The retry mechanics beneath it:

`SOPINManager` (`so_pin.go`) verifies in three explicit calls —
`BeginVerify(pin)` spends one retry up front and returns the candidate SMK,
`ConfirmVerified()` commits success, `RecordFailure()` commits failure — so a
caller that crashes or never reports back cannot obtain a free attempt.

| Control | Value | Behavior |
|---|---|---|
| Total retry budget | 8 (`DefaultSOPINMaxRetries`) | Exhausted → `ErrSOPINBlocked`, terminal until `authenticatorReset` |
| Consecutive failures per power cycle | 3 (`PINMaxConsecutiveFailures`) | Reached → `ErrSOPINAuthBlocked`; resumes only after a restart |
| Persistence | Budget persisted; consecutive counter not | A restart clears the power-cycle block, never the budget |

The user PIN applies the same consecutive-failure rule (CTAP 2.1 §6.5.5.5)
through the same counter type, `pinMismatchGuard` (`pin_mismatch.go:24,72`),
which `SOPINManager` also uses. Every `pinHashEnc` check — `changePIN`,
`getPinToken`, `getPinUvAuthTokenUsingPinWithPermissions` — goes through
`verifyPinHashAndConsumeRetryLocked` (`cmd_clientpin.go:969`):

| Control | Behavior |
|---|---|
| Retry budget | Spent and persisted before the comparison; exhausted → `ErrPINBlocked` (`CTAP2_ERR_PIN_BLOCKED`) |
| Mismatch | Regenerates the keyAgreement key (`regenerateKeyAgreementLocked`, `cmd_clientpin.go:1045`), so the platform must run key agreement again; an existing pinUvAuthToken is kept |
| 3 consecutive mismatches | `ErrPINAuthBlocked` (`CTAP2_ERR_PIN_AUTH_BLOCKED`) even with retries left; every further attempt is refused without spending a retry, and `getPINRetries` reports `powerCycleState: true` (`cmd_clientpin.go:310`) |
| Correct PIN | Clears the consecutive count and restores the budget |
| Restart / `authenticatorReset` | Clears the consecutive count (it lives in `authenticatorPINState`, `cmd_clientpin.go:230`, never persisted) |

`authenticatorConfig` (`0x0D`) carries the vendor-prototype subcommand
`AuthConfigCmdVendorPrototype` (`0x80`); the operation is then selected by a
vendor command ID nested inside it (`cmd_config.go`):

| Subcommand | ID | Dispatches to |
|---|---|---|
| `VendorCmdSetSOPIN` | `0x01` | `Authenticator.InitializeToken` |
| `VendorCmdChangeSOPIN` | `0x02` | `Authenticator.ChangeSOPIN` |
| `VendorCmdUnlockWithSOPIN` | `0x03` | `Authenticator.UnlockSO` |
| `VendorCmdResetUserPIN` | `0x04` | SO resets a locked user PIN |
| `VendorCmdReplaceAttestKey` | `0x05` | Generates the attestation key and a CSR |
| `VendorCmdGetTokenInfo` | `0x06` | `Authenticator.TokenFlags` — read-only |
| `VendorCmdSetRPPolicy` | `0x07` | Set/update a per-RP policy |
| `VendorCmdGetRPPolicy` | `0x08` | Read-only |
| `VendorCmdDeleteRPPolicy` | `0x09` | Delete a per-RP policy |
| `VendorCmdListRPPolicies` | `0x0A` | Read-only |
| `VendorCmdSetProfile` | `0x0B` | Set the authenticator profile |
| `VendorCmdSetAttestCert` | `0x0C` | Installs the CA-issued chain (`provision-attestation`'s second step) |

`VendorCmdReplaceAttestKey` and `VendorCmdSetAttestCert` are the two CTAP
operations `xkey fido2 provision-attestation` (`cli.md`) drives from the
command line — the only host-side caller of either.

### Key material handling in memory

The authenticator's `KeyManager` holds four unwrapped keys while unlocked —
Admin Key, Credential Master Key, Storage Master Key, User Master Key — each
in memguard-backed protected memory (`secure.Buffer`): mlocked, canary-guarded,
and deterministically wiped on release. `KeyWrapper.UnwrapInto` decrypts into
a caller-supplied destination sized before any borrow, and `WrapFrom(src
*secure.Buffer)` reads from a borrow the caller owns — neither method can
express a plaintext slice the caller does not control (go-xkms#291,
go-xkms#387). Because protected-buffer borrows must not nest, wrapping one
protected key under another goes through `wrapFromProtected`, which releases
the wrapping-key borrow before the plaintext borrow is taken.

## Error semantics

Daemon and GUI-host errors are typed and declared at the package or file
level, never constructed inline: `touch.go` (`ErrTouchDaemonNotRunning`,
`ErrTouchFailed`), `unlock.go` (`ErrUnlockDaemonNotRunning`,
`ErrUnlockMissingPIN`, `ErrUnlockFailed`, `ErrUnlockStillLocked`,
`ErrUnlockIncomplete`), `fido2_status.go` (`ErrFIDO2StatusDaemonNotRunning`,
`ErrFIDO2StatusFailed`), `fido2_provision_attestation.go` (eleven
`ErrAttestProvision*` sentinels covering storage, SO auth, CA reachability
and chain installation), `pkg/gui/services/fido2_device_service.go`
(`ErrFIDO2DeviceAlreadyRunning`, `ErrFIDO2DeviceNotRunning`,
`ErrFIDO2UHIDNotAvailable`, `ErrFIDO2StorageRequired`,
`ErrFIDO2UHIDSetupFailed`), `pkg/gui/services/fido2_service.go` (nine
`ErrFIDO2*` sentinels for credential, RP-policy, token-store and backend
lookups).

CTAP2 status codes returned by the authenticator itself are
`virtual-authenticator`'s to document.

## Test strategy

- **CLI**: `fido2_test.go`, `fido2_backend_selection_test.go`,
  `fido2_cdp_test.go`, `fido2_device_fingerprint_test.go`,
  `fido2_init_token_test.go`, `fido2_passkey_store_warning_test.go`,
  `fido2_phone_bridge_test.go`, `fido2_policy_test.go`,
  `fido2_policy_partial_test.go`, `fido2_provision_attestation_test.go`,
  `fido2_set_pin_test.go`, `fido2_status_store_test.go`, `touch_test.go`,
  `unlock_test.go` — all in `xkey/cmd/xkey/cmd`.
- **GUI**: `fido2_device_service_test.go`,
  `fido2_device_service_presence_test.go`, `fido2_service_test.go`,
  `fido2_service_enrollment_test.go` in `xkey/pkg/gui/services`.
- **Cross-module**: `go-xkms/test/integration/{webauthn-browser,logins}`
  exercise the daemon end to end; see
  [`virtual-authenticator/engineering.md`](../virtual-authenticator/engineering.md#test-strategy).
