# Browser Extension AutoFill — Architecture

> **Status: NORMATIVE** · Feature: `autofill` · Module: `go-xkms/xkey` · Last verified: 2026-10-10

## Scope

End-to-end credential and TOTP autofill for the xKey browser extension:
domain matching, policy, rate limiting and CTAP2 assertion verification
(`go-xkms/pkg/autofill`, root module, reached only through `sdk/go/autofill.go`
per the SDK boundary in `xkey/CLAUDE.md`), the native messaging host and its
extension-pairing ceremony (`xkey/pkg/nativemsg`), the IPC protocol between
the host and either server (`xkey/pkg/ipc`), the `AutoFillService`
(`xkey/pkg/gui/services/autofill_service.go`) that implements it, and the two
processes that can host that service: the desktop GUI
(`pkg/gui/app.go`) and the headless daemon (`xkey extension serve`,
`cmd/xkey/cmd/extension_serve.go`). The browser extension itself
(`xkey/extension/`, TypeScript/Manifest V3) is covered at the level the Go
side needs to reason about the protocol, not exhaustively.

Out of scope: the credential stores autofill reads from
([oath/](../oath/), [password/](../password/)) and the barrier that
encrypts them ([seal/](../seal/)).

## System overview

```
Browser extension (content script + background worker)
    |  stdin/stdout, length-prefixed JSON
    |  X25519 ECDH session encryption (AES-256-GCM) + Ed25519 extension pairing
    v
Native messaging host (xkey extension host / part of xkey extension serve)
    pkg/nativemsg: SessionCrypto (per-connection) + PairingVerifier (persistent identity)
    |  Unix domain socket, JSON (ipc.AutofillPayload / PairingPayload)
    v
IPC server (pkg/ipc)
    |  in-process Go method calls
    v
AutoFillService (pkg/gui/services/autofill_service.go)
    --> StaticPasswordService (credential search/get, see password/)
    --> OATHService (TOTP generation, see oath/)
    --> AppLockService (gate on app lock state)
    --> authenticator.Authenticator (in-process CTAP2 challenge-response)
    --> audit.Logger (compliance trail)
```

Two different processes can host the IPC server and `AutoFillService`: the
desktop GUI (`pkg/gui/app.go`, Wails) and the headless daemon (`xkey
extension serve`) for servers/SSH sessions with no desktop. Both speak the
identical native-messaging and IPC protocol, so the extension does not know
or care which one it is talking to.

Neither runs unless **local app access** is on (`GUIConfig.LocalAppAccessEnabled`,
off by default) and in effect: a verified enterprise policy with
`extension_enabled` false turns it off whatever the setting says. The GUI
opens its socket only while local app access is in effect and xKey is
unlocked, and closes it on lock, seal, disable, a disabling policy and
shutdown (see
[../gui/architecture.md](../gui/architecture.md)). `xkey extension serve`
refuses to start while the setting is off. The same setting enables
`AutoFillService`, replacing the former `BrowserExtensionEnabled` flag, which
left the socket running even with the extension off.

## Components

### Domain matching (`go-xkms/pkg/autofill/domain.go`)

`ExtractDomain`, `ExtractHostname`, `MatchesDomain` (dot-boundary exact or
subdomain match — rejects `evil-github.com` against `github.com`),
`MatchesBaseDomain` (eTLD+1 comparison via `golang.org/x/net/publicsuffix`,
for same-organization multi-subdomain services like AWS console regions),
`MatchesPattern` (leading-wildcard glob, `*.example.com`), and `MatchesEntry`
(the three-strategy match `AutoFillService.SearchCredentials` actually
calls: stored-URL match, then custom `MatchPatterns` glob, then eTLD+1
fallback).

### Policy and rate limiting (`go-xkms/pkg/autofill/policy.go`)

`AutoFillPolicy{FillMode, TOTPPolicy, SessionTimeoutSec,
RequireAuthentication, AllowedDomains, BlockedDomains, MaxFillsPerMinute,
AuditEnabled}` — validated by `Validate()`, domain-checked by
`IsDomainAllowed` (blocked always wins; an empty allow-list permits
everything not blocked). `RateLimiter` is a sliding-60-second-window
counter (`atomic.Int64` limit, mutex-protected timestamp slice).

**`RequireAuthentication` (bool) replaced the field-per-fill PIN check** an
earlier design used; see engineering.md's note on the CTAP2 authentication
this field now gates.

### CTAP2 assertion verification (`go-xkms/pkg/autofill/verifier.go`)

`AssertionVerifier` checks a WebAuthn/CTAP2 assertion produced by xKey's own
in-process virtual authenticator: authenticator-data length, RP ID hash,
user-presence flag, (optionally) user-verification flag, monotonic
signature-counter replay protection, and an ECDSA P-256/SHA-256 signature
over a COSE-decoded public key. `VerifierOptions.AllowMissingUV` exists for
exactly one caller — this feature's own — because the in-process ceremony
that produces the assertion cannot make a genuine UV claim; see the
doc comment at `AutoFillVerifierOptions` (`sdk/go/autofill.go:28`) and
`newAutofillVerifier` (`autofill_service.go`) for the full reasoning. It is
never appropriate for verifying an assertion from an authenticator outside
this process.

### `AutoFillService` (`pkg/gui/services/autofill_service.go`)

The orchestrator. Beyond the search/get/TOTP flow the legacy documentation
described, it also owns:

- **CTAP2 challenge-response authentication** for `GetCredential`, gated by
  `AutoFillPolicy.RequireAuthentication` (or an enterprise policy forcing
  it on): `ensureRegistered` registers (once, persisted to
  `registration.json`) or loads a discoverable CTAP2 credential under RP ID
  `xkey-autofill` on the same virtual authenticator that powers the USB
  FIDO2 device; `authenticateWithCTAP2` then asks it for an assertion (PIN
  hash supplied internally, so the extension never sees it; user presence,
  not verification, is the real signal — see the verifier note above) and
  checks it with an `AssertionVerifier`.
- **`SaveCredential`/`IgnoreDomain`** — the extension can offer to save a
  newly-typed credential; a per-instance in-memory ignore list
  (`sync.Map`) suppresses repeated prompts for a domain.
- **Enterprise policy overrides** (`EnterpriseExtensionPolicy`): an SO can
  force-enable/disable the extension, force `RequireAuthentication` or
  audit logging on, and set domain allow/block lists that layer on top of
  (and always win over) the user's own policy. `UserCanConfigure` governs
  whether the user may change any setting at all
  (`*PolicyDeniedError` otherwise).
- **Fuzzy OATH cross-referencing** (`matchOATHAccount`): a TOTP account is
  offered for a domain when the account's issuer or account name shares a
  substring with the domain's base label — not an exact match, because
  issuers rarely spell a domain exactly (e.g., issuer "GitHub" for
  `github.com`).

### Native messaging (`xkey/pkg/nativemsg`)

Two independent layers, both required before autofill traffic flows:

1. **Per-connection session encryption** (`crypto.go`): ephemeral X25519
   ECDH at connection start, HKDF-SHA256 derives two directional AES-256-GCM
   keys (send/recv assigned by lexicographic public-key comparison so both
   sides agree without extra signaling), monotonic per-direction nonce
   counters reject replays.
2. **Persistent extension identity/pairing** (`pairing.go`): each browser
   extension has an Ed25519 keypair. The *first* connection from an origin
   triggers a pairing ceremony — the host generates a 6-digit code
   (`StartPairing`), the GUI or headless server displays it (via the IPC
   `PairingHandler`, below), the user types it back into the extension,
   and `CompletePairing` persists `{IdentityKey, PairedAt}` keyed by
   origin at `<data dir>/extension/pairing.json` (multi-extension: several
   origins may be paired simultaneously). Every subsequent connection signs
   `SHA-256(ephemeralPubKey || origin || "xkey-ext-v1")` with the identity
   key so the host can verify *this* session belongs to the paired
   extension, not just any process that knows the pairing code once did.
   Repeated pairing-code or identity-signature failures lock out for 15 and
   5 minutes respectively (`maxPairingFailures`/`maxVerifyFailures`). The
   failure counters and lockout deadlines are durable, kept in
   `<data dir>/extension/pairing-limits.json` (0600) beside the pairing
   state (`pairing_limits.go:47,62`) and re-read on every check
   (`pairing_limits.go:120`): the browser launches a fresh native host per
   connection, so an in-memory counter would reset on every relaunch. They
   live in their own file so unpairing cannot clear a lockout, and an
   unreadable or corrupt file fails pairing closed. The pairing code is
   compared in constant time (`pairing.go:261`).
   `--no-pairing` on `extension host`/`extension serve` skips identity
   verification entirely (development only). `VerifyParentProcess` is an
   additional, non-authoritative check (reads `/proc/$PPID/exe` on Linux)
   that the process that launched the host is a known browser binary.

`Host.handshake` sequences the two: X25519 key exchange first, then either
`handshakeWithIdentity` (identity present, already paired: verify and
proceed) or `initiatePairing` (not yet paired: run the code ceremony) before
the relay loop starts. `relayLoop` also re-checks pairing on every message
(`PairingVerifier.Reload` + `IsPairedForOrigin`) so a GUI-side "Unpair" click
disconnects an active session on its next message, without polling.

### IPC protocol (`xkey/pkg/ipc`)

Unix domain socket (mode `0600`, directory mode `0700`; ownership transferred
to `SUDO_UID`/`SUDO_GID` when launched under `sudo`), JSON message framing,
map-based O(1) dispatch by message `type` and, within `autofill`, by
`AutofillPayload.Action`. `AutofillHandler` is the nine-method interface
`AutoFillService` implements (`search`, `get`, `totp`, `totp_by_id`,
`status`, `policy`, `save`, `ignore_domain`, `focus`); `PairingHandler` is
the two-method interface (`HandlePairingNotifyCode`,
`HandlePairingCompleted`) the native host uses to tell whichever server is
running about a pairing ceremony in progress.

### Browser extension (`xkey/extension/`)

Manifest V3, Chrome and Firefox. Background service worker owns the native
messaging connection and encryption; content script detects password/TOTP
fields, injects a fill-icon overlay, and sets values through the native
`HTMLInputElement` setter (to trigger framework change detection); popup
offers manual search. Permissions: `nativeMessaging`, `activeTab`, `tabs`.

## Data flow: credential fill with CTAP2 authentication required

1. User clicks the xKey icon on a password field; content script sends
   `{action:"search", domain:"github.com"}`.
2. Background worker's session (X25519 + paired-identity signature) is
   already established, or established now via the handshake/pairing
   sequence above.
3. `AutoFillService.SearchCredentials` checks preconditions (extension
   enabled, app unlocked), rate limit, domain policy (user + enterprise),
   matches stored passwords via `xkms.AutoFillMatchesEntry`, cross-references
   OATH accounts, audits, and returns matches.
4. User selects a credential; the extension requests
   `{action:"get", id, challenge}` with a fresh random challenge.
5. Because `RequireAuthentication` is true, `GetCredential` calls
   `authenticateWithCTAP2`: the local virtual authenticator prompts for
   touch (and PIN, via its own internal hash) exactly as it would for a
   real WebAuthn ceremony, produces an assertion, and
   `AssertionVerifier.Verify` checks it server-side before the password is
   released.
6. The password (never cached in the extension) fills the form; the
   assertion travels back to the extension as proof authentication
   happened, in case it wants to display that.

## Rejected alternatives

- **Trusting the extension's own claim that PIN/touch happened**, instead
  of verifying a CTAP2 assertion server-side. The assertion is the only
  proof that cannot be forged by a compromised or malicious extension
  process, even though the authenticator that produces it lives in the
  same host process — see `AssertionVerifier`/`VerifierOptions` above.
- **Requiring genuine WebAuthn user verification (UV) for the in-process
  autofill ceremony.** The authenticator only sets UV for a real clientPIN
  ceremony or biometric-capable hardware, neither of which this path uses;
  requiring it would mean requiring a flag only this same process could
  ever fabricate, which verifies nothing. See `VerifierOptions.AllowMissingUV`.
- **One-time pairing code with no persistent identity binding.** A code
  alone would only prove possession at pairing time; the Ed25519 identity
  signature on every subsequent session proves *this* connection is the
  extension that completed that specific pairing ceremony, not merely
  something that once observed the code.

## See also

- [engineering.md](engineering.md) — exported surface, invariants, errors, tests
- [cli.md](cli.md) — `xkey extension` verbs and flags
- [api.md](api.md) — every transport (native messaging, IPC, GUI bindings)
- [user.md](user.md) — task-oriented usage
- [password/](../password/), [oath/](../oath/) — the stores this feature reads
- [seal/](../seal/) — the barrier that encrypts those stores
