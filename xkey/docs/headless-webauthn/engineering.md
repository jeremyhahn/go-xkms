# Headless WebAuthn — Engineering Contract

> **Status: NORMATIVE** · Feature: `headless-webauthn` · Module: `go-xkms/xkey` · Last verified: 2026-09-22

## Exported surface

The ceremony driver is `go-xkms/pkg/webauthn/client` — `NewClient(config)`,
`Register(ctx, req)`, `Login(ctx, req)`, `Available(ctx)`, over an
`AuthenticatorAdapter`. Full contract:
[`../../../docs/webauthn/engineering.md`](../../../docs/webauthn/engineering.md)
§"The headless client".

xkey supplies the adapter (its own authenticator), the CLI
(`xkey/cmd/xkey/cmd/auth.go`, `auth_piv.go`, `auth_session.go`), and storage
(`xkey/pkg/tokenstore`, `xkey/pkg/serverregistry`).

## CLI contract

`xkey auth register`:

| Flag | Default | Meaning |
|---|---|---|
| `--server` | — | **required** — server URL |
| `--spki-pin` | `""` | SPKI SHA-256 pin for certificate pinning |
| `--tls-ca` | `""` | extra PEM CA bundle, on top of the xKey trust store |
| `--setup-token` | `""` | pre-authorized enrolment token |
| `--email` | — | **required** — the canonical login key to enrol |
| `--display-name` | the login key | human-readable name |
| `--pin-stdin` | `false` | read the authenticator's CTAP2 PIN from standard input |
| `--pin` | `""` | the same PIN as a flag value; visible in the process list |

`xkey auth login`:

| Flag | Default | Meaning |
|---|---|---|
| `--server` | — | **required** |
| `--email` | — | **required** — the canonical login key to authenticate |
| `--tls-ca` | `""` | extra PEM CA bundle, on top of the xKey trust store |
| `--piv` | `false` | authenticate with a PIV slot certificate over mTLS instead of WebAuthn |
| `--slot` | `9a` (`PIVSlotAuthentication`) | PIV slot, with `--piv` |
| `--backend` | software | PIV key backend: `software` or `pkcs11`, with `--piv` |
| `--pin-stdin` | `false` | read the authenticator's CTAP2 PIN from standard input (WebAuthn path only) |
| `--pin` | `""` | the same PIN as a flag value; visible in the process list |

## CTAP2 PIN input

Both PIN flags, on every command that takes a PIN, are declared by one helper
and read by one resolver — `addPINFlags` and `resolvePINInput` in
`xkey/cmd/xkey/cmd/pin_input.go`. `xkey unlock` uses the same pair, so the
precedence (`--pin-stdin` -> `XKEY_PIN` -> `--pin`) cannot drift between verbs.

Invariants:

- **An empty resolved PIN is a legitimate value**, not an error: an
  authenticator with no PIN configured needs none. Commands that require one —
  `unlock` — apply that policy themselves.
- **`--pin-stdin` with nothing on standard input is an error**
  (`ErrPINInputStdinEmpty`). Defaulting silently to an empty PIN is what makes
  the subsequent CTAP failure illegible.
- **A command that resolves a PIN without declaring the flags is a wiring
  defect** and is reported (`ErrPINInputFlagsMissing`) rather than silently
  resolving no PIN.
- **The PIN is never logged, printed, or placed in a documented command line.**
  Examples use `--pin-stdin`.

The PIN reaches the authenticator through `CeremonyRequest{OptionsJSON, Origin,
PIN}` (`webauthn_ceremony.go`), which carries it by name: a positional
signature holding `Origin` and `PIN` adjacent would let a transposition send
the PIN to the relying party as an origin.

**`CeremonyRequest.PIN`, `fido2.WebAuthnRegistrationOptions.PIN`,
`fido2.WebAuthnAssertionRequest.PIN` and `fido2.WebAuthnAuthenticationOptions.PIN`
are all `*secure.Secret`** (`go-xkms/sdk/go/secure`), not plain strings: the
resolved PIN is sealed into protected memory by `sealCeremonyPIN` immediately
after `resolvePINInput` returns it, and is never held as plaintext in a
struct. `Authenticator.AuthorizeWithPIN` and the `GetPINToken` step beneath it
open the secret only for the instant the CTAP 2.1 6.5.5.7 pinHashEnc
computation needs its bytes, then destroy the buffer. A nil `*secure.Secret`
is the zero value for "no PIN configured", replacing the empty string.

Registration sets `fido2.WebAuthnRegistrationOptions.PIN`; assertion sets
`fido2.WebAuthnAssertionRequest.PIN`. Both authorize through the one
`Authenticator.AuthorizeWithPIN` path — there is no second authorization route.

## PIN failure reporting

`ceremonyFailure` classifies an authenticator refusal before it reaches the
operator:

| Condition | Result |
|---|---|
| `CTAP2_ERR_PIN_REQUIRED` and no PIN supplied | `ErrWebAuthnPINRequired`, naming the flags that supply one |
| `CTAP2_ERR_PIN_REQUIRED` and a PIN WAS supplied | the ceremony sentinel, verbatim — the authorization was attempted and rejected |
| anything else | the ceremony sentinel, with the cause preserved |

A wrong PIN arrives as `fido2.PINAttemptsError`, which wraps `ErrInvalidPIN`
with the authenticator's own remaining-attempts counter
(`Authenticator.PINRetries`, CTAP 2.1 6.5.5.2), so a key approaching lockout
says so. `errors.Is(err, fido2.ErrInvalidPIN)` still matches.

`xkey auth status --server <url>`, `xkey auth token --server <url>`,
`xkey auth refresh`, `xkey auth logout`.

## Invariants

- **The relying party is unmodified.** These are the standard
  `/api/v1/webauthn/*` ceremonies; there is no headless-specific endpoint and
  no server-side relaxation.
- **`--spki-pin` is verified before any credential is created.** Enrolling
  against an unverified server is the failure this flag exists to prevent.
- **The xKey trust store is a first-class CA source for `auth`.**
  `defaultAuthClientFactory` (`xkey/cmd/xkey/cmd/auth.go`) builds the client's
  `*tls.Config` from the system roots, the trust store `xkey trust add`
  populates, and `--tls-ca`. A CA the operator has added is therefore sufficient
  on its own; pinning is not the only route. It previously read none of them,
  so a correctly-added CA still failed with "certificate signed by unknown
  authority" (#250).
- **A bare `--spki-pin` remains trust-on-first-use.** With no `--tls-ca` on the
  same command line the pin is the trust anchor and no chain is built, so an
  unrelated certificate in the trust store cannot break a working pinned
  invocation. Named together with `--tls-ca`, the pin is additive on top of
  chain validation (`xkms.VerifySPKIPinnedConnection`) rather than discarded.
- **A setup token is single-purpose and should be short-lived.** It authorizes
  creating a credential.
- **`--piv` is a different authentication path, not a fallback.** It uses mTLS
  with a slot certificate; WebAuthn is not attempted.
- **The login key is an email, and it has no default.** The server resolves
  both ceremonies with `GetUserByEmail`, so `--email` is the only identifier
  that reaches a principal; there is no `--username` flag. The old default —
  the current OS user, in a CI container `root` or a random UID — could only
  miss that lookup, and on a relying party with public registration enabled a
  miss is a sign-up that enrols the credential onto an account nobody created.
- **Tokens are session credentials.** `xkey/pkg/tokenstore` holds them; treat
  the store's protection as the credential's protection.
- **Concurrency.** One ceremony at a time per authenticator; the CTAP2 channel
  is not multiplexed.

## Error semantics

Failures surface as the CLI's typed errors over the client's:
`ErrServerURLRequired`, `ErrAuthEmailRequired`, `ErrAuthLoginKeyNotEmail`,
`ErrRegistrationFailed`, `ErrAuthenticationFailed`, `ErrServerUnavailable`,
`ErrAuthenticatorNotFound`, `ErrCTAPOperationFailed`,
`ErrInvalidServerResponse`, `ErrInvalidChallenge`.

**Fail closed:** an SPKI mismatch, an unavailable authenticator, an expired or
invalid setup token, an origin or RP-id mismatch, or an expired ceremony session
all refuse. Nothing falls back to a weaker credential.

Note that the relying party deliberately returns a uniform 401 for every
ceremony failure ([`../../../docs/webauthn/api.md`](../../../docs/webauthn/api.md)),
so the client's error is often the more specific of the two — and the server log
is where the real reason is.

## Configuration

Which server, which account, and which authenticator backend. The last of these
is set where the authenticator runs
([`../virtual-authenticator/engineering.md`](../virtual-authenticator/engineering.md)),
not on the `auth` verbs — a headless login inherits whatever backend the running
`xkey fido2` daemon was started with.

`xkey/pkg/serverregistry` records the servers this xkey knows, so `--server` can
be a known name rather than a full URL after the first enrolment.

## Persistence

Credentials live in the authenticator's store; session tokens in
`xkey/pkg/tokenstore`; server records in `xkey/pkg/serverregistry`.

## Test strategy

- **Cross-module end to end** — `go-xkms/test/integration/logins` builds `xkey`
  and drives real registration and login against a running server. This is the
  suite that actually covers this feature.
- **Client unit** — `go-xkms/pkg/webauthn` client and `SoftwareAdapter` suites.
- **CLI** — `xkey/cmd/xkey/cmd/auth_test.go`, `auth_piv_test.go`,
  `auth_session_test.go`.

## Observability

The relying party's audit records are the authoritative trail — a headless login
appears there like any other. On the client side, an enrolment that fails on an
SPKI mismatch is the one event worth surfacing loudly: it means the server did
not verify, and continuing would have created a credential somewhere unintended.
