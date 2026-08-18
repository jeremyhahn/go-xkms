# Headless WebAuthn — Engineering Contract

> **Status: NORMATIVE** · Feature: `headless-webauthn` · Module: `go-xkms/xkey` · Last verified: 2026-08-19

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
| `--setup-token` | `""` | pre-authorized enrolment token |
| `--username` | current OS user | account to enrol |
| `--display-name` | username | human-readable name |

`xkey auth login`:

| Flag | Default | Meaning |
|---|---|---|
| `--server` | — | **required** |
| `--username` | current OS user | account to authenticate |
| `--piv` | `false` | authenticate with a PIV slot certificate over mTLS instead of WebAuthn |
| `--slot` | `9a` (`PIVSlotAuthentication`) | PIV slot, with `--piv` |
| `--backend` | software | PIV key backend: `software` or `pkcs11`, with `--piv` |

`xkey auth status --server <url>`, `xkey auth token --server <url>`,
`xkey auth refresh`, `xkey auth logout`.

## Invariants

- **The relying party is unmodified.** These are the standard
  `/api/v1/webauthn/*` ceremonies; there is no headless-specific endpoint and
  no server-side relaxation.
- **`--spki-pin` is verified before any credential is created.** Enrolling
  against an unverified server is the failure this flag exists to prevent.
- **A setup token is single-purpose and should be short-lived.** It authorizes
  creating a credential.
- **`--piv` is a different authentication path, not a fallback.** It uses mTLS
  with a slot certificate; WebAuthn is not attempted.
- **The default `--username` is the current OS user.** Convenient, and a trap
  in a CI container where that is `root` or a random UID — pass it explicitly.
- **Tokens are session credentials.** `xkey/pkg/tokenstore` holds them; treat
  the store's protection as the credential's protection.
- **Concurrency.** One ceremony at a time per authenticator; the CTAP2 channel
  is not multiplexed.

## Error semantics

Failures surface as the CLI's typed errors over the client's:
`ErrServerURLRequired`, `ErrUsernameRequired`, `ErrRegistrationFailed`,
`ErrAuthenticationFailed`, `ErrServerUnavailable`, `ErrAuthenticatorNotFound`,
`ErrCTAPOperationFailed`, `ErrInvalidServerResponse`, `ErrInvalidChallenge`.

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
