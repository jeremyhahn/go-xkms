# WebAuthn Relying Party — Architecture

> **Status: NORMATIVE** · Feature: `webauthn` · Repo: `go-xkms` · Last verified: 2026-09-04

## The problem

Passwords are the weakest credential in the stack, and every project in the
portfolio needs to authenticate someone. Written per project, that is five
relying-party implementations with five sets of origin-checking bugs.

`pkg/webauthn` is the **one** WebAuthn relying party in the portfolio. Every
binary in the stack reaches it through the QuicBaaS SDK re-export; nobody
implements a second one.

## Shape chosen: a service over three pluggable stores

`pkg/webauthn.Service` (`service.go:43`) holds the ceremony logic. Everything it
persists goes through three interfaces (`interfaces.go`), so the same relying
party runs against memory in tests and against go-qrdb in production:

```go
type UserStore interface {
	GetByID(ctx, userID []byte) (User, error)
	GetByEmail(ctx, email string) (User, error)
	Create(ctx, email, displayName string) (User, error)
	Save(ctx, user User) error
}

type SessionStore interface {
	Save(ctx, data *webauthn.SessionData) (string, error)
	Get(ctx, sessionID string) (*webauthn.SessionData, error)
	Delete(ctx, sessionID string) error
}

type CredentialStore interface {
	Save(ctx, cred *Credential) error
	GetByUserID(ctx, userID []byte) ([]*Credential, error)
	GetByCredentialID(ctx, credID []byte) (*Credential, error)
	Update(ctx, cred *Credential) error
}
```

Token issuance is a fourth seam:

```go
type JWTGenerator interface {
	GenerateToken(ctx, user User) (string, error)
}
type TokenPairGenerator interface {
	GenerateTokenPair(ctx, user User) (access, refresh string, err error)
}
```

`TokenPairGenerator` is detected with a **type assertion** by the ceremony
handlers, and a plain `JWTGenerator` still works. That is why `Service` has both
`FinishRegistration`/`FinishLogin` (single token) and
`FinishRegistrationPair`/`FinishLoginPair` (access + refresh): the pair variants
exist without forcing every embedder to supply refresh tokens.

Implementations shipped: `memory_stores.go` (tests), `qrdb_userstore.go` and
`backend_stores.go` (production, through `go-qrdb/sdk/go`).

Rejected alternatives:

- **One relying party per project.** Rejected — see the problem statement.
- **A hard dependency on go-qrdb for storage.** Rejected: the store interfaces
  keep the RP testable in memory and let a composer choose the backing store.
- **Baking token issuance in.** Rejected: JWT shape and lifetime are the
  composer's decision, so it is an interface.

## Component boundaries

| Piece | Package | Owner |
|---|---|---|
| RP ceremonies, policy | `pkg/webauthn` | go-xkms |
| HTTP ceremony handlers | `pkg/webauthn/http`, `pkg/api/rest` | go-xkms |
| Headless client ("browser") | `pkg/webauthn/client` | go-xkms |
| Mock authenticator | `pkg/webauthn/mock_authenticator.go` | go-xkms |
| Stores (production) | `qrdb_userstore.go`, `backend_stores.go` over `go-qrdb/sdk/go` | store is **go-qrdb's** |
| Credential-store decoration (composed host) | `rest.WebAuthnServiceParams.CredentialStoreDecorator` → `apimodule.WithWebAuthnCredentialStoreDecorator` | the **composing host** supplies it |
| The user identity itself | go-qrdb | **go-qrdb** |
| CTAP2 client talking to real hardware | `pkg/fido2` — [`../fido2-ctap2/`](../fido2-ctap2/architecture.md) | go-xkms |
| The FIDO2 auth *factor* | `pkg/factor/fido2` — [`../auth-factors/`](../auth-factors/architecture.md) | go-xkms |

This is capability row **"WebAuthn relying party" (tier 1)**; SDK access is
`Security().Auth()`.

## Data flow

```
registration:
  client → POST /api/v1/webauthn/registration/begin
             → Service.BeginRegistration(ctx, email, displayName)
               → SessionStore.Save   → sessionID
             ← CredentialCreation options
  authenticator creates a credential (user gesture)
  client → POST /api/v1/webauthn/registration/finish
             → Service.FinishRegistration(ctx, sessionID, parsedResponse)
               → verify attestation, origin, challenge
               → CredentialStore.Save
               → JWTGenerator / TokenPairGenerator
             ← token(s) + user

login:
  client → POST /api/v1/webauthn/login/begin   → Service.BeginLogin(ctx, userID)
  client → POST /api/v1/webauthn/login/finish  → Service.FinishLogin(...)
             → verify assertion, origin, challenge, signature counter
             → CredentialStore.Update (counter)
             ← token(s) + user
```

The `/sdk/...` route variants exist for programmatic clients that are not a
browser — the headless client in `pkg/webauthn/client` and the xkey virtual
authenticator drive those. Both lanes resolve the SAME `Service`, so the
`CredentialStore.Save` above is the one place a composing host can observe
every registration this relying party accepts, whichever lane served it —
that is what the credential-store decorator hooks
([engineering.md](engineering.md) §"Credential-store decoration").

## Trust boundaries

- **The WebAuthn routes are unauthenticated because they *are* the
  authentication.** `GroupWebAuthn` is `RouteAuthPublic`, behind the login rate
  limiter.
- **`RPID` and `RPOrigins` are the security parameters.** The RP id binds a
  credential to a domain; the origin list is what a ceremony response is checked
  against. Getting either wrong is what turns WebAuthn into a redirect
  vulnerability. Neither is cosmetic.
- **`UserVerification`, `AttestationPreference`, `ResidentKeyRequirement` and
  `AuthenticatorAttachment` are policy**, applied at ceremony construction. They
  determine whether a PIN/biometric is required, whether attestation is checked,
  and whether the credential is discoverable.
- **`AllowPublicRegistration` is a `*bool` on purpose, and defaults closed** —
  unset means registration is disabled, matching the stack registration model
  (invite-only unless explicitly opened), while staying distinguishable from
  explicitly false so a composer's default and an operator's decision do not
  collide silently. Under a composed host the host-projected value is
  authoritative.
- **Signature counters are checked and updated.** A counter that goes backwards
  is a cloned-authenticator signal.

## What this feature deliberately does not do

- **It does not define users.** `UserStore` is an interface over go-qrdb's user
  model; go-xkms has no local user model.
- **It does not issue its own tokens.** JWT shape and lifetime come from the
  injected generator.
- **It does not talk to hardware.** Browser-side that is the platform's job;
  headless that is [`../fido2-ctap2/`](../fido2-ctap2/architecture.md).
- **It is not an OIDC provider.** OIDC lives above, in go-quicbaas and in the
  xkey OIDC client.
