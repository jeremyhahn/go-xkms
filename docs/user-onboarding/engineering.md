# User Onboarding (Enrollment Invitations) — Engineering

> **Status: NORMATIVE** · Feature: `user-onboarding` · Repo: `go-xkms` · Last verified: 2026-09-29

## Exported surface

### `pkg/xkms` (service layer, `servicer_invite.go` / `servicer_user.go`)

```go
// InviteConfig controls the operator-configured invitation link base URL
// and TTL bounds. The zero value is usable.
type InviteConfig struct {
	PublicBaseURL string
	DefaultTTL    time.Duration // 0 -> qrdbsdk.DefaultInviteTTL (24h)
	MaxTTL        time.Duration // 0 -> 7 days
}

// InviteStore is the storage seam CreateUser and invite redemption use.
// pkg/server wires exactly one production implementation,
// tenantPrefixedInviteStore (see "Configuration" below) — no
// preferred-plus-fallback pair. qrdbsdk.TenantInviteStore also satisfies it
// structurally with no adapter, and is what this package's own tests
// construct directly.
type InviteStore interface {
	Create(ctx context.Context, userID, tenantID string, ttl time.Duration) (token string, entity *qrdbsdk.InviteEntity, err error)
	Lookup(ctx context.Context, tenantID, token string) (*qrdbsdk.InviteEntity, error)
	Redeem(ctx context.Context, tenantID, token string) (*qrdbsdk.InviteEntity, error)
}

func (s *XKMSService) SetInviteStore(store InviteStore)
func (s *XKMSService) SetInviteConfig(cfg InviteConfig)

// CreateUser (servicer_user.go) — an email-login-key account is created
// PENDING and CreateUser mints the invitation in the same call; the caller
// rolls the account back on mint failure.
func (s *XKMSService) CreateUser(ctx context.Context, req *transport.CreateUserRequest) (*transport.GetUserResponse, error)

// Invite redemption. Each takes and returns the transport.* wire type
// directly — this IS transport.InviteServicer, composed into
// transport.XKMSServicer, so every transport (REST, gRPC, Unix, QUIC, MCP,
// embedded) calls these through the one composed interface rather than a
// transport-specific shape (see api.md's transport table).
func (s *XKMSService) GetInvite(ctx context.Context, req *transport.GetInviteRequest) (*transport.GetInviteResponse, error)
func (s *XKMSService) BeginInviteRegistration(ctx context.Context, req *transport.BeginInviteRegistrationRequest) (*transport.BeginInviteRegistrationResponse, error)
func (s *XKMSService) FinishInviteRegistration(ctx context.Context, req *transport.FinishInviteRegistrationRequest) (*transport.FinishInviteRegistrationResponse, error)
func (s *XKMSService) ActivateInvitePIV(ctx context.Context, req *transport.ActivateInvitePIVRequest) (*transport.ActivateInvitePIVResponse, error)
```

`transport.CreateUserRequest.InviteTTLSeconds` overrides the minted TTL (0 or
negative takes the configured default; above the cap is clamped, never
refused). `transport.GetUserResponse.Invite` (`*transport.InviteInfo{Token,
URL, ExpiresAt}`) is populated exactly once, by `CreateUser`, for an account
with an email login key; every other caller of `GetUserResponse` leaves it
nil.

Minting an invitation is decided by go-qrdb's `users:invite`
(`qrdbsdk.PermissionUsersInvite`), not by `users:create`: the transports gate
`CreateUser` on `users:create`, and `CreateUser` then asks
`AuthorizeCaller` for `users:invite` before it creates an email-login-key
account (`pkg/xkms/servicer_user.go`). A caller holding `users:create` alone
gets go-qrdb's `*qrdbsdk.PermissionDeniedError` and no account is created. The
bootstrap path (`WithoutEmailLoginKey`) mints no invitation and needs only
`users:create`; with no authorizer wired (RBAC disabled) every request is
allowed.

### `pkg/webauthn` (relying party)

```go
// BeginInviteRegistration / FinishInviteRegistration are the ONLY
// unauthenticated entry points that may enroll the first credential of an
// account that already existed before the call. They require
// LifecyclePending and, for Begin, zero existing credentials.
func (s *Service) BeginInviteRegistration(ctx context.Context, email string) (*protocol.CredentialCreation, string, error)
func (s *Service) FinishInviteRegistration(ctx context.Context, sessionID string, response *protocol.ParsedCredentialCreationData) (User, error)
```

`BeginRegistration` (the public, unauthenticated entry point) was narrowed:
it now refuses any account that existed before the call, in every case —
see `architecture.md` "Closing the hole".

## Invariants

- **Single redemption.** qrdb's `invite.Store.Redeem` is the single-winner
  primitive (`SaveIfAbsent` on a redemption marker); concurrent redemptions
  of one token resolve to exactly one winner. xkms never redeems twice for
  one successful ceremony (see the ordering in `architecture.md`).
- **Credential before activation before redemption.** Enforced by
  `FinishInviteRegistration` / `ActivateInvitePIV`'s call order in
  `servicer_invite.go`; violating it is the one thing a change to this file
  must not do.
- **PENDING is the only lifecycle Begin/Finish accept.** Both
  `webauthn.Service.BeginInviteRegistration` and `FinishInviteRegistration`
  check `user.Lifecycle() != qrdbsdk.LifecyclePending` and refuse with
  `ErrRegistrationRefused` otherwise — an active account (already activated),
  a suspended/locked/disabled/deleting one, or a pending one that already
  holds a credential are all refused identically.
- **Opaque failures only.** See `architecture.md` "Opacity". Never add a
  code path that answers "not found" differently from "expired" or "already
  redeemed" for an unauthenticated caller.
- **No re-implemented single-use/expiry primitive.** Generation, digesting,
  expiry and single-use enforcement are qrdb's (`qrdbsdk.NewInviteStore`),
  never reimplemented in this package. `pkg/server.tenantPrefixedInviteStore`
  (see "Configuration") is a routing/caching wrapper around
  `qrdbsdk.InviteDAOStore`, not a parallel implementation.
- **One storage path, no fallback.** The owner's standing rule is "never use
  fallbacks without approval." `pkg/server` wires exactly one `InviteStore`
  implementation, unconditionally — there is no preferred-implementation-
  with-fallback branch to keep in sync or reason about.

## Configuration

`pkg/config.InviteConfig` (operator YAML, `invite:` section):

```yaml
invite:
  public_base_url: "https://kms.example.com/ui"   # never derived from a request Host
  default_ttl: "24h"                                # Go duration string; empty -> qrdb's 24h
  max_ttl: "168h"                                    # empty -> 7 days
```

Wired in `pkg/server/server.go` as ONE path, unconditionally:
`pkg/server.tenantPrefixedInviteStore` (`invite_store.go`), built on the
same `s.createStorage("invites")` seam every other xkmsd subsystem's
persistent metadata uses — the identical precedent `pkcs11state` sets
(`initializePKCS11StateStore`), not a second, independent storage path. It
namespaces each tenant's records with a `storage.NewPrefixBackend` key
prefix (a collision-proof sentinel for the empty/default tenant — see
`invite_store.go`'s `defaultInviteStoreTenant`) over `pkg/storage/kvadapter`
(the existing `storage.Backend`→`qrdbsdk.KVStore` bridge; never duplicate
it), and caches one `*qrdbsdk.InviteDAOStore` per tenant for the process
lifetime. Guarded writes (the atomic `PutIfAbsent` single-use redemption
requires) come from whatever `storage.backend` is configured — memory,
file, pebble and qrdb all provide a genuine atomic primitive via
`storage.GuardedWritesUsable`, so a future backend that cannot serialize
guarded writes fails at construction, not on the first redemption. This is
what makes invitations work in xkmsd's **default** configuration, with no
barrier registry required — go-xkms#1363 turns `createStorage` itself into
a prefixed, barrier-protected, replicated view over the one shared qrdb
datastore, and this store moves with that change automatically since it
only ever calls `createStorage`.

An earlier revision of this wiring tried `qrdbsdk.TenantInviteStore`
(routed through the embedded qrdb node's per-tenant `Services().StoreResolver`,
non-nil only when a `BarrierRegistry` was configured) first and fell back to
a `createStorage`-backed store otherwise. That was removed: the owner's
standing rule is "never use fallbacks without approval," and a
preferred-plus-fallback pair is two storage paths to keep in sync for one
capability. `qrdbsdk.TenantInviteStore` remains a valid `InviteStore`
implementation (this package's own tests construct it directly, since it
needs no `storage.Backend` at all) — it is simply not what `pkg/server`
wires into a running xkmsd.

`CreateUser` fails closed (`ErrNotConfigured`) only if `tenantPrefixedInviteStore`'s
construction itself failed (for example `createStorage` erroring) — never
because of a missing barrier registry, since the one wired path does not
require one. This is not fatal to server startup: `pkg/server/server.go`
logs a warning and leaves the store unset, so the failure surfaces at the
first `CreateUser`/redemption call rather than blocking every other
subsystem from starting. `pkg/server/invite_config.go` parses the
`invite:` duration strings, failing startup on a malformed value.

## Errors

- `xkms.ErrInviteUnusable` — the one opaque answer for absent/expired/
  redeemed/malformed tokens.
- `xkms.ErrPIVCertDecode` / `xkms.ErrPIVCertRejected` — PIV-specific,
  surfaced with their own detail (400 / 422) since they are the caller's own
  malformed or untrusted input, not a probeable secret.
- `xkms.ErrNotConfigured` — no invite store (mint or redeem) or, for
  `ActivateInvitePIV`, no CA wired.
- `pkg/webauthn.ErrRegistrationRefused` — the account named by a valid
  invitation is not eligible (wrong lifecycle, already has a credential);
  mapped to `xkms.ErrInviteUnusable` by the `pkg/xkms` orchestration so it
  reaches the caller with the same opacity as every other unusable token.

## Tests

- `pkg/webauthn/registration_policy_test.go`,
  `pkg/webauthn/registration_auth_test.go`,
  `pkg/webauthn/account_standing_test.go` — `BeginRegistration`'s narrowed
  refusal and `BeginInviteRegistration`/`FinishInviteRegistration`'s pending-
  only acceptance, including mid-ceremony deactivation.
- `pkg/xkms/servicer_invite_test.go` — the full orchestration: mint, begin,
  finish (real WebAuthn ceremony via `virtualwebauthn`), PIV activation
  (real X.509 chain verification), opacity of unknown/reused tokens,
  `effectiveInviteTTL` defaults/caps, `buildInviteURL`.
- `pkg/xkms/servicer_user_test.go` — `CreateUser` minting, the
  `WithoutEmailLoginKey` exception, fail-closed with no invite store, and
  rollback on mint failure.
- `pkg/api/rest/handlers_invite_test.go` — the REST surface: metadata
  lookup, opaque 404s (including a redeemed token answering identically to
  an unknown one), the FIDO2 begin/finish and PIV activate wiring gaps
  (503), and a full begin-ceremony round trip.
- `pkg/server/invite_store_test.go` — `tenantPrefixedInviteStore`, the one
  production `InviteStore`: create/lookup/redeem, single-use enforcement, an
  unknown token, tenant isolation, the empty-tenant sentinel not colliding
  with a realistic lookalike tenant name, and per-tenant store caching.
- `pkg/api/grpc`, `pkg/api/mcp`, `pkg/api/transport/{grpc,unix,quic,rest,mcp,embedded}` —
  `CreateUser`'s `Invite` field, and the `GetInvite`/
  `BeginInviteRegistration`/`FinishInviteRegistration`/`ActivateInvitePIV`
  RPCs themselves, on every transport (see `api.md`'s transport table),
  including MCP's `ErrIdentityCeremonyExcluded` for the FIDO2 Begin/Finish
  pair.
- `cmd/xkmsctl` — `user invite redeem`: reference parsing (full link vs.
  bare token + `--tenant-id`), method validation, and the FIDO2/PIV
  redemption paths against a mock client.

Run: `go test -tags "codec_cbor codec_json codec_msgpack tpm_simulator frost" ./pkg/xkms/... ./pkg/webauthn/... ./pkg/api/... ./pkg/server/... ./cmd/xkmsctl/...`
