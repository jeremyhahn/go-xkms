# User Onboarding (Enrollment Invitations) — Architecture

> **Status: NORMATIVE** · Feature: `user-onboarding` · Repo: `go-xkms` · Last verified: 2026-09-29

## The problem

A brand-new account holds no credential. Passwordless authentication has
nothing to bootstrap the FIRST credential with: WebAuthn's own ceremony
authenticates against a credential the account already holds, and PIV
activation binds a certificate to an account that must already exist. Before
this feature, xkms closed that gap by letting anyone who knew an account's
email start a WebAuthn registration ceremony against it, unauthenticated, the
moment the account existed with zero credentials — an admin-provisioned
account with no invitation step at all was enrollable by whoever asked first
(go-xkms#1294).

## Shape chosen: qrdb's invitation primitive, redeemed through xkms's own
## ceremonies

The invitation record — a single-use, digest-stored token bound to a user and
tenant with an expiry — lives in go-qrdb (`pkg/invite`, re-exported as
`qrdbsdk.TenantInviteStore`), not in xkms. An invitation is a pending-user
record, and qrdb owns the user model; keeping token generation, digesting,
tenant routing and single-use enforcement in one place means go-xkms and
go-quicbaas consume one implementation instead of each keeping a copy. See
`../../../go-qrdb/pkg/invite/store.go`'s package doc for the full reasoning.

What xkms owns is everything downstream of "a valid, unredeemed token names
this pending account": the WebAuthn and PIV ceremonies that redemption
authorizes, since xkms is the canonical home for both (see the repository's
Layer Ownership). `pkg/xkms/servicer_invite.go` is the orchestration:

- `XKMSService.CreateUser` (`pkg/xkms/servicer_user.go:72`) creates an
  email-login-key account `LifecyclePending` and mints the invitation in the
  same call, returning the plaintext token exactly once
  (`transport.GetUserResponse.Invite`). A mint failure rolls the account
  back: a pending account nothing can activate is worse than no account.
- `BeginInviteRegistration` / `FinishInviteRegistration`
  (`pkg/xkms/servicer_invite.go`) redeem the token against xkms's WebAuthn
  relying party (`pkg/webauthn.Service.BeginInviteRegistration` /
  `FinishInviteRegistration`), which is the ONLY entry point that may enroll
  the first credential of an account that already existed before the call.
- `ActivateInvitePIV` (`pkg/xkms/servicer_invite.go`) redeems the token by
  verifying a presented PIV certificate's chain against the CA's own trust
  pool (`pkg/pivcert.VerifyChain`, roots from `provider.CA.CABundle()`) and
  binding its SPKI thumbprint.

Both paths bind the credential to the still-pending account, activate it, and
redeem the invitation, in that fixed order — see "Ordering" below.

## Closing the hole: `pkg/webauthn.Service.BeginRegistration`

`BeginRegistration` (`pkg/webauthn/service.go:151`) is the unauthenticated,
public entry point browsers and the CLI call directly. It now refuses
**every** account that existed before the call, whatever its credential
count: an account with a credential needs `BeginAddCredential` and a session
(go-xkms#1294, the original ruling); an account with none needs
`BeginInviteRegistration`. The only account `BeginRegistration` may still
enroll a credential for is one it creates itself, inline, when open
self-registration is configured (`Config.AllowPublicRegistration`) — the
implicit-create branch is what "public registration" means, and it is safe
precisely because nothing existed before the call.

`BeginInviteRegistration` is a sibling entry point with the opposite
authorization: it requires `LifecyclePending` and zero credentials, and its
caller (`pkg/xkms`) has already proven the account is the one a valid
invitation names — the account's email is read from the invitation's own
`UserID`, never from client input.

## Ordering

Both redemption paths bind the credential to the pending account BEFORE
activating it, and activate the account BEFORE redeeming the invitation:

1. **Bind.** `FinishInviteRegistration` persists the WebAuthn credential (or
   `ActivateInvitePIV` binds the SPKI thumbprint) while the account is still
   `LifecyclePending`.
2. **Activate.** The account transitions to `LifecycleActive`
   (`XKMSService.activateInviteUser`). A failed write does not prove the
   state did not land — a lost response can report failure on an account
   that IS now active — so activation is reconciled by re-reading the
   account before deciding whether to keep the fail-closed refusal.
3. **Redeem.** The invitation is consumed last (`inviteStore.Redeem`).

A failure at step 1 or 2 leaves the invitation intact and the token
retryable. A failure at step 3, after activation is confirmed, is reported as
a server error rather than silently succeeding, because a token that cannot
be marked spent remains redeemable — but the credential is already bound and
the account already active, so the operator's own next attempt (or an
administrator's) is not blocked by it. This mirrors go-quicbaas's
`PIVActivator.Activate` / `ActivateFIDO2Finish`, which solved the identical
ordering problem first; xkms's version differs only in owning the ceremonies
directly instead of calling out to them.

## Opacity

Every unauthenticated lookup — `InviteMetadataLookup`,
`BeginInviteRegistration`, `FinishInviteRegistration`'s pre-ceremony lookup,
`ActivateInvitePIV`'s pre-verification lookup — collapses qrdb's
`ErrInviteNotFound`, `ErrInviteExpired`, `ErrInviteAlreadyRedeemed` and
`ErrInviteEmptyToken` into the single `xkms.ErrInviteUnusable`
(`pkg/xkms/servicer_invite.go`'s `classifyInviteError`). Telling a stranger a
token exists but is spent confirms a real user was invited — the enumeration
an opaque token exists to prevent. The REST transport renders this as one
404 response (`ErrorCodeInviteUnusable`,
`pkg/api/rest/handlers_invite.go`), matching the account-standing opacity
rule already applied to login (go-xkms#1296, go-xkms#1298).

## Rejected alternative: a copy of the invitation model in xkms

An xkms-local invite store was rejected outright. The company SDK-boundary
constitution and this repository's own Layer Ownership section are explicit
that xkms consumes qrdb's user/identity model through the SDK and must not
define a parallel one; an invitation is a pending-user record, so the same
rule applies to it. The only xkms-owned code here is the ceremony
authorization the redemption triggers.

## What this does not cover

Platform administrator and security officer bootstrap (the very first
identity on a fresh node) is certificate-based and has no invitation step —
see `pkg/firstboot` in go-qrdb and the ceremony types. Invitations were
deliberately kept out of that path; the two answer different questions (an
admin already holds, or is issued, a certificate — an ordinary invited user
has nothing yet).
