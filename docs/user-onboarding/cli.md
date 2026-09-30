# User Onboarding (Enrollment Invitations) — CLI

> **Status: NORMATIVE** · Feature: `user-onboarding` · Repo: `go-xkms` · Last verified: 2026-09-29

## `xkmsctl user register <username> --email <address>`

Creates the account (pending an email login key becomes `LifecyclePending`)
and prints the one-time activation invitation. It no longer drives a local
FIDO2 ceremony inline: an administrator cannot enroll a passkey on an
invitee's behalf, so enrolling the account's first credential is authorized
by the invitation, not by having just created the account
(go-xkms#1294 part B).

```
$ xkmsctl user register alice --email alice@example.com --display-name "Alice"
No users exist. First user will be administrator.
Registering new user...
  Username: alice
  Display Name: alice
  Role: admin

User created successfully; activation is pending.

Activation invitation (shown once — only its digest is stored):
  Token:      b64url-secret
  Link:       https://kms.example.com/ui/#/invite/acme/b64url-secret
  Expires:    2026-09-30T12:00:00Z

Send this link to the invitee, or redeem it yourself via the server's
REST invite endpoints (docs/user-onboarding/cli.md) to enroll the first
FIDO2 passkey or PIV credential and activate the account.

Username: alice
Role: admin
```

The first user registered still becomes administrator automatically.
`--display-name` and `--role` behave as before. `--json` output carries
`invite_token`, `invite_url`, `invite_expires_at` alongside the usual
summary fields.

**Removed flags**: `--device`, `--timeout`, `--user-verification`,
`--pin`/`--pin-stdin`/`--pin-env`, `--origin`, `--rp-id`, `--rp-name` no
longer apply to this command — nothing here drives a local authenticator any
more. They remain on `xkmsctl user login`, which is unaffected.

## `xkmsctl admin create <username> --email <address>`

Same change, for the FIDO2 admin-enrollment method: it creates the account
and prints the invitation instead of enrolling inline. The `--method mtls`
path is unaffected — an mTLS admin is created active, with no login key and
no invitation, exactly as before.

```
$ xkmsctl admin create admin --email admin@example.com
Creating administrator account...
Username: admin
Display Name: admin

Administrator account created; activation is pending.

Activation invitation (shown once — only its digest is stored):
  Token:      b64url-secret
  ...
```

**Removed flags** (FIDO2 method only): `--device`, `--timeout`,
`--user-verification`, `--pin*`, `--origin`, `--rp-id`, `--rp-name`.

## `xkmsctl user invite redeem <invite-link-or-token>`

Redeems an activation invitation over `xkmsctl`'s default transport (any
configured transport carries it — invite redemption is a capability on
every transport, not a REST-only one). It enrolls the invitee's first
credential and activates the account, in the safe order
`FinishInviteRegistration` / `ActivateInvitePIV` use server-side: bind
credential, activate account, redeem invitation.

Accepts either the full invitation link `xkmsctl user register` /
`xkmsctl admin create` printed (tenant and token both come from the link),
or a bare token with `--tenant-id`.

FIDO2 (the default, `--method fido2`) drives the local CTAP2 security key
through the registration ceremony, the same way `xkmsctl user login` drives
it through authentication:

```
$ xkmsctl user invite redeem "https://kms.example.com/ui/#/invite/acme/b64url-secret"
Invitation for alice@example.com (expires 2026-09-30T12:00:00Z)

Please touch your security key to activate the account...
Account activated.
User ID: 42
```

PIV (`--method piv`) activates the account with a PIV certificate instead of
a local FIDO2 ceremony — provide `--piv-cert-file` with the certificate PEM
to present:

```
$ xkmsctl user invite redeem b64url-secret --tenant-id acme \
    --method piv --piv-cert-file piv-cert.pem
Invitation for alice@example.com (expires 2026-09-30T12:00:00Z)
Account activated.
User ID: 42
```

Flags: `--tenant-id`, `--method` (`fido2` or `piv`), `--device`,
`--user-verification`, `--timeout`, `--piv-cert-file`, plus the same
`--pin`/`--pin-stdin`/`--pin-env` and `--origin`/`--rp-id`/`--rp-name` flags
`xkmsctl user login` uses for its FIDO2 ceremony.

An invalid, expired, already-redeemed, or wrong-tenant invitation, and a
token that simply does not exist, all fail the same opaque way — the CLI
reports the same error for all four, matching every other transport
(`docs/user-onboarding/architecture.md`).
