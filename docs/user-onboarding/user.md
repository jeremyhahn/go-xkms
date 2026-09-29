# User Onboarding (Enrollment Invitations) — User Guide

> **Status: NORMATIVE** · Feature: `user-onboarding` · Repo: `go-xkms` · Last verified: 2026-09-29

## Why an invitation

A brand-new account has no passkey and no certificate yet — nothing to
authenticate an enrollment request with. xkms closes that gap with a
one-time invitation: an administrator creates the account, xkms hands back a
link, and following that link is what proves you are the person the account
was created for.

## As an administrator: inviting someone

```
xkmsctl user register <username> --email <their-address>
```

The command prints an activation link and a raw token. **This is the only
time either is shown** — xkms stores only a digest, so if the link is lost
the account must be deleted and recreated. Send the link to the invitee (or
give them the raw token plus the server address, if they are elsewhere).

The invitation expires — 24 hours by default, configurable by your operator
— after which the account can no longer be activated with it; delete and
recreate the account to issue a new one.

## As an invitee: activating your account

1. Open the link an administrator sent you.
2. Register a FIDO2 security key (a hardware key, or your platform's
   built-in passkey support) or present a PIV smart card certificate, as the
   activation page prompts.
3. Once the ceremony completes, your account is active and the invitation is
   spent — the same link cannot be used again.

If the link has expired or was already used, the page reports it as not
valid, without saying which; ask your administrator for a new one.

## Adding a second passkey later

Once your account is active, invitations are no longer involved: sign in and
add another passkey from an authenticated session (`BeginAddCredential`). An
invitation only ever covers the very first credential.
