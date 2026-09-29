# WebAuthn Relying Party — User Guide

> **Status: NORMATIVE** · Feature: `webauthn` · Repo: `go-xkms` · Last verified: 2026-09-29

## What this is

The server side of "sign in with your security key". You do not run it directly
— it is part of `xkmsd`. This page is for the person configuring it and for the
person whose login is failing.

## Prerequisites

- `xkmsd` with WebAuthn configured (without it, the routes are not registered
  at all and you get 404, not an error message).
- A token issuer configured, or the session routes are likewise absent.
- An authenticator: a hardware security key, a platform authenticator, or an
  xkey acting as one.

## Configuring it: the two settings that matter

```yaml
webauthn:
  id: kms.example.com
  display_name: Example KMS
  origins:
    - https://kms.example.com:8443
  user_verification: required
  attestation: direct
  resident_key: preferred
  authenticator_attachment: cross-platform
  timeout: 60s
  allow_public_registration: false
```

**`id`** binds every credential to a domain. Pick it once and never change it —
changing it does not migrate credentials, it invalidates all of them, and every
user re-enrols.

**`origins`** is the list a ceremony response is checked against. It must
contain the exact origin your users' browsers send, scheme and port included.
This is the setting people get wrong, and the symptom is "registration works,
login always fails" or vice versa.

The rest are policy:

- `user_verification: required` forces a PIN or biometric, not just a touch.
- `attestation: direct` lets the server see which authenticator model was used;
  `none` does not.
- `resident_key` controls whether the credential is discoverable — needed for
  usernameless login.
- `authenticator_attachment: platform` restricts to built-in authenticators,
  `cross-platform` to removable keys.
- `allow_public_registration` decides whether anyone can enrol themselves.
  **Unset means no**: registration is invite-only by default, matching the
  stack-wide registration model (`iam.self_service_registration.enabled`,
  default off). To open self-service sign-up, set it to `true` explicitly.
  Accounts provisioned by an administrator still enrol their first passkey
  through the same endpoint either way — only implicit account creation for
  unknown emails is withheld, answered with `403 registration_refused`.

  When xkms runs embedded as a ServiceModule under go-quicbaas, the host's
  registration flag is authoritative: the host projects its decision into
  this field, and a value set only in the xkms config is not consulted.

  **Migration (v0.9.x and earlier → v0.10.0):** the default used to be open. A deployment
  that relied on omitting the key now refuses unknown emails; add
  `allow_public_registration: true` to restore the old behaviour.

Leave `debug: false`. It logs ceremony detail that is useful to an attacker.

## Registering and signing in

From the CLI, against a real key:

```
xkmsctl fido2 list-devices
xkmsctl fido2 register alice
xkmsctl fido2 authenticate
```

Headlessly, which is how agents and CI do it:

```
xkey auth register --server https://kms.example.com:8443 --email alice@example.com
xkey auth login --server https://kms.example.com:8443 --email alice@example.com
```

The unauthenticated registration begin enrols an account's **first** passkey
only. To add a second passkey, sign in first and start the ceremony from your
session: `POST /api/v1/webauthn/credentials/begin` with your bearer token
(`auth.webAuthnAddCredentialBegin()` in the TypeScript SDK), then finish with
`registration/finish` as usual. The passkey always goes to the account you are
signed in as. Running `xkey auth register` again for an account that already
has a passkey is refused with 403.

Check who you are:

```
xkmsctl user get alice
```

## Troubleshooting

| What you see | What it means | What to do |
|---|---|---|
| 404 on every WebAuthn route | WebAuthn is not configured on this server | server-side configuration |
| login and refresh routes missing | no token issuer configured | server-side configuration |
| "registration succeeded, login always fails" | the login origin is not in `origins` | add the exact origin, with scheme and port |
| every credential stopped working at once | `id` changed | change it back, or accept that everyone re-enrols |
| the authenticator never prompts | `user_verification` or `authenticator_attachment` excludes it | relax the policy, or use a matching authenticator |
| 401 with no detail | intentional — the server does not tell clients why | read the server log; it has the real reason |
| 429 | login rate limiter | back off |
| server log warns "the authenticator may be cloned" and the audit log has `auth.webauthn.clone_warning` | the credential's signature counter did not advance — a restored backup, or a copied key | the login was allowed; investigate the credential, and delete it if you cannot account for the copy |
| 429 for every user behind one load balancer | the limiter sees the balancer as the client | list the balancer in `server.trusted_proxies` |
| 503 `session_limit` on begin | too many ceremonies were begun and not finished | retry shortly; abandoned sessions expire within about three minutes |
| 413 | request body over 1 MiB | a ceremony body is a few KiB; check the client |
| 403 `registration_refused` on registration begin | the account already has a passkey, or sign-up is closed and there is no such account; the server does not say which | sign in and add the passkey from your session, or ask an administrator to provision the account |
| 409 `credential_exists` on registration finish | that authenticator's credential is already registered | use a different authenticator, or remove the old registration first |
| login begin succeeds for an email with no account | intentional: the server answers with decoy options so it cannot be used to discover accounts | check the email; the ceremony will fail at the authenticator or at finish |
| worked, then failed after restoring a backup of the key | the signature counter went backwards | this is the clone check firing; investigate rather than bypass |

The uniform, detail-free 401 is deliberate: distinguishable failures would let
anyone enumerate users and probe which authenticator each holds. When you are
debugging, the server log is where the answer is.

## Where to go next

- Talking to the authenticator directly: [`../fido2-ctap2/user.md`](../fido2-ctap2/user.md)
- How WebAuthn becomes an authentication factor: [`../auth-factors/user.md`](../auth-factors/user.md)
- Logging in with no browser and no human: [`../../xkey/docs/headless-webauthn/user.md`](../../xkey/docs/headless-webauthn/user.md)
