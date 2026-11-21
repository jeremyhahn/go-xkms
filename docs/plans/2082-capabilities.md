# Plan: console controls gate on /api/v1/capabilities (row #2082, PR #2200)

## Objective

Tenant Agent ruling 972 (1): "Every console view and action must work against
a real xkmsd. No UI control may lead to a 501 or 'not configured' state. Gate
each control on capabilities, with a clear disabled state that names the
setting to turn on. Make RegisterPanel and LoginPanel consistent."

The owner clicked "Create account" with WebAuthn off and got "not
implemented": RegisterPanel called registration/begin without reading
/api/v1/capabilities, and xkmsd answered 501.

## Subsystem to setting

| flag (where)                          | route(s) gated                | setting named in the UI       |
|---------------------------------------|-------------------------------|-------------------------------|
| webauthn_enabled (public)             | /api/v1/webauthn/*            | webauthn.enabled              |
| piv_login_enabled (public)            | /api/v1/auth/piv/*            | auth.piv_login.enabled        |
| ca (/auth/me)                         | /api/v1/ca/* (not /ca/bundle) | ca (section in xkmsd.yaml)    |
| ssh (/auth/me)                        | /xkms/v1/ssh/keys*            | storage (DAO factory)         |
| tenants (/auth/me)                    | /api/v1/tenants/              | node barrier registry (node:) |
| passwords (/auth/me)                  | /api/v1/passwords*, vault     | storage (DAO factory)         |
| webauthn (/auth/me)                   | add-passkey view              | webauthn.enabled              |

The public `GET /api/v1/capabilities` keeps only the login-page flags, so an
anonymous caller cannot fingerprint which subsystems the deployment wired;
the console's gated views sit behind sign-in and read the session's
`/auth/me` capabilities map. capabilityFlags (handlers_auth.go) uses the
same hasX guard as the route's Enabled in routes.go, never a second source
of truth. The setting text lives in the UI (svelte-auth `capabilities.ts`,
web/app `stores/capabilities.svelte.ts`).

## Slices (each its own commit, test before fix)

1. docs(plans): this file.
2. test(api/rest): /auth/me reports each gated subsystem false on a server
   without it and true with it, in agreement with each route guard; the
   public capabilities stay coarse.
3. fix(api/rest): guard helpers shared by routes.go and capabilityFlags.
4. test(svelte-auth): RegisterPanel with webauthn_enabled false renders the
   disabled state naming webauthn.enabled and makes no registration/begin
   request; both panels read the same capabilities helper.
5. fix(svelte-auth): shared capabilities helper, RegisterPanel gate.
6. test/fix(web/app): capabilities store; gated views (CA, SSH, tenants,
   passwords) show the disabled state instead of calling the route.
7. test(integration/web): live xkmsd with webauthn off; "Create account" shows
   the disabled state and no response is 501.
8. docs(web-console) + changelog.
9. Codex P1s on #2200 (KeyHmacView verdict invalidation, KeyAccessPolicyView
   exact expiry, SealView unseal without backends:list): vitest test commit,
   then fix commit, each.

## Out of scope

- 503-when-not-composed subsystems (PIN, PIV slots, platform, TPM policies):
  views already render the 503 message; gating them is a later slice.
- docs/SPEC.md, .github/workflows/.
