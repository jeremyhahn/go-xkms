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

| capability flag      | route(s) gated                    | setting named in the UI       |
|----------------------|-----------------------------------|-------------------------------|
| webauthn_enabled     | /api/v1/webauthn/*                | webauthn.enabled              |
| piv_login_enabled    | /api/v1/auth/piv/*                | auth.piv_login.enabled        |
| ca_enabled           | /api/v1/ca/* (not /ca/bundle)     | ca (section in xkmsd.yaml)    |
| ssh_enabled          | /xkms/v1/ssh/keys*                | xkms (XKMS service)           |
| tenants_enabled      | /api/v1/tenants/                  | node barrier registry         |
| passwords_enabled    | /api/v1/passwords*, vault         | password store                |

Each flag is computed from the same condition as the route's Enabled guard in
routes.go (one helper per subsystem, used by both), never a second source of
truth. The response also carries `settings`: flag name to the setting string,
so the UI names the setting the server reports.

## Slices (each its own commit, test before fix)

1. docs(plans): this file.
2. test(api/rest): capabilities reports each gated subsystem false on a server
   without it and true with it, from the real server wiring.
3. fix(api/rest): capabilities flags + guard helpers shared with routes.go.
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
