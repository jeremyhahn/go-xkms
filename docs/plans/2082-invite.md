# Row 2082 slice: invite link route (ruling 973 (3))

## Objective

`pkg/xkms/servicer_invite.go` `buildInviteURL` mails `/#/invite/<tenant>/<token>`
links, but the web app had no such route. Add the route and a passkey
enrolment view bound to the invite.

## Slices, in order

1. test(web/app): `test/router_invite.test.ts` (route resolves with decoded
   tenant and token; malformed paths do not) and `test/view_invite.test.ts`
   (webauthn off: disabled state naming `webauthn.enabled`, no invite request;
   404: unusable-link state; success: begin/finish with tenant and token, then
   sign-in and `/dashboard`).
2. feat(web/app): `parseHash` invite route, `InviteView.svelte` in both App
   branches, `@go-xkms/sdk` `InvitesClient` (get, beginRegistration,
   finishRegistration) with `src/invites.test.ts`; dist rebuilt.
3. test(web/app): mock-tier `e2e/invite.spec.ts`; stale nav locators in
   navigation and shell-rbac specs made exact (make test-web-e2e was red).
4. test(integration/web): live `tests/invite.spec.ts` (operator creates a
   user, invitee redeems on a CDP virtual authenticator, link then spent).
   Passes only once PR #2296 (server-side redemption fix) is in.
5. docs: `docs/web-console/user.md` invite section, changelog entry.

## Design notes

- The finish call returns only `user_id`, so the view follows enrolment with
  a passkey sign-in (`webAuthnBeginLogin` by the invited email) through the
  same svelte-auth CredentialProvider; no second WebAuthn implementation.
- If that sign-in fails the passkey is still registered; the view sends the
  user to `/login`.

## Out of scope

- Server changes (pkg/), the PIV activation path, SPEC.md.
