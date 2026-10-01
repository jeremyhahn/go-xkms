# OIDC Credentials — User Guide

> **Status: NORMATIVE** · Feature: `oidc-credentials` · Repo: `go-xkms` · Last verified: 2026-09-30

## When to use it

Use a server OIDC credential when something other than you needs a token
for an OAuth provider, or needs it after you log off: an agent account, a
CI job, a service. The server keeps the login fresh; whoever needs the token
asks for it by name. Your personal logins on your own machine stay in
xkey's local OIDC.

## Shared or personal

- **Shared** (`--scope tenant`): every user of the tenant can use it. Use it
  for a team's or an automation's login.
- **Personal** (`--scope user`, the default): only you can see or use it —
  not other users, and not system administrators.

## Bring a login in

1. **Device login** (OpenAI, and providers that offer RFC 8628):

   ```bash
   xkmsctl oidc create codex --scope tenant --template openai
   xkmsctl oidc login codex --scope tenant
   # open the printed URL on any device and enter the code
   ```

2. **Import an existing login** — no new login needed:

   ```bash
   xkmsctl oidc import codex --scope tenant --codex-auth ~/.codex/auth.json --create
   ```

   After importing a codex login, stop using that `auth.json` on the
   machine it came from: the server now rotates the refresh token, and the
   copy left behind will be refused the next time codex tries to refresh it.

3. **A long-lived token** (`claude setup-token` prints one valid for a year):

   ```bash
   claude setup-token | xkmsctl oidc import claude --scope tenant --create --template anthropic --access-token -
   ```

## Use it

```bash
xkmsctl oidc token corp                          # prints the access token
xkmsctl oidc token codex --scope tenant --codex-auth-out ~/.codex/auth.json
```

The codex file is written so that codex never refreshes it; ask for a new
one when it expires.

## Watch it

```bash
xkmsctl oidc list
```

| Status | Meaning | What to do |
|---|---|---|
| `pending` | No login yet | `login` or `import` |
| `active` | Usable; the server refreshes it | — |
| `relogin_required` | The provider rejected the refresh token (expired, revoked, or used by someone else) | `login` or `import` again |
| `expired` | A non-refreshable token ran out | `import` a new one |

A `last_error` on an active credential means a refresh failed for a reason
that may pass (the provider was unreachable); the current token keeps being
served while it is valid.

## In the web console

**OIDC Credentials** lists shared and personal credentials with their
status, creates and deletes them, imports tokens or a pasted codex
`auth.json`, runs a device login, and copies a current access token.
