# OIDC — User Guide

Status: current. Last verified: 2026-09-30.

## Log in to a standard OIDC provider

```bash
xkey oidc login --issuer https://accounts.google.com --client-id YOUR_CLIENT_ID
```

This opens your browser, completes the PKCE authorization-code flow, and
stores the resulting session. `xkey oidc token` shows what was stored;
`xkey oidc logout` clears it.

If you'll use the same provider repeatedly, save it once and log in by name:

```bash
xkey oidc providers add --name google --issuer https://accounts.google.com --client-id YOUR_CLIENT_ID
xkey oidc login --provider google
```

## Protect the session with a barrier

If you've run `xkey barrier init`, your OIDC session (access token, refresh
token, ID token) is automatically encrypted at rest the same way your OATH
codes and FIDO2 credentials already are — nothing extra to do at login time
beyond supplying the barrier password when the command needs it:

```bash
xkey oidc login --issuer https://accounts.google.com --client-id YOUR_CLIENT_ID \
  --barrier-password-file ~/.xkey/barrier.pw
```

Without a barrier, xkey warns once ("store is unencrypted at rest; run
`xkey barrier init` to encrypt it") and stores the session as it always did
— login still works, nothing is blocked, but the file is readable by
anything with your file-system permissions.

**Upgrading**: if you had a session stored before this change, it is not
carried forward — the CLI does not read the old file format under any
circumstances. Run `xkey oidc login` again.

## Check and refresh your session

```bash
xkey oidc token              # summary; add --show-full to see the raw tokens
xkey oidc refresh             # rotate the access token using the stored refresh token
```

A session established with `--provider <name>` (a provider that skips
`.well-known` discovery) must be refreshed with `--provider <name>` too, so
`refresh` knows which manual endpoints to use.

## Keep the session fresh automatically

```bash
# Blocks the terminal, refreshing every 14 minutes:
xkey oidc login --provider google --auto-refresh 840

# Same, but detached from the terminal:
xkey oidc login --provider google --auto-refresh 840 --background
xkey oidc status              # see it running
xkey oidc stop google          # stop it
```

With `--background` and a barrier, supply the barrier password
non-interactively — the detached process has no terminal to prompt on:

```bash
xkey oidc login --provider google --auto-refresh 840 --background \
  --barrier-password-file ~/.xkey/barrier.pw
```

(`XKEY_BARRIER_PASSWORD` in your environment also works, and is inherited by
the background process automatically. `--barrier-password-stdin` is no use
here either — the detached background process has no standard input to read
a piped value from. There is no `--barrier-password` value flag at all: a
value on the command line would be visible to anything that can list
processes on the machine.)

## Run a script on login or refresh

```bash
xkey oidc login --provider google --exec ./on-login.sh
```

The script receives a JSON payload on stdin and the same fields as
environment variables (`OIDC_ACCESS_TOKEN`, `OIDC_REFRESH_TOKEN`,
`OIDC_ID_TOKEN`, `OIDC_SUBJECT`, `OIDC_EMAIL`, …) — see
[cli.md](cli.md#xkey-oidc-login) for the full flag reference.

## AWS Console login

`xkey oidc aws` is a separate, DPoP-based flow for AWS Console native login;
it keeps its own session store (`--session-store`) holding the DPoP private
key and refresh token, but follows the identical barrier-or-fallback
behavior described above: barrier-encrypted when `xkey barrier init` has
been run, an unencrypted file with one warning otherwise, and an explicit
`--session-store <dir>` bypassing the barrier entirely. See
[cli.md](cli.md#xkey-oidc-aws).

## Using a specific directory instead of the barrier

```bash
xkey oidc login --provider google --token-store /tmp/scratch-tokens
```

An explicit `--token-store <dir>` always writes an unencrypted store in that exact directory,
whether or not a barrier is initialized — useful for a throwaway or
scripted session you don't want mixed in with your normal one.

## Server credentials in the GUI

With the xKey GUI connected to an xkmsd, the OIDC view's Providers tab shows a
**Server credentials** section above your local providers. These are logins
the server holds on its tenant barrier and refreshes itself; your local
providers below are untouched and keep working as before. When no server is
connected the section is not shown.

- **Add server credential** — pick a provider template (openai, anthropic,
  google, ...; or a custom provider with its issuer, client ID, scopes and
  device endpoint) and a scope: *Personal* (only you) or *Shared with the
  tenant*. The credential is pending until it has a login.
- **Device login** — for providers that support it (openai): the dialog shows
  the user code and the verification URL; approve it on any device. The GUI
  polls the server at the provider's interval until the credential is active,
  and stops when the login expires or you close the dialog.
- **Import login** — paste tokens (access token, optional refresh token and
  expiry), or the content of a codex `auth.json` (imported as an openai
  credential). Tick *Create the credential* to create it in the same step.
  The pasted secrets are cleared from the form as soon as you submit.
- **Refresh**, **Delete**, and **Copy token** — Copy token asks the server
  for a current access token when you click it and puts it on the clipboard,
  which clears itself after the configured timeout.

A credential whose status is *Re-login required* or *Expired* is marked in the
list: run a device login again, or import a new login. anthropic tokens are
imported and never refreshed, so they expire on their own date.

The same credentials are reachable from the CLI with `xkey oidc` while an
xkmsd is configured — see [cli.md](cli.md#server-mode-an-xkmsd-configured).
