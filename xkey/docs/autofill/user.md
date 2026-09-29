# Browser Extension AutoFill — User Guide

> **Status: NORMATIVE** · Feature: `autofill` · Module: `go-xkms/xkey` · Last verified: 2026-09-27

## Install the browser extension

1. Install the native messaging manifest so the browser can launch xKey:

   ```bash
   xkey extension install          # all supported browsers
   xkey extension install chrome   # Chrome and Chromium derivatives only
   xkey extension install firefox
   ```

2. Load the extension itself (from `xkey/extension/dist/` for a development
   build, or your browser's extension store for a packaged release).

3. Run xKey — either the desktop GUI, or headless:

   ```bash
   echo -n "my-secret" | xkey extension serve --barrier-password-stdin
   ```

## Pair the extension (first connection only)

The first time the extension connects, xKey shows a 6-digit code (in the
GUI's pairing dialog, or via the headless server's IPC notification to
whatever is watching it). Enter that code in the extension's prompt. After
that, the extension's identity is remembered — no code is needed again
unless you unpair it.

```bash
# Check pairing status
xkey extension pair-status

# Force a fresh pairing ceremony
xkey extension unpair
```

## Fill a credential

Click the xKey icon that appears on a password field. If more than one
saved credential matches the page, a chooser appears. If your policy
requires authentication, xKey prompts for touch (and PIN, if configured) on
its virtual authenticator before releasing the password — the same
touch/PIN ceremony a real WebAuthn login uses.

## Fill a TOTP code

When xKey detects a one-time-code field and you have a matching OATH
account (added via `xkey oath add` or the GUI — see [oath/](../oath/)), it
offers to fill the code automatically or on request, depending on your
`totp_policy` setting.

## Save a new credential from a form

When you submit a login form xKey doesn't recognize, the extension can
offer to save it. Choosing "never for this site" adds the domain to an
in-memory ignore list for the current session.

## Configure policy

Policy (fill mode, TOTP handling, domain allow/block lists, rate limit,
whether authentication is required, audit logging) is set through the GUI's
extension settings panel, or by an enterprise SO's policy configuration,
which always takes precedence over your own settings. There is no CLI verb
for editing the policy directly; `xkey extension serve`'s `--no-auth` flag
is the one CLI-level override, and it is meant for development, not daily
use.

## Run headless (server, SSH session, no desktop)

```bash
echo -n "my-secret" | xkey extension serve --barrier-password-stdin
# or, with an already-provisioned TPM-sealed barrier:
xkey extension serve --tpm-device /dev/tpmrm0
```

The extension talks to this the same way it talks to the desktop GUI — pair
it the same way described above.

## Uninstall

```bash
xkey extension unpair              # forget the paired identity
xkey extension uninstall           # remove the native messaging manifest
```
