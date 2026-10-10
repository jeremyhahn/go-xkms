# xKey Desktop GUI — User Guide

> **Status: NORMATIVE** · Feature: `gui` · Module: `go-xkms/xkey` · Last verified: 2026-10-09

## Launching it

```
xkey            # launches the GUI if a display is available, otherwise the CLI
xkey --gui      # force the GUI
xkey --no-gui   # force the CLI, even with a display available
```

Running any subcommand (`xkey oath list`, `xkey fido2`, ...) always uses the
CLI, regardless of display. See [cli.md](cli.md) for the full dispatch rule
and what happens on a binary built without GUI support.

## First run

The first launch walks you through the **Setup Wizard** — see
[../setup-wizard/](../setup-wizard/) for quick vs. manual personal setup and
enterprise SO provisioning. Everything below assumes setup is complete.

## Getting around

The GUI is organized as a set of views, one per capability area: Dashboard,
Pairing (phone), FIDO2, OATH, PIV, TPM, SSH, Passwords, Certificates, Keys,
Seal (barrier), Security Factors, OIDC, Browser, API Explorer, Trust Store,
Audit Log, Admin, and Settings. Which of these are visible depends on what
you have set up and, for Admin, whether your account has server-admin
privileges (`AdminService` — see [engineering.md](engineering.md)).

## System tray

If your desktop supports it, xkey runs a tray icon with quick status and
actions: connection status, a Phone submenu (connect/disconnect/attest),
managed-key count, storage status, an FIDO2 submenu (start/stop the phone
bridge, view credentials), and shortcuts to Settings and the Audit Log.
Closing the main window minimizes to tray rather than quitting, unless you
choose Quit from the tray menu.

## Pairing a phone

See [../phone/user.md](../phone/user.md) — pairing itself, attestation, and
using the phone as your FIDO2 key backend. In the GUI this is the
**Pairing** view.

## Settings

Theme (light/dark/system), window behavior, and the settings covered in each
feature's own user guide (barrier/seal, PIN, SSH, autofill, and so on) live
under **Settings**. Application-lock behavior — for installations that have
not set up a barrier at all — is covered by `AppLockService`
([engineering.md](engineering.md)); if you do have a barrier, app-lock
composes with it rather than replacing it.

### Let other apps use your keys

Off by default. Turn on **Settings → Browser → Let other apps use my keys
while xKey is open** (or run `xkey app-access enable` and restart xKey) to
let the browser extension and the PKCS#11 module reach your keys. xKey then
opens a private local socket, only while it is open and unlocked. Locking
xKey, sealing the barrier, turning the setting off or quitting removes the
socket at once.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `xkey` opens a terminal help screen instead of the window | No display detected (`$DISPLAY`/`$WAYLAND_DISPLAY` unset on Linux), or a subcommand was given. Use `xkey --gui` to force it. |
| "this binary was built without GUI support" | Rebuild with `make -C xkey build-local`, or with `-tags 'ble production codec_json'` — see [cli.md](cli.md) |
| The Admin view is missing | Your account does not have server-admin privileges, or the GUI has no active server connection |
| The browser extension or PKCS#11 module cannot reach xKey | Local app access is off, or xKey is locked or closed. Turn the setting on and unlock xKey |
| A view's action fails with a barrier-related error | A barrier is initialized on this host but not currently unsealed — unseal it first (Seal view or `xkey barrier unseal`) |

## See also

- [../phone/user.md](../phone/user.md) — phone pairing and attestation
- [../setup-wizard/](../setup-wizard/) — first-run setup
- [../seal/user.md](../seal/user.md) — the barrier and auto-unseal
