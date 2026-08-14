# FIDO2 Daemon Overview

`xkey fido2` runs xKey as a virtual FIDO2/WebAuthn security key. It creates a
virtual USB HID device through Linux UHID, so browsers and applications see a
CTAP2 authenticator that behaves like a hardware key — except the private keys
live wherever you point the backend, and the touch can be approved over a
socket instead of with a finger.

The bare command *is* the daemon (`start` is only a named alias for it). It runs
in the foreground.

## What it is

| | |
|---|---|
| Protocol | CTAP2, FIDO 2.1 compliant; pinUvAuthProtocol 1 and 2 (2 preferred) |
| Presented as | USB HID device via Linux UHID (`/dev/uhid`), or Chrome's virtual authenticator over CDP |
| Key storage | `software`, `tpm2`, or `phone` |
| Credentials | Resident/discoverable credentials supported |
| Browsers | Chrome and Firefox |

## What the daemon owns

One process, several responsibilities — see
[daemon-architecture.md](daemon-architecture.md) for how they fit together:

- The **UHID device** that makes it visible as a security key.
- The **CTAP2 authenticator** and its credential storage.
- A **virtual keyboard**, used to type stored passwords into whatever has focus.
- The **static password store** the browser extension reads for autofill.
- An **IPC socket**, which is how `xkey unlock`, `xkey touch` and the browser
  extension reach the running daemon.
- Optionally, a **Chrome DevTools bridge** instead of UHID.

## Running it

```bash
# Software backend, interactive touch approval
sudo xkey fido2 --backend software

# TPM-backed keys
sudo xkey fido2 --backend tpm2

# Unattended: never block on a touch
sudo xkey fido2 --require-touch=false --auto-uv

# No /dev/uhid and no sudo — drive Chrome's virtual authenticator instead
xkey fido2 --cdp --cdp-port 9222
```

`sudo` is needed because `/dev/uhid` is normally root-only; `uinput` group
membership or `xkey uhid setup` are the alternatives. The `--cdp` path needs
neither, but only works against a Chrome started with remote debugging.

Check whether a daemon is already up — it exits non-zero when none is
listening, so scripts can gate on it:

```bash
xkey fido2 status
```

## Note on the GUI

The xKey GUI bundles the authenticator, password manager and IPC server into
its own process. Do not run `xkey fido2` alongside it: you would get a second
authenticator with a separate PIN and a separate credential store.

## See Also

- [Daemon Architecture](daemon-architecture.md) -- components and how requests flow
- [Daemon Configuration](daemon-configuration.md) -- flags, environment, config file
- [FIDO2 README](README.md) -- full flag reference, backends, SO PIN, attestation
- [Authenticator Overview](authenticator-overview.md) -- the CTAP2 library beneath the daemon
