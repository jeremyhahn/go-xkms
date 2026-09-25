# BLE Transport — User Guide

> **Status: NORMATIVE** · Feature: `ble` · Module: `go-xkms/xkey` · Last verified: 2026-09-24

This page covers pairing over Bluetooth specifically. For what pairing
gives you once it's done — using the phone as a FIDO2 backend, syncing
data, sharing keys, re-attesting — see `xkey/docs/phone-hsm/user.md`.

## Before you start

- Your phone needs the xKey Android app installed and running (a separate
  app, not part of this build — see the app's own documentation for
  install steps).
- This computer needs Bluetooth hardware and, on Linux, BlueZ (standard on
  any recent distribution). A binary built without Bluetooth support
  (`xkey/docs/ble/cli.md` "The `ble` build-tag gate") will tell you so
  clearly rather than fail silently.
- Bring the two devices physically close; BLE range is short.

## Pairing

```bash
xkey device pair
```

Open the app on your phone, then run the command above on the desktop. It
scans for a few seconds, lists what it found, and lets you pick one if
more than one xKey-capable device is nearby:

```bash
xkey device pair --device "John's Pixel"     # skip the picker
xkey device pair --timeout 60s               # scan longer, e.g. in a noisy RF environment
xkey device pair --force                     # re-pair a device you already paired
```

Pairing does a few things you don't have to do by hand: it establishes an
encrypted channel to the phone, checks the phone's hardware attestation
(that it really is what it claims to be), and saves the pairing so future
commands don't need to repeat any of this.

If your organization requires a Security Officer PIN to allow pairing with
a phone that can't prove attestation:

```bash
echo -n "$SO_PIN" | xkey device pair --so-pin-stdin
```

## Just looking for nearby devices

```bash
xkey device scan
```

Lists what's advertising nearby without connecting to anything — useful to
confirm the phone app is actually running and advertising before you try
to pair.

## Letting the phone connect to you

Most of the time your desktop initiates the connection (`pair`, and later
whatever operation you're running). Some things — chiefly, the phone
asking this laptop to prove its own integrity — go the other direction:

```bash
xkey device listen
```

This puts the laptop into a waiting state, advertising itself, until the
already-paired phone connects. It's not something you'd normally run
proactively; the app tells you when it needs this.

```bash
xkey device listen --timeout 5m       # give up after 5 minutes instead of waiting forever
```

## If pairing or connecting keeps failing

- **Nothing found when scanning**: make sure the app is open and actively
  advertising on the phone, Bluetooth is on on both ends, and you're
  within range.
- **Connects, then drops, then works on retry**: this usually resolves
  itself — xKey automatically works around a couple of known BlueZ
  quirks around Android's rotating Bluetooth address (see
  `architecture.md` if you're curious about the mechanics). If it never
  recovers, `bluetoothctl remove <address>` (find the address with
  `xkey device scan` or `bluetoothctl devices`) clears a stuck cache entry.
- **"BLE unavailable"**: either this build wasn't made with Bluetooth
  support, or Bluetooth is disabled on this machine. Check `bluetoothctl
  show` or your desktop's Bluetooth settings.
