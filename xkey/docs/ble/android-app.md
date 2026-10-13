# xkey Android App

> **Status: REFERENCE** · Last verified: 2026-10-13
> Pointer to the phone-side app; its build, structure and UI are not in this repository. The [ble](architecture.md) feature folder is normative.

## Overview

The phone side of the BLE backend is **xkey-android**, a separate Kotlin
repository with no Go import in either direction
([architecture.md](architecture.md#the-android-app-is-out-of-scope-for-this-repository)).
Its Gradle build, signing, source layout, permissions, key storage and UI
cannot be verified from this repository and are documented there, not here.

## What this repository defines for the app

The app is a BLE peripheral (GATT server) that the desktop central finds by
the xkey service UUID (`XKeyServiceUUID`, `xkey/pkg/phone/ble_transport.go:33`).
The wire contract it must match — GATT UUIDs, fragment header, Noise XX
session, JSON-RPC methods — is specified in [protocol.md](protocol.md) and
[engineering.md](engineering.md). A change to any of it is a coordinated,
wire-compatible change on both sides.

## Pairing with Desktop

1. Start advertising in the app.
2. On the desktop, run `xkey device pair` (there is no `xkey phone pair`;
   see phone-hsm's [cli.md](../phone-hsm/cli.md)).
3. The desktop prints a verification code derived from the Noise handshake
   (`xkey/cmd/xkey/cmd/device_pair.go:363`); the app does not yet display a
   matching code.

The desktop does not perform OS-level BLE pairing or bonding; it trusts the
device in BlueZ and relies on the Noise handshake alone
(`ble_transport.go:506-507`).
