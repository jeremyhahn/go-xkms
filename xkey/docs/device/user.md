# Device Pairing and Enrollment — User Guide

> **Status: NORMATIVE** · Feature: `device` · Module: `go-xkms/xkey` · Last verified: 2026-09-29

This page covers the two things you bring a second machine into xkey's trust
boundary for: using a phone as a hardware key backend, and letting a remote
host reuse this one's key backends as an agent. For the day-to-day phone
operations after pairing (signing, FIDO2, PIV sync, OATH sync, sharing),
see [phone-hsm/user.md](../phone-hsm/user.md).

## Pair a phone over Bluetooth

```
xkey device scan
xkey device pair
xkey device pair --device "Pixel-8" --timeout 60s
```

Requires a binary built with `-tags ble` (the release binaries are). The
phone must be running the xkey-android app and advertising. Pairing performs
a Noise XX handshake and, unless your policy says otherwise, refuses to
complete if the phone's hardware attestation cannot be verified.

## After pairing, reach the phone over the network instead of BLE

`xkey device relay` is **not** a way to pair a phone — there is no QR code.
Pair with `xkey device pair` (BLE) first. Once paired, if BLE proximity is
not available for a later session (a headless host, a phone on a different
network segment), `xkey device relay` serves that same paired device's
session over TCP instead:

```
xkey device relay
xkey device relay --device "Pixel-8"
```

It binds loopback only by default; see
[phone-hsm/user.md](../phone-hsm/user.md#when-the-phone-is-not-on-the-same-bus)
for reaching it from the network and the rest of its flags.

## Enroll this machine as a remote agent

On the machine you want to grant remote access *to* xkey's local backends
(the master), start the agent server first — see
[agent/user.md](../agent/user.md). Then, on the machine that will connect
remotely:

```
xkey device enroll --server master.example.com:9443 --xkmsd-url grpcs://xkms.example.com:8443
```

This device generates its own key pair, gets it signed by the xkmsd
certificate authority, and confirms the master accepts the resulting
certificate — all in one step. A successful `enroll` means `connect` will
work immediately:

```
xkey device connect master.example.com:9443
```

If enrollment fails with "the master did not accept the issued agent
certificate," check that the master's `agent start --tls-ca` trusts the same
xkmsd certificate authority this device enrolled against.

## Check status, and unpair

```
xkey device list
xkey device status
xkey device unpair "Pixel-8"
```

A handshake or attestation-fingerprint mismatch on a previously paired
device is a security event, not routine connectivity noise — find out why
the phone's identity changed before re-pairing with `--force`.
