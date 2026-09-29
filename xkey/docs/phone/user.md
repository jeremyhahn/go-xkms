# Phone Backend — User Guide

> **Status: NORMATIVE** · Feature: `phone` · Module: `go-xkms/xkey` · Last verified: 2026-09-29

## What this does

Uses a paired Android phone's hardware security element (TEE, or StrongBox)
to generate and hold your FIDO2 credential keys, instead of software or a
local TPM. The phone never sends a private key off the device; it signs, and
xkey relays the signature.

## 1. Pair your phone

Pairing itself — scanning, confirming, and the attestation check — is a
`device` verb; see phone-hsm's [user guide](../phone-hsm/user.md) for the
full walkthrough:

```
xkey device scan
xkey device pair
xkey device list -o json
```

Or, from the desktop GUI, use the **Pairing** view.

## 2. Use the phone as your FIDO2 backend (CLI)

```
sudo xkey fido2 --backend phone
```

Or target a specific paired phone if you have more than one:

```
sudo xkey fido2 --backend phone --phone-device "Pixel-8"
```

`xkey fido2` connects to the phone before it starts serving requests, so a
phone that is out of range or not paired is reported immediately rather than
on your first sign-in attempt. Requires a build with `-tags ble`.

## 3. Use the phone from the desktop GUI

Open the **Pairing** view. Paired phones show connection state; use the
**Attest** action to re-run the attestation check, and the security-factor
policy screen to require attestation for a specific device going forward.
The GUI keeps your phone's local session key (the desktop-side Noise
private key) sealed behind your barrier when one is set up, the same way
`xkey barrier` protects everything else.

## 4. No line of sight to your phone's BLE? Use the TCP relay

```
xkey device relay
```

Serves an **already-paired** phone's session over plain TCP instead of BLE
— useful when the phone and desktop are not in Bluetooth range of each
other but can reach each other over a network (go-xkms#1306). It is not a
pairing mechanism: pair the phone first with `xkey device pair` (BLE), then
use `xkey device relay` for later sessions. It pins to that paired device's
Noise static key and requires the same live attestation proof `xkey device
listen` requires, and binds to loopback only unless you pass `--listen` with
a non-loopback address. See phone-hsm's [cli.md](../phone-hsm/cli.md) for
every flag, including `--device`, `--allow-sync`, and the config key that
sets a default listen address.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `xkey fido2 --backend phone` fails immediately with a BLE-support error | Built without `-tags ble` |
| "device not found in paired devices" | `--phone-device` does not match any name or address in your paired devices; run `xkey device list` |
| Pairing refuses with a barrier error | A barrier is initialized on this host but not currently open — unseal it first (`xkey barrier unseal`), then pair or connect |
| Connection drops when the phone's Bluetooth address changes | Expected on Android — it rotates its BLE address periodically; xkey rescans and updates the saved address automatically |

## See also

- [phone-hsm](../phone-hsm/user.md) — pairing, the Noise session, and the
  full `device` command group
- [ble](../ble/) — BLE GATT protocol and the Android app
