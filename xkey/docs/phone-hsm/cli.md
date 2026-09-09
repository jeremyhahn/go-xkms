# Phone as HSM — CLI

> **Status: NORMATIVE** · Feature: `phone-hsm` · Module: `go-xkms/xkey` · Last verified: 2026-09-09

Binary: `xkey`, group `device` (`xkey/cmd/xkey/cmd/device*.go`).

## Pairing

| Verb | Flags |
|---|---|
| `device scan` | — |
| `device pair` | `--device` (name or address), `--timeout` (scan timeout), `--force` (re-pair even if already paired), `--so-pin-stdin` / `--so-pin` / `XKEY_SO_PIN` (verify a sealed enterprise policy so it is honoured in both directions; see below) |
| `device list` | — |
| `device status` | `--device` (check a specific device) |
| `device unpair <device-name>` | `--force` (skip confirmation) |

```
xkey device scan
xkey device pair
xkey device pair --device "Pixel-8" --timeout 60s
echo -n "$SO_PIN" | xkey device pair --so-pin-stdin   # sealed enterprise policy, verified
xkey device list -o json
xkey device status --device "Pixel-8"
```

Pairing is the moment of trust: both ends exchange and verify static public
keys, and the phone's attestation fingerprint is bound into the session. Use
In an enterprise deployment the config directory is sealed (`xkey_policy.hmac`
is present) and the SO-controlled pairing policy is consulted only after it has
been verified with the Security Officer PIN. Supply it with `--so-pin-stdin`
(preferred), `XKEY_SO_PIN` or `--so-pin`; a sealed policy that does not verify
refuses the pairing (`ErrPairingPolicyRefused`). Without an SO PIN the sealed
policy is not consulted and an unattestable device is refused whatever
`devices.yaml` says (#118).

`--force` only when you mean to replace an existing pairing — it discards the
old binding.

## Using the phone as the key backend

```
xkey fido2 --backend phone --phone-device "Pixel-8"
```

Key operations then run inside the phone's TEE or StrongBox. Private keys never
cross the channel; only operations and results do.

## Attestation and enrollment

| Verb | Purpose |
|---|---|
| `device attest <key-id>` | Prove a key was generated in the phone's hardware |
| `device attest-device` | Device-level attestation |
| `device device-info [device-name]` | Report device details |
| `device enroll` | Enrol the device |
| `device enroll-phone` | Enrol the phone specifically |

```
xkey device attest my-key
xkey device device-info "Pixel-8"
```

## PIV on the phone

| Verb | Purpose |
|---|---|
| `device phone-list` | List phone-held PIV material |
| `device phone-generate <slot>` | Generate a key in a phone PIV slot |
| `device phone-push-cert <slot> <cert-file>` | Store a certificate in a slot |
| `device phone-pull-cert <slot>` | Retrieve a slot's certificate |
| `device piv-sync` | Synchronise PIV state |

## OATH, sharing and sync

| Verb | Purpose |
|---|---|
| `device oath-sync` | Synchronise OATH credentials |
| `device share <backend> <key-id>` | Share a key with the phone |
| `device import <key-id>` | Import a key from the phone |
| `device share-policy list\|set\|remove` | Manage sharing policy |
| `device sync` / `sync-status` / `sync-push` / `sync-pull` | State synchronisation |
| `device push <name-or-id>` / `pull` | Move individual items |

## Connectivity

| Verb | Purpose |
|---|---|
| `device connect <address>` | Connect to a specific address |
| `device listen` | Wait for an inbound connection |
| `device relay` | Run the TCP relay path |

```
xkey device listen
xkey device connect 192.0.2.10:port
```

The relay carries an already-encrypted Noise session; it cannot read the
traffic.

## One operation at a time

The channel is deliberately serialised. A Noise session advances a nonce per
message, and out-of-order frames are rejected by the phone — so parallel
commands against one paired device will not go faster, and may fail.

## Exit codes

`0` on success. Non-zero for no device found, a scan timeout, a handshake
mismatch, or a phone-side error.

**A handshake or fingerprint mismatch is a security event**, not a connectivity
problem. Do not resolve it by re-pairing with `--force` without finding out why
the identity changed.

## Parity coverage

The `go-xkms` parity runner covers `xkmsctl`, not `xkey`. Coverage here is
`xkey/pkg/pairing` unit suites, the USB transport suite, the Android
compatibility suites, and the manual end-to-end procedure — a real phone is
required for the last of these.
