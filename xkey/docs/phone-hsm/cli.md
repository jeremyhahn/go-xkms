# Phone as HSM — CLI

> **Status: NORMATIVE** · Feature: `phone-hsm` · Module: `go-xkms/xkey` · Last verified: 2026-09-21

Binary: `xkey`, group `device` (`xkey/cmd/xkey/cmd/device*.go`).

## Pairing

| Verb | Flags |
|---|---|
| `device scan` | — |
| `device pair` | `--device` (name or address), `--timeout` (scan timeout), `--force` (re-pair even if already paired), `--so-pin-stdin` / `--so-pin` / `XKEY_SO_PIN` (verify a sealed enterprise policy so it is honoured in both directions; see below), `--barrier-password` / `--barrier-password-file` / `XKEY_BARRIER_PASSWORD` (seal the new pairing's key, if a barrier exists; see *The barrier, when one exists* below) |
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

## The barrier, when one exists (#42)

`device pair`, `device listen` and `device attest-device` open this host's
barrier, if one has been initialized, **before** doing anything else with a
paired device's Noise static private key — pairing to seal the new key into
it, the other two to unseal an existing one.

**A host that has never run `xkey barrier init` is not refused.** Pairing
writes the key in the same legacy plaintext form xkey has always used, and
logs one warning naming the fix:

```
$ xkey device pair --device "Pixel-8"
...
level=WARN msg="pairing key stored unencrypted: no barrier is initialized on this host; run \`xkey barrier init\` to protect it" device=Pixel-8
```

`device listen` and `device attest-device` warn the same way when reading
such a record, and none of the three prompt for a barrier password in this
case — there is nothing to unseal.

**A barrier that exists but cannot currently be opened is always a
refusal.** A wrong or missing password against an initialized barrier
refuses the command; there is no fallback to plaintext once you have opted
into protecting this key. Supply the password with `--barrier-password`, a
file via `--barrier-password-file`, or `XKEY_BARRIER_PASSWORD` for unattended
use (e.g. `device listen` run from a service unit):

```
xkey barrier init                                          # once, to start protecting this key
xkey device pair --barrier-password-file /run/secrets/xkey-barrier
XKEY_BARRIER_PASSWORD="$(cat /run/secrets/xkey-barrier)" xkey device listen
```

**There is no migration between the two forms.** Which form a reader expects
is decided by this host's barrier state at read time, not by inspecting the
stored record: with a barrier open, only the sealed form is accepted; with
none open, only the legacy plaintext form is. A device paired before a
barrier existed keeps connecting as long as that stays true — but running
`xkey barrier init` on a host with existing legacy-plaintext pairings does
**not** upgrade them: the next `device listen` or `device attest-device`
against one now refuses with a re-pair message (`pairing:` `... re-pair this
device`) instead of connecting. Re-pair the device (`xkey device pair`) to
write a fresh sealed record. Every other device-backed verb below
(`oath-sync`, `share`, `import`, `sync-*`, `enroll-phone`, `fido2 --backend
phone`) follows the same rule through `unsealDeviceLocalKey`.

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
| `device attest-device` | Device-level attestation (opens a barrier if one exists — #42, see above) |
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
| `device listen` | Wait for an inbound connection (opens a barrier if one exists — #42, see above) |
| `device relay` | Run the TCP relay path |

```
xkey device listen
xkey device connect 192.0.2.10:port
xkey device relay
xkey device relay --listen 192.0.2.10:8444
```

`device relay` binds `phone.relay_listen_address` from the xkey config
(`XKEY_PHONE_RELAY_LISTEN_ADDRESS`; default `:8444`, every interface), and
`--listen` overrides it for one run: flag over environment over file over
the built-in default. The address must be `host:port`; a bare `:port` binds
every interface, an address binds that interface.

The relay is the host's end of the Noise session (`pkg/phone/tcp_server.go`
performs the handshake, decrypts each request and dispatches it), so it is
a trusted xkey host component that handles plaintext after decryption; only
the network between the phone and this host sees encrypted frames alone.

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
