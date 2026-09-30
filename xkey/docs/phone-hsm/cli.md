# Phone as HSM — CLI

> **Status: NORMATIVE** · Feature: `phone-hsm` · Module: `go-xkms/xkey` · Last verified: 2026-09-29

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
into protecting this key. Supply the password with `--barrier-password-stdin`, a
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
(`oath sync`, `share`, `import`, `sync-*`, `enroll-phone`, `fido2 --backend
phone`) follows the same rule through `unsealDeviceLocalKey`.

## Using the phone as the key backend

```
xkey fido2 --backend phone --phone-device "Pixel-8"
```

Key operations then run inside the phone's TEE or StrongBox. Private keys never
cross the channel; only operations and results do.

## Attestation and enrollment

`device enroll` (agent-certificate enrollment, unrelated to phone pairing)
is [device/cli.md](../device/cli.md#device-enroll--device-connect--agent-enrollment)'s;
the verbs below are the phone-specific ones this folder owns.

| Verb | Flags |
|---|---|
| `device attest <key-id>` | `--device` (specific paired device), `--no-verify` (skip certificate chain verification), `--timeout` (default `1m0s`, includes biometric wait) |
| `device attest-device` | `--device` (defaults to the default device), `--force` (ignore the grace period and re-attest anyway), `--set-grace-period` (duration, e.g. `5m`, `30m`; default `0s`), `--barrier-password` / `--barrier-password-file` (opens a barrier if one exists — #42, see above) |
| `device device-info [device-name]` | — |
| `device enroll-phone` | `--device` (defaults to the default device), `--ca` (`local` or `xkms`, default `local`), `--subject` (subject DN to request), `--validity` (credential lifetime and re-attestation cadence; duration, default `0s` meaning 90 days), `--min-security-level` (`software`, `trusted_environment`, or `strongbox`; default `trusted_environment`), `--require-verified-boot` (default `true`), `--allow-package` (Android package name, repeatable), `--allow-signer` (hex SHA-256 signing digest, repeatable), `--allow-unpinned` (permit an allow-listed package with no signing digest; development only, default `false`) |

```
xkey device attest my-key
xkey device attest-device --device "Pixel-8"
xkey device device-info "Pixel-8"
xkey device enroll-phone --device "Pixel-8" --ca xkms --validity 2160h
```

## PIV on the phone

These live under `xkey piv`, not `xkey device` — see [piv/cli.md](../piv/cli.md)
for the rest of that group.

| Verb | Flags |
|---|---|
| `piv phone-list` | `--device`, `--timeout` (default `1m0s`) |
| `piv phone-generate <slot>` | `--algorithm`/`-a` (`ECDSA-P256`, `ECDSA-P384`, `RSA-2048`; default `ECDSA-P256`), `--device`, `--timeout` (default `1m0s`) |
| `piv phone-push-cert <slot> <cert-file>` | `--device`, `--timeout` (default `1m0s`) |
| `piv phone-pull-cert <slot>` | `--device`, `--output` (default stdout), `--timeout` (default `1m0s`) |

```
xkey piv phone-list --device "Pixel-8"
xkey piv phone-generate 9a --algorithm ECDSA-P384
xkey piv phone-pull-cert 9a --output cert.pem
```

## OATH, sharing and sync

`oath sync`/`push`/`pull` live under `xkey oath`, not `xkey device`; the
other verbs here are `xkey device` verbs. All are phone-backed, so they are
documented once, here.

| Verb | Flags |
|---|---|
| `oath sync` | `--device`, `--store` (default `~/.xkey/data/oath.json`), `--barrier-password` / `--barrier-password-file`, `--timeout` (default `1m0s`) |
| `oath push <name-or-id>` | Same flags as `oath sync` |
| `oath pull` | Same flags as `oath sync` |
| `device share <backend> <key-id>` | `--device`, `--label` (label for the shared key on the phone), `--timeout` (default `1m0s`) |
| `device import <key-id>` | `--backend` (target backend, default `software`), `--device`, `--timeout` (default `1m0s`) |
| `device share-policy list` | — |
| `device share-policy remove <backend> <key-id>` | — |
| `device share-policy set <backend> <key-id>` | `--allow` (default `false`), `--devices` (comma-separated fingerprints), `--share-public` (default `true`), `--share-private` (software keys only, default `false`), `--share-symmetric` (default `false`) |
| `device sync` | `--all` (default `true`), `--oath`, `--passwords`, `--trust-store` (select specific stores instead of all), `--dry-run`, `--device`, `--barrier-password` / `--barrier-password-file`, `--timeout` (default `1m0s`) |
| `device sync-pull` | Same flags as `device sync`, pull direction only |
| `device sync-push` | Same flags as `device sync`, push direction only |
| `device sync-status` | `--device`, `--barrier-password` / `--barrier-password-file`, `--timeout` (default `1m0s`) |

```
xkey oath sync --device "Pixel-8"
xkey oath push "GitHub" --device "Pixel-8"
xkey device share software my-key --device "Pixel-8" --label "backup key"
xkey device import my-key --device "Pixel-8"
xkey device share-policy set software my-key --allow --devices <fingerprint>
xkey device sync --device "Pixel-8" --passwords --oath
xkey device sync-status --device "Pixel-8"
```

## Connectivity

| Verb | Purpose |
|---|---|
| `device connect <address>` | Connect to a specific address |
| `device listen` | Wait for an inbound connection (opens a barrier if one exists — #42, see above) |
| `device relay` | Run the TCP relay path |

```
xkey device listen
xkey device relay
xkey device relay --device "Pixel-8"
xkey device relay --listen 192.0.2.10:8444
xkey device relay --allow-sync
```

(`device connect <address>` above is unrelated to phone pairing: it is the
agent-enrollment verb that reaches a previously enrolled master xkmsd using
the certificate obtained during enrollment -- see `device enroll`.)

`device relay` (go-xkms#1306) is the TCP counterpart to `device listen`'s
BLE peripheral, not a pairing mechanism: it serves an **already-paired**
device's phone-initiated session, pinned to that device's Noise static key
exactly the way `device listen` pins to it, and gated on the same live
attestation proof (the host sends `local.attestDevice` to the phone and
requires a verified answer) before serving anything. Pair with `device
pair` (BLE) first.

It shares every flag `device listen` registers -- `--device` (selects which
paired device to serve; falls back to the devices file's default device,
then the sole paired device), `--name`, `--timeout`, `--attestation-mode`,
`--tpm-device`, `--tpm-enrollment`, `--tpm-pcr-bank`, `--allow-sync`, the SO
PIN and barrier-password flags -- plus its own `--listen`.

`--listen` binds `phone.relay_listen_address` from the xkey config
(`XKEY_PHONE_RELAY_LISTEN_ADDRESS`; default `127.0.0.1:8444`, loopback
only), and the flag overrides it for one run: flag over environment over
file over the built-in default. The address must be `host:port`; a bare
`:port` binds every interface. Reachable from the network is an explicit
choice -- pass a non-loopback address (for example `0.0.0.0:8444`) only when
you intend the relay to accept connections from other hosts.

`--allow-sync` opts the session in to serving `remote.syncPasswords`,
`remote.syncOATH` and `remote.syncAll` -- the bridge methods that export the
password vault or OATH secrets to the phone. Without it those three methods
are refused; every other bridge method (signing, FIDO2, PIV, trust-store
sync, and so on) is unaffected. An enterprise policy sealed under the SO PIN
can lock this decision either way (`phone_sync_allow_secret_export` /
`lock_phone_sync_policy`), overriding `--allow-sync`.

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
