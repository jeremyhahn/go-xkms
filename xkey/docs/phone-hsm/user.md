# Phone as HSM — User Guide

> **Status: NORMATIVE** · Feature: `phone-hsm` · Module: `go-xkms/xkey` · Last verified: 2026-09-29

## What this does

Turns your phone into the secure element behind xkey. Keys are generated inside
the phone's hardware — the TEE, or StrongBox on Android — and never leave it.
Your desktop asks the phone to sign; the phone signs.

You need the xkey-android app on the phone.

## Pairing

```
xkey device scan
xkey device pair
xkey device list -o json
```

Or a specific device:

```
xkey device pair --device "Pixel-8" --timeout 60s
```

Pairing is the moment that matters: both devices exchange and verify each
other's identity, and the phone's hardware attestation is bound into the
connection from then on. Everything afterwards rests on it.

That is true whichever way you pair. The desktop GUI's **Pair** button runs the
same attestation as `xkey device pair` and applies the same policy: a phone
whose hardware attestation cannot be verified is **refused by default**, and
nothing is written down. If you have decided to accept such a device anyway,
set `allow_unattestable_devices: true` under `attestation_policy` in
`devices.yaml` (see [`../device/engineering.md`](../device/engineering.md)); the pairing
then completes with no security level, boot state or device fingerprint on
record, and the GUI says so. An enterprise policy can lock that choice closed.

`--force` re-pairs over an existing pairing. It throws the old binding away —
use it when you mean to, not to make an error go away.

**Your desktop's own pairing key can be protected too, if you set up a
barrier.** Pairing generates a private key for *this* machine — the
credential that lets the phone trust your desktop back. If you have set up a
barrier (`xkey barrier init`, or the desktop GUI's setup wizard), xkey seals
this key under it the same way it protects everything else under `xkey
barrier`, and never writes it to disk in the clear. If you have **not** set
one up, xkey pairs anyway, exactly as it always has, and tells you about it:

```
xkey barrier init                                            # optional, protects this key
xkey device pair --barrier-password-file /run/secrets/xkey-barrier
```

or, with no barrier at all:

```
$ xkey device pair --device "Pixel-8"
...
pairing key stored unencrypted: no barrier is initialized on this host; run `xkey barrier init` to protect it
```

`device listen` and `device attest-device` behave the same way on read: if a
barrier exists they open it, and if not they warn and continue. The desktop
GUI mirrors this too — **Pair** and **Connect** use the barrier when the app
has one set up (which in the ordinary case just means the app itself is
unlocked) and fall back to the same warning when it does not.

The one case that **does** refuse: a barrier that exists but is currently
locked (the app is locked, or the CLI wasn't given a working password). Once
you have chosen to protect this key, a locked barrier is not treated as
permission to fall back to writing it unencrypted — see the troubleshooting
table below.

A device you paired before setting up a barrier, or on a host that still has
none, keeps working: the first successful `device attest-device` or `device
listen` against it **after** a barrier exists quietly upgrades its stored
key to the protected form, after which the file never holds it in the clear
again.

**Under a sealed enterprise policy.** If your Security Officer sealed the
device's policy, `xkey device pair` refuses a phone whose attestation cannot be
verified unless the sealed policy says otherwise — and it reads that policy
only after verifying it with the SO PIN. A fleet that pairs development
handsets locks the setting open in the sealed policy and pairs with

```
echo -n "$SO_PIN" | xkey device pair --so-pin-stdin
```

Without the SO PIN the sealed policy is not consulted and the refusal stands.
A sealed policy that does not verify — the file was edited after sealing —
refuses the pairing outright; ask the SO to re-seal it.

## Using it

```
xkey fido2 --backend phone --phone-device "Pixel-8"
```

Now the credentials xkey holds live in the phone. Someone with your laptop does
not have them.

## Checking the phone really is what it claims

```
xkey device attest my-key
xkey device device-info "Pixel-8"
xkey device status --device "Pixel-8"
```

Android hardware attestation proves the key was generated inside the phone's
secure element, and the evidence chains to Google's roots — which have to be in
your truststore, classified `android-hardware`. See
[`../platform-trust/user.md`](../platform-trust/user.md).

## PIV, OATH and sync

```
xkey piv phone-list
xkey piv phone-generate 9a
xkey piv phone-push-cert 9a cert.pem
xkey piv phone-pull-cert 9a

xkey oath sync
xkey device sync-status
```

## When the phone is not on the same bus

`xkey device relay` (go-xkms#1306) is not a pairing mechanism -- it serves
an **already-paired** device's session over TCP, pinned to that device's
Noise static key exactly the way `device listen` pins to it, and gated on
the same live attestation proof. Pair with `device pair` (BLE) first.

```
xkey device listen
xkey device relay
xkey device relay --device "Pixel-8"
```

(`device connect <address>` is a different, unrelated verb: agent
enrollment against a master xkmsd, not phone connectivity.)

The relay listens on `phone.relay_listen_address` from your xkey config,
`127.0.0.1:8444` (loopback only) unless you set it. Reachable from the
network is an explicit choice: set a non-loopback address in the config
file, in the environment, or for one run on the command line; each
overrides the one before:

```yaml
phone:
  relay_listen_address: "192.0.2.10:8444"
```

```
XKEY_PHONE_RELAY_LISTEN_ADDRESS=192.0.2.10:8444 xkey device relay
xkey device relay --listen 192.0.2.10:8444
```

`--allow-sync` opts the session in to serving `remote.syncPasswords`,
`remote.syncOATH` and `remote.syncAll` -- the methods that export the
password vault or OATH secrets to the phone. Without it those three refuse;
every other bridge method is unaffected.

The relay is this machine's end of the session, not a blind pipe: it
performs the Noise XX handshake with the phone, decrypts each request and
answers it, so it runs only on the trusted xkey host, never on an
intermediate one. The session is end-to-end between the phone and this
host; anything on the network in between sees only encrypted frames.

## One thing at a time

The connection is deliberately serialised, so running several commands against
the phone in parallel will not be faster and may fail outright. The encryption
uses a per-message counter, and out-of-order frames are rejected.

## Losing the phone

Unpair it:

```
xkey device unpair "Pixel-8"
```

The keys inside it cannot be extracted — that is exactly why you put them there,
and it is also the recovery constraint. Anything that only existed on that phone
is gone. Keep a second credential enrolled before you need one.

## One current limitation, stated plainly

The encrypted channel uses a fixed cipher suite
(`Noise_XX_25519_ChaChaPoly_SHA256`) with no FIPS-approved alternative. If you
are deploying into an environment that requires FIPS-approved cryptography end
to end, this path does not currently satisfy it. Changing it needs the phone app
to change in the same release, so it is coordinated work rather than a setting.

## Troubleshooting

| What you see | What it means | What to do |
|---|---|---|
| no devices found | the app is not running, or the transport is not available | open xkey-android; try `--timeout` |
| pairing times out | scan window too short, or the phone is not discoverable | `--timeout 60s` |
| **handshake failure (key mismatch)** | the phone did not prove it holds the key you paired with | **do not `--force`.** Find out why the key changed |
| **device fingerprint mismatch** | the phone presented a different hardware identity than it did at pairing — honest after a factory reset or app reinstall, alarming otherwise | **do not `--force`.** Investigate before re-pairing |
| **attested key changed since pairing** | `device attest-device` found a different hardware key; the existing binding was left untouched | if you deliberately reset the phone, re-pair with `--force`; if not, treat as suspicious |
| **the peer did not prove possession of the attested key** | the phone could not sign this connection's challenge — an outdated app, or not the handset you paired with | update the phone app; if it is current, investigate |
| **device answered with an unsupported attestation protocol version** | the phone app predates challenge-response attestation | update xkey-android |
| **device attestation could not be verified - pairing refused** (GUI) | the phone's attestation chain does not reach a trusted Android hardware root, it did not sign this pairing's challenge, or the desktop has no trust store to judge it with | check the trust store (`xkey trust list`); update xkey-android; only if you accept an unattested device, set `allow_unattestable_devices: true` |
| "not connected" after an error | the session ended | reconnect; a Noise session cannot resume mid-stream |
| commands are slow in parallel | the channel is serialised | run them in sequence |
| attestation rejected | the Android hardware root is missing or misclassified | add it with purpose `android-hardware` |
| `password` commands fail over the phone | the channel does not carry the vault | expected — use the desktop store |
| the phone app disconnects when it sleeps | power management | keep it awake for long operations |
| **stored device fingerprint is not valid hex** | the saved pairing record is corrupt or truncated | re-pair the device; the connection is refused until you do |
| **pairing key stored unencrypted: no barrier is initialized...** (a warning, not an error) | no barrier exists on this host, so this desktop's own pairing key was written/read in the legacy plaintext form | informational; run `xkey barrier init` if you want it protected |
| **barrier password required** / **failed to unseal barrier** | a barrier exists but no password (or the wrong one) was supplied; the operation is refused, since a barrier you set up does not fall back to plaintext | `--barrier-password`, `--barrier-password-file`, or `XKEY_BARRIER_PASSWORD` |

Those two rows are security events rather than nuisances, and the key mismatch
is the more serious of the two: it means the other end could not prove it holds
the key you paired with. Re-pairing with `--force` will make either message go
away and will not answer the question.

### A corrupt stored fingerprint refuses the connection

A stored fingerprint that is not valid hex, or is not the right length, now
**refuses the connection** rather than continuing with the check disabled.

The refusal is deliberate and is not recoverable by retrying. A malformed value
used to be treated the same as no fingerprint at all — the check was silently
skipped rather than failed, so anyone able to edit the pairing file could
switch it off by flipping a single character, and nothing would say so.

To be clear about what that did and did not open up: your phone is also
authenticated by its **paired key**, and that check is separate and always
applies. Losing the fingerprint check does not let just any phone connect. It
drops one of two checks, leaving the paired key on its own. Turning off a check
you asked for, without telling you, is reason enough to refuse.

> **What this check does and does not tell you.** The stored fingerprint
> identifies the **security key inside your phone** — one generated in the
> handset's secure hardware when you first set the app up, and kept for as long
> as the app is installed. Two phones cannot have the same one.
>
> On reconnect the phone sends that value back so the two sides agree on who is
> connecting. That part is just a name being repeated, and on its own it would
> prove nothing. What backs it up is the step immediately after: your computer
> sends the phone a fresh random challenge, and the phone has to **sign it with
> that same hardware key, then and there**. A recording of an earlier connection
> will not do, and neither will a copy of the phone's certificates — those are
> public.
>
> So a successful connection now says three things: the key really is inside a
> genuine, locked, verified-boot handset (the manufacturer's certificate chain
> says so); it is the same key you paired with; and whoever is on the other end
> holds it right now.
>
> The **paired key** check is still there and still separate: the encrypted
> handshake proves the other end holds the key exchanged at pairing, and refuses
> the connection otherwise.
>
> A fingerprint mismatch means the phone is presenting a different hardware
> identity than the one you paired with. That happens honestly after a factory
> reset or a reinstall — and dishonestly if it is not your phone. Investigate
> before re-pairing.
>
> One caveat worth knowing: a device paired **before** this check existed is no
> longer connectable at all — there is no weaker binding to keep working under.
> Re-pair it with `xkey device pair` (or the GUI pairing flow) to establish a
> fresh challenge-response binding.

Recovery is to **re-pair the device**, which writes a fresh record. The error
names the offending value — truncated, with its true length — so you can tell
which stored record is at fault without opening the file.

## Where to go next

- The authenticator that uses the phone: [`../virtual-authenticator/user.md`](../virtual-authenticator/user.md)
- Trusting Android attestation roots: [`../platform-trust/user.md`](../platform-trust/user.md)
- Hardware-backed keys generally: [`../../../docs/crypto-backends/user.md`](../../../docs/crypto-backends/user.md)
