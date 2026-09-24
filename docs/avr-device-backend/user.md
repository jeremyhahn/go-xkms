# AVR Device Backend — User Guide

> **Status: NORMATIVE** · Feature: `avr-device-backend` · Repo: `go-xkms` · Last verified: 2026-09-23

## What this is for

You have a small AVR board running `arduino-generic` firmware with a secure
element on it. The element holds a P-256 keypair that was generated inside it on
a provisioning bench and cannot be read out. This backend lets a Go program hold
that device as an xkms key provider: read its public identity, and read what the
device says about its own root of trust.

## What you can do with it

- **Find out whether the device's key is really in hardware.** `AttestLevel`
  answers `hardware`, `software` or `unattested`, from the tier the device
  reports about itself.
- **Find out what it can actually compute.** `Algorithms` lists what the
  element's own capability bitmap claims. A typical ATECC608A says ECDSA P-256
  and HMAC-SHA256, and — correctly — not Ed25519: the part has no hardware for
  it.
- **Read the device's public identity.** `GetKey` returns a handle carrying the
  P-256 public point, validated against the curve.
- **Ask it to prove it is that device, right now.** `AttestKey` hands it a
  challenge and gets back a certificate the device minted and signed for that
  challenge alone. The challenge is `deviceattest01.DICENonce(keyAuthorization)`
  — hash it with that function, never by hand.
- **Check on the device.** `Health` gives uptime, free RAM and why the part last
  restarted. A board that keeps reporting a watchdog reset is a board to look
  at.
- **Read the element's serial number, on a bench.** `Identity` also reports
  whether each of the element's two zones is locked. A part with its config zone
  locked and its data zone open is half-provisioned — not a blank, not a
  finished device.

## What you cannot do with it, and why

- **Sign anything of your own.** The protocol has no command that signs a digest
  you supplied, deliberately: a signature over opaque bytes is a signature over
  whatever the holder of those bytes says it is. The device signs only documents
  it builds itself.
- **Generate, delete or rotate the key.** The identity is written on a
  provisioning jig and the element's zones are then locked, irreversibly. A new
  identity means a new part.
- **Decrypt.** The key is a signing identity.
- **Read the element serial from a fielded device.** Those commands are
  compiled out of a production image on purpose. `Identity` works on a
  provisioning image; a device record is keyed on the identity public key
  instead, which a fielded device will answer for.

## Reading an error

- `avr backend: this firmware carries no handler for the command` — the ordinary
  answer from a **production** image. Provisioning commands are compiled out on
  purpose: a device that could be re-provisioned over its own serial line would
  have no identity worth trusting. It is not a fault.
- `avr backend: device has no provisioned identity` — the part is blank. It
  refuses to speak for an identity it does not have, which is the right answer:
  evidence that verifies against a shared key proves nothing while looking
  exactly like evidence that proves something.
- `avr backend: device did not answer` — the link. Check the port, the baud
  rate, and whether something else has the device open.
- `avr backend: device speaks an unsupported protocol version` — the firmware's
  protocol **major** differs from this host's. Nothing past the capability reply
  can be trusted to mean what it appears to mean. Upgrade one end.
- `avr backend: unrecognised crypto tier` — the firmware is newer than this
  host. The device still attaches; its keys are reported `unattested` until the
  host learns the tier, which is the safe direction to be wrong in.

## When an attestation is refused

- `avr backend: device echoed a different challenge` — the certificate answers
  some other challenge. The device has no clock, so that nonce is the only thing
  separating a live answer from a recording; this is refused and never
  downgraded to a warning.
- `avr backend: attestation nonce is not the enrolment width` — the challenge is
  not 32 bytes. Most likely a raw key authorization instead of
  `DICENonce` of one, or the device's *other* nonce: the 16-byte one belongs in
  the evidence frame and means runtime freshness, not enrolment.
- `avr backend: unsupported on this build or part` — a software-tier device.
  It knows exactly what a certificate is and has no public half to certify. This
  is a part to change, not a build.
- `avr backend: the alias certificate was not produced by the device's element`
  — the certificate's key or signature is not what an ATECC608A makes. It holds
  a key only on P-256 and signs only ECDSA-SHA256.
- `avr backend: certificate chain verification failed` — you configured roots
  and this device does not descend from them.
- `dice: tcg-dice-UCCS-evidence extension not found` — the device put its
  challenge somewhere other than where the specification says. There is no
  fallback to another field, deliberately.

## A note about time

The device has no clock. Nothing it reports is a timestamp, and `Health.Uptime`
is not one either — it says how long the part has been running. Freshness, when
attestation arrives, will always be a nonce the verifier chose.
