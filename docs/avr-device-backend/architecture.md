# AVR Device Backend — Architecture

> **Status: NORMATIVE** · Feature: `avr-device-backend` · Repo: `go-xkms` · Last verified: 2026-10-11

## The problem

A classic AVR part with a secure element on its I2C bus has a real identity: a
P-256 keypair generated inside the element on a provisioning jig, whose private
half has no path out. That identity is worth the same things every other
hardware identity in this library is worth — an enrolment record, an attestation
level a policy can act on, a device a CA can issue to.

What it is not is a general key store. The part has 2 KB of RAM, no clock, and a
wire protocol with 64-byte payloads. Presenting it as an ordinary backend that
"just happens to be slow" would have callers ask it for an RSA key, a decryption
or a signature over a digest they chose, and get a failure at the point where
they had already committed to it.

## Shape chosen: a read-only key provider that reports from the device's CAPS reply

`pkg/backend/avr` implements `types.KeyProvider` and nothing more. Every answer
it gives about the device comes from the device's own `CAPS` reply, read once at
construction and cached; every operation the part cannot perform refuses with a
sentinel that says which permanent property of the part or the protocol refuses
it.

```
caller ──opens link──► io.ReadWriter
                          │
             aggeneric.Device (arduino-generic/sdk/go)   ◄── owns the wire
                          │
                   avr.Backend  ──► types.KeyProvider
```

The backend does not own the link. A device is one physical thing with several
concerns on it, and the code that opened the port is the code that should close
it; `Close` marks the backend closed and leaves the port alone.

It does own the **conversation** over that link, and has to. `aggeneric.Device`
is a strict request/response client with no locking of its own — one sequence
number, one receive buffer, one event list — while `types.KeyProvider` requires
a thread-safe implementation, so the backend serialises every command on a
mutex and holds it across the whole of a multi-frame exchange. For the same
reason it applies `Config.RequestTimeout` to the device rather than only to each
call's context: `Do` derives its read deadline from the device's own timeout and
sees a context only between reads, so a deadline that never reached the device
would not be the deadline the read got.

## The boundary with arduino-generic

`arduino-generic` owns the AVR wire protocol, the firmware that speaks it and
the host SDK for it. This package owns none of those. Every byte that reaches
the wire is put there by an SDK call — there is no frame built here, no command
id declared here, no reply layout parsed here.

That boundary is what decides what this feature contains. Where the SDK has no
call, the capability is absent and says so, rather than being reconstructed from
the firmware's headers. A second copy of a wire format is a copy that drifts,
and the half that drifts is always the one nobody is testing against real
firmware.

## Why `Capabilities.Keys` is false

`Keys` reads as "generates and stores keys". This backend does neither: the
identity is created on a provisioning jig, inside an element whose zones are
then locked irreversibly, by firmware that is replaced before the part ships.

It is also load-bearing elsewhere. `pkg/xkms/algorithms.go`'s
`BuildAlgorithmsResponse` advertises ECDSA at four curve sizes, RSA at three key
sizes and Ed25519 for **every** backend whose `Keys` is true. For this device
that would claim eight algorithms it cannot perform, one of which — Ed25519 —
the ATECC608A has no hardware for at all. A host that negotiated a peer down
onto it would fail at the moment it mattered most.

Callers that want to know what the device can perform call `Backend.Algorithms`,
which answers from the device's own capability bitmap.

## Attestation

`AttestKey` asks the device to mint an alias certificate for a challenge —
`ATTEST_CERT`, which the SDK pages internally — and checks what came back.

```
verifier nonce = SHA-256(ACME key authorization)       32 bytes
        │        deviceattest01.DICENonce
        ▼
   device mints and signs an alias certificate, carrying the nonce in
   the eat_nonce claim of tcg-dice-UCCS-evidence
        │
        ▼
   parse → dice.Verify: curve and signature algorithm, the UCCS
   extension, constant-time nonce compare, operational flags, UEID,
   anchor (when roots are configured)
```

The nonce check is **unconditional**. The device has no clock, so that nonce is
the only thing separating a live answer from a replayed recording, and a
mismatch refuses. Anchoring is conditional, because roots belong to whoever
configured them and a device on a bench has none; `Attestation.Anchored` reports
which happened and never conflates "no roots configured" with "anchored".

This host never hashes the key authorization. `deviceattest01.DICENonce` is the
one place that hashing happens, so a device, a provisioning tool and a verifier
cannot each hash something slightly different — a trailing newline, the token
rather than the whole authorization — and produce a mismatch whose cause is
invisible from either end. A caller that passes a raw key authorization is
refused for its width.

### One verifier: `dice.Verify`

`checkAliasCertificate` parses the leaf and hands it, with any configured
intermediates, to `dice.Verify` (`pkg/backend/avr/attestation.go:178-212`).
Nothing about the DICE formats is reimplemented here.

The AVR alias profile emits **exactly one** extension:
`tcg-dice-UCCS-evidence`, critical. The UEID and the firmware measurement travel
as CWT claims 256 and 273 *inside that extension's claims set* rather than as
X.509 extensions of their own, because the certificate is assembled on an 8-bit
part from a fixed PROGMEM template and every extra extension costs flash the
part does not have. `dice.Verify` accepts a UCCS-only leaf (DICE Attestation
Architecture §6.1.4 permits UCCS "in place of" `DiceTcbInfo`) and reads the
UEID with `dice.DeviceUeid`, which finds claim 256; see
[`../dice-device-identity/`](../dice-device-identity/). The result reaches the
caller as `Attestation.Ueid`, type byte included (`attestation.go:80-84`), with
`Attestation.Claims` still carrying every claim as the raw CBOR the device
encoded.

`RequireDeviceSignedLeaf` is set (`attestation.go:207`): the alias certificate
is signed by the DeviceID key in the same element, whose certificate is not in
the chain, so without it nothing would pin the leaf's signature algorithm to
the ECDSA-SHA256 the element emits.

## Enrolment over ACME device-attest-01

The evidence `AttestKey` returns is the `dice` attestation format of
`pkg/acme/challenges/device-attest-01`: `Attestation.CertificateDER` goes, as
the device sent it, into the attestation object's `x5c`. The server verifies it
against `challenges.device_attest.dice_roots`, with
`dice_require_device_signed_leaf: true` for this profile
(`pkg/config/acme.go:810-820`), and authorizes the order only for the identity
the evidence carries — the lowercase hex of the UEID read by `dice.DeviceUeid`
(`pkg/acme/challenges/device-attest-01/identity.go:162-171`).

`pkg/acme/client/device_attest_dice_e2e_test.go` proves the whole path against
the real arduino-generic firmware compiled for the host and started by the
SDK's `agsim` simulator (built by `make agsim`): the order is for the device's
UEID, the evidence answers the challenge's nonce, the CSR is bound to the alias
key, and the issued certificate carries the UEID as its `permanentIdentifier`.
Refusals for another UEID, another nonce, untrusted roots and a CSR for another
key are pinned beside it.

### Limitation: a physical device cannot finish enrolment

Finalization needs a CSR signed by the attested key, which for this profile is
the DeviceID key inside the element. The firmware has no command that signs a
CSR, and `Backend.Signer` returns `ErrSigningUnsupported`
(`pkg/backend/avr/backend.go:436-441`) because the protocol deliberately signs
no host-supplied digest. The end-to-end test completes only because the
simulator's DeviceID key is a published **test** key whose private half the
test derives to sign the CSR (`testDeviceIDSeed`). A real part answers the
challenge but cannot produce the CSR, so there is no production adapter from
this backend to the ACME client's `TPMModule`; closing that gap needs a
firmware command that signs a CSR it assembles itself.

## Rejected alternatives

**A `crypto.Signer` whose `Sign` always fails.** It would put the discovery that
this device cannot sign at the end of a protocol exchange the caller had already
committed to. `GetKey` returns a `*DeviceKey` that fails the `crypto.Signer`
assertion instead, which puts the discovery where a negotiation can still act on
it.

**Returning an unverified certificate when no roots are configured.** The
certificate is returned, but only after every check that does not need a root
has passed — the challenge above all. What is optional is anchoring, not
freshness. A `nil` trust store never means "skip the nonce".

**Inferring hardware backing from the attestation feature bit.** The bit says a
command is compiled in. The crypto tier says what the root of trust is. Only the
second is an attestation claim, and a device can report the first with the
second set to software.

**Treating an unrecognised crypto tier as at least as strong as the last one
this host knows.** Tiers extend and never renumber, so a larger number carries
no promise. An unknown tier reports `AttestLevelUnattested` and an error.

**Refusing to attach to a device whose tier or protocol minor is newer than this
host.** That would take a fleet down on a host upgrade alone. A newer minor is
tolerated; an unknown tier attaches and degrades. Only a protocol **major**
mismatch refuses, because past that the frames themselves may not parse.
