# DICE Device Identity — Architecture

> **Status: NORMATIVE** · Feature: `dice-device-identity` · Repo: `go-xkms` · Last verified: 2026-10-11

## The question this answers

A constrained device has no TPM, no secure element running a rich OS, and no
clock. It still has to prove two things to a CA before that CA will issue it an
identity: *which device it is*, and *what firmware it is running*.

TCG DICE (Device Identifier Composition Engine) answers both with one
construction. The device derives its identity from a Unique Device Secret and a
measurement of the firmware it is about to run, so a change to the firmware
produces a different identity. The evidence travels in an X.509 chain carrying
three TCG extensions, and this feature is the parser, the verifier and the
certificate profile for them.

DICE is the **fourth** attestation format in this repository, beside TPM 2.0,
Android Key and YubiKey PIV. It is the only one for a device with no clock.

## Language

This feature provides **DICE-based device identity with a hardware root of
trust**. It is deliberately not described as "TCG DICE compliant": the AVR
profile meets the TCG hardware requirements only partially, and the device says
so on the wire — `OperationalFlags.notSecure` is set whenever the device
reports a software-only tier, and the CA carries that claim onto the
certificate rather than dropping it.

## Ownership

| Half | Owner | Where |
|------|-------|-------|
| ASN.1 structures, verification | this feature | `pkg/attestation/dice/` |
| The invariants gate entry | this feature | `pkg/attestation/invariants.go` |
| The IDevID certificate profile | this feature | `pkg/ca/profile_dice.go` |
| OID registries | this feature | `pkg/ca/tcg_oids.go`, `pkg/certstore/types.go` |
| The ACME format tag | this feature | `pkg/acme/challenges/device-attest-01/` |
| Talking to the device | the AVR backend | `pkg/backend/avr/` |
| The AVR wire protocol and firmware | `arduino-generic` | not this repo |
| Device registry and fleet policy | `go-trusted-platform` | not this repo |

## Data flow

```
device                      CA / verifier
------                      -------------
                      <---  nonce
mint alias certificate
  DiceTcbInfo
    fwids      = firmware measurement
    flags      = operational states
    vendorInfo = vendor-defined device state
  TcgUeid      = device identifier (optional)
  UccsEvidence
    uccs       = CBOR claims set, eat_nonce (10) = the nonce,
                 ueid (256) = device identifier (optional)
                       --->  chain + CSR
                             1. anchor the chain          (dice.Verify)
                                every critical DICE extension
                                cleared to do so decodes
                             2. ECDSA P-256 device keys   (dice.Verify)
                             3. nonce matches             (dice.Verify)
                             4. operational states permitted
                             5. CSR key == alias SPKI     (attestation.VerifyInvariants)
                             6. issue                     (ca "dice-idevid")

Steps 1-4 and step 5 are one exchange for a CSR carrying its evidence, and TWO
for ACME: device-attest-01 delivers the chain at the challenge and the CSR at
finalization. There the leaf is carried across as a VerifiedAttestation and
step 5 is BindCSRKey, which runs before issuance. The challenge verifier
refuses to answer for the dice format on its own, so step 5 cannot be the step
that gets skipped.
```

## Decisions

### ECDSA P-256, and nothing else

The hardware root of trust is an ATECC608A. It holds P-256 keys and has no
hardware Ed25519, so a DICE certificate presenting any other key was not
produced by that hardware. `dice.Verify` refuses it rather than reporting
hardware backing the device does not have. There is no Ed25519 path and none is
advertised.

The constraint applies to the **leaf** and to any certificate above it carrying
a DICE extension — those are device-resident. It stops there: the manufacturer
CA that anchors the device is not the hardware root of trust, and holding it to
the device's curve would refuse every deployment whose CA is stronger than its
devices.

The key and the signature algorithm are checked on two *different*
certificates, because they belong to two different parties. A certificate's
public key is its subject's; the algorithm it was signed with is its issuer's.

That leaves the case where the issuer is device-resident and its certificate is
not in the chain, which is the ordinary AVR shape: the device has nowhere to
keep its DeviceID certificate, so the chain is the alias leaf alone or a
DeviceID intermediate carrying no DICE extension of its own. There is then no
certificate to check the algorithm on, and an alias signed with ECDSA-SHA384
would verify. `VerifyOptions.RequireDeviceSignedLeaf` is how a profile that
knows its leaf was signed by the element says so; `pkg/backend/avr` sets it.

### Freshness is the verifier's nonce, always

A DICE device has no clock. There is no timestamp it could supply that would
mean anything, so no code in this feature compares a device-supplied time
against the host's. `VerifyOptions.CurrentTime` exists and moves only the
certificate expiry check — the verifier's own clock, used for nothing else.

The nonce travels in the `eat_nonce` claim (CWT claim key 10) of the CBOR
claims set inside `tcg-dice-UCCS-evidence` (§6.1.4). That is the
specification's own mechanism, and interoperability is why it was chosen:
another DICE verifier reading the same certificate finds the challenge where
it expects it, at a registry-assigned claim key rather than in a field whose
meaning each vendor defines.

The extension is unsigned by design — §6.1.4: "the certificate signature
authenticates, and integrity protects UCCS contents" — so nothing in the
parser verifies a signature over the claims. The certificate's own signature,
already checked by the time the claims are read, is what authenticates them.

There is **no fallback to `DiceTcbInfo.vendorInfo`**, the placement this
feature used before. A fallback would mean a device that echoes the challenge
in the wrong field still verifies, which would leave the move having bought
nothing. A leaf with no UCCS extension is refused with
`ErrUccsEvidenceNotFound`, and a claims set with no nonce with
`ErrNonceClaimMissing`; the two are distinct because an operator needs to tell
a device that answered the wrong way from one that did not answer.

### One device identifier, two placements

The DICE architecture lets a device state its UEID as the `tcg-dice-Ueid`
extension or as the EAT `ueid` claim (CWT key 256) inside its UCCS evidence. A
device carries the one it can afford: the arduino-generic alias certificate is
built on an 8-bit part from a fixed template with room for one DICE extension,
so it uses the claim (`pkg/attestation/dice/uccs.go:60-66`). Every reader in
this repo goes through `dice.DeviceUeid` (`extension.go:690`) — `dice.Verify`
and the device-attest-01 identity gate
(`pkg/acme/challenges/device-attest-01/identity.go:163`) — so no reader can
miss a claim-only device. A certificate stating both must state the same value;
a disagreement is `ErrUeidConflict`, because choosing one would make the
device's identity depend on which placement a reader happened to consult.

### The UCCS extension is not carried onto the IDevID

The `dice-idevid` profile in `pkg/ca` carries `tcg-dice-TcbInfo` and
`tcg-dice-Ueid` from the request onto the certificate, and deliberately not
`tcg-dice-UCCS-evidence`. An IDevID is provisioned once and lives for ten
years; a challenge is good for one exchange. Persisting a nonce into a
long-lived certificate would put a value that means "this answer is live" into
a document that outlives the answer by a decade. The challenge belongs on the
per-exchange alias certificate the device mints, which is where `dice.Verify`
and the invariants gate read it from.

A consequence: a device that states its UEID only as claim 256 receives an
IDevID with no `tcg-dice-Ueid`, since the profile copies only the extension
(`pkg/ca/profile_dice.go:220-229`). Its identity is still bound through
ACME, where the order's `permanentIdentifier` is the hex UEID read by
`DeviceUeid`.

### Rejected: refusing claim keys this verifier does not know

`ParseTcbInfo` refuses an unknown `DiceTcbInfo` field tag, and the claims-set
parser deliberately does the opposite. A `DiceTcbInfo` is a SEQUENCE with ten
declared members, so an eleventh names nothing. A CWT claims set is an open
IANA registry: an attester carrying a `ueid`, an `oemid` or a measurement claim
beside its nonce is conforming, and a verifier that refused it would refuse
most of the devices the UCCS extension exists to interoperate with.

The unread claims are **kept**, in `ClaimsSet.Other`, as the raw CBOR items
they arrived as. Refusing them would be wrong and dropping them would make the
verifier's report of what the device said untrue.

### Rejected: accepting a tagged claims set, and EAT's array-of-nonces

RFC 9781 registers CBOR tag 601 for a UCCS. It is refused here: the extension
OID already identifies the content, so a tag adds nothing and accepting both
framings would put two encodings of the same evidence on the wire — the same
objection that makes a repeated `DiceTcbInfo` tag an error.

EAT also allows `eat_nonce` to be an array of two or more byte strings, for
several verifiers each contributing one. That is refused too: this profile
issues one challenge, and a set of candidates leaves "did the device answer
me" without a single answer.

### Deviation: EAT's 64-byte nonce ceiling is not enforced

EAT bounds `eat_nonce` at 8 to 64 bytes. The **lower** bound is enforced — a
challenge short enough to guess establishes no freshness. The **upper** bound
is not, because a verifier refusing the echo of its own challenge would be
refusing itself, and a caller is free to choose a challenge wider than 64
bytes. The leniency runs only in the direction that makes a nonce harder to
guess; what it costs is that an attester echoing such a challenge emits
evidence a strictly conforming EAT verifier rejects, and the fix for that
belongs to whoever chooses the challenge.

**This repository's own flow stays inside the bound.** ACME
`device-attest-01` carries SHA-256 of the key authorization — 32 bytes,
computed in one place by `DICENonce` — precisely because
`<token>.<RFC 7638 thumbprint>` is 87 bytes and could not be carried by a
conforming claims set at all.

### Rejected: modelling DiceTcbInfo with `encoding/asn1` struct tags

`encoding/asn1` omits any `optional` field holding its type's zero value. Three
DiceTcbInfo fields have meaningful zeros — layer 0 is the DICE core, index 0
is the first measured asset, svn 0 is a first release — so a struct-tagged
encoder silently drops them. `MarshalTcbInfo` writes the fields out one at a
time for this reason, and `TestLayerZeroSurvivesTheWire` pins the contrast.

### Rejected: skipping unknown fields and unknown flag bits

Both are refused. This is attestation evidence: a field the verifier cannot
read is a claim it cannot weigh, and an unread flag bit is an operational state
the device is actively declaring. Refusing matches the existing format gate,
which refuses evidence whose format it does not recognise for the same reason.

### Rejected: stripping `notSecure` at issuance

The CA carries the device's `DiceTcbInfo` onto the certificate verbatim,
flags included. A CA that dropped `notSecure` would issue a certificate reading
as a stronger attestation than the device ever made. The whole value of
carrying the evidence forward is that a relying party can read what the device
actually claimed.

## Interaction with crypto/x509

DICE Attestation Architecture §6.1.1 says the `DiceTcbInfo` extension SHOULD be
critical, and `crypto/x509` refuses any chain carrying a critical extension it
does not recognise. A verifier that does not account for this cannot anchor a
spec-conformant DICE chain at all.

`dice.Verify` clears the DICE OIDs from `UnhandledCriticalExtensions` before
calling `Verify` — legitimate, because this package does handle them — and does
it on **copies**. Mutating the caller's certificates would leave them marked as
handled for every later verifier in the process, including ones that do not
know DICE.
