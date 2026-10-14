# DICE Device Identity — Architecture

> **Status: NORMATIVE** · Feature: `dice-device-identity` · Repo: `go-xkms` · Last verified: 2026-10-13

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
trust**. It is deliberately not described as "TCG DICE compliant": a constrained
device's profile may meet the TCG hardware requirements only partially, and the
device says so on the wire — `OperationalFlags.notSecure` is set whenever the device
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
| The possession request profile | this feature | `pkg/acme/challenges/device-attest-01/possession.go` |
| Talking to the device | the device's backend, registered through the hook (below) | the backend's module (`pkg/backend/avr/` today) |
| The device's wire protocol and firmware | the firmware's own repository | not this repo |
| The device-registry lookup contract (`DeviceResolver`) | this feature | `pkg/acme/challenges/device-attest-01/anchors.go` |
| The device registry itself, and fleet policy | the platform that owns enrollment, which injects a `DeviceResolver` | not this repo |

### Plugging in a device backend

This feature verifies evidence; it does not talk to devices. A device backend
lives in its own Go module, registers from that module's `init()` with
`xkms.RegisterExternalBackend` (`pkg/xkms/registry_external.go:54`), and is
compiled in by a blank import of the adapter module (`import _ "<adapter>"`).
The backend drives its device to mint the alias certificate and hands the chain
to `dice.Verify` with the `VerifyOptions` its profile needs. Naming, the
factory contract and the errors are in
[crypto-backends: Registering a backend from another module](../crypto-backends/engineering.md#registering-a-backend-from-another-module).

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
                                ACME: in the device's provisioning
                                record first (DeviceResolver)
                                every critical DICE extension
                                cleared to do so decodes
                             2. ECDSA P-256 device keys   (dice.Verify)
                             3. nonce matches             (dice.Verify)
                             4. operational states permitted
                             5. CSR key == alias SPKI     (attestation.VerifyInvariants)
                                ACME: == the attested SPKI, and the
                                registry is asked again
                             6. issue                     (ca "dice-idevid")

Steps 1-4 and step 5 are one exchange for a CSR carrying its evidence, and TWO
for ACME: device-attest-01 delivers the chain at the challenge and the CSR at
finalization. There the leaf is carried across as a VerifiedAttestation, the
CSR is the device's possession request (below), and step 5 is
VerifyPossessionCSR and then BindCSRKey, both before issuance. The challenge
verifier refuses to answer for the dice format on its own, so step 5 cannot be
the step that gets skipped.
```

### Anchored in the provisioning record

A DICE alias certificate is signed by the key it carries, and a small device
often keeps no DeviceID certificate to present above it. So the chain a device sends vouches
only for itself: any host can mint one for a key it generated and name any
device's UEID. What says which key belongs to a device is the record written
when the device was provisioned, outside any field host. ACME
`device-attest-01` therefore looks the alias's UEID up in a `DeviceResolver`
the enrolling platform injects, and accepts the alias only along the path the
record selects:

- **raw key** — the record holds the DeviceID public key; the alias carries
  exactly that key and its signature verifies under it.
- **endorsement** — the record holds a DeviceID certificate; it names the same
  UEID, and `[alias, DeviceID certificate]` anchors in `dice_roots`.

No resolver, no record, or a record that does not vouch for the key is
`unauthorized`. The key the record vouched for is persisted with the challenge
as the attested SPKI, finalization accepts only a CSR for it, and finalization
asks the registry again, so a device withdrawn or re-keyed in between is
refused.

Rejected: anchoring in `dice_roots` alone. Nothing a field device presents
chains to a root without the provisioning record, and a root that certified a
device's DeviceID key says nothing once that device is withdrawn. Rejected:
falling back to the raw-key path when an endorsement has no `dice_roots`. A
record that names a certificate is checked as one, or refused. Rejected: a
default registry. There is none to default to, so a server without one refuses
every `dice` attestation; a stock `xkmsd` is such a server.

## Decisions

### ECDSA P-256, and nothing else

The profile's hardware root of trust is a P-256-only key store (a secure
element such as the ATECC608A). It holds P-256 keys and has no hardware
Ed25519, so a DICE certificate presenting any other key was not produced by
that hardware. `dice.Verify` refuses it rather than reporting
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
not in the chain, which is the ordinary constrained-device shape: the device has nowhere to
keep its DeviceID certificate, so the chain is the alias leaf alone or a
DeviceID intermediate carrying no DICE extension of its own. There is then no
certificate to check the algorithm on, and an alias signed with ECDSA-SHA384
would verify. `VerifyOptions.RequireDeviceSignedLeaf` is how a profile that
knows its leaf was signed by the element says so; a device backend whose
element signs the leaf sets it (`pkg/backend/avr/attestation.go:207`).

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
device carries the one it can afford: a constrained device that mints a
fixed-template alias certificate has room for one DICE extension, so it uses
the claim (`pkg/attestation/dice/uccs.go:60-66`). Every reader in
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

### Possession at finalize: the device signs a fixed template

A template-minting device has no ASN.1 encoder, and its alias key is its static
DeviceID key, so the leaf it presents at the challenge says nothing about which
finalize it belongs to (`pkg/acme/challenges/device-attest-01/possession.go:39-46`).
It proves possession at finalize instead, by signing a PKCS#10
CertificationRequestInfo filled in from a fixed template. The template's one
host-supplied input is `b = SHA-256(keyAuthorization)`, the same `b` the
challenge carried (`DICENonce`, `deviceattest01.go:440`). The host rebuilds the
CertificationRequestInfo and wraps the device's signature
(`AssemblePossessionCSR`, `possession.go:232`); a device that can sign a
digest through a Go `crypto.Signer` uses `SignPossessionCSR` (`:256`).

The template, which `BuildPossessionCRI` (`:171`) writes and the package
comment states byte for byte (`:51-62`):

| Field | Value |
|-------|-------|
| version | 0 |
| subject | empty Name, `30 00` |
| subjectPKInfo | id-ecPublicKey, prime256v1, uncompressed point |
| attributes | one `extensionRequest` (1.2.840.113549.1.9.14, `:86`) |
| extension 1 | `subjectAltName`, **critical** (RFC 5280 §4.2.1.6: the subject is empty), one otherName `id-on-permanentIdentifier` (RFC 4043), `identifierValue` = lower-case `hex(DeviceID)`, no assigner (`possessionExtensions`, `:212-227`) |
| extension 2 | `tcg-dice-UCCS-evidence` (2.23.133.5.4.6), **not critical**, CBOR `{10: b}` |
| signature | ecdsa-with-SHA256 |

The request names its device as the ACME identifier type
`permanent-identifier` (`PossessionIdentifierType`, `:81`) with value
`hex(DeviceID)` (`Identifier`, `:132-133`), the form the challenge's identity
gate compares against the order.

`VerifyPossessionCSR` (`:358`) is the finalize side. `ParsePossessionCSR`
(`:280`) first refuses any request that is not what the template writes for the
values it carries (`ErrPossessionCSRMalformed`), then four checks run, each
with its own error:

| Check | Error | Where |
|-------|-------|-------|
| the signature verifies under the request's own key | `ErrPossessionSignatureInvalid` | `possession.go:374` |
| the SubjectPublicKeyInfo is byte-equal to the attested leaf's | `ErrPossessionKeyMismatch` | `possession.go:377` |
| the UCCS nonce is SHA-256 of this order's key authorization, compared in constant time | `ErrPossessionNonceMismatch` | `possession.go:380` |
| the request's identifiers are exactly the order's | `ErrPossessionIdentifierMismatch` | `possession.go:383` |

The ACME finalize handler runs it for every `dice` record and then still runs
`BindCSRKey`, the gate every format shares
(`pkg/acme/server/handlers/device_attest.go:228-235`, called from
`order_finalize.go:605`). A refusal is `badCSR`.

A consequence of the identifier check: a `dice` order names one device and
nothing else. An order that also asks for a DNS name, or for a second device,
cannot be finalized by a possession request.

**Nothing in the request reaches the certificate.** The UCCS extension is
evidence about this one request. The CA copies no requested extension: the CSR's
extensions reach only a certificate profile (`pkg/ca/ca.go:1956`), and the
finalize handler issues with the attested `permanentIdentifier` alone
(`order_finalize.go:851`). `TestOrderFinalize_DeviceAttest01_CertificateAssertsTheAttestedIdentity`
proves it at the handler, and the `pkg/ca` subtest "a DICE possession request's
extensions are not copied" (`sign_othernames_test.go:96`) proves it at the CA.

#### Rejected: binding through `challengePassword`

PKCS#9 `challengePassword` is a string a CA compares, which no DICE verifier
reads as a challenge. The UCCS `eat_nonce` is where the challenge already
travels at the challenge, so the binding goes there too (`possession.go:64-68`).

#### Rejected: a critical UCCS extension

`CreateUccsEvidenceExtension` marks the extension critical on an alias
certificate, because there the claims are what make the certificate an
attestation. In the possession request it is never issued: it is evidence about
the request, not a claim for the certificate, so it is not critical
(`possession.go:65-68`).

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
