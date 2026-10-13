# DICE Device Identity — API

> **Status: NORMATIVE** · Feature: `dice-device-identity` · Repo: `go-xkms` · Last verified: 2026-10-13

## Transports

| Transport | Reachable | Notes |
|-----------|-----------|-------|
| Embedded Go SDK | yes | `pkg/attestation/dice` is importable as-is |
| ACME `device-attest-01` | yes | format tag `dice` |
| Certificate profile registry | yes | profile name `dice-idevid` |
| REST / gRPC / QUIC / MCP | no | no DICE-specific route; see below |

There is no DICE-specific network route, and that is not an omission. DICE
evidence arrives as part of an existing ceremony — an ACME `device-attest-01`
challenge, or a certificate signing request naming the `dice-idevid` profile —
so it travels on the transports those already use. A parallel route would be a
second way to say the same thing.

## ACME device-attest-01

The `dice` attestation format sits beside `tpm` in
`pkg/acme/challenges/device-attest-01`. The attestation object is the WebAuthn
shape with the DICE certificate chain in `x5c`; there is no `certInfo`, `sig`
or `pubArea`, because a DICE device signs no separate attestation structure.

```json
{
  "fmt": "dice",
  "attStmt": { "x5c": ["<alias certificate DER>", "<embedded CA DER>"] }
}
```

The object is CBOR, and the client sends it to the challenge URL as the payload
`{"attObj": "<base64url, unpadded, of the CBOR>"}`
(draft-ietf-acme-device-attest). The server verifies it from the payload and
never contacts the device, so a device on a serial port enrolls through a
gateway that holds the ACME account: the gateway forwards the device's alias
chain and POSTs. `deviceattest01.EncodeAttestationRequest` builds the payload
(`ACMEEncodeDeviceAttestRequest` in `sdk/go/acme`).

The server anchors the alias certificate in the **device's provisioning
record**, never in a root pool alone: a DICE alias is signed by the key it
carries, so on its own it vouches for nothing. The embedder that owns
enrollment injects a `deviceattest01.DeviceResolver` through
`TrustAnchors.Devices` (`ACMEDeviceResolver` in `sdk/go/acme`).
`TrustAnchorVerifier` looks the alias's UEID up in it — 34 lowercase hex digits,
`01` followed by the DeviceID — and the record selects one of two paths:

| Record (`ProvisionedDevice`) | The alias is accepted when |
|---|---|
| `DeviceIDKey`, a DER SubjectPublicKeyInfo | it carries exactly that key and its ECDSA-SHA256 signature verifies under it |
| `DeviceIDCertificate`, a DER DeviceID certificate | the certificate names the same UEID and `[alias, DeviceID certificate]` anchors in `acme.challenges.device_attest.dice_roots` |

Only then does `dice.Verify` check the nonce, the UEID and the `dice_require_*`
policy. For a device whose DeviceID key is held in a secure element, set
`dice_require_device_signed_leaf`.

**Fails closed as `unauthorized`** (`ErrDeviceNotAuthorized`): no resolver, a
UEID with no record (the resolver wraps `ErrDeviceNotProvisioned`), a resolver
error, a malformed record, a key or signature that does not match the raw-key
record, or an endorsement with no `dice_roots`, another UEID or no chain. A
stock `xkmsd` injects no resolver, so it refuses every `dice` attestation; a
DICE fleet enrolls through an embedder that supplies its registry.

Verification is dispatched by format. For `dice` it parses the `x5c` leaf and
requires the `eat_nonce` claim of the leaf's `tcg-dice-UCCS-evidence`
extension to equal SHA-256 of the ACME key authorization — the digest, because
EAT bounds `eat_nonce` at 8..64 bytes and a key authorization is 87.
`DICENonce` is the one place that hash is computed. A leaf that carries the
value in `DiceTcbInfo.vendorInfo` instead is refused: there is no fallback to
the earlier placement. It verifies **no quote** and consults **no clock** — the
device has neither.

**The nonce is not the whole check, and the challenge cannot finish it.** An
ACME order is two requests: the evidence arrives at the challenge and the CSR
at finalization, so a verifier that answered "valid" from the challenge alone
would have authorized issuance for a key nobody compared against the device's.
Verification is therefore two phases:

| Call | When | Establishes |
|------|------|-------------|
| `VerifyAttestation(...) (*VerifiedAttestation, error)` | challenge | Format, registry anchoring, freshness. Returns the **verified leaf** and the **attested SPKI**, the key the provisioning record vouched for. |
| `(*VerifiedAttestation).VerifyPossessionCSR(csr, orderIdentifiers)` | finalization, `dice` only | The CSR is the device's possession request: the fixed template, signed by the alias key, over `DICENonce(keyAuthorization)`, naming exactly the order's identifiers (`possession.go:358`). |
| `(*VerifiedAttestation).BindCSRKey(csr)` | finalization | The record carries an attested SPKI and the CSR's SubjectPublicKeyInfo is byte-equal to it; the CSR self-signature verifies; the alias certificate carries the same key, through `attestation.VerifyInvariants`. |
| `(*VerifiedAttestation).ConfirmRegistration(ctx, verifier)` | finalization | The device registry still holds the device's record, and its key is still the attested SPKI. A refusal is `unauthorized`. |

**The `dice` CSR is a possession request.** A template-minting device signs a
CertificationRequestInfo built from a fixed template whose one host-supplied
input is `b = DICENonce(keyAuthorization)`, and the host wraps the signature
(`AssemblePossessionCSR`, `possession.go:232`). Its shape is an empty subject,
a P-256 key and one `extensionRequest` holding a critical `subjectAltName` with
the `permanentIdentifier` otherName `hex(DeviceID)` and a non-critical
`tcg-dice-UCCS-evidence` whose `eat_nonce` is `b`
([architecture.md](architecture.md#possession-at-finalize-the-device-signs-a-fixed-template)).
The order's identifier is `permanent-identifier` / `hex(DeviceID)`. The ACME
finalize handler runs `VerifyPossessionCSR` and then `BindCSRKey` for a `dice`
record (`pkg/acme/server/handlers/device_attest.go:228-235`); any other request
is `badCSR`, so a `dice` order names one device and nothing else. The UCCS
extension and every other requested extension stay off the certificate: the
handler issues with the attested `permanentIdentifier` alone
(`order_finalize.go:851`).

`Verify` — the one-shot `ChallengeVerifierFunc` shape — **refuses** `dice`
with `ErrKeyBindingRequired`, and `tpm` too: its evidence certifies `pubArea`,
which is bound to the CSR the same way (see
[acme-issuance/engineering.md](../acme-issuance/engineering.md#device-attest-01-key-binding)). A server wiring this challenge
holds the `VerifiedAttestation` between the two requests and runs `BindCSRKey`
before issuance; there is no path on which the nonce alone authorizes a
certificate.

`VerifiedAttestation` carries `LeafDER` as well as the parsed `Leaf`, because
the record has to outlive the request that produced it: a server that is not a
single process writes it down between the two, and only bytes survive that.
`BindCSRKey` binds against those bytes — a re-encoded certificate is a
different document, and the device's signature is over the original.
`AttestedSPKI` is stored beside it (`entities.DeviceAttestation.AttestedSPKI`);
a `dice` record without one was never anchored in a registry and its finalize is
`badCSR`.

`ValidateAttestationFormat` and the verification dispatch table are the same
map, so a format the server reports as supported is always one it can actually
dispatch.

`Setup` still supports `tpm` alone. It builds evidence with a local TPM, and a
DICE device mints its own alias certificate — there is nothing for the host to
construct.

## The invariants gate

`attestation.FormatDICE` (`"dice"`) is registered in the `profiles` map with
`bindLeafSPKI: true` and `dice.Challenge` as the challenge extractor. Key
binding is a direct comparison of the CSR's SubjectPublicKeyInfo against the
alias certificate's — the check without which anyone holding a copy of the
chain could present it beside a CSR for a software key.

Both carriers reach it, and neither open-codes it: `SignCSR` through
`enforceAttestationInvariants` in `pkg/xkms`, and ACME `device-attest-01`
through `VerifiedAttestation.BindCSRKey`.

## Certificate profile

`dice-idevid`, registered in the default profile registry.

| Field | Value | Source |
|-------|-------|--------|
| Key usage | `digitalSignature` | Certificate Profiles Table 1: a non-ECA IDevID MUST NOT contain `keyCertSign` |
| Extended key usage | TLS client + server auth | Table 1 leaves "appropriate values for the usage model" to the issuer |
| Policy OID | `tcg-dice-kp-identityInit` | Table 1 makes it mandatory; `eca` and `attestInit` are optional and not asserted |
| Basic constraints | omitted | Table 1: a non-ECA certificate SHOULD NOT contain them |
| Default validity | 3650 days | A manufacturing identity outlives every credential derived from it |
| `tcg-dice-TcbInfo` | required, re-encoded | Refuses `ErrDICEEvidenceMissing` without it |
| `fwids` inside it | at least one | Refuses `ErrDICEEvidenceInvalid` wrapping `dice.ErrNoMeasurement`. Every field of `DiceTcbInfo` is optional, so `30 00` parses: requiring the extension is not requiring the measurement |
| `tcg-dice-Ueid` | optional, re-encoded | The profile does not require one. A device may state its UEID as UCCS claim 256 instead; `dice.DeviceUeid` reads either, and refuses a leaf whose two statements differ |

Evidence is decoded and re-encoded rather than copied, so the issued
certificate carries canonical DER whatever the device sent, and evidence the CA
cannot parse is never signed.
