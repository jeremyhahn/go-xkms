# DICE Device Identity — API

> **Status: NORMATIVE** · Feature: `dice-device-identity` · Repo: `go-xkms` · Last verified: 2026-09-28

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

The server anchors the chain to the operator's `acme.challenges.device_attest.dice_roots`
and applies the `dice_require_*` policy through `deviceattest01.TrustAnchorVerifier`,
which calls `dice.Verify`. For an AVR with an ATECC608A set
`dice_require_device_signed_leaf`.

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
| `VerifyAttestation(...) (*VerifiedAttestation, error)` | challenge | Format, chain anchoring, freshness. Returns the **verified leaf**. |
| `(*VerifiedAttestation).BindCSRKey(csr)` | finalization | The CSR self-signature verifies, and its SubjectPublicKeyInfo is the alias certificate's, through `attestation.VerifyInvariants`. |

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
| `tcg-dice-Ueid` | optional, re-encoded | The profile does not require one |

Evidence is decoded and re-encoded rather than copied, so the issued
certificate carries canonical DER whatever the device sent, and evidence the CA
cannot parse is never signed.
