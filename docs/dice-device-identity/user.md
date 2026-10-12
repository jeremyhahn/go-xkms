# DICE Device Identity — User

> **Status: NORMATIVE** · Feature: `dice-device-identity` · Repo: `go-xkms` · Last verified: 2026-10-11

## Verifying a device's evidence

```go
import "github.com/jeremyhahn/go-xkms/pkg/attestation/dice"

nonce := newRandomNonce()        // 16+ bytes from crypto/rand
chain := fetchChainFromDevice(nonce)

evidence, err := dice.Verify(chain, &dice.VerifyOptions{
    TrustedRoots:       manufacturerRoots,
    ExpectedNonce:      nonce,
    RequireMeasurement: true,
})
if err != nil {
    return err
}

log.Printf("device %x runs %s %s", evidence.Ueid,
    evidence.TcbInfo.Model, evidence.TcbInfo.Version)
```

The nonce is **required**. It is the only freshness this format has: the device
has no clock, so there is no timestamp it could send that would distinguish a
live answer from a recording. It must be at least 8 bytes; a shorter challenge
is guessable, and evidence echoing one is refused.

The device echoes it in the `eat_nonce` claim (CWT claim key 10) of the CBOR
claims set inside the `tcg-dice-UCCS-evidence` extension of the alias
certificate. There is no other place `Verify` looks: a device that puts the
nonce in `DiceTcbInfo.vendorInfo` is refused.

## Reading what else the device claimed

```go
for key, value := range evidence.Claims.Other {
    fmt.Printf("CWT claim %d: %x\n", key, value) // raw CBOR
}
```

A CWT claims set is an open registry, so a conforming attester may carry claims
this verifier does not model. They are kept rather than refused or dropped, as
the raw CBOR items they arrived as, so you can see everything the device said.
`evidence.Claims.Nonce` is the challenge that was matched.

## Accepting a software-only tier

By default `Verify` refuses a device reporting any of the four operational
states. A fleet that includes devices without a hardware root of trust has to
say so explicitly:

```go
evidence, err := dice.Verify(chain, &dice.VerifyOptions{
    TrustedRoots:   manufacturerRoots,
    ExpectedNonce:  nonce,
    PermittedFlags: dice.OperationalFlags{NotSecure: true},
})
```

Permitting one state does not permit another — a device that reports
`notSecure` *and* `debug` is still refused. `evidence.Flags` reports what the
device actually claimed, so the caller can record the tier it admitted.

## Pinning a specific device

```go
opts := &dice.VerifyOptions{
    TrustedRoots:  manufacturerRoots,
    ExpectedNonce: nonce,
    ExpectedUeid:  enrolledDeviceID,
}
```

Without `ExpectedUeid` a successful verification means "a device from this
manufacturer", not "the device I enrolled".

A device states its identifier in one of two places: the `tcg-dice-Ueid`
extension, or the `ueid` claim (CWT claim key 256) of its UCCS evidence. A
small device such as an arduino-generic AVR carries only the claim. `Verify`
reads either, and so does `dice.DeviceUeid` when you need the identifier from a
certificate yourself:

```go
id, err := dice.DeviceUeid(leaf) // extension or claim 256
```

Prefer it to `dice.UeidFromCertificate`, which reads only the extension. Set
`RequireUeid` to refuse a leaf that states neither.

## Reading what a device measured

```go
info, err := dice.TcbInfoFromCertificate(leaf)
for _, fwid := range info.FWIDs {
    fmt.Printf("%s: %x\n", fwid.HashAlg, fwid.Digest)
}
if info.Layer != nil {
    fmt.Printf("measured at DICE layer %d\n", *info.Layer)
}
```

`Layer`, `Index` and `SVN` are pointers: `nil` means the device did not report
the field, and `0` is a real value it did report. Layer 0 is the DICE core.

## Common refusals

| Error | What happened |
|-------|---------------|
| `ErrNonceRequired` | No nonce was issued. Freshness cannot be established afterwards. |
| `ErrNonceMismatch` | The device echoed a different nonce. Possibly a replay. |
| `ErrUccsEvidenceNotFound` | The leaf carries no `tcg-dice-UCCS-evidence`, so there is no challenge to read. A nonce in `DiceTcbInfo.vendorInfo` is not a fallback. |
| `ErrNonceClaimMissing` | The claims set is readable but carries no `eat_nonce` claim: the device answered without the challenge. |
| `ErrNonceClaimLength` | The echoed nonce is shorter than 8 bytes, so it establishes no freshness. |
| `ErrMalformedClaimsSet` / `ErrDuplicateClaim` | The claims set is not one this verifier can read in full — a duplicate claim key, an indefinite-length or tagged encoding, trailing bytes. |
| `ErrUnsupportedKeyType` | A device certificate carries something other than ECDSA P-256. The hardware holds P-256 only. |
| `ErrOperationalStateNotPermitted` | The device declared a state you did not permit. The message names which. |
| `ErrUnknownTcbInfoField` / `ErrUnknownOperationalFlag` | The device sent something this verifier cannot read. Refused rather than ignored — an unread claim is not a claim you can rely on. |
| `ErrUeidMismatch` | The device is not the one `ExpectedUeid` names. |
| `ErrUeidNotFound` | `RequireUeid` or `ExpectedUeid` was set and the leaf states no identifier in either place. |
| `ErrUeidConflict` | The leaf states its identifier in the extension and in claim 256, and the two differ. Neither is chosen. |
| `ErrChainVerificationFailed` | The chain does not reach a configured trust anchor. |
| `ErrNoMeasurement` | `RequireMeasurement` was set and the leaf carried no FWID — or the `dice-idevid` profile was asked to issue against evidence that measures nothing. |
| `ErrCriticalEvidenceUnreadable` | A certificate in the chain marks DICE evidence critical that this verifier cannot decode. Anchoring tells `crypto/x509` those extensions were handled, so it only says that about extensions it actually read. |
| `ErrUnsupportedSignatureAlgorithm` | A certificate a device key signed is not ECDSA-SHA256. With `RequireDeviceSignedLeaf` that includes the leaf, whose issuer is the device even when its certificate is not in the chain. |

Every one of these is reachable from `sdk/go` as `ErrDICE<Name>` — for example
`xkms.ErrDICENonceMismatch` — so a consumer that cannot import `pkg/` can still
use `errors.Is`.

## Enrolling a device over ACME

`device-attest-01` with the `dice` format is two steps, and both are required:

```go
// At the challenge: the device's evidence, verified and kept. payload is the
// body the client POSTed to the challenge URL, {"attObj": base64url(CBOR)};
// nothing is fetched from the device. verifier is the server's trust policy,
// e.g. a deviceattest01.TrustAnchorVerifier over the configured DICE roots.
verified, err := deviceattest01.VerifyAttestation(verifier, payload, keyAuthorization)

// At finalization: the key the CA is about to certify.
if err := verified.BindCSRKey(csr); err != nil {
    return err            // the CSR is not for the attested key
}
```

The one-shot `deviceattest01.Verify` refuses the `dice` format with
`ErrKeyBindingRequired`. That is deliberate: the nonce says the device answered
your challenge, and nothing about which key the certificate will be for — the
CSR does not exist yet. Persist the `VerifiedAttestation` (its `LeafDER` is the
device's own bytes) between the two requests and bind before issuing.
