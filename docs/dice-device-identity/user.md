# DICE Device Identity — User

> **Status: NORMATIVE** · Feature: `dice-device-identity` · Repo: `go-xkms` · Last verified: 2026-10-17

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

## Reading the root of trust

`evidence.RootType` says where the device keeps its Unique Device Secret, as
its chain declares it in DiceTcbInfo:

```go
switch evidence.RootType {
case dice.RootTypeHardware: // UDS in a secure element; notSecure is clear
case dice.RootTypeSoftware: // UDS in device storage; notSecure is set
case dice.RootTypeUnreported: // the chain declares neither
}
```

The same value reaches you as `attestation.Result.RootType` from the
attestation verifier, as `VerifiedAttestation.RootType` from ACME
device-attest-01, and as `xkms.DICERootType` through `sdk/go`. A software root
is refused unless you permit `NotSecure` (above), whichever certificate in the
chain declared it. Only authenticated certificates are read: with
`TrustedRoots` set, every certificate you pass must be on the verified path;
without, only the leaf counts.

A device declares its root by putting one of these in its DiceTcbInfo
`vendorInfo`, with `notSecure` to match:

```go
vendorInfo, err := dice.RootTypeVendorInfo(dice.RootTypeSoftware)
info := &dice.TcbInfo{
    VendorInfo: vendorInfo,
    Flags:      &dice.OperationalFlags{NotSecure: true},
    // ...
}
```

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
constrained device that mints a fixed-template alias certificate carries only
the claim. `Verify`
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
| `ErrOperationalStateNotPermitted` | The device declared a state you did not permit. The message names which. A software root on any certificate of the verified path counts as `notSecure` (CA m452). |
| `ErrUnknownTcbInfoField` / `ErrUnknownOperationalFlag` | The device sent something this verifier cannot read. Refused rather than ignored — an unread claim is not a claim you can rely on. |
| `ErrUeidMismatch` | The device is not the one `ExpectedUeid` names. |
| `ErrUeidNotFound` | `RequireUeid` or `ExpectedUeid` was set and the leaf states no identifier in either place. |
| `ErrUeidConflict` | The leaf states its identifier in the extension and in claim 256, and the two differ. Neither is chosen. |
| `ErrChainVerificationFailed` | The chain does not reach a configured trust anchor. |
| `ErrNoMeasurement` | `RequireMeasurement` was set and the leaf carried no FWID — or the `dice-idevid` profile was asked to issue against evidence that measures nothing. |
| `ErrCriticalEvidenceUnreadable` | A certificate in the chain marks DICE evidence critical that this verifier cannot decode. Anchoring tells `crypto/x509` those extensions were handled, so it only says that about extensions it actually read. |
| `ErrUnsupportedSignatureAlgorithm` | A certificate a device key signed is not ECDSA-SHA256. With `RequireDeviceSignedLeaf` that includes the leaf, whose issuer is the device even when its certificate is not in the chain. |

Over ACME `device-attest-01`, the device registry adds its own refusals, all
joined under `deviceattest01.ErrDeviceNotAuthorized` and answered as
`unauthorized`:

| Error | What happened |
|-------|---------------|
| `ErrNoDeviceResolver` | The server has no device registry. A stock `xkmsd` has none. |
| `ErrDeviceNotProvisioned` | The registry holds no record for the device's UEID. |
| `ErrProvisioningRecordInvalid` | The record sets neither or both fields, or holds a key that is not P-256 or a certificate that does not parse. |
| `ErrAttestedKeyMismatch` | The alias certificate's key is not the provisioned DeviceID key, or the record was re-keyed before finalization. |
| `ErrAliasSignatureInvalid` | The alias certificate does not verify under the provisioned DeviceID key. |
| `ErrDeviceEndorsementInvalid` | The provisioned DeviceID certificate names another UEID, or does not chain the alias to `DICERoots`. |

`sdk/go/acme` re-exports the three a registry implementer or caller branches
on: `ACMEErrDeviceNotAuthorized`, `ACMEErrDeviceNotProvisioned` and
`ACMEErrNoDeviceResolver`, beside `ACMEDeviceResolver` and
`ACMEProvisionedDevice`.

Every one of the `dice` errors above is reachable from `sdk/go` as `ErrDICE<Name>` — for example
`xkms.ErrDICENonceMismatch` — so a consumer that cannot import `pkg/` can still
use `errors.Is`.

## Enrolling a device over ACME

`device-attest-01` with the `dice` format is two steps, and both are required:

```go
// At the challenge: the device's evidence, verified and kept. payload is the
// body the client POSTed to the challenge URL, {"attObj": base64url(CBOR)};
// nothing is fetched from the device. verifier is the server's trust policy:
// a deviceattest01.TrustAnchorVerifier whose TrustAnchors.Devices is your
// device registry.
verified, err := deviceattest01.VerifyAttestation(verifier, payload, keyAuthorization)

// At finalization: the device's possession request, the key the CA is about
// to certify, and the registry again.
if err := verified.VerifyPossessionCSR(csr, order.Identifiers); err != nil {
    return err            // not the device's request for this order
}
if err := verified.BindCSRKey(csr); err != nil {
    return err            // badCSR: the CSR is not for the attested key
}
if err := verified.ConfirmRegistration(ctx, verifier); err != nil {
    return err            // unauthorized: the device was withdrawn or re-keyed
}
```

The `dice` CSR is the device's **possession request**: a fixed template the
device signs with its alias key. It carries its alias certificate's claims set
(ueid and measurements, nothing else) with the nonce set to
`b = deviceattest01.DICENonce(keyAuthorization)`, and names the device by
`hex(ueid)` as a `permanent-identifier`. A device whose key sits behind a Go
`crypto.Signer` produces it in one call:

```go
claims, err := dice.UccsFromCertificate(aliasCert)
der, err := deviceattest01.SignPossessionCSR(signer, claims,
    deviceattest01.DICENonce(keyAuthorization))
```

A device that signs only raw digests gets the bytes to sign from
`BuildPossessionCRI(pub, claims, b)` and hands its DER signature back to
`AssemblePossessionCSR(cri, signature)`. `acmeclient.DeviceAttest` does this for
an `AttestedKey` whose `Format` is `deviceattest01.FormatDICE`.

| Finalize refusal (`badCSR`) | What happened |
|-----------------------------|---------------|
| `ErrPossessionCSRMalformed` | The request is not exactly what the template writes: an ordinary CSR, a subject, an extra extension, attribute or claim, a non-critical extension, a claims set without its ueid or measurements, an identifier that is not the claims set's ueid, another curve. |
| `ErrPossessionSignatureInvalid` | The signature does not verify under the request's key. |
| `ErrPossessionKeyMismatch` | The request is for a key other than the one the device attested. |
| `ErrPossessionNonceMismatch` | The request was signed for another order's challenge. |
| `ErrPossessionIdentifierMismatch` | The order names something besides this one device: a DNS name, or a second device. |

### Provisioning the device registry

A DICE alias certificate is signed by the key it carries, so the server accepts
it only for a device you provisioned. Implement `deviceattest01.DeviceResolver`
over wherever you record provisioning, and pass it as `TrustAnchors.Devices`:

```go
type registry struct{ devices map[string]*deviceattest01.ProvisionedDevice }

func (r *registry) ResolveDevice(ctx context.Context, ueid string) (*deviceattest01.ProvisionedDevice, error) {
    device, ok := r.devices[ueid]
    if !ok {
        return nil, deviceattest01.ErrDeviceNotProvisioned
    }
    return device, nil
}

verifier, err := deviceattest01.NewTrustAnchorVerifier(deviceattest01.TrustAnchors{
    DICERoots: roots,     // only needed for records that hold a DeviceID certificate
    Devices:   &registry{devices: provisioned},
})
```

- Key the record by the device's UEID as 34 lowercase hex digits: `01`
  followed by its 16-byte DeviceID, e.g. `01a1b2c3d4e5f60718293a4b5c6d7e8f90`.
- Set **one** field: `DeviceIDKey`, the DER SubjectPublicKeyInfo of the
  device's P-256 DeviceID key, when the device signs its own alias certificate;
  or `DeviceIDCertificate`, the DER DeviceID certificate issued at provisioning,
  when that certificate signs the alias and chains to `DICERoots`.
- Return an error wrapping `ErrDeviceNotProvisioned` for an unknown UEID, and
  any other error when the lookup itself fails. Both refuse the device.

A server with no registry refuses every DICE device as `unauthorized`. That
includes a stock `xkmsd`, which has nowhere to take a registry from: DICE
enrollment runs in an embedder that supplies one.


The one-shot `deviceattest01.Verify` refuses the `dice` format with
`ErrKeyBindingRequired`. That is deliberate: the nonce says the device answered
your challenge, and nothing about which key the certificate will be for — the
CSR does not exist yet. Persist the `VerifiedAttestation` (its `LeafDER` is the
device's own bytes) between the two requests and bind before issuing.
