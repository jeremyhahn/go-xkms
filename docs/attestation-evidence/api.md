# Attestation Evidence — API

> **Status: NORMATIVE** · Feature: `attestation-evidence` · Repo: `go-xkms` · Last verified: 2026-10-01

## No transport surface, deliberately

The primitives take evidence and caller-trusted inputs and return a typed
answer. They hold no state and need no keys, so a network round trip would
add an attack surface and nothing else. They are exposed as a Go API only:

```go
import "github.com/jeremyhahn/go-xkms/sdk/go/evidence"
```

The appraisal service that uses them over the network is the Verifier, which
lives above go-xkms.

## Go API

See [engineering.md](engineering.md) for the full list. The common sequence:

```go
leaf, extra, err := evidence.ParseCertificatesPEM(akCertPEM)
akKey, err := evidence.VerifyAKCertificate(leaf, extra, evidence.AKCertificateOptions{Roots: anchors})
quote, err := evidence.VerifyQuote(evidence.QuoteInput{
    Attest: attest, Signature: sig, Key: akKey,
    QualifyingData: nonce, PCRs: reported,
})
log, err := evidence.ParseEventLog(eventLogBytes)
err = evidence.VerifyEventLog(log, quote.Bank, reported)
```

## Signed reference values (CoRIM)

No network surface: the primitive is reachable in process through
`sdk/go/evidence`:

- `VerifySignedCoRIM(data []byte, CoRIMVerifyOptions) (*ReferenceManifest, error)`
- types `CoRIMVerifyOptions`, `ReferenceManifest`, `ReferenceValue`,
  `ReferenceEnvironment`, `ReferenceMeasurement`, `MeasurementKey`,
  `ReferenceDigest`
- the `MeasurementKey*` kind constants and the `ErrCoRIM*` sentinels, matched
  with `errors.Is`.

Dependencies: `github.com/veraison/corim` v1.1.2, `github.com/veraison/go-cose`
v1.3.0, with `github.com/lestrrat-go/jwx/v2` raised to v2.1.7 over the version
corim requires.
