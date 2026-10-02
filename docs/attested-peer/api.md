# Attested Peer — API

> **Status: NORMATIVE** · Feature: `attested-peer` · Repo: `go-xkms` · Last verified: 2026-10-02

## No transport surface of its own, deliberately

The primitive is a library call: `Verify(ctx, Evidence, Policy) → (Verdict, error)`.
It is not exposed on REST, gRPC, QUIC, MCP, Unix or the embedded transport by
this repo, and it should not be. Its purpose is to sit **inside** a transport
gate and decide whether a request is admitted; a remote endpoint that answered
"is this evidence good?" would itself need the very gate it implements.

The same holds for the device-trust primitives beside it. `VerifyIDevID`,
`VerifyIAK`, `EvidenceFromTLS` and `QualifyingDataFromTLS` take a
`*x509.Certificate` or a `*tls.ConnectionState` and return an answer; none
reads a header, a metadata map or a request, and none decides what happens to
a request next.

| Transport | Status |
|---|---|
| REST / gRPC / QUIC / MCP / Unix / embedded | Not applicable here. The transport-facing half is go-qrdb's attested-caller gate, which calls the `pkg/attestation/peergate` verifier on every network transport and fails closed. |

## The gate verifier: a composition-plane (Tier 2) capability

`pkg/attestation/peergate` is placed in Tier 2: a host injects the `Verifier`
into go-qrdb's node through `qrdbsdk.NewPeerAttestationGate` and
`node.WithPeerAttestationGate`, and mounts the `Collector`'s two calls on its
own transports. Neither half has a transport of its own here, for the reasons
above, and because both are defined over the `*tls.ConnectionState` of the
request — a value that exists only inside the transport that terminated TLS.

```go
import (
    qrdbsdk  "github.com/jeremyhahn/go-qrdb/sdk/go"
    qrdbnode "github.com/jeremyhahn/go-qrdb/sdk/go/node"
    xkms     "github.com/jeremyhahn/go-xkms/sdk/go"
)

store, err := xkms.NewPeerMemoryEvidenceStore(xkms.PeerMemoryEvidenceStoreConfig{})
collector, err := xkms.NewPeerEvidenceCollector(xkms.PeerEvidenceCollectorConfig{Store: store})
verifier, err := xkms.NewPeerGateVerifier(xkms.PeerGateVerifierConfig{
    Store:  store,
    Policy: xkms.PeerPolicy{Anchors: akRoots, Baseline: baseline, RequiredPCRs: []int{10}},
    DeviceIdentity: &xkms.PeerDevIDPolicy{Anchors: deviceRoots}, // optional
})
gate, err := qrdbsdk.NewPeerAttestationGate(verifier, qrdbsdk.PeerAttestationPolicy{
    Permissions:    []qrdbsdk.Permission{...},
    MaxEvidenceAge: 15 * time.Minute,
})
node, err := qrdbnode.NewStandaloneNode(ctx, cfg, serverOpts, qrdbnode.WithPeerAttestationGate(gate))
```

The two collector calls a host mounts, and what they mean on the wire:

| Call | Input | Output | Refusals |
|---|---|---|---|
| `Challenge(ctx, r.TLS)` | the request's TLS state (the peer is its verified client certificate) | `PeerChallenge{Nonce, ExpiresAt}` | `*PeerCertificateError` (403), `*PeerGateCapacityError` (503) |
| `Submit(ctx, r.TLS, evidence)` | the request's TLS state and a `PeerEvidence` (the wire shape below) | — | `*PeerCertificateError` (403), `*PeerChallengeError` (403), `*PeerChannelBindingError` (403), `*PeerEvidenceStoreError` (503) |

A submission whose quote is wrong is accepted and stored: the verifier refuses
it on the next gated request, as a cryptographic failure, where go-qrdb's gate
audits it. The status codes are a suggestion for an HTTP host.

The verifier's outcome reaches the caller through go-qrdb's gate, which maps
it: a refused verdict is `*PeerAttestationRefusedError` (REST 403, gRPC
`PERMISSION_DENIED`), a verifier error is the same error with reason
`verifier-error` (REST 503, gRPC `UNAVAILABLE`).

## The SDK surface

`sdk/go/attestation_peer.go` aliases the package for consumers that must not
import `pkg/*` directly. go-quicbaas re-exports these under
`sdk/go/xkms/*`, and go-trusted-platform reaches them there.

```go
import xkms "github.com/jeremyhahn/go-xkms/sdk/go"

verifier := xkms.NewPeerAttestationVerifier()
verdict, err := verifier.Verify(ctx, xkms.PeerEvidence{...}, xkms.PeerPolicy{...})
```

Types: `PeerAttestationVerifier`, `PeerVerifierOption`, `PeerEvidence`,
`PeerPolicy`, `PeerVerdict`, `PeerChecks`, `PeerClockInfo`, `PeerFailureClass`,
`PeerDevIDPolicy`, `PeerTLSEvidence`.
Constants: `PeerFailureNone`, `PeerFailureAbsence`, `PeerFailureCryptographic`,
`PeerChannelBindingExporterLabel`, `PeerChannelBindingLength`.
Functions: `NewPeerAttestationVerifier`, `WithPeerVerifierClock`,
`PeerQualifyingData`, `PeerChannelBinding`, `PeerVerifyIDevID`,
`PeerVerifyIAK`, `PeerIsIDevID`, `PeerIsIAK`, `PeerEvidenceFromTLS`,
`PeerQualifyingDataFromTLS`.
Errors: `PeerPolicyError`, `PeerContextError`, `PeerChannelBindingError`,
`PeerFailureClassError`, `PeerDevIDError`, `PeerDevIDPolicyError`. A persisted
class parses back through `PeerFailureClass`'s own `UnmarshalText`; an unknown
name is rejected with `*PeerFailureClassError`, which carries the rejected
text.

The `Peer` prefix is the existing convention of this flat namespace, not a
statement about scope: `Evidence`, `Verifier` and `VerifyOptions` already name
the x509 key-attestation surface in `sdk/go`.

## Device credential validation

```go
err := xkms.PeerVerifyIDevID(ctx, cert, xkms.PeerDevIDPolicy{
    Anchors:       deviceRoots,          // provisioned, never from the peer
    Intermediates: deviceIntermediates,
})
```

| Outcome | Meaning | Suggested mapping |
|---|---|---|
| `nil` | The certificate is a device identity credential valid under the policy | proceed to the attestation verdict |
| `*PeerDevIDError` | The certificate is not that credential; `Credential` names the class checked ("IDevID"/"IAK") and `Reason` the check that failed | deny (REST 403, gRPC `PermissionDenied`), audit as an ordinary refusal |
| `*PeerDevIDPolicyError` | The **verifier** is misconfigured — no trust anchors | deny, alert the operator (REST 500 class, gRPC `Internal`) |
| `*PeerContextError` | The request is already gone | — |

A chain failure unwraps: `errors.As(err, &x509.UnknownAuthorityError{})` holds
through `*PeerDevIDError`.

`PeerIsIDevID` / `PeerIsIAK` return a bool for the shape alone — no chain, no
clock. Use them to route a credential to a handler, never to admit one.

## Binding evidence to the connection it arrived on

```go
bound, err := xkms.PeerEvidenceFromTLS(state, reported)   // *tls.ConnectionState
if err != nil {
    return deny(err)                                      // *PeerChannelBindingError
}
verdict, err := verifier.Verify(ctx, bound.Evidence, bound.BindPolicy(basePolicy))
```

`bound.BindPolicy` takes and returns a `PeerPolicy` by value, so one
provisioned policy binds many connections and the caller's copy is never
written to. On the quoting side, `PeerQualifyingDataFromTLS(state, nonce)`
returns the value to hand to `TPM2.Quote`.

Neither function inspects the evidence: a missing quote or a wrong nonce is
still answered in the verdict, so these return an error only when the
connection itself cannot yield a binding.

## The quoting side of the gate

```go
evidence, err := xkms.PeerQuoteEvidence(state, challenge.Nonce, tpm, []uint{0, 7, 10}, akCertPEM)
```

`state` is the client side of the TLS connection the evidence will be
submitted on; `tpm` is any `PeerQuoter` (the TPM2 keystore is one). Errors:
`*PeerChannelBindingError` when the connection cannot export, `*PeerQuoteError`
when the TPM cannot quote or a PCR kept changing under the quote.

## The wire shape a consumer carries

The primitive does not define a wire format; the consumer's transport does.
What must cross the wire for a verdict to be possible is exactly `Evidence`:

| Field | Producer | Notes |
|---|---|---|
| `Quote` | the peer's TPM, via `TPM2.Quote` | marshaled `TPMS_ATTEST` |
| `Signature` | the peer's TPM | raw RSA, or ECDSA ASN.1 / `r‖s` |
| `Nonce` | the verifier | echoed by the peer; the verifier compares its own copy |
| `PCRs` | the peer | the values it read for the quoted selection |
| `AKCertificatePEM` | enrollment | the verifier should hold this from enrollment, not accept it from the request |
| `CollectedAt` | the collector | stamped on receipt |

`Policy` never crosses the wire: it is the verifier's.

## Status and error mapping for consumers

When a consumer maps a verdict onto a transport:

| Verdict | Suggested mapping | Rationale |
|---|---|---|
| `Passed` | admit | — |
| `Failure = absence` | deny (REST 403, gRPC `PermissionDenied`), audit as an ordinary refusal | nothing proven about the peer's state |
| `Failure = cryptographic` | deny, audit as a **security event**, feed the consumer's quarantine threshold | evidence present and wrong |
| `*PolicyError` | deny, alert the operator (REST 500 class, gRPC `Internal`) | the verifier is misconfigured |
| `*ContextError` | the request is already gone | — |

The mapping is the consumer's to ratify; this table records the intent the
failure classes were designed to serve.
