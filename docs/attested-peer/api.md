# Attested Peer — API

> **Status: NORMATIVE** · Feature: `attested-peer` · Repo: `go-xkms` · Last verified: 2026-09-10

## No transport surface of its own, deliberately

The primitive is a library call: `Verify(ctx, Evidence, Policy) → (Verdict, error)`.
It is not exposed on REST, gRPC, QUIC, MCP, Unix or the embedded transport by
this repo, and it should not be. Its purpose is to sit **inside** a transport
gate and decide whether a request is admitted; a remote endpoint that answered
"is this evidence good?" would itself need the very gate it implements.

| Transport | Status |
|---|---|
| REST / gRPC / QUIC / MCP / Unix / embedded | Not applicable here. The transport-facing half is the attested-caller middleware in go-qrdb (go-qrdb#278), which calls this primitive on every transport it covers and fails closed. |

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
`PeerPolicy`, `PeerVerdict`, `PeerChecks`, `PeerClockInfo`, `PeerFailureClass`.
Constants: `PeerFailureNone`, `PeerFailureAbsence`, `PeerFailureCryptographic`,
`PeerChannelBindingExporterLabel`, `PeerChannelBindingLength`.
Functions: `NewPeerAttestationVerifier`, `WithPeerVerifierClock`,
`PeerQualifyingData`, `PeerChannelBinding`.
Errors: `PeerPolicyError`, `PeerContextError`, `PeerChannelBindingError`,
`PeerFailureClassError`. A persisted class parses back through
`PeerFailureClass`'s own `UnmarshalText`; an unknown name is rejected with
`*PeerFailureClassError`, which carries the rejected text.

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
