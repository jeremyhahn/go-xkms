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
| REST / gRPC / QUIC / MCP / Unix / embedded | No verdict endpoint. The transport-facing half is go-qrdb's attested-caller gate, which calls the `pkg/attestation/peergate` verifier on every network transport and fails closed. What a peer calls is the collector: the two verbs below. |

## Installing the gate

**xkmsd.** Set the mode and pass the policy:

```yaml
attestation:
  peer_gate: required   # off (default) | optional | required
```

```go
srv, err := server.New(cfg, server.WithAttestedCallerPolicy(peergate.GatePolicy{
    Quote:          peer.Policy{Anchors: akRoots, Baseline: baseline, RequiredPCRs: []int{10}},
    DeviceIdentity: &peer.DevIDPolicy{Anchors: deviceRoots}, // optional
    Permissions:    []qrdbsdk.Permission{...},
    MaxEvidenceAge: 15 * time.Minute,
}))
```

The mode in the configuration overrides the policy's. `peer_gate` other than
`off` requires `datastore.mode: standalone`, since the gate sits on the
embedded node (`pkg/config/config.go:1801-1806`), and a policy:
`ErrAttestedCallerPolicyMissing` otherwise (`pkg/server/peer_gate.go:54`).

**A host composing the xkms module** (go-quicbaas):

```go
import (
    qrdbnode "github.com/jeremyhahn/go-qrdb/sdk/go/node"
    xkms     "github.com/jeremyhahn/go-xkms/sdk/go"
)

module, err := xkms.NewServiceModule(resolve,
    xkms.WithServiceModuleQRDBClient(client),
    xkms.WithServiceModuleServiceContext(serviceContext),
    xkms.WithAttestedCallerGate(xkms.AttestedCallerPolicy{
        Mode:           xkms.AttestedCallerRequired,
        Quote:          xkms.PeerPolicy{Anchors: akRoots, Baseline: baseline},
        Permissions:    gated,
        MaxEvidenceAge: 15 * time.Minute,
    }))
node, err := qrdbnode.NewStandaloneNode(ctx, cfg, serverOpts,
    qrdbnode.WithPeerAttestationGate(module.PeerAttestationGate()))
```

Without `WithServiceModuleQRDBClient`, `NewServiceModule` returns
`*AttestedCallerClientError`: the evidence lives in the host's datastore.
`serviceContext` is the node's `ServiceContext`: on a node that enforces
authentication, the evidence storage runs as the node's service principal,
and without the option it is refused (`qrdbsdk.ErrUnauthenticated`). The
PCR baseline is the host's; go-xkms ships none.

The building blocks (`NewPeerDAOEvidenceStore`, `NewPeerEvidenceCollector`,
`NewPeerGateVerifier`, then `qrdbsdk.NewPeerAttestationGate`) stay exported for
a host that assembles a gate of its own.

## The verbs: Challenge and Submit

| Verb | REST | gRPC (`KeystoreService`) | MCP | Permission |
|---|---|---|---|---|
| Challenge | `POST /api/v1/peer-attestation/challenge` | `PeerAttestationChallenge` | `peer.attestation.challenge` | `peer_attestation:challenge` |
| Submit | `POST /api/v1/peer-attestation/evidence` | `SubmitPeerAttestation` | `peer.attestation.submit` | `peer_attestation:submit` |

Routes: `pkg/api/rest/routes.go:414-415`, `pkg/api/grpc/proto/xkmsv1/xkms.proto:777`
and `:783`, `pkg/api/mcp/server.go:456-457`. Both permissions are self-scoped;
the built-in User and Operator roles hold them
(`pkg/apimodule/module_grants.go:94`, `:121`), Admin and Owner hold every
module permission, SO and Auditor neither. The gate never gates them
(`ExemptPermissions`, `pkg/attestation/peergate/gate.go:63`), since they are
how a peer becomes attested.

Challenge takes no input: the peer is the verified client certificate on the
connection. It returns `nonce` (32 bytes) and `expires_at`. Submit takes the
evidence quoted over that nonce, bound to **the same connection**:

| Field | Notes |
|---|---|
| `quote` | marshaled `TPMS_ATTEST` |
| `signature` | the quote signature |
| `nonce` | the challenge nonce |
| `pcrs` | index → value for the quoted selection |
| `ak_certificate_pem` | the attestation key certificate chain |

A submission whose quote is wrong is accepted and stored: the verifier refuses
it on the next gated request, as a cryptographic failure, where go-qrdb's gate
audits it. The collector keeps challenges in memory, so a peer answers a
challenge on the node that issued it; the evidence itself is shared through
the datastore.

Errors, classified once for all three transports
(`pkg/api/apierrors/tables.go:240-261`):

| Error | Class | REST | gRPC |
|---|---|---|---|
| No verified client certificate (`*PeerCertificateError`), including the unix socket and the in-process caller | Unauthenticated | 401 | `UNAUTHENTICATED` |
| No unexpired challenge, a different nonce, or a replay (`*PeerChallengeError`); a connection that cannot be bound (`*PeerChannelBindingError`) | FailedPrecondition | 409 | `FAILED_PRECONDITION` |
| The challenge table is full (`*PeerGateCapacityError`) | ResourceExhausted | 429 | `RESOURCE_EXHAUSTED` |
| No gate on this node (`ErrNotConfigured`), the evidence store or nonce source failed | Unavailable | 503 | `UNAVAILABLE` |

MCP maps the same classes to its JSON-RPC codes.

The verifier's outcome reaches the caller of a gated operation through
go-qrdb's gate: a refused verdict is `*PeerAttestationRefusedError` (REST 403,
gRPC `PERMISSION_DENIED`), a verifier error is the same error with reason
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
