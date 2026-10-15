# Attested Peer — Using it

> **Status: NORMATIVE** · Feature: `attested-peer` · Repo: `go-xkms` · Last verified: 2026-10-02

Two parties: the **quoter** (the peer that must prove its state) and the
**verifier** (the side that decides). Both import `pkg/attestation/peer`
directly or its `sdk/go` `Peer*` aliases.

## Quoting side: produce evidence bound to this connection

```go
state := tlsConn.ConnectionState()
qualifying, err := peer.QualifyingDataFromTLS(&state, nonce) // nonce came from the verifier
if err != nil {
    return err // refuse; never fall back to an unbound quote
}
q, err := tpm.Quote([]uint{0, 1, 2, 3, 4, 5, 6, 7, 10}, qualifying)
```

`QualifyingDataFromTLS` derives the binding and folds it into the qualifying
data in one step, so there is no path where the binding fails and the bare
nonce is quoted anyway. `ChannelBinding` and `QualifyingData` remain available
for a caller that needs the two halves separately.

Return `q.Quoted`, `q.Signature`, and the PCR values you read for the same
selection. Include PCR 10 when the verifier's policy will require it; a quote
over the firmware registers alone cannot pass such a policy.

If there is no TLS connection to bind to (you are answering a verifier that is
not on the wire with you), pass the bare `nonce` as qualifying data.

## Verifying side: render a verdict

```go
verifier := peer.NewVerifier()

state := tlsConn.ConnectionState()
bound, err := peer.EvidenceFromTLS(&state, peer.Evidence{
    Quote:            resp.Quote,
    Signature:        resp.Signature,
    Nonce:            nonce,                 // the one you issued
    PCRs:             resp.PCRs,
    AKCertificatePEM: enrolled.AttestCert,   // from enrollment, not the request
    CollectedAt:      time.Now().UTC(),
})
if err != nil {
    return deny(err)                         // this connection yields no binding
}

verdict, err := verifier.Verify(ctx, bound.Evidence, bound.BindPolicy(peer.Policy{
    Anchors:       platformRoots,
    Intermediates: platformIntermediates,
    Baseline:      profile.PCRBaseline,      // includes PCR 10
    RequiredPCRs:  []int{10},
}))
if err != nil {
    return deny(err)                         // misconfigured policy, or ctx done
}
if !verdict.Passed {
    switch verdict.Failure {
    case peer.FailureCryptographic:
        auditSecurityEvent(verdict.Reason)   // count toward quarantine
    case peer.FailureAbsence:
        auditRefusal(verdict.Reason)         // deny only
    }
    return deny(verdict)
}
admit()
```

## Gating a go-qrdb node on attested peers

`api.md` has the full listing.

1. Decide the policy: the attestation key anchors and the PCR baseline you
   enrolled (go-xkms ships no reference values), and, if your peers' TLS
   certificates are IDevIDs, a `DeviceIdentity` policy so a quote from another
   TPM is refused. Name the permissions that need an attested caller and the
   maximum evidence age.
2. Pick the mode. `required` refuses a gated call from any peer without
   fresh, passing evidence. `optional` lets a peer that has never submitted
   through, and refuses one whose evidence fails: use it while peers are
   being rolled onto attestation.
3. Install it:
   - **xkmsd:** set `attestation.peer_gate` to the mode (the embedded node
     needs `datastore.mode: standalone`) and pass the policy with
     `server.WithAttestedCallerPolicy`.
   - **A host of the xkms module:** pass `WithAttestedCallerGate(policy)` and
     `WithServiceModuleQRDBClient` to `NewServiceModule`, then
     `module.PeerAttestationGate()` to `node.WithPeerAttestationGate`.
4. On each peer, on a schedule shorter than the maximum evidence age, over
   mTLS on one connection: call Challenge
   (`POST /api/v1/peer-attestation/challenge`, gRPC
   `PeerAttestationChallenge`, MCP `peer.attestation.challenge`), call
   `PeerQuoteEvidence` with the client side of **that same connection**, and
   Submit the result on it (`POST /api/v1/peer-attestation/evidence`,
   `SubmitPeerAttestation`, `peer.attestation.submit`). An HTTP client pinned
   to one connection (`MaxConnsPerHost: 1`) does this; the response's `TLS`
   field is the state to quote with. The peer needs `peer_attestation:challenge`
   and `peer_attestation:submit`, which the User and Operator roles hold.
   In a cluster, answer a challenge on the node that issued it.

What the peer then sees on a gated call:

| Situation | Result |
|---|---|
| Never submitted, or evidence withdrawn (`store.Delete`) | refused (`optional`: admitted) |
| Challenge or Submit with no client certificate (the unix socket, the in-process caller) | refused as unauthenticated |
| Latest submission valid and younger than the maximum age | admitted |
| Latest submission older than the maximum age | refused until the peer submits again |
| Latest submission forged, bound to another session, off the baseline, or from another TPM | refused, audited as a security event |

## Consulting cached evidence on a request path

`pkg/attestation/peergate` does all of this for a go-qrdb node, and keeps the
channel binding of the session the evidence arrived on so the cached quote is
still verified as bound. Use the primitive directly only when you build a gate
of your own.

A request path must never trigger a quote. Verify the cached evidence with the
age bound the cache policy allows, and without a channel binding (the cached
quote was bound to the collector's connection, not this one):

```go
verdict, err := verifier.Verify(ctx, cached.Evidence, peer.Policy{
    Anchors:        roots,
    Baseline:       baseline,
    RequiredPCRs:   []int{10},
    MaxEvidenceAge: 15 * time.Minute,
})
```

Stale evidence fails `Freshness` as an **absence**: deny, but do not treat the
peer as compromised. `verdict.EvidenceAge` says how old it was.

## Capturing a first baseline (trust on first use)

A consumer whose policy has no baseline yet verifies with `Baseline: nil`. The
verdict fails `Baseline` as an absence, but if `AKCertificate`, `Signature`,
`Nonce` and `PCRDigest` all hold, `verdict.PCRs` carries the proven values and
may be recorded as the baseline. Record that as a security event: it is the
moment trust was conferred without prior evidence.

## Checking that the peer holds a device credential

Attestation says the peer is in a good state. It does not say the certificate
it authenticated with is a device credential at all — so check both, and check
this one first: it is cheap, and a peer without a device identity has nothing
to attest as.

```go
leaf := state.PeerCertificates[0]
if err := peer.VerifyIDevID(ctx, leaf, peer.DevIDPolicy{
    Anchors:       deviceRoots,          // provisioned; never taken from the peer
    Intermediates: deviceIntermediates,
}); err != nil {
    return deny(err)                     // *DevIDError, or *DevIDPolicyError if you have no anchors
}
```

`VerifyIAK` is the same check for the attestation credential — the one whose
certificate you pass as `AKCertificatePEM`. An IDevID is refused by
`VerifyIAK` and an IAK by `VerifyIDevID`: the two classes are marked
differently precisely so one cannot be presented as the other.

`IsIDevID` and `IsIAK` answer the shape question only — no chain is built and
no clock is consulted — so they are for routing a credential to the right
handler. **Never** admit a peer on a predicate.

## Reading a verdict

- `Passed` — admit.
- `Checks` — which of the eight held.
- `Failure` — `cryptographic` (evidence present and wrong) or `absence` (a
  check could not run). Only the first is grounds for anything beyond denial.
- `Reason` — every failed check, in order, human-readable.
- `Clock` — the TPM's `ResetCount` / `RestartCount`; compare with the previous
  quote from the same TPM to notice a reboot.

## What to watch for

- **`AllowUnrestrictedAK` is for tests.** A certificate without
  `tcg-cap-verifiedTPMRestricted` does not prove the quote came from a TPM.
- **Hold the certificate from enrollment.** Accepting a certificate from the
  request means the peer chooses its own anchor.
- **Keep the nonce yours.** Compare against the nonce you issued, never one
  echoed in the response.
