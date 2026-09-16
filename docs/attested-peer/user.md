# Attested Peer — Using it

> **Status: NORMATIVE** · Feature: `attested-peer` · Repo: `go-xkms` · Last verified: 2026-09-16

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

## Consulting cached evidence on a request path

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
