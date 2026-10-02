# Attested Peer — Architecture

> **Status: NORMATIVE** · Feature: `attested-peer` · Repo: `go-xkms` · Last verified: 2026-10-02

## The question this answers

Is the other end of a connection a **currently attested** system, or merely the
holder of a certificate a trusted CA issued?

A valid mTLS certificate proves identity. It does not prove state, and a
compromised peer still holds its key. Anywhere the stack wants an *attested*
caller — the motivating case is a node admitting an attestation reporting
server that dials it for quotes (go-trusted-platform#226) — identity is the
wrong property to gate on. `pkg/attestation/peer` is the one implementation
that renders that verdict from a TPM 2.0 quote, and the SDK re-exports it so
every consumer reaches the same code (go-xkms#273).

## Ownership

| Half | Owner | Where |
|---|---|---|
| Verification primitive: quote → verdict | **go-xkms** (this feature) | `pkg/attestation/peer`, aliased in `sdk/go/attestation_peer.go` |
| Device credential validation: is this certificate an IDevID/IAK? | **go-xkms** (this feature) | `VerifyIDevID`, `VerifyIAK`, `IsIDevID`, `IsIAK` |
| Turning a TLS connection into bound evidence | **go-xkms** (this feature) | `EvidenceFromTLS`, `QualifyingDataFromTLS` |
| The attested-caller gate: middleware that calls a verifier and fails closed on every transport | go-qrdb | `PeerAttestationGate`, `node.WithPeerAttestationGate` |
| The verifier that gate calls, the evidence cache it reads and the collector that fills it | **go-xkms** (this feature) | `pkg/attestation/peergate`, aliased in `sdk/go/attestation_peergate.go` |
| Pairing a device identity credential with its TPM's attestation key | **go-xkms** (this feature) | `VerifySameDevice` |
| Mounting the collector on a transport, provisioning anchors and baselines, quarantine action | the host (go-quicbaas, go-trusted-platform) | the host composes the pieces above |
| Producing the quote | go-xkms `pkg/tpm2` | `TPM2.Quote(pcrs, qualifyingData)` |

xkms owns all TPM 2.0 attestation (`docs/00-ownership-and-sdk-boundary.md`).
The primitive takes its trust anchors and policy as **inputs**: where they come
from — enrollment records, a device profile, a control plane — is the
consumer's provisioning problem, and this package deliberately resolves nothing
from a store. A verifier that looked the anchor up from the peer's own claims
would have no anchor at all.

## The eight checks

`Verify(ctx, Evidence, Policy) → (Verdict, error)` runs every check and reports
each one. Order is the order the dependencies fall in; nothing short-circuits
so the verdict names every failure, not the first.

| # | Check | What must hold | On failure |
|---|---|---|---|
| 1 | `AKCertificate` | The attestation key certificate in the evidence chains to `Policy.Anchors` (via `Policy.Intermediates` plus any intermediates carried in the PEM), is valid at verification time, and carries `tcg-cap-verifiedTPMRestricted` (2.23.133.11.1.3). | Missing certificate or anchors: **absence**. Does not chain, expired, not Restricted, unsupported key type: **cryptographic**. |
| 2 | `Signature` | The signature verifies over the marshaled `TPMS_ATTEST` under the certified key, using the hash the quote itself names (see below). | Missing: absence. Wrong: cryptographic. |
| 3 | `Nonce` | `TPMS_ATTEST.extraData` equals `QualifyingData(Evidence.Nonce, Policy.ChannelBinding)`. | Missing nonce: absence. Wrong: cryptographic. |
| 4 | `ChannelBinding` | Same value as 3 when the policy binds; a quote carrying the bare nonce under a binding policy fails this check while passing 3. | Cryptographic. |
| 5 | `PCRDigest` | The reported PCR index set equals the quote's selection, every value is the bank's digest size, and the values hashed in ascending index order equal the signed digest. | Missing values: absence. Anything else: cryptographic. Unusable selection (no PCRs, several banks, SHA-1 bank): absence. |
| 6 | `RequiredPCRs` | Every `Policy.RequiredPCRs` register is in the quote's selection. | Absence: the quote does not cover what the policy needs; nothing was proven wrong. |
| 7 | `Baseline` | The **proven** values (1–3 and 5 all hold) equal `Policy.Baseline`: same index set, same values. | No baseline, values unproven, or a different index set: absence. A value that differs: **cryptographic**. |
| 8 | `Freshness` | `VerifiedAt − Evidence.CollectedAt ≤ Policy.MaxEvidenceAge`. | Undated, future-dated or stale evidence: absence. |

`Passed` is the conjunction of all eight. A check the policy does not demand
(binding without `ChannelBinding`, freshness without `MaxEvidenceAge`, required
registers with none listed) is recorded as holding.

`Verify` returns an error for exactly two things: an unusable **policy**
(`*PolicyError` — negative age, negative index, empty baseline value, a required
PCR with no baseline entry) and a done context (`*ContextError`). Everything
about the **evidence** is answered in the verdict, so a gate can deny on a
false `Passed` or on an error and never has to tell them apart.

## Two failure classes, not one boolean

A negative verdict carries `Verdict.Failure`, a typed `FailureClass`:

- **`FailureCryptographic`** — a check ran and the evidence was wrong: the
  certificate does not chain or is not Restricted, the signature does not
  verify, the nonce or channel binding does not match, the reported values do
  not hash to the signed digest, a proven value diverges from the baseline.
  This is evidence of a peer in a bad state and may justify quarantine.
- **`FailureAbsence`** — a check could not run: no certificate, no anchors, no
  baseline, no timestamp, a register the peer did not quote, stale evidence.
  The peer is denied but nothing has been proven about its state. An
  unreachable peer, an expired cache or a provisioning gap must never look like
  a compromise (go-trusted-platform#226: "no evidence is not failed
  attestation").

Cryptographic dominates: one wrong check beside any number of absences is a
cryptographic verdict. The class is derived in exactly one place (`finish`) so
no check can promote or demote another's classification, and it marshals by
name (`"cryptographic"` / `"absence"` / `"none"`) so a cached report carries it
unchanged.

## Channel binding (design question 1)

A quote proves state at *quote* time, not at request time. Without binding, a
genuine quote can be relayed onto an attacker's own TLS session. The design:

- Both ends derive `ChannelBinding(&tls.ConnectionState)` = 32 bytes of
  exported keying material under the label `EXPORTER-attested-peer` with no
  context (RFC 5705 / RFC 8446 §7.5). TLS 1.3 and TLS 1.2 with extended master
  secret both support it; a connection that cannot export is a refusal, never
  a fall-back to an unbound nonce.
- The quoting side hands `QualifyingData(nonce, binding)` =
  `SHA-256(nonce ‖ binding)` to `TPM2.Quote`, which passes it to the TPM
  verbatim as `TPM2B_DATA` — 32 bytes, within every TPM's limit. **The
  existing `Quote` API needed no change**: it already carries arbitrary
  qualifying data through.
- The verifier recomputes the same value from its own nonce and its own view
  of the connection. A quote bound to another connection, or not bound at all,
  fails `ChannelBinding`.
- Without a binding (a verifier that is not on a TLS connection, or a live
  challenge over an already-attested channel) `QualifyingData(nonce, nil)` is
  the bare nonce, so existing quote/verify pairs keep working.

## Measured userspace as a policy requirement (design question 2)

A firmware/boot-chain PCR set does not detect a swapped userspace daemon —
precisely the threat when the peer is a reporting server. `Policy.RequiredPCRs`
lets a policy insist that PCR 10 (IMA) is in the quote, and `Policy.Baseline`
must then carry a value for it (a policy that requires a register it cannot
compare is rejected as a `PolicyError`). A quote over PCRs 0 and 7 alone cannot
pass such a policy, and a quote whose PCR 10 diverges while 0 and 7 match is a
cryptographic failure.

## Freshness (design question 3)

`Policy.MaxEvidenceAge` bounds `Evidence.CollectedAt`, the collector's
timestamp — **not** the TPM clock. `TPMS_CLOCK_INFO.Clock` counts milliseconds
of TPM up-time and has no wall-clock meaning without a per-TPM reference; using
it as an age would be a guess dressed as a check. The verdict reports the clock
information (`Verdict.Clock`: `Clock`, `ResetCount`, `RestartCount`, `Safe`) so a
consumer holding an earlier quote from the same TPM can notice a reboot, but
that is a consumer's comparison, not a check here.

A live challenge with a fresh nonce needs no age bound and leaves
`MaxEvidenceAge` zero. Cached evidence — the only kind a request-path middleware
may consult (go-qrdb#278 question 4) — sets it, and the verdict's `EvidenceAge`
says how old the evidence was.

## Trust anchor and policy as inputs (design question 4)

The primitive resolves nothing. `Policy.Anchors`, `Policy.Baseline` and the
peer's certificate are supplied by the caller from wherever it enrolled them. A
bare public key is not accepted as an anchor: without the certificate the
Restricted attribute cannot be checked, and TCG *TPM 2.0 Keys for Device
Identity and Attestation* v1 r12 §8.2 makes that check a MUST for a relying
party. `Policy.AllowUnrestrictedAK` exists for tests and is documented as such.

## Signature and hash rules

The TPM computes the PCR digest with the signing key's scheme hash and signs
the attestation structure with the same hash, so the PCR digest length names
the hash for both: 32 → SHA-256, 48 → SHA-384, 64 → SHA-512. RSA signatures
are accepted as RSASSA or RSA-PSS (a raw TPM signature does not say which);
ECDSA as ASN.1 DER (what `TPM2.Quote` returns) or raw `r‖s` (what a TPM emits).
Only single-bank SHA-256/384/512 selections are compared; SHA-1 is not
acceptable evidence of state.

## Device credential validation

A quote answers "is this system in a good state". It does not answer "is this
certificate a device credential at all", and a relying party needs both: a
certificate a trusted CA issued to a laptop is not an IDevID, and an
attestation key presented as an identity is the spoofing TCG marks the two
classes to prevent.

`VerifyIDevID` and `VerifyIAK` answer that, over the certificate the CA in
`pkg/ca` issues from a TCG-CSR-IDEVID:

| Check | What must hold |
|---|---|
| Validity | The certificate is within its own window at `DevIDPolicy.CurrentTime` (zero means now). Checked before the chain so an expired credential says so. |
| Chain | It chains to `DevIDPolicy.Anchors` through `Intermediates`. There is no anchorless mode: a nil pool is a `*DevIDPolicyError`, never a pass. |
| Key usage | `digitalSignature` is present (§8.1 Table 22); the certificate is not a CA and signs neither certificates nor CRLs. |
| Class | An IDevID asserts `tcg-cap-verifiedTPMFixed` and **not** `tcg-cap-verifiedTPMRestricted`; an IAK asserts the reverse. §8.2 forbids combining them, so each class refuses the other's marker. |
| Device names | subjectAltName carries the two §8.1 otherNames: an RFC 4108 hardwareModuleName whose `hwType` is the TPM 2.0 OID 2.23.133.1.2 with a non-empty `hwSerialNum`, and an RFC 4043 permanentIdentifier with a non-empty `identifierValue` assigned by `tcg-on-ekPermIdSha256` (2.23.133.12.1). |

Both encodings TCG defines for the class assertion are accepted — a
certificate policy (§8.2) and an extended key usage (§8.1) — because `pkg/ca`
stamps both and a conformant issuer may stamp either. The object identifiers
are declared in `pkg/attestation/peer` rather than imported from `pkg/ca`, so
that verifying a credential does not link the certificate authority; a test
pins each one to the value `pkg/ca` issues, because a validator that drifts
from its own issuer rejects every device it enrolled.

Unlike `Verify`, these return an **error**, not a verdict. A verdict exists
because evidence can be partially absent and the difference between absent and
wrong decides whether a peer may be quarantined. A certificate is not partial:
it either is this credential or it is not.

`IsIDevID` and `IsIAK` answer the shape question alone — no chain, no clock —
for routing a credential to a handler. They are documented as predicates and
must never be the authorization decision.

## Binding evidence to a connection, without owning the middleware

The binding derivation was already here; what was missing was the step that
uses it. A consumer had to call `ChannelBinding`, remember to put the same
value in `Policy.ChannelBinding`, and remember to fail closed when the
exporter refused. Each of those is a silent downgrade when forgotten: evidence
bound to a connection verified under an unbound policy accepts a relayed
quote.

`EvidenceFromTLS(state, reported)` returns the evidence **and** the binding as
one value whose `BindPolicy` installs it, so the pair cannot drift, and
returns `*ChannelBindingError` with no evidence when the connection cannot
export. `QualifyingDataFromTLS(state, nonce)` is the same closure on the
quoting side: a connection that yields no binding yields no qualifying data,
so a quoter cannot perform half of the binding.

Both are library calls over `*tls.ConnectionState`. Nothing here is HTTP- or
gRPC-shaped, nothing reads a header, and neither decides what a request does
next: that is still the consumer's middleware (go-qrdb#278). They say nothing
about the evidence either — missing or wrong quote fields stay the verdict's
business — so a middleware gets an error from them only when its own
connection is unusable.

## The go-qrdb gate verifier (`pkg/attestation/peergate`)

go-qrdb's attested-caller gate runs after authentication and RBAC: for a gated
permission it asks a `PeerAttestationVerifier` whether the peer on the
connection is currently attested, and refuses on anything but a fresh, passing
verdict about that same peer. go-qrdb owns that seam and nothing behind it.
`pkg/attestation/peergate` is what stands behind it, so a host composes the
gate from go-qrdb and go-xkms alone and writes no verification code.

```
peer                         host (collector mounted on its transport)        go-qrdb node
 |  Challenge  ------------>  Collector.Challenge(state) -> nonce
 |  quote(H(nonce||exporter(conn)))  (QuoteEvidence)
 |  Submit(evidence) ------>  Collector.Submit(state, evidence)
 |                              -> Record{thumbprint, evidence, exporter(conn), receipt time}
 |                                                     EvidenceStore
 |  gated request ---------------------------------------------------------->  authn, RBAC, gate
 |                                                Verifier.VerifyPeer  <------  AttestedPeer{cert, thumbprint}
 |                                                re-verify the record under the provisioned
 |                                                policy bound to its own connection
```

**Identity is the connection, never the request.** The collector and the
verifier both key on the canonical SPKI thumbprint of the certificate the TLS
handshake verified (go-qrdb's `ComputeSPKIThumbprint`, the same identifier a
certificate binding holds). A record exists only for a peer that answered a
nonce issued to that thumbprint, over a connection authenticated as it.

**Challenges are single-use and short-lived.** `Challenge` issues a 32-byte
random nonce per peer (a new one replaces the last); `Submit` consumes it
whether the submission is accepted or not, so a nonce is answered at most once
and a wrong guess costs the challenge. Outstanding challenges and stored
records are both bounded, and a full store evicts only evidence older than its
retention window, never a current peer's.

**The binding is carried, not dropped.** The quote is bound to the TLS session
it was submitted on, and the record keeps that session's exporter value. On a
gated request the verifier re-verifies the record under the policy *bound to
that stored value*. This proves the TPM that signed the quote was on the far
end of a session authenticated by this certificate, without requiring the
gated request to arrive on the same session. A record with no binding is
refused, so a foreign store cannot downgrade verification to an unbound one.

**Verdicts are rendered from the cache, on every call.** `VerifyPeer` never
collects. It does verify again, under the current policy and clock, so a
baseline change, an attestation key certificate that expired, or evidence
past the policy's own age bound takes effect on the next request. The
verdict's `CollectedAt` is the collector's receipt time, which the gate holds
to its own maximum age independently of the verifier. The verdict names the
record's own thumbprint, so a store that answers with another peer's record is
refused by the gate as a peer mismatch.

**The latest evidence wins.** A submission replaces the peer's record whether
its quote passes or not. The collector does not judge it: a peer whose state
turned bad cannot keep presenting an older passing quote once it has submitted
a new one, and a wrong quote is refused on the next gated request as a
cryptographic failure, which go-qrdb audits as a security event.

**Device binding closes the relay channel binding leaves open.** Channel
binding proves the TPM-holder was on the authenticated session. It does not
stop a host holding a valid client certificate from asking a *different*,
healthy machine to quote over its session. When `VerifierConfig.DeviceIdentity`
is set, the connection certificate must verify as an IDevID under that policy
and `VerifySameDevice` must find the same TCG DevID §8.1 hardware module name
and permanent identifier on it and on the attestation key certificate. Two
well-formed credentials that name different TPMs are a cryptographic failure;
a connection certificate that is not a device credential is an absence.

**Failure classes carry through.** The gate's verdict uses the primitive's
classes unchanged, with the same rule: one cryptographic failure beside any
number of absences is cryptographic. No evidence, stale evidence and an
unreadable credential are absences; a forged signature, a quote bound to
another session, a measurement off the baseline and a device mismatch are
cryptographic. The verifier returns an error, which the gate also refuses,
only when it cannot decide at all: a peer description whose thumbprint is not
its certificate's, a store failure, a done context.

**The cache is per process by default.** `MemoryStore` serves one node. A host
that spreads peers across nodes either routes submissions to every node or
supplies its own `EvidenceStore`; the interface is three methods (`Put`,
`Get`, `Delete`), and `Delete` is how a host withdraws a peer's evidence.

## What is deliberately not here

- **Revocation.** The consumer's recommendation is attestation-gated
  short-lived credentials, which fail closed by expiry; a pushed denylist
  fails open. Neither changes this primitive.
- **The transport middleware.** go-qrdb's gate is the middleware on every
  transport; this feature supplies the verifier it calls.
- **The collector's transport.** `Collector.Challenge` and `Collector.Submit`
  take the request's `*tls.ConnectionState`; the host mounts them on whatever
  transport its peers reach, the same way it mounts any other route.
- **Event-log replay.** The verdict is over PCR values; reconstructing them
  from a TCG event log is a separate capability.

## The residual limit, stated plainly

Nothing here detects a compromise that changes no measured state, or one that
occurs after the last quote. Channel binding shrinks the window to one
connection; a short `MaxEvidenceAge` and a short refresh interval shrink the
rest. Attestation is not continuous proof and the API does not imply it.
