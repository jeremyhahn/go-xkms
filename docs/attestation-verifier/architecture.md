# Attestation Verifier — Architecture

> **Status: NORMATIVE** · Feature: `attestation-verifier` · Module: `go-xkms` · Last verified: 2026-10-14

## The problem

Several unrelated hardware roots can back a key xkms is asked to certify —
YubiKey PIV, TPM 2.0, Android StrongBox, and whatever a future backend adds —
and each proves it a different way: a static PIV slot certificate, a
TPM2_Certify structure over a public area, an Android key-attestation X.509
extension. A CA that wants to gate certificate issuance on "this key lives in
hardware" needs one place that decides whether a chain of evidence is good
enough, or it needs that decision reimplemented once per format — three ways
to get it wrong instead of one, and a fourth vendor blocked until a fourth
copy exists.

Chain validity is not the whole answer, either. A structurally valid,
correctly-anchored attestation chain proves that *some* hardware produced
*some* certificate. It does not by itself prove that the hardware attested to
the *specific key* a CSR asks the CA to certify, or that the evidence is
fresh rather than a recording of an earlier exchange. Skipping that check
turns a public, replayable attestation chain — these travel with every
enrollment — into a certificate that reads as hardware-backed for a key that
was never near the hardware.

## Shape chosen: two checks that both have to pass

**Chain and signature verification** — `Verifier` (`verifier.go`) validates a
certificate chain structurally (each certificate signed by the next, none
expired) and, when trust anchors are configured, against those anchors.
`VerifyChainAnchored` is the fail-closed form: called with zero anchors it
returns `ErrNoTrustAnchors` rather than falling back to structural-only
validation, because a self-consistent chain the caller minted must never
satisfy an attestation gate (`verifier.go:192`). `Verify` additionally checks
a cryptographic signature over attestation data and, optionally, freshness
(timestamp/nonce) and TPM PCR values — the full flow for a self-contained
`AttestationStatement` produced by `AttestKey`.

**Format-specific invariants** — `VerifyInvariants`/`Evidence`
(`invariants.go`) answer the question chain validation cannot: does *this*
evidence bind to *this* CSR's key, and is it fresh. Binding is per-format,
because the mechanism is a property of the format, not a policy choice —
`FormatAndroidKey`/`FormatYubiKeyPIV` bind by comparing the leaf's
`SubjectPublicKeyInfo` to the CSR; `FormatTPM2` binds through a
`TPM2_Certify` Name comparison (`tpm2.VerifyCertifyRaw`), because a TPM Name
is a digest over the public *area* and cannot be derived from a public key.
Freshness is likewise per-format: only formats that carry a challenge
mechanism (Android's attestation extension) are checked for one; PIV
attestation is deliberately never demanded a nonce, because a PIV slot
attestation certificate is minted once at key generation and is static
thereafter (`invariants.go:131-140`) — replay there is defeated by binding,
not freshness. TPM2 is the same: the TCG-CSR-IDEVID carrier supplies no
challenge either, because that certification is produced when the IDevID is
created, long before a CA picks one — freshness for *that* ceremony comes
from credential activation and the quote, both bound to values chosen
in-session (`pkg/ca/tcg.go:375-378`).

**One gate, two carriers.** `VerifyInvariants` is called from two places
because the evidence formats it checks are externally defined standards
delivered two different ways, not because the check itself differs:
`pkg/xkms.enforceAttestationInvariants` (`servicer_ca_attestpolicy.go:76`)
adapts a generic `SignCSR` request (PKCS#10 CSR plus a format-tagged
certificate chain) into `Evidence`; `pkg/ca`'s TCG-CSR-IDEVID path
(`tcg.go:379-390`) adapts the TCG-CSR-IDEVID packed structure (TPM public
areas and a `TPM2_Certify` structure, no PKCS#10 at all) into the same
`Evidence` shape, for `FormatTPM2` only. The code comment at the second call
site says this outright: before this gate existed, "each route reached its
own conclusion by its own route, and they had already drifted apart"
(`tcg.go:367-373`).

**These are invariants, not policy.** The package comment is explicit: "there
is no configuration that disables them" (`invariants.go:31`). The one
deliberate, logged escape hatch is narrower than that: a server can call
`XKMSService.AllowUnboundAttestationFormats(true)` to accept a format whose
binding mechanism the evidence *cannot express* (`ErrBindingUnavailable`) —
off by default, and every such issuance is logged at `WARN` with the
consequence spelled out (`servicer_ca_attestpolicy.go:48-60`). It does not
relax `ErrKeyNotBound` or `ErrStaleEvidence` — those two are not
configurable at all.

## Two checks belong to different call paths

This matters for reading the code correctly: `Verify()` (and the
`VerifySignature` it calls) verifies a self-contained `AttestationStatement`
— the shape `AttestKey` produces, with a `Signature` over `AttestationData`
proving the hardware itself signed the statement. The CSR-attestation gate
(below) does **not** build one of those. `verifyCSRAttestation`
(`pkg/xkms/servicer_ca.go:306`) constructs a statement carrying only `Format`
and `CertificateChain`, and calls `VerifyChainAnchored` — never `Verify` or
`VerifySignature`. Proof of possession there comes from elsewhere: the CSR's
own self-signature (`csr.CheckSignature()`,
`servicer_ca_attestpolicy.go:88`) plus, for TPM2, the `TPM2_Certify`
signature checked inside `VerifyInvariants`' binding step. In the current
tree, `Verifier.Verify`/`VerifySignature` are exercised by the package's own
tests and by `examples/attestation/basic-attestation` — no server-side
consumer calls them; the one production consumer uses the chain-anchoring and
invariant halves only. This is not a gap: an `AttestationStatement`'s
`Signature` field is a separate proof shape (a detached signature over
`AttestationData`) that the X.509-chain-only evidence formats
(`yubikey-piv`, `tpm2`, `android-key-attestation`) never populate, so nothing
today calls `Verify()` with a chain-based `Evidence`.

## Component boundaries

| Piece | Where | Owner |
|---|---|---|
| Chain/signature verifier | `pkg/attestation/verifier.go`, `types.go`, `errors.go` | this feature |
| Format-agnostic key-binding gate | `pkg/attestation/invariants.go` | this feature |
| Per-format trust-anchor config | `pkg/config/attestation.go` (`AttestationConfig`) | this feature |
| CSR-attestation gate (consumer, generic `SignCSR`) | `pkg/xkms/servicer_ca.go`, `servicer_ca_attestpolicy.go` | `pkg/xkms` |
| CSR-attestation gate (consumer, TCG-CSR-IDEVID `SignTCGCSR`) | `pkg/ca/tcg.go:379-390` | `pkg/ca`, see [`certificate-authority`](../certificate-authority/) |
| Server startup wiring (consumer) | `pkg/server/server.go:913-926` | `pkg/server` |
| Attestation *generation* (`AttestKey`) | `pkg/backend/tpm2/attestation.go`, `pkg/backend/pkcs11/attestation.go`, `types.AttestingKeyProvider` | [`key-management`](../key-management/), [`tpm2`](../tpm2/), [`pkcs11-backend`](../pkcs11-backend/) |
| Attested-peer (quote → verdict, TLS binding) | `pkg/attestation/peer` | [`attested-peer`](../attested-peer/) |
| Android extension parsing | `pkg/attestation/android` | referenced here for `androidChallenge`; otherwise xkey's phone documentation |
| Well-known/external root pools | `pkg/attestation/truststore` | consumed by both this feature (`AttestationConfig.Verifiers`) and [`certificate-authority`](../certificate-authority/) (TCG EK trust) — not owned by either |

This folder documents the root `pkg/attestation` package: `verifier.go`,
`types.go`, `errors.go`, `invariants.go`, and the config/wiring that connects
them to CSR issuance. It does not document the `peer`, `android`, or
`truststore` subpackages — each has its own home, above — and it does not
document attestation *generation* (`AttestKey`), which is a key-provider
capability documented alongside the rest of key lifecycle management.

## Data flow

```
attestation:                              # xkmsd config, pkg/config.Config.Attestation
  formats:
    tpm2:
      external_root_paths: [/etc/xkms/tpm-manufacturer-root.pem]
    yubikey-piv:
      external_root_paths: [/etc/xkms/yubico-piv-root.pem]
    android-key-attestation:
      embedded_roots: [google-hardware-attestation]

  → AttestationConfig.Verifiers()          (pkg/config/attestation.go:58)
      per format: truststore.New(cfg) → attestation.NewVerifier(store.Roots())
      a format with zero resulting roots is a config error, not an anchorless verifier

  → XKMSService.SetAttestationVerifiers(verifiers)   (pkg/server/server.go:916-926, startup)
      a verifier with TrustAnchorCount()==0 is rejected here too — defense in depth

CSR arrives with AttestationFormat/AttestationChain/AttestationNonce set
  (transport.SignCSRRequest, pkg/api/transport/types.go:1327-1333)

  → verifyCSRAttestation                    (pkg/xkms/servicer_ca.go:306)
      attestationVerifierFor(format) — fails closed if format unconfigured
      verifier.VerifyChainAnchored(stmt, opts)   — chain structure + anchoring
      → enforceAttestationInvariants           (servicer_ca_attestpolicy.go:76)
          builds Evidence{Format, Leaf, SubjectSPKI, ExpectedChallenge}
          attestation.VerifyInvariants(ev)       — binding + challenge
      → (android-key-attestation only) verifyAndroidCSRAttestation — deployment policy

  → issue, or refuse with a typed error
```

The TCG-CSR-IDEVID path (`POST /api/v1/ca/tcg/sign-csr`, `SignTCGCSR`) calls
the same `VerifyInvariants` directly, without going through `pkg/xkms` or
`AttestationConfig` at all — it anchors EK trust separately, through
`MultiIdentityCAConfig.TCGConfig.TrustAnchors`
([`certificate-authority/engineering.md`](../certificate-authority/engineering.md)),
not through this feature's per-format `Verifier`s:

```
TCG-CSR-IDEVID arrives (packed TPM public areas + TPM2_Certify structure)
  → tpm2.VerifyTCG_CSR_IDevID_Stateless      — envelope signature (RSA-PSS/ECDSA)
  → attestation.VerifyInvariants(Evidence{Format: FormatTPM2, ...})  — binding only, no challenge
  → issue, or ca.ErrTCGCSRVerificationFailed
```

## Trust boundaries

- **Anchors are entirely operator-supplied**, per format. There is no
  auto-discovery, no vendor-root distribution, and no fallback to the system
  trust store — a format with no configured anchors is refused at the gate,
  twice over (`AttestationConfig.Verifiers` refuses an anchorless format at
  load time; `SetAttestationVerifiers` refuses one at wiring time even if a
  caller constructed a `Verifier` some other way).
- **A structurally valid chain is not, by itself, provenance.** `VerifyChain`
  says so explicitly in its own doc comment: with no anchors it validates
  structure only, "which proves nothing about hardware provenance because
  the whole chain is caller-supplied" (`verifier.go:156-160`).
  `VerifyChainAnchored` is the form that fails closed.
- **Binding is the check that matters most.** Anchoring establishes that
  *some* configured-vendor hardware exists; binding establishes that *this*
  hardware attested to *this* key. Skipping it is exactly the gap a public,
  replayable attestation chain would otherwise open.
- **Freshness is per-format, not universal.** A format with no challenge
  mechanism that is asked to carry one is refused (`ErrStaleEvidence`,
  `invariants.go:200-204`) — silently ignoring a caller-supplied challenge
  the format cannot check would let the caller believe freshness was
  verified when it was not.
- **The one policy knob is opt-in, narrow, and loud.**
  `AllowUnboundAttestationFormats` only widens `ErrBindingUnavailable`, never
  `ErrKeyNotBound` or `ErrStaleEvidence`, and every use is logged at `WARN`
  with the consequence stated in the log line.

## Rejected alternatives

- **Per-backend verification.** Rejected: TPM2 and PKCS#11 backends would
  each reimplement chain validation and binding, in slightly different ways,
  for the same CA-side decision. One verifier, format-pluggable invariants.
- **Stopping at chain anchoring.** Rejected: proves hardware provenance in
  general, not that the specific key was attested. `enforceAttestationInvariants`'s
  own comment calls key binding "the single most important check in the
  whole path" for exactly this reason (`servicer_ca_attestpolicy.go:31-35`).
- **A configurable invariant policy** (e.g., a flag to skip binding or
  freshness per deployment). Rejected — see "These are invariants, not
  policy," above. The one opt-in exists for a narrower case
  (`ErrBindingUnavailable`) and is logged every time.
- **A single verifier shared across every format.** Rejected: a Yubico
  anchor must never validate a TPM chain, or vice versa
  (`servicer_ca.go:303`). Verifiers are per-format, keyed and checked
  independently.

## Planned: reference-value replay

Not built yet; the SPEC.md row is `in progress`. Reference-value replay
predicts a PCR value for a new component image from a signed CoRIM, for
[tpm-policies](../tpm-policies/architecture.md#planned-unattended-unlock-across-updates)
branch updates.

- It applies TCG extend arithmetic, `PCR = H(PCR ‖ digest)`, generic over the
  bank (sha256, sha384).
- It replays an event log up to the replaced component's event, then extends
  the component digest taken from the signed CoRIM in its place.
- It extends `EventLog.Replay`
  (`pkg/attestation/evidence/eventlog.go:333`), which replays a whole log, and
  takes digests from `Manifest.PCRDigests`
  (`pkg/attestation/refvalue/refvalue.go:167`) after `VerifySigned`
  (`pkg/attestation/refvalue/refvalue.go:199`).

## What this feature deliberately does not do

- **It does not generate attestations.** `AttestKey` and
  `types.AttestingKeyProvider` are a key-provider capability, documented in
  [`key-management`](../key-management/), [`tpm2`](../tpm2/) and
  [`pkcs11-backend`](../pkcs11-backend/).
- **It does not decode Android's attestation extension itself** —
  `pkg/attestation/android.ParseKeyAttestation` does, and `invariants.go`
  calls it only to read the challenge field.
- **It does not implement the attested-peer quote-to-verdict primitive** —
  that is `pkg/attestation/peer`, a different verifier for a different
  question ("is the live TLS peer currently attested"), documented in
  [`attested-peer`](../attested-peer/).
- **It does not distribute or fetch trust anchors** — `pkg/attestation/truststore`
  loads what the operator configured (embedded well-known roots or local PEM
  files); nothing here walks AIA or ships vendor roots.
- **It does not expose a CLI or network verb of its own.** See
  [`cli.md`](cli.md) and [`api.md`](api.md).
