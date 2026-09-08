# Certificate Authority — Architecture

> **Status: NORMATIVE** · Feature: `certificate-authority` · Repo: `go-xkms` · Last verified: 2026-09-08

## The problem

A trusted-computing stack needs its own CA, and it needs one whose signing key
lives in the same hardware everything else in the stack lives in. Bolting a
general-purpose CA onto a KMS gives you two key stores, two trust models, and a
private key that has to be handed from one to the other. `TrustedCA` exists so
the CA's signing identity *is* a key in the keystore: a TPM key, a PKCS#11 key,
a cloud KMS key, chosen the same way any other key is.

## Shape chosen: `TrustedCA` as a `crypto.Signer` over the keystore

`pkg/ca/interface.go:107` defines `TrustedCA`, and its first line is the whole
design:

```go
type TrustedCA interface {
	crypto.Signer

	CALifecycle
	CAIssuer
	CATrustChain
	CARevoker
	CATLSConfig
	CATrustPools
	CAStores
	CAIdentityInfo
	CASigningIdentity
	CACertificateAccessor
	CAObjectStore
	CAChainImporter
	CACrossSigner
	CAAttestation
	CATCGEnrollment
}
```

Fifteen small interfaces composed into one, rather than one flat forty-method
interface. Each is independently implementable and independently mockable, and
`CAStores` makes the coupling explicit: `KeyStore() xkms.Backend` and
`CertStore() certstore.CertStore`. The CA does not own key storage — it borrows
the keystore.

Rejected alternatives:

- **Wrapping an existing CA product (step-ca, Boulder) behind an adapter.**
  Rejected because the signing key would live in that product's store, which
  defeats the point; the comparison work is retained as
  `docs/acme/boulder-comparison-enhancements.md` for the ACME half.
- **One flat `CA` interface.** Rejected: every consumer would depend on
  attestation, cross-signing and TCG enrollment to get `SignCSR`.
- **Making the CA a separate service.** Rejected for the default deployment —
  the CA and the KMS share a keystore, a barrier and a tenant model, and
  splitting them means synchronising all three across a network.

## Component boundaries

| Piece | Package | Owner |
|---|---|---|
| `TrustedCA`, issuance, revocation, CRL, chains | `pkg/ca` | go-xkms |
| Cross-signing | `pkg/ca/cross_signing.go` | go-xkms |
| Hybrid / PQ certificate paths | `pkg/ca/hybrid.go` | go-xkms |
| TPM attestation import and verification | `pkg/ca/attestation.go` | go-xkms |
| TCG EK/AK enrollment | `CATCGEnrollment` in `pkg/ca` | go-xkms |
| Certificate storage adapter | `pkg/certstore` | go-xkms |
| Signing keys | `pkg/xkms` keystore — see [`../crypto-backends/`](../crypto-backends/architecture.md) | go-xkms |
| Certificate and serial blobs | go-objstore | **go-objstore** |
| Ceremony that drives first CA creation | go-qrdb's ceremony; `pkg/init` `CAAdapter` bridges `TrustedCA` → qrdb's `CeremonyCA` | **go-qrdb** owns the seam |
| ACME RFC 8555 on top of this CA | `pkg/acme` — see [`../acme/`](../acme/architecture.md) | go-xkms |

This is capability row **"`TrustedCA`, ACME RFC-8555, DANE, AIA, cross-sign"
(tier 1)**. ACME is documented in its own folder because it is a protocol
surface with its own client, server, transports and challenge types; DANE and
AIA are here.

## Data flow

Issuance:

```
CSR (PEM)
  → POST /api/v1/ca/sign-csr        (session-authenticated, hasCA-gated)
    → TrustedCA.SignCSR(ctx, csrPEM, opts)
      → policy + extension construction (pkg/ca/ca_extensions.go, certpolicy)
        → CASigningIdentity.Signer(ctx)      — a crypto.Signer from the keystore
          → the backend signs; the private key never leaves the device
      → certstore persists the certificate; serial recorded
    ← *x509.Certificate
```

Revocation writes a revocation record; `GenerateCRL` renders the current set;
`IsRevoked(serial)` answers from it. `CAChainImporter.ImportDistributionCRLs`
pulls CRLs named by a certificate's distribution points, and
`ImportIssuingCAs` walks AIA to fetch and store issuers — that is the AIA half
of the capability row.

Trust distribution has a deliberately **public** route:
`GET /v1/ca/bootstrap` is `RouteAuthPublic` under `GroupRoot`, because a client
that has no trust yet cannot authenticate to get it. It is safe because the
bundle is public information and the client verifies it out of band — DANE,
SPKI pin, or Noise. See [`../trust-bootstrap/`](../trust-bootstrap/architecture.md).

## Trust boundaries

- **The CA signing key is a keystore key.** Its protection is the backend's
  protection. A CA on the software backend is exactly as strong as the barrier;
  a CA on a TPM or HSM is as strong as the device.
- **`GET /v1/ca/bootstrap` is unauthenticated by design.** It serves only the
  public bundle. Never add anything private to that route.
- **Cross-signed material is stored per issuer CN** (`ImportXSignedCertificate(issuerCN, cert)`)
  so a bundle can be assembled for a specific relying party without implying
  that every issuer is trusted.
- **Attestation import is not attestation trust.** `ImportAttestation*` stores
  evidence; `VerifyAttestationQuote` is the check. Storing is not verifying.
- **A TCG DevID enrollment proves TPM residency, not TPM provenance.** The
  stateless verifier establishes that the IDevID and IAK are Template H-0 keys
  in one TPM, and that the IAK certified the IDevID. It does not verify the
  endorsement key certificate against the manufacturer's roots, which TCG
  DevID v1 r12 §6.2.2 step 7b calls for; nothing in this repository does. Until
  a manufacturer truststore exists, a device that supplies its own EK
  certificate is trusted to name its own TPM, and the hardwareModuleName in
  the issued certificate inherits that limit.
- **Multi-keystore CAs** (`pkg/ca/multi_keystore*.go`) let one CA identity hold
  parallel keys of different algorithms in different backends. Each is a
  distinct trust root even though they share a name — `CABundleFiltered(storeType, keyAlgorithm)`
  exists so a relying party gets the chain it can actually verify.

## What this feature deliberately does not do

- **No ACME here.** Protocol handling, challenges, orders, nonces and accounts
  are [`../acme/`](../acme/architecture.md).
- **It does not own the ceremony.** First-boot CA creation runs inside go-qrdb's
  ceremony through the `CeremonyCA` seam; go-xkms supplies the adapter, not the
  orchestration. See [`../init-ceremony/`](../init-ceremony/architecture.md).
- **It does not own identity, users or RBAC.** Those are go-qrdb's. Certificates
  bind *to* identities the CA does not define.
- **It is not a public web PKI CA.** No CT log submission, no OCSP responder,
  no CAA enforcement in the current tree; the ACME roadmap tracks those.
- **It does not anchor endorsement key certificates.** No manufacturer
  truststore, no vendor root distribution, no AIA walk for EK issuers. Adding
  one is an architecture decision about where manufacturer roots come from and
  what an unanchored enrollment should do, not a local change to the CSR path.
