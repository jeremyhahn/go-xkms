# Certificate Authority — Architecture

> **Status: NORMATIVE** · Feature: `certificate-authority` · Repo: `go-xkms` · Last verified: 2026-10-12

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
| The one signing seam every issuance path uses (`Issuer`, `CertificateSpec`) | `pkg/ca/issuance.go` | go-xkms |
| Certificate profiles (KU, EKU, basic constraints) | `pkg/ca/profiles.go`, `profile_*.go` | go-xkms |
| Cross-signing | `pkg/ca/cross_signing.go` | go-xkms |
| Hybrid / PQ certificate paths | `pkg/ca/hybrid.go` | go-xkms |
| TPM attestation import and verification | `pkg/ca/attestation.go` | go-xkms |
| TCG EK/AK enrollment | `CATCGEnrollment` in `pkg/ca` | go-xkms |
| Certificate store — certificate and chain entities on a go-qrdb DAO, in the CA's `ca` database | `pkg/certstore` | go-xkms |
| Signing keys | `pkg/xkms` keystore — see [`../crypto-backends/`](../crypto-backends/architecture.md) | go-xkms |
| Certificate records (DAO, database, node) | `go-qrdb/sdk/go` | **go-qrdb** |
| Ceremony that drives first CA creation | go-qrdb's ceremony; `pkg/init` `CAAdapter` bridges `TrustedCA` → qrdb's `CeremonyCA` | **go-qrdb** owns the seam |
| `TrustedCA` as go-qrdb's cluster CA (Key A), signing through its `crypto.Signer` with no CA key bytes (go-xkms#1381) | `clusterca.KeyProvider` (`pkg/trust/clusterca/keyprovider.go`), passed via `qrdbnode.WithClusterCAKeyProvider` — see [`../clustering/engineering.md`](../clustering/engineering.md) | **go-qrdb** owns the seam; go-xkms supplies the CA |
| ACME RFC 8555 on top of this CA | `pkg/acme` — see [`../acme-issuance/`](../acme-issuance/architecture.md) | go-xkms |

This is capability row **"`TrustedCA`, ACME RFC-8555, DANE, AIA, cross-sign"
(tier 1)**. ACME is documented in its own folder because it is a protocol
surface with its own client, server, transports and challenge types. AIA is
here. DANE is not part of `TrustedCA`: TLSA records are built and handed to an
application-supplied publisher by `pkg/trust/dane`, documented with
[`../trust-bootstrap/`](../trust-bootstrap/architecture.md).

Issuance has a single signing point. Callers own the certificate's contents
(serial, subject, names, validity) in a `CertificateSpec`; the profile owns
its policy (key usage, EKU, basic constraints); `Issuer.Sign` is the only
place in `pkg/ca` that calls `x509.CreateCertificate`. A profile change
therefore reaches every path at once, and the `TestCertificatePolicy_*`
suites fail if a path bypasses the seam. Details are in
[`engineering.md`](engineering.md) §Canonical issuance.

## Data flow

Issuance:

```
CSR (PEM)
  → POST /api/v1/ca/sign-csr        (session-authenticated, hasCA-gated)
    → TrustedCA.SignCSR(ctx, csrPEM, opts)
      → policy + extension construction (pkg/ca/ca_extensions.go, certpolicy)
        → CASigningIdentity.Signer(ctx)      — a crypto.Signer from the keystore
          → the backend signs; the private key never leaves the device
      → certstore persists the certificate entity (qrdb DAO); serial recorded
    ← *x509.Certificate
```

Revocation writes a revocation record; `GenerateCRL` renders the current set;
`IsRevoked(serial)` answers from it. `CAChainImporter.ImportDistributionCRLs`
pulls CRLs named by a certificate's distribution points, and
`ImportIssuingCAs` walks AIA to fetch and store issuers — that is the AIA half
of the capability row.

### Replicated revocation state and CRL artifact (#275)

A clustered deployment (go-xkms embedding a qrdb node in Raft mode) needs any
instance to be able to answer a revocation check, serve OCSP, or serve a CRL —
without spreading the CA signing key to every node. The design splits state,
signing and serving:

| concern | where | why |
|---|---|---|
| revocation state (serial, reason, revokedAt) | `ca.revocationStore` (`storage.Backend`, backed by qrdb) | Raft replicates it; every instance reads the same facts |
| CRL **signing** | go-xkms only, wherever the CA key lives | a CRL must be signed by the CA key; signing it in the storage layer would put the key on every qrdb node |
| signed CRL **bytes** | a sibling row in the same store, `crl/<issuer-ski-hex>` | a published artifact, replicated like any other value — not regenerated by every reader |
| CRL / OCSP **serving** | any go-xkms instance | a stateless read of replicated bytes / replicated state |

`pkg/ca/crl_persistence.go` is the CRL half. `CA.CRL(ctx)` is the read path:
it returns the persisted DER, regenerating and persisting first only when
none exists yet or the published `NextUpdate` has passed. `GenerateCRL`
remains the explicit force-refresh verb — it always signs a new CRL, even
when a valid one is already published, which is what `POST /ca/crl` calls.
`recordRevocation` (shared by `Revoke` and `RevokeCert`, so every revocation
entry point is covered) also refreshes the CRL as a best-effort side effect,
so a client rarely observes the staleness window in practice; when that
refresh fails the revocation itself has already durably recorded (writes are
ordered so the state enforcement reads lands first), and the next stale read
repairs the CRL.

There is deliberately **no leader election and no background scheduler**
(owner ruling, #275, option A). A CRL was never a live query — it is a
document with `thisUpdate`/`nextUpdate` — so "regenerate on write, detect
and repair staleness on read" needs no cluster awareness the CA layer does
not already have, and is correct on a single node with no configuration
change.

`certstore.compositeCertStore`'s `StoreCRL`/`GetCRL` are kept, not removed:
they are the in-memory hot-path cache `CA.CRL` checks first, warmed by every
call on that instance that (re)generates a CRL. They are not a second source
of truth — the persisted artifact in `revocationStore` is, and
every path that bypasses the cache (a miss, or a different instance) reads
that.

A fourth sibling row shares the same rationale: `issued-keys/<serial>`
(`pkg/ca/ca_extensions.go`, go-xkms#751) records the exact `KeyAttributes` a
server-side key generation used, written by whichever node issued the
certificate. `RevokeCert`'s `DeleteKeys` option can be served by any
instance, so that record has to be replicated state in `revocationStore`
like the revocation record itself, not something held only in the memory of
the node that issued the certificate.

Every revocation reader goes through one read path, and every one of them
fails closed (go-xkms#1116):

- **Single serial** — `CA.lookupRevocation` (`pkg/ca/ca_extensions.go:856`)
  checks this instance's in-memory map, then reads through to
  `revocationStore`. `IsRevoked` (`pkg/ca/ca.go:2152`) — and so `Verify`
  (`pkg/ca/ca.go:2030`) and `VerifyPeerCertificate` (`pkg/ca/tls.go:502`,
  `:538`) — and the OCSP responder's `checkCertificateStatus`
  (`pkg/ca/ocsp.go:231`) all call it. Before #1116 only OCSP read through;
  `IsRevoked` answered from the map alone, which is filled at `Load` and by
  this instance's own revocations, so a certificate revoked on node A still
  passed `Verify` on node B.
- **Full set** — `CA.loadPersistedRevocations`
  (`pkg/ca/ca_extensions.go:888`) scans every record in `revocationStore`
  into the map. `Load` runs it at startup (`pkg/ca/ca.go:914`), and
  `generateAndPersistCRL` runs it before building a CRL
  (`pkg/ca/crl_persistence.go:179`). Before #1116 CRL generation built from
  the map alone, so node B's regenerated CRL overwrote the shared
  `crl/<ski>` artifact without node A's revocations.

A store hit on the single-serial path is cached in the map; a miss never is.
Revocation is permanent here — there is no un-revoke or certificate-hold
release — so a cached hit cannot go stale, while a cached miss would hide the
next revocation any other node records. Fail closed means: only a definite
`storage.ErrNotFound` reads as "not revoked". A store fault, a corrupt record,
a listing failure, or an unreadable previous CRL number is an error that
refuses the verification, the OCSP answer (`ocsp.Unknown`), the CRL, or the
`Load` — never a silent un-revoke and never a CRL number that goes backwards.

`IsRevoked` keeps its context-free signature (it is part of `TrustedCA` and
`provider.CA`), so its read-through runs under `context.Background()`.

Trust distribution has a deliberately **public** route:
`GET /v1/ca/bootstrap` is `RouteAuthPublic` under `GroupRoot`, because a client
that has no trust yet cannot authenticate to get it. It is safe because the
bundle is public information and the client verifies it out of band — DANE,
SPKI pin, or Noise. See [`../trust-bootstrap/`](../trust-bootstrap/architecture.md).

### CA reload across restarts: `Load` before `Init` (go-xkms#793)

`pkg/server`'s `initializeCA` never assumes a data directory is new: it
always calls `TrustedCA.Load` first and falls through to `Init` only when
`Load` reports `errors.Is(err, ca.ErrCertificateNotFound)` — the certificate
record genuinely does not exist under this CN. Any other `Load` failure
(a corrupt or unreadable persisted certificate, an unavailable keystore
backend) fails server startup closed rather than treating damaged existing
state as "never initialized" and silently forging a new root over it. This
is the boot-time complement to the CRL/revocation replication design above:
just as a stale CRL is repaired by regenerating from the persisted
revocation state rather than assumed absent, a CA that fails to `Load` is
assumed damaged, not absent, unless the specific evidence (no certificate
record at all) says otherwise.

The design puts one obligation on `Load` itself: it must resolve an
identity's key attributes exactly the way `Init` did when it wrote that
identity's key, or the two can disagree over the identical persisted state.
`Init` and `Load` share `getCAKeyAttributes` for this reason — see
[`engineering.md`](engineering.md) for the persistence contract this
enforces.

## Overlay identity: caller-named profiles under name-constrained subordinates

Two profiles certify keys for overlay identity rather than for a
requester-chosen name:

| Profile | Certifies | Names | Lifetime |
|---|---|---|---|
| `ipsec-vtep` | an IKEv2 tunnel endpoint (RFC 4945, RFC 7296) | at least one IP address; DNS allowed | 30 days default, 90 days max |
| `x509-svid` | a SPIFFE X.509-SVID leaf | exactly one SPIFFE ID URI; DNS allowed | 1 hour default, 24 hours max |

**The names come from the issuing caller, never from the CSR.** Both profiles
implement `CallerSANProfile`. Under one, `SignCSR` ignores the CSR's subject
and names. The CSR proves possession of the key and contributes nothing
else. The names arrive on `SignOptions.SANS` and the subject on
`SignOptions.Subject`. The caller is the party that knows the truth: the IPAM
reservation for a tunnel endpoint, the placement for a workload. A requester
who could name itself would be issuing to itself. The tenant SPIFFE synthesis
options are refused under these profiles, because they would add a name the
caller did not supply.

**Each is issued under a dedicated, name-constrained subordinate.**
`(*CA).IssueSubordinateCA` certifies a caller-held key as a CA with an RFC 5280
name constraints extension:

- the tunnel subordinate is confined to the fabric's IPv4 and IPv6 ranges;
- the SPIFFE subordinate is confined to one trust domain.

The subordinate signs through `SignOptions.Signer` and `IssuerCert`, so its key
stays in the keystore, TPM or HSM the caller chose. A compromised tunnel
subordinate can then certify only addresses inside the fabric, and a
compromised SPIFFE subordinate only identities inside its trust domain. A
relying party enforces both during path validation.

**URI constraints bind the trust domain, not the path.** RFC 5280 §4.2.1.10
constrains a URI by its host only. For a SPIFFE ID that host is the trust
domain, so no X.509 constraint can confine a subordinate to
`spiffe://<td>/tenant/<t>/`. Path scoping belongs to the issuing caller, which
checks the requested ID before it asks for a certificate
(`spiffe.WorkloadID.HasPathPrefix`). This is a property of the standard, not a
gap in this implementation.

**The CA refuses what path validation would reject.** Before signing any
certificate, under any profile, `Issuer.Template` checks the leaf's IP, DNS,
URI and email names against the issuing certificate's name constraints and
refuses a violation (`ErrNameConstraintViolation`). The CA therefore never
mints a certificate that every conforming relying party would reject.

**Attestation evidence is the caller's statement, carried in the certificate.**
An `ipsec-vtep` certificate may carry the private, non-critical
`tp-attestationEvidence` extension: the verifier's verdict ID, a PCR digest and
the appraisal time. The CA does not appraise anything. It encodes what the
issuing caller (the relying party that admitted the endpoint) supplies, and it
validates the encoding. Because CSR extensions are never copied, a requester
cannot inject its own evidence.

## SPIFFE identities

`pkg/spiffe` is the one place SPIFFE IDs are built and checked, re-exported as
`sdk/go/spiffe`. It has two shapes. The tenant-scoped identity
`spiffe://<td>/tenant/<t>/<kind>/<name>` (`ID`, `BuildURI`, `ParseID`,
`TenantFromURIs`) is what the CA stamps on broker-issued certificates and what
mTLS login reads back. The general builder and validator (`TrustDomain`,
`WorkloadID`) accepts any trust domain and path the SPIFFE-ID specification
allows, and nothing else. The `x509-svid` profile validates its URI SAN with
it, and an issuing caller scopes a subordinate's paths with
`WorkloadID.HasPathPrefix`, because the X.509 URI constraint binds only the
trust domain. The package is a leaf with no go-xkms imports.

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
- **A TCG DevID enrollment proves both TPM residency and TPM provenance.**
  The stateless verifier establishes that the IDevID and IAK are Template H-0
  keys in one TPM, and that the IAK certified the IDevID; `verifyEKCertificateChain`
  (`pkg/ca/tcg_ek_trust.go`) separately verifies the endorsement key
  certificate against the CA's configured TPM-manufacturer trust anchors, per
  TPM 2.0 Keys for Device Identity and Attestation v1.10r9 §6.1.2 step 5b and
  §6.2.2 step 4b, before either check's result is trusted enough to issue
  from. **A CA with no anchors configured refuses every EK certificate**
  (`ErrTCGEKCertUntrusted`) rather than falling back to residency-only proof
  -- there is no permissive default a device can rely on by supplying its own
  EK certificate.
- **AIA and CRL distribution point URLs are attacker-directed.** Whoever
  issued a certificate chose them, so `ImportIssuingCAs` and
  `ImportDistributionCRLs` fetch through one bounded path, `fetchPKIObject`
  (`pkg/ca/pki_fetch.go:112`). It fetches only http and https URLs
  (`checkFetchURL`, `pki_fetch.go:86`). Its client is built by
  `pkg/netguard.GuardedTransport` (`pki_fetch.go:63-81`), the same guarded
  dialer the ACME challenge-validation client uses (see
  [`../acme-issuance/architecture.md`](../acme-issuance/architecture.md)):
  the dialer's `Control` hook refuses every `netguard.ReservedAddr` address
  after DNS resolution, so a rebinding hostname or a redirect cannot reach
  loopback, private, link-local (including cloud metadata), CGNAT, the
  TEST-NETs, NAT64, 6to4 or the other special-purpose ranges. Bodies are
  capped at 64 KiB for a certificate and 32 MiB for a CRL
  (`netguard.ReadLimited`, `pki_fetch.go:137`). The AIA walk also verifies
  that each fetched certificate signed the certificate that named it
  (`trust_chain_extensions.go:314`), ends on a repeated certificate
  (`:310`), and refuses a walk more than five issuers deep (`:295`), so an
  AIA URL can neither plant an unrelated certificate in the store nor loop
  forever.
- **Multi-keystore CAs** (`pkg/ca/multi_keystore*.go`) let one CA identity hold
  parallel keys of different algorithms in different backends. Each is a
  distinct trust root even though they share a name — `CABundleFiltered(storeType, keyAlgorithm)`
  exists so a relying party gets the chain it can actually verify.

## What this feature deliberately does not do

- **No ACME here.** Protocol handling, challenges, orders, nonces and accounts
  are [`../acme-issuance/`](../acme-issuance/architecture.md).
- **It does not own the ceremony.** First-boot CA creation runs inside go-qrdb's
  ceremony through the `CeremonyCA` seam; go-xkms supplies the adapter, not the
  orchestration. See [`../init-ceremony/`](../init-ceremony/architecture.md).
- **It does not own identity, users or RBAC.** Those are go-qrdb's. Certificates
  bind *to* identities the CA does not define.
- **It is not a public web PKI CA.** No CT log submission, no CAA enforcement
  in the current tree; the ACME roadmap tracks those. An RFC 6960 OCSP
  responder does exist (`pkg/ca/ocsp.go`, `NewOCSPResponder`) — it answers
  from the same revocation state the CRL renders, described above — and
  `pkg/acme/server/handlers/ocsp.go`'s `OCSPHandler` adapts it to
  `net/http`, but no route registers that handler today; a caller mounts it
  or feeds the responder DER-encoded requests directly.
- **It does not distribute vendor roots or walk AIA for EK issuers.** It
  anchors EK certificates against the operator-configured
  `TCGConfig.TrustAnchors` (`pkg/attestation/truststore.Config`) -- see
  "Trust boundaries" above -- but does not ship, fetch, or auto-discover a
  TPM manufacturer's root; the operator supplies it, the same way
  `pkg/config.AttestationConfig` requires an operator-supplied trust store
  per attestation format.
