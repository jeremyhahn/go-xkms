# Init Ceremony — Architecture

> **Status: NORMATIVE** · Feature: `init-ceremony` · Repo: `go-xkms` · Last verified: 2026-09-23

## The problem

A brand-new KMS has no CA, no barrier, no officers and no way to authenticate
anyone. Every credential it will ever issue has to come from somewhere, and that
somewhere cannot itself require a credential. The init ceremony is that
bootstrap: it stands up the CA, the barrier and the first officers in one
auditable sequence, and it is designed so that no single participant ends up
holding everything.

## Shape chosen: go-qrdb runs the ceremony, go-xkms supplies the CA

go-qrdb owns the ceremony — the state machine, the officer model, the share
splitting, the persistence. go-xkms owns the CA. The join is one adapter:

```go
var _ qrdbsdk.CeremonyCA = (*CAAdapter)(nil)
func NewCAAdapter(xkmsCA CeremonyCA, trustDomain string) *CAAdapter
```

with a deliberately narrow local interface:

```go
// CeremonyCA is the subset of ca.TrustedCA the init ceremony depends on…
// Declaring the narrow dependency here instead of the full 76-method
// ca.TrustedCA keeps the ceremony's CA surface honest about what it
// actually calls.
type CeremonyCA interface {
	ca.CALifecycle   // Init, Load, IsInitialized
	ca.CAIssuer      // SignCSR, CreateCSR, IssueCertificate
	ca.CATrustChain  // CACertificate, CABundle, Verify, …
}
```

Three interfaces out of fifteen. That is the whole design statement: the
ceremony can issue certificates and read the trust chain, and it cannot revoke,
cross-sign, or touch attestation.

**xkmsd drives the ceremony, not firstboot.** go-xkms is a single-tenant KMS
with no RBAC user store, so the admin-user-plus-roles orchestration that
firstboot performs does not apply. `pkg/init/firstboot_adapter.go` exists for
the cases that need it; the default path is `xkmsd init` calling
`qrdbsdk.CeremonyService` directly.

Rejected alternatives:

- **Implementing a ceremony in go-xkms.** Rejected by ownership — the ceremony,
  the barrier, Shamir custody and firstboot are all go-qrdb's.
- **Passing the full `ca.TrustedCA` to the ceremony.** Rejected: a 76-method
  dependency hides what is actually used and makes every CA change a ceremony
  concern.
- **Issuing officer certificates out of band.** Rejected: the point of the
  ceremony is that the first credentials are issued under the same audited
  sequence as everything after them.

## The system-tenant exception

`ca_adapter.go` carries one deliberate exception, and it is worth understanding
before touching tenancy:

```go
const systemTenantID = "system"
```

The SO / bootstrap certificate is **always** scoped to the `system` tenant, and
when a SPIFFE trust domain is configured the adapter stamps
`spiffe://<td>/tenant/system/user/<CN>` onto it. The comment states why: *"the
SO cert explicitly carries tenant/system so the control plane works before any
tenant barrier unseals."*

This is the control-plane exception in the login tenant-derivation order. Every
other identity derives its tenant normally; the SO certificate cannot, because
at the moment it is issued there is no unsealed tenant to derive from.

## Component boundaries

| Piece | Where | Owner |
|---|---|---|
| Ceremony state machine, officers, share splitting | `go-qrdb/sdk/go` (`CeremonyService`) | **go-qrdb** |
| Ceremony types (`CeremonyState`, `OfficerConfig`, `CeremonyConfig`, `PendingCert`, `ChallengeResponse`, `InitResult`, `ClaimCertResult`, `ShareClaimResult`, `SignCSRInitResult`) | aliased in `pkg/init/ceremony.go` | **go-qrdb** |
| Threshold types (`ThresholdInitializer`, `ThresholdOptions`, `ThresholdStatus`, `NoopThresholdInitializer`) | aliased in `pkg/init/threshold*.go` | **go-qrdb** |
| CA bridge | `pkg/init/ca_adapter.go` | go-xkms |
| Transport adapter | `pkg/init/adapter.go` (`CeremonyAdapter` → `transport.InitCeremonyService`) | go-xkms |
| Admin factor enrollment | `pkg/init/admin_enrollment.go`, `admin_factors.go` | go-xkms |
| Firstboot bridge | `pkg/init/firstboot_adapter.go` | go-xkms |
| Threshold registry | `pkg/init/threshold_registry.go` | go-xkms |
| SPIFFE identity stamping | `pkg/spiffe` | go-xkms |
| Driver | `cmd/xkmsd/init_ceremony.go` | go-xkms |
| Durable node open (shared with `xkmsd run`) | `pkg/server` (`ResolveNodeSeal`, `EmbeddedNodeStorageConfig`, `OpenEmbeddedNode`) | go-xkms |
| First-boot bootstrap (shared with `xkmsd run`) | `pkg/server` (`RunFirstBoot`, `BuildFirstBootDependencies`) | go-xkms wiring, go-qrdb bootstrap |
| Admin-factor persister | `cmd/xkmsd/init_factor_persister.go` | go-xkms |

Capability row: **"Ceremony CA seam" (tier 2)** — interface go-qrdb, impl
go-xkms, composed via `WithCeremonyCA`.

## Data flow

```
operator:  xkmsd init
  → CA: Init (self-signed root, or CSR + intermediate)
  → barrier: initialize with the chosen strategy
  → officers: each submits a CSR
      → CAAdapter.SignCSR → SO/officer certificate, tenant=system, SPIFFE SAN
  → shares: split M-of-N, one per officer

single-admin mode only (ceremony reaches StateOperational):
  → durable node: OpenEmbeddedNode against the SAME Storage.Path / seal
      strategy `xkmsd run` will resolve from the same config
  → first-boot: RunFirstBoot (system tenant, roles, administrator + cert,
      cert bound to the user record) — idempotent, so `xkmsd run`'s own
      first-boot is a no-op afterward
  → admin factors: PreflightAdminFactors → EnrollAdminFactors
      (PIV / PKCS#11 / FIDO2 / mTLS, via pkg/factor), each factor persisted
      immediately through the durable node's user auth-factor store
  → node closed before `xkmsd init` exits, so `xkmsd run` can reopen the
      same Pebble directory

officer, remotely:
  xkmsctl init claim-cert  --username … --key … --spki-pin …
    → ClaimCertBegin / ClaimCertComplete   → officer certificate + CA bundle
  xkmsctl init claim-share --username … --cert … --key … --spki-pin …
    → ClaimShareBegin / ClaimShareComplete → that officer's share
```

Claiming is two-phase — begin, then complete — so the server can bind a
challenge to the claim and the officer proves possession of the key before
anything is released.

`--spki-pin` is **required** on both claim verbs. An officer claiming a
credential has, by definition, no CA bundle yet, so the connection is verified
by pin. See [`../trust-bootstrap/`](../trust-bootstrap/architecture.md).

## Trust boundaries

- **The ceremony is the root of every credential.** Anyone who can run it
  controls the deployment.
- **Officers prove key possession before receiving anything**, in both claim
  flows.
- **SPKI pinning is mandatory on the claim path.** There is no bundle to verify
  against yet.
- **The SO certificate is a control-plane credential** scoped to the `system`
  tenant, and works before any tenant barrier unseals — which is exactly what
  makes it powerful.
- **Shares go out one per officer.** The ceremony is the only moment they exist
  in one place; that is why it is a ceremony.
- **The role passed to `init sign-csr`** — `so`, `admin`, `operator`, `user`,
  `auditor`, `custodian` — determines the certificate's authority.

## Admin factors are persisted durably (single-admin mode)

On the single-admin path (the ceremony reaches `StateOperational`), `xkmsd
init` opens the SAME durable qrdb node `xkmsd run` will later reopen from the
same data directory (`pkg/server.OpenEmbeddedNode`, shared with
`(*server.Server).initEmbeddedQRDBNode` so the two opens can never disagree
about the database engine or the barrier/seal/encryption-at-rest
configuration — see `pkg/server.ResolveNodeSeal` /
`EmbeddedNodeStorageConfig`). It runs qrdb's canonical first-boot
(`pkg/server.RunFirstBoot`) against that node — system tenant, roles, the
administrator, and its CA-issued certificate, bound to the user record — and
then enrolls the planned admin login factors with a persister
(`cmd/xkmsd/init_factor_persister.go`) that writes each one through the same
node's user auth-factor store immediately after it enrolls. The node is
closed before `xkmsd init` exits. `(*server.Server).runFirstBoot` is
idempotent (a node whose administrator already exists is a no-op), so it
stays a safety net for a deployment that runs `xkmsd run` directly without
`xkmsd init` first, rather than a second bootstrap.

M-of-N mode does not reach this path: there is no single administrator at
ceremony time, only officers, so no admin factors are enrolled and nothing
about M-of-N durability changes here.

Splitting and distributing the qrdb node's OWN barrier Shamir quorum (as
opposed to the ceremony's own officer/share distribution, which this feature
already implements) is not yet wired into `xkmsd init`: it refuses with a
typed error (`ErrNodeShamirUnsupported`) rather than silently leaving the
node sealed. `none`, `passphrase` and `tpm2` are fully supported.

## What this feature deliberately does not do

- **It does not own the ceremony, the barrier, Shamir custody, firstboot or the
  identity model.** All go-qrdb's.
- **It does not run RBAC orchestration.** Single-tenant KMS, no RBAC user store.
- **It does not drive the qrdb node barrier's own Shamir split** — see above.
- **It does not replace ACME.** The ceremony issues the *first* credentials;
  routine issuance is [`../acme-issuance/`](../acme-issuance/architecture.md).
