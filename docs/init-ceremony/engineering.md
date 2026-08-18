# Init Ceremony — Engineering Contract

> **Status: NORMATIVE** · Feature: `init-ceremony` · Repo: `go-xkms` · Last verified: 2026-08-19

## Exported surface — `pkg/init`

### The CA bridge (`ca_adapter.go`)

```go
var _ qrdbsdk.CeremonyCA = (*CAAdapter)(nil)

const systemTenantID = "system"

// The subset of ca.TrustedCA the ceremony depends on.
type CeremonyCA interface {
	ca.CALifecycle
	ca.CAIssuer
	ca.CATrustChain
}

type CAAdapter struct {
	ca                CeremonyCA
	spiffeTrustDomain string
}
func NewCAAdapter(xkmsCA CeremonyCA, trustDomain string) *CAAdapter
```

Three of `ca.TrustedCA`'s fifteen sub-interfaces. The source states the rule:
declaring the narrow dependency here *"keeps the ceremony's CA surface honest
about what it actually calls."* Widening it is a design change, not a
convenience.

`spiffeTrustDomain`, when non-empty, stamps
`spiffe://<td>/tenant/system/user/<CN>` onto SO/bootstrap certificates.

### The transport bridge (`adapter.go`)

```go
type CeremonyAdapter struct{ cs *CeremonyService }
func NewCeremonyAdapter(cs *CeremonyService) *CeremonyAdapter
```

Implements `transport.InitCeremonyService`, converting `CeremonyService` types
to transport types at the boundary.

### Admin factor enrollment

```go
type AdminEnrollmentConfig struct{ … }
type AdminEnrollmentContext struct{ … }

func NewAdminEnrollmentParams(ec AdminEnrollmentContext) qrdbsdk.AdminEnrollmentParams
func NewAdminFactorRegistry(cfg AdminEnrollmentConfig) (*qrdbsdk.AuthFactorRegistry, *xkmsfido2.LocalCeremony, error)
func PreflightAdminFactors(ctx context.Context, cfg AdminEnrollmentConfig) error
func EnrollAdminFactors(…)
```

`PreflightAdminFactors` runs first so a missing authenticator is discovered
before the ceremony commits anything.

### Aliased types — all go-qrdb's

`ceremony.go`: `CeremonyState`, `OfficerConfig`, `CeremonyConfig`,
`PendingCert`, `ChallengeResponse`, `InitResult`, `ClaimCertResult`,
`ShareClaimResult`, `SignCSRInitResult`.

`threshold.go` / `threshold_noop.go`: `ThresholdInitializer`,
`ThresholdOptions`, `ThresholdStatus`, `NoopThresholdInitializer`,
`NewNoopThresholdInitializer()`. Registry: `threshold_registry.go`.

`errors.go` aliases the ceremony error types — `ShamirSplitError`,
`CSRParseError`, `CertEncodeError`, `ShareStoreError`, `CABundleError`,
`SPKIPinError` — and adds two of its own: `RandomSourceError`,
`AdminKeyGenerationError`.

## Invariants

- **The ceremony runs once.** A second `init` against an initialized deployment
  fails rather than re-rooting it.
- **The CA surface stays narrow.** Three sub-interfaces. Needing a fourth is a
  design conversation, not an import.
- **The SO certificate is always `system`-tenant scoped.** It has to work before
  any tenant barrier unseals; that is the control-plane exception in the login
  tenant-derivation order.
- **Claims are two-phase.** `ClaimCertBegin`/`Complete` and
  `ClaimShareBegin`/`Complete` — the officer proves key possession against a
  server challenge before anything is released.
- **SPKI pinning is required on the claim path.** The officer has no CA bundle
  yet, so there is nothing else to verify against.
- **Preflight before enroll.** `PreflightAdminFactors` fails early rather than
  half-way through a ceremony.
- **`RandomSourceError` is fatal.** A ceremony that cannot get good randomness
  must abort, not proceed with weak material.
- **Shares are emitted once.** No API returns a share after the ceremony.

## Known gap: the factor persister is nil

`cmd/xkmsd/init_ceremony.go:403`:

```go
// TODO(P1): supply the factor persister once xkmsd init runs on the
// durable qrdb-backed store. A nil persister preserves today's
// behaviour exactly -- factors enroll and are reported but not stored
// -- rather than silently appearing to persist.
Persister: nil,
```

Admin factors enrolled during the ceremony are enrolled and reported, and **not
stored**. The nil is deliberate: a non-nil placeholder would look like it
persisted. Anyone relying on ceremony-time factor enrollment surviving a restart
is relying on something that does not happen today.

## Error semantics

Ceremony error types are go-qrdb's, aliased in `pkg/init/errors.go`:
`ShamirSplitError`, `CSRParseError`, `CertEncodeError`, `ShareStoreError`,
`CABundleError`, `SPKIPinError`. Locally defined: `RandomSourceError`,
`AdminKeyGenerationError`.

**Fail closed:** a CA that will not initialize, an unparseable CSR, a failed
Shamir split, a share store that will not accept a share, an SPKI pin mismatch,
a bad random source, or a failed admin key generation all abort the ceremony.
There is no partially-initialized success state.

## Configuration

Ceremony configuration is `CeremonyConfig` and `OfficerConfig` (go-qrdb's),
supplied by `xkmsd init`. The go-xkms-side inputs:

- **The CA** — a `CeremonyCA`, i.e. a configured `ca.TrustedCA`.
- **`spiffeTrustDomain`** — empty disables SPIFFE SAN stamping; non-empty stamps
  `spiffe://<td>/tenant/system/user/<CN>` on SO certificates.
- **`AdminEnrollmentConfig`** — which factors to enroll, relying-party identity,
  passkey device and PIN, FIDO2 handler.
- **Threshold** — `ThresholdOptions`, or `NoopThresholdInitializer` where
  threshold initialization does not apply.

Roles accepted by `init sign-csr`: `so`, `admin`, `operator`, `user`,
`auditor`, `custodian`.

## Persistence

Ceremony state, officers, pending certificates and shares are persisted by
**go-qrdb**. go-xkms persists the CA's own material through the keystore and
certificate store. Admin factors are **not** persisted — see the gap above.

## Test strategy

- **Unit** — `pkg/init/ceremony_test.go`, `admin_enrollment_test.go`,
  `admin_factors_test.go`, `firstboot_adapter_test.go`, `threshold_test.go`,
  `coverage_boost_test.go`.
- **End to end** — `pkg/api/rest/init_ceremony_e2e_test.go`,
  `init_public_derivation_test.go`; `pkg/api/mcp/init_public_test.go`,
  `init_public_derivation_test.go`.
- **Route gating** — `pkg/api/{grpc,unix}/initgate_guard_test.go`,
  `pkg/api/initgate`.
- **Integration** — `test/integration/bootstrap`, `test/integration/logins`.

The public-derivation suites exist on both REST and MCP because the init routes
are reachable before authentication; they assert the derivation is identical on
both.

## Observability

Ceremony steps are audited through go-qrdb's ceremony service. The events that
matter in a later investigation are: which officers claimed, when, from where,
and which roles were issued. Correlation IDs propagate from the transport
middleware, and the CA's own issuance audit ([`../certificate-authority/`](../certificate-authority/engineering.md))
records every certificate the ceremony produced.
