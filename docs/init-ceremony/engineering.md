# Init Ceremony — Engineering Contract

> **Status: NORMATIVE** · Feature: `init-ceremony` · Repo: `go-xkms` · Last verified: 2026-09-23

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

**Hardware seams.** `AdminEnrollmentConfig` carries one field per hardware
driver the console process can attach:

| Field | Factor | Nil / unset behaviour |
|---|---|---|
| `FIDO2Handler *pkgfido2.FIDO2Handler` | `fido2` | Default fido2 factor stays registered; the browser path still works |
| `PIVGenerator xkms.PIVKeyGenerator` | `piv` | Planned `piv` **fails preflight** and `Enroll` refuses |
| `AllowSoftwarePIV bool` | `piv` | Opts a software-only deployment into a software-backed admin PIV credential |

PIV is fail-closed here, unlike the `pkg/factor` library default. An operator
who ran `--admin-factor piv` holding a smartcard and got a software key would
have no way to tell: the enrollment succeeds, is recorded identically, and is
usable. So with no generator attached the registered `piv` factor reports
`piv.NoGeneratorReason` at preflight and returns
`*piv.GeneratorUnattachedError` from `Enroll`. Software PIV stays reachable —
by naming `AllowSoftwarePIV`, never by omission.

`xkmsd init` attaches no PIV generator today, so `xkmsd init --admin-factor
piv` refuses. That is the intended outcome until a card driver is wired: before
this change it silently enrolled software.

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

## Admin factors are persisted (single-admin mode)

On the single-admin path (the ceremony reaches `StateOperational`),
`executeCeremony` (`cmd/xkmsd/init_ceremony.go`) calls `bootstrapDurableAdmin`,
which:

1. Opens the durable qrdb node via `pkg/server.OpenEmbeddedNode`, resolving an
   identical storage+seal shape to the one `xkmsd run` will resolve from the
   same config (`pkg/server.ResolveNodeSeal` / `EmbeddedNodeStorageConfig`).
2. Completes the node's own barrier when the resolved strategy leaves it
   sealed (`unsealDurableInitNode`): `none` and a provisioned `tpm2`
   auto-unseal at construction; `passphrase` is completed directly with
   `--so-pin`, since `xkmsd init` IS the operator-present ceremony. `shamir`
   is refused with the typed `ErrNodeShamirUnsupported` — see Known
   limitations.
3. Runs qrdb's canonical first-boot against that node
   (`pkg/server.RunFirstBoot`) — the same sequence
   `(*server.Server).runFirstBoot` runs, factored out into
   `BuildFirstBootDependencies` so both callers wire identical dependencies,
   including a `CertBinder` that pins the issued admin certificate's SPKI
   thumbprint to the user record.
4. Resolves the administrator's numeric userID
   (`Client.Users().GetUserByCertThumbprint`) and builds a persister
   (`cmd/xkmsd/init_factor_persister.go`) over the SAME node's
   `Client.UserAuthFactors()`.
5. Enrolls the planned admin login factors (`EnrollAdminFactors`), which calls
   the persister once per factor immediately after it enrolls — so a failure
   partway through leaves the earlier factors both enrolled and persisted,
   never enrolled and lost.
6. Closes the node before returning, success or failure, so `xkmsd run` can
   reopen the same Pebble directory afterward.

`(*server.Server).runFirstBoot` stays idempotent (a node whose administrator
already exists is a no-op) and remains the safety net for a deployment that
runs `xkmsd run` directly without `xkmsd init` first.

### Known limitations

- **The qrdb node barrier's own Shamir split is not yet wired.** `xkmsd init`
  refuses with `ErrNodeShamirUnsupported` rather than attempt an unseal that
  cannot complete with a single credential. `none`, `passphrase` and `tpm2`
  are fully supported.
- **M-of-N mode is unaffected.** There is no single administrator at ceremony
  time in M-of-N mode, so `bootstrapDurableAdmin` never runs there.

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
  passkey device and PIN, FIDO2 handler, PIV generator, and the explicit
  `AllowSoftwarePIV` opt-in.
- **Threshold** — `ThresholdOptions`, or `NoopThresholdInitializer` where
  threshold initialization does not apply.

Roles accepted by `init sign-csr`: `so`, `admin`, `operator`, `user`,
`auditor`, `custodian`.

## Persistence

Ceremony state, officers, pending certificates and shares are persisted by
**go-qrdb**. go-xkms persists the CA's own material through the keystore and
certificate store. Admin factors are persisted durably on the single-admin
path — see above.

## Test strategy

- **Unit** — `pkg/init/ceremony_test.go`, `admin_enrollment_test.go`,
  `admin_enrollment_piv_test.go`,
  `admin_factors_test.go`, `firstboot_adapter_test.go`, `threshold_test.go`,
  `coverage_boost_test.go`.
- **End to end** — `pkg/api/rest/init_ceremony_e2e_test.go`,
  `init_public_derivation_test.go`; `pkg/api/mcp/init_public_test.go`,
  `init_public_derivation_test.go`.
- **Route gating** — `pkg/api/{grpc,unix}/initgate_guard_test.go`,
  `pkg/api/initgate`.
- **Durable admin persistence** — `cmd/xkmsd/init_node_test.go`
  (`resolveInitNodeConfig`, `openDurableInitNode`, `unsealDurableInitNode`,
  and `TestExecuteCeremony_SingleAdmin_PersistsAdminFactorAcrossReopen`, which
  closes and reopens the durable node within the same test to prove a
  persisted factor survives without a running process),
  `cmd/xkmsd/init_factor_persister_test.go` (the `Enrollment` →
  `auth.AuthFactor` conversion per factor type, and the persister's
  fail-closed contract).
- **Integration** — `test/integration/bootstrap`, `test/integration/logins`,
  `test/integration/initceremony` (`integration && initceremony`; builds and
  runs the real `xkmsd` binary through `init` → `run` → restart → mTLS
  authentication with no re-enrollment in between).

The public-derivation suites exist on both REST and MCP because the init routes
are reachable before authentication; they assert the derivation is identical on
both.

## Observability

Ceremony steps are audited through go-qrdb's ceremony service. The events that
matter in a later investigation are: which officers claimed, when, from where,
and which roles were issued. Correlation IDs propagate from the transport
middleware, and the CA's own issuance audit ([`../certificate-authority/`](../certificate-authority/engineering.md))
records every certificate the ceremony produced.
