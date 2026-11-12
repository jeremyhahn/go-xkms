# authz-tenant-ou: tenant OU on PIV self-signed and xkmsd bootstrap certificates

Row: authz-tenant-ou (docs/SPEC.md:72), epic #2089. Status: planned (row stays planned).

## Objective

Every certificate go-xkms issues for a tenant or the node names the tenant as
subject OU[0] through the one stamping function (`StampTenant`). This slice
covers the two self-signed leaf paths that do not yet carry it:

- PIV slot self-signed certificate (`pkg/xkms/piv_manager.go`,
  `buildAndStoreSelfSigned`, reached from `pivGenerateSelfSigned` and
  `SelfSignExistingPIVKey`): OU[0] is the caller's tenant, never the request OU.
- xkmsd bootstrap listener certificate (`pkg/server/unified_tls.go`,
  `ensureBootstrapCert`): OU[0] is the system tenant; a persisted certificate
  without it is regenerated.

## Steps

1. Test commit: pkg/xkms/piv_tenant_ou_test.go and
   pkg/server/unified_tls_tenant_ou_test.go (fail before the fix).
2a. Refactor: move `StampTenant` and its two errors to the leaf package
   pkg/certsubject (pkg/ca imports pkg/xkms, so pkg/xkms cannot import pkg/ca);
   pkg/ca keeps aliases.
2. Fix: stamp both subjects; bootstrap reuse check requires the system tenant OU.
3. Docs: engineering.md invariant list and changelog entry.

## Out of scope

- `CreateHybridCertificate` (caller's template, no production caller).
- Virtual-authenticator attestation certificate
  (`pkg/fido2/authenticator/attestation.go:184`).
- CA hierarchy, FIDO2 attestation profile, LAK: exempt by invariant.

## Results

Results to follow.
