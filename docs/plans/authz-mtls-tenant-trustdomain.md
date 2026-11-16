# authz-mtls-tenant: xkmsd mTLS tenant by qrdbsdk.TenantFromClientCert

Epic #2086, SPEC row authz-mtls-tenant (docs/SPEC.md:58), PR #2109.

## What the row does

The xkmsd mTLS authenticator (`pkg/auth/mtls.go`) decides the tenant with
go-qrdb's `qrdbsdk.TenantFromClientCert` under `MTLSConfig.TrustDomain`, the
same rule as the ACME admin mTLS resolver:

- `certTenant` (mtls.go:256): a certificate with a Subject OU claims a tenant
  and the rule decides it. An OU with no SPIFFE tenant SAN, or an OU that
  disagrees with the SAN, is refused (`qrdbsdk.ErrInvalidClientCertificate`).
  A certificate with no OU claims no tenant, as before, so SVID-only and
  testutil certificates keep working.
- `userIdentity` (mtls.go:309): a bound go-qrdb user of another tenant is
  refused with `CertificateTenantMismatchError`. `pkg/acme/admin` aliases
  that type.
- `certIdentity` (mtls.go:337): the certificate-only path; returns
  `(*Identity, error)`.
- `pkg/server/server.go` (three sites) and `cmd/xkmsd/admin.go` pass the
  node's `TrustDomain()`.

Decision (slice 2): the pinned rule (v0.51.0-alpha) refuses an OU alone and
an OU differing from the SAN, so the first brief's "OU-only keeps today's
tenant" and "SAN beats a differing OU" cases could not hold. The row applies
the rule whenever the certificate claims a tenant (has an OU) and leaves
no-OU certificates tenantless. `TenantID_FromOU` in mtls_test.go now expects
the refusal.

## Tests

- `TestMTLSAuthenticator_CertificateTenant_QRDBRule` and
  `TestMTLSAuthenticator_BoundUserTenant_QRDBRule`
  (`pkg/auth/mtls_tenant_test.go`), on generated certificates.
- Updated `pkg/auth/mtls_test.go` cases.

## Results (lane row2086a, 2026-11-16)

- go test -race -tags "codec_cbor codec_json codec_msgpack" pkg/auth/...,
  pkg/acme/admin/..., pkg/server/..., cmd/xkmsd: pass.
- GODEBUG=fips140=only go test pkg/auth: pass.
- make lint: pass (0 issues on every module and tag set).
- SPEC row 58 file:line references (mtls.go:256, :309, :337) and test names
  re-checked against the code: current.

## Open

- With a trust domain set, no tenant may equal the cluster trust domain, so
  a node certificate under the cluster domain that carries an OU is refused
  on the certificate-only path; callers that rely on such certificates are
  not yet checked.
- Out of scope: role mapping, permissions, `pkg/server/unified_tls.go`.
- The PR waits for lane-verify and the CA merge gate.

Closes #2086
