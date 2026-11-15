# authz-mtls-tenant: xkmsd mTLS tenant by qrdbsdk.TenantFromClientCert

Epic #2086, SPEC row authz-mtls-tenant (docs/SPEC.md:58).

## Objective

The xkmsd mTLS authenticator (`pkg/auth/mtls.go`) takes the tenant from the
certificate's SPIFFE tenant SAN first and the subject OU second, through
go-qrdb's `qrdbsdk.TenantFromClientCert` (the same rule as the ACME admin
resolver and the REST auth handler), and refuses a bound user whose tenant
differs from the certificate's tenant.

## Steps

1. `MTLSConfig.TrustDomain` and the authenticator field. Test commit:
   `pkg/auth/mtls_tenant_test.go` with table cases on generated certificates:
   SPIFFE tenant SAN beats a differing OU; OU-only certificate keeps today's
   tenant; a certificate `TenantFromClientCert` refuses is refused with
   `qrdbsdk.ErrInvalidClientCertificate`; a bound user whose tenant differs
   from the certificate's tenant is refused. The new cases fail.
2. Fix commit: `certIdentity` returns `(*Identity, error)` and uses
   `TenantFromClientCert(cert, trustDomain)`; `userIdentity` refuses a tenant
   mismatch with a typed error; `buildIdentity` propagates; callers pass the
   node's trust domain (empty keeps the OU rule).
3. Changelog entry; SPEC row 58 set to shipped when the acceptance holds.

## Out of scope

Role mapping, permissions, `pkg/server/unified_tls.go` (lane stenoua).

## Results

Blocked before step 1: the brief's cases contradict the pinned rule.
`go doc github.com/jeremyhahn/go-qrdb/sdk/go TenantFromClientCert`
(v0.51.0-alpha) says a certificate names a tenant only when its first
Subject OU and its SPIFFE SAN trust domain are both present and agree:

- an OU alone is refused (ErrSpiffeNoTenantID), so "OU-only keeps today's
  tenant" cannot hold through the rule;
- an OU differing from the SAN is refused
  (ClientCertificateTenantNameMismatchError), so "SAN beats a differing OU"
  cannot hold either;
- `clusterTrustDomain == ""` skips only the cluster checks; it does not keep
  the OU rule;
- with a trust domain set, no tenant may be the cluster trust domain, so a
  node certificate under the cluster domain is refused on the
  certificate-only path.

Applying the rule as written changes pkg/auth/mtls_test.go behaviour outside
this lane's file map: TestMTLSAuthenticator_TenantID_FromOU (OU-only cert
expects tenant-from-ou) and TestMTLSAuthenticator_TenantID_FromUserStore
(testutil cert with no tenant, user tenant-123 expected to pass) would both
be refused, along with every other bound-user test on testutil certificates.
REST/gRPC/server mTLS callers using certificates without a SPIFFE tenant SAN
would stop authenticating.

### Slice 2 (resumed): decision taken, built

Built the reversible middle: the rule decides the tenant whenever the
certificate claims one (it carries a Subject OU, the field read by hand
before); a certificate with no OU claims no tenant, as before, so testutil
and SVID-only certificates keep working. OU-only and OU/SAN-mismatch
certificates are now refused (TenantID_FromOU updated to expect it). The
bound-user path refuses a user of another tenant with
auth.CertificateTenantMismatchError; pkg/acme/admin aliases that type. The
server (three sites) and cmd/xkmsd/admin.go pass TrustDomain().

- go build ./...: pass. go vet pkg/auth, pkg/acme/admin, pkg/server, cmd/xkmsd: pass.
- go test pkg/auth/...: new cases fail on the test commit (build), pass on the fix.
- go test pkg/api/rest/..., pkg/config/..., cmd/xkmsd/..., pkg/server, pkg/acme/admin/...: pass.
- go test pkg/acme/client: only the 5 TestDeviceAttestDICE* fail (tfwsim-atecc608a
  binary not built in the lane; unrelated).
- docs/SPEC.md row 58 not changed: the lane's policy guard refuses the path
  (LANE_POLICY_ALLOW not set).

### Slice 3: SPEC row shipped

- docs/SPEC.md row 58 set to shipped (anchors mtls.go:256, :309, :337 re-checked).
- make test-go UNIT_TEST_SCOPE=./pkg/auth/...: pass.
- make lint: pass (0 issues on every module and tag set).
