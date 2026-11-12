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

Open decision for the coordinator/owner, one of:

1. Strict: adopt the qrdb rule on both paths (as pkg/acme/admin does), and
   allow edits to pkg/auth/mtls_test.go and pkg/testutil certificate helpers
   (tenant SPIFFE SAN + OU), plus whatever integration fixtures issue
   tenant-less client certificates.
2. Scoped: apply the rule only on the bound-user path (refuse a user/cert
   tenant mismatch only when the certificate names a tenant), leaving the
   certificate-only path's OU behaviour for a later row.
