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

Results to follow.
