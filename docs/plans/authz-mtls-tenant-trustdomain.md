# authz-mtls-tenant: xkmsd mTLS tenant by qrdbsdk.TenantFromClientCert

Epic #2086, SPEC row authz-mtls-tenant (docs/SPEC.md:58), PR #2109.

## Requirement (not re-scoped, ruling 734)

The row as written on main: `certIdentity` takes the tenant from subject
OU[0] by hand; replaced by `qrdbsdk.TenantFromClientCert`, as the ACME admin
mTLS resolver does. Codex (f3df47a0b) found the earlier SPEC flip re-scoped
the row; the coordinator ruled the requirement text stays.

## What the code does

- `certIdentity` (pkg/auth/mtls.go:288-293) calls
  `qrdbsdk.TenantFromClientCert(cert, MTLSConfig.TrustDomain)` and binds
  `qrdbsdk.NormalizeTenantID` of the result, with no go-xkms rule on top;
  every refusal is go-qrdb's error (`qrdbsdk.ErrInvalidClientCertificate`).
- The rules that apply are go-qrdb's own, documented on
  `TenantFromClientCert` (go-qrdb sdk/go v0.51.0-alpha `types_auth.go`,
  alias of go-qrdb `pkg/auth.TenantFromClientCert`): OU and SPIFFE SAN must
  both be present and agree (an OU alone or a SAN alone names no tenant; a
  disagreeing OU is refused); a certificate with no OU is refused; with a
  cluster trust domain no tenant may be it; SANs under two domains are
  refused. Line numbers are not cited: the module cache is outside the
  lane workspace.
- Removed: the go-xkms rule "a certificate with no OU claims no tenant" on
  the certificate-only path (it produced a tenantless, cross-tenant identity).
- Callers pass the node's trust domain: pkg/server/server.go (three sites),
  cmd/xkmsd/admin.go.

## Tests

- `TestMTLSAuthenticator_CertIdentity_DelegatesToQRDB`: SAN only, OU only,
  agree, disagree, neither, with and without a trust domain; certIdentity
  matches `TenantFromClientCert` exactly.
- `TestMTLSAuthenticator_CertificateTenant_QRDBRule`; the ValidCert,
  WithoutUserStore and TenantID_NoOU tests in mtls_test.go use a tenant
  claim or expect go-qrdb's refusal.
- `TestMTLSAuthenticator_BoundUser_AsOnMain`: bound-user path unchanged.

## Codex reviews fixed

- e6efbde90 P1 (11-16): bound-user path (`userIdentity`) as on main;
  test c03110e74, fix 12c5b98c7; refusal cases deleted from
  `TestMTLSAuthenticator_BoundUserTenant_QRDBRule`.
- 0f15f7600 P1 (11-17): REST/gRPC mTLS fixtures sign the tenant claim
  (`testutil.GenerateTestTenantClientCert`), no-tenant cert refused on
  both transports (97490a71c). P2: changelog says no-OU certs are refused.

## Open

- docs/SPEC.md row 58 cites mtls.go:337-342; certIdentity is now at
  288-293 (SPEC.md not edited in this slice).
- The row text says the SPIFFE SAN "takes precedence over" the OU; go-qrdb
  refuses a disagreeing pair instead. Row wording is the owner's call.

Closes #2086
