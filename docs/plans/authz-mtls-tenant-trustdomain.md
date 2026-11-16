# authz-mtls-tenant: xkmsd mTLS tenant by qrdbsdk.TenantFromClientCert

Epic #2086, SPEC row authz-mtls-tenant (docs/SPEC.md:58), PR #2109.

## Requirement (not re-scoped, ruling 734)

The row as written on main: `certIdentity` takes the tenant from subject
OU[0] by hand; replaced by `qrdbsdk.TenantFromClientCert`, as the ACME admin
mTLS resolver does. Codex (f3df47a0b) found the earlier SPEC flip re-scoped
the row; the coordinator ruled the requirement text stays.

## What the code does

- `certIdentity` (pkg/auth/mtls.go:337-342) calls
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
- `TestMTLSAuthenticator_CertificateTenant_QRDBRule`,
  `TestMTLSAuthenticator_BoundUserTenant_QRDBRule`; the ValidCert,
  WithoutUserStore and TenantID_NoOU tests in mtls_test.go now use a tenant
  claim or expect go-qrdb's refusal.

## Follow-ups needing owner approval (rule 720)

- `userIdentity` (bound-user path) still applies the tenant rule only when
  the certificate has an OU, and refuses a bound user of another tenant
  (`CertificateTenantMismatchError`). The mismatch refusal mirrors go-qrdb's
  "look the thumbprint up within that tenant only"; the OU gate is go-xkms's.
  Dropping it refuses every bound user on a certificate without a tenant
  claim (REST/gRPC/server callers), so it is left for an owner decision.
- The row text says the SPIFFE SAN "takes precedence over" the OU; go-qrdb
  refuses a disagreeing pair instead. Row wording is the owner's call.

## Open

- docs/SPEC.md row 58 is back to main's requirement text; only Status
  (shipped), the certIdentity line reference and the Detail references
  (mtls.go:337-342, mtls_tenant_test.go, mtls_test.go) changed.
- The two owner follow-ups above are not reflected in SPEC text.

Closes #2086
