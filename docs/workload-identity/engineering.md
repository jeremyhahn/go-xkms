# Workload Identity — Engineering Contract

> **Status: NORMATIVE** · Feature: `workload-identity` · Repo: `go-xkms` · Last verified: 2026-10-25

The contract is `docs/SPEC.md` row `workload-identity`. The tenant is the SPIFFE
trust domain: a tenant identity is `spiffe://<tenant>/<kind>/<name>`, and the
certificate also carries the tenant in `Subject.OrganizationalUnit[0]`, the
tenant key go-qrdb reads. The cluster keeps its own trust domain, the pin every
login verifies under, and no tenant may be that trust domain.

## Exported surface

| Symbol | Where | Contract |
|---|---|---|
| `spiffe.BuildURI(clusterTrustDomain, tenantID, kind, name)` | `pkg/spiffe/spiffe.go:146` | Builds `spiffe://<tenant>/<kind>/<name>`. The cluster trust domain must be valid, and a tenant equal to it is `ErrTenantIsClusterTrustDomain` (`pkg/spiffe/spiffe.go:54`). A tenant that is not a trust-domain name is refused (`pkg/spiffe/spiffe.go:97`). Kind is `user` or `svc` (`pkg/spiffe/spiffe.go:69`, `:72`); name is one path segment. |
| `spiffe.ParseID(u)` | `pkg/spiffe/spiffe.go:165` | Reads a tenant identity back. A URI that is not two path segments of a known kind is skipped (`ok=false`, no error); a malformed tenant is an error. |
| `spiffe.TenantFromURIs(uris, clusterTrustDomain)` | `pkg/spiffe/spiffe.go:206` | Finds the one tenant identity among the SANs. The cluster trust domain as tenant, or two different tenants, is an error (fail-closed). |
| `(*CA).SignCSRWithSPIFFE(ctx, csrPEM, profile, validityDays, trustDomain, tenantID, kind, name)` | `pkg/ca/service_adapter.go:63` | Signs a CSR stamped with the tenant identity under the cluster trust domain. Kind defaults to `user`; name defaults to the subject CN. The same signature is on `pkg/ca/provider` and the `sdk/go` CA. |
| `SignOptions` / `CertificateRequest` `SPIFFETrustDomain`, `TenantID`, `SPIFFEKind`, `SPIFFEName` | `pkg/ca/types.go` | `SPIFFETrustDomain` with `TenantID` requests the SAN (`pkg/ca/ca.go:1886`). `TenantID` always stamps OU[0] (`StampTenant`, `pkg/ca/tenant_subject.go:43`) and records ownership for revocation. |

## Invariants

- **One SAN synthesis site.** `pkg/ca/ca.go:1886` builds the URI with
  `spiffe.BuildURI` (`:1895`) on the CSR and keypair paths. A failed build is
  `ErrSigningFailed` wrapping the `pkg/spiffe` cause, before anything is signed.
- **Caller-named profiles take names only from the caller.** `x509-svid` and
  `ipsec-vtep` refuse the synthesis options with
  `ErrTenantSPIFFEWithCallerSANs` (`pkg/ca/profile_contracts.go:85`;
  `signCallerNamedCSR`, `pkg/ca/subordinate.go:53`). The caller passes the
  SPIFFE ID in `SignOptions.SANS`, and `TenantID` stamps OU[0].
- **`x509-svid` binds its trust domain to the tenant.** `ValidateTemplate`
  (`pkg/ca/profile_ipsec_svid.go:236`) requires exactly one URI SAN that is a
  SPIFFE ID whose trust domain equals `OrganizationalUnit[0]` (`:244`); anything
  else is `ErrInvalidSAN`. `ipsec-vtep` refuses any URI.
- **Each tenant's bundle is its own CA.** A tenant's SVIDs are signed by a
  subordinate whose URI name constraint is that tenant's trust domain
  (`(*CA).IssueSubordinateCA`). Another tenant's bundle does not chain them
  (`x509.UnknownAuthorityError`), and that tenant's CA cannot issue them: the CA
  refuses with `ErrNameConstraintViolation` before signing.
- **The control plane is the `system` tenant.** The SO and admin certificates
  are `spiffe://system/user/<CN>` with OU[0] `system` when the adapter has a
  trust domain (`pkg/init/firstboot_adapter.go:101`, `:123`); without one they
  are refused with `ErrNoSPIFFETrustDomain` (`pkg/init/errors.go:104`).

## Seams

- **go-qrdb v0.51.0-alpha.** `sdk.TenantFromClientCert(cert, clusterTrustDomain)`
  (`sdk/go/types_auth.go:207`, aliasing `pkg/auth/mtls.go:275`) names a
  certificate's tenant only when OU[0] and the SAN's trust domain agree, and
  `auth.TenantPrincipalURIs` (`pkg/auth/mtls.go:324`) issues the same form
  (`pkg/spiffe/spiffe.go:21`). The CA's output resolves through that rule
  (`TestSignCSR_TenantResolvesThroughQRDBRule`).
- **One cluster trust domain.** `embeddednode.TrustDomain(cfg)`
  (`pkg/embeddednode/embedded_node.go:297`: `cluster.raft_enrollment.trust_domain`,
  else `embeddednode.DefaultTrustDomain`, `"xkms.cluster"`) is the only source.
  The ACME node URI-SAN hook (`cmd/xkmsd/acme.go`, `clusterACMETrustDomain`) and
  the raft node provisioner (`pkg/server/qrdb_node_cluster_acme.go`,
  `buildClusterCAOptions`) read it, and `EmbeddedNodeStorageConfig` hands it to
  the embedded go-qrdb node as both `Auth.SPIFFETrustDomain` and
  `Auth.ClusterTrustDomain`. The latter is go-qrdb's cluster-peer domain
  (node SAN `spiffe://<domain>/node/<raftAddress>`, pinned by
  `clusterkeys.Receiver` and `Sender`); left empty it would fall back to
  go-qrdb's `"qrdb.cluster"` (`TestEmbeddedNodeStorageConfig_OneClusterTrustDomain`).
- **go-qrdb tenant IDs (open).** go-qrdb's tenant-ID rules do not yet hold a
  tenant ID to the trust-domain grammar: v0.51.0-alpha refuses only control
  bytes, `/` and `\` on create (`ValidateTenantIDShape`,
  `pkg/tenant/reserved.go:132`, `:41`). A tenant whose ID is not a trust-domain
  name can be created, and go-xkms refuses its SVID before signing.
- **go-quicbaas** receives SVIDs and verifies them against the tenant's bundle.

## ACME issuance

A service gets its SVID at deploy through ACME, with the `x509-svid` order
profile (draft-aaron-acme-profiles).

- **Profile.** The directory lists `x509-svid` in `meta.profiles`
  (`pkg/acme/server/handlers/directory.go:51`, from `orderProfiles`,
  `pkg/acme/server/handlers/order_svid.go:36`). A newOrder naming any other
  profile is `invalidProfile` (`pkg/acme/server/handlers/new_order.go:82`).
- **Identifier.** The order names exactly one `spiffe` identifier
  (`common.AuthzTypeSPIFFE`, `pkg/acme/common/types.go:42`) in canonical form,
  `spiffe://<tenant>/svc/<name>` (`svidIdentity`, `order_svid.go:70`).
- **Authorization.** The account must be bound to a tenant, the identifier
  must be in that tenant, and the tenant must sign with its own CA, never the
  global one (`authorizeSVIDOrder`, `order_svid.go:112`). The tenant binding is
  the authorization: it is saved valid with no challenges and the order is
  created `ready` (`saveSVIDAuthorization`, `order_svid.go:147`).
- **Finalize.** The checks run again against the account as it stands
  (`svidFinalizeIdentity`, `order_svid.go:191`, called at
  `order_finalize.go:581`). The CSR may carry no DNS, IP or email name and no
  other URI, and its CN and OU may only be empty, the service name and the
  tenant (`matchesSVIDIdentifier`, `order_svid.go:173`). A refused CSR leaves
  the order `ready`. If the tenant has lost its own CA, the order fails
  (`order_finalize.go:784`).
- **Signing.** The order's SPIFFE ID is the one caller SAN and `TenantID`
  stamps OU[0]; the subject has no CN (`order_finalize.go:917`). The SVID is
  linted by its own issuer, which admits a URI SAN whose host is a tenant
  rather than an FQDN (`linter.Identifiers.SVID`, `pkg/acme/linter/linter.go:95`;
  `order_finalize.go:957`). The issued certificate is verified against the
  tenant's CA (`verifyIssued`, `order_finalize.go:326`).

| Refusal | Typed error | ACME problem |
|---|---|---|
| Not exactly one `spiffe` identifier | `ErrSVIDIdentifierRequired` | `malformed` |
| Not canonical `spiffe://<tenant>/<kind>/<name>` | `ErrSVIDIdentifierInvalid` | `malformed` |
| Kind is not `svc` | `ErrSVIDKindNotService` | `rejectedIdentifier` |
| Account not bound to a tenant | `ErrSVIDAccountNotTenantBound` | `unauthorized` |
| Identifier in another tenant | `ErrSVIDOtherTenant` | `unauthorized` |
| Tenant without its own signing CA | `ErrSVIDTenantCARequired` | `unauthorized` |

## Tests

| Test | Covers |
|---|---|
| `pkg/ca/spiffe_san_test.go` | SAN and OU[0] stamping on both issuance paths, kind/name overrides, go-qrdb resolution |
| `pkg/ca/profile_ipsec_svid_test.go` `TestX509SVID_*` | `x509-svid` shape and refusals; `TestX509SVID_TenantBundleIsolation` for cross-tenant verification |
| `pkg/spiffe/spiffe_test.go` | Build/parse round trip, cluster-trust-domain refusal, fail-closed tenant matching |
| `pkg/acme/linter/linter_test.go` | The `SVID` admission excludes only the URI-SAN lints |
| `pkg/acme/server/handlers/order_svid_test.go` | `x509-svid` through ACME: directory profile, an SVID with the tenant URI and OU[0] signed by the tenant CA, each refusal above, finalize CSR and lost-CA refusals |
