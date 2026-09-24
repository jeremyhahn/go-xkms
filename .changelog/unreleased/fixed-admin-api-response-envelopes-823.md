- **`admin-api.yaml` now documents the response every admin handler actually
  writes, and there is exactly one copy of it.** The tenant, tenant-CA, EAB,
  certificate, account and order sections still documented a
  `SuccessResponse{success,data,pagination}` / `ErrorResponse{success,error}`
  JSON envelope that no handler in `pkg/acme/admin` has ever written: every
  handler on this API writes its payload directly with `writeJSON` (a bare
  object, a bare array, or `admin.ListResponse{items,total,page,per_page}`
  for the paginated list operations) and every error as RFC 7807
  `application/problem+json` via `writeProblem` or `PermissionGate.Wrap`'s
  own 401/403 path — there was never a success/error envelope on the error
  side either. All thirty-plus operations across Tenants, Tenant CA, EAB,
  Certificates, Accounts, Orders and Status/Stats are corrected to match:
  list operations now reference new `List*Response` schemas
  (`ListTenantsResponse`, `ListCertificatesResponse`, `ListAccountsResponse`,
  `ListOrdersResponse`, `ListEABResponse`) shaped exactly like
  `admin.ListResponse`; single-resource and message responses reference the
  bare payload type; every `401`/`403`/`400`/`404`/`409`/`500` now points at
  the existing `Problem*` `application/problem+json` responses the
  roles/users/audit/algorithms/barrier sections already used. The dead
  `SuccessResponse`, `ErrorResponse`, `ErrorInfo` and `Pagination` schemas and
  their five `ErrorResponse`-based `responses:` entries are removed. Also
  added the `KeyInfo` schema and the `keys` property on `CAStatus`,
  `TenantRootCAInfo` and `TenantIntCAInfo` — a field the corresponding Go
  types (`admin.CAStatus`, `admin.TenantRootCAInfo`, `admin.TenantIntCAInfo`)
  emit but the schemas never declared — and marked `UserInfo.role_ids`
  nullable: `db.User.RoleIDs` carries no `omitempty` tag, so an unassigned
  user serializes it as JSON `null`, not `[]`.
- **New test `pkg/acme/admin/openapi_response_test.go` validates response
  *bodies*, not just routes.** #822's `TestAdminOpenAPISpec_MatchesRouter`
  (`pkg/acme/api/server`) only compared the router's (method, path) set
  against the spec; it never invoked a handler. The new test calls every
  admin handler directly (bypassing the router and `PermissionGate`, the
  same pattern `pkg/acme/admin`'s existing `rbac_coverage_test.go` and
  `barrier_coverage_test.go` use) with a representative success and error
  case per operation, and validates the literal recorded response against
  `admin-api.yaml` via `github.com/getkin/kin-openapi/openapi3filter`
  (already a direct `go.mod` dependency since #822; no new dependency
  added). It caught the two schema gaps above (the missing `keys` property
  and the non-nullable `role_ids`) during development.
- **BREAKING (docs only): `api/openapi/` and `docs/acme/api/openapi.yaml`
  are removed.** `api/openapi/{acme-api,admin-api}.yaml` was a manually
  "kept in sync" duplicate of the embedded
  `pkg/acme/api/swagger/openapi/*.yaml` with no Makefile, CI, script or doc
  consumer — a second copy that could only drift, never a source of truth;
  the embedded copy `GET /openapi/{spec}.yaml` serves live is now the only
  copy. `docs/acme/api/openapi.yaml` (~3,174 lines) was a hand-curated
  combined spec inherited verbatim from `go-trusted-ca`'s
  `docs/api/openapi.yaml` migration and never kept current; its two
  referrers (`docs/acme/admin/api-reference.md`,
  `docs/acme/admin/README.md`) now point at the live
  `GET /openapi/admin-api.yaml` endpoint and the
  `pkg/acme/api/swagger/openapi/admin-api.yaml` source instead. Anything
  that fetched either removed path must fetch the live endpoint or read the
  source file going forward. Files:
  `pkg/acme/api/swagger/openapi/admin-api.yaml`, `api/openapi/` (removed),
  `docs/acme/api/openapi.yaml` (removed), `docs/acme/admin/api-reference.md`,
  `docs/acme/admin/README.md`, `pkg/acme/admin/openapi_response_test.go`
  (new). Refs go-xkms#823.
