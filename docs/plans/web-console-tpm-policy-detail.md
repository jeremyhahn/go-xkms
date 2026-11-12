# Web console: TPM Policy Detail (#1443, lane sujn)

## Gap

Main serves GET `/api/v1/tpm/policies`, GET `/api/v1/tpm/policies/{name}`,
POST `/api/v1/tpm/policies/{name}/verify` and GET
`/api/v1/tpm/policies/{name}/objects`, all with a `tenant_id` query
(pkg/api/rest/routes.go, pkg/api/rest/handlers_tpm_policy.go), and sdk/ts has
`tpmPolicies.list`, `.get`, `.verify` and `.objects` with a `tenantId`
argument. TpmPoliciesView.svelte never passes a tenant ID and never calls
`get`, and no view shows a condition's captured `pcr_values` or `pcr_digest`.

## Slice

- Helper web/app/src/lib/tpmPolicyDetail.ts: `listScopes`, `listPolicyNames`,
  `loadPolicy`, `policyObjects`, `verifyPolicy` over the SDK, and `pcrRows`
  (a pcr condition's `pcr_values` as rows sorted by PCR index).
- View web/app/src/views/TpmPolicyDetailView.svelte (read-only): scope select
  ("Own scope" then tenant IDs), policy select, Load / Objects / Verify
  buttons; policy card with one block per branch (pcr: bank, PCR/value table,
  digest; locality: localities; auth_value); objects card; verify card;
  `Alert` for errors.
- Route `#/tpm/policies/detail` (`tpmPolicyDetail`), nav entry "TPM Policy
  Detail" after TPM Policies, capability `tpm_policies`.
- One added line per place in nav.ts (1), router.svelte.ts (2), App.svelte
  (2); no other line changed there.

## Tests

web/app/test/view3_tpm_policy_detail.test.ts: scopes, tenant scope, load
(PCR values, digest, locality, index, approved), objects (and empty),
verify (mismatch, PCR 7), errors for get/objects/verify.

## Checks

sdk/ts build, svelte-auth npm ci, web/app npm ci, the new vitest file, the
whole web/app suite, svelte-check, vite build, pkg/api/rest -race, sdk/go
build, make lint.

## Out of scope

Policy create/update/revoke/delete/auto-unseal, tenant TPM mode, vTPM, TPM key
policy lookup, TpmPoliciesView.svelte, lib/tpmPolicy.ts, Go code, sdk/ts,
docs/SPEC.md.

## Results

Results to follow.
