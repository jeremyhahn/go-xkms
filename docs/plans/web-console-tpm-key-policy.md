# Web console: TPM Key Policy lookup (epic #1443, lane suij)

## Gap

The server answers "which named TPM policy was this key or sealed object
created under" in one call, `GET /api/v1/keys/{id}/tpm-policy?tenant_id=&kind=`
(permission `tpm_policy:get`, registered only when TPM policies are wired),
and the TS SDK exposes it as `tpmPolicies.keyPolicy`. TpmPoliciesView lists
policies and their objects but never asks the reverse question, so an
operator holding a key id must walk every policy or use xkmsctl.

## The view

- `web/app/src/views/TpmKeyPolicyView.svelte`, `PageHeader` "TPM Key Policy".
- Form: object id (required), kind select `key` (default) / `sealed`,
  optional tenant id, a Look up button disabled until an id is entered.
- Result card: object id, kind, policy name, auth policy digest (monospace,
  a dash when absent), created time.
- Errors: an error `Alert` with the message; an earlier result is cleared.

## Route and nav

- Route `#/tpm/key-policy` -> `tpmKeyPolicy`.
- Nav entry "TPM Key Policy" after FROST in Keys & Crypto, capability
  `tpm_policies`, requires `tpm_policy:get`.
- One added line per place (nav.ts; router union and path map; App.svelte
  import and dispatch), no other change there, shared with lanes suia-suii
  and suik, suil, suim, suin, suio so the merges stay trivial.

## Tests

`web/app/test/view3_tpm_key_policy.test.ts`: validation (disabled button,
no call on mount), key lookup, sealed lookup with tenant, missing auth
policy, error clears an earlier result. Test commit before the feat commit.

## Checks

sdk/ts build, svelte-auth install, web/app npm ci, the new vitest file, the
whole web/app suite, svelte-check, vite build, pkg/api/rest -race,
sdk/go build, make lint.

## Out of scope

TpmPoliciesView and its test, lib/tpmPolicy.ts, policy create/update/revoke,
Go code, sdk/ts, xkey, web/desktop, docs/SPEC.md.

## Results

Results to follow.
