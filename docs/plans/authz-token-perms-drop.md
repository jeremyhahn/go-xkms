# authz-token-perms: drop Permissions from ACME admin token claims

SPEC row authz-token-perms (docs/SPEC.md:73), epic #1557.

## Objective

`pkg/acme/auth.TokenClaims` carries a `Permissions` list that no
authorization decision reads (authorization comes from
`qrdbsdk.Authorizer`). Remove the field and its copy on refresh so the
claims no longer look like authority they do not carry.

## Steps

1. test(acme/auth): a token JSON carrying `"permissions"` decodes into
   `TokenClaims` and re-encodes without a `permissions` key; a claim set
   refreshed by the memory client carries none. Fails before step 2.
2. refactor(acme/auth): delete `TokenClaims.Permissions`, its copy in
   `MemoryClient` refresh and every test reference.
3. docs: changelog entry (removed), SPEC row 73 set to shipped.

## Out of scope

Role CRUD `Permissions` in pkg/acme/api (role messages), pkg/auth,
pkg/oidc and xkey `TokenClaims` types.

## Results

- test commit, before the refactor: `TestTokenClaimsDropPermissionList` fails on both NotContains asserts (expected).
- `go test -count=1 -tags "codec_cbor codec_json codec_msgpack" ./pkg/acme/...` after the refactor: all pass except 5 DICE e2e tests in pkg/acme/client (`device_attest_dice_e2e_test.go:274`, `:299`, `:313`, `:329`, `:346`): `tfwsim-atecc608a` not built in the module cache. They fail at a stat of the missing simulator binary, before any code this change touches runs (they need `make tfwsim-atecc608a`). Not re-run on main d55b1b73c7.
- `go build ./...`: pass.
- `make lint`: pass (0 issues across all modules and tag sets).
- SPEC row 73 not set: docs/SPEC.md is a protected path in this lane (policy-guard, no LANE_POLICY_ALLOW). Proposed row text is in the lane report.
