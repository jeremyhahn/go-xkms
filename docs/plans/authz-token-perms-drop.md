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

Results to follow.
