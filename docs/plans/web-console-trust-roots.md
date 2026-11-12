# Web console: Trust Roots view (epic #1443, lane suiw, slice 23)

## Gap

Main serves `/api/v1/trust-roots` (pkg/api/rest/routes.go, registered only
when trustRootHandlers is wired; resource `trust_roots`): GET list
`?purpose=`, POST import, GET/DELETE `/{fingerprint}`, POST
`/{fingerprint}/quarantine`. No console view calls these routes, and
capabilityFlags has no `trust_roots` key, so the console cannot tell whether
the deployment wired them.

## Slices

1. test(rest,web): `TestCapabilityFlags_TrustRoots` (flag true with
   trustRootHandlers, false and present without) and
   web/app/test/view3_trust_roots.test.ts (load, empty list, purpose filter,
   import, quarantine, delete with confirm, error Alert).
2. feat(rest): `"trust_roots": s.trustRootHandlers != nil,` in capabilityFlags.
3. feat(web): web/app/src/lib/trustRoots.ts (wire types,
   `TRUST_ROOT_PURPOSES`, list/import/quarantine/delete over
   `getSDKClient().http.request`), web/app/src/views/TrustRootsView.svelte
   (PageHeader, purpose filter, table with Quarantine/Delete, import card,
   error Alert), route `#/trust/roots`, nav entry under Certificates & CA
   gated on capability `trust_roots` and `trust_roots:list`.
   One added line per place: nav.ts (1), router.svelte.ts (2), App.svelte (2).
4. docs(web-console): Navigation table row in docs/web-console/user.md,
   `trust_roots` in the capability list of docs/web-console/engineering.md,
   changelog entry.
5. Checks: sdk/ts build (dist restored), svelte-auth and web/app npm ci,
   vitest (new file and whole suite), svelte-check, vite build,
   pkg/api/rest -race, sdk/go build, make lint.

## Out of scope

Trust Bundle view (suil), xkey trust classify, sdk/ts, Go code beyond the
flag line and its test, docs/SPEC.md.

## Results

- go test -run TestCapabilityFlags ./pkg/api/rest/: pass.
- sdk/ts npm ci + build: pass (tracked sdk/ts/dist restored, not committed).
- sdk/ts/svelte-auth npm ci: pass.
- web/app npm ci: pass.
- vitest test/view3_trust_roots.test.ts: 9/9 pass (first run caught a test
  fixture whose issuer equalled its subject; made distinct in feat(web)).
- web/app npm test (NODE_OPTIONS=--no-experimental-webstorage): 51 files,
  421 tests pass.
- svelte-check: 0 errors, 0 warnings.
- vite build to /tmp/suiw-dist: pass.
- go test -race (codec tags) ./pkg/api/rest/: pass.
- sdk/go go build ./...: pass.
- make lint: pass (0 issues on every tag set).
