# Web console: Trust Bundle view (row 1443, lane suil)

## Gap

Main serves the CA bootstrap bundle at `GET /v1/ca/bootstrap` (public) and the
TS SDK exposes `ca.bootstrapBundle()` (raw PEM text), but no console view calls
it. Operators fetch the bundle a new client pins on first contact with curl.

## The view

`web/app/src/views/TrustBundleView.svelte`, route `#/trust/bundle`:

- `PageHeader` "Trust Bundle" with a Refresh action;
- one line: this is the bundle clients pin on first contact;
- the certificate count (split on `-----END CERTIFICATE-----`, no X.509 parsing);
- the PEM in a monospace read-only block;
- Download (`xkms-ca-bundle.pem`, `application/pem-certificate-chain`) and Copy;
- "No bootstrap bundle is configured" for an empty bundle (Download hidden);
- an error `Alert` when the call fails.

Nav entry in the Overview section, directly after Dashboard, icon `ShieldCheck`,
no RBAC or capability gate (the route is public on the server).

## One line per place

Lanes suia-suii and suij, suik, suim, suin, suio also touch nav.ts,
router.svelte.ts and App.svelte. This lane adds exactly one line at each anchor
(nav.ts after Dashboard; router union after `"dashboard"`; path map after
`"/dashboard"`; App.svelte import after DashboardView; dispatch after
`<DashboardView />`) and changes no other line there.

## Tests

`web/app/test/view3_trust_bundle.test.ts`: mount (call once, PEM + "2
certificates"), download, refresh, empty, error. Committed before the view
(ruling 286).

## Checks

sdk/ts build, svelte-auth install, web/app npm ci, the new vitest file, the
whole web/app suite (NODE_OPTIONS=--no-experimental-webstorage), svelte-check,
vite build, `go test -race` of pkg/api/rest, sdk/go build, make lint.

Out of scope: CaView, the bundle's filters, Go code, sdk/ts, xkey, web/desktop,
docs/SPEC.md.

## Results

- sdk/ts build: pass.
- svelte-auth npm ci, web/app npm ci: pass.
- vitest test/view3_trust_bundle.test.ts: 5/5 pass.
- vitest whole web/app suite (NODE_OPTIONS flag): 51 files, 417 tests pass.
- svelte-check: only the baseline errors (UsersView.svelte:121 and view2_users.test.ts:51, role/roles).
- vite build: pass.
- go test -race pkg/api/rest: pass.
- sdk/go build: pass.
- make lint: pass (0 issues on every module and tag set).
