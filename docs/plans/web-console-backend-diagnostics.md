# Web console: Backend Diagnostics view (row web-console, SPEC.md:139)

## Gap

Main serves GET `/api/v1/backend/status` (backends:read), POST
`/api/v1/backend/test` (backends:read) and GET `/api/v1/backend/algorithms`
(keys:list) (pkg/api/rest/routes.go:237-239), but sdk/ts has no method for
them and no console view calls them. BackendsView only lists the configured
backends, so checking one backend's status or running its self-test needs curl.

## Slice

- Helper `web/app/src/lib/backendDiagnostics.ts`: TS interfaces for
  `BackendStatusResponse`, `BackendTestResponse`,
  `GetSupportedAlgorithmsResponse`, and `backendStatus(backend)`,
  `backendTest(backend)`, `backendAlgorithms(backend)` over
  `getSDKClient().http.request` (status and algorithms with `?backend=`, test
  with a `{backend}` body).
- View `web/app/src/views/BackendDiagnosticsView.svelte`: `PageHeader`
  "Backend Diagnostics"; a backend select fed by `backends.list`; a status card
  (type, status badge, device, region, key ID, PCR banks and registers, true
  capabilities); a Run self-test button with a busy state and its result; the
  algorithms list; `Alert` for errors. Status and algorithms load when a
  backend is chosen; the self-test runs only on the button.
- Route `#/backends/diagnostics` (`backendDiagnostics`), nav entry under
  Overview after Backends, requiring backends:read.
- One added line per place in nav.ts, router.svelte.ts (union, path map) and
  App.svelte (import, dispatch); no other line changed there.

## Tests

`web/app/test/view3_backend_diagnostics.test.ts`: load (list, status,
algorithms, rendered fields, no "undefined"), self-test pass/fail, button
disabled states, error alerts (list, status, test; algorithms failure keeps
the status card).

## Checks

sdk/ts build, svelte-auth and web/app `npm ci`, the new vitest file, the
web/app suite, `npm run check`, vite build, `go test -race ./pkg/api/rest/`,
sdk/go build, `make lint`.

## Out of scope

BackendsView, the System Health view, Go code, sdk/ts, docs/SPEC.md.

## Results

- sdk/ts build (dist restored), svelte-auth and web/app `npm ci`: pass.
- `vitest run test/view3_backend_diagnostics.test.ts`: 8/8 pass.
- web/app `npm test` (NODE_OPTIONS=--no-experimental-webstorage): 51 files, 420 tests pass.
- `npm run check` (svelte-check): 0 errors, 0 warnings.
- `vite build --outDir /tmp/sujd-dist`: pass.
- `go test -race ./pkg/api/rest/` (codec tags): ok.
- `go build ./...` in sdk/go: pass.
- `make lint`: 0 issues on every module and tag set.
