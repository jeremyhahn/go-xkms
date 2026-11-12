# Web console: Certificate Import (epic #1443, lane suih)

## Gap

The REST API has `POST /api/v1/certs?key_id=&backend=`, `HEAD /api/v1/certs/{id}`
and `POST /api/v1/certs/{id}/chain` (certs:enroll / certs:read), and the TS SDK
has `certs.save`, `certs.exists` and `certs.saveChain`. The console's
CertificatesView only lists and shows certificates, so an operator holding a
certificate from an external CA must use xkmsctl or curl to store it.

## The view

`web/app/src/views/CertImportView.svelte`, route `#/certs/import`:

- `PageHeader` "Import Certificate".
- Form: key id, backend select filled from `backends.list`, certificate PEM
  textarea, optional chain PEM textarea (split into blocks on
  `-----END CERTIFICATE-----`).
- Nothing is sent until the PEM checks pass; a non-PEM paste shows an inline error.
- `certs.exists` before `save`; if a certificate exists, a confirm step names the
  key and `save` runs only after Confirm.
- `save`, then `saveChain` when a chain is given; `Alert` for errors; a chain
  failure after a good save says the certificate was stored but the chain was not.

## Nav and router

One added line in each of five places (shared rule with lanes suia-suig and
suii, so merges stay trivial): nav.ts after the Certificates entry
(`requires: certs:enroll`), router.svelte.ts union and path map, App.svelte
import and dispatch.

## Tests

`web/app/test/view3_cert_import.test.ts`: mount, validation, new certificate
(save + chain), overwrite guard (confirm/cancel), errors (save fails, chain fails).
Test commit before the feat commit (ruling 286).

## Checks

sdk/ts build, svelte-auth install, web/app npm ci, the new vitest file, the
web/app suite, svelte-check, vite build, pkg/api/rest -race, sdk/go build,
make lint.

## Out of scope

CertificatesView, `certs.tlsBundle`, CA issuance, Go code, sdk/ts, xkey,
web/desktop, docs/SPEC.md.

## Results

- sdk/ts `npm ci` + `npm run build`: pass (rebuilt tracked dist/ restored, not committed).
- sdk/ts/svelte-auth `npm ci`: pass.
- web/app `npm ci`: pass.
- vitest test/view3_cert_import.test.ts: pass (9 tests).
- web/app `npm test` with `NODE_OPTIONS=--no-experimental-webstorage`: pass (51 files, 421 tests).
- `npm run check`: baseline only (UsersView.svelte:121 and view2_users.test.ts:51, role/roles).
- vite build to /tmp/suih-dist: pass.
- `go test -race` ./pkg/api/rest/ (codec tags): pass.
- sdk/go `go build ./...`: pass.
- `make lint`: pass.
- Note: the feat commit for the view carries a `test(web)` subject (a reused message file); no amend under lane rules.
