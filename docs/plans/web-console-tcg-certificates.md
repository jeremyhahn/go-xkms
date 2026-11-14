# Web console: TCG Certificates view (epic #1443, lane suik)

## Gap

The CA serves `POST /api/v1/ca/tcg/ek`, `/ca/tcg/ak` and `/ca/tcg/sign-csr`
(pkg/api/rest/routes.go, permission certs:issue, only with a CA), and the TS
SDK has `ca.issueEK`, `ca.issueAK` and `ca.signTCGCSR`, but the console has no
screen for them: CaView covers CSR signing, revocation and CRLs only.

## The view

- `web/app/src/views/TcgCertsView.svelte`, `PageHeader` "TCG Certificates".
- Three tabs: EK, AK, TCG CSR. Each is a form with common name, optional
  organization and tenant id, and a key (PEM or Base64) or CSR (Base64) textarea.
- EK/AK result: serial number, decoded certificate PEM in a monospace block,
  a download button (`downloadText`).
- TCG CSR result: IAK and IDevID certificates as Base64 DER, a download each.
- Errors in an `Alert`; input that is neither PEM nor Base64 is an inline error.
- `ca.enrollDevice` is out of scope (its response carries the
  credential-activation secret, which the console must not render).

## Route and nav

- Route `#/ca/tcg` (`caTcg`), nav entry "TCG Certificates" after Certificate
  Authority, capability `ca`, requires certs:issue.
- One added line per place in nav.ts, router.svelte.ts (union, path map) and
  App.svelte (import, dispatch), shared rule with lanes suia-suii and suij,
  suil, suim, suin, suio, so their merges stay trivial.

## Tests

`web/app/test/view3_tcg_certs.test.ts`: tabs and no call on mount; EK issue
(PEM encoded, Base64 as is, optional fields undefined, result rendered); AK
issue; TCG CSR sign with both downloads and the invalid-input error;
validation (Issue disabled) and a rejected call showing an error Alert.

## Checks

sdk/ts build, svelte-auth and web/app npm ci, the new vitest file, the whole
web/app suite (NODE_OPTIONS=--no-experimental-webstorage), svelte-check, vite
build, pkg/api/rest -race, sdk/go build, make lint.

## Results

- sdk/ts build, svelte-auth and web/app npm ci: pass (the rebuilt, tracked sdk/ts/dist restored, not committed).
- vitest test/view3_tcg_certs.test.ts: 8/8 pass.
- vitest whole web/app suite (NODE_OPTIONS=--no-experimental-webstorage): 51 files, 420 tests pass.
- svelte-check: only the baseline errors (src/views/UsersView.svelte:121 and test/view2_users.test.ts:51, role/roles).
- vite build: pass.
- go test -race ./pkg/api/rest/: pass.
- sdk/go go build ./...: pass.
- make lint: pass.
