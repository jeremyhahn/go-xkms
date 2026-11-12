# Web console: PIV Slots view (epic #1443, lane suif)

## Gap

xkms stores, reads, exports and deletes a PIV slot's certificate and makes a
CSR signed by the slot key (`/api/v1/piv/slots/...`, TS SDK
`getSDKClient().piv`), but the console only lists slots (PivView calls
`listSlots`). An operator cannot see, install or remove a slot certificate,
or get a CSR for a slot key, without xkmsctl.

## The view

`web/app/src/views/PivSlotsView.svelte`, route `#/piv/slots`:

- `PageHeader` "PIV Slots"; a slot table (slot, name, key and certificate
  presence as `StatusBadge`s, subject, algorithm, expiry) and row actions.
- View (slot with a certificate): `getCertificate(slot, backend, "pem")`,
  the decoded PEM in a `Modal`, with Export (`exportCertificate(slot,
  backend, "pem")`).
- Install: a `Modal` with a PEM textarea, `storeCertificate(slot, {backend,
  certificate: btoa(pem), format: "pem"})`; Install disabled while empty.
- Delete: a confirm `Modal` naming the slot, then `deleteCertificate(slot,
  backend)`.
- CSR (slot with a key): subject fields, `generateCSR(slot, {backend,
  subject, ...})` with empty optional fields omitted; the decoded CSR PEM.
- `Alert` on a list load error; error toasts on failed actions.

## Nav and route

Nav entry "PIV Slots" (`/piv/slots`, icon FileBadge, requires `piv:read`)
directly after the PIV entry in the Security section. Lanes suia-suie touch
nav.ts, router.svelte.ts and App.svelte too: this lane adds exactly one line
in each of the five places (union, path map, import, dispatch, nav) and
changes no other line there, so merges stay trivial.

## Tests

`web/app/test/view3_piv_slots.test.ts` (committed before the view): mount,
view, install, delete (confirm and cancel), CSR, and errors (list and store).

## Checks

sdk/ts build, svelte-auth install, web/app npm ci, the new vitest file, the
whole web/app suite (NODE_OPTIONS=--no-experimental-webstorage), svelte-check,
vite build, `go test -race ./pkg/api/rest/`, sdk/go build, `make lint`.
Baseline failures on main: view1/view2 svelte-auth tests, svelte-check at
UsersView.svelte:121.

Results to follow.

## Follow-ups (out of scope)

Key generation and certificate import on a slot, PIV login, a link from
PivView to this view.
