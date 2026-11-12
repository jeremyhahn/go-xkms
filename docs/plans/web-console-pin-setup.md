# Web console: PIN Setup view (lane suii, epic #1443, CA m2581 UI slice 9)

## Gap

The REST API serves `POST /api/v1/pin/so/set`, `/pin/user/set` (pin:write),
`/pin/so/verify` and `/pin/user/verify` (pin:read), and the TS SDK exposes
`pin.setSO`, `pin.setUser`, `pin.verifySO` and `pin.verifyUser`. The console's
PinView calls only `lockoutStatus`, `changeSO`, `changeUser` and
`resetLockout`, so a fresh deployment cannot set its initial PINs, and an
operator cannot check a PIN, without xkmsctl.

## The view

`web/app/src/views/PinSetupView.svelte`, route `#/pin/setup`, `PageHeader`
"PIN Setup", three cards:

- Set SO PIN: current (factory default) SO PIN, new, confirm -> `pin.setSO`.
- Set user PIN: SO PIN, new user PIN, confirm -> `pin.setUser`.
- Verify PIN: SO / user choice and a PIN -> `pin.verifySO` / `pin.verifyUser`;
  a failure warns that it counts toward the lockout.
- A link to `#/pin` for change, lockout and reset.

PINs are secrets: password inputs with `autocomplete="off"`, cleared after
every call, never in a toast, alert or rendered text.

## Nav and routing

Nav entry "PIN Setup" (`pinSetup`, `/pin/setup`, icon KeyRound, requires
pin:write) directly after the PIN entry. Lanes suia-suig and suih
(Certificate Import) touch the same files, so this lane adds exactly one line
per place: one in nav.ts, two in router.svelte.ts (union, path map), two in
App.svelte (import, dispatch), and changes no other line there.

## Tests

`web/app/test/view3_pin_setup.test.ts`: set SO (call shape, toast without
PINs, inputs cleared, mismatch calls nothing), set user (same), verify (SO and
user, success and rejection, input cleared), error alert with the server
message and no PIN in text or toasts, every PIN input `type="password"`.

## Checks

sdk/ts build, svelte-auth install, web/app npm ci, the new vitest file, the
whole web/app suite, svelte-check, vite build, `pkg/api/rest` -race tests,
sdk/go build, make lint.

Out of scope: PinView and its test, lockout/change flows, PIV, Go code,
sdk/ts, xkey, web/desktop, docs/SPEC.md.

## Results

Results to follow.
