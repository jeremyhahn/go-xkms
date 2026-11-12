# Plan: xkey acme GUI view (lane sacmeh, issue #2085)

Row (docs/SPEC.md:155): the `xkey acme` namespace "(account, enroll, endorse,
renew, revoke) in CLI and GUI, a thin caller of `pkg/acme/client` through
`sdk/go`".

## Prior lanes

- sacmea, sacmee, sacmef: the whole CLI (account, revoke, renew, enroll, endorse).
- sacmeg: the Wails-bound Go `services.ACMEService` (RegisterAccount,
  UpdateAccount, DeactivateAccount, RevokeCertificate, RenewCertificate), the
  shared client factory in acme_client.go and the wailsjs bindings
  (docs/plans/acme-gui-service.md).

## This slice

1. Test commit: xkey/frontend/src/views/ACME.test.ts (vitest, mocked
   `window.go.services.ACMEService`): register sends the connection built from
   the form and shows uri/status; update contacts splits on commas; deactivate
   only after confirm (cancel calls nothing); revoke sends the chosen reason
   (default `unspecified`); renew sends the request and shows the PEM, a
   rejected call shows an alert and no PEM; actions disabled without directory
   URL or account key path; "No backend connection" without `window.go`.
   Go: TestACMEService_RenewCertificate_CSRPath pins the CSR loader.
2. Feat commit: backend.ts ACME types, views/ACME.svelte (Connection, Account,
   Revoke, Renew cards), App.svelte nav entry `acme` (store section).
3. Refactor commit: fold `loadACMECSR` and `loadCSR` into one exported
   `services.LoadACMECSR` in acme_client.go, used by the GUI service and the CLI.
4. Docs commit: xkey/docs/acme/README.md Status.

## Out of scope

- GUI enroll/endorse (need the GUI TPM through TPMAccessor): a later slice.
- dist rebuild, wailsjs binding changes (no bound signature changes).

## Results
