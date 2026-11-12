# xkey acme: GUI enroll and endorse on the shared TPM (lane sacmei)

Row (docs/SPEC.md:155): the `xkey acme` namespace (account, enroll, endorse,
renew, revoke) in CLI and GUI, a thin caller of `pkg/acme/client` through
`sdk/go`. Issue #2085.

## Prior lanes

- sacmea, sacmee, sacmef: the whole CLI (xkey/cmd/xkey/cmd/acme*.go).
- sacmeg: `services.ACMEService` (account, revoke, renew) on the shared client
  factory, plan docs/plans/acme-gui-service.md.
- sacmeh: views/ACME.svelte (Connection, Account, Revoke, Renew cards) and
  `services.LoadACMECSR`, plan docs/plans/acme-gui-view.md.

Both plans left GUI enroll and endorse open: they need the GUI TPM through
the shared `TPMAccessor`.

## This slice

1. Tests first (ruling 286): Go cases in acme_service_test.go (config mapping,
   PEM output, validation before TPM/client use, release on error, no TPM
   source, NewACMETPMSource over the accessor) and vitest cases in
   ACME.test.ts (Enroll, device-attest-01 PCRs, disabled buttons, EK request,
   error alert).
2. Feat: `ACMEService.EnrollDevice` and `EndorseDevice`, `SetTPMSource`,
   `NewACMETPMSource` over the shared TPMAccessor (never closes the adapter,
   only releases the accessor), the one app.go `SetTPMSource` call, the
   backend.ts types, the Device enrollment card in ACME.svelte, and the
   bindings regenerated with `make generate-wailsjs`.
3. Docs: xkey/docs/acme/README.md status.

## Out of scope

CLI changes, xkey/frontend/dist rebuild, pkg/acme/client, sdk/go.

## Results

- npm ci, npm run check --fail-on-warnings, vitest ACME.test.ts (14), npm test (102), vite build to /tmp: pass.
- go build ./... and go test -tags "production codec_json" -run ACME ./pkg/gui/services/: pass.
- go test ./cmd/xkey/cmd/... (codec_cbor codec_json codec_msgpack): timed out at 10 min in the unrelated TestPINCommands_AddressTheWizardDataDirectory (blocked in fsync on the loaded lane disk); -run ACME on the same package: pass.
- make check-wailsjs: pass (bindings match the Go services).
- make lint: pass (0 issues).
- Port: sdkacme.ACMEEnrollmentConfig.Port is a string, so the service formats a positive port and leaves zero to the client default.
