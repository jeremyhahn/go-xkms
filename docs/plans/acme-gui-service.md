# xkey acme: GUI ACMEService (Go side)

Row: acme (docs/SPEC.md:155), issue #2085, lane sacmeg.

## Objective

The `xkey acme` namespace is "in CLI and GUI". The CLI verbs (account,
enroll, endorse, renew, revoke) are on the branch. This slice adds the Go
side of the GUI: a Wails-bound `services.ACMEService`, on a client factory
moved out of package cmd so both front ends share one copy.

## Moved code (xkey/pkg/gui/services/acme_client.go)

- `ACMEClient` interface (RegisterAccount, UpdateAccount, DeactivateAccount,
  RevokeCertificate, RenewCertificate, EnrollDevice,
  RequestEndorsementKeyCertificate, Close).
- `ACMEClientOptions`, `NewACMEClient` (sdk/go client, with timeout).
- `LoadACMEAccountKey`, `ParseACMERevocationReason`, `LoadCertificatePEM`.
- The CLI keeps aliases: `acmeClient`, `acmeClientOptions`,
  `newACMEClientFunc = services.NewACMEClient`; CLI tests unchanged.

## ACMEService (xkey/pkg/gui/services/acme_service.go)

- `NewACMEService`, `SetContext`; injectable `newClient` factory.
- `RegisterAccount(conn, contact)`, `UpdateAccount(conn, contacts)`,
  `DeactivateAccount(conn, confirm)` (refuses without confirm),
  `RevokeCertificate(conn, certPath, reason)`,
  `RenewCertificate(conn, req)` returning the PEM certificate.
- Types: `ACMEConnection`, `ACMEAccountInfo`, `ACMERenewRequest`.
- Each method recovers panics and closes its client; no key material is
  returned or logged.

## Binding

- app.go: field, constructor, bindings list, SetContext on startup.
- app_window_test.go asserts the service is bound.
- wailsjs regenerated with `make generate-wailsjs`; `make check-wailsjs`.

## Slices

1. Test commit: acme_service_test.go (fake client) + binding assert.
2. Feat commit: acme_client.go, acme_service.go, CLI switch, app wiring,
   generated bindings.
3. Docs commit: xkey/docs/acme/README.md status.

## Out of scope

- The Svelte view (xkey/frontend/src).
- GUI enroll/endorse (need the GUI TPM through TPMAccessor).

## Results
