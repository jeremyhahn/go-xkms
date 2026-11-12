# xkey-sdk-only: pkg/xkms through sdk/go (lane sxsdkj, row 2084)

## Gap

docs/SPEC.md:180: xkey reaches go-xkms through sdk/go only. Five xkey test
files still import `github.com/jeremyhahn/go-xkms/pkg/xkms` (as `pkgxkms`):

- xkey/cmd/xkey/cmd/password_vault_passkey_test.go
- xkey/cmd/xkey/cmd/password_vault_keyfactor_test.go
- xkey/cmd/xkey/cmd/xkmsd_harness_test.go
- xkey/cmd/xkey/cmd/piv_software_test.go
- xkey/pkg/gui/services/staticpw_vault_keyfactor_test.go

## Name map (pkg/xkms -> sdk/go)

- `Backend` -> `ServiceBackend`
- `XKMSService` -> `XKMSService`
- `BackendConfig` -> `ServiceBackendConfig`
- `New` -> `NewServiceBackend`
- `Reset` -> `Reset`
- `ResetPIV` -> `XKMSResetPIV`
- `PivSlotCN` -> `PivSlotCN` (new alias in sdk/go/xkms_service.go)

## Tests

- sdk/go/xkms_reexport_test.go `TestReexport_PivSlotCN`: the alias matches
  `pkgxkms.PivSlotCN` for slots 9a/9c/9d/9e and one unknown slot.

## Checks

- sdk/go TestReexport_ test, sdk/go build, xkey build + vet, the cmd and
  gui/services test runs, make lint.

## Results

- sdk/go `go test -race -run TestReexport_ .`: pass.
- sdk/go `go build ./...`: pass.
- xkey `go build ./...` + `go vet` on cmd/xkey/cmd and pkg/gui/services: pass.
- xkey cmd tests (PasswordVault|VaultPKCS11Token|LoginPKCS11Backend|SoftwarePIV|XKMSd): pass.
- xkey gui/services tests (KeyFactor|BrowserBridge|ConsoleOriginAllowed): pass.
- `make lint`: pass (0 issues on every module and tag set).
- No xkey file imports pkg/xkms any more; gofmt reported nothing on the edited files.
