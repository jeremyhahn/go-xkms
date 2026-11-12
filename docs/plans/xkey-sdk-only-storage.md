# xkey-sdk-only: pkg/storage and pkg/backend/software through sdk/go (lane sxsdkh)

Row: xkey-sdk-only (docs/SPEC.md:180), issue #2084, PR #2107.

## Gap

SPEC.md:180: xkey reaches go-xkms through sdk/go only; xkey tests that
import root pkg/ move to the sdk/go surface. These test files still import
`go-xkms/pkg/storage` and/or `go-xkms/pkg/backend/software`:

- xkey/cmd/xkey/cmd/password_vault_keyfactor_test.go (storage, software)
- xkey/cmd/xkey/cmd/xkmsd_harness_test.go (storage, software)
- xkey/pkg/gui/services/ssh_service_test.go (storage, software)
- xkey/pkg/gui/services/ssh_profile_service_test.go (storage)
- xkey/pkg/gui/services/ssh_connect_service_test.go (storage)
- xkey/pkg/gui/services/ssh_console_service_test.go (storage)
- xkey/pkg/gui/services/staticpw_vault_keyfactor_test.go (storage, software)
- xkey/test/integration/password/vault_tpm_test.go (storage)

## Name map (sdk/go root package `xkms`)

- `storage.New()`, `pkgstorage.New()`, `storage.NewMemory()` -> `NewStorageMemory()`
- `storage.Backend` -> `StorageBackend`
- `storage.CompareAndSwapper` -> `StorageCompareAndSwapper` (new)
- `storage.CompareAndDeleter` -> `StorageCompareAndDeleter` (new)
- `storage.OpenEngine` / `EngineConfig` / `EngineFile` -> `StorageOpenEngine` / `StorageEngineConfig` / `StorageEngineFile`
- `software.NewBackend` / `software.Config` -> `NewSoftwareBackend` / `SoftwareBackendConfig`

## New sdk/go aliases

`StorageCompareAndSwapper = storage.CompareAndSwapper` and
`StorageCompareAndDeleter = storage.CompareAndDeleter` in sdk/go/storage.go,
proved by sdk/go/storage_compare_test.go (pointer-to-interface identity block
and `TestStorageCompareCapabilities_MemoryBackend`).

## Checks

- sdk/go: `go test -race -run TestStorageCompare .`, `go build ./...`
- xkey: `go build ./...`, vet of cmd/xkey/cmd, pkg/gui/services, test/integration/password (integration tag)
- xkey: `go test -race -run 'SSH|Vault|StaticPW' ./pkg/gui/services/`, `-run 'Vault|RunCA' ./cmd/xkey/cmd/`
- `make lint`

## Results

- done-check after the refactor: no xkey .go file imports pkg/storage or pkg/backend/software.
- sdk/go `go test -race -run TestStorageCompare .`: ok.
- sdk/go `go build ./...`: ok.
- xkey `go build ./...` + vet (cmd/xkey/cmd, pkg/gui/services, test/integration/password with integration tag): ok (first try hit a proxy stream error on modernc.org/libc v1.79.0; the rerun passed).
- xkey `go test -race -run 'SSH|Vault|StaticPW' ./pkg/gui/services/`: ok.
- xkey `go test -race -run 'Vault|RunCA' ./cmd/xkey/cmd/`: ok.
- `make lint`: ok, 0 issues on every module and tag set.

Note: ssh_connect_service_test.go `wedgedStore` now embeds `xkmssdk.StorageBackend`,
so its promoted field is named `StorageBackend` (was `Backend`).
`gofmt -l xkey/cmd/xkey/cmd` also lists four device_* test files this lane did not touch.
