- **The deprecated `BackendFactory` seam is deleted from `cmd/xkmsctl`.**
  With `migrate` and `tls get` both moved off it, `Config.BackendFactory`,
  `BackendFactory` (the type), `Config.CreateBackend()` and
  `Config.CreateCertStorage()` (dead once `tls get` stopped building a local
  cert store) are removed from `cmd/xkmsctl/config.go`, along with their
  dedicated tests in `config_test.go` and the now-dead sentinel errors in
  `errors.go` (`ErrCreateBackendFailed`, `ErrCreateCertStorageFailed`,
  `ErrCreateDestinationBackendFailed`, `ErrCreateMigrationPlanFailed`,
  `ErrCreateMigratorFailed`, `ErrCreateSoftwareBackendFailed`,
  `ErrCreateSourceBackendFailed`, `ErrCreateStorageBackendFailed`,
  `ErrFromToFlagsRequired`, `ErrKeyIDFromToFlagsRequired`,
  `ErrInvalidKeyParameters`, `ErrMigrationFailed`, `ErrValidationFailed`,
  `MigrationResultError`). `ClientFactory` is now the only client-injection
  seam in xkmsctl; every command reaches xkmsd through the SDK `Client`.
