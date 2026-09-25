# PIV Certificate Management — Engineering

> **Status: NORMATIVE** · Feature: `piv` · Module: `go-xkms/xkey` · Last verified: 2026-09-27

## Exported surface — `cmd/xkey/cmd` (piv group)

Types (`cmd/xkey/cmd/piv.go`): `PIVStorageType` (`PIVStorageTypeFile`,
`PIVStorageTypeTPM2`, `PIVStorageTypePKCS11`); `PIVBackendType`
(`PIVBackendSoftware`, `PIVBackendTPM2`, `PIVBackendPKCS11`); `PIVSlot`
(local CLI type — `PIVSlotAuthentication` = `"9a"`, `PIVSlotDigitalSignature`
= `"9c"`, `PIVSlotKeyManagement` = `"9d"`, `PIVSlotCardAuthentication` =
`"9e"`); `CertFormat` (`CertFormatPEM`, `CertFormatDER`); `PIVConfig`
(`Backend`, `StorageType`, `StoragePath`, `TPMDevice`, `PKCS11Library`,
`PKCS11Token`, `PKCS11PIN`, `PKCS11SOPIN`) with `Validate() error`;
`PIVSlotInfo` (`Slot`, `Subject`, `Issuer`, `NotBefore`, `NotAfter`,
`Algorithm`, `Fingerprint`). Exported command: `PIVCmd` (the `piv` parent
cobra command — capitalized so `auth_piv.go`'s sibling `auth login --piv`
tree can reference its default constants).

Sentinel errors (`cmd/xkey/cmd/piv.go`): `ErrPIVInvalidBackend`,
`ErrPIVInvalidStorageType`, `ErrPIVStoragePathRequired`,
`ErrPIVInvalidSlot`, `ErrPIVSlotRequired`, `ErrPIVCertFileRequired`,
`ErrPIVCertificateNotFound`, `ErrPIVInvalidFormat`,
`ErrPIVStorageCreationFailed`, `ErrPIVCertificateReadFailed`,
`ErrPIVCertificateParseFailed`, `ErrPIVStoreFailed`, `ErrPIVDeleteFailed`,
`ErrPIVExportFailed`, `ErrPIVListFailed`, `ErrPIVOutputFileRequired`,
`ErrPIVTPMDeviceRequired`, `ErrPIVPKCS11LibraryRequired`,
`ErrPIVPKCS11TokenRequired`. Build-tag stub errors:
`ErrPIVTPM2BuildTagRequired` (`piv_tpm2_stub.go`),
`ErrPIVPKCS11BuildTagRequired` (`piv_pkcs11_stub.go`).

Functions: `validatePIVSlot(slot string) (xkms.PIVSlot, error)`,
`defaultPIVStorageTypeForBackend(backend PIVBackendType) PIVStorageType`
(software→file, tpm2→tpm2, pkcs11→pkcs11), `buildPIVConfig() *PIVConfig`
(reads bound Viper flags), `createPIVStorage(cfg *PIVConfig, logger
*slog.Logger) (xkms.PIVCertificateStorage, error)`,
`ensurePIVInitialized(pivCfg *PIVConfig, logger *slog.Logger) error`
(idempotent SDK manager init + store registration; also wires the PKCS#11
key backend when `Backend == PIVBackendPKCS11`).

`piv_csr.go`: `pivCSRCmd` (`csr <slot>`) — builds a CSR for a slot's
existing key from `--cn` (required), `--organization`,
`--organizational-unit`, `--country`, `--province`, `--locality`,
`--san`/`--san-dns`/`--san-ip`/`--san-uri` (repeatable), `--output`/`-o`.

`piv_generate.go`: `pivGenerateCmd` (`generate <slot>`) — generates a new
key pair with `--algorithm`/`-a` (`ECCP256`, `ECCP384`, `Ed25519`,
`RSA2048`, `RSA4096`; default `ECCP256`), `--pin-policy` (`never`, `once`,
`always`; default `once`), `--touch-policy` (`never`, `cached`, `always`;
default `never`), `--force`/`-f`, `--output-format` (`self-signed`,
`public-key`, `csr`, `ca-signed`; default `self-signed`), `--subject`,
`--organization`, `--country`, `--validity-days`, `--output`/`-o`.

`piv_import.go`: `pivImportCmd` (`import <slot> <cert-file>`) — `--verify`
(default `true`, checks the certificate's public key matches the slot's),
`--force`/`-f` (import even if verification fails).

`piv_pkcs11.go` (build tag `pkcs11`) / `piv_pkcs11_stub.go` (`!pkcs11`):
`createPKCS11PIVStorage`, `ensurePKCS11Backend`,
`ensurePKCS11BackendResolver`, `pivPINSecret`.

`piv_tpm2.go` (build tag `tpm2`) / `piv_tpm2_stub.go` (`!tpm2`):
`createTPM2PIVStorage`.

`auth_piv.go`: `buildAuthPIVConfig(cmd *cobra.Command) *PIVConfig` — builds a
`PIVConfig` for `xkey auth login --piv` from that command's own `--backend`
flag plus the same Viper-bound storage settings the `piv` group uses;
errors `ErrAuthPIVSignerCreationFailed`, `ErrAuthPIVLoginFailed`,
`ErrAuthPIVClientCreationFailed`.

## Exported surface — SDK types this feature consumes

Re-exported from `sdk/go` (`github.com/jeremyhahn/go-xkms/sdk/go`, package
alias `xkms`): `PIVSlot`, `ValidatePIVSlot`, `PIVSlotName`,
`PIVPrimarySlots`, `PIVCertFormat` (`PIVFormatPEM`, `PIVFormatDER`),
`PIVCertificateStorage` (`sdk/go/pivcert.go`, aliasing `pkg/pivcert`),
`PIVFileStorageConfig`, `NewFileStorageBackend`, `NewPIVFileBackend`,
`PIVManagerConfig` (`sdk/go/xkms_service.go`, aliasing `pkg/xkms`),
`InitializePIV`, `RegisterPIVStore`. See
[docs/piv-smartcard](../../../docs/piv-smartcard/engineering.md) for these
types' own contract; this page only records that xkey depends on them,
not their internals.

## Exported surface — `pkg/gui/services/piv_service.go`

`PIVService` with `SetContext`, `SetClient` (SDK `transport.Client`),
`SetLocalEnabled`, `SetLocalBackend`, `SetCCIDNotifier`, `SetRegistry`
(`backendregistry.Registry`), `SetBackendTypeFn`, `SetLocalCAAvailable`,
`SetBackend`, `GetBackend`, `IsConnected`, `GetCAAvailability() map[string]bool`,
`GetSlots() ([]PIVSlot, error)`, `GetCertificate(slot string)
(*PIVCertificate, error)`, `GenerateKey(slot, algorithm string)
(*PIVGenerateKeyResult, error)`, `GenerateKeyAdvanced(opts
PIVGenerateOptions) (*PIVGenerateAdvancedResult, error)`,
`ImportCertificate(slot string, certPEM []byte) error`,
`ExportCertificate(slot string) (string, error)`, `ExportPublicKey(slot
string) (string, error)`, `GenerateCSR(slot string, subject *CSRSubject)
(string, error)`, `DeleteCertificate(slot string) error`,
`SelfSignExistingKey(slot, commonName string, validityDays int) (string,
error)`.

## Invariants

- `PIVConfig.Validate()` refuses an unknown `Backend` or `StorageType`, and
  refuses a storage-type-specific requirement that is missing (`StoragePath`
  for file, `TPMDevice` for tpm2, `PKCS11Library`+`PKCS11Token` for pkcs11)
  before any storage backend is constructed.
- `createPIVStorage` is only reached after `Validate()` succeeds
  (`ensurePIVInitialized`, `cmd/xkey/cmd/piv_generate.go`).
- `ensurePIVInitialized` is safe to call once per process per backend; the
  underlying SDK manager init is `sync.Once`-guarded, and re-registering an
  already-registered store for the same backend name is a no-op path, not
  an error.
- `piv import --verify` (default on) compares the imported certificate's
  public key against the slot's existing key before accepting it;
  `--force` is required to import a mismatched certificate anyway.

## Configuration

**There is no config-file or environment-variable surface for `piv`
settings**, despite the legacy `piv/README.md`'s claim of a `PIV_BACKEND`
family of environment variables. `PIVCmd`'s persistent flags are bound with
`viper.BindPFlag` only (`piv.backend`, `piv.storage`, `piv.storage_path`,
`piv.tpm_device`, `piv.pkcs11_library`, `piv.pkcs11_token`,
`piv.pkcs11_pin`, `piv.pkcs11_so_pin`), and the package-level `viper`
singleton these flags are bound on is never pointed at a config file
(`ReadInConfig`) and never has `AutomaticEnv` enabled anywhere in
`cmd/xkey/cmd`. `buildPIVConfig`'s `viper.GetString` calls therefore only
ever return the CLI flag's current value — set `--backend`,
`--piv-storage`, etc. on the command line.

| Flag | Default |
|---|---|
| `--backend` | `software` |
| `--piv-storage` | (matches backend) |
| `--storage-path` | `./data/piv` |
| `--tpm-device` | `/dev/tpmrm0` |
| `--pkcs11-library` | `/usr/lib/softhsm/libsofthsm2.so` |
| `--pkcs11-token` | (none) |
| `--pkcs11-pin` | (none) |
| `--pkcs11-so-pin` | (none) |

## Tests

`cmd/xkey/cmd/piv_test.go`, `piv_tpm2_test.go`,
`piv_tpm2_simulator_test.go` (build tag `tpm_simulator`); GUI-side
`pkg/gui/services/piv_service_test.go`, `piv_service_backend_test.go`,
`piv_cert_absent_test.go`; integration coverage under
`test/integration/piv/`.
