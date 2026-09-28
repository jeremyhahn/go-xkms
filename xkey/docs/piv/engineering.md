# PIV Certificate Management — Engineering

> **Status: NORMATIVE** · Feature: `piv` · Module: `go-xkms/xkey` · Last verified: 2026-09-28

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
(software→file, tpm2→tpm2, pkcs11→pkcs11), `buildPIVConfig(cmd
*cobra.Command) (*PIVConfig, error)` (flag, then the unified xkey config,
then the backend-matched default -- see Configuration below; `cmd` may be
nil), `createPIVStorage(cfg *PIVConfig, logger
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

`auth_piv.go`: `buildAuthPIVConfig(cmd *cobra.Command) (*PIVConfig, error)` —
builds a `PIVConfig` for `xkey auth login --piv` from that command's own
`--backend` flag plus the same unified-config-resolved storage settings the
`piv` group uses (see Configuration below); errors
`ErrAuthPIVSignerCreationFailed`, `ErrAuthPIVLoginFailed`,
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

**Fixed in go-xkms#871.** Before it, `PIVCmd`'s persistent flags were bound
with `viper.BindPFlag` only, and the package-level `viper` singleton they
were bound on was never pointed at a config file and never had `AutomaticEnv`
enabled anywhere in `cmd/xkey/cmd` -- so `buildPIVConfig`'s `viper.GetString`
calls only ever returned the CLI flag's current value, despite `piv.backend`
etc. looking like config keys.

`buildPIVConfig` (`cmd/xkey/cmd/piv.go:603-639`) now resolves six of the
eight settings through `xkeyconfig.PIVConfig` (`pkg/config/config.go:93-107`):
an explicit flag wins, then the loaded config's `piv.<field>` value -- which
itself already merges the matching `XKEY_PIV_*` environment variable and the
config file's `piv:` section via `pkg/config/load.go`'s
`registerConfigKeys` -- then the backend-matched default. `pivConfigString`
and `pivStorageOverride` (`piv.go:527-594`) implement the precedence, mirroring
`resolveXKMSdURL` (`xkmsd_client.go:181-192`).

| Flag | Default | Also settable via |
|---|---|---|
| `--backend` | `software` | `piv.backend` / `XKEY_PIV_BACKEND` |
| `--piv-storage` | (matches backend) | `piv.storage` / `XKEY_PIV_STORAGE` |
| `--storage-path` | empty: resolved by `resolvePIVStoragePath` (`xkey/cmd/xkey/cmd/piv.go`) to `<xkey-home>/data/piv` | `piv.storage_path` / `XKEY_PIV_STORAGE_PATH` |
| `--tpm-device` | `/dev/tpmrm0` | `piv.tpm_device` / `XKEY_PIV_TPM_DEVICE` |
| `--pkcs11-library` | `/usr/lib/softhsm/libsofthsm2.so` | `piv.pkcs11_library` / `XKEY_PIV_PKCS11_LIBRARY` |
| `--pkcs11-token` | (none) | `piv.pkcs11_token` / `XKEY_PIV_PKCS11_TOKEN` |
| `--pkcs11-pin-stdin` | `false` | `XKEY_PIV_PKCS11_PIN` only (never a config key) |
| `--pkcs11-so-pin-stdin` | `false` | `XKEY_PIV_PKCS11_SO_PIN` only (never a config key) |

The PKCS#11 PIN and Security Officer PIN deliberately have no config-file or
generic-environment surface: they resolve exclusively through
`resolvePIVPKCS11Secret` (`piv.go:519-533`), which is `pivPKCS11PINSource`/
`pivPKCS11SOPINSource` (`piv.go:57-69`) resolved by `pinSource.resolve`
(`pin_input.go`) when `cmd` declares `--pkcs11-pin-stdin`, or the bare
environment variable otherwise. There is no `--pkcs11-pin` value flag, for
the same reason `pin_input.go` gives for having no `--pin` value flag
(go-xkms#272): a value on the command line is visible to every other process
on the host via `ps`. `PIVCmd` and its descendants (`list`, `show`, `store`,
`delete`, `export`, `status`, `import`, `generate`, `csr`) declare the stdin
flags as persistent flags; `cert request`/`show`/`export`, `device listen`,
`provision` and `auth login --piv` are sibling command trees that call
`buildPIVConfig`/`buildAuthPIVConfig` too but declare none of `piv`'s flags,
so on those commands every setting resolves from the config/environment only,
and the PKCS#11 PIN resolves from its environment variable only.

## Tests

`cmd/xkey/cmd/piv_test.go`, `piv_tpm2_test.go`,
`piv_tpm2_simulator_test.go` (build tag `tpm_simulator`); GUI-side
`pkg/gui/services/piv_service_test.go`, `piv_service_backend_test.go`,
`piv_cert_absent_test.go`; integration coverage under
`test/integration/piv/`.
