# Configuration

## Two config types

| Type | Where | Purpose |
|---|---|---|
| `config.PKCS11Config` | `pkg/config/config.go:791` | the four fields exposed in `xkmsd.yaml` |
| `pkcs11.Config` | `pkg/backend/pkcs11/config.go:32` | the full library-level configuration |

`pkg/server/backend_pkcs11.go` maps the first onto the second. Anything not in
the YAML is only reachable by constructing `pkcs11.Config` directly (library
embedding, xkey, tests).

## Daemon YAML

```yaml
  # pkcs11:
  #   enabled: true
  #   library: "/usr/lib/softhsm/libsofthsm2.so"
  #   token: "xkms"
  #   pin: ""
```

(`configs/xkmsd.yaml`, commented out by default — the zero-privilege preset
aborts startup for any enabled backend that cannot reach its device.)

```go
type PKCS11Config struct {
	Enabled bool   `yaml:"enabled"`
	Library string `yaml:"library"`
	Token   string `yaml:"token"`
	Pin     string `yaml:"pin"`
}
```

Validation: with `enabled: true`, an empty `library` fails config validation
with `PKCS11 library is required`. `ListEnabledBackends()` reports `pkcs11`.

Environment override — only the library path has one:

```go
	// PKCS#11 settings
	if pkcs11Lib := os.Getenv("PKCS11_LIBRARY"); pkcs11Lib != "" && cfg.Backends.PKCS11 != nil {
		cfg.Backends.PKCS11.Library = pkcs11Lib
	}
```

## `pkcs11.Config` fields

| Field | YAML | Required | Meaning |
|---|---|---|---|
| `CN` | `cn` | no | Identifier for logs. The daemon sets `"pkcs11-backend"`. |
| `Library` | `library` | **yes** | Path to the Cryptoki `.so`. Must exist — `Validate()` stats it and returns `ErrLibraryNotFound`. |
| `LibraryConfig` | `config` | no | Vendor config file path (for SoftHSM, the `softhsm2.conf`). |
| `PIN` | `pin` | for use | User PIN (`CKU_USER`). Minimum 4 characters when set. |
| `SOPIN` | `so-pin` | PIV / init | Security Officer PIN or YubiKey management key. Minimum 4 characters when set. |
| `PlatformPolicy` | `platform-policy` | no | Platform policy flag carried on the config. |
| `Slot` | `slot` | no | `*int`. Standard tokens: physical slot number. YubiKey PIV: the PIV slot (`0x9a`, `0x9c`, `0x9d`, `0x9e`). |
| `TokenLabel` | `label` | **yes** | Token label; `Validate()` rejects an empty one. Preferred over `Slot` — slot numbers are not stable across reboots. |
| `KeyStorage` | — | **yes** | `storage.Backend` for key **metadata only**. Key material stays in the HSM. |
| `CertStorage` | — | **yes** | `storage.Backend` for certificate material. |
| `Tracker` | — | no | `types.AEADSafetyTracker`. Defaults to `backend.NewMemoryAEADTracker()`; production deployments should supply a persistent one. |
| `SessionPoolSize` | `session-pool-size` | no | Pre-opened sessions. `<= 0` falls back to `DefaultSessionPoolSize` (8). |

`Validate()` enforces: library path set and present on disk, token label set,
PIN/SO PIN length, and both storage backends non-nil.

Convenience predicates: `IsSoftHSM()` (path contains `libsofthsm`) and
`IsYubiKeyPIV()` (path contains `libykcs11`/`ykcs11`). `String()` masks both
PINs.

## Storage wiring

The daemon creates two namespaced stores and hands them over:

```go
	pkcs11Backend, err := pkcs11.NewBackend(&pkcs11.Config{
		CN:          "pkcs11-backend",
		Library:     s.config.Backends.PKCS11.Library,
		TokenLabel:  s.config.Backends.PKCS11.Token,
		PIN:         s.config.Backends.PKCS11.Pin,
		KeyStorage:  keyStorage,
		CertStorage: certStorage,
	})
```

`keyStorage` is `pkcs11/keys`, `certStorage` is `pkcs11/certs`, both from
`s.createStorage(...)`. `KeyStorage` receives only JSON metadata — the only
writer is `ImportKey`, which records handle, CN, key type, algorithm, store
type and an `imported: true` marker.

Certificates can additionally live inside the token; see
`CertStorageConfig` (`cert_config.go`) with modes `External` (default),
`Hardware`, and `Hybrid`. Hybrid and External both require `ExternalStorage`;
Hardware and Hybrid both require `EnableHardwareStorage`.

## PIN and credential handling

**As shipped, the user PIN is read literally from the daemon config**
(`pkg/server/backend_pkcs11.go:44` → `config.PKCS11Config.Pin`). Unlike the
barrier passphrase and CA key passwords, it is **not** run through the
`credential://` resolver or `${ENV}` expansion, and there is no
`XKMS_PKCS11_PIN` override for the backend (the `XKMS_RNG_PKCS11_PIN` variable
belongs to the RNG subsystem, not this backend). Practical consequences:

- Treat `xkmsd.yaml` as a secret file (`0600`, root-owned) whenever
  `backends.pkcs11.pin` is populated.
- Prefer a token whose PIN policy tolerates being supplied once at boot, and
  rotate it through the vendor tooling rather than through xkms.
- Embedders that need a resolved secret should construct `pkcs11.Config`
  themselves and populate `PIN` from their own resolver before calling
  `NewBackend`.

The project rule that node-local key material passes through the barrier is
satisfied differently here from the software/pkcs8 backends: **there is no
node-local key material to seal.** Private keys are created by `C_GenerateKeyPair`
inside the token and never exist outside it (see [security.md](security.md)).
The barrier protects xkms's own state; the token's PIN policy and the device
boundary protect the keys.

## SoftHSM helper

`SoftHSMConfig(tokenDir)` renders a working `softhsm2.conf` (file object store,
`umask 0077`, all mechanisms enabled, `reset_on_fork = false`) for tests and
first-time setup.
