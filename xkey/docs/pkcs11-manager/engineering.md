# PKCS#11 Module/Token Manager — Engineering Contract

> **Status: NORMATIVE** · Feature: `pkcs11-manager` · Module: `go-xkms/xkey` · Last verified: 2026-09-23

## Exported surface — `xkey/pkg/gui/services`

```go
type PKCS11Service struct { /* unexported fields */ }

func NewPKCS11Service() *PKCS11Service

func (s *PKCS11Service) SetContext(ctx context.Context)
func (s *PKCS11Service) SetConnectHook(fn PKCS11ConnectHook)
func (s *PKCS11Service) SetDisconnectHook(fn PKCS11DisconnectHook)
func (s *PKCS11Service) SetManager(m xkms.PKCS11Manager)
func (s *PKCS11Service) GetManager() xkms.PKCS11Manager
func (s *PKCS11Service) SetRegistry(r backendregistry.Registry)
func (s *PKCS11Service) IsAvailable() bool
func (s *PKCS11Service) Close() error

func (s *PKCS11Service) ProbeModules() []ProbeResult
func (s *PKCS11Service) RegisterModule(libraryPath, displayName string) (string, error)
func (s *PKCS11Service) RegisterModuleFromConfig(moduleID, libraryPath, displayName string) (string, error)
func (s *PKCS11Service) UnregisterModule(moduleID string) error
func (s *PKCS11Service) RefreshSlots(moduleID string) ([]PKCS11SlotInfo, error)
func (s *PKCS11Service) GetModule(moduleID string) (*PKCS11ModuleInfo, error)
func (s *PKCS11Service) ListModules() []PKCS11ModuleInfo
func (s *PKCS11Service) ListTokens() []PKCS11TokenInfo
func (s *PKCS11Service) GetModuleSlots(moduleID string) ([]PKCS11SlotInfo, error)
func (s *PKCS11Service) InitializeToken(moduleID string, slotID uint, label, soPin, userPin string) error
func (s *PKCS11Service) TestConnection(libraryPath string, slotID uint, userPIN string) error
func (s *PKCS11Service) ProbeSlots(libraryPath string) ([]PKCS11SlotInfo, error)
func (s *PKCS11Service) Connect(moduleID string, slotID uint, userPin, soPin string) error
func (s *PKCS11Service) Disconnect(moduleID string, slotID uint) error
func (s *PKCS11Service) GetConnection(moduleID string, slotID uint) (*PKCS11ConnectionInfo, error)
func (s *PKCS11Service) ListConnections() []PKCS11ConnectionInfo
```

`PKCS11Service` is built entirely on `xkms.PKCS11Manager` (`sdk/go`, an alias
for `go-xkms/pkg/pkcs11/manager.Manager`). It never imports `go-xkms/pkg/*`.

## Slot backend synchronization (this feature's subject)

Three unexported helpers, all in `pkcs11_service.go`, keep
`xkey/pkg/backendregistry` in sync with the manager's slot table:

```go
func slotBackendID(moduleID string, slotID uint) string
func (s *PKCS11Service) syncSlotBackends(moduleID string)
func (s *PKCS11Service) registerSlotBackends(mod *xkms.PKCS11ModuleInfo)
func (s *PKCS11Service) unregisterSlotBackends(moduleID string)
```

`syncSlotBackends` is the entry point: it fetches the module's current slot
table with `s.manager.GetModule`, unregisters every existing slot-backend
entry for that module, then re-registers one for every slot that currently
reports `TokenPresent`. Doing a full unregister-then-register on every call
rather than diffing old and new slot lists keeps the invariant trivial to
state and verify: **after `syncSlotBackends(moduleID)` returns, the registry
holds exactly one entry per currently-present token in that module, and
none for slots without one.**

It is called from every operation that can change slot state:

| Call site | Why |
|---|---|
| `RegisterModule` (fresh registration and the TestConnection-reuse path) | slots just enumerated for the first time |
| `RegisterModuleFromConfig` | same, on startup restore |
| `RefreshSlots` | explicit hot-plug re-enumeration |
| `InitializeToken` | label, serial, and initialized state just changed |
| `UnregisterModule` (via `unregisterSlotBackends` directly -- there is no module left to re-register slots for) | module is gone, so are its slots |
| `Close` (via `unregisterSlotBackends` for every module, before closing the manager) | same, for every module at shutdown |

`syncSlotBackends` and `unregisterSlotBackends` are no-ops when
`s.registry == nil`: a `PKCS11Service` with no registry wired in behaves
exactly as it did before this feature.

`TestConnection` and `ProbeSlots` call `s.manager.RegisterModule` /
`s.manager.UnregisterModule` directly rather than through the
`PKCS11Service` wrapper methods, so they never trigger a sync -- both are
explicitly transient probes (register, test, immediately unregister) and
must not leave registry state behind, matching that they also skip
persisting to the unified config.

## Registry entry shape

Slot backend ID: `fmt.Sprintf("%s-slot-%d", moduleID, slotID)`. Cannot
collide with a module-level entry's ID (an admin-configured module ID never
contains `-slot-N`).

```go
&backendregistry.RegisteredBackend{
	ID:          "<moduleID>-slot-<slotID>",
	Location:    backendregistry.LocationLocal,
	Category:    backendregistry.CategoryPKCS11,
	DisplayName: <token label, or "<module display name> slot <N>" if the token has none>,
	Capabilities: map[backendregistry.Capability]bool{
		backendregistry.CapSigning:    true,
		backendregistry.CapEncryption: true,
		backendregistry.CapPIV:        true,
		// CapFIDO2 intentionally absent: see below.
	},
	Metadata: map[string]string{
		"module_id":          moduleID,
		"slot_id":             fmt.Sprintf("%d", slotID),
		"library_path":       mod.LibraryPath,
		"token_label":        slot.Label,
		"token_serial":       slot.Serial,
		"token_manufacturer": slot.Manufacturer,
		"token_model":        slot.Model,
		"hardware_version":   slot.HardwareVersion,
		"firmware_version":   slot.FirmwareVersion,
	},
}
```

State is always `StateReady` at registration time: a slot backend represents
"a token is present and its metadata is known," not "a session is open."
Connection state is tracked separately, on the module-level entry, by
`Connect`/`Disconnect` (unchanged by this feature).

`slot_id` in `Metadata` doubles as the marker that distinguishes a
per-slot entry from a module-level one during `unregisterSlotBackends`'s
scan of the registry (`Category == CategoryPKCS11 && Metadata["module_id"]
== moduleID && Metadata["slot_id"] present`); a module-level entry has
neither key set, so it is left untouched.

**CapFIDO2 is never set.** A YubiKey's FIDO2 applet is a separate HID USB
interface that browsers talk to directly; the PIV applet (`libykcs11`)
cannot proxy FIDO2 credentials, and generic HSMs don't implement FIDO2
either.

## Error handling

`s.registry.Register` and `s.registry.Unregister` errors inside
`registerSlotBackends` / `unregisterSlotBackends` are logged
(`Warn` / `Debug` respectively) and otherwise ignored: one slot's registry
failure must not abort registration of the module's other slots, or fail
the `RegisterModule` call that triggered the sync. This matches the
pre-existing behavior of the now-deleted `pkcs11mgr` package.

`syncSlotBackends` logs and returns early if `s.manager.GetModule` fails
(module vanished between the triggering call and the sync, or was never
registered); it does not return an error, since every one of its call sites
already has its own success/failure result to report to its caller.

## Build tags

- Production code: no PKCS#11-specific build tag inside `pkcs11_service.go`
  itself -- it is compiled unconditionally and dispatches through
  `xkms.PKCS11Manager`, whose concrete implementation is chosen by the
  `pkcs11` build tag one layer down (`go-xkms/pkg/pkcs11/manager`: real
  implementation under `pkcs11`, a stub returning `ErrPKCS11Disabled`
  otherwise).
- Tests exercising the real manager against SoftHSM2 use `//go:build
  pkcs11`, matching the convention `pkg/pkcs11/manager`'s own SoftHSM tests
  use in the root module. Tests using the mock manager
  (`pkcs11MockManager`) carry no build tag and always run.

## Tests

| File | Build tag | What it covers |
|---|---|---|
| `pkg/gui/services/pkcs11_service_slotregistry_test.go` | none | Slot sync logic against a mock manager: registers only present slots, one slot's registry failure does not block the others or fail `RegisterModule`, `UnregisterModule` removes the module's slot backends, a `nil` registry is a no-op |
| `pkg/gui/services/pkcs11_service_softhsm_test.go` | `pkcs11` | The same behaviors against a real SoftHSM2 token in an isolated `t.TempDir()`-backed token store: registration carries real token metadata, `InitializeToken` updates it in place, `UnregisterModule` removes it, an invalid library path leaves the registry untouched, no registry configured is a no-op |

Run the SoftHSM-backed suite with `go test -tags 'pkcs11 ble codec_json'
./pkg/gui/services/...` (add `CGO_ENABLED=1`; the `pkcs11` tag pulls in
`miekg/pkcs11`, which is cgo). Every test in this package runs under the
package-wide `TestMain` home-directory isolation
(`pkg/gui/services/home_isolation_test.go`): config writes triggered by
`RegisterModule`'s `persistModule` call fail harmlessly against a read-only
process home rather than touching the developer's real
`~/.config/xkey/xkey.yaml`.

## Wiring

`App.NewApp` (`xkey/pkg/gui/app.go`) calls `a.pkcs11Service.SetRegistry(a.backendRegistry)`
immediately after constructing the service -- before `a.populateBackendRegistry()`
and `a.restorePKCS11Modules()` run -- so modules restored from the unified
config at startup get their slot backends registered on the same pass,
rather than only after a later wiring step.
