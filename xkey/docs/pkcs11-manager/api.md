# PKCS#11 Module/Token Manager — API

> **Status: NORMATIVE** · Feature: `pkcs11-manager` · Module: `go-xkms/xkey` · Last verified: 2026-09-23

## Transport: Wails frontend bindings

`PKCS11Service` (`xkey/pkg/gui/services/pkcs11_service.go`) is bound to the
Wails runtime; every exported method is callable from the Svelte frontend as
a JavaScript async function with the same name and argument order. There is
no REST, gRPC, or other network transport for this feature -- it is local
GUI-process state only, mirrored into `xkey/pkg/backendregistry` for the
rest of the application (admin area, setup wizard, key operations) to read.

## Methods relevant to slot registry synchronization

| Method | Effect on the registry |
|---|---|
| `RegisterModule(libraryPath, displayName string) (string, error)` | Loads the module, then registers one backend per slot with a token present |
| `RegisterModuleFromConfig(moduleID, libraryPath, displayName string) (string, error)` | Same, used when restoring modules saved in the unified config at startup |
| `RefreshSlots(moduleID string) ([]PKCS11SlotInfo, error)` | Re-enumerates the module's slots, then re-synchronizes: a newly present token gains a backend, one that is no longer present loses it |
| `InitializeToken(moduleID string, slotID uint, label, soPin, userPin string) error` | Re-synchronizes so the slot's backend reflects the new label and serial without a separate `RefreshSlots` call |
| `UnregisterModule(moduleID string) error` | Removes every backend registered for the module's slots |
| `Close() error` | Removes every slot backend for every registered module, then shuts down the manager |
| `TestConnection`, `ProbeSlots` | Do **not** touch the registry -- both are explicit, transient probes that register and unregister the module internally without ever calling the synchronizing wrapper methods above |

None of these calls return the registry entries themselves; read them back
through `xkey/pkg/backendregistry.Registry` (`Get`, `List`,
`ListByCategory(backendregistry.CategoryPKCS11)`), which the GUI's admin and
setup-wizard views already consume for every backend category.

## Registry entry read shape

See [engineering.md](engineering.md#registry-entry-shape) for the exact
`RegisteredBackend` fields a per-slot entry carries (ID format, capabilities,
metadata keys).
