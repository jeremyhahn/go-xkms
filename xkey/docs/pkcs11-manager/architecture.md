# PKCS#11 Module/Token Manager — Architecture

> **Status: NORMATIVE** · Feature: `pkcs11-manager` · Module: `go-xkms/xkey` · Last verified: 2026-10-12

## The problem

xkey needs to load PKCS#11 libraries (SoftHSM2, a YubiKey's `libykcs11`, or any
other PKCS#11 v2.40 module), enumerate the slots and tokens they expose, and
let the user pick one to connect to before doing anything with it. The GUI's
setup wizard and admin area both need to show every present token — its
label, manufacturer, model, and serial number — as soon as a module is
registered, not only after the user has connected to a specific slot.

The module/token lifecycle itself (`RegisterModule`, `RefreshSlots`,
`Connect`, ...) is not xkey's to own: it is hardware-crypto logic, and xkey
consumes hardware crypto exclusively through `go-xkms/sdk/go` per the
project's ownership-and-SDK-boundary rules (`00-ownership-and-sdk-boundary.md`).
What xkey does own is bridging that manager's view of the world into its own
backend registry (`xkey/pkg/backendregistry`), which is what every other part
of the GUI and CLI reads to discover available backends.

## Shape chosen: PKCS11Service owns registry synchronization, the manager owns hardware

```
┌─────────────────────────────┐
│ go-xkms/pkg/pkcs11/manager   │  module load, slot enumeration, token
│ (reached via sdk/go)         │  init, sessions -- hardware concerns only,
└──────────────┬───────────────┘  no knowledge that xkey or a registry exist
               │ xkms.PKCS11Manager (sdk/go alias)
               ▼
┌─────────────────────────────┐
│ xkey/pkg/gui/services        │  wraps the manager, translates its types to
│   .PKCS11Service              │  the frontend's JSON shape, and -- the
└──────────────┬───────────────┘  subject of this feature -- keeps
               │                  backendregistry in sync with the manager's
               ▼                  slot table
┌─────────────────────────────┐
│ xkey/pkg/backendregistry     │  what the rest of xkey (admin UI, setup
└───────────────────────────────┘  wizard, key operations) reads
```

`PKCS11Service` is built entirely on the sdk/go-exposed manager
(`xkms.PKCS11Manager = pkg/pkcs11/manager.Manager`, `xkms.PKCS11SlotInfo =
pkg/pkcs11/manager.SlotInfo`, ...). It never imports `go-xkms/pkg/*`
directly, per the architecture gate in `00-ownership-and-sdk-boundary.md`:
xkey production code imports only sdk/go and its subpackages.

## Two kinds of registry entry, and why both exist

The registry already had one way to represent a PKCS#11 backend before this
feature: a coarse, single entry per **configured module**, created either
when the unified config loads at startup (`App.populateBackendRegistry`) or
when the user explicitly configures one through the admin UI
(`AdminService.ConfigureBackend`). That entry's ID is the module ID chosen at
configuration time, it carries generic PKCS#11 capabilities, and it exists
whether or not the module is currently loaded.

This feature adds a second, finer-grained kind: a **per-slot entry**,
registered and unregistered automatically as `PKCS11Service` observes the
manager's slot table change. Its ID is `<moduleID>-slot-<slotID>`, which
cannot collide with a module-level ID (module IDs never contain `-slot-N`),
so the two coexist without conflict. A per-slot entry only exists while its
slot currently reports a token present, and it carries that token's label,
manufacturer, model, serial number, and hardware/firmware version --
metadata a coarse, admin-configured entry never has, because the admin UI
lets the user pick one slot without first enumerating what's physically
there.

The per-slot entries are what let the setup wizard and admin area show "here
are the three tokens plugged in right now, pick one" before the user commits
to a slot. The module-level entry is what the user's saved configuration
resolves to across restarts.

## Where this used to live, and why it moved

Before this feature, per-slot auto-registration lived in a package called
`xkey/pkg/pkcs11mgr` -- a complete, independent reimplementation of the
module/token manager that happened to also know how to register slots in
`backendregistry`. It duplicated everything `pkg/pkcs11/manager` already did
(module load, slot enumeration, sessions, errors) with one added capability
and, critically, was never wired into the running application: nothing in
`xkey/cmd` or `xkey/pkg/gui` imported it. It was dead code carrying live
logic nobody could reach.

`pkcs11mgr` has been deleted. The one behavior worth keeping --
auto-registering each present slot as a backend -- now lives directly in
`PKCS11Service`, built on the same manager the rest of xkey already uses
(`pkg/pkcs11/manager` via `sdk/go`), instead of a second implementation next
to it.

## Rejected: teaching the manager about the registry

An alternative was to give `pkg/pkcs11/manager` itself a
`WithRegistry`-style option and have it call into `backendregistry` directly,
mirroring `pkcs11mgr`'s original constructor shape. That was rejected: the
manager is hardware-crypto logic owned by go-xkms proper and reached by
several consumers beyond xkey (see
[docs/pkcs11-provider-module/engineering.md](../../../docs/pkcs11-provider-module/engineering.md#pkgpkcs11manager)); teaching it about
one consumer's GUI-facing registry type would invert the dependency the SDK
boundary exists to enforce. `PKCS11Service` sits on the xkey side of that
boundary already, so the synchronization logic belongs there.

## Cross-references

- [PKCS#11 module/token manager](../../../docs/pkcs11-provider-module/engineering.md#pkgpkcs11manager) -- the
  manager this feature is built on
- [PKCS#11 IPC transport](../pkcs11/ipc.md) -- a different PKCS#11-adjacent
  concern in xkey (external processes talking to a running xkey instance),
  not converted to the feature-folder convention yet
- `00-ownership-and-sdk-boundary.md` -- the ownership-and-SDK-boundary
  constitution (company standards repository)
