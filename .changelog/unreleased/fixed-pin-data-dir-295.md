- **Every `xkey pin` subcommand resolved `~/.xkey` instead of `~/.xkey/data`,
  so it read a phantom empty store and `set-so` could fork the SO PIN
  silently** (#295). `resolvePINDataDir`'s private fallback dropped the
  `data` segment every other subsystem uses, so on a wizard-configured
  device `pin status` reported both PINs unset, `verify` failed against a
  correct PIN, and `set-so` — seeing the phantom store's `soPINSet=false` —
  accepted a new SO PIN without the current one and wrote it beside the
  real record. Worse, `createPINService` ran `MkdirAll` on every path, so a
  read-only `pin status` *created* the empty `~/.xkey/pin/` that made the
  failure invisible.

  The CLI now has ONE data-directory resolution chain,
  `resolveDataDir`/`resolveDataDirExisting`
  (`xkey/cmd/xkey/cmd/datadir.go`): flag > `XKEY_DATA_DIR` > config
  `data_dir` > the xhome data directory — and both the pin and barrier
  groups delegate to it, removing the drifted private copy. Read commands
  (`status`, `verify`, `change-*`, `reset-lockout`) resolve through the new
  non-creating `xhome.ResolveExisting` and open the store with
  `openPINService`, which returns a typed `*PINStoreNotFoundError` instead
  of fabricating a fresh store; only `set-so`/`set-user` may create it.
  `pin status` now renders an absent store as `PIN store: not found`
  (JSON: `store_present: false`) — a fresh install and a misresolved path
  no longer print the same confident "No". Verified by a wizard-layout
  regression test (`TestPINCommands_AddressTheWizardDataDirectory`) proving
  status/verify/set-so all address `~/.xkey/data/pin/`, that a refused
  `set-so` leaves the wizard's SO PIN intact, and that no phantom
  `~/.xkey/pin/` appears; the test fails on the pre-fix resolution.
