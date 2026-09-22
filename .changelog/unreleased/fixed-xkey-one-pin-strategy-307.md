- **`xkey` has exactly one governing PIN backend per device, read by the GUI, the headless daemon and `xkey pin` alike (#307, #272).**
  A PIN set through the desktop GUI's TPM2 wizard used to authenticate the
  GUI itself but not `xkey pin` or `xkey extension serve`, which
  hard-coded the software backend regardless of what the GUI had
  persisted (`GUIConfig.PINStrategy`, a GUI-only, cgo config file). A
  value that verified `VALID` against one store answered `invalid PIN`
  against the other, and each failed retry against a TPM-backed store
  spent one of its limited dictionary-attack attempts. The governing
  strategy now lives at `<dataDir>/pin/strategy`, beside the PIN state it
  governs, owned by the new non-cgo `xkey/pkg/pinstrategy` package:
  `pinstrategy.Resolve` auto-selects hardware-first on a fresh install and
  persists the choice, or builds exactly the persisted strategy's backend
  on every later call. `xkey pin` and `xkey extension serve` gained their
  own TPM provider adapter (`pinstrategy.NewTPMProvider` over a
  short-lived TPM open, `openTPMModule`, shared with the barrier
  strategy's `probeTPMSealer`); the GUI's `initPINService` now delegates
  to `services.ResolvePINBackend`, which performs a one-time migration of
  an older install's `GUIConfig.PINStrategy` into the shared file. A
  device whose persisted strategy needs a provider unavailable in this
  build/host (typically `tpm2` probed from a host with no TPM) is refused
  with a typed `*pinstrategy.ProviderUnavailableError` — via `xkey pin
  verify`/`status`, or `xkey extension serve` failing to start — rather
  than silently answering from a different backend. `xkey pin status`
  now always names the strategy that actually governs. `--unified-pin`'s
  help text and docs no longer claim to synchronize a PKCS#11 or file PIN
  store: it only propagates the FIDO2 PIN hash
  (`authenticator.Config.UnifiedPIN`, via
  `qrdbsdk.PINService.SetFIDO2HashSetter`), which is the only thing it
  ever did. `xkey/pkg/pinstrategy` and its callers reach `pkg/pinselect`
  and `pkg/pintpm2` exclusively through new `sdk/go` re-exports
  (`PINSelectConfig`, `ErrPINSelectNoSoftwareProvider`,
  `PINSelectSoftwareStorageError`, `PINTPMBackend`, `NewPINTPMBackend`),
  never by importing `go-xkms/pkg/*` directly, per the SDK boundary
  Architecture Gate.
