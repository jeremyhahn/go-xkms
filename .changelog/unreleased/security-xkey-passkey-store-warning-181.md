- **The FIDO2 passkey store now warns once, at open, when it is holding
  private keys unencrypted (#181).** go-qrdb's seal barrier is the *only*
  at-rest encryption in this stack; xkey adds no per-credential wrap of its
  own on top of it. When a barrier is active, `authenticator.BackendStorage`
  is constructed over the barrier backend and credential records are
  encrypted by the barrier the same way every other barrier-routed store is
  (GUI: `xkey/pkg/gui/app.go:753`; standalone daemon: `xkey fido2
  --storage-type barrier`, `xkey/cmd/xkey/cmd/fido2.go:1400-1458`). Without a
  barrier — `xkey fido2 --storage-type file`
  (`xkey/cmd/xkey/cmd/fido2.go:1375-1386`) and the GUI's pre-`barrier init`
  fallback (`xkey/pkg/gui/app.go:761-772`) — the store is a plain 0600 file
  and always has been; that plaintext state is the operator's configuration
  choice, not a bug, but it was previously silent.

  Both file-store construction sites now emit one `slog.Warn` naming the
  exposure ("passkey store is unencrypted at rest: private keys are stored
  in plaintext") and pointing at the remedy (`xkey barrier init`) every time
  the store is opened — never a refusal, never a silent fallback.
  `--storage-type memory` (the daemon's default) and the barrier-backed path
  are unaffected; neither writes plaintext to disk. This is deliberately
  narrow: #134 is adding a shared "is the barrier initialized? open it or
  warn" helper for the OATH paths in a parallel branch, so the two file-store
  sites here warn directly rather than growing a second helper that would
  need reconciling with it. #42 is the tracking issue for the standalone
  daemon's credential-store hardening this change is one step of.

  `xkey fido2 status` already named the live store and its
  `EncryptedAtRest` field already reported `false` for `file`/`memory` and
  `true` for `barrier` (`xkey/cmd/xkey/cmd/fido2_status.go`); that disclosure
  is unchanged, now pinned by `TestDescribeStorageNamesTheFileStoreAsUnencrypted`
  and its siblings in `fido2_status_store_test.go`.

  Also deleted the dead `DAOCredentialStore` (`xkey/pkg/authenticator/dao_credential_store.go`,
  its `FIDO2CredentialEntity` DAO entity in `entity.go`, and both test files):
  `NewDAOCredentialStore` had zero non-test callers — the GUI and the
  standalone daemon both construct `authenticator.BackendStorage`, not a
  DAO-backed store, so there was no barrier-protected-versus-unprotected
  split between them to begin with, only the barrier-versus-no-barrier split
  this change addresses. `MigrateCredentials` (`xkey/pkg/authenticator/migration.go`),
  the only production reference to the deleted type, is removed with it; it
  also had zero callers.

  Files: `xkey/cmd/xkey/cmd/fido2.go`, `xkey/cmd/xkey/cmd/fido2_init_token.go`,
  `xkey/cmd/xkey/cmd/fido2_provision_attestation.go`, `xkey/pkg/gui/app.go`,
  `xkey/pkg/authenticator/migration.go`. Verified by
  `TestCreateFIDO2Storage_FileWarnsUnencrypted`,
  `TestCreateFIDO2Storage_MemoryDoesNotWarn`,
  `TestNewFIDO2Device_FileStorageWarnsUnencrypted`,
  `TestNewFIDO2Device_MemoryStorageDoesNotWarn`
  (`xkey/cmd/xkey/cmd/fido2_passkey_store_warning_test.go`), and
  `TestInitializeDataDir_WarnsWhenFIDO2StoreUnencrypted`,
  `TestInitializeDataDir_NoWarningWhenBarrierActive`
  (`xkey/pkg/gui/fido2_passkey_store_warning_test.go`).
