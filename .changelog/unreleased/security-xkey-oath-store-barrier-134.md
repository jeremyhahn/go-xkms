- **The `xkey oath` CLI, `xkey backup`, and `xkey device oath-sync` now
  encrypt OATH TOTP/HOTP secrets at rest through the same barrier the GUI and
  `xkey extension serve` already use, instead of always writing a plain
  `oath.json` file** (#134, #148, refs #210). Owner ruling: no second
  encryption scheme and no new wrapping key — every OATH store path opens
  `oath.NewBackendStore` over the unsealed barrier backend
  (`xkms.NewBarrierBackend`) when a barrier is initialized at the default
  store location, sharing the `--barrier-password` / `--barrier-password-file`
  / `XKEY_BARRIER_PASSWORD` reach `xkey fido2` and `xkey extension serve`
  already have through one new shared helper
  (`resolveSecretStoreBackend`, `xkey/cmd/xkey/cmd/barrier_store.go`). When no
  barrier is initialized, the historical 0600 `oath.NewFileStore` is
  unchanged, and xkey now logs one `slog.Warn` per store open naming the
  store and pointing at `xkey barrier init` — never a silent plaintext
  fallback. A barrier that is initialized but cannot be opened (wrong or
  missing password, unsupported strategy, corrupt root key) is a typed
  refusal (`ErrBarrierStoreOpenFailed`), never a downgrade to plaintext. An
  explicit `--store` / `--oath-store` path always selects the plain file at
  that path, bypassing the barrier decision, matching the pre-existing
  `xkey backup` convention for explicit store overrides. `xkey backup`
  reads/writes the OATH store through the same resolution
  (`resolveOATHBackupStore`), so a backup taken while the barrier is active
  captures the same ciphertext the GUI wrote instead of a stale or absent
  plaintext file; the trust store and password store are unchanged and keep
  their existing barrier-encrypted refusal at their own default locations.
  `fido2`'s explicit `--storage barrier` path was refactored onto the same
  low-level unseal primitive (`openBarrierBackend`) so there remains exactly
  one function in the CLI that knows how to unseal the barrier, removing a
  duplicate inline copy that also leaked an unused file-backend handle. The
  dead `oath.NewDAOStore`, `OATHCredentialEntity`, and their
  `MigrateFromBackend` helper (no production caller; only the FIDO2
  authenticator's own, unrelated DAO store remains) were deleted along with
  their tests. In-memory secret custody from #210
  (`Credential.secret *secure.Buffer`) is unchanged; the accepted
  `crypto/hmac` ipad/opad residue documented at `GenerateCounter`
  (`xkey/pkg/oath/generator.go`) is unchanged and cross-referenced from
  `xkey/docs/oath/README.md`. Verified by CLI tests asserting a
  barrier-backed `oath add` writes no plaintext secret or name to disk, a
  no-barrier `oath add` logs the warning and still round-trips through the
  plain file, a wrong or missing barrier password is a typed refusal that
  never writes plaintext, an explicit `--store` bypasses the barrier, and a
  full `xkey backup create`/`restore` round trip against a barrier-backed
  OATH store never leaks the plaintext secret into the sealed backup file.
