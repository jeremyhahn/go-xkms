- **Every xkey on-disk and config migration path is gone — BREAKING, no compatibility with pre-migration data.** xkey never carried more than one on-disk shape for the same state; each shape now has exactly one reader, and a record in the old shape is a typed error telling the operator what to do, not a silent upgrade. Affected areas and required operator action:

  - **GUI config.** `~/.xkey/gui.json` is no longer copied from its legacy
    location on load, and `GUIConfig.PINStrategy` (#307) plus
    `ResolvePINBackend`'s legacy-strategy parameter are gone — the PIN
    backend is derived from the live TPM/store state on every start, not a
    persisted strategy field. `xkey/pkg/gui/migration.go`, which deleted
    stale pin-state files on every start, is deleted along with its `app.go`
    call site. Operator action: none for a config already in the current
    shape; a `gui.json` at the old path is simply not read.
  - **Data-dir moves.** `app.go`'s `MigrateFrom`/`migrateBarrierData` sealed
    barrier data relocation, `SealService.MigrateFrom`,
    `BarrierService`'s cross-directory fallback probe, `TPMService`'s
    one-time `pcr_policies.json` import (`SetPolicyStore` is now mandatory —
    calling it without a store returns `ErrTPMPolicyStoreNotSet`), and
    `sshstore.MigrateLegacyStores` are all deleted. `phone.yaml` is no
    longer renamed to `devices.yaml` on read (`cmd/xkey/cmd/device.go`,
    `phone_service.go`). Operator action: data left at a superseded path is
    not picked up automatically — move `pcr_policies.json`, barrier/seal
    blobs, SSH store files, and `phone.yaml` (rename to `devices.yaml`) into
    their current locations by hand before upgrading.
  - **Config defaults.** `PolicySection.RequirePlatformPolicy` (#313) is
    deleted from the config struct and from `PolicyCanonicalJSON` — the
    HMAC over an enterprise policy document changes as a result; a policy
    signed under the old canonical form must be re-signed.
    `config.AutoPopulateBackends` (the derive-on-read backend-list backfill)
    is gone; `DefaultConfig()` now seeds the one built-in software backend
    directly, so a config written before this change and missing a backend
    list stays empty instead of being backfilled at read time. Browser
    profile-mode backfill (`browser_service.go`, `Settings.svelte`) and the
    CLI's per-mode `server_url` fallback (`cmd/xkey/cmd/trust.go`, now
    requires `trust.bootstrap.server_url` directly) are removed the same
    way. `SealService.SealData`/`UnsealData` no longer default an empty
    `PolicyType` to `"none"` or infer a missing `BackendID`; both fields are
    now required on every seal/unseal call and blob record
    (`ErrSealInvalidPolicyType`, `ErrSealBlobPolicyTypeMissing`,
    `ErrSealBlobBackendIDMissing`). Operator action: set
    `trust.bootstrap.server_url` explicitly if it relied on per-mode
    derivation; re-sign any enterprise policy document; a stored seal blob
    missing `policy_type`/`backend_id` must be re-sealed.
  - **Pairing records.** The Noise-key sealed/plaintext migration
    (`migrateLegacyNoiseKeyAndSave`, `migrateLocalNoiseKey`, and the reseal
    branches in `device_listen.go`, `device_attest_device.go`, and
    `phone_service.go`'s `Connect`) is deleted. Both storage forms — sealed
    (barrier present) and plaintext (no barrier) — are still read, but a
    stored key whose form doesn't match the current barrier state is now
    `pairing.ErrNoiseKeyFormMismatch` instead of being transparently
    resealed. Device attestation records with no `AttestationProtocolVersion`
    or `AttestationProtocolVersion == 1` (#129/#130, predating the
    challenge-response attestation model) are now
    `ErrDeviceAttestationVersionUnsupported` rather than being treated as a
    legacy enrolment. Operator action: re-pair any device that hits either
    error.
  - **Services.** `StaticPasswordService.AddPassword`/`UpdatePassword`'s old
    positional-argument (V1) signatures are deleted; the struct-parameter
    (V2) versions are renamed to the base names
    (`AddPasswordParams`/`UpdatePasswordParams`) and are now the only
    entry points — `Passwords.svelte` and the generated Wails bindings are
    updated to call them under the new names.
    `TPMStatusLevelDefault`/`Provisioned`/`Verified` (unused status-level
    constants) and their `TPM.svelte` cases are removed.
    `tokenstore.BackendTokenStore` is deleted; every caller now constructs
    a `tokenstore.DAOStore` via `xkms.NewKVStoreAdapter` +
    `tokenstore.NewDAOStore`, the same DAO path already used elsewhere.
    Operator action: none — these are internal API renames/removals with
    no on-disk format change.
  - **staticpw.** `pkg/staticpw/migration.go`
    (`MigrateEntry`/`MigrateStore`/`MigrateToScopedLayout`/
    `MigrateFromBackend`) and `EncryptedStore.MigrateToEncrypted` are
    deleted, along with the plaintext pass-through in
    `EncryptedStore.GetDecrypted`: a stored password with no `ENC:` prefix
    is now `ErrPasswordNotEncrypted` rather than being returned as
    plaintext. The `MigrateStaticPasswordEntry`/`MigrateStaticPasswordStore`
    re-exports are removed from `sdk/go/staticpw.go` and
    `xkey/pkg/staticpw/lib.go`, and the `app.go` call into
    `staticpw.MigrateStore` is removed. Operator action: an entry rejected
    with `ErrPasswordNotEncrypted` must be deleted and re-added through
    `EncryptedStore` so it is written back out encrypted; there is no
    automatic upgrade path.
  - **LUKS default paths unified to xhome.** `xkey/pkg/luks`'s deprecated
    `DefaultLUKSFile`/`DefaultDataDir` constants and
    `GetDefaultLUKSPath`/`GetDefaultDataDir` helpers (home-relative
    `~/.xkey.luks` and `~/.xkey`, computed independently of `xhome`) are
    deleted. `luks.NewVolume` and every CLI/GUI caller that previously fell
    back to them (`unseal`, `lock`, `seal`, `wipe`, `migrate`,
    `import-data`, and `StorageService`) now resolve paths through
    `xhome.Resolve()` exclusively, matching every other xkey path
    resolution. Operator action: a LUKS container created under the old
    `~/.xkey.luks` file path (rather than `<xhome>/xkey.luks`) is not found
    automatically — pass `--path`/`--mount-point` explicitly to locate it,
    or move it into the resolved xhome directory.
