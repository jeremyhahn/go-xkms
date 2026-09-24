- **BREAKING: `pkg/backend/tpm2.Config.KeyDir` no longer defaults to a
  cwd-relative `./tpm2-keys`.** `Validate` previously filled an unset
  `KeyDir` with a path resolved relative to the process's working
  directory, so any caller that went through `xkms.AutoInitialize` without
  an `AutoConfig.DataDir` (or supplied a `map[string]interface{}` config
  with no `"key_dir"`) — including plain unit tests and a daemon started
  from an arbitrary cwd — left a stray `tpm2-keys/` directory wherever the
  process happened to be run from (seen under `xkey/pkg/pkcs11/`). `KeyDir`
  is now a required field: `Validate` returns a typed error wrapping the new
  `tpm2.ErrKeyDirRequired` sentinel when it is empty, matching the
  already-established convention for every other cwd-independent path in
  this codebase (`pkg/server`'s `resolveTPM2KeyDir`, which derives the
  key directory from `storage.path` and fails the same way when that is
  unset; `pkg/pkcs11/module`'s `ErrStoragePathRequired`; `pkg/config`'s
  `storage.path` validation). Callers unaffected: `pkg/server` (derives
  `KeyDir` from `storage.path`), `pkg/xkms.AutoInitialize` with
  `AutoConfig.DataDir` set (derives a per-backend subdirectory), and every
  test already pinning `key_dir`/`KeyDir` to `t.TempDir()`. A caller that
  relied on the old default and supplies no `DataDir`/`storage.path` now
  gets a clear error instead of scattered key material.
