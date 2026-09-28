- **`xkey piv`, `xkey fido2` and `xkey device listen`/`sync*` now honour the
  config file and environment variable sources they advertised (or should
  have), instead of silently reading only their command-line flag —
  BREAKING for `--pkcs11-pin`/`--pkcs11-so-pin`.** The global `viper`
  instance these commands bound flags to (`root.go:245-247`'s own comment
  called it "phased out") was never pointed at a config file and never had
  `AutomaticEnv` enabled, so every `piv.*`/`device.listen.*`/`device.sync*.*`
  key it exposed only ever reflected the bound flag's current value; the
  `fido2` command's Long help claimed `XKEY_FIDO2_*`/config-file support for
  every flag when only `fido2.attestation` was actually wired, and even that
  wiring was itself blind to `pkg/config`'s own `fido2.storage`/
  `storage_path`/`device_name` keys. `xkeyconfig.PIVConfig`
  (`pkg/config/config.go:93-107`) is new: `--backend`, `--piv-storage`,
  `--storage-path`, `--tpm-device`, `--pkcs11-library` and `--pkcs11-token`
  now resolve flag-then-config/environment-then-backend-matched-default
  through it, the same precedence `resolveXKMSdURL` already used for the
  xkmsd endpoint; `buildPIVConfig` (`cmd/xkey/cmd/piv.go:603-639`) and every
  command that builds PIV storage (`piv`, `cert request`/`show`/`export`,
  `device listen`, `provision`, `auth login --piv`) go through it. The
  PKCS#11 PIN and Security Officer PIN deliberately stay out of that config
  section and out of any generic environment binding: `--pkcs11-pin` and
  `--pkcs11-so-pin` value flags are gone (a value on the command line is
  visible to every other process on the host via `ps`, the same reason
  `--pin`/`--so-pin` were removed in #272) and are replaced by
  `--pkcs11-pin-stdin`/`XKEY_PIV_PKCS11_PIN` and
  `--pkcs11-so-pin-stdin`/`XKEY_PIV_PKCS11_SO_PIN`
  (`pivPKCS11PINSource`/`pivPKCS11SOPINSource`, `piv.go:57-69`), the same
  stdin-then-dedicated-env-var convention `pin_input.go` already used for the
  host PIN service's own PIN. `buildFIDO2Config`
  (`cmd/xkey/cmd/fido2.go:553-596`) now installs `fido2.storage`,
  `fido2.storage_path` and `fido2.device_name` from the loaded config the
  same way it already did for `fido2.attestation`, and the command's Long
  help now names exactly the four flags (`--storage`, `--storage-path`,
  `--name`, `--attestation`) that have a config/environment source instead of
  claiming all of them do. `device listen`'s and `device sync`/`sync-push`/
  `sync-pull`/`sync-status`'s `viper.BindPFlag` calls were dead code — bound
  but never read back through `viper.Get*` anywhere, since both commands
  already read their flags directly off `cmd.Flags()` — and are deleted
  rather than wired up: `sync`'s `--trust-store`/`--oath`/`--passwords`/
  `--all`/`--dry-run` select what one invocation does and have no config-file
  meaning, and `listen`'s `--help` never claimed a config/environment source
  to begin with. Files: `pkg/config/config.go`, `pkg/config/load_test.go`,
  `pkg/config/config_test.go`, `cmd/xkey/cmd/piv.go`, `pin_input.go`,
  `auth_piv.go`, `cert.go`, `piv_import.go`, `piv_generate.go`, `piv_csr.go`,
  `provision.go`, `device_listen.go`, `device_sync.go`, `fido2.go`, and the
  corresponding `_test.go` files; docs:
  `xkey/docs/piv/{cli,engineering,architecture}.md`,
  `xkey/docs/virtual-authenticator/cli.md`, `xkey/docs/fido2/README.md`,
  `xkey/docs/device/engineering.md` (go-xkms#871).
