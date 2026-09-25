- **Docs no longer document environment variables that go-xkms and xkey never
  read.** `xkey/docs/piv/README.md`'s `PIV_*` table and
  `xkey/docs/password/{cli,engineering}.md`'s `XKEY_FIDO2_*` table both
  advertised env vars that only ever reach `viper.BindPFlag` on the global,
  un-`AutomaticEnv`'d Viper singleton (`xkey/cmd/xkey/cmd/piv.go:463-470`,
  `fido2.go:436-440`) — nothing consulted the environment, flags only; both
  docs now say so and point at go-xkms#871, which owns wiring them up or
  removing the dead bindings. `docs/pkcs11/module/usage.md`'s "Debug
  Logging" section (`XKMS_DEBUG`, `XKMS_LOG_FILE`) is removed outright: the
  PKCS#11 module has no debug/log-file configuration of any kind.
  `docs/pkcs11/module/security.md`'s PIN example exported `XKMS_PIN` and
  then never referenced it in the `pkcs11-tool` command that followed; it
  now uses `--pin` directly and points at the module's real
  `XKMS_PKCS11_USER_PIN` (`pkg/pkcs11/module/config.go:56`) for the
  auto-init case. `docs/architecture/quick-reference.md` and
  `server-architecture.md` named `XKMS_SERVER_LOG_LEVEL`, `XKMS_REST_ADDRESS`
  and `XKMS_GRPC_ADDRESS`, none of which exist on `ServerConfig`
  (`pkg/config/config.go:329-341`) or `LoggingConfig` (`:382`); replaced
  with the real `XKMS_LOGGING_LEVEL`, `XKMS_SERVER_REST_PORT` and
  `XKMS_SERVER_GRPC_PORT`. `docs/xkmsd-configuration/architecture.md` is
  corrected to stop claiming a "registered alias table for pre-viper
  names" that its own next section says was removed outright. Also added
  `path/file.go:Symbol` citations and precedence statements to doc entries
  for env vars confirmed real but previously uncited:
  `XKMS_PKCS11_PIV_BACKENDS` (`docs/pkcs11/module/piv.md`),
  `XKMS_CLUSTER_*` (`docs/clustering/user.md`, `docs/cluster/user.md`),
  `XKMS_STORAGE_PATH` (`docs/storage/README.md`), and the CTAP2 PIN
  resolvers (`XKEY_PIN`, `XKMS_FIDO2_PIN`) in
  `xkey/docs/{headless-webauthn,fido2,agent-automation}/cli.md` and
  `docs/webauthn/cli.md`, which also corrected a `--pin` value-flag row
  that go-xkms#272 removed from `xkey auth register`/`login` (xkmsctl's
  `--pin` still exists and is unaffected). Docs-only; no Go code changed.
  Refs go-xkms#937, go-xkms#871, go-xkms#272.
