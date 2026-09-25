- **`xkey fido2`, `xkey piv`, `xkey password`, and `xkey oath` no longer
  default their on-disk storage paths relative to the process's working
  directory (BREAKING for anyone relying on the old `./data/...` defaults;
  #929, follow-up to #926).** `defaultFIDO2StoragePath`, `defaultPIVStoragePath`,
  `defaultPasswordStorePath`, and `defaultOATHStorePath` were `"./data"`,
  `"./data/piv"`, `"./data/staticpw"`, and `"./data/oath.json"` respectively —
  wherever a command happened to run from, not the resolved xkey home. Each
  now resolves through xkey's single existing data-directory chain
  (`resolveDataDir`/`featureDataDir`, `datadir.go`: the command's own flag →
  `XKEY_DATA_DIR` → the config `data_dir` key → `~/.xkey/data`, honoring
  `XKEY_HOME` and portable/USB mode) instead of inventing a second one:
  `resolveFIDO2StoragePath` (`fido2.go`, also used by the RP-policy store and
  the always-file-backed authenticator profile store), `resolvePIVStoragePath`
  (`piv.go`), `passwordStorePath` (`password.go`, shared by `xkey fido2
  --password-store`), and `openOATHStore`'s existing barrier-or-file fallback
  (`oath.go`), which previously built its plain-file path from the unresolved
  flag default instead of the same `dataDir` it already used for the barrier
  decision. The `xkey fido2` daemon's password-store integration, previously
  silently enabled by default at the cwd-relative path, now resolves lazily to
  the same `~/.xkey/data/staticpw` `xkey password` uses. All four `--*-path`/
  `--store`/`--password-store` flags now default to empty and resolve at run
  time; `xkey <verb> --help` and the generated skill CLI reference
  (`skills/xkey-agent/reference/cli.md`) document the resolved default.
  Resolution failure (e.g. no resolvable `$HOME` and no override) is a typed
  error, never a silent fallback. Also: `pkg/acme/client.TrustedCAConfig`
  gains a `DataDir` field; `Audit.LogPath`, previously the hardcoded
  `DefaultAuditLogPath = "trusted-ca-audit.log"`, now resolves to
  `DataDir/DefaultAuditLogFileName` when unset (mirroring
  `pkg/config.ACMEAuditConfig.ResolveLogPath`, the pattern xkmsd's embedded
  ACME audit trail already uses), and `TrustedCAConfig.Validate` — now called
  from `TrustedCA.Serve` before opening the audit trail — rejects an enabled
  trail with neither `DataDir` nor `Audit.LogPath` set with a typed
  `*errors.TrustedCAError` instead of falling back to a cwd-relative log file.
