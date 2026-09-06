- **The `extension`, `trust` and `auth` command groups resolved
  `~/.xkey/data/<feature>` by hand, so under `XKEY_HOME`, portable mode or
  `XKEY_DATA_DIR` they read and wrote a different location than the GUI,
  the wizard and every other CLI group** (#381, split from #295). Each
  group built its path from `os.UserHomeDir()` with no override at all
  (trust honoured only `trust.store_path`); the segment was correct on a
  default install and silently wrong everywhere else. The browser
  launcher carried a second spelling of the trust store path, and the
  `agent` and `backup` groups kept private `~/.xkey/data` fallbacks
  beside the root-resolved home — `agent` even fell back to a temporary
  directory when the home was unresolvable.

  All of them now delegate to the one CLI chain from #295
  (`xkey/cmd/xkey/cmd/datadir.go`) through two new helpers,
  `featureDataDir` / `featureDataDirExisting`, which return
  `<dataDir>/<feature>` so a group spells only its feature segment:
  `extension host` resolves creating and remains the only extension
  command that creates the pairing directory, while `unpair` and
  `pair-status` resolve non-creating and fail with a typed error (new
  `ErrExtensionPairStatusFailed`) instead of rendering an unresolvable
  home as "Not paired"; `trustStoreDir` is the single trust-store
  resolver shared by `openTrustStore` and `browser launch`;
  `authStoragePath` drops the `data/` prefix from its constant; and
  `agentDataDir`/`agentStoreDir`/`agentCertDir`/`agentStateFile` return an
  error rather than a temporary directory. **Deliberate behaviour
  change:** these groups now honour `XKEY_HOME`, the portable
  `.xkey-home` marker, `XKEY_DATA_DIR` and the `data_dir` config key
  exactly as `pin` and `barrier` do; a device that had been relying on
  the hand-built default while running under one of those overrides will
  now address the overridden location. Verified by per-group truth-table
  tests (flag-less chain: `XKEY_DATA_DIR` > `data_dir` > `XKEY_HOME` >
  `~/.xkey/data`), read-side tests proving `pair-status`/`unpair` create
  nothing and read a pairing placed under `XKEY_DATA_DIR` or `XKEY_HOME`,
  and a grep gate (`TestNoAdHocDataDirLiterals`) that scans the command
  sources and fails on any hand-spelled data-directory literal outside
  `datadir.go`; restoring the old `auth` and `extension` literals turns
  the gate and the truth tables red.
