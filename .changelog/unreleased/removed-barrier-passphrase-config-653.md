- **The barrier no longer accepts a boot-time unseal secret from
  configuration, a flag, or the environment, and backends now initialize
  after unseal — BREAKING.** `pkg/config`'s `BarrierConfig.Passphrase` field
  is deleted, matching go-qrdb's own `SealConfig`, which carries no such
  field either: an operator supplies the passphrase or Shamir quorum at
  Initialize/Unseal time, via `xkmsctl barrier unseal` (or `unseal-shares`)
  or the equivalent API call, on every restart. `cmd/xkmsd`'s
  `--seal-passphrase` flag and the `XKMS_BARRIER_PASSPHRASE` environment
  variable are removed with it. `pkg/config.Load` now rejects a config file
  or environment variable that still sets `barrier.passphrase` with a typed
  `*config.RemovedFieldError` naming the field and the replacement, instead
  of silently dropping the now-unmapped key.
  **The qrdb node's own barrier ("the flip") now engages for every software
  strategy too, not just `none`/`tpm2`.** New `config.BarrierConfig.NodeFlipWired`
  reports true for `none`, `passphrase`, `shamir`, and `tpm2` — go-qrdb's own
  node-embedded seal subsystem (`go-qrdb/sdk/go/node`) natively builds
  `none`/`passphrase`(deferred)/`shamir` from `DaemonConfig.Seal` alone;
  xkms additionally injects a pre-built `tpm2` `SealingStrategy` constructed
  directly from `Backends.TPM2` config, never from an already-initialized
  backend. `passphrase`/`shamir` leave the node sealed at construction, and
  `Server.New` blocks inside `initializeQRDBStorage` on the qrdb node's own
  sealed-window listener — the identical two-phase boot `cmd/qrdbd` drives
  via `initSealSubsystem` -> `awaitUnseal`, reached here entirely through
  `go-qrdb/sdk/go`, no parallel implementation — until an operator completes
  `xkmsctl barrier unseal`/`unseal-shares` or the equivalent API call, or the
  configured `barrier.sealed_window_timeout` elapses.
  **`Server.New` now initializes the credential service and resolves every
  `credential://` config reference BEFORE `initializeBackends`**, so the
  five backend-credential fields that used to be read too early to benefit —
  `backends.pkcs11.pin`, `rng.pkcs11.pin`, `backends.awskms.secret_key`,
  `backends.azurekv.client_secret`, `backends.vault.token` — now resolve a
  `credential://` reference exactly like a CA password already did; see
  `pkg/server/secret_wiring_test.go`'s
  `TestBackendCredentials_ResolveViaCredentialReference`. This reorder does
  not create the cycle a full move of `initializeBarrier` would: xkms's own
  (non-node) barrier hardware strategies — built from already-initialized
  backends via `buildHardwareSealStrategies` — are now reached only for a
  strategy `NodeFlipWired` excludes (`pkcs11`, the cloud-KMS strategies).
  `Config.ComplianceGaps()` now reports a gap exactly when
  `BarrierConfig.NodeFlipWired` is false for the configured strategy: a
  `qrdb` + `passphrase`/`shamir` deployment is no longer flagged, because
  the node's own barrier genuinely encrypts the data plane for it — the
  ceremony gates *access*, it does not leave data in plaintext.
  `configs/xkmsd-local.yaml` and `configs/xkmsd-integration.yaml` pass
  `TestShippedDaemonConfigsAreCompliant` unchanged (still `passphrase`
  strategy) as a direct result.
  **Not approved, not implemented (go-xkms#653 item 3):** a `pkcs11` (or
  cloud-KMS) barrier strategy remains impossible to wire to the node flip —
  it would need the same already-initialized PKCS#11 backend
  `buildHardwareSealStrategies` reads from `s.keyProviders`, which
  `initializeBackends` now builds strictly after unseal and credential
  resolution. Deferring the PKCS#11 seal strategy's PIN to unseal time
  (matching the software strategy's own per-call credential shape) would
  need a `pkg/seal`/`types.Sealer` interface change; `types.Sealer` and the
  PKCS#11 strategy are unchanged in this pass.
  Files: `pkg/config/config.go`, `pkg/config/load.go`,
  `pkg/server/node_seal.go`, `pkg/server/qrdb_node.go`,
  `pkg/server/server.go`, `pkg/server/secret_wiring.go`,
  `cmd/xkmsd/main.go`, `configs/xkmsd*.yaml`,
  `test/integration/cluster/config.node.yaml`,
  `test/integration/api/config.test.yaml`,
  `test/integration/web/config.yaml`,
  `test/integration/bootstrap/docker-compose.yml`, `README.md`,
  `docs/seal/README.md`, `docs/xkmsd-configuration/cli.md`,
  `docs/xkmsd-configuration/engineering.md`.
