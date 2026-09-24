- **`credentials.seal_strategy: barrier` now works where the barrier can
  actually back it, and is refused with a typed error everywhere else,
  instead of always failing with `ErrNilBarrier`.** The credential service
  is constructed, and resolves every backend's `credential://` secret
  (PKCS#11/RNG-PKCS#11 PIN, AWS KMS/Azure Key Vault secret, Vault token),
  before `initializeBackends` runs — and the general (non-node) xkms barrier
  is itself built from those already-initialized backends
  (`buildHardwareSealStrategies`), so a `barrier`-sealed credential store in
  that configuration would need the barrier to unseal itself before it can
  exist: a structural cycle, not an ordering bug. The ONE barrier available
  in time is the embedded qrdb node's own (the "flip",
  `pkg/server/node_seal.go`'s `resolveNodeSeal`): it is adopted inside
  `initializeQRDBStorage`, before the credential service is ever
  constructed, whenever `storage.backend: qrdb` is hosted with the embedded
  transport, `barrier.enabled: true`, and `barrier.strategy` is one
  `BarrierConfig.NodeFlipWired` reports true for (`none`, `passphrase`,
  `shamir`, `tpm2`) — that configuration already worked with no code change
  to `pkg/server`'s boot order. `config.Config.Validate()` now calls the new
  `CredentialsBarrierStrategySupported()` and refuses
  `credentials.seal_strategy: barrier` with a typed `*errs.Message` naming
  the deployment's actual storage/transport/barrier shape whenever that
  method reports false, so a misconfigured deployment fails at config load
  with an actionable message instead of deep inside `Server.New`. Files:
  `pkg/config/config.go` (`CredentialsBarrierStrategySupported`, `Validate`),
  `pkg/config/config_test.go`, `pkg/server/credentials_barrier_test.go`
  (new — a stored credential round-trips across a restart under the
  supported shape, and an unsupported shape is refused cleanly with no
  partial server), `docs/init/credentials.md`. go-xkms#812.
