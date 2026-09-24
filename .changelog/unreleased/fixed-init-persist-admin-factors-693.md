- **Admin login factors enrolled during `xkmsd init` now survive a restart.**
  Single-admin mode previously ran the ceremony's CA/barrier/officer work
  against ephemeral, in-memory storage and enrolled admin factors (mTLS,
  FIDO2, PIV) with a `nil` `qrdbsdk.AdminFactorPersister` — the factors
  enrolled and were reported, but nothing durable ever recorded them, so a
  restarted `xkmsd run` had no way to authenticate with them. `xkmsd init`
  now opens the SAME durable qrdb node `xkmsd run` will later reopen from the
  same data directory (`pkg/server.OpenEmbeddedNode`, sharing
  `ResolveNodeSeal` / `EmbeddedNodeStorageConfig` with
  `(*server.Server).initEmbeddedQRDBNode` so the two opens can never
  disagree about the database engine or the barrier/seal/encryption-at-rest
  configuration), runs qrdb's canonical first-boot against it
  (`pkg/server.RunFirstBoot`, factored out of `(*Server).runFirstBoot` into
  the shared `BuildFirstBootDependencies`, which now also wires a
  `CertBinder` so the issued admin certificate is bound to the user record —
  previously unset, so `UserByCertThumbprint` never resolved the admin
  either at init or at run), and enrolls the planned admin factors through a
  persister (`cmd/xkmsd/init_factor_persister.go`) that writes each one,
  immediately as it enrolls, into that node's user auth-factor store via the
  same `qrdbtransport.UserAuthFactorClient` the running server already uses
  to authenticate. A failure partway through a multi-factor plan leaves the
  earlier factors both enrolled and persisted, per go-qrdb's
  `AdminFactorPersister` contract. The node's own barrier completes its
  unseal directly for `passphrase` (`xkmsd init` is the operator-present
  ceremony) and auto-unseals for `none`/`tpm2`; `shamir` is refused with a
  typed `ErrNodeShamirUnsupported` rather than left half-sealed — the node
  barrier's own Shamir split ceremony is separate, tracked work. M-of-N mode
  is unaffected: there is no single administrator at ceremony time. Files:
  `pkg/server/embedded_node.go` (new), `pkg/server/firstboot.go`,
  `pkg/server/node_seal.go`, `pkg/server/qrdb_node.go`,
  `pkg/server/server.go`, `pkg/server/backend_tpm2.go`,
  `cmd/xkmsd/init_ceremony.go`, `cmd/xkmsd/init_node.go` (new),
  `cmd/xkmsd/init_factor_persister.go` (new). Fixes go-xkms#693.
