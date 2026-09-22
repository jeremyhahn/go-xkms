- **xkmsd's bootstrap listener no longer keeps its Noise/P-256 static keys in
  plaintext config or regenerates them every restart; they are now persisted
  barrier-sealed (#35, #42, #436).** `bootstrap.noise.static_key_hex` /
  `static_key_file` / `p256_static_key_hex` / `p256_static_key_file` put a
  private key inline in YAML or in a plaintext file, and configuring neither
  generated a fresh ephemeral key on every boot — silently invalidating every
  client that had pinned the previous public key. The xkey pairing half of
  this custody model landed first as #42
  (`xkey/pkg/pairing/noise_key_seal.go`); this closes the xkmsd half.

  `pkg/server/bootstrap_key_custody.go` resolves each suite's key on boot:
  with a barrier configured (`s.barrier`, adopted from the embedded qrdb node
  or built by `initializeBarrier` — the boot order already runs this
  post-unseal, since `s.barrier` is only ever set once `initEmbeddedQRDBNode`
  has confirmed the node unsealed), the hex-encoded key is read from and
  written to the barrier's own key-value store
  (`bootstrap-noise/x25519-static-key`, `bootstrap-noise/p256-static-key`) via
  `seal.Barrier.Get`/`Put`, the same mechanism `pkg/server/credentials`
  already uses for operator-owned secrets. The first boot after upgrade reads
  the deprecated config field once, seals the key it names, and logs that the
  field is deprecated; every later boot finds the sealed key and never reads
  config again. With no barrier configured, the deprecated fields are still
  honored unchanged, and a key with neither configured is persisted (not
  regenerated) as a 0600 file in the server's data directory, with one warning
  that it lacks barrier protection.

  The four config fields are marked `Deprecated` in
  `config.NoiseBootstrapConfig`'s doc comments; they still parse (the
  migration depends on it) but are not read again once a key is sealed or
  persisted. `pkg/server/bootstrap_key_custody.go`,
  `pkg/server/bootstrap_key_custody_test.go`, `pkg/server/errors.go`,
  `pkg/config/config.go`.
