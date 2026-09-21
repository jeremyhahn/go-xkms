- **`pkg/acme/qrdb` config validation now refuses `barrier.enabled: true` up
  front, instead of letting `New` build an embedded QRDB server that can
  never be unsealed.** `BarrierConfig` (config.go) has no credential or
  auto-unseal source, so enabling it only deferred the failure to the first
  data-plane call, which failed with "data-plane barrier is sealed"
  (service.go). `Config.Validate` now returns the typed
  `ErrBarrierCredentialUnsupported` error as soon as `Barrier.Enabled` is
  true, so `New` fails fast at configuration time. The field is kept —
  existing configuration files with `barrier.enabled: false` still parse —
  and its doc comment states the constraint: encryption at rest for the ACME
  data plane is configured through the parent xkmsd barrier instead (#551).
