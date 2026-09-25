- **`xkey cert request` never connected its SDK client before signing,
  making every real invocation fail**: `runCertRequest`
  (`xkey/cmd/xkey/cmd/cert.go`) built the REST/SPKI-pinned transport client
  with `xkms.NewWithOptions` and called `client.SignCSR` directly, without
  the `client.Connect(ctx)` step every other xkmsd-reaching command
  performs (compare `connectXKMSdClient` in
  `xkey/cmd/xkey/cmd/xkmsd_client.go`). An unconnected transport client
  reports "client not connected" on first use, so `xkey cert request`
  against a real server could never succeed. This went unnoticed because no
  test exercised the command against a real xkmsd; go-xkms#704's in-process
  REST harness (`xkey/cmd/xkey/cmd/xkmsd_harness_test.go`) reached the
  success path for the first time and surfaced it immediately.
  `runCertRequest` now calls `client.Connect(ctx)` and reports a new typed
  `ErrCertConnectFailed` on failure. (go-xkms#704)
