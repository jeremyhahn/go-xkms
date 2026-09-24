- **xkmsctl no longer has a process-environment switch to an unaudited
  software FIDO2 authenticator — BREAKING.** `cmd/xkmsctl/fido2.go`'s
  `defaultFIDO2HandlerFactory` checked `FIDO2_USE_VIRTUAL=true` and, when set,
  called `virtualdevice.NewNativeVirtualDevice` with no `Authenticator`
  supplied, so it built its own unaudited one (the gap tracked by #804): any
  process able to set an environment variable before a production `xkmsctl`
  invocation could silently redirect FIDO2 register/authenticate ceremonies
  from real hardware to a software authenticator, unaudited and undocumented.
  `defaultFIDO2HandlerFactory` now unconditionally enumerates hardware and
  has no runtime switch at all; verified by building the release binary and
  confirming it contains no reference to the virtual device's identifying
  strings. The FIDO2 integration harness (`test/integration/fido2`, which
  execs a built `xkmsctl` and needs a software authenticator in CI) keeps the
  same `FIDO2_USE_VIRTUAL` / `FIDO2_VIRTUAL_STATE_DIR` environment contract,
  but the seam that understands them now lives in
  `cmd/xkmsctl/fido2_virtual.go`, gated by `//go:build integration && fido2`
  and wired in via `init()`; it is compiled in only when `xkmsctl` is built
  with both tags, which none of the release build targets (`make build`,
  `make release-*`) do. The `integration-test-fido2*` Makefile targets now
  build the `xkmsctl` binary under test with `-tags 'integration,fido2'` so
  the harness keeps working.
