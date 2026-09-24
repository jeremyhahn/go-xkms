- **`ResolveNodeSeal` no longer crashes the daemon on a `barrier.strategy:
  tpm2` config with no `backends.tpm2` section.** `barrier.strategy`
  selects the qrdb node-seal flip's hardware strategy independently of
  `backends.tpm2` (the separate crypto-operation TPM2 backend, gated by its
  own `Enabled` flag), so an operator can reasonably configure one without
  the other. `ResolveNodeSeal` (`pkg/server/embedded_node.go`) dereferenced
  `cfg.Backends.TPM2` unconditionally once `storage.path` resolved, so this
  config nil-pointer-panicked the whole process (`New` -> `resolveNodeSeal`
  -> `ResolveNodeSeal`) instead of failing one deployment closed. It now
  checks for a nil `Backends.TPM2` after the existing `storage.path` guard
  (preserving that check's precedence) and returns a typed `*NodeSealError`
  naming the missing section, exactly like the existing "no usable,
  provisioned TPM was found" case. Found and fixed while adding
  `Server.New`-level coverage for `resolveNodeSeal`'s error-wrapping branch;
  regression tests: `TestResolveNodeSeal_TPM2NoBackendConfigFailsClosed`
  (`pkg/server/node_seal_test.go`) and
  `TestNew_NodeSealFailure_WrapsAsErrServiceInit`
  (`pkg/server/new_error_wrapping_test.go`). Fixes part of go-xkms#705.

- **The loopback desktop engine (`pkg/server/loopback`) no longer races
  `Close` against its own `Start`.** `Launch` started `Server.Start` in a
  background goroutine with the comment "Start blocks while serving", but
  `Start` is non-blocking — it only registers each transport's serving
  goroutine via `sync.WaitGroup.Add` and returns. A caller that calls
  `Close` immediately after `Launch` returns (a real pattern: e.g. the
  desktop shell exiting right after boot, not just a test) could win the
  race against `Start`'s own goroutine, so `Shutdown`'s `wg.Wait()` could
  observe the `WaitGroup` before `Start`'s `wg.Add` ran — undefined by
  `sync.WaitGroup`'s contract — and, separately, the REST goroutine's own
  fail-closed abort-on-cancelled-context path (`pkg/server/server.go`
  `startREST`) never closed the already-open pre-bound loopback listener on
  that path, leaking the socket for the life of the process. `Launch` now
  calls `Start` synchronously before returning, and `startREST`'s abort
  path closes the injected listener. Regression tests:
  `TestInstance_Close_StopsTheListener` and `TestLaunch_BindsLoopbackOnly`
  (`pkg/server/loopback/loopback_launch_test.go`), run with `-race`.
  Files: `pkg/server/loopback/loopback.go`, `pkg/server/server.go`. Fixes
  part of go-xkms#705.
