- **`pkg/luks.Manager` now has `Mount`/`Unmount` methods, and its whole
  state machine rejects calls made out of order instead of silently
  proceeding** (#917). `Executor` gained `Mount(ctx, config)` and
  `Unmount(ctx, config)` — previously the interface had no mutating mount
  operation at all, only the `IsMounted` query, so nothing could ever set
  the `mounted` flag `Manager.IsMounted()` reads. `Manager.Mount` now
  returns `ErrNotUnlocked` if the volume isn't unlocked or `ErrAlreadyMounted`
  if it's already mounted, then sets `mounted` on a successful
  `Executor.Mount`; `Manager.Unmount` returns `ErrNotMounted` when not
  mounted, then clears it. `Manager.Unlock` now returns `ErrAlreadyUnlocked`
  on a second unlock, and `Manager.Lock` returns `ErrNotUnlocked` when the
  volume isn't unlocked — wiring up the four sentinel errors
  (`ErrNotMounted`, `ErrAlreadyMounted`, `ErrNotUnlocked`,
  `ErrAlreadyUnlocked`) that were declared in `pkg/luks/errors.go` but never
  returned by anything. Files: `pkg/luks/manager.go`, `pkg/luks/manager_test.go`;
  re-exported unchanged by `sdk/go/luks` (type aliases, no source changes
  needed there). Verified by new success/error/state-guard tests for
  `Mount`/`Unmount` and the four sentinels, `GOWORK=off go test -race
  ./pkg/luks/... ./sdk/go/luks/...`.

  A production `Executor` backed by `github.com/jeremyhahn/go-luks2` (the
  pure-Go LUKS2 library already used by this repository's `xkey` module,
  `xkey/go.mod`) is **not** included in this change: it is a new dependency
  for the root `go-xkms` module and is being held for explicit owner
  approval before it lands, still tracked under #917. `pkg/luks.Executor`
  therefore still has no production implementation in this repository —
  only `mockExecutor` in tests.
