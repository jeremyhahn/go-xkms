# 8384: xkey serve unlock test times out at the 5 s IPC deadline (DS-8384)

## Failure

Main f54087661513 (run 43003017872), Nested Module Tests: only
`xkey/cmd/xkey/cmd` `TestExtensionServe_LocksAtStartupWhenAUserPINIsSet`
fails, both subtests (no-barrier=true 7.35 s, no-barrier=false 17.33 s), at
`client.Unlock("user-pin-1234")`: `ipc: protocol error: read unix
...serve.sock: i/o timeout`; the server then logs `encode response failed ...
broken pipe`. `ipc.DefaultTimeout` is 5 s and the client sets it as the
connection deadline. #2063 only raised the toolchain container memory, so
more -race test binaries run at once.

## Working cause

A correct-PIN unlock (PIN verification KDF plus what unlock opens) takes over
5 s under -race on a loaded runner.

## Slices

1. Measure the Unlock call alone and under load (times below).
2. Test commit: a client_test.go case that `NewClient(path, WithTimeout(d))`
   uses d as the deadline (fails before the fix).
3. Fix commit: the `WithTimeout` option; the serve tests' client uses a
   deadline that fits a -race unlock. DefaultTimeout stays 5 s unless a
   real unlock outside -race exceeds it.

## Out of scope

Weakening the test, skips, retries; the PIN KDF cost.

## Measurements

- This node (112 CPUs), -race, -count=3, correct-PIN `Unlock` alone:
  155-196 ms. With `-cpu 1` beside `go test -race ./pkg/...`: 298-739 ms.
  Far under 5 s here; CI's >5 s needs ~25x this, so the cost scales with
  contention (CPU-bound KDF), next: read AppLockService.HandleUnlock.
