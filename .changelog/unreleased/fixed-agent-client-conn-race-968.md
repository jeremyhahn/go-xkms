- **`xkey/pkg/agent.Client`'s gRPC connection field is now an atomic
  pointer, closing a data race between `Disconnect` and the background
  reconnection monitor.** `Disconnect` cleared the plain `*grpc.ClientConn`
  field with no synchronization while `monitorConnection`'s goroutine read
  it concurrently (`GetState`, `WaitForStateChange`) on every poll iteration;
  under `-race` this was masked in existing tests only because they slept a
  fixed duration after `Connect` before calling `Disconnect`, giving the
  monitor a head start it needed no guarantee of. `conn` is now
  `atomic.Pointer[grpc.ClientConn]` (`Connect`, `Disconnect`, `IsConnected`,
  `Connection`, and `monitorConnection` in `pkg/agent/client.go` all updated
  to `Load`/`Store`/`Swap`), so `Disconnect` is safe to call at any point
  relative to the monitor goroutine's loop. Found and fixed while replacing
  the sleep-then-assert readiness waits across `xkey`'s test suite (#968):
  removing the artificial delay in `pkg/agent/monitor_test.go` and
  `pkg/agent/coverage_test.go` surfaced the race the sleep had been
  papering over.
