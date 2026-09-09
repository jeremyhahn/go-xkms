- **`SSHProxy.Stop` waits for the accept loop.** It closed the listener and
  waited for the connection handlers, but never for the accept goroutine
  itself, and the `done` channel it closed was read by nobody, so `Stop`
  could return while that goroutine was still winding down. The race
  detector reported the caller's next write against the goroutine's last
  read, and once #481 began running `xkey/pkg/agent` under `-race` on every
  PR that became a gate flake (`TestSSHProxy_StartStop`, reproducible within
  300 runs on `main`). The accept loop now owns its listener, closes `done`
  when it returns, and `Stop` waits on it before removing the socket:
  0 races in 300 runs and in the full package.
