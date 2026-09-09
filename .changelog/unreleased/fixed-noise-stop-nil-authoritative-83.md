- **A Noise bootstrap server that finished draining as the shutdown deadline
  expired is no longer reported as an incomplete shutdown, and its static keys
  are destroyed rather than retained** (#83). `pkg/server/server.go`.

  `noiseStopDrained`, the one decision that licenses freeing the bootstrap
  static keys' protected pages, required both a nil from
  `noiseboot.Server.Stop` and an unexpired caller context. The second conjunct
  was the only signal under go-truststrap v0.2.0-alpha, whose `Stop` returned
  nil on its own timeout path too. The pin is now v0.4.0-alpha
  (go-truststrap#13): nil is returned only after the run's WaitGroup has
  emptied, the caller's deadline expiring first is `ErrShutdownIncomplete`,
  and upstream re-checks its drained channel before ever saying so, precisely
  so that a server that finished is not reported as incomplete. Reading the
  expired context over that nil undid the re-check: a drain that completed as
  the deadline expired retained a key that was safe to wipe and put
  "noise bootstrap handshake workers" into xkmsd's `ErrShutdownIncomplete`
  when nothing was still running. The decision now reads the error alone;
  concurrent `Stop` callers may still see different outcomes, each under its
  own deadline, and nothing here assumes otherwise — the two call sites
  already derive their own contexts.

  Held against the pinned server, not its description:
  `TestNoiseStop_NilIsAuthoritative` completes a handshake and leaves the
  worker blocked, then shows eight concurrent `Stop` callers (short and
  already-expired deadlines) all get `ErrShutdownIncomplete` and never nil,
  and that once the worker exits `Stop` returns nil under an already-expired
  context too. Passes 200 of 200 under `-race`. The decision table now names
  upstream's sentinels, so a future pin that changes them turns it red.
