- **The Noise server's lifecycle sentinels reach the SDK (#498).**
  `NoiseServer.Stop` returns `ErrShutdownIncomplete` when the caller's
  deadline expires before the handshake workers drain, and `Start`/`Stop`
  return `ErrServerAlreadyStarted`/`ErrServerNotStarted`, but neither
  `pkg/trust/bootstrap` nor `sdk/go/bootstrap` re-exported them, so an SDK
  consumer orchestrating the server had to import go-truststrap to dispatch
  on them, which the layer ownership forbids. Both layers now carry
  `ErrNoiseShutdownIncomplete`, `ErrNoiseServerNotStarted` and
  `ErrNoiseServerAlreadyStarted` as the upstream values.
