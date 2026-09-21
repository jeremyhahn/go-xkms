- **`xkey/pkg/agent.ClientConfig.LocalAddress` is gone — BREAKING (config).**
  The field was declared, defaulted to `localhost:19443`, and documented as
  the local reverse-proxy bind address, but nothing read it: `Client.Connect`
  only ever dials `MasterAddress`, and no code in `pkg/agent` opened a
  listener on it — the field had no config-file, environment, or flag path
  to begin with. `ClientConfig`, `DefaultClientConfig` and the `Client` doc
  comment (which claimed the client "exposes its services locally via gRPC
  reverse proxy") are updated to describe what actually exists: an mTLS
  connection to the master with automatic reconnect. Any `local_address` key
  still present in a client config file is now unused rather than silently
  dropped by dead code; remove it. (#513)
