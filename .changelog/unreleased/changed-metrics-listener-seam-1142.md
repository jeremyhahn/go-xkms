- **`pkg/server.Server` gained a listener-injection seam for the metrics
  endpoint.** `SetMetricsListener(net.Listener)` hands the Prometheus metrics
  HTTP server a pre-bound listener to serve, taking precedence over binding
  `Metrics.Port`; `MetricsAddr() net.Addr` reports the bound address once
  `Start` has run, returning `nil` when no listener was injected. This
  mirrors the existing `SetRESTListener`/`rest.Server.Addr()` pair for the
  REST transport. Without injection, `startMetrics` binds `Metrics.Port`
  exactly as before — the change is additive. Callers (tests in particular)
  that previously had to name a literal metrics port and race to bind it
  first can now bind `:0` themselves and read the real port back instead.
  (go-xkms#1142)
