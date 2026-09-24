# Observability — CLI

> **Status: NORMATIVE** · Feature: `observability` · Repo: `go-xkms` · Last verified: 2026-09-23

No CLI surface: `xkmsctl` has no `metrics` command group. Metrics are scraped
over HTTP by Prometheus (or `curl`/any HTTP client) — see
[`api.md`](api.md) — not queried through the CLI. `xkmsctl` does report daemon
health through its own health-check surface, which is a separate feature
(the `health.Checker` readiness/liveness/startup probes
`pkg/server.initializeHealth` registers), not this one.
