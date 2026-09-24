# Observability — User Guide

> **Status: NORMATIVE** · Feature: `observability` · Repo: `go-xkms` · Last verified: 2026-09-23

## Enabling metrics

```yaml
metrics:
  enabled: true
  port: 9090
  path: /metrics
```

With `enabled: true`, xkmsd serves Prometheus-format metrics at
`http://<host>:<port><path>` (default `/metrics`) for as long as the daemon
runs. Point a Prometheus `scrape_config` at it:

```yaml
scrape_configs:
  - job_name: xkms
    static_configs:
      - targets: ["kms.example.com:9090"]
```

Bind the metrics port to a network only your monitoring stack can reach —
the endpoint is unauthenticated (see [`api.md`](api.md)).

## What you get

- **Per-operation totals, durations, and errors** — key
  generate/get/delete/list/import/export/rotate/copy/wrap/unwrap (both the
  BYOK ceremony and the by-key-ID PKCS#11 `C_WrapKey`/`C_UnwrapKey`
  primitives)/export-material/get-import-parameters, crypto
  sign/verify/encrypt/decrypt/derive-key/derive-key-ECDH/attest, and CA
  issue/revoke/sign-CSR/generate-CRL — each labeled by backend and outcome,
  so you can build a dashboard panel like "sign operations by backend, error
  rate over 5m" directly from `xkms_operations_total` and `xkms_errors_total`.
  See [`engineering.md`](engineering.md)'s operation-to-servicer-method table
  for the full list of operation names and which backend each is labeled
  with.
- **Real backend health**, not a static "up" value: `xkms_backend_healthy`
  reflects the same responsiveness probe the daemon's own readiness check
  uses, refreshed every 30 seconds. A backend that stops responding (a
  disconnected PKCS#11 token, an unreachable cloud KMS) shows `0` within one
  refresh cycle.
- **Keys and certificates per backend** (`xkms_keys_total`,
  `xkms_certs_total`), refreshed on every create/delete and on the same
  30-second cycle as backend health, so a dashboard can alert on an
  unexpected count change.
- **Active connections per protocol** (`xkms_active_connections`), covering
  HTTP, gRPC, and the local Unix socket.
- **Resource metrics** (goroutines, heap, GC pause, uptime) for basic
  capacity monitoring.

## Useful queries

Error rate by operation:

```promql
sum by (operation) (rate(xkms_errors_total[5m]))
```

p95 operation latency:

```promql
histogram_quantile(0.95, rate(xkms_operation_duration_seconds_bucket[5m]))
```

Backend down:

```promql
xkms_backend_healthy == 0
```

## Disabling metrics

Set `metrics.enabled: false`, or call `metrics.Disable()` if you are
embedding xkms as a library (`sdk/go`) and want to silence collection at
runtime without restarting. Every `Record*`/`Set*` call becomes a true no-op
while disabled — nothing is buffered and replayed when re-enabled.
