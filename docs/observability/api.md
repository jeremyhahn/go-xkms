# Observability — API

> **Status: NORMATIVE** · Feature: `observability` · Repo: `go-xkms` · Last verified: 2026-09-23

## Capability matrix

| Capability | Surface | Permission |
|---|---|---|
| Scrape metrics | `GET /metrics` on the metrics listener (`metrics.port`, default alongside the REST port) | none (unauthenticated; bind the listener to a trusted network) |

This is the only network capability this feature adds: a single
`promhttp.Handler()` endpoint (`pkg/server.startMetrics`), not a capability
reachable through REST, gRPC, Unix, QUIC, MCP, or the embedded SDK the way
[`key-management/api.md`](../key-management/api.md)'s "six transports" model
describes. There is no RPC, no request/response DTO, and no permission to
declare — the endpoint is Prometheus's own exposition format, unauthenticated
by design (the same posture Prometheus's own `/metrics` convention assumes),
which is why `metrics.port`/`metrics.path` should be bound to a network only
your scrape targets (Prometheus, an operator's `curl`) can reach.

## What every transport contributes, indirectly

Every REST, gRPC, and Unix request — and, through `XKMSService`, every QUIC
and embedded-SDK call — updates the counters and histograms this endpoint
serves. See [`architecture.md`](architecture.md) for exactly which method
call increments which series, and [`engineering.md`](engineering.md) for the
full metric/label reference. There is no per-transport API contract to
document beyond that: the metrics surface is uniform across transports
because instrumentation happens once, below all of them.

## Example scrape

```
$ curl -s http://kms.example.com:9090/metrics | grep xkms_operations_total
xkms_operations_total{backend="tpm2",operation="sign",status="success"} 42
xkms_operations_total{backend="pkcs11",operation="generate",status="error"} 1
```
