# Observability — Architecture

> **Status: NORMATIVE** · Feature: `observability` · Repo: `go-xkms` · Last verified: 2026-09-23

## The problem

A KMS that cannot report how many operations it served, how long they took,
whether they failed, and whether each backend is actually reachable cannot be
operated at scale — an operator is reduced to reading logs after the fact.
`pkg/metrics` is xkms's Prometheus instrumentation: real counters, histograms,
and gauges updated by real operations, scraped at `/metrics`.

Before go-xkms#720 the package shipped two unconnected halves: a working
Prometheus API (`RecordOperation`, `RecordError`, `SetKeysTotal`,
`SetCertsTotal`, `SetBackendHealth`, `NewConnectionTracker`) with zero
callers outside its own tests, and a `MetricsAdapter` interface/`NoOpMetrics`
implementation/`WithMetrics` context helper that also had zero callers. The
backend-health gauge was hard-coded to `1` for every backend at startup and
never updated again. This feature folder documents the instrumented state
that replaced both gaps.

## Shape chosen: instrument once, at the service boundary

`pkg/xkms`'s `XKMSService` is the single implementation every transport
(REST, gRPC, Unix, QUIC, MCP, the embedded SDK) drives — see
[`key-management/architecture.md`](../key-management/architecture.md) for why
that boundary exists. Instrumenting `XKMSService`'s key, crypto, and CA
methods once — rather than in each transport's handler — means every
transport is counted exactly once, with no risk of a REST request being
counted twice (once in the handler, once in the servicer) or a QUIC request
not being counted at all because its handler forgot the call gRPC's
remembered.

Each instrumented method follows one pattern (`pkg/xkms/metrics_instrumentation.go`):

```go
func (s *XKMSService) Sign(ctx context.Context, req *transport.SignRequest) (resp *transport.SignResponse, err error) {
	start := time.Now()
	backendName := s.metricsBackendName(req.Backend)
	defer func() { recordServiceOp(metrics.OpSign, backendName, start, err) }()
	...
}
```

`recordServiceOp` reads the named return `err` after the method body has run
and calls `metrics.RecordOperation` (always) and `metrics.RecordError` (on
failure). This is deliberately a `defer` over named returns, not a manual
call before every `return` statement: a manual call is one `return` away from
being forgotten on a new error path a future change adds: the defer cannot be
skipped.

## Labels: bounded cardinality only

Every series is labeled `operation`, `backend`, and `status`/`error_type` —
never a key ID, common name, or tenant ID. Two choices enforce this:

- **`error_type` is the Go type name of the returned error**
  (`errorTypeLabel`, e.g. `"*xkms.ErrKeyNotFound"`), not `err.Error()`. This
  repository's rule is that every returned error is a typed error
  (`pkg/xkms/errors.go`), never an inline `fmt.Errorf`/`errors.New`, so the
  set of possible type names is fixed at compile time and bounded regardless
  of what a wrapped backend error happens to say in its message (which can
  quote a key ID or path).
- **CA operations use the fixed backend label `"ca"`** (`caMetricsBackend`),
  not a per-request value: a deployment has at most one CA provider, and it
  is not addressed by backend name the way key/crypto operations are.
- **A listing across every backend uses the fixed label `"all"`**
  (`metricsAllBackends`) rather than one series per backend visited, so a
  wildcard `ListKeys("")` does not fan out into N series on every call.

## Which backend labels a multi-backend operation (go-xkms#825)

Most operations name exactly one backend, so `backend` is unambiguous. A few
name two, and the choice of which one labels the series follows the same
rule in both directions:

- **`CopyKey`** (source and destination backend) is metered under the
  **destination**: that is where the operation's effect lands (a key is
  imported there), the same as `GenerateKey`/`ImportKey` are metered under
  the backend they write to — and it is the same backend `KeysTotal` is
  incremented for, so one variable feeds both.
- **`WrapKeyByID`/`UnwrapKeyByID`** (a wrapping/unwrapping key backend and a
  target key backend) are metered under the **wrapping/unwrapping key's**
  backend: that backend performs the cryptographic operation (the wrap or
  the decrypt), symmetric with how `Sign`/`Verify`/`Encrypt`/`Decrypt` are
  metered under the backend holding the operating key. `UnwrapKeyByID`'s
  `KeysTotal` increment, in contrast, targets the **target** backend, where
  the recovered key is imported — deliberately not the same backend the
  operation is metered under, since the crypto and the storage effect are
  two different backends here. See `docs/observability/engineering.md`'s
  operation-to-servicer-method table for the full mapping.

## Keys/certs totals: increment/decrement on the request path, reconcile on a sweep

`metrics.KeysTotal`/`CertsTotal` are updated two ways, deliberately kept
separate:

- **On the request path**, a successful key create/import or certificate
  save calls `metrics.IncrementKeysTotal`/`IncrementCertsTotal`; a successful
  delete calls the matching `Decrement*`. These are a direct
  `prometheus.Gauge.Inc()`/`.Dec()` — O(1), no backend call. An earlier
  version of this instrumentation recounted by calling `ListKeys`/`ListCerts`
  on every create/delete (`refreshKeysTotal`/`refreshCertsTotal`); that turns
  every key operation into O(n) work in however many keys/certs the backend
  holds, and for a remote backend (`awskms`, `gcpkms`, `azurekv`, `vault`)
  adds a network round trip — and API-throttling risk — to every request.
  Neither belongs on the request path.
- **On a periodic sweep**, `updateBackendMetrics` (`pkg/server/server.go`,
  every `backendMetricsInterval`) recounts each backend by actually listing
  it and publishes the absolute count with `metrics.SetKeysTotal`/
  `SetCertsTotal`. This is the reconciliation point: an incrementing counter
  can desync from reality (a backend mutated outside this process — a
  PKCS#11 token managed by another tool, a direct store write — or simply a
  gauge that was never seeded), and only a real recount can correct that.
  Bounding *how often* the recount runs, rather than never running one, is
  what keeps drift from persisting indefinitely without paying its O(n) cost
  on every request.

`SaveCertificateChain` deliberately does **not** call `IncrementCertsTotal`:
a chain is stored under a distinct key (`storage.CertChainPath`) that
`storage.ListCerts` explicitly excludes from the count `CertsTotal` tracks
(see `storage/namespace.go`), so saving one does not change that count.

## Backend health and keys/certs reconciliation: one `ListKeys` call, not two

`updateBackendMetrics` calls each backend's `ListKeys` **exactly once** per
sweep and derives both signals from that one call: an error means the
backend is unhealthy (`metrics.SetBackendHealth(name, false)`, recorded as an
`OpHealthCheck` failure); success means both healthy and the real key count
(`metrics.SetKeysTotal(name, len(keys))`). `ListCerts` is a second,
unavoidable call for the certs count (there is no combined primitive), but
that is one call per backend for one gauge, not a second call duplicating
one already made.

This does **not** reuse `pkg/server.initializeHealth`'s registered
`health.Checker` checks (`s.healthChecker`, consulted on demand by REST's
`GET /health/ready`): `Checker.Ready(ctx)` returns only a
status/message/latency/error per check, never the key list a count needs, so
routing the sweep through it would still cost a second `ListKeys` per
backend — the same duplication under a different name. There was also no
existing scheduling to inherit: readiness runs synchronously per HTTP
request, and `pkg/config.HealthConfig` carries no interval field.
`backendMetricsInterval` (30s) instead matches the resource collector's own
existing cadence (`metrics.StartResourceCollector`), so there is one
periodic-metrics schedule in the codebase, not two.

Neither sweep adds a `Health()`/`Ping()` method to the `Backend` interface:
every backend already has a real, in-use responsiveness probe (`ListKeys`),
and a second one every backend implementation would have to grow in lockstep
would duplicate it for no gain. If a future backend genuinely cannot answer
`ListKeys` cheaply, that is a reason to revisit this choice for that backend
specifically — not a reason to invent a parallel interface method today for
backends that don't have the problem.

## Connections: `ConnectionTracker` only where xkms owns the listener

`metrics.ConnectionTracker` (increment on connect, decrement on `Close`) is
wired onto the **Unix domain socket** listener
(`pkg/api/unix/grpc_server.go`'s `connMetricsHandler`, a `grpc.StatsHandler`)
because xkms owns that listener directly — it calls `net.Listen("unix", ...)`
itself.

**REST and network gRPC already have per-request instrumentation**
(`metrics.HTTPMiddleware`, `metrics.GRPCUnaryServerInterceptor`/
`GRPCStreamServerInterceptor`, wired in `pkg/api/rest/server.go` and
`pkg/api/grpc/server.go` respectively) that increments/decrements
`ActiveConnections` per request; `ConnectionTracker` is additive for
transports that have no such middleware.

**QUIC and MCP are not xkms listeners in the shipped topology.** Network
serving runs through go-qrdb's embedded unified multi-protocol server: xkms
registers its capability as a `qrdbserver.ServiceModule`
(`pkg/apimodule/module.go`), and `RegisterGRPC`/`RegisterHTTP`/`RegisterMCP`/
`RegisterQUIC` attach method handlers to a server go-qrdb constructs, owns,
and accepts connections on. `go-qrdb/pkg/apimodule.ServiceModule` (the
interface xkms's `Module` implements) exposes no connection-lifecycle hook —
only per-method registration — so there is no seam in the current SDK for a
module to observe a QUIC or MCP connection opening or closing. Per this
repository's rule that xkms never diverges from or invents around a
lower-layer (go-qrdb) contract, this is filed as a gap for go-qrdb to close
(a `ServiceModule`-level connection hook, or a metric go-qrdb publishes
itself for its own listeners) rather than worked around locally — e.g. by
xkms standing up a second, parallel QUIC or MCP listener purely to get an
accept loop to instrument, which would duplicate go-qrdb's transport and
contradict the "one unified server" design that transport exists for.
`ProtocolQUIC` and `ProtocolMCP` remain defined in `pkg/metrics` — a future
go-qrdb hook, or a legacy standalone listener path, would use them without a
label rename — but nothing currently calls
`NewConnectionTracker(ProtocolQUIC)` or `NewConnectionTracker(ProtocolMCP)`.

## Rejected: keeping `MetricsAdapter`/`NoOpMetrics`/`WithMetrics`

The adapter interface existed to let "calling applications implement custom
metrics collection strategies" — but go-xkms has exactly one metrics
strategy, Prometheus, and every consumer of xkms (xkmsd, the embedded SDK) is
this same repository. A pluggable-adapter seam with one real caller and zero
alternate implementations is speculative generality this project's
conventions forbid (YAGNI); it was deleted in the same change that gave the
real Prometheus API its callers, along with the 54 `Metric*` string constants
and 15 `Op*` constants (trimmed to the ones a real operation now uses) that
existed only to feed it. See `.changelog/unreleased/` for the entry.
