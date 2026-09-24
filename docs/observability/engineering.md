# Observability — Engineering Contract

> **Status: NORMATIVE** · Feature: `observability` · Repo: `go-xkms` · Last verified: 2026-09-23

## Exported surface — `pkg/metrics`

```go
// Operation names -- every one has a real caller at the XKMSService boundary.
const (
	OpGenerate, OpStore, OpGet, OpDelete, OpList,
	OpSign, OpVerify, OpEncrypt, OpDecrypt,
	OpExport, OpImport, OpRotate, OpHealthCheck,
	OpIssueCert, OpRevokeCert, OpGenerateCRL string
)

const StatusSuccess, StatusError string

func RecordOperation(operation, backend, status string, duration float64)
func RecordError(operation, backend, errorType string)
func SetKeysTotal(backend string, count float64)
func SetCertsTotal(backend string, count float64)
func SetBackendHealth(backend string, healthy bool)
func Enable() / Disable() / IsEnabled() bool

// Protocol identifiers
const ProtocolHTTP, ProtocolGRPC, ProtocolQUIC, ProtocolMCP, ProtocolUnix string

func HTTPMiddleware(next http.Handler) http.Handler
func GRPCUnaryServerInterceptor() grpc.UnaryServerInterceptor
func GRPCStreamServerInterceptor() grpc.StreamServerInterceptor

type ConnectionTracker struct{ /* unexported */ }
func NewConnectionTracker(protocol string) *ConnectionTracker
func (ct *ConnectionTracker) Close()
func (ct *ConnectionTracker) Duration() time.Duration

type ResourceCollector struct{ /* unexported */ }
func NewResourceCollector(ctx context.Context, interval time.Duration) *ResourceCollector
func StartResourceCollector(ctx context.Context, interval time.Duration) *ResourceCollector
func (rc *ResourceCollector) Start() / Stop()
func CollectOnce()
```

Prometheus collectors (`promauto`-registered `var`s, namespace `xkms`):
`OperationsTotal`, `OperationDuration`, `ErrorsTotal`, `AuditWriteFailuresTotal`,
`ActiveConnections`, `HTTPRequestsTotal`, `HTTPRequestDuration`,
`GRPCRequestsTotal`, `GRPCRequestDuration`, `Goroutines`, `MemoryAllocBytes`,
`MemorySysBytes`, `GCPauseTotalSeconds`, `KeysTotal`, `CertsTotal`,
`BackendHealthy`, `ServerUptime`. All exported for direct use by tests
(`testutil.ToFloat64`, `.Write(&dto.Metric{})`) and by any code that needs a
collector reference rather than a `Record*`/`Set*` call.

`SetKeysTotal`/`SetCertsTotal` publish an absolute value (the periodic
reconciliation sweep's job); `IncrementKeysTotal`/`DecrementKeysTotal` and
`IncrementCertsTotal`/`DecrementCertsTotal` adjust by one with no backend
call (the request path's job) — see architecture.md's "Keys/certs totals"
section for why both exist and neither replaces the other.

## Internal surface — `pkg/xkms` (unexported, `metrics_instrumentation.go`)

```go
func recordServiceOp(operation, backendName string, start time.Time, err error)
func errorTypeLabel(err error) string
func (s *XKMSService) metricsBackendName(explicit string) string
func incrementKeysTotal(backendName string)
func decrementKeysTotal(backendName string)
func incrementCertsTotal(backendName string)
func decrementCertsTotal(backendName string)
const caMetricsBackend = "ca"
const metricsAllBackends = "all"
```

Every `XKMSService` method in `servicer_key.go`, `servicer_cert.go`,
`servicer_crypto.go`, and `servicer_ca.go` that maps to an `Op*`/backend
constant above calls `recordServiceOp` via `defer` on named returns — see
[`architecture.md`](architecture.md) for why `defer` on named returns and not
a manual call before each `return`.

## Invariants

- **Label cardinality is bounded.** Labels are `operation`, `backend`,
  `status`, and `error_type` only. `error_type` is a Go type name
  (`errorTypeLabel`), never `err.Error()`; `backend` is a registered backend
  name, `"ca"`, or `"all"` — never a key ID, common name, or tenant ID. A
  change that would add a label carrying a caller-supplied value is a
  regression, not a feature.
- **Every transport is counted exactly once.** Instrumentation lives on
  `XKMSService` methods, not in transport handlers (`pkg/api/rest`,
  `pkg/api/grpc`, `pkg/api/mcp`, `pkg/api/transport/quic`). A change that adds
  `metrics.RecordOperation` inside a transport handler for an operation
  `XKMSService` already instruments double-counts that operation.
- **Keys/certs totals are incremented/decremented on the request path, never
  recounted there.** `incrementKeysTotal`/`decrementKeysTotal`/
  `incrementCertsTotal`/`decrementCertsTotal` are the only calls a servicer
  method makes; none of them call `ListKeys`/`ListCerts`. A change that adds
  a listing call to a key/cert create/delete path to "keep the gauge
  accurate" is the O(n)-per-request regression this feature folder exists to
  prevent — the periodic sweep (next bullet) is where recounting belongs.
  See architecture.md.
- **Backend health and keys-total reconciliation share one `ListKeys` call
  per backend per sweep.** `pkg/server.updateBackendMetrics`
  (`probeBackendMetrics`) is the only caller of `metrics.SetBackendHealth`
  outside tests, and it derives both the health gauge and the keys-total
  reconciliation from the same `ListKeys` result — never two separate calls
  for the two signals. A hard-coded `true` health value (the pre-#720 state)
  and a second, duplicate `ListKeys` call (an earlier #720 revision, fixed
  before merge) are both regressions this feature folder exists to prevent
  recurring.
- **`Op*`/`Metric*` names all have a real caller.** A name with zero callers
  is deleted, not kept "for future use" (see the deleted `MetricsAdapter`
  surface in architecture.md). Adding a new `Op*` constant requires wiring it
  into a real `XKMSService` method in the same change.

## Errors

`pkg/metrics` returns no errors of its own: `Record*`/`Set*`/`Increment*`/
`Decrement*` are best-effort gauge/counter updates that cannot fail short of
a Prometheus client panic (which would indicate a label-cardinality bug,
caught by the invariant above). `probeBackendMetrics`
(`pkg/server/server.go`) swallows a `ListKeys`/`ListCerts` error by design —
a transient listing failure must not crash the periodic sweep for every
other backend, and skips only that backend's gauge update for the tick; the
next tick retries.

## Configuration — `pkg/config.MetricsConfig`

```go
type MetricsConfig struct {
	Enabled bool   `yaml:"enabled"`
	Path    string `yaml:"path"`
	Port    int    `yaml:"port"`
}
```

`Enabled` gates `pkg/server.initializeMetrics` (enables the package,
starts the resource collector, seeds backend/keys/certs gauges) and
`startMetrics`/`startBackendMetrics` (serves `/metrics` and runs the 30
second periodic refresher, respectively). `metrics.Enable()`/`Disable()` is
also toggled directly by tests; `IsEnabled()` gates every `Record*`/`Set*`
call so a disabled package is a true no-op, not merely an unscraped one.

## Tests

- `pkg/metrics/*_test.go` — the Prometheus API in isolation (counters,
  histograms, gauges, middleware, `ConnectionTracker`, `ResourceCollector`).
- `pkg/xkms/metrics_instrumentation_test.go` — drives `GenerateKey`, `Sign`,
  `DeleteKey`, and `SaveCertificate`/`DeleteCertificate`/`SaveCertificateChain`
  through the real `XKMSService` (the `mockKeyStore`/`mockExtendedKeyStore`
  test backends from `service_test.go`) and asserts the resulting
  `OperationsTotal`/`OperationDuration`/`ErrorsTotal`/`KeysTotal`/`CertsTotal`
  series — the "scrape after driving operations through the service
  boundary" contract, read directly off the shared Prometheus registry
  rather than through an HTTP round-trip (`/metrics` itself is
  `promhttp.Handler()`, standard library code with nothing xkms specific to
  test). `countingBackend` (a `Backend` wrapper counting `ListKeys`/
  `ListCerts` calls) backs the request-path performance assertions: zero
  extra listing calls from `GenerateKey`/`SaveCertificate`/
  `DeleteCertificate`, and exactly the one `findKeyAttrs` already makes from
  `DeleteKey`.
- `pkg/server/backend_metrics_test.go` — `updateBackendMetrics` against a
  healthy backend, a backend whose `ListKeys` probe fails, and a mix of both,
  asserting `BackendHealthy`/`KeysTotal`/`CertsTotal`/`OpHealthCheck`; a
  `listKeysCalls`/`listCertsCalls`-counting backend double asserting exactly
  one call of each per backend per sweep; and a drift-reconciliation case
  (the gauge is deliberately set to a wrong value, then the sweep corrects
  it to the real count).
- `pkg/api/unix/connection_tracker_test.go` — dials a real client connection
  through the Unix listener's `grpc.StatsHandler` and asserts
  `ActiveConnections{protocol="unix"}` increments on connect and decrements
  on close.

Run: `go test ./pkg/metrics/... ./pkg/xkms/... ./pkg/server/... ./pkg/api/unix/...`
(root module, `GOWORK=off`).
