- **Prometheus metrics are now real, not aspirational: every key, crypto,
  and CA operation is instrumented at the `XKMSService` boundary, backend
  health is a live probe, and keys/certs totals track create and delete.**
  `pkg/metrics` previously declared 54 `Metric*` names, 15 `Op*` names, and a
  `MetricsAdapter`/`NoOpMetrics`/`WithMetrics` pluggable-adapter seam with
  zero callers outside its own tests, while `pkg/server/server.go` hard-coded
  every backend's health gauge to `1` at startup and never updated it again
  (go-xkms#720). `pkg/xkms`'s `GenerateKey`, `ListKeys`, `GetKey`,
  `DeleteKey`, `ImportKey`, `ExportKey`, `RotateKey`,
  `GetCertificate`/`SaveCertificate`/`DeleteCertificate`/`ListCertificates`/
  `SaveCertificateChain`/`GetCertificateChain`/`GetTLSCertificate`/
  `CertificateExists`, `Sign`/`Verify`/`Encrypt`/`Decrypt`/`EncryptAsym`, and
  `GetCABundle`/`GetCACertificate`/`SignCSR`/`IssueCertificate`/
  `RevokeCertificate`/`GenerateCRL`/`IsRevoked` now record
  `xkms_operations_total`, `xkms_operation_duration_seconds`, and
  `xkms_errors_total` through one shared `recordServiceOp` helper
  (`pkg/xkms/metrics_instrumentation.go`), called via `defer` on named
  returns so no new error path can forget it. Because this lives on
  `XKMSService` rather than in each transport's handler, REST, gRPC, Unix,
  QUIC, MCP, and the embedded SDK are all counted exactly once. Labels stay
  bounded cardinality by construction: `error_type` is the Go type name of
  the typed error returned (`errorTypeLabel`), never `err.Error()` or a key
  ID/common name/tenant ID. `pkg/server.updateBackendMetrics` (new, ticking
  every 30s to match the existing resource-collector cadence, and seeded
  synchronously at startup) replaces the hard-coded `true` with a real
  per-backend `ListKeys` probe, calling it exactly once per backend per
  sweep and deriving both the health gauge and an `xkms_keys_total`
  reconciliation from that one result (`xkms_certs_total` reconciles from
  one `ListCerts` call). `xkms_keys_total`/`xkms_certs_total` are otherwise
  kept accurate on the request path by a plain `Inc()`/`Dec()` on a
  successful key create/import/delete or certificate save/delete
  (`metrics.IncrementKeysTotal`/`DecrementKeysTotal`/`IncrementCertsTotal`/
  `DecrementCertsTotal`) — not by recounting via `ListKeys`/`ListCerts` on
  every request, which would turn an O(1) key operation into O(n) and add a
  network round trip (and API-throttling risk) to every request against a
  remote backend (`awskms`/`gcpkms`/`azurekv`/`vault`); the periodic sweep is
  the sole reconciliation point that pays for an accurate recount. The Unix
  domain socket listener
  (`pkg/api/unix/grpc_server.go`) now tracks active connections through a
  `grpc.StatsHandler` wired to `metrics.ConnectionTracker` — the one
  transport-owned listener without existing per-request middleware; QUIC and
  MCP are served entirely inside go-qrdb's embedded unified server, which
  exposes no connection-lifecycle hook on `ServiceModule` today, so
  `metrics.ProtocolQUIC`/`ProtocolMCP` stay defined for when that hook
  exists rather than being wired against a listener xkms does not own (see
  `docs/observability/architecture.md`). **BREAKING (pre-release, no
  compatibility shim):** `pkg/metrics`'s `MetricsAdapter` interface,
  `NoOpMetrics`, `WithMetrics`/`GetMetrics`/`RecordCounter`/
  `RecordCounterWithValue`/`RecordGauge`/`RecordHistogram`/`RecordTimer`/
  `WithTimer` convenience functions, all 54 `Metric*` string constants, and
  the unused `OpBackup`/`OpRestore` operation names are deleted; three new
  operation names (`OpIssueCert`, `OpRevokeCert`, `OpGenerateCRL`) and one
  new protocol name (`ProtocolUnix`) were added, each with a real caller in
  the same change. New tests: `pkg/xkms/metrics_instrumentation_test.go`
  drives real operations through `XKMSService`, reads the Prometheus
  registry directly, and (via a `ListKeys`/`ListCerts`-counting `Backend`
  double) asserts the request path makes zero listing calls it did not
  already need; `pkg/server/backend_metrics_test.go` covers a healthy, a
  failing, and a mixed backend, asserts exactly one `ListKeys`/`ListCerts`
  call per backend per sweep, and asserts the sweep reconciles a drifted
  gauge back to the real count; `pkg/api/unix/connection_tracker_test.go`
  dials a real connection through the Unix listener and asserts the gauge.
  Full five-file feature folder at `docs/observability/`. go-xkms#720.
