- **`pkg/acme/server/metrics`'s ~30 Prometheus functions are now wired to
  real ACME events instead of only referenced from tests, and the registry
  is visible on `/metrics`.** `metrics.Middleware` is mounted on the ACME
  router through a single shared helper, `metrics.Mount` (initializes the
  registry and attaches the middleware), used by both
  `cmd/xkmsd/acme.go`'s `buildACMERouter` and the standalone TrustedCA
  (`pkg/acme/client/trustedca.go`). Handlers now record: order creation and
  its three terminal transitions (`NewOrderHandler` increments
  `acme_active_orders`/`acme_pending_challenges`;
  `ChallengeHandler`/`OrderFinalizeHandler`'s `sendFinalizeResponse`/
  `failOrder` decrement `acme_active_orders` on each terminal path);
  challenge validation by type and result (`acme_challenges_completed_total`);
  finalize/issuance success and failure with latency
  (`acme_certificates_issued_total`, `acme_certificate_issuance_duration_seconds`,
  `acme_errors_total{type="issuance_failed"}`); revocation
  (`acme_certificates_revoked_total`); and account creation/deactivation
  (new `acme_accounts_created_total` counter, `acme_tenant_active_accounts`
  gauge). Tenant-bound accounts also record the existing per-tenant
  counters/gauges via `metrics.NewMetricsCollector`. xkmsd's `/metrics`
  (`pkg/server/server.go`) now gathers the ACME registry alongside the
  default one through a new `Server.RegisterMetricsGatherer` +
  `serverGatherer`, rather than a second endpoint; this also fixes a
  duplicate-metric scrape failure that combining the two registries'
  Go/process collectors would otherwise cause — `metrics.Init` no longer
  registers them, and a new `metrics.RegisterRuntimeCollectors` adds them
  only for the standalone TrustedCA, which serves this registry alone.
  Deleted as dead code (no matching operation): the `trustedca`-namespaced
  cluster/Raft metrics and `ClusterMetricsCollector` (superseded by
  `pkg/acme/qrdb`'s real qrdb-backed `RaftMetricsCollector`), the
  tenant-rate-limit and SLO/service-health metrics (the ACME rate limiter
  tracks its own internal, non-Prometheus counters — see the engineering
  doc's Known gap), `acme_certificates_expiring_soon` (no background scan
  populates it), and the `Set*` gauge setters superseded by the `Inc*`/`Dec*`
  pairs actually wired. Deploy assets ported from go-trusted-ca and updated
  to the metric names/labels that actually exist:
  `deploy/prometheus/rules/acme.yml` (validated with `promtool check
  rules`) and `deploy/grafana/` (dashboard + provisioning), documented in
  `deploy/README.md`'s new Monitoring section; the Raft dashboard was not
  ported since none of the `dragondb_raft_*` metrics it queried exist in
  this codebase. Docs:
  `docs/acme-issuance/engineering.md#observability`,
  `docs/acme/ROADMAP.md`. Verified by
  `pkg/acme/server/metrics/{metrics,production,middleware}_test.go`,
  `pkg/acme/server/handlers/metrics_test.go` (per-handler counter deltas,
  success and failure, via `prometheus/testutil`),
  `pkg/server/metrics_gatherer_test.go`, and
  `cmd/xkmsd/metrics_test.go` (end-to-end: a request through
  `buildACMERouter` shows up in a real `pkg/server.Server`'s `/metrics`).
  go-xkms#734.
